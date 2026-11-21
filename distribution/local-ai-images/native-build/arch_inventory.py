from bisect import bisect_left
import gzip
import hashlib
import re
from pathlib import PurePosixPath
import tarfile

from native_profile import PROFILE, QualificationError, require


PACKAGE_ROOT = "var/lib/pacman/local/"
MAX_MEMBERS = 500000


class BoundedTarInfo(tarfile.TarInfo):
    def _proc_member(self, archive):
        require(0 <= self.size <= PROFILE["disk_growth_bytes"], "Tar member exceeds bounded profile")
        if self.type in {tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK}:
            require(self.size <= PROFILE["document_bytes"], "Tar extended metadata exceeds limit")
        require(self.type != tarfile.GNUTYPE_SPARSE, "Sparse archive records require separate validation")
        member = super()._proc_member(archive)
        require(set(member.pax_headers) <= {"path", "linkpath", "size", "uid", "gid", "uname", "gname", "mtime", "atime", "ctime"},
                "Unsupported archive extended attributes")
        return member

    def _proc_gnusparse_00(self, *arguments):
        raise QualificationError("Sparse archive records require separate validation")

    def _proc_gnusparse_01(self, *arguments):
        raise QualificationError("Sparse archive records require separate validation")

    def _proc_gnusparse_10(self, *arguments):
        raise QualificationError("Sparse archive records require separate validation")


class LayerReader:
    def __init__(self, stream, total):
        self.stream = stream
        self.total = total
        self.digest = hashlib.sha256()
        self.position = 0

    def read(self, size):
        require(type(size) is int and 0 <= size <= 65536, "Unbounded layer read")
        remaining = PROFILE["disk_growth_bytes"] - self.total["bytes"]
        data = self.stream.read(min(size, remaining + 1))
        require(self.total["bytes"] + len(data) <= PROFILE["disk_growth_bytes"], "Uncompressed layers exceed profile")
        self.total["bytes"] += len(data)
        self.position += len(data)
        self.digest.update(data)
        return data

    def tell(self):
        return self.position


def safe_path(value):
    require(isinstance(value, str) and len(value.encode("utf-8")) <= 4096 and not any(ord(character) < 32 for character in value), "Invalid image path")
    while value.startswith("./"):
        value = value[2:]
    path = PurePosixPath(value)
    require(not path.is_absolute() and ".." not in path.parts and "\\" not in value, "Unsafe image path")
    return "" if str(path) == "." else str(path)


def parse_desc(raw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= PROFILE["document_bytes"], "Missing or oversized authentic pacman metadata")
    result = {}
    field = None
    for line in raw.decode("utf-8", errors="strict").splitlines():
        if not line:
            field = None
        elif line.startswith("%") and line.endswith("%"):
            name = line[1:-1]
            require(re.fullmatch(r"[A-Z0-9_]+", name) and name not in result, "Invalid or repeated pacman metadata field")
            result[name] = []
            field = name
        else:
            require(field is not None, "Pacman metadata value has no field")
            result[field].append(line)
    return result


def package_identity(raw):
    fields = parse_desc(raw)
    for name in ("NAME", "VERSION", "BASE", "ARCH"):
        require(len(fields.get(name, [])) == 1, "Pacman identity is incomplete: " + name)
    name, version, base, architecture = (fields[key][0] for key in ("NAME", "VERSION", "BASE", "ARCH"))
    require(re.fullmatch(r"[a-z0-9][a-z0-9@._+-]*", name) and re.fullmatch(r"[a-z0-9][a-z0-9@._+-]*", base), "Invalid package name or base")
    require(re.fullmatch(r"[A-Za-z0-9.+_:~-]+", version), "Invalid package version")
    require(architecture in {"x86_64", "any"}, "Wrong package architecture")
    return {"name": name, "version": version, "base": base, "architecture": architecture}


def package_snapshot(filesystem, metadata, require_complete):
    packages = []
    names = set()
    for path, entry in sorted(filesystem.items()):
        if not path.startswith(PACKAGE_ROOT) or not path.endswith("/desc"):
            continue
        relative = path[len(PACKAGE_ROOT):]
        if relative.count("/") != 1:
            continue
        require(entry["kind"] == "file" and entry.get("sha256") in metadata, "Package descriptor is not authentic regular metadata")
        identity = package_identity(metadata[entry["sha256"]])
        directory = relative.split("/", 1)[0]
        require(directory == identity["name"] + "-" + identity["version"], "Package directory disagrees with descriptor")
        require(identity["name"] not in names, "Duplicate installed package name")
        names.add(identity["name"])
        observed = {"desc": entry["sha256"]}
        for name in ("files", "mtree"):
            sibling = filesystem.get(PACKAGE_ROOT + directory + "/" + name)
            if sibling is not None:
                require(sibling["kind"] == "file" and sibling.get("sha256") in metadata, "Package evidence is not authentic regular metadata")
                observed[name] = sibling["sha256"]
            elif require_complete:
                require(False, "Package is missing authentic " + name + ": " + identity["name"])
        if "files" in observed:
            fields = parse_desc(metadata[observed["files"]])
            require("FILES" in fields, "Package file inventory is missing its FILES field")
            for owned in fields["FILES"]:
                require(safe_path(owned), "Invalid empty package-owned path")
        packages.append({**identity, "metadata": observed})
    return packages


def whiteout(path, member):
    leaf = PurePosixPath(path).name
    if not leaf.startswith(".wh."):
        return None
    require(member.isfile() and member.size == 0, "Whiteout must be an empty regular entry")
    parent = str(PurePosixPath(path).parent)
    parent = "" if parent == "." else parent
    if leaf == ".wh..wh..opq":
        return parent, True
    target = leaf[4:]
    require(target and target not in {".", ".."}, "Invalid whiteout target")
    return safe_path((parent + "/" if parent else "") + target), False


def apply_layer(filesystem, changes, removals):
    result = dict(filesystem)
    for path, opaque in removals:
        prefix = path + "/" if path else ""
        for existing in list(result):
            if existing.startswith(prefix) or (not opaque and existing == path):
                del result[existing]
    lower_paths = sorted(result)
    for path, entry in sorted(changes.items(), key=lambda item: (len(PurePosixPath(item[0]).parts), item[0])):
        for parent in PurePosixPath(path).parents:
            if str(parent) == ".":
                continue
            ancestor = result.get(str(parent))
            require(ancestor is None or ancestor["kind"] == "directory", "Image writes through a non-directory ancestor")
        if entry["kind"] != "directory":
            prefix = path + "/"
            start = bisect_left(lower_paths, prefix)
            for index in range(start, len(lower_paths)):
                existing = lower_paths[index]
                if not existing.startswith(prefix):
                    break
                result.pop(existing, None)
        result[path] = dict(entry)
    for path in changes:
        entry = result[path]
        if entry["kind"] != "hardlink":
            continue
        target = entry["target"]
        visited = {path}
        while True:
            require(target not in visited and target in result, "Missing or cyclic image hardlink")
            visited.add(target)
            linked = result[target]
            if linked["kind"] != "hardlink" or "sha256" in linked:
                require(linked["kind"] in {"file", "hardlink"}, "Image hardlink does not resolve to a regular file")
                entry["sha256"] = linked["sha256"]
                entry["logical_bytes"] = linked.get("logical_bytes", linked["bytes"])
                break
            target = linked["target"]
    return result


def observe_layers(layers):
    filesystem = {}
    metadata = {}
    metadata_bytes = 0
    observations = {}
    layer_reports = []
    physical_files = []
    total = {"bytes": 0, "members": 0}
    for digest, expected_diff_id, compressed in layers:
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", digest) and re.fullmatch(r"sha256:[0-9a-f]{64}", expected_diff_id), "Invalid OCI layer identity")
        compressed_hash = hashlib.sha256()
        original = compressed.tell()
        while block := compressed.read(65536):
            compressed_hash.update(block)
        require("sha256:" + compressed_hash.hexdigest() == digest, "Compressed layer bytes differ")
        compressed.seek(original)
        changes = {}
        removals = []
        seen = set()
        with gzip.GzipFile(fileobj=compressed, mode="rb") as decoded:
            reader = LayerReader(decoded, total)
            with tarfile.open(fileobj=reader, mode="r|", tarinfo=BoundedTarInfo, encoding="utf-8", errors="strict") as archive:
                count = 0
                for member in archive:
                    count += 1
                    total["members"] += 1
                    require(total["members"] <= MAX_MEMBERS and not member.issparse(), "Layer has too many or unsupported sparse entries")
                    require(0 <= member.size <= PROFILE["disk_growth_bytes"], "Image member exceeds profile")
                    path = safe_path(member.name)
                    if not path:
                        require(member.isdir(), "Invalid image root member")
                        continue
                    require(path not in seen, "Duplicate image path in one layer")
                    seen.add(path)
                    removed = whiteout(path, member)
                    if removed is not None:
                        removals.append(removed)
                        continue
                    entry = {"mode": member.mode, "uid": member.uid, "gid": member.gid, "layer": digest, "bytes": member.size}
                    if member.isfile():
                        entry["kind"] = "file"
                        data_hash = hashlib.sha256()
                        capture = (path.startswith(PACKAGE_ROOT) and path.rsplit("/", 1)[-1] in {"desc", "files", "mtree"}) or path == "usr/share/ve-os-local-ai/installed-output-files.json"
                        require(not capture or member.size <= PROFILE["document_bytes"], "Package metadata exceeds document limit")
                        retained = bytearray() if capture else None
                        remaining = member.size
                        with archive.extractfile(member) as data:
                            while remaining:
                                chunk = data.read(min(65536, remaining))
                                require(chunk, "Truncated image file")
                                data_hash.update(chunk)
                                if retained is not None:
                                    retained.extend(chunk)
                                remaining -= len(chunk)
                        entry["sha256"] = data_hash.hexdigest()
                        if retained is not None and entry["sha256"] not in metadata:
                            metadata_bytes += len(retained)
                            require(metadata_bytes <= PROFILE["metadata_bytes"], "Package evidence exceeds metadata envelope")
                            metadata[entry["sha256"]] = bytes(retained)
                    elif member.isdir():
                        entry["kind"] = "directory"
                    elif member.issym():
                        require(len(member.linkname.encode()) <= 4096 and not any(ord(value) < 32 for value in member.linkname), "Invalid image symlink")
                        entry.update(kind="symlink", target=member.linkname)
                    elif member.islnk():
                        entry.update(kind="hardlink", target=safe_path(member.linkname))
                    elif member.ischr() or member.isblk() or member.isfifo():
                        entry.update(kind="character" if member.ischr() else "block" if member.isblk() else "fifo",
                                     major=member.devmajor, minor=member.devminor)
                    else:
                        require(False, "Unsupported image object type")
                    changes[path] = entry
                while trailing := archive.fileobj.read(65536):
                    require(not trailing.strip(b"\0"), "Nonzero data after image tar end")
            require("sha256:" + reader.digest.hexdigest() == expected_diff_id, "Uncompressed OCI diff ID differs")
        filesystem = apply_layer(filesystem, changes, removals)
        physical_files.append({"layer": digest, "entries": {path: dict(filesystem[path]) for path in changes}, "whiteouts": removals})
        packages = package_snapshot(filesystem, metadata, require_complete=False)
        for package in packages:
            key = tuple(package[name] for name in ("name", "version", "base", "architecture"))
            item = observations.setdefault(key, {**package, "layers": [], "metadata_versions": []})
            if digest not in item["layers"]:
                item["layers"].append(digest)
            if package["metadata"] not in item["metadata_versions"]:
                item["metadata_versions"].append(package["metadata"])
        layer_reports.append({"digest": digest, "diff_id": expected_diff_id, "member_count": count,
                              "changed_paths": len(changes), "whiteouts": len(removals)})
    final = package_snapshot(filesystem, metadata, require_complete=True)
    require(final, "Image contains no authentic installed Arch package inventory")
    for package in observations.values():
        require(any(set(version) == {"desc", "files", "mtree"} for version in package["metadata_versions"]),
                "Distributed package lacks authentic files/mtree evidence")
    return {"system_format": "arch-pacman", "physical_packages": list(observations.values()), "final_packages": final,
            "filesystem": filesystem, "physical_files": physical_files, "metadata_blobs": metadata, "layers": layer_reports,
            "uncompressed_bytes": total["bytes"], "metadata_bytes": metadata_bytes}
