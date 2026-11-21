import gzip
import hashlib
import io
import re
import tarfile

from arch_inventory import BoundedTarInfo, LayerReader, MAX_MEMBERS, apply_layer, safe_path
from native_profile import PROFILE, require


METADATA_NAMES = {".PKGINFO", ".BUILDINFO", ".MTREE"}
REPEATED = {"license", "replaces", "group", "conflict", "provides", "backup", "depend", "optdepend",
            "makedepend", "checkdepend", "xdata", "buildenv", "options", "installed"}


def assignments(raw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= PROFILE["document_bytes"], "Missing or oversized package assignments")
    result = {}
    for line in raw.decode("utf-8", errors="strict").splitlines():
        line = line.lstrip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition(" = ")
        require(separator and re.fullmatch(r"[a-z][a-z0-9_]*", key), "Malformed package assignment")
        require(not any(ord(character) < 32 for character in value), "Control character in package assignment")
        require(key not in result or key in REPEATED, "Repeated singular package assignment: " + key)
        result.setdefault(key, []).append(value)
    return result


def single(fields, key):
    require(len(fields.get(key, [])) == 1 and fields[key][0], "Missing singular package assignment: " + key)
    return fields[key][0]


def metadata_binding(metadata, expected, recipe=None):
    require(set(metadata) == METADATA_NAMES, "Archive lacks authentic package producer metadata")
    package = assignments(metadata[".PKGINFO"])
    build = assignments(metadata[".BUILDINFO"])
    require(single(build, "format") == "2", "Unsupported BUILDINFO format")
    for key, field in (("name", "pkgname"), ("version", "pkgver"), ("base", "pkgbase")):
        require(single(package, field) == expected[key] == single(build, field), "Package producer identity differs: " + key)
    require(single(package, "arch") == expected["architecture"] == single(build, "pkgarch"), "Package producer architecture differs")
    digest = single(build, "pkgbuild_sha256sum").lower()
    require(re.fullmatch(r"[0-9a-f]{64}", digest), "Invalid producer PKGBUILD digest")
    if recipe is not None:
        require(isinstance(recipe, bytes) and 0 < len(recipe) <= PROFILE["document_bytes"], "Invalid original PKGBUILD bytes")
        require(hashlib.sha256(recipe).hexdigest() == digest, "Packaging recipe differs from actual producer BUILDINFO")
    with gzip.GzipFile(fileobj=io.BytesIO(metadata[".MTREE"])) as stream:
        mtree = stream.read(PROFILE["document_bytes"] + 1)
    require(len(mtree) <= PROFILE["document_bytes"] and mtree.startswith(b"#mtree\n"), "Missing or oversized original package mtree")
    return {"identity": dict(expected), "pkgbuild_sha256": digest, "recipe_bound": recipe is not None,
            "metadata_sha256": {name: hashlib.sha256(raw).hexdigest() for name, raw in metadata.items()},
            "licenses": package.get("license", []), "build_environment": build.get("installed", []),
            "mtree_uncompressed_sha256": hashlib.sha256(mtree).hexdigest()}


def read_package_tar(stream):
    totals = {"bytes": 0}
    reader = LayerReader(stream, totals)
    files = {}
    metadata = {}
    with tarfile.open(fileobj=reader, mode="r|", tarinfo=BoundedTarInfo, encoding="utf-8", errors="strict") as archive:
        for index, member in enumerate(archive, 1):
            require(index <= MAX_MEMBERS and not member.issparse(), "Package archive exceeds member bound or uses sparse metadata")
            path = safe_path(member.name)
            require(path and path not in files and path not in metadata, "Duplicate or empty package archive path")
            require(0 <= member.size <= PROFILE["disk_growth_bytes"], "Package member exceeds limit")
            entry = {"mode": member.mode, "uid": member.uid, "gid": member.gid, "bytes": member.size}
            if member.isfile():
                digest = hashlib.sha256()
                retain = path in METADATA_NAMES
                require(not retain or member.size <= PROFILE["document_bytes"], "Package metadata exceeds document limit")
                raw = bytearray() if retain else None
                remaining = member.size
                with archive.extractfile(member) as content:
                    while remaining:
                        block = content.read(min(remaining, 65536))
                        require(block, "Truncated package member")
                        digest.update(block)
                        if retain:
                            raw.extend(block)
                        remaining -= len(block)
                if retain:
                    metadata[path] = bytes(raw)
                entry.update(kind="file", sha256=digest.hexdigest())
            elif member.isdir():
                entry["kind"] = "directory"
            elif member.issym():
                require(len(member.linkname.encode()) <= 4096 and not any(ord(char) < 32 for char in member.linkname), "Invalid package symlink")
                entry.update(kind="symlink", target=member.linkname)
            elif member.islnk():
                entry.update(kind="hardlink", target=safe_path(member.linkname))
            else:
                require(False, "Unsupported package archive object")
            require(path not in METADATA_NAMES or member.isfile(), "Package metadata must be a regular file")
            files[path] = entry
        while tail := archive.fileobj.read(65536):
            require(not tail.strip(b"\0"), "Hidden data after package archive end")
    require(set(metadata) == METADATA_NAMES, "Archive lacks authentic package producer metadata")
    return {"metadata": metadata, "files": apply_layer({}, files, []), "uncompressed_bytes": totals["bytes"]}


def compare_package_files(package, owned_paths, actual_files):
    checked = []
    differences = []
    for original in owned_paths:
        path = safe_path(original)
        require(path and path in package["files"], "Installed ownership names a file absent from original archive")
        expected = package["files"][path]
        actual = actual_files.get(path)
        if actual is None:
            differences.append({"path": path, "reason": "absent"})
            continue
        expected_kind = "file" if expected["kind"] == "hardlink" else expected["kind"]
        actual_kind = "file" if actual["kind"] == "hardlink" else actual["kind"]
        fields = ["mode", "uid", "gid"]
        if expected_kind == "file":
            fields += ["sha256"]
        if expected_kind == "symlink":
            fields += ["target"]
        changed = [field for field in fields if expected.get(field) != actual.get(field)]
        if expected_kind != actual_kind:
            changed.append("kind")
        if changed:
            differences.append({"path": path, "reason": "changed", "fields": changed})
        else:
            checked.append(path)
    return {"matched_paths": checked, "differences": differences, "all_owned_paths_match": not differences}
