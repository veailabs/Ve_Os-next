import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import time

from arch_inventory import BoundedTarInfo, safe_path
from arch_packages import metadata_binding
from native_inputs import unique_object
from native_profile import PROFILE, require


def hash_file(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def document(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1 and path.stat().st_size <= PROFILE["document_bytes"], "Invalid source evidence document")
    return json.loads(path.read_bytes(), object_pairs_hook=unique_object)


def git_tree(files):
    directories = {"": {}}
    for path, (mode, digest) in files.items():
        parent, _, name = path.rpartition("/")
        require(name and path not in directories, "Ambiguous source Git path")
        directories.setdefault(parent, {})[name] = (mode, digest)
        while parent:
            ancestor, _, name = parent.rpartition("/")
            directories.setdefault(ancestor, {})
            require(name not in directories[ancestor], "Source file conflicts with tree directory")
            parent = ancestor
    for directory in sorted(directories, key=lambda value: len(PurePosixPath(value).parts), reverse=True):
        entries = directories[directory]
        data = b""
        for name, (mode, digest) in sorted(entries.items(), key=lambda item: (item[0] + ("/" if item[1][0] == "40000" else "")).encode()):
            data += mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(digest)
        digest = hashlib.sha1(b"tree " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if directory:
            parent, _, name = directory.rpartition("/")
            require(name not in directories[parent], "Duplicate source directory")
            directories[parent][name] = ("40000", digest)
    return digest


class ComponentReader:
    def __init__(self, stream, size, deadline):
        self.stream, self.size, self.deadline = stream, size, deadline
        self.bytes = 0
        self.digest = hashlib.sha256()

    def read(self, size=-1):
        require(time.monotonic() < self.deadline, "Source validation deadline exceeded")
        require(type(size) is int and size >= 0, "Unbounded source component read")
        block = self.stream.read(min(size, 65536))
        self.bytes += len(block)
        require(self.bytes <= self.size, "Source component grew beyond receipt")
        self.digest.update(block)
        return block


def inspect_component(stream, entry, deadline, recipe_path=None, recipe_hash=None, tree=None, required_members=()):
    reader = ComponentReader(stream, entry["bytes"], deadline)
    files = {}
    content_identities = {}
    seen = set()
    recipe_seen = False
    expanded = 0
    with tarfile.open(fileobj=reader, mode="r|gz", tarinfo=BoundedTarInfo) as archive:
        for member in archive:
            require(len(seen) < 500000 and not member.issparse(), "Unsupported or excessive source members")
            path = safe_path(member.name)
            require(path and path not in seen, "Duplicate or empty source component member")
            seen.add(path)
            expanded += member.size
            require(expanded <= 8 * 1024 ** 3, "Expanded source component exceeds validation bound")
            if member.isdir():
                continue
            if member.issym():
                require(tree is not None or len(member.linkname.encode()) <= 4096, "Invalid source symlink")
                content = member.linkname.encode()
                files[path] = ("120000", hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest())
                content_identities[path] = {"kind": "symlink", "target": member.linkname, "mode": member.mode}
                continue
            require(member.isfile(), "Unsupported source component object")
            content_hash = hashlib.sha256()
            blob = hashlib.sha1(b"blob " + str(member.size).encode() + b"\0")
            remaining = member.size
            with archive.extractfile(member) as content:
                while remaining:
                    require(time.monotonic() < deadline, "Source validation deadline exceeded")
                    chunk = content.read(min(remaining, 65536))
                    require(chunk, "Truncated source component")
                    remaining -= len(chunk)
                    content_hash.update(chunk)
                    blob.update(chunk)
            files[path] = ("100755" if member.mode & 0o111 else "100644", blob.hexdigest())
            content_identities[path] = {"kind": "file", "sha256": content_hash.hexdigest(), "mode": member.mode}
            if path == recipe_path:
                require(content_hash.hexdigest() == recipe_hash, "Complete source archive changed producer recipe")
                recipe_seen = True
        while trailing := archive.fileobj.read(65536):
            expanded += len(trailing)
            require(expanded <= 8 * 1024 ** 3 and not trailing.strip(b"\0"), "Unexpected data after source tar end")
            require(time.monotonic() < deadline, "Source validation deadline exceeded")
    while reader.read(65536):
        pass
    require(reader.bytes == entry["bytes"] and reader.digest.hexdigest() == entry["sha256"], "Complete source component hash or size differs")
    require(recipe_path is None or recipe_seen, "Original recipe is absent from complete source archive")
    require(all(path in seen or any(name.startswith(path + "/") for name in seen) for path in required_members),
            "Complete source archive omitted a declared source")
    if tree is not None:
        require(git_tree(files) == tree, "Complete upstream source tree differs from pinned Git object")
    return content_identities


def inventory_records(stream, entry, deadline):
    reader = ComponentReader(stream, entry["bytes"], deadline)
    seen = set()
    with gzip.GzipFile(fileobj=reader) as decoded:
        while line := decoded.readline(65537):
            require(len(line) <= 65536 and len(seen) < 500000, "Original file inventory exceeds bound")
            record = json.loads(line, object_pairs_hook=unique_object)
            path = record.get("path", "")
            require(safe_path(path) == path and path and path not in seen, "Invalid or duplicate original package path")
            seen.add(path)
            require(record.get("kind") in {"file", "directory", "symlink", "hardlink"}, "Invalid original package file kind")
            require(all(type(record.get(key)) is int and record[key] >= 0 for key in ("mode", "uid", "gid")), "Invalid original package ownership or mode")
            if record["kind"] in {"file", "hardlink"}:
                require(re.fullmatch(r"[0-9a-f]{64}", record.get("sha256", "")), "Original file lacks a content digest")
            if record["kind"] in {"hardlink", "symlink"}:
                require(isinstance(record.get("target"), str) and len(record["target"].encode()) <= 4096, "Invalid original link target")
            yield record
    while reader.read(65536):
        pass
    require(reader.bytes == entry["bytes"] and reader.digest.hexdigest() == entry["sha256"], "Original package file inventory hash differs")


def validate_sources(root, context, deadline):
    catalog_path = context / "metadata/source-package-archives.json"
    catalog = document(catalog_path)
    receipt = document(root / "acquisition.json")
    require(receipt.get("status") == "acquired-and-verified-before-compilation" and receipt.get("schema_version") == 1, "Source acquisition did not pass")
    require(receipt.get("catalog_sha256") == hash_file(catalog_path), "Source archive catalog changed")
    expected = {(row["name"], row["version"], row["base"], row["architecture"]): row for row in catalog["packages"]}
    require(len(expected) == len(catalog["packages"]) and expected, "Ambiguous source package catalog")
    packages = {}
    for proof in receipt["packages"]:
        identity = proof["identity"]
        key = tuple(identity[name] for name in ("name", "version", "base", "architecture"))
        require(key in expected and key not in packages, "Missing, additional or duplicate verified package identity")
        row = expected[key]
        require(proof["archive_sha256"] == row["sha256"] and proof["archive_bytes"] == row["bytes"], "Verified original archive differs from retained identity")
        codes = [line.split()[1] for line in proof["signature_status"].splitlines() if line.startswith("[GNUPG:] ") and len(line.split()) > 1]
        require("VALIDSIG" in codes and any(code in codes for code in ("TRUST_FULLY", "TRUST_ULTIMATE"))
                and not set(codes) & {"BADSIG", "ERRSIG", "REVKEYSIG", "EXPKEYSIG", "EXPSIG", "KEYEXPIRED", "SIGEXPIRED"}, "Original package signature did not pass trusted verification")
        raw = {}
        for name in (".PKGINFO", ".BUILDINFO", ".MTREE"):
            path = root / "metadata" / row["sha256"] / name
            require(path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1 and path.stat().st_size <= PROFILE["document_bytes"], "Original package metadata is missing or unsafe")
            raw[name] = path.read_bytes()
            require(hashlib.sha256(raw[name]).hexdigest() == proof["metadata"][name], "Captured original package metadata changed")
        binding = metadata_binding(raw, identity)
        require(binding["pkgbuild_sha256"] == proof["pkgbuild_sha256"], "Captured producer binding differs")
        packages[key] = binding
    require(set(packages) == set(expected), "Not every original package was verified")
    components = {}
    for proof in receipt["packages"]:
        entry = proof["file_inventory"]
        require(entry["path"] == "package-files/" + proof["archive_sha256"] + ".json.gz" and entry["path"] not in components,
                "Original file inventory identity differs")
        components[entry["path"]] = (entry, {"inventory": True})
    recipe_keys = set()
    for recipe in receipt["recipes"]:
        key = recipe["base"], recipe["version"], recipe["pkgbuild_sha256"]
        require(key not in recipe_keys, "Duplicate complete source recipe")
        recipe_keys.add(key)
        require(re.fullmatch(r"[0-9a-f]{40}", recipe["packaging_commit"]), "Source recipe lacks exact packaging commit")
        process = recipe.get("source_process", {})
        status = process.get("status", {})
        require(process.get("uid") == process.get("euid") == 65534 and process.get("groups") == []
                and status.get("NoNewPrivs") == "1" and set(status) == {"NoNewPrivs", "CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb"}
                and all(isinstance(value, str) and re.fullmatch(r"0+", value) for key, value in status.items() if key.startswith("Cap")),
                "Fetched recipe ran with unverified privileges")
        for entry, path in ((recipe["recipe"], "PKGBUILD"), (recipe["source"], recipe["base"] + "/PKGBUILD")):
            require(entry["path"] not in components, "Source component path is duplicated")
            required_members = []
            if entry == recipe["source"]:
                names = recipe.get("source_members")
                require(isinstance(names, list) and len(names) == len(set(names)) and all(isinstance(name, str) and name and "/" not in name and name not in {".", ".."} for name in names),
                        "Declared source member inventory is missing or unsafe")
                required_members = [recipe["base"] + "/.SRCINFO"] + [recipe["base"] + "/" + name for name in names]
            components[entry["path"]] = (entry, {"recipe_path": path, "recipe_hash": recipe["pkgbuild_sha256"], "required_members": required_members})
    require(recipe_keys == {(key[2], key[1], value["pkgbuild_sha256"]) for key, value in packages.items()}, "Complete sources do not cover every original producer recipe")
    upstream_expected = {"llama.cpp": PROFILE["source_commit"], "archlinux-docker": "d9f7a01562208910488140c54ffe402c3e7a231e"}
    upstream_seen = set()
    upstream_files = {}
    for upstream in receipt["upstream"]:
        name = upstream["name"]
        require(name in upstream_expected and name not in upstream_seen and upstream["commit"] == upstream_expected[name], "Upstream source identity differs")
        raw = upstream["commit_object"].encode()
        require(hashlib.sha1(b"commit " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == upstream["commit"], "Upstream commit object hash differs")
        require(raw.splitlines()[0] == ("tree " + upstream["tree"]).encode(), "Upstream commit does not bind this tree")
        require(name != "llama.cpp" or upstream["tree"] == PROFILE["source_tree"], "llama.cpp source tree differs")
        upstream_seen.add(name)
        entry = upstream["source"]
        require(entry["path"] not in components, "Duplicate upstream source component")
        components[entry["path"]] = (entry, {"tree": upstream["tree"], "upstream_name": name})
    require(upstream_seen == set(upstream_expected), "Required upstream sources are incomplete")
    seen = set()
    group_names = set()
    total = 0
    for group in receipt["source_archives"]:
        name = group["name"]
        require(re.fullmatch(r"llamacpp-source-packages-[0-9]{2}\.tar", name) and name not in group_names, "Invalid or duplicate complete source group")
        group_names.add(name)
        path = root / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1 and path.stat().st_size == group["bytes"] <= PROFILE["asset_bytes"], "Complete source group size differs")
        require(hash_file(path) == group["sha256"], "Complete source group hash differs")
        total += group["bytes"]
        require(total <= PROFILE["source_bytes"], "Complete source delivery exceeds approved bound")
        with tarfile.open(path, "r:", tarinfo=BoundedTarInfo) as archive:
            for member in archive:
                require(member.isfile() and member.name in components and member.name not in seen, "Unexpected source group member")
                seen.add(member.name)
                entry, arguments = components[member.name]
                require(entry["archive"] == name and member.size == entry["bytes"], "Source component boundary differs")
                with archive.extractfile(member) as content:
                    if arguments.get("inventory"):
                        for record in inventory_records(content, entry, deadline):
                            pass
                    else:
                        parameters = {key: value for key, value in arguments.items() if key != "upstream_name"}
                        identities = inspect_component(content, entry, deadline, **parameters)
                        if "upstream_name" in arguments:
                            upstream_files[arguments["upstream_name"]] = identities
    require(seen == set(components), "A complete source component is missing")
    return {"status": "source-validation-passed", "verified_packages": len(packages), "verified_recipes": len(recipe_keys),
            "catalog_sha256": receipt["catalog_sha256"], "acquisition_sha256": hash_file(root / "acquisition.json"),
            "source_archives": receipt["source_archives"], "source_bytes": total, "upstream_files": upstream_files}


def copy_sources(prefix, image_id, destination, environment, deadline):
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", image_id), "Invalid exact source image")
    require(not destination.exists(), "Source handoff directory must be new")
    name = "ve-native-source-export"
    command = prefix + ["create", "--name=" + name, "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--entrypoint=/bin/true", image_id]
    subprocess.run(command, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=min(90, deadline - time.monotonic()))
    destination.mkdir(mode=0o700)
    process = None
    try:
        process = subprocess.Popen(prefix + ["cp", name + ":/ve-source-export/.", "-"], env=environment, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        seen, total, metadata_total = set(), 0, 0
        with tarfile.open(fileobj=process.stdout, mode="r|", tarinfo=BoundedTarInfo) as archive:
            for member in archive:
                path = safe_path(member.name)
                if not path and member.isdir():
                    continue
                require(len(seen) < 4096 and path not in seen and time.monotonic() < deadline, "Source copy exceeded member/deadline bound")
                seen.add(path)
                directory = path == "metadata" or re.fullmatch(r"metadata/[0-9a-f]{64}", path)
                if member.isdir():
                    require(directory, "Unexpected source directory")
                    (destination / path).mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                source = bool(re.fullmatch(r"llamacpp-source-packages-[0-9]{2}\.tar", path))
                metadata = path == "acquisition.json" or re.fullmatch(r"metadata/[0-9a-f]{64}/\.(PKGINFO|BUILDINFO|MTREE)", path)
                require(member.isfile() and (source or metadata), "Unexpected source handoff object")
                require(0 < member.size <= (PROFILE["asset_bytes"] if source else PROFILE["document_bytes"]), "Source handoff file exceeds limit")
                total += member.size
                if not source:
                    metadata_total += member.size
                require(total <= PROFILE["source_bytes"] + PROFILE["metadata_bytes"] and metadata_total <= PROFILE["metadata_bytes"], "Source handoff exceeds approved envelope")
                output = destination / path
                output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with archive.extractfile(member) as stream, output.open("xb") as target:
                    remaining = member.size
                    while remaining:
                        require(time.monotonic() < deadline, "Source handoff deadline exceeded")
                        block = stream.read(min(remaining, 65536))
                        require(block, "Truncated source handoff file")
                        target.write(block)
                        remaining -= len(block)
        require(process.wait(timeout=max(1, deadline - time.monotonic())) == 0, "Source handoff command failed")
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        if process is not None and process.stdout is not None:
            process.stdout.close()
        subprocess.run(prefix + ["rm", "--force", "--ignore", name], env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=30)
import gzip
