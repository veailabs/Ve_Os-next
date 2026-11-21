import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile

from runner_resources import require


ROOT = Path(__file__).resolve().parent


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, "Duplicate input manifest key")
        result[name] = value
    return result


def input_manifest():
    manifest = json.loads((ROOT / "llamacpp-inputs.json").read_text(), object_pairs_hook=unique_object)
    require(set(manifest) == {"schema_version", "runtime", "status", "files"}, "Unexpected input manifest fields")
    require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1, "Unsupported input manifest")
    require(manifest["runtime"] == "llamacpp" and manifest["status"] == "reviewed-input-candidate-not-built", "Unexpected input profile")
    require(isinstance(manifest["files"], list) and 1 <= len(manifest["files"]) <= 64, "Invalid input count")
    names = set()
    total = 0
    for record in manifest["files"]:
        require(set(record) == {"path", "bytes", "sha256"}, "Unexpected input record fields")
        name = record["path"]
        require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", name), "Unsafe input path")
        path = PurePosixPath(name)
        require(not any(part in {".", "..", ".git"} for part in path.parts) and str(path) == name, "Unsafe input path")
        require(name not in names, "Duplicate input path")
        names.add(name)
        require(type(record["bytes"]) is int and 0 < record["bytes"] <= 16 * 1024 ** 2, "Invalid input size")
        require(isinstance(record["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", record["sha256"]), "Invalid input digest")
        total += record["bytes"]
    require(total <= 32 * 1024 ** 2, "Input context exceeds limit")
    require("Containerfile" in names and "packaging-LICENSE" in names, "Recipe or licence is missing")
    return manifest


def read_input(root, record):
    require(root.is_dir() and not root.is_symlink() and root.resolve() == root, "Noncanonical input root")
    path = root / record["path"]
    current = root
    for part in PurePosixPath(record["path"]).parts[:-1]:
        current = current / part
        require(current.is_dir() and not current.is_symlink(), "Linked input directory")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1, "Input must be an unlinked regular file")
        require(metadata.st_size == record["bytes"], "Input size mismatch: " + record["path"])
        data = source.read(record["bytes"] + 1)
        require(len(data) == record["bytes"] and hashlib.sha256(data).hexdigest() == record["sha256"],
                "Input digest mismatch: " + record["path"])
        return data


def verify_context(root, manifest):
    root = Path(root)
    expected = {record["path"] for record in manifest["files"]}
    actual = set()
    for parent, directories, files in os.walk(root, followlinks=False):
        for name in directories:
            require(not (Path(parent) / name).is_symlink(), "Linked directory in input context")
        for name in files:
            actual.add(str((Path(parent) / name).relative_to(root)))
    require(actual == expected, "Input context contains missing or unreviewed files")
    for record in manifest["files"]:
        read_input(root, record)
    return {"files": len(expected), "bytes": sum(record["bytes"] for record in manifest["files"]),
            "manifest_sha256": hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}


def stage_context(destination):
    manifest = input_manifest()
    source = ROOT / "llamacpp-context"
    proof = verify_context(source, manifest)
    destination = Path(destination)
    require(destination.parent.resolve(strict=True) == destination.parent, "Noncanonical staging parent")
    require(not destination.exists() and not destination.is_symlink(), "Staging destination already exists")
    destination.mkdir(mode=0o700)
    try:
        for record in manifest["files"]:
            target = destination / record["path"]
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with target.open("xb") as output:
                output.write(read_input(source, record))
            target.chmod(0o400)
        verify_context(destination, manifest)
    except BaseException:
        shutil.rmtree(destination)
        raise
    return proof


def context_archive(context):
    manifest = input_manifest()
    verify_context(context, manifest)
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for record in sorted(manifest["files"], key=lambda item: item["path"]):
            data = read_input(context, record)
            member = tarfile.TarInfo(record["path"])
            member.size = len(data)
            member.mode = 0o644
            member.mtime = 0
            member.uid = member.gid = 0
            member.uname = member.gname = ""
            archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


def write_context_archive(work):
    data = context_archive(work / "context")
    with (work / "context.tar").open("xb") as output:
        output.write(data)
    (work / "context.tar").chmod(0o400)
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def context_digest(work):
    data = context_archive(work / "context")
    digest = hashlib.sha256(data).hexdigest()
    read_input(work, {"path": "context.tar", "bytes": len(data), "sha256": digest})
    return digest
