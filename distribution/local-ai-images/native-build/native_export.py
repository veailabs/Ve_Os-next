import hashlib
import json
import os
from pathlib import Path
import re
import stat
import shutil
import tarfile

from native_inputs import unique_object
from native_profile import PROFILE, REPOSITORY_ID, require, unit_name


METADATA_NAMES = {"source.json", "source-delivery.json", "native-provenance.json"}


def canonical_manifest(manifest):
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def validate_manifest(manifest):
    expected = {"schema_version", "repository_id", "runtime", "platform", "source_commit", "run_id", "attempt",
                "image", "source_delivery_sha256", "assets"}
    require(isinstance(manifest, dict) and set(manifest) == expected, "Unexpected frozen manifest fields")
    require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1, "Unsupported frozen manifest schema")
    require(type(manifest["repository_id"]) is int and manifest["repository_id"] == REPOSITORY_ID, "Frozen repository differs")
    require(manifest["runtime"] == "llamacpp" and manifest["platform"] == "linux/amd64", "Frozen runtime differs")
    require(isinstance(manifest["source_commit"], str) and re.fullmatch(r"[0-9a-f]{40}", manifest["source_commit"]), "Invalid frozen source identity")
    unit_name(manifest["run_id"], manifest["attempt"])
    require(isinstance(manifest["source_delivery_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", manifest["source_delivery_sha256"]), "Invalid source delivery digest")
    image = manifest["image"]
    require(isinstance(image, dict) and set(image) == {"bytes", "sha256"} and type(image["bytes"]) is int and 0 < image["bytes"] <= PROFILE["image_bytes"], "Invalid image archive size")
    require(isinstance(image["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", image["sha256"]), "Invalid image archive digest")
    assets = manifest["assets"]
    require(isinstance(assets, list) and 1 <= len(assets) < PROFILE["asset_count"], "Invalid frozen asset count")
    names = set()
    totals = {"image": 0, "source": 0, "metadata": 0}
    image_index = 0
    metadata = set()
    for asset in assets:
        require(isinstance(asset, dict) and set(asset) == {"name", "path", "role", "offset", "bytes", "file_bytes", "sha256"}, "Unexpected frozen asset fields")
        name, path, role = asset["name"], asset["path"], asset["role"]
        require(isinstance(name, str) and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}", name) and name not in names, "Invalid or duplicate frozen asset name")
        require(isinstance(role, str) and role in totals and type(asset["bytes"]) is int and 0 < asset["bytes"] <= PROFILE["asset_bytes"], "Invalid frozen asset role or size")
        require(type(asset["offset"]) is int and asset["offset"] >= 0 and type(asset["file_bytes"]) is int, "Invalid frozen range")
        require(isinstance(asset["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", asset["sha256"]), "Invalid frozen digest")
        require(asset["offset"] + asset["bytes"] <= asset["file_bytes"], "Frozen asset range exceeds file")
        if role == "image":
            image_index += 1
            require(name == f"llamacpp-amd64.oci.tar.part{image_index:02}" and path == "image.oci.tar", "Unexpected image asset name")
            require(asset["offset"] == totals["image"] and asset["file_bytes"] == image["bytes"], "Image chunks are not a complete ordered archive")
        else:
            require(asset["offset"] == 0 and asset["file_bytes"] == asset["bytes"] and path == name, "Source and evidence assets must be complete files")
            if role == "source":
                require(re.fullmatch(r"llamacpp-source-[a-z0-9-]+\.tar(?:\.gz)?", name), "Unexpected source bundle name")
            else:
                require(name in METADATA_NAMES and asset["bytes"] <= PROFILE["document_bytes"], "Unexpected or oversized evidence")
                metadata.add(name)
                if name == "source-delivery.json":
                    require(asset["sha256"] == manifest["source_delivery_sha256"], "Source delivery digest differs")
        names.add(name)
        totals[role] += asset["bytes"]
    require(totals["image"] == image["bytes"] and totals["source"] > 0, "Image or complete source assets are missing")
    require(metadata == METADATA_NAMES, "Required evidence assets are missing")
    encoded = canonical_manifest(manifest)
    require(len(encoded) <= PROFILE["document_bytes"], "Frozen manifest exceeds document limit")
    totals["metadata"] += len(encoded)
    require(totals["source"] <= PROFILE["source_bytes"] and totals["metadata"] <= PROFILE["metadata_bytes"], "Frozen source or evidence exceeds cap")
    require(sum(totals.values()) <= PROFILE["export_bytes"], "Frozen export exceeds total cap")
    return totals


def validate_frozen_root(root):
    require(root.is_absolute() and root.resolve() == root and root.is_dir() and not root.is_symlink(), "Noncanonical frozen directory")
    for path in (root, root.parent):
        metadata = path.stat()
        require(metadata.st_uid == 0 and not metadata.st_mode & 0o022, "Frozen parent is writable by builder")
    require(not root.stat().st_mode & 0o222, "Frozen directory is not read-only")


def open_asset(root, asset):
    validate_frozen_root(root)
    path = root / asset["path"]
    require(path.parent == root and path.name == asset["path"], "Unsafe frozen file path")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    stream = None
    try:
        metadata = os.fstat(descriptor)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_uid == 0 and not metadata.st_mode & 0o222,
                "Frozen asset is not an immutable regular file")
        require(metadata.st_size == asset["file_bytes"], "Frozen file size changed")
        stream = os.fdopen(descriptor, "rb")
        stream.seek(asset["offset"])
        return stream
    except BaseException:
        if stream is None:
            os.close(descriptor)
        else:
            stream.close()
        raise


def verify_stream(stream, asset):
    stream.seek(asset["offset"])
    remaining = asset["bytes"]
    digest = hashlib.sha256()
    while remaining:
        data = stream.read(min(1024 * 1024, remaining))
        require(data, "Frozen asset was truncated")
        digest.update(data)
        remaining -= len(data)
    require(digest.hexdigest() == asset["sha256"], "Frozen asset bytes changed")
    stream.seek(asset["offset"])


def load_manifest(root):
    validate_frozen_root(root)
    path = root / "export-manifest.json"
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_uid == 0 and not metadata.st_mode & 0o222,
                "Frozen manifest is not immutable")
        require(0 < metadata.st_size <= PROFILE["document_bytes"], "Invalid frozen manifest size")
        data = source.read(PROFILE["document_bytes"] + 1)
        require(len(data) == metadata.st_size, "Frozen manifest changed while reading")
    manifest = json.loads(data, object_pairs_hook=unique_object)
    validate_manifest(manifest)
    require(data == canonical_manifest(manifest), "Frozen manifest encoding differs")
    return manifest


def upload_assets(manifest):
    validate_manifest(manifest)
    encoded = canonical_manifest(manifest)
    return manifest["assets"] + [{"name": "export-manifest.json", "path": "export-manifest.json", "role": "metadata",
                                  "offset": 0, "bytes": len(encoded), "file_bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}]


def release_tag(manifest):
    validate_manifest(manifest)
    return "ve-ai-build-llamacpp-" + manifest["source_commit"] + "-" + manifest["run_id"] + "-" + manifest["attempt"]


def stage_export(work, source_sha, run_id, attempt):
    from native_execution import read_document, write_document

    unit = unit_name(run_id, attempt)
    source_proof = read_document(work.parent.parent / "source-validated.json")
    image_proof = read_document(work / "image-validated.json")
    smoke = read_document(work.parent.parent / "native-smoke.json")
    require(source_proof.get("status") == "source-validation-passed" and source_proof.get("source_sha") == source_sha
            and source_proof.get("unit") == unit, "This attempt has no matching validated source")
    require(image_proof.get("status") == "image-validation-passed" and image_proof["source_correspondence"]["complete"] is True,
            "Image/source correspondence did not pass")
    require(smoke.get("status") == "native-smoke-passed" and smoke.get("source_sha") == source_sha and smoke.get("unit") == unit,
            "Native isolation evidence differs")
    source = image_proof["source"]
    require(source["context_sha256"] == source_proof["context_sha256"], "Source and runtime contexts differ")
    destination = work / "export-ready"
    require(not destination.exists(), "Export staging already exists")
    destination.mkdir(mode=0o700)
    source_files = []
    for archive in source_proof["source_archives"]:
        name = archive["name"]
        require(re.fullmatch(r"llamacpp-source-packages-[0-9]{2}\.tar", name), "Invalid validated source name")
        original = work / "source-export" / name
        require(original.is_file() and not original.is_symlink() and original.stat().st_nlink == 1, "Validated source is no longer a regular file")
        original.rename(destination / name)
        source_files.append(name)
    context_name = "llamacpp-source-context.tar"
    shutil.copyfile(work / "context.tar", destination / context_name)
    source_files.append(context_name)
    evidence_name = "llamacpp-source-evidence.tar.gz"
    with tarfile.open(destination / evidence_name, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
        evidence_files = [(work / "source-export/acquisition.json", "acquisition.json"),
                          (work.parent.parent / "source-validated.json", "source-validated.json"),
                          (work / "image-validated.json", "image-validated.json")]
        evidence_files += [(path, path.relative_to(work / "source-export").as_posix()) for path in sorted((work / "source-export/metadata").rglob("*")) if path.is_file()]
        total = 0
        for path, name in evidence_files:
            require(not path.is_symlink() and path.stat().st_nlink == 1, "Source evidence is linked")
            total += path.stat().st_size
            require(total <= PROFILE["metadata_bytes"], "Complete source evidence exceeds metadata limit")
            member = tarfile.TarInfo(name)
            member.size = path.stat().st_size
            member.mode = 0o644
            with path.open("rb") as stream:
                archive.addfile(member, stream)
    source_files.append(evidence_name)
    image = work / "image.oci.tar"
    require(image.is_file() and not image.is_symlink() and image.stat().st_nlink == 1 and image.stat().st_size == source["archive_bytes"], "Validated image changed")
    image.rename(destination / "image.oci.tar")
    asset_records = []
    for name in source_files:
        path = destination / name
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        asset_records.append({"name": name, "path": name, "role": "source", "offset": 0,
                              "bytes": path.stat().st_size, "file_bytes": path.stat().st_size, "sha256": digest})
    for expected in source_proof["source_archives"]:
        actual = next(asset for asset in asset_records if asset["name"] == expected["name"])
        require(actual["bytes"] == expected["bytes"] and actual["sha256"] == expected["sha256"], "Source bytes changed after validation")
    require(next(asset for asset in asset_records if asset["name"] == context_name)["sha256"] == source["context_sha256"], "Context bytes changed after validation")
    delivery = {"schema_version": 1, "status": "complete", "system_format": "arch-pacman", "runtime": "llamacpp",
                "image_digest": source["image_digest"], "context_sha256": source["context_sha256"],
                "source_archives": [{key: asset[key] for key in ("name", "bytes", "sha256")} for asset in asset_records],
                "system_inventory": image_proof["source_correspondence"], "producer_evidence": evidence_name,
                "registry_publisher_compatible": False}
    provenance = {"schema_version": 1, "source_commit": source_sha, "run_id": run_id, "attempt": attempt,
                  "context_sha256": source["context_sha256"], "native_smoke": smoke, "runtime_commands": image_proof["commands"],
                  "source_image_id": source_proof["source_image_id"], "gpu_qualification": False, "public_release": False}
    for name, value in (("source.json", source), ("source-delivery.json", delivery), ("native-provenance.json", provenance)):
        write_document(destination / name, value)
        content = (destination / name).read_bytes()
        asset_records.append({"name": name, "path": name, "role": "metadata", "offset": 0, "bytes": len(content),
                              "file_bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()})
    image_assets = []
    offset = 0
    whole = hashlib.sha256()
    with (destination / "image.oci.tar").open("rb") as stream:
        while offset < source["archive_bytes"]:
            size = min(PROFILE["asset_bytes"], source["archive_bytes"] - offset)
            remaining = size
            digest = hashlib.sha256()
            while remaining:
                block = stream.read(min(65536, remaining))
                require(block, "Validated image was truncated")
                digest.update(block)
                whole.update(block)
                remaining -= len(block)
            image_assets.append({"name": f"llamacpp-amd64.oci.tar.part{len(image_assets) + 1:02}", "path": "image.oci.tar", "role": "image",
                                 "offset": offset, "bytes": size, "file_bytes": source["archive_bytes"], "sha256": digest.hexdigest()})
            offset += size
    require(whole.hexdigest() == source["archive_sha256"], "Image bytes changed after validation")
    manifest = {"schema_version": 1, "repository_id": REPOSITORY_ID, "runtime": "llamacpp", "platform": "linux/amd64",
                "source_commit": source_sha, "run_id": run_id, "attempt": attempt,
                "image": {"bytes": source["archive_bytes"], "sha256": source["archive_sha256"]},
                "source_delivery_sha256": hashlib.sha256((destination / "source-delivery.json").read_bytes()).hexdigest(),
                "assets": asset_records + image_assets}
    validate_manifest(manifest)
    (destination / "export-manifest.json").write_bytes(canonical_manifest(manifest))
    return destination, manifest


def freeze_export(work, staged, manifest, deadline):
    from native_process import stop_unit
    from native_volume import verify_work_volume
    from runner_resources import run

    unit = unit_name(manifest["run_id"], manifest["attempt"])
    stop_unit(unit, deadline)
    verify_work_volume(work, unit)
    require(staged == work / "export-ready" and staged.resolve() == staged, "Unexpected freeze staging path")
    expected = {asset["path"] for asset in manifest["assets"]} | {"export-manifest.json"}
    require({path.name for path in staged.iterdir()} == expected, "Unexpected freeze input set")
    for path in staged.iterdir():
        metadata = path.lstat()
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_uid == os.getuid(), "Freeze input is linked or not builder-owned")
    frozen = work.parent / "frozen"
    require(not frozen.exists() and not frozen.is_symlink(), "Frozen export already exists")
    run(["sudo", "-n", "mv", "--", str(staged), str(frozen)], deadline=deadline)
    files = [str(frozen / name) for name in sorted(expected)]
    run(["sudo", "-n", "chown", "0:0", "--", str(frozen), *files], deadline=deadline)
    run(["sudo", "-n", "chmod", "0444", "--", *files], deadline=deadline)
    run(["sudo", "-n", "chmod", "0555", "--", str(frozen)], deadline=deadline)
    require(load_manifest(frozen) == manifest, "Frozen manifest changed")
    for asset in upload_assets(manifest):
        with open_asset(frozen, asset) as stream:
            verify_stream(stream, asset)
    return frozen
