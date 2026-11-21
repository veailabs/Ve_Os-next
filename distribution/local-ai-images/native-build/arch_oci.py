from contextlib import ExitStack
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat
import tarfile

from arch_inventory import BoundedTarInfo, observe_layers
from native_profile import PROFILE, require


spec = importlib.util.spec_from_file_location("ve_os_reviewed_publisher", Path(__file__).resolve().parent.parent / "publish.py")
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


def image_inventory(path, context_sha256):
    require(re.fullmatch(r"[0-9a-f]{64}", context_sha256), "Invalid exact context digest")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= PROFILE["image_bytes"], "Invalid or oversized OCI output")
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode="r:", tarinfo=BoundedTarInfo) as archive:
            members = {}
            for member in archive:
                require(len(members) < 4096 and member.name not in members, "Duplicate or excessive outer OCI entries")
                directory = member.name in {"blobs", "blobs/sha256"} and member.isdir()
                regular = member.type == tarfile.REGTYPE and (member.name in {"index.json", "oci-layout"} or re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", member.name))
                require(directory or regular, "Unsafe outer OCI entry")
                members[member.name] = member

            def document(name):
                member = members.get(name)
                require(member is not None and member.isfile() and member.size <= PROFILE["document_bytes"], "Missing or oversized OCI document")
                return publisher.decode(archive.extractfile(member).read())

            index = document("index.json")
            require(isinstance(index, dict) and isinstance(index.get("manifests"), list) and len(index["manifests"]) == 1, "Expected one OCI image")
            image_digest = index["manifests"][0].get("digest", "")
            require(re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest), "Invalid OCI manifest identity")
            manifest = document("blobs/sha256/" + image_digest[7:])
            config_digest = manifest.get("config", {}).get("digest", "")
            require(re.fullmatch(r"sha256:[0-9a-f]{64}", config_digest), "Invalid OCI config identity")
            config = document("blobs/sha256/" + config_digest[7:])
            source = {"schema_version": 1, "runtime": PROFILE["runtime"], "platform": PROFILE["platform"],
                      "context_sha256": context_sha256, "archive_sha256": digest, "archive_bytes": before.st_size,
                      "image_digest": image_digest, "config_digest": config_digest}
            publisher.validate_oci(Path(path), source)
            with ExitStack() as opened:
                layers = [(layer["digest"], diff_id, opened.enter_context(archive.extractfile(members["blobs/sha256/" + layer["digest"][7:]])))
                          for layer, diff_id in zip(manifest["layers"], config["rootfs"]["diff_ids"])]
                inventory = observe_layers(layers)
        after = os.fstat(stream.fileno())
        current = os.stat(path, follow_symlinks=False)
        for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink"):
            require(getattr(before, field) == getattr(after, field) == getattr(current, field), "OCI output changed during validation")
    return {"source": source, "inventory": inventory}
