import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat

from native_profile import GIB, MIB, PROFILE, unit_name
from native_process import unit_state
from runner_resources import mounts, require, run


HOST_METADATA_BYTES = 16 * MIB
HOST_MARGIN_BYTES = 16 * MIB
ALIGNMENT_BYTES = 4 * MIB


def allocated_tree(root):
    require(root.is_dir() and not root.is_symlink() and root.resolve() == root, "Noncanonical checkout directory")
    device = root.stat().st_dev
    seen = set()
    total = 0
    for parent, directories, files in os.walk(root, followlinks=False):
        for path in [Path(parent)] + [Path(parent) / name for name in directories + files]:
            metadata = path.lstat()
            require(metadata.st_dev == device, "Checkout crosses filesystem boundary")
            require(stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode),
                    "Unsupported checkout file type")
            identity = (metadata.st_dev, metadata.st_ino)
            if identity not in seen:
                total += metadata.st_blocks * 512
                seen.add(identity)
    return total


def volume_budget(source_bytes):
    require(type(source_bytes) is int and source_bytes >= 0, "Invalid measured checkout size")
    maximum = PROFILE["disk_growth_bytes"] - source_bytes - HOST_METADATA_BYTES - HOST_MARGIN_BYTES
    capacity = maximum // ALIGNMENT_BYTES * ALIGNMENT_BYTES
    require(capacity >= GIB, "Checkout leaves insufficient bounded build space")
    return {"checkout_allocated_bytes": source_bytes, "loop_bytes": capacity,
            "host_metadata_bytes": HOST_METADATA_BYTES, "host_margin_bytes": HOST_MARGIN_BYTES,
            "total_ceiling_bytes": PROFILE["disk_growth_bytes"]}


def volume_root(runner_temp, run_id, attempt):
    require(os.getuid() > 0 and os.getuid() == os.geteuid(), "Non-root trusted runner setup required")
    require(runner_temp.is_dir() and runner_temp.resolve() == runner_temp and not runner_temp.is_symlink(),
            "Noncanonical runner temporary directory")
    require(runner_temp.stat().st_uid == os.getuid(), "Runner temporary directory has unexpected owner")
    return runner_temp / unit_name(run_id, attempt).removesuffix(".service")


def mounted_at(path):
    return [item for item in mounts(Path("/proc/self/mountinfo").read_text()) if item["path"] == str(path)]


def validate_image(image, receipt):
    require(image.resolve() == image and not image.is_symlink(), "Linked volume image")
    metadata = image.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_uid == os.getuid(),
            "Unexpected volume image type or owner")
    require(metadata.st_ino == receipt["image_inode"] and metadata.st_dev == receipt["image_device"], "Volume image identity changed")
    require(metadata.st_size == receipt["budget"]["loop_bytes"], "Volume image size changed")
    require(metadata.st_blocks * 512 >= metadata.st_size, "Volume image is not fully preallocated")
    require(metadata.st_blocks * 512 <= metadata.st_size + ALIGNMENT_BYTES, "Volume allocation exceeds allowance")
    return metadata


def validate_loop(record, device, image, metadata, size):
    require(record.get("name") == device and re.fullmatch(r"/dev/loop[0-9]+", device), "Unexpected loop device")
    require(record.get("back-file") == str(image), "Loop backing path changed")
    require(record.get("back-ino") == metadata.st_ino, "Loop backing inode changed")
    require(record.get("back-maj:min") == str(os.major(metadata.st_dev)) + ":" + str(os.minor(metadata.st_dev)),
            "Loop backing filesystem changed")
    require(record.get("offset") == 0 and record.get("sizelimit") == size and record.get("ro") is False,
            "Loop mapping differs from bounded image")


def loop_record(device, deadline=None):
    require(re.fullmatch(r"/dev/loop[0-9]+", device), "Unexpected loop device")
    result = json.loads(run(["sudo", "-n", "losetup", "--list", "--json", "--output",
                             "NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN,OFFSET,SIZELIMIT,RO", "--", device], deadline=deadline))
    require(len(result.get("loopdevices", [])) == 1, "Owned loop mapping is missing or ambiguous")
    return result["loopdevices"][0]


def validate_mount(entries, mountpoint, device):
    require(len(entries) == 1, "Owned mount is missing or ambiguous")
    entry = entries[0]
    require(entry["path"] == str(mountpoint) and entry["source"] == device and entry["type"] == "ext4" and entry["root"] == "/",
            "Unexpected mounted filesystem")
    require({"rw", "nosuid", "nodev"}.issubset(set(entry["options"])), "Missing required mount options")


def save_receipt(root, receipt):
    path = root / "volume.json"
    require(not path.is_symlink(), "Linked volume receipt")
    encoded = json.dumps(receipt, indent=2).encode() + b"\n"
    require(len(encoded) <= PROFILE["document_bytes"], "Volume receipt exceeds limit")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        metadata = os.fstat(output.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_uid == os.getuid(), "Linked or invalid volume receipt")
        output.truncate(0)
        output.write(encoded)


def create_volume(checkout, runner_temp, run_id, attempt, deadline=None):
    require(platform.system() == "Linux" and platform.machine() == PROFILE["architecture"], "Native Linux x64 setup required")
    root = volume_root(runner_temp, run_id, attempt)
    require(checkout != runner_temp and checkout not in runner_temp.parents and runner_temp not in checkout.parents,
            "Checkout and volume staging must be separate")
    require((checkout / ".git").is_dir() and not (checkout / ".git").is_symlink(), "Self-contained checkout required")
    require(not (checkout / ".git/objects/info/alternates").exists(), "Shared Git object storage is unsupported")
    budget = volume_budget(allocated_tree(checkout))
    require(shutil.disk_usage(runner_temp).free >= PROFILE["admission_free_bytes"], "Insufficient admission disk space")
    require(not root.exists() and not root.is_symlink(), "Volume run directory already exists")
    root.mkdir(mode=0o700)
    receipt = {"schema_version": 1, "run_id": run_id, "attempt": attempt, "budget": budget, "state": "preparing",
               "root_device": root.stat().st_dev, "root_inode": root.stat().st_ino, "loop_device": None, "checkout_path": str(checkout)}
    image = root / "volume.ext4"
    with image.open("xb") as output:
        os.fchmod(output.fileno(), 0o600)
        metadata = os.fstat(output.fileno())
        receipt.update(image_inode=metadata.st_ino, image_device=metadata.st_dev)
    save_receipt(root, receipt)
    run(["fallocate", "--length", str(budget["loop_bytes"]), "--", str(image)], deadline=deadline)
    validate_image(image, receipt)
    require(shutil.disk_usage(root).free >= PROFILE["disk_floor_bytes"] + HOST_METADATA_BYTES, "Insufficient remaining host free space")
    run(["/usr/sbin/mkfs.ext4", "-F", "-m", "0", "-E", "nodiscard,lazy_itable_init=0,lazy_journal_init=0", str(image)], timeout=180, deadline=deadline)
    validate_image(image, receipt)
    device = run(["sudo", "-n", "losetup", "--find", "--show", "--sizelimit", str(budget["loop_bytes"]), "--", str(image)], deadline=deadline)
    require(re.fullmatch(r"/dev/loop[0-9]+", device), "Unexpected allocated loop device")
    receipt["loop_device"] = device
    save_receipt(root, receipt)
    validate_loop(loop_record(device, deadline=deadline), device, image, validate_image(image, receipt), budget["loop_bytes"])
    mountpoint = root / "filesystem"
    mountpoint.mkdir(mode=0o700)
    require(not mounted_at(mountpoint), "Volume mountpoint is already mounted")
    run(["sudo", "-n", "mount", "-t", "ext4", "-o", "nosuid,nodev", "--", device, str(mountpoint)], deadline=deadline)
    validate_mount(mounted_at(mountpoint), mountpoint, device)
    work = mountpoint / "build"
    run(["sudo", "-n", "mkdir", "--mode=0700", "--", str(work)], deadline=deadline)
    run(["sudo", "-n", "chown", str(os.getuid()) + ":" + str(os.getgid()), "--", str(work)], deadline=deadline)
    require(work.stat().st_uid == os.getuid() and work.stat().st_dev != root.stat().st_dev, "Build directory is not on the owned volume")
    require(os.statvfs(work).f_blocks * os.statvfs(work).f_frsize <= budget["loop_bytes"], "Mounted filesystem exceeds capacity")
    receipt["state"] = "mounted"
    save_receipt(root, receipt)
    return root, work, receipt


def remove_volume(runner_temp, receipt, deadline=None):
    root = volume_root(runner_temp, receipt["run_id"], receipt["attempt"])
    require(root.stat().st_dev == receipt["root_device"] and root.stat().st_ino == receipt["root_inode"], "Volume run directory identity changed")
    image = root / "volume.ext4"
    metadata = validate_image(image, receipt)
    device = receipt["loop_device"]
    require(device is not None, "Loop mapping was not established; retain setup evidence")
    validate_loop(loop_record(device, deadline=deadline), device, image, metadata, receipt["budget"]["loop_bytes"])
    unit = unit_name(receipt["run_id"], receipt["attempt"])
    state = unit_state(unit, deadline=deadline)
    require(state in {"inactive", "failed"}, "Build unit must be stopped before volume cleanup")
    mountpoint = root / "filesystem"
    entries = mounted_at(mountpoint)
    if entries:
        validate_mount(entries, mountpoint, device)
        run(["sudo", "-n", "umount", "--", str(mountpoint)], deadline=deadline)
        require(not mounted_at(mountpoint), "Owned filesystem remains mounted")
    validate_loop(loop_record(device, deadline=deadline), device, image, validate_image(image, receipt), receipt["budget"]["loop_bytes"])
    run(["sudo", "-n", "losetup", "--detach", device], deadline=deadline)
    remaining = json.loads(run(["sudo", "-n", "losetup", "--list", "--json", "--output", "NAME"], deadline=deadline))
    require(isinstance(remaining, dict) and isinstance(remaining.get("loopdevices"), list), "Invalid active loop inventory")
    require(all(isinstance(item, dict) and isinstance(item.get("name"), str) and re.fullmatch(r"/dev/loop[0-9]+", item["name"])
                for item in remaining["loopdevices"]), "Invalid active loop inventory entry")
    require(all(item.get("name") != device for item in remaining["loopdevices"]), "Loop mapping remains attached")
    validate_image(image, receipt)
    image.unlink()
    receipt["state"] = "removed"
    save_receipt(root, receipt)


def verify_work_volume(work, unit):
    require(work.name == "build" and work.parent.name == "filesystem", "Unexpected bounded build path")
    root = work.parent.parent
    path = root / "volume.json"
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_size <= PROFILE["document_bytes"],
                "Invalid bounded volume receipt")
        receipt = json.load(source)
    require(receipt["state"] == "mounted" and receipt["schema_version"] == 1, "Bounded volume is not ready")
    require(unit_name(receipt["run_id"], receipt["attempt"]) == unit, "Bounded volume belongs to another run")
    require(volume_root(root.parent, receipt["run_id"], receipt["attempt"]) == root, "Volume directory does not match run identity")
    require(root.stat().st_dev == receipt["root_device"] and root.stat().st_ino == receipt["root_inode"], "Volume root changed")
    require(receipt["budget"] == volume_budget(receipt["budget"]["checkout_allocated_bytes"]), "Volume budget changed")
    require(allocated_tree(Path(receipt["checkout_path"])) <= receipt["budget"]["checkout_allocated_bytes"], "Checkout grew after allocation")
    validate_image(root / "volume.ext4", receipt)
    validate_mount(mounted_at(work.parent), work.parent, receipt["loop_device"])
    require(work.stat().st_uid == os.getuid() and work.stat().st_dev != root.stat().st_dev, "Builder is outside bounded filesystem")
    require(os.statvfs(work).f_blocks * os.statvfs(work).f_frsize <= receipt["budget"]["loop_bytes"], "Filesystem capacity exceeds allocation")
    require(shutil.disk_usage(root).free >= PROFILE["disk_floor_bytes"], "Host disk floor reached")
    return receipt
