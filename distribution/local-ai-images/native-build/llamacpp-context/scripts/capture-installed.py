import hashlib
import json
from pathlib import Path
import stat


root = Path("/out")
files = {}
for path in sorted(root.rglob("*")):
    metadata = path.lstat()
    name = path.relative_to(root).as_posix()
    if stat.S_ISDIR(metadata.st_mode):
        continue
    entry = {"mode": stat.S_IMODE(metadata.st_mode), "uid": metadata.st_uid, "gid": metadata.st_gid}
    if stat.S_ISREG(metadata.st_mode):
        with path.open("rb") as source:
            entry.update(kind="file", sha256=hashlib.file_digest(source, "sha256").hexdigest())
    elif stat.S_ISLNK(metadata.st_mode):
        entry.update(kind="symlink", target=str(path.readlink()))
    else:
        raise RuntimeError("Unsupported installed output: " + name)
    files[name] = entry
encoded = json.dumps(files, sort_keys=True, indent=2).encode() + b"\n"
if not files or len(encoded) > 4 * 1024 ** 2:
    raise RuntimeError("Installed output evidence exceeds bound or is empty")
Path("/evidence/installed-output-files.json").write_bytes(encoded)
