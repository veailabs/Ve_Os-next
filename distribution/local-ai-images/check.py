from pathlib import Path
import subprocess
import sys

import publish


root = Path(__file__).resolve().parent
subprocess.run([sys.executable, str(root / "test_publish.py")], check=True)
sources = sorted(root.glob("*/source.json"))
publish.require(sources, "No actual image source records")
for path in sources:
    runtime = path.parent.name
    source = publish.source_record(runtime)
    if (path.parent / "source-delivery.json").exists():
        publish.source_delivery(runtime)
    if (path.parent / "release.json").exists():
        publish.release_record(runtime, source)
        print(runtime + ": source and release records verified locally")
    else:
        print(runtime + ": exact source snapshot verified; publication record absent")
