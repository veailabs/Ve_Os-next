import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import time
import unittest

import arch_inventory
import native_image
from test_arch_inventory import layer, package


class ImageCorrespondenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.context = self.root / "context"
        self.context.mkdir()
        payload = b"compiled executable"
        self.compiled = {"usr/bin/llama-server": {"kind": "file", "mode": 0o644, "uid": 0, "gid": 0, "sha256": hashlib.sha256(payload).hexdigest()}}
        self.files = {**package(), "usr/bin/llama-server": payload,
                      "usr/share/ve-os-local-ai/installed-output-files.json": json.dumps(self.compiled).encode()}
        original = {"path": "usr/bin/fixture", "kind": "file", "mode": 0o644, "uid": 0, "gid": 0, "sha256": hashlib.sha256(b"first").hexdigest()}
        content = gzip.compress(json.dumps(original).encode() + b"\n", mtime=0)
        self.entry = {"archive": "original-files.tar", "path": "package-files/fixture.json.gz", "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        with tarfile.open(self.root / self.entry["archive"], "w") as archive:
            member = tarfile.TarInfo(self.entry["path"])
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        mtree = self.files[arch_inventory.PACKAGE_ROOT + "fixture-1-1/mtree"]
        receipt = {"packages": [{"identity": {"name": "fixture", "base": "fixture", "version": "1-1", "architecture": "x86_64"},
                                 "metadata": {".MTREE": hashlib.sha256(mtree).hexdigest()}, "file_inventory": self.entry}]}
        (self.root / "acquisition.json").write_text(json.dumps(receipt))

    def verify(self, files):
        observed = arch_inventory.observe_layers([layer(files)])
        return native_image.verify_package_files(observed, self.root, self.context, {"upstream_files": {"llama.cpp": {}}}, time.monotonic() + 10)

    def test_actual_package_and_captured_compiler_bytes_are_explained(self):
        result = self.verify(self.files)
        self.assertTrue(result["complete"])
        self.assertEqual(result["matched_physical_paths"], 1)

    def test_same_package_metadata_does_not_hide_modified_file(self):
        result = self.verify({**self.files, "usr/bin/fixture": b"changed code"})
        self.assertFalse(result["complete"])
        self.assertEqual(result["unexplained_paths"][0]["reason"], "modified-package-file")

    def test_arbitrary_binary_under_evidence_directory_is_not_exempted(self):
        result = self.verify({**self.files, "usr/share/ve-os-local-ai/hidden-executable": b"not declared"})
        self.assertFalse(result["complete"])
        self.assertEqual(result["unexplained_paths"][0]["path"], "usr/share/ve-os-local-ai/hidden-executable")

    def test_compiler_manifest_does_not_cover_changed_output(self):
        result = self.verify({**self.files, "usr/bin/llama-server": b"other code"})
        self.assertFalse(result["complete"])
        self.assertEqual(result["unexplained_paths"][0]["path"], "usr/bin/llama-server")


if __name__ == "__main__":
    unittest.main()
