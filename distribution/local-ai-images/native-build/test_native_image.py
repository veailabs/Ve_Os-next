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
        directory = {"path": "usr/lib", "kind": "directory", "mode": 0o755, "uid": 0, "gid": 0}
        self.files[arch_inventory.PACKAGE_ROOT + "fixture-1-1/files"] = b"%FILES%\nusr/bin/fixture\nusr/lib/\n\n"
        content = gzip.compress(b"".join(json.dumps(item).encode() + b"\n" for item in (original, directory)), mtime=0)
        self.entry = {"archive": "original-files.tar", "path": "package-files/fixture.json.gz", "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        with tarfile.open(self.root / self.entry["archive"], "w") as archive:
            member = tarfile.TarInfo(self.entry["path"])
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        mtree = self.files[arch_inventory.PACKAGE_ROOT + "fixture-1-1/mtree"]
        receipt = {"packages": [{"identity": {"name": "fixture", "base": "fixture", "version": "1-1", "architecture": "x86_64"},
                                 "metadata": {".MTREE": hashlib.sha256(mtree).hexdigest()}, "file_inventory": self.entry}]}
        (self.root / "acquisition.json").write_text(json.dumps(receipt))

    def verify(self, files, directory=None):
        if directory is None:
            directory = tarfile.TarInfo("usr/lib")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
        observed = arch_inventory.observe_layers([layer(files, [directory])])
        return native_image.verify_package_files(observed, self.root, self.context, {"upstream_files": {"llama.cpp": {}}}, time.monotonic() + 10)

    def test_actual_package_and_captured_compiler_bytes_are_explained(self):
        result = self.verify(self.files)
        self.assertTrue(result["complete"])
        self.assertEqual(result["matched_physical_paths"], 2)

    def test_same_package_metadata_does_not_hide_modified_file(self):
        result = self.verify({**self.files, "usr/bin/fixture": b"changed code"})
        self.assertFalse(result["complete"])
        self.assertEqual(result["unexplained_paths"][0]["reason"], "modified-package-file")

    def test_reviewed_context_replacement_still_explains_changed_package_config(self):
        with tarfile.open(self.root / self.entry["archive"]) as archive:
            content = archive.extractfile(self.entry["path"]).read()
        content = gzip.compress(gzip.decompress(content).replace(b"usr/bin/fixture", b"etc/pacman.conf"), mtime=0)
        self.entry.update(bytes=len(content), sha256=hashlib.sha256(content).hexdigest())
        with tarfile.open(self.root / self.entry["archive"], "w") as archive:
            member = tarfile.TarInfo(self.entry["path"])
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        receipt = json.loads((self.root / "acquisition.json").read_text())
        receipt["packages"][0]["file_inventory"] = self.entry
        (self.root / "acquisition.json").write_text(json.dumps(receipt))
        ownership = arch_inventory.PACKAGE_ROOT + "fixture-1-1/files"
        self.files[ownership] = self.files[ownership].replace(b"usr/bin/fixture", b"etc/pacman.conf")
        del self.files["usr/bin/fixture"]
        self.files["etc/pacman.conf"] = b"reviewed pinned snapshot config"
        (self.context / "pacman.conf").write_bytes(self.files["etc/pacman.conf"])
        result = self.verify(self.files)
        self.assertTrue(result["complete"])
        self.assertTrue(any(item["path"] == "etc/pacman.conf" and item["source"] == "reviewed-context" for item in result["generated_paths"]))

    def test_package_directory_mode_owner_group_and_type_are_authenticated(self):
        for field, value in (("mode", 0o777), ("uid", 1000), ("gid", 1000), ("type", tarfile.REGTYPE)):
            directory = tarfile.TarInfo("usr/lib")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            setattr(directory, field, value)
            with self.subTest(field=field):
                result = self.verify(self.files, directory)
                self.assertFalse(result["complete"])
                self.assertEqual(result["unexplained_paths"], [{"layer": result["physical_packages"][0]["layers"][0],
                                                               "path": "usr/lib", "reason": "modified-package-file"}])

    def test_later_layer_cannot_change_authenticated_directory_permissions(self):
        original = tarfile.TarInfo("usr/lib")
        original.type = tarfile.DIRTYPE
        original.mode = 0o755
        modified = tarfile.TarInfo("usr/lib")
        modified.type = tarfile.DIRTYPE
        modified.mode = 0o777
        observed = arch_inventory.observe_layers([layer(self.files, [original]), layer({}, [modified])])
        result = native_image.verify_package_files(observed, self.root, self.context, {"upstream_files": {"llama.cpp": {}}}, time.monotonic() + 10)
        self.assertFalse(result["complete"])
        self.assertEqual(result["unexplained_paths"], [{"layer": observed["physical_files"][1]["layer"], "path": "usr/lib", "reason": "modified-package-file"}])

    def test_unowned_directory_requires_explicit_generated_parent_and_safe_metadata(self):
        observed = arch_inventory.observe_layers([layer(self.files)])
        entries = observed["physical_files"][0]["entries"]
        for path, mode, complete in (("unexplained", 0o755, False), ("usr/share/ve-os-local-ai", 0o755, True),
                                     ("usr/share/ve-os-local-ai", 0o777, False)):
            with self.subTest(path=path, mode=mode):
                entries[path] = {"kind": "directory", "mode": mode, "uid": 0, "gid": 0}
                result = native_image.verify_package_files(observed, self.root, self.context, {"upstream_files": {"llama.cpp": {}}}, time.monotonic() + 10)
                self.assertEqual(result["complete"], complete)
                del entries[path]

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
