import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import native_volume as volume
from native_profile import GIB, PROFILE
from runner_resources import QualificationError


class VolumeBudgetTests(unittest.TestCase):
    def test_checkout_and_host_overhead_are_subtracted_before_allocation(self):
        small = volume.volume_budget(32 * 1024 ** 2)
        combined = volume.volume_budget(850 * 1024 ** 2)
        self.assertLess(combined["loop_bytes"], small["loop_bytes"])
        for budget in (small, combined):
            total = budget["checkout_allocated_bytes"] + budget["loop_bytes"] + budget["host_metadata_bytes"] + budget["host_margin_bytes"]
            self.assertLessEqual(total, PROFILE["disk_growth_bytes"])
            self.assertEqual(budget["loop_bytes"] % volume.ALIGNMENT_BYTES, 0)

    def test_oversized_or_invalid_checkout_is_not_silently_excluded(self):
        for size in (-1, True, "0", 8 * GIB):
            with self.subTest(size=size), self.assertRaises(QualificationError):
                volume.volume_budget(size)

    def test_actual_allocation_counts_git_and_does_not_follow_external_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            root = parent / "source"
            root.mkdir()
            (root / ".git").mkdir()
            (root / ".git/objects").write_bytes(b"a" * 8192)
            (root / "source").write_bytes(b"b" * 4096)
            (parent / "outside").write_bytes(b"c" * 65536)
            (root / "outside-link").symlink_to(parent / "outside")
            actual = volume.allocated_tree(root)
            expected = sum(path.lstat().st_blocks * 512 for path in (root, root / ".git", root / ".git/objects", root / "source", root / "outside-link"))
            self.assertEqual(actual, expected)

    def test_hardlinked_checkout_bytes_are_counted_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "source").write_bytes(b"b" * 4096)
            os.link(root / "source", root / "alias")
            self.assertEqual(volume.allocated_tree(root), root.stat().st_blocks * 512 + (root / "source").stat().st_blocks * 512)

    def test_special_checkout_files_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            os.mkfifo(root / "fifo")
            with self.assertRaises(QualificationError):
                volume.allocated_tree(root)


class VolumeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.device = "/dev/loop12"
        self.image = self.root / "volume.ext4"
        self.metadata = SimpleNamespace(st_ino=123, st_dev=os.makedev(8, 1))
        self.record = {"name": self.device, "back-file": str(self.image), "back-ino": 123,
                       "back-maj:min": "8:1", "offset": 0, "sizelimit": 4 * GIB, "ro": False}

    def tearDown(self):
        self.temporary.cleanup()

    def test_only_exact_kernel_backing_identity_is_accepted(self):
        volume.validate_loop(self.record, self.device, self.image, self.metadata, 4 * GIB)
        changes = ({"name": "/dev/sda"}, {"back-file": "/some/other/image"}, {"back-ino": 124},
                   {"back-maj:min": "8:2"}, {"offset": 4096}, {"sizelimit": 0}, {"ro": True})
        for change in changes:
            with self.subTest(change=change), self.assertRaises(QualificationError):
                volume.validate_loop({**self.record, **change}, self.device, self.image, self.metadata, 4 * GIB)

    def test_mount_source_and_security_options_are_checked(self):
        entry = {"path": str(self.root), "source": self.device, "type": "ext4", "root": "/", "options": ["rw", "nosuid", "nodev"]}
        volume.validate_mount([entry], self.root, self.device)
        for change in ({"source": "/dev/loop99"}, {"type": "overlay"}, {"root": "/another"}, {"options": ["rw"]}):
            with self.subTest(change=change), self.assertRaises(QualificationError):
                volume.validate_mount([{**entry, **change}], self.root, self.device)
        with self.assertRaises(QualificationError):
            volume.validate_mount([], self.root, self.device)

    def test_receipt_hardlink_rejected_before_any_existing_bytes_are_truncated(self):
        target = self.root / "important"
        target.write_text("preserve me")
        os.link(target, self.root / "volume.json")
        with self.assertRaises(QualificationError):
            volume.save_receipt(self.root, {"state": "new"})
        self.assertEqual(target.read_text(), "preserve me")

    def test_receipt_symlink_rejected_without_modifying_target(self):
        target = self.root / "important"
        target.write_text("preserve me")
        (self.root / "volume.json").symlink_to(target)
        with self.assertRaises(QualificationError):
            volume.save_receipt(self.root, {"state": "new"})
        self.assertEqual(target.read_text(), "preserve me")

    def test_changed_or_sparse_image_is_rejected(self):
        self.image.write_bytes(b"a" * 4096)
        metadata = self.image.stat()
        receipt = {"image_inode": metadata.st_ino, "image_device": metadata.st_dev, "budget": {"loop_bytes": 4096}}
        volume.validate_image(self.image, receipt)
        with self.assertRaises(QualificationError):
            volume.validate_image(self.image, {**receipt, "image_inode": metadata.st_ino + 1})
        with self.image.open("wb") as image:
            image.truncate(16 * 1024 ** 2)
        receipt["budget"]["loop_bytes"] = 16 * 1024 ** 2
        with self.assertRaisesRegex(QualificationError, "preallocated"):
            volume.validate_image(self.image, receipt)

    def test_setup_refuses_non_linux_before_creating_anything(self):
        with patch.object(volume.platform, "system", return_value="Darwin"), patch.object(volume, "run") as execute:
            with self.assertRaises(QualificationError):
                volume.create_volume(self.root, self.root, "123", "1")
            execute.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_changed_mount_prevents_unmount_or_detach(self):
        root = self.root / "run"
        root.mkdir()
        receipt = {"run_id": "123", "attempt": "1", "root_device": root.stat().st_dev,
                   "root_inode": root.stat().st_ino, "loop_device": self.device, "budget": {"loop_bytes": 4 * GIB}}
        entry = {"path": str(root / "filesystem"), "source": "/dev/loop99", "type": "ext4", "root": "/", "options": ["rw", "nosuid", "nodev"]}
        with patch.object(volume, "volume_root", return_value=root), patch.object(volume, "validate_image", return_value=self.metadata), \
             patch.object(volume, "loop_record", return_value=self.record), patch.object(volume, "validate_loop"), \
             patch.object(volume, "mounted_at", return_value=[entry]), patch.object(volume, "unit_state", return_value="inactive"), \
             patch.object(volume, "run") as execute:
            with self.assertRaises(QualificationError):
                volume.remove_volume(self.root, receipt)
            execute.assert_not_called()

    def test_active_build_prevents_any_mount_cleanup(self):
        root = self.root / "run"
        root.mkdir()
        receipt = {"run_id": "123", "attempt": "1", "root_device": root.stat().st_dev,
                   "root_inode": root.stat().st_ino, "loop_device": self.device, "budget": {"loop_bytes": 4 * GIB}}
        with patch.object(volume, "volume_root", return_value=root), patch.object(volume, "validate_image", return_value=self.metadata), \
             patch.object(volume, "loop_record", return_value=self.record), patch.object(volume, "validate_loop"), \
             patch.object(volume, "mounted_at") as mounted, patch.object(volume, "unit_state", return_value="active"), \
             patch.object(volume, "run") as execute:
            with self.assertRaisesRegex(QualificationError, "must be stopped"):
                volume.remove_volume(self.root, receipt)
            mounted.assert_not_called()
            execute.assert_not_called()

    def test_detached_device_node_does_not_block_image_removal_but_active_mapping_does(self):
        for remaining, removed in (({"loopdevices": [{"name": "/dev/loop99"}]}, True),
                                   ({"loopdevices": [{"name": self.device}]}, False), ({}, False), ([], False),
                                   ({"loopdevices": [{}]}, False), ({"loopdevices": [None]}, False),
                                   ({"loopdevices": [{"name": "/dev/sda"}]}, False), ({"loopdevices": [{"name": 1}]}, False)):
            with self.subTest(remaining=remaining):
                self.image.write_bytes(b"a" * 4096)
                metadata = self.image.stat()
                receipt = {"run_id": "123", "attempt": "1", "root_device": self.root.stat().st_dev,
                           "root_inode": self.root.stat().st_ino, "loop_device": self.device,
                           "image_inode": metadata.st_ino, "image_device": metadata.st_dev,
                           "budget": {"loop_bytes": 4096}, "state": "mounted"}
                record = {**self.record, "back-ino": metadata.st_ino,
                          "back-maj:min": str(os.major(metadata.st_dev)) + ":" + str(os.minor(metadata.st_dev)), "sizelimit": 4096}
                def execute(args, **kwargs):
                    if args == ["sudo", "-n", "losetup", "--detach", self.device]:
                        return ""
                    if args == ["sudo", "-n", "losetup", "--list", "--json", "--output", "NAME"]:
                        return json.dumps(remaining)
                    self.fail("Unexpected cleanup command: " + str(args))
                with patch.object(volume, "volume_root", return_value=self.root), \
                     patch.object(volume, "loop_record", return_value=record), \
                     patch.object(volume, "mounted_at", return_value=[]), \
                     patch.object(volume, "unit_state", return_value="inactive"), patch.object(volume, "run", side_effect=execute):
                    if removed:
                        volume.remove_volume(self.root, receipt)
                        self.assertEqual(json.loads((self.root / "volume.json").read_text())["state"], "removed")
                    else:
                        with self.assertRaises(QualificationError):
                            volume.remove_volume(self.root, receipt)
                self.assertEqual(self.image.exists(), not removed)


if __name__ == "__main__":
    unittest.main()
