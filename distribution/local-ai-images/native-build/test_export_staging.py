from contextlib import contextmanager
import hashlib
import json
import os
import stat
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import native_export as export
import native_execution as execution
from native_profile import QualificationError


class ExportStagingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.work = self.root / "filesystem/build"
        self.work.mkdir(parents=True)
        source_root = self.work / "source-export"
        (source_root / "metadata").mkdir(parents=True)
        self.source = "a" * 40
        self.unit = "ve-os-native-123-1.service"
        payload = b"previously verified OCI fixture bytes"
        context = b"previously verified context fixture bytes"
        source_bytes = b"previously verified complete source fixture bytes"
        (self.work / "image.oci.tar").write_bytes(payload)
        (self.work / "context.tar").write_bytes(context)
        (source_root / "llamacpp-source-packages-01.tar").write_bytes(source_bytes)
        (source_root / "acquisition.json").write_text('{"fixture":true}')
        self.source_proof = {"status": "source-validation-passed", "source_sha": self.source, "unit": self.unit,
                             "context_sha256": hashlib.sha256(context).hexdigest(), "source_image_id": "sha256:" + "b" * 64,
                             "source_archives": [{"name": "llamacpp-source-packages-01.tar", "bytes": len(source_bytes), "sha256": hashlib.sha256(source_bytes).hexdigest()}]}
        self.image_proof = {"status": "image-validation-passed", "source_correspondence": {"complete": True}, "commands": [],
                            "source": {"schema_version": 1, "runtime": "llamacpp", "platform": "linux/amd64",
                                       "context_sha256": hashlib.sha256(context).hexdigest(), "image_digest": "sha256:" + "c" * 64,
                                       "config_digest": "sha256:" + "d" * 64, "archive_bytes": len(payload), "archive_sha256": hashlib.sha256(payload).hexdigest()}}
        self.save()
        (self.root / "native-smoke.json").write_text(json.dumps({"status": "native-smoke-passed", "source_sha": self.source, "unit": self.unit}))

    def save(self):
        (self.root / "source-validated.json").write_text(json.dumps(self.source_proof))
        (self.work / "image-validated.json").write_text(json.dumps(self.image_proof))

    def test_staging_moves_original_image_and_binds_complete_sources_and_evidence(self):
        inode = (self.work / "image.oci.tar").stat().st_ino
        staged, manifest = export.stage_export(self.work, self.source, "123", "1")
        self.assertEqual((staged / "image.oci.tar").stat().st_ino, inode)
        self.assertFalse((self.work / "image.oci.tar").exists())
        self.assertEqual(export.validate_manifest(manifest)["image"], self.image_proof["source"]["archive_bytes"])
        names = {asset["name"] for asset in manifest["assets"]}
        self.assertIn("llamacpp-source-context.tar", names)
        self.assertIn("llamacpp-source-evidence.tar.gz", names)
        delivery = json.loads((staged / "source-delivery.json").read_text())
        self.assertFalse(delivery["registry_publisher_compatible"])

    def test_incomplete_correspondence_cannot_be_staged(self):
        self.image_proof["source_correspondence"]["complete"] = False
        self.save()
        with self.assertRaisesRegex(QualificationError, "correspondence"):
            export.stage_export(self.work, self.source, "123", "1")
        self.assertFalse((self.work / "export-ready").exists())

    def test_previous_attempt_source_proof_cannot_authorize_export(self):
        self.source_proof["unit"] = "ve-os-native-123-2.service"
        self.save()
        with self.assertRaisesRegex(QualificationError, "matching validated source"):
            export.stage_export(self.work, self.source, "123", "1")

    def test_source_byte_change_after_validation_is_rejected(self):
        (self.work / "source-export/llamacpp-source-packages-01.tar").write_bytes(b"tampered source")
        with self.assertRaisesRegex(QualificationError, "Source bytes changed"):
            export.stage_export(self.work, self.source, "123", "1")

    def test_unlisted_freeze_file_is_rejected_before_privileged_mutation(self):
        staged, manifest = export.stage_export(self.work, self.source, "123", "1")
        (staged / "not-approved").write_text("unexpected")
        with patch("native_process.stop_unit"), patch("native_volume.verify_work_volume"), patch("runner_resources.run") as run:
            with self.assertRaisesRegex(QualificationError, "input set"):
                export.freeze_export(self.work, staged, manifest, time.monotonic() + 10)
            run.assert_not_called()

    @contextmanager
    def freeze_filesystem(self, staged, mutate=False):
        real_root = os.geteuid() == 0
        builder_uid = 65534 if real_root else os.getuid()
        path_stat, descriptor_stat = Path.stat, os.fstat
        owners = {}
        if real_root:
            for path in [staged, *staged.iterdir()]:
                os.chown(path, builder_uid, builder_uid)
        else:
            parent = path_stat(self.work.parent)
            owners[(parent.st_dev, parent.st_ino)] = (0, 0)

        def metadata(value):
            owner = owners.get((value.st_dev, value.st_ino))
            if owner is None:
                return value
            fields = list(value)
            fields[4:6] = owner
            return os.stat_result(fields)

        def execute(command, **kwargs):
            self.assertEqual(command[:2], ["sudo", "-n"])
            operation = command[2]
            if operation == "mv":
                self.assertEqual(command[3], "--")
                Path(command[4]).rename(command[5])
            elif operation == "chown":
                self.assertEqual(command[3:5], ["0:0", "--"])
                for value in command[5:]:
                    if real_root:
                        os.chown(value, 0, 0)
                    else:
                        current = path_stat(Path(value))
                        owners[(current.st_dev, current.st_ino)] = (0, 0)
            elif operation == "chmod":
                self.assertEqual(command[4], "--")
                for value in command[5:]:
                    Path(value).chmod(int(command[3], 8))
                if mutate and command[3] == "0555":
                    path = Path(command[5]) / "image.oci.tar"
                    path.chmod(0o644)
                    payload = path.read_bytes()
                    path.write_bytes(b"x" + payload[1:])
                    path.chmod(0o444)
            else:
                self.fail("Unexpected privileged operation")
            return ""

        with patch("native_process.stop_unit") as stop, patch("native_volume.verify_work_volume") as volume, \
             patch("runner_resources.run", side_effect=execute) as run, patch.object(export.os, "getuid", return_value=builder_uid), \
             patch.object(Path, "stat", lambda path, **kwargs: metadata(path_stat(path, **kwargs))), \
             patch.object(os, "fstat", lambda descriptor: metadata(descriptor_stat(descriptor))):
            yield run, stop, volume

    def test_successful_freeze_enforces_ownership_modes_and_verifies_every_descriptor(self):
        staged, manifest = export.stage_export(self.work, self.source, "123", "1")
        with self.freeze_filesystem(staged) as (run, stop, volume):
            with patch.object(export, "verify_stream", wraps=export.verify_stream) as verify:
                frozen = export.freeze_export(self.work, staged, manifest, time.monotonic() + 10)
            stop.assert_called_once()
            volume.assert_called_once_with(self.work, self.unit)
            self.assertEqual([call.args[0][2] for call in run.call_args_list], ["mv", "chown", "chmod", "chmod"])
            self.assertFalse(staged.exists())
            self.assertEqual(frozen.stat().st_uid, 0)
            self.assertEqual(stat.S_IMODE(frozen.stat().st_mode), 0o555)
            for path in frozen.iterdir():
                self.assertEqual((path.stat().st_uid, path.stat().st_gid, stat.S_IMODE(path.stat().st_mode)), (0, 0, 0o444))
            self.assertEqual(export.load_manifest(frozen), manifest)
            self.assertEqual(verify.call_count, len(export.upload_assets(manifest)))
        frozen.chmod(0o755)

    def test_mutation_during_freeze_is_rejected_by_final_descriptor_verification(self):
        staged, manifest = export.stage_export(self.work, self.source, "123", "1")
        with self.freeze_filesystem(staged, mutate=True):
            with self.assertRaisesRegex(QualificationError, "Frozen asset bytes changed"):
                export.freeze_export(self.work, staged, manifest, time.monotonic() + 10)
        (self.work.parent / "frozen").chmod(0o755)

    def test_missing_environment_id_fails_before_any_allocation(self):
        with patch.object(execution, "workflow_identity", return_value=(self.source, "veailabs/VE-OS")), \
             patch.dict(execution.os.environ, {}, clear=True), patch.object(execution.volume, "create_volume") as allocate:
            with self.assertRaisesRegex(QualificationError, "environment ID"):
                execution.prepare_export()
            allocate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
