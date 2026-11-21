import hashlib
import json
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

    def test_missing_environment_id_fails_before_any_allocation(self):
        with patch.object(execution, "workflow_identity", return_value=(self.source, "veailabs/Ve_Os-next")), \
             patch.dict(execution.os.environ, {}, clear=True), patch.object(execution.volume, "create_volume") as allocate:
            with self.assertRaisesRegex(QualificationError, "environment ID"):
                execution.prepare_export()
            allocate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
