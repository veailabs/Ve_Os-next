import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import native_builder as builder
import native_execution as execution
import native_process as process
from native_profile import PROFILE, QualificationError


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.unit = "ve-os-native-123-1.service"

    def tearDown(self):
        self.temporary.cleanup()

    def test_service_output_remains_plain_bounded_file_data(self):
        command = [sys.executable, "-c", "print('::warning::not a workflow command')"]
        with patch.object(execution, "controller_environment", return_value={"PATH": "/usr/bin:/bin"}):
            result = execution.bounded_service(command, self.root / "log", self.unit, time.monotonic() + 5)
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual((self.root / "log").read_text(), "::warning::not a workflow command\n")

    def test_log_overflow_stops_owned_unit_and_never_overfills_file(self):
        command = [sys.executable, "-c", "print('x'*128)"]
        with patch.object(execution, "controller_environment", return_value={"PATH": "/usr/bin:/bin"}), \
             patch.dict(PROFILE, {"document_bytes": 32}), patch.object(execution, "stop_unit") as stop:
            with self.assertRaisesRegex(QualificationError, "log exceeds"):
                execution.bounded_service(command, self.root / "log", self.unit, time.monotonic() + 5)
            stop.assert_called_once()
            self.assertEqual(stop.call_args.args[0], self.unit)
        self.assertLessEqual((self.root / "log").stat().st_size, 32)

    def test_deadline_stops_owned_unit_and_terminates_client(self):
        command = [sys.executable, "-c", "import time;time.sleep(30)"]
        with patch.object(execution, "controller_environment", return_value={"PATH": "/usr/bin:/bin"}), patch.object(execution, "stop_unit") as stop:
            with self.assertRaisesRegex(QualificationError, "deadline"):
                execution.bounded_service(command, self.root / "log", self.unit, time.monotonic() + 0.05)
            stop.assert_called_once()

    def test_cancellation_stops_unit_before_propagating(self):
        command = [sys.executable, "-c", "import time;time.sleep(30)"]
        with patch.object(execution, "controller_environment", return_value={"PATH": "/usr/bin:/bin"}), \
             patch.object(execution.selectors.DefaultSelector, "select", side_effect=execution.Cancelled("cancelled")), \
             patch.object(execution, "stop_unit") as stop:
            with self.assertRaises(execution.Cancelled):
                execution.bounded_service(command, self.root / "log", self.unit, time.monotonic() + 5)
            stop.assert_called_once()

    def test_existing_log_is_not_overwritten(self):
        log = self.root / "log"
        log.write_text("retain evidence")
        with patch.object(execution.subprocess, "Popen") as launch:
            with self.assertRaises(FileExistsError):
                execution.bounded_service(["unused"], log, self.unit, time.monotonic() + 5)
            launch.assert_not_called()
        self.assertEqual(log.read_text(), "retain evidence")

    def test_failed_service_never_reports_success(self):
        with patch.object(execution, "controller_environment", return_value={"PATH": "/usr/bin:/bin"}), patch.object(execution, "stop_unit"):
            with self.assertRaisesRegex(QualificationError, "successfully"):
                execution.bounded_service([sys.executable, "-c", "raise SystemExit(2)"], self.root / "log", self.unit, time.monotonic() + 5)

    def test_missing_unit_is_clean_but_missing_user_bus_is_not(self):
        absent = subprocess.CompletedProcess([], 4, b"LoadState=not-found\nActiveState=inactive\n", b"Unit not found")
        with patch.object(process, "controller_environment", return_value={}), patch.object(process.subprocess, "run", return_value=absent) as call:
            process.stop_unit(self.unit, time.monotonic() + 5)
            self.assertEqual(call.call_count, 1)
        no_bus = subprocess.CompletedProcess([], 1, b"", b"Failed to connect to bus")
        with patch.object(process, "controller_environment", return_value={}), patch.object(process.subprocess, "run", return_value=no_bus):
            with self.assertRaises(QualificationError):
                process.stop_unit(self.unit, time.monotonic() + 5)

    def test_stop_verifies_post_stop_state(self):
        active = subprocess.CompletedProcess([], 0, b"LoadState=loaded\nActiveState=active\n", b"")
        stopped = subprocess.CompletedProcess([], 0, b"", b"")
        with patch.object(process, "controller_environment", return_value={}), patch.object(process.subprocess, "run", side_effect=[active, stopped, active]):
            with self.assertRaisesRegex(QualificationError, "remains active"):
                process.stop_unit(self.unit, time.monotonic() + 5)


class NativeEvidenceTests(unittest.TestCase):
    def proof(self):
        return {"status": "native-smoke-passed", "runtime": "llamacpp", "source_sha": "a" * 40,
                "unit": "ve-os-native-123-1.service", "base_digest": PROFILE["base"].split("@", 1)[1],
                "memory_max_bytes": PROFILE["build_memory_bytes"], "swap_max_bytes": 0,
                "namespaces": {name: value for value, name in enumerate(("user", "pid", "net", "ipc", "uts", "mnt", "cgroup"), 1)},
                "environment_names": ["PATH", "HOME", "LANG"]}

    def test_matching_kernel_probe_evidence_is_accepted(self):
        execution.validate_smoke(self.proof(), "a" * 40, "ve-os-native-123-1.service")

    def test_stale_or_incomplete_evidence_never_qualifies(self):
        for changes in ({"source_sha": "b" * 40}, {"unit": "ve-os-native-123-2.service"}, {"status": "pending"},
                        {"base_digest": "sha256:" + "0" * 64}, {"memory_max_bytes": 0}, {"swap_max_bytes": 1}, {"namespaces": {}},
                        {"environment_names": ["GITHUB_TOKEN"]}):
            with self.subTest(changes=changes), self.assertRaises(QualificationError):
                execution.validate_smoke({**self.proof(), **changes}, "a" * 40, "ve-os-native-123-1.service")

    def test_credential_environment_is_rejected_without_reporting_values(self):
        for name in ("GH_TOKEN", "ACTIONS_RUNTIME_TOKEN", "SSH_AUTH_SOCK", "AWS_SESSION_TOKEN", "HTTPS_PROXY", "MY_SECRET"):
            with self.subTest(name=name), self.assertRaises(QualificationError) as raised:
                builder.validate_probe_environment((name + "=DO_NOT_REPORT_THIS_VALUE\0").encode())
            self.assertNotIn("DO_NOT_REPORT_THIS_VALUE", str(raised.exception))
        self.assertEqual(builder.validate_probe_environment(b"PATH=/usr/bin\0LANG=C\0"), ["LANG", "PATH"])

    def test_untrusted_document_links_and_duplicate_fields_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target = root / "source"
            target.write_text('{"status":"ready","status":"missing"}')
            with self.assertRaises(QualificationError):
                execution.read_document(target)
            target.write_text('{}')
            (root / "link").symlink_to(target)
            with self.assertRaises(OSError):
                execution.read_document(root / "link")
            os.link(target, root / "hardlink")
            with self.assertRaises(QualificationError):
                execution.read_document(target)

    def test_document_writer_never_overwrites_existing_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "proof.json"
            execution.write_document(path, {"original": True})
            with self.assertRaises(FileExistsError):
                execution.write_document(path, {"original": False})
            self.assertEqual(json.loads(path.read_text()), {"original": True})


if __name__ == "__main__":
    unittest.main()
