import contextlib
import io
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
import runner_resources as runner
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

    def test_failed_smoke_emits_actual_service_log_and_retains_cleanup_error_chain(self):
        command = [sys.executable, "-c", "print('::warning::smoke failure evidence');raise SystemExit(2)"]
        environment = {"RUNNER_TEMP": str(self.root), "GITHUB_WORKSPACE": str(self.root / "checkout"),
                       "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}
        output = io.StringIO()
        with patch.dict(os.environ, environment), \
             patch.object(execution, "qualify", return_value=("a" * 40, "veailabs/Ve_Os-next", {})), \
             patch.object(execution.volume, "volume_root", return_value=self.root), \
             patch.object(execution.volume, "create_volume", return_value=(self.root, self.root / "work", {"state": "mounted"})), \
             patch.object(execution, "prepare_work", return_value={}), \
             patch.object(builder, "service_command", return_value=command), \
             patch.object(execution, "controller_environment", return_value={"PATH": "/usr/bin:/bin"}), \
             patch.object(execution, "stop_unit"), \
             patch.object(execution.volume, "remove_volume", side_effect=QualificationError("cleanup failed")), \
             contextlib.redirect_stdout(output):
            with self.assertRaises(QualificationError) as raised:
                execution.execute_smoke()
        report = json.loads(output.getvalue())
        self.assertEqual(report["stage"], "native-smoke")
        self.assertEqual(report["bounded_log_tail"], "::warning::smoke failure evidence\n")
        self.assertEqual([item["message"] for item in execution.failure_details(raised.exception)["failures_latest_first"]],
                         ["cleanup failed", "Native service did not complete successfully"])

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
    def test_cli_returns_failure_and_reports_primary_and_cleanup_errors(self):
        program = '''import sys
from unittest.mock import patch
import native_execution as execution
from native_profile import QualificationError
def fail():
    try:
        raise QualificationError("primary smoke failure")
    finally:
        raise QualificationError("secondary cleanup failure")
sys.argv=["native_execution.py","smoke"]
with patch.object(execution,"execute_smoke",side_effect=fail):
    raise SystemExit(execution.main())
'''
        result = subprocess.run([sys.executable, "-c", program], cwd=Path(execution.__file__).parent,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        diagnostic = json.loads(result.stderr.split("Native execution failed: ", 1)[1])
        self.assertEqual([item["message"] for item in diagnostic["failures_latest_first"]],
                         ["secondary cleanup failure", "primary smoke failure"])

    def test_primary_failure_survives_cleanup_failure_in_diagnostics(self):
        try:
            try:
                raise QualificationError("native smoke failed")
            finally:
                raise QualificationError("cleanup failed")
        except QualificationError as error:
            report = execution.failure_details(error)
        self.assertEqual([entry["message"] for entry in report["failures_latest_first"]],
                         ["cleanup failed", "native smoke failed"])

    def test_failure_log_tail_is_bounded_and_workflow_commands_remain_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "native-smoke.log"
            path.write_text("a" * 40000 + "\n::warning::untrusted output\n")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                execution.report_failure_log(path)
            lines = output.getvalue().splitlines()
            self.assertEqual(len(lines), 1)
            report = json.loads(lines[0])
            self.assertEqual(len(report["bounded_log_tail"]), 32768)
            self.assertIn("\n::warning::untrusted output\n", report["bounded_log_tail"])
            link = Path(temporary) / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                execution.report_failure_log(link)

    def test_fixed_platform_command_reports_bounded_escaped_stderr_without_general_arguments(self):
        failed = subprocess.CompletedProcess([], 1, "", "\n::warning::platform error\n" + "x" * 3000)
        with patch.object(runner.subprocess, "run", return_value=failed):
            with self.assertRaises(QualificationError) as raised:
                runner.run(["sudo", "-n", "losetup", "--detach", "--", "/dev/loop12"])
            diagnostic = json.loads(str(raised.exception).split(": ", 1)[1])
            self.assertEqual(diagnostic["command"], "sudo losetup")
            self.assertEqual(diagnostic["exit_code"], 1)
            self.assertEqual(len(diagnostic["stderr"]), 2048)
            self.assertNotIn("\n", str(raised.exception))
            with self.assertRaises(QualificationError) as raised:
                runner.run(["git", "DO_NOT_REPORT_ARGUMENT"])
            self.assertNotIn("DO_NOT_REPORT_ARGUMENT", str(raised.exception))
            self.assertNotIn("stderr", str(raised.exception))

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
