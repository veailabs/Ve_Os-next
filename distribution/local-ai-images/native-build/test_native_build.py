import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import native_profile as profile
import runner_resources as runner


class RunnerIdentityTests(unittest.TestCase):
    def setUp(self):
        self.environment = {"GITHUB_ACTIONS": "true", "VERIFIED_RUNNER_ENVIRONMENT": "github-hosted",
                            "GITHUB_REPOSITORY_ID": "1465654995", "GITHUB_REF": "refs/heads/master",
                            "VERIFIED_REF_PROTECTED": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
                            "GITHUB_REPOSITORY": "veailabs/VE-OS", "GITHUB_SHA": "a" * 40,
                            "EXPECTED_ARCH": "x86_64", "RECLAIM_TOOLS": "false"}
        self.event = {"repository": {"id": 1465654995, "private": False, "full_name": "veailabs/VE-OS"}}

    def validate(self, **changes):
        arguments = {"environment": self.environment, "event": self.event, "system": "Linux",
                     "architecture": "x86_64", "head": "a" * 40}
        arguments.update(changes)
        return runner.validate_identity(**arguments)

    def test_actual_public_native_dispatch_identity_is_accepted(self):
        self.assertEqual(self.validate(), "veailabs/VE-OS")

    def test_temporary_same_repository_identity_is_accepted(self):
        self.environment["GITHUB_REPOSITORY"] = "veailabs/Ve_Os-next"
        self.event["repository"]["full_name"] = "veailabs/Ve_Os-next"
        self.assertEqual(self.validate(), "veailabs/Ve_Os-next")

    def test_old_fork_name_is_rejected_even_with_matching_event(self):
        self.environment["GITHUB_REPOSITORY"] = "veailabs/Ve_Os"
        self.event["repository"]["full_name"] = "veailabs/Ve_Os"
        with self.assertRaises(runner.QualificationError):
            self.validate()

    def test_untrusted_execution_contexts_are_rejected(self):
        changes = {"GITHUB_ACTIONS": "false", "VERIFIED_RUNNER_ENVIRONMENT": "self-hosted",
                   "GITHUB_REPOSITORY_ID": "1", "GITHUB_REF": "refs/heads/feature",
                   "VERIFIED_REF_PROTECTED": "false", "GITHUB_EVENT_NAME": "pull_request_target",
                   "GITHUB_REPOSITORY": "attacker/Ve_Os", "GITHUB_SHA": "main",
                   "EXPECTED_ARCH": "aarch64", "RECLAIM_TOOLS": "TRUE"}
        for name, value in changes.items():
            with self.subTest(name=name), self.assertRaises(runner.QualificationError):
                self.validate(environment={**self.environment, name: value})

    def test_event_repository_private_or_spoofed_identity_is_rejected(self):
        for change in ({"private": True}, {"id": 1}, {"id": "1465654995"},
                       {"full_name": "veailabs/other"}, {"private": "false"}):
            with self.subTest(change=change), self.assertRaises(runner.QualificationError):
                self.validate(event={"repository": {**self.event["repository"], **change}})

    def test_emulation_and_changed_checkout_are_rejected(self):
        for change in ({"architecture": "aarch64"}, {"system": "Darwin"}, {"head": "b" * 40}):
            with self.subTest(change=change), self.assertRaises(runner.QualificationError):
                self.validate(**change)

    def test_invalid_identity_never_measures_or_reclaims(self):
        with tempfile.TemporaryDirectory() as temporary:
            event = Path(temporary) / "event.json"
            event.write_text(json.dumps(self.event))
            environment = {**self.environment, "GITHUB_EVENT_PATH": str(event), "GITHUB_REF": "refs/pull/1/merge",
                           "RECLAIM_TOOLS": "true"}
            with patch.dict(os.environ, environment, clear=True), patch.object(runner.platform, "system", return_value="Linux"), \
                 patch.object(runner.platform, "machine", return_value="x86_64"), patch.object(runner, "run", return_value="a" * 40), \
                 patch.object(runner, "inventory") as inventory, patch.object(runner, "reclaim") as reclaim:
                with self.assertRaises(runner.QualificationError):
                    runner.main()
                inventory.assert_not_called()
                reclaim.assert_not_called()

    def test_moving_master_never_measures_or_reclaims(self):
        with tempfile.TemporaryDirectory() as temporary:
            event = Path(temporary) / "event.json"
            event.write_text(json.dumps(self.event))
            environment = {**self.environment, "GITHUB_EVENT_PATH": str(event), "RECLAIM_TOOLS": "true"}
            with patch.dict(os.environ, environment, clear=True), patch.object(runner.platform, "system", return_value="Linux"), \
                 patch.object(runner.platform, "machine", return_value="x86_64"), \
                 patch.object(runner, "run", side_effect=["a" * 40, "b" * 40 + "\trefs/heads/master"]), \
                 patch.object(runner, "inventory") as inventory, patch.object(runner, "reclaim") as reclaim:
                with self.assertRaisesRegex(runner.QualificationError, "master moved"):
                    runner.main()
                inventory.assert_not_called()
                reclaim.assert_not_called()


class ReclaimTests(unittest.TestCase):
    def test_non_allowlisted_path_is_rejected_even_when_absent(self):
        with self.assertRaisesRegex(runner.QualificationError, "allowlisted"):
            runner.validate_reclaim(Path("/tmp/no-such-sdk"), runner.reclaim_candidates("x86_64"), [])

    def test_symlink_and_non_directory_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target = root / "target"
            target.mkdir()
            link = root / "link"
            link.symlink_to(target)
            regular = root / "regular"
            regular.write_text("leave untouched")
            for path in (link, regular):
                with self.subTest(path=path), self.assertRaises(runner.QualificationError):
                    runner.validate_reclaim(path, [path], [])
            self.assertTrue(target.is_dir())
            self.assertEqual(regular.read_text(), "leave untouched")

    def test_nested_mount_or_mounted_sdk_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for mounted in (root, root / "nested"):
                with self.subTest(mounted=mounted), self.assertRaisesRegex(runner.QualificationError, "Mounted"):
                    runner.validate_reclaim(root, [root], [{"path": str(mounted)}])

    def test_parent_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "target").mkdir()
            (root / "target" / "sdk").mkdir()
            (root / "alias").symlink_to(root / "target", target_is_directory=True)
            path = root / "alias" / "sdk"
            with self.assertRaises(runner.QualificationError):
                runner.validate_reclaim(path, [path], [])

    def test_missing_sdk_is_skipped_and_safe_sdk_is_eligible(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            absent = root / "absent"
            self.assertFalse(runner.validate_reclaim(absent, [absent], []))
            self.assertTrue(runner.validate_reclaim(root, [root], []))

    def test_mount_escapes_are_decoded_before_safety_check(self):
        result = runner.mounts("1 2 3:4 / /sdk\\040tools rw - ext4 /dev/a rw\n")
        self.assertEqual(result[0]["path"], "/sdk tools")

    def test_arm_never_selects_x64_android_installation(self):
        self.assertNotIn(Path("/usr/local/lib/android"), runner.reclaim_candidates("aarch64"))
        with self.assertRaises(runner.QualificationError):
            runner.reclaim_candidates("riscv64")


class ResourceTests(unittest.TestCase):
    def report(self):
        return {"architecture": "x86_64", "filesystems": [{"path": "/tmp/build", "available_bytes": 12 * profile.GIB,
                                                          "available_inodes": 100000}],
                "memory": {"effective_available_bytes": 12 * profile.GIB},
                "available_cpus": [0, 1, 2, 3], "cgroup": {"version": 2},
                "tools": {name: "/usr/bin/" + name for name in ("podman", "git", "python3", "flock", "systemd-run", "skopeo")}}

    def test_sufficient_measured_capacity_is_not_build_qualification(self):
        result = profile.admission(self.report())
        self.assertTrue(result["resource_admission_passed"])
        self.assertFalse(result["build_qualified"])
        self.assertIn("complete Arch corresponding-source validation", result["remaining_checks"])

    def test_each_actual_filesystem_must_have_space(self):
        report = self.report()
        report["filesystems"].append({"path": "/separate-store", "available_bytes": 9 * profile.GIB, "available_inodes": 100})
        self.assertFalse(profile.admission(report)["resource_admission_passed"])

    def test_fail_closed_for_unmeasured_space_or_insufficient_memory(self):
        for changes in ({"filesystems": []}, {"memory": {"effective_available_bytes": 9 * profile.GIB}},
                        {"available_cpus": []}, {"architecture": "aarch64"}, {"cgroup": {"version": None}}, {"tools": {}}):
            with self.subTest(changes=changes):
                self.assertFalse(profile.admission({**self.report(), **changes})["resource_admission_passed"])

    def test_cgroup_parent_limit_overrides_large_host_and_child(self):
        text = "MemTotal: 16777216 kB\nMemAvailable: 12582912 kB\nSwapTotal: 4194304 kB\nSwapFree: 4194304 kB\n"
        groups = {"ancestors": [{"memory.max": str(12 * profile.GIB), "memory.current": str(profile.GIB)},
                                {"memory.max": str(8 * profile.GIB), "memory.current": str(2 * profile.GIB)}]}
        memory = runner.memory_inventory(text, groups)
        self.assertEqual(memory["effective_max_bytes"], 8 * profile.GIB)
        self.assertEqual(memory["effective_available_bytes"], 6 * profile.GIB)
        self.assertFalse(profile.admission({**self.report(), "memory": memory})["resource_admission_passed"])

    def test_host_memory_pressure_overrides_cgroup_headroom(self):
        text = "MemTotal: 16777216 kB\nMemAvailable: 1048576 kB\n"
        memory = runner.memory_inventory(text, {"ancestors": [{"memory.max": "max"}]})
        self.assertEqual(memory["effective_available_bytes"], profile.GIB)

    def test_unavailable_or_malformed_memory_never_qualifies(self):
        for text, groups in (("MemTotal: 16777216 kB\n", {"ancestors": []}),
                             ("MemTotal: 100 kB\nMemAvailable: 100 kB\n", {"ancestors": [{"memory.max": "bad"}]})):
            with self.assertRaises(runner.QualificationError):
                runner.memory_inventory(text, groups)

    def test_nested_cgroup_measurements_include_all_visible_ancestors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            child = root / "runner" / "build"
            child.mkdir(parents=True)
            (root / "memory.max").write_text(str(8 * profile.GIB))
            (root / "memory.current").write_text(str(profile.GIB))
            (child / "memory.max").write_text("max")
            groups = runner.cgroups("0::/runner/build\n", [{"root": "/", "path": str(root), "type": "cgroup2"}])
            self.assertEqual(len(groups["ancestors"]), 3)
            self.assertEqual(groups["ancestors"][-1]["memory.max"], str(8 * profile.GIB))

    def test_cgroup_membership_outside_mount_fails_closed(self):
        with self.assertRaises(runner.QualificationError):
            runner.cgroups("0::/outside\n", [{"root": "/different", "path": "/sys/fs/cgroup", "type": "cgroup2"}])

    def test_reclaim_executes_only_fixed_validated_sdk_path(self):
        target = Path("/usr/share/swift")
        with patch.object(runner, "reclaim_candidates", return_value=[target]), \
             patch.object(runner.Path, "read_text", return_value=""), \
             patch.object(runner, "validate_reclaim", return_value=True), \
             patch.object(runner.Path, "exists", return_value=False), \
             patch.object(runner.Path, "is_symlink", return_value=False), \
             patch.object(runner, "run", return_value="") as execute, patch.object(runner.os, "sync"):
            self.assertEqual(runner.reclaim("x86_64"), [str(target)])
            execute.assert_called_once_with(["sudo", "-n", "rm", "-rf", "--one-file-system", "--", str(target)], timeout=180)

    def test_reclaim_guard_failure_prevents_removal(self):
        with patch.object(runner, "reclaim_candidates", return_value=[Path("/usr/share/swift")]), \
             patch.object(runner.Path, "read_text", return_value=""), \
             patch.object(runner, "validate_reclaim", side_effect=runner.QualificationError("Mounted SDK")), \
             patch.object(runner, "run") as execute:
            with self.assertRaises(runner.QualificationError):
                runner.reclaim("x86_64")
            execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
