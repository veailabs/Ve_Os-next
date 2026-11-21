import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import native_builder as builder
import native_inputs as inputs
import native_volume as volume
from native_profile import PROFILE
from runner_resources import QualificationError


class InputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.context = self.root / "llamacpp-context"
        self.context.mkdir()
        files = {"Containerfile": b"FROM scratch\n", "packaging-LICENSE": b"test licence\n", "scripts/build": b"test data\n"}
        records = []
        for name, data in files.items():
            path = self.context / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            records.append({"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        self.manifest = {"schema_version": 1, "runtime": "llamacpp", "status": "reviewed-input-candidate-not-built", "files": records}
        (self.root / "llamacpp-inputs.json").write_text(json.dumps(self.manifest))
        self.patcher = patch.object(inputs, "ROOT", self.root)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.temporary.cleanup()

    def test_exact_allowlisted_bytes_are_copied_to_fresh_staging_directory(self):
        destination = self.root / "stage"
        proof = inputs.stage_context(destination)
        self.assertEqual(proof["files"], 3)
        self.assertEqual(inputs.verify_context(destination, self.manifest), proof)
        self.assertEqual((destination / "scripts/build").read_bytes(), b"test data\n")
        self.assertFalse((destination / "Containerfile").stat().st_mode & 0o222)

    def test_context_tampering_fails_before_staging_exists(self):
        (self.context / "Containerfile").write_bytes(b"FROM changed\n")
        with self.assertRaises(QualificationError):
            inputs.stage_context(self.root / "stage")
        self.assertFalse((self.root / "stage").exists())

    def test_unreviewed_or_missing_files_are_rejected(self):
        secret = self.context / ".gitconfig"
        secret.write_text("unreviewed credential helper")
        with self.assertRaises(QualificationError):
            inputs.stage_context(self.root / "stage")
        secret.unlink()
        (self.context / "Containerfile").unlink()
        with self.assertRaises(QualificationError):
            inputs.stage_context(self.root / "stage")

    def test_symlink_file_never_reads_outside_context(self):
        path = self.context / "Containerfile"
        path.unlink()
        path.symlink_to(self.root / "outside")
        (self.root / "outside").write_text("private")
        with self.assertRaises((OSError, QualificationError)):
            inputs.stage_context(self.root / "stage")

    def test_hardlink_and_fifo_inputs_are_rejected(self):
        path = self.context / "Containerfile"
        os.link(path, self.root / "alias")
        with self.assertRaises(QualificationError):
            inputs.stage_context(self.root / "stage")
        path.unlink()
        os.mkfifo(path)
        with self.assertRaises(QualificationError):
            inputs.stage_context(self.root / "stage")

    def test_symlinked_input_directory_is_rejected(self):
        (self.context / "scripts").rename(self.root / "scripts")
        (self.context / "scripts").symlink_to(self.root / "scripts", target_is_directory=True)
        with self.assertRaises(QualificationError):
            inputs.stage_context(self.root / "stage")

    def test_existing_destination_is_never_replaced(self):
        destination = self.root / "stage"
        destination.mkdir()
        (destination / "keep").write_text("keep")
        with self.assertRaises(QualificationError):
            inputs.stage_context(destination)
        self.assertEqual((destination / "keep").read_text(), "keep")

    def test_linked_staging_parent_is_rejected(self):
        (self.root / "alias").symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(QualificationError):
            inputs.stage_context(self.root / "alias" / "stage")

    def test_path_traversal_or_duplicate_manifest_keys_are_rejected(self):
        for name in ("../secret", "/secret", "a/../secret", ".git/config", "a//b"):
            self.manifest["files"][0]["path"] = name
            (self.root / "llamacpp-inputs.json").write_text(json.dumps(self.manifest))
            with self.subTest(name=name), self.assertRaises(QualificationError):
                inputs.input_manifest()
        (self.root / "llamacpp-inputs.json").write_text('{"runtime":"llamacpp","runtime":"other"}')
        with self.assertRaises(QualificationError):
            inputs.input_manifest()

    def test_mid_copy_failure_removes_only_new_staging_directory(self):
        destination = self.root / "stage"
        original = inputs.read_input
        calls = 0
        def fail_later(root, record):
            nonlocal calls
            calls += 1
            if calls == 5:
                raise QualificationError("changed input")
            return original(root, record)
        with patch.object(inputs, "read_input", side_effect=fail_later):
            with self.assertRaises(QualificationError):
                inputs.stage_context(destination)
        self.assertFalse(destination.exists())
        self.assertTrue((self.context / "Containerfile").exists())

    def test_context_tar_is_deterministic_and_binds_staged_bytes(self):
        work = self.root / "work"
        work.mkdir()
        inputs.stage_context(work / "context")
        identity = inputs.write_context_archive(work)
        first = (work / "context.tar").read_bytes()
        self.assertEqual(inputs.context_digest(work), identity["sha256"])
        os.utime(work / "context" / "Containerfile", (12345, 54321))
        self.assertEqual(inputs.context_archive(work / "context"), first)
        (work / "context.tar").chmod(0o600)
        (work / "context.tar").write_bytes(b"changed")
        with self.assertRaises(QualificationError):
            inputs.context_digest(work)


class BuilderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.unit = "ve-os-native-123-1.service"
        self.group = self.root / self.unit
        (self.group / "supervisor").mkdir(parents=True)
        for name, value in {"memory.max": str(PROFILE["build_memory_bytes"]), "memory.swap.max": "0",
                            "cgroup.procs": "", "cgroup.controllers": "memory cpu pids"}.items():
            (self.group / name).write_text(value)
        self.groups = {"version": 2, "ancestors": [{"path": str(self.group / "supervisor")}, {"path": str(self.group)}]}

    def tearDown(self):
        self.temporary.cleanup()

    def test_builder_subprocess_receives_only_constructed_environment(self):
        with patch.dict(os.environ, {"GH_TOKEN": "test-never-forward", "ACTIONS_RUNTIME_TOKEN": "test-runtime",
                                    "SSH_AUTH_SOCK": "/test/socket", "HTTPS_PROXY": "https://test:password@proxy"}):
            environment = builder.isolated_environment(self.root, 1000)
            result = subprocess.run([sys.executable, "-c", "import json,os;print(json.dumps(dict(os.environ)))"],
                                    env=environment, capture_output=True, text=True, check=True)
        actual = json.loads(result.stdout)
        self.assertNotIn("GH_TOKEN", actual)
        self.assertNotIn("ACTIONS_RUNTIME_TOKEN", actual)
        self.assertNotIn("SSH_AUTH_SOCK", actual)
        self.assertNotIn("HTTPS_PROXY", actual)
        self.assertEqual(actual["HOME"], str(self.root / "home"))
        self.assertEqual(actual["REGISTRY_AUTH_FILE"], str(self.root / "empty-auth.json"))

    def test_root_and_linked_build_directory_are_rejected(self):
        with self.assertRaises(QualificationError):
            builder.isolated_environment(self.root, 0)
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(QualificationError):
            builder.isolated_environment(alias, 1000)

    def test_forged_source_and_run_identifiers_are_rejected(self):
        for run, attempt in (("1;touch x", "1"), ("0", "1"), ("1", "-1"), ("1/2", "1")):
            with self.subTest(run=run, attempt=attempt), self.assertRaises(QualificationError):
                builder.unit_name(run, attempt)
        for source, repository in (("master", "veailabs/Ve_Os"), ("a" * 40, "attacker/repo")):
            with self.assertRaises(QualificationError):
                builder.service_command(self.root, source, repository, "123", "1", 1000)

    def test_real_group_limits_are_read_not_assumed_from_requested_flags(self):
        self.assertEqual(builder.verify_group(self.groups, self.unit), self.group)
        for name, value in (("memory.max", "max"), ("memory.swap.max", "1"), ("cgroup.procs", "123"),
                            ("cgroup.controllers", "cpu pids")):
            path = self.group / name
            previous = path.read_text()
            path.write_text(value)
            with self.subTest(name=name), self.assertRaises(QualificationError):
                builder.verify_group(self.groups, self.unit)
            path.write_text(previous)

    def test_sibling_or_legacy_cgroup_cannot_claim_enforcement(self):
        with self.assertRaises(QualificationError):
            builder.verify_group({**self.groups, "version": 1}, self.unit)
        wrong = {**self.groups, "ancestors": [{"path": str(self.root / "other" / "supervisor")}, {"path": str(self.group)}]}
        with self.assertRaises(QualificationError):
            builder.verify_group(wrong, self.unit)

    def test_constructed_service_and_container_commands_have_no_credential_or_mount_channel(self):
        with patch.dict(os.environ, {"GH_TOKEN": "test-never-forward", "ACTIONS_RUNTIME_TOKEN": "test-runtime"}):
            service = builder.service_command(self.root, "a" * 40, "veailabs/Ve_Os-next", "123", "1", 1000)
            command = builder.container_command(self.root, "a" * 40, "veailabs/Ve_Os-next", Path("/user.slice/unit/containers"), "b" * 64)
        self.assertNotIn("test-never-forward", " ".join(service + command))
        self.assertNotIn("test-runtime", " ".join(service + command))
        for argument in command:
            self.assertFalse(argument.startswith(("--privileged", "--cap-add", "--volume", "--mount", "--secret", "--ssh")))
        for namespace in ("network", "pid", "ipc", "uts", "userns", "cgroupns"):
            self.assertNotIn("--" + namespace + "=host", command)
        self.assertIn("--build-arg=VE_SOURCE_REVISION=sha256:" + "b" * 64, command)
        self.assertIn("--build-arg=VE_SOURCE_URL=urn:ve-os:local-source:sha256:" + "b" * 64, command)
        self.assertIn("--isolation=oci", command)
        self.assertIn("--cgroup-parent=/user.slice/unit/containers", command)
        self.assertIn("--property=DelegateSubgroup=supervisor", service)

    def test_unenforced_child_fails_before_exec(self):
        work = self.root / "work"
        work.mkdir()
        (work / "empty-auth.json").write_text('{"auths":{}}\n')
        (work / "empty-hooks").mkdir()
        read_text = Path.read_text
        def host_text(path, *args, **kwargs):
            return "" if str(path).startswith("/proc/") else read_text(path, *args, **kwargs)
        with patch.object(builder.platform, "system", return_value="Linux"), patch.object(builder.platform, "machine", return_value="x86_64"), \
             patch.object(builder.os, "getuid", return_value=os.getuid()), patch.object(builder.os, "geteuid", return_value=os.getuid()), \
             patch.object(volume, "verify_work_volume", return_value={}), \
             patch.object(builder, "verify_context"), patch.object(builder, "input_manifest", return_value={}), \
             patch.object(builder, "mounts", return_value=[]), patch.object(builder, "cgroups", return_value={"version": 1, "ancestors": []}), \
             patch.object(builder.Path, "read_text", host_text), patch.object(builder.os, "execve") as execute:
            with self.assertRaisesRegex(QualificationError, "Unified delegated|Rootless user"):
                builder.child(work, "a" * 40, "veailabs/Ve_Os-next", self.unit)
            execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
