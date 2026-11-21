import copy
from contextlib import ExitStack, redirect_stdout
import gzip
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
from types import SimpleNamespace
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("image_publish", Path(__file__).with_name("publish.py"))
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


def encoded(value):
    return json.dumps(value, sort_keys=True).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def descriptor(data, kind):
    return {"digest": digest(data), "size": len(data), "mediaType": kind}


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runtime = self.root / "tensorfold"
        self.runtime.mkdir()
        self.context = b"retained test source context"
        (self.runtime / "context.tar").write_bytes(self.context)
        self.context_hash = hashlib.sha256(self.context).hexdigest()

    def image(self, config_change=None, manifest_change=None, layers=None):
        raw_layers = []
        for entries in layers or [[("runtime-proof", b"proof")]]:
            raw_layer = io.BytesIO()
            with tarfile.open(fileobj=raw_layer, mode="w") as archive:
                for name, data in entries:
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
            raw_layers.append(raw_layer.getvalue())
        compressed = [gzip.compress(layer, mtime=0) for layer in raw_layers]
        config = {
            "os": "linux", "architecture": "arm64",
            "config": {"Labels": {
                "org.opencontainers.image.revision": "sha256:" + self.context_hash,
                "org.opencontainers.image.source": "urn:ve-os:local-source:sha256:" + self.context_hash,
            }},
            "rootfs": {"type": "layers", "diff_ids": [digest(layer) for layer in raw_layers]},
        }
        if config_change:
            config_change(config)
        config_bytes = encoded(config)
        manifest = {"schemaVersion": 2, "mediaType": publisher.MANIFEST, "config": descriptor(config_bytes, publisher.CONFIG), "layers": [descriptor(layer, publisher.LAYER) for layer in compressed]}
        if manifest_change:
            manifest_change(manifest)
        manifest_bytes = encoded(manifest)
        self.members = [("oci-layout", encoded({"imageLayoutVersion": "1.0.0"})), ("index.json", encoded({"schemaVersion": 2, "manifests": [descriptor(manifest_bytes, publisher.MANIFEST)]}))]
        self.members += [("blobs/sha256/" + digest(data)[7:], data) for data in (manifest_bytes, config_bytes, *compressed)]
        self.source = {"schema_version": 1, "runtime": "tensorfold", "platform": "linux/arm64", "context_sha256": self.context_hash, "image_digest": digest(manifest_bytes), "config_digest": digest(config_bytes)}
        return self.write_archive()

    def write_archive(self, special=None):
        archive_path = self.root / "image.oci.tar"
        with tarfile.open(archive_path, "w") as archive:
            for name, data in self.members:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            if special:
                archive.addfile(special)
        self.source.update(archive_sha256=publisher.hash_file(archive_path), archive_bytes=archive_path.stat().st_size)
        (self.runtime / "source.json").write_text(json.dumps(self.source))
        return archive_path

    def record(self):
        (self.runtime / "debian-source-map.tsv").write_text("binary\t1\tarm64\tfixture\t1\n")
        (self.runtime / "built-using.json").write_text("[]")
        source_archive = {"name": "fixture-source.tar.gz", "bytes": 5, "sha256": hashlib.sha256(b"proof").hexdigest()}
        file = {"path": "debian/fixture/source.dsc", "bytes": 5, "sha256": source_archive["sha256"], "url": "https://example.invalid/source.dsc"}
        delivery = {"schema_version": 1, "status": "complete", "debian_sources": [{"package": "fixture", "version": "1", "files": [file]}], "upstream_sources": [{"name": name, "revision": "fixture", "files": [dict(file, path="upstream/" + name)]} for name in ("tensorfold", "libjpeg-turbo", "libwebp")], "source_archives": [source_archive]}
        delivery_path = self.runtime / "source-delivery.json"
        delivery_path.write_text(json.dumps(delivery))
        return {"schema_version": 1, "repository_id": publisher.REPOSITORY_ID, "runtime": "tensorfold", "source_commit": "a" * 40, "release_id": 123, "release_tag": "fixture-v1", "assets": [{"id": 456, "name": "fixture.oci.tar", "bytes": self.source["archive_bytes"], "sha256": self.source["archive_sha256"]}], "source_manifest_sha256": publisher.hash_file(delivery_path), "source_assets": [dict(source_archive, id=789)]}

    def save_record(self, record):
        (self.runtime / "release.json").write_text(json.dumps(record))

    def test_valid_oci_and_source_record(self):
        archive = self.image()
        source = publisher.source_record("tensorfold", self.root)
        self.assertEqual(publisher.validate_oci(archive, source), source["image_digest"])

    def test_archive_checksum_and_size_are_bound(self):
        archive = self.image()
        with self.assertRaisesRegex(ValueError, "checksum"):
            publisher.validate_oci(archive, dict(self.source, archive_sha256="0" * 64))
        with self.assertRaisesRegex(ValueError, "size"):
            publisher.validate_oci(archive, dict(self.source, archive_bytes=1))

    def test_context_tampering_is_rejected(self):
        self.image()
        (self.runtime / "context.tar").write_bytes(b"different context")
        with self.assertRaisesRegex(ValueError, "context checksum"):
            publisher.source_record("tensorfold", self.root)

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "Duplicate JSON"):
            publisher.decode(b'{"id":1,"id":2}')

    def test_path_traversal_and_unexpected_members_are_rejected(self):
        for path in ("../escape", "/escape", "blobs/sha256/../escape", "extra.txt"):
            with self.subTest(path=path):
                self.image()
                self.members.append((path, b"bad"))
                with self.assertRaisesRegex(ValueError, "Unsafe"):
                    publisher.validate_oci(self.write_archive(), self.source)

    def test_links_and_special_members_are_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind):
                self.image()
                member = tarfile.TarInfo("blobs/sha256/" + "a" * 64)
                member.type = kind
                member.linkname = "/etc/passwd"
                with self.assertRaisesRegex(ValueError, "Unsafe"):
                    publisher.validate_oci(self.write_archive(member), self.source)

    def test_duplicate_tar_members_are_rejected(self):
        self.image()
        self.members.append(self.members[0])
        with self.assertRaisesRegex(ValueError, "Duplicate archive"):
            publisher.validate_oci(self.write_archive(), self.source)

    def test_blob_checksum_is_verified(self):
        self.image()
        name, data = self.members[-1]
        self.members[-1] = (name, data[:-1] + bytes([data[-1] ^ 1]))
        with self.assertRaisesRegex(ValueError, "Blob checksum"):
            publisher.validate_oci(self.write_archive(), self.source)

    def test_descriptor_sizes_are_verified(self):
        archive = self.image(manifest_change=lambda m: m["layers"][0].update(size=1))
        with self.assertRaisesRegex(ValueError, "Descriptor size"):
            publisher.validate_oci(archive, self.source)

    def test_external_layers_are_rejected(self):
        archive = self.image(manifest_change=lambda m: m["layers"][0].update(urls=["https://example.invalid/layer"]))
        with self.assertRaisesRegex(ValueError, "External OCI"):
            publisher.validate_oci(archive, self.source)

    def test_wrong_platform_and_source_labels_are_rejected(self):
        changes = [lambda c: c.update(architecture="amd64"), lambda c: c["config"]["Labels"].update({"org.opencontainers.image.revision": "sha256:" + "0" * 64}), lambda c: c["config"]["Labels"].update({"org.opencontainers.image.source": "https://example.invalid"})]
        for change in changes:
            with self.subTest(change=change):
                archive = self.image(config_change=change)
                with self.assertRaises(ValueError):
                    publisher.validate_oci(archive, self.source)

    def test_unreferenced_blob_is_rejected(self):
        self.image()
        data = b"unreferenced"
        self.members.append(("blobs/sha256/" + digest(data)[7:], data))
        with self.assertRaisesRegex(ValueError, "Unreferenced"):
            publisher.validate_oci(self.write_archive(), self.source)

    def test_missing_record_disables_publication(self):
        self.image()
        with self.assertRaisesRegex(ValueError, "publication is disabled"):
            publisher.release_record("tensorfold", self.source, self.root)

    def test_valid_asset_record_and_invalid_asset_inputs(self):
        self.image()
        record = self.record()
        self.save_record(record)
        self.assertEqual(publisher.release_record("tensorfold", self.source, self.root), record)
        mutations = [lambda r: r.update(repository_id=1), lambda r: r.update(release_id=True), lambda r: r.update(source_commit="master"), lambda r: r.update(url="https://example.invalid"), lambda r: r["assets"][0].update(id=0), lambda r: r["assets"][0].update(name="../escape"), lambda r: r["assets"][0].update(bytes=2**31), lambda r: r["assets"].append(copy.deepcopy(r["assets"][0]))]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                invalid = copy.deepcopy(record)
                mutation(invalid)
                self.save_record(invalid)
                with self.assertRaises(ValueError):
                    publisher.release_record("tensorfold", self.source, self.root)

    def test_runtime_traversal_and_unknown_runtime_are_rejected(self):
        for runtime in ("../tensorfold", "ollama", "tensorfold;id"):
            with self.assertRaisesRegex(ValueError, "Unknown runtime"):
                publisher.source_record(runtime, self.root)

    def test_corresponding_source_closure_and_assets_are_required(self):
        self.image()
        record = self.record()
        self.save_record(record)
        path = self.runtime / "source-delivery.json"
        original = json.loads(path.read_text())
        mutations = [lambda d: d.update(status="incomplete"), lambda d: d.update(debian_sources=[]), lambda d: d["debian_sources"][0].update(version="2"), lambda d: d["debian_sources"][0].update(files=[]), lambda d: d.update(upstream_sources=[]), lambda d: d.update(source_archives=[]), lambda d: d["debian_sources"][0]["files"][0].update(path="../escape")]
        for mutation in mutations:
            bad = copy.deepcopy(original)
            mutation(bad)
            path.write_text(json.dumps(bad))
            with self.subTest(delivery=bad), self.assertRaises(ValueError):
                publisher.source_delivery("tensorfold", self.root)
        path.write_text(json.dumps(original))
        record["source_manifest_sha256"] = "0" * 64
        self.save_record(record)
        with self.assertRaisesRegex(ValueError, "manifest checksum"):
            publisher.release_record("tensorfold", self.source, self.root)
        record["source_manifest_sha256"] = publisher.hash_file(path)
        record["source_assets"][0]["sha256"] = "0" * 64
        self.save_record(record)
        with self.assertRaisesRegex(ValueError, "Source assets"):
            publisher.release_record("tensorfold", self.source, self.root)

    def test_source_versions_and_static_components_are_not_collapsed(self):
        status = "Package: executable\nVersion: 1+b2\nSource: upstream (1)\nStatus: install ok installed\nBuilt-Using: rust-one (= 2)\nStatic-Built-Using: rust-two (= 3),\n rust-one (= 2)\n\nPackage: library\nSource: upstream\nVersion: 2\nConffiles:\n /etc/example abc123\nStatus: install ok installed\n"
        self.assertEqual(publisher.status_sources(status), {("upstream", "1"), ("upstream", "2"), ("rust-one", "2"), ("rust-two", "3")})
        self.image()
        self.record()
        (self.runtime / "built-using.json").write_text(json.dumps([{"binary": "binary", "field": "Built-Using", "sources": "rust-one (= 2)"}]))
        with self.assertRaisesRegex(ValueError, "closure is incomplete"):
            publisher.source_delivery("tensorfold", self.root)

    def test_anonymous_copy_disables_ambient_registry_auth(self):
        with patch.object(publisher, "run") as command:
            publisher.copy_image("docker://ghcr.io/veailabs/fixture@sha256:" + "a" * 64, "oci-archive:/tmp/fixture.tar", anonymous=True)
        self.assertIn("--src-no-creds", command.call_args.args[0])
        self.assertIn("--preserve-digests", command.call_args.args[0])

    def test_package_owner_repository_and_visibility_are_verified(self):
        package = {"package_type": "container", "name": "ve-os-local-ai/tensorfold", "owner": {"login": "veailabs"}, "repository": {"id": publisher.REPOSITORY_ID, "full_name": "veailabs/Ve_Os-next"}, "visibility": "public"}
        publisher.verify_package_metadata(package, "veailabs/Ve_Os-next", "tensorfold")
        mutations = [lambda p: p.update(package_type="npm"), lambda p: p.update(name="other"), lambda p: p.update(owner={"login": "other"}), lambda p: p.update(repository=None), lambda p: p["repository"].update(id=1), lambda p: p["repository"].update(full_name="veailabs/old-fork"), lambda p: p.update(visibility="private")]
        for mutation in mutations:
            bad = copy.deepcopy(package)
            mutation(bad)
            with self.subTest(package=bad), self.assertRaises(ValueError):
                publisher.verify_package_metadata(bad, "veailabs/Ve_Os-next", "tensorfold")

    def test_workflow_identity_requires_public_protected_master_and_reviewers(self):
        sha = "a" * 40
        environment = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY_ID": str(publisher.REPOSITORY_ID), "GITHUB_REF": "refs/heads/master", "GITHUB_REPOSITORY": "veailabs/Ve_Os-next", "GITHUB_SHA": sha}
        answers = [{"id": publisher.REPOSITORY_ID, "private": False, "default_branch": "master"}, {"protected": True, "commit": {"sha": sha}}, {"id": publisher.ENVIRONMENT_ID, "can_admins_bypass": False, "deployment_branch_policy": {"protected_branches": True}, "protection_rules": [{"type": "required_reviewers", "reviewers": [{"type": "User", "reviewer": {"id": publisher.OWNER_REVIEWER_ID}}]}]}]
        for name in ("veailabs/Ve_Os-next", "veailabs/VE-OS"):
            with self.subTest(repository=name), patch.dict(os.environ, dict(environment, GITHUB_REPOSITORY=name), clear=True), patch.object(publisher, "public_api", side_effect=answers) as api, patch.object(publisher, "run", return_value=sha.encode()):
                self.assertEqual(publisher.workflow_identity(), name)
                self.assertEqual(api.call_args_list[0].args[0], "repos/" + name)
                self.assertEqual(api.call_args_list[1].args[0], "repos/" + name + "/branches/master")
        environment["GITHUB_REPOSITORY"] = "veailabs/VE-OS"
        owner = {"type": "User", "reviewer": {"id": publisher.OWNER_REVIEWER_ID}}
        extra_user = {"type": "User", "reviewer": {"id": 999}}
        extra_team = {"type": "Team", "reviewer": {"id": 999}}
        reviewer_variants = [[owner, extra_user], [owner, extra_team], [extra_user], [extra_team]]
        variants = [(2, "protection_rules", [{"type": "required_reviewers", "reviewers": reviewers}]) for reviewers in reviewer_variants]
        variants.append((2, "protection_rules", [{"type": "required_reviewers", "reviewers": [owner]}, {"type": "required_reviewers", "reviewers": [extra_user]}]))
        variants += [(0, "private", True), (0, "id", 1), (1, "protected", False), (1, "commit", {"sha": "b" * 40}), (2, "protection_rules", []), (2, "deployment_branch_policy", None), (2, "can_admins_bypass", True), (2, "can_admins_bypass", None), (2, "id", 1)]
        for index, key, value in variants:
            rejected = copy.deepcopy(answers)
            rejected[index][key] = value
            with self.subTest(key=key), patch.dict(os.environ, environment, clear=True), patch.object(publisher, "public_api", side_effect=rejected), patch.object(publisher, "run", return_value=sha.encode()):
                with self.assertRaises(ValueError):
                    publisher.workflow_identity()
        for key, value in [("GITHUB_EVENT_NAME", "pull_request_target"), ("GITHUB_REF", "refs/heads/feature"), ("GITHUB_REPOSITORY_ID", "1"), ("GITHUB_REPOSITORY", "someone/Ve_Os"), ("GITHUB_REPOSITORY", "veailabs/Ve_Os")]:
            with self.subTest(key=key), patch.dict(os.environ, dict(environment, **{key: value}), clear=True), patch.object(publisher, "public_api") as api:
                with self.assertRaises(ValueError):
                    publisher.workflow_identity()
                api.assert_not_called()


    def system_image(self, layers):
        archive = self.image(layers=layers)
        self.record()
        return archive

    def verify_system_image(self, archive):
        expected = publisher.expected_system_sources("tensorfold", self.root)
        with patch.object(publisher, "expected_system_sources", return_value=expected):
            publisher.validate_oci(archive, self.source)
            publisher.verify_system_sources(archive, self.source)

    def test_system_sources_are_read_from_actual_image_layers(self):
        status = b"Package: binary\nSource: fixture\nVersion: 1\nStatus: install ok installed\n"
        archive = self.system_image([[("var/lib/dpkg/status", status)]])
        self.verify_system_image(archive)
        archive = self.system_image([[("other", b"content")]])
        with self.assertRaisesRegex(ValueError, "no installed Debian"):
            self.verify_system_image(archive)
        archive = self.system_image([[("var/lib/dpkg/status", status.replace(b"Version: 1", b"Version: 2"))]])
        with self.assertRaisesRegex(ValueError, "differs from actual"):
            self.verify_system_image(archive)

    def test_root_and_nested_whiteouts_remove_inherited_metadata(self):
        status = b"Package: binary\nSource: fixture\nVersion: 1\nStatus: install ok installed\n"
        for whiteout in (".wh.var", ".wh..wh..opq", "var/.wh.lib", "var/lib/.wh..wh..opq", "var/lib/dpkg/.wh.status"):
            with self.subTest(whiteout=whiteout):
                archive = self.system_image([[("var/lib/dpkg/status", status)], [(whiteout, b"")]])
                with self.assertRaisesRegex(ValueError, "no installed Debian"):
                    self.verify_system_image(archive)

    def test_same_layer_replacement_survives_whiteouts_in_either_order(self):
        status = b"Package: binary\nSource: fixture\nVersion: 1\nStatus: install ok installed\n"
        inherited = status.replace(b"Version: 1", b"Version: 2")
        for whiteout in (".wh.var", ".wh..wh..opq", "var/lib/.wh..wh..opq", "var/lib/dpkg/.wh.status"):
            for reverse in (False, True):
                entries = [(whiteout, b""), ("var/lib/dpkg/status", status)]
                if reverse:
                    entries.reverse()
                with self.subTest(whiteout=whiteout, replacement_first=reverse):
                    archive = self.system_image([[("var/lib/dpkg/status", inherited)], entries])
                    self.verify_system_image(archive)

    def release_fixture(self):
        status = b"Package: binary\nSource: fixture\nVersion: 1\nStatus: install ok installed\n"
        archive = self.image(layers=[[("var/lib/dpkg/status", status)]])
        record = self.record()
        release = {"id": record["release_id"], "tag_name": record["release_tag"], "draft": False, "assets": [dict(asset, size=asset["bytes"], state="uploaded", digest="sha256:" + asset["sha256"]) for asset in record["source_assets"] + record["assets"]]}
        return archive, record, release

    def test_fetch_archive_validates_metadata_and_actual_streams(self):
        for failure in (None, "wrong-release", "missing-asset", "truncated", "altered", "process-failure"):
            with self.subTest(failure=failure):
                archive, record, release = self.release_fixture()
                streams = {789: b"proof", 456: archive.read_bytes()}
                if failure == "wrong-release":
                    release["tag_name"] = "different"
                if failure == "missing-asset":
                    release["assets"] = release["assets"][:1]
                if failure == "truncated":
                    streams[456] = streams[456][:-1]
                if failure == "altered":
                    streams[456] = b"x" + streams[456][1:]
                processes = []
                class Download:
                    def __init__(self, arguments, **kwargs):
                        identifier = int(arguments[2].rsplit("/", 1)[1])
                        self.stdout = io.BytesIO(streams[identifier])
                        self.code = 1 if failure == "process-failure" else 0
                        processes.append(self)
                    def __enter__(self):
                        return self
                    def __exit__(self, *args):
                        self.stdout.close()
                    def wait(self, **kwargs):
                        return self.code
                    def poll(self):
                        return self.code
                output = self.root / (str(failure) + ".download.tar")
                expected = publisher.expected_system_sources("tensorfold", self.root)
                with patch.object(publisher, "public_api", return_value=release), patch.object(publisher.subprocess, "Popen", side_effect=Download), patch.object(publisher, "expected_system_sources", return_value=expected):
                    if failure:
                        with self.assertRaises(ValueError):
                            publisher.fetch_archive("veailabs/Ve_Os-next", record, self.source, output)
                    else:
                        publisher.fetch_archive("veailabs/Ve_Os-next", record, self.source, output)
                        self.assertEqual(output.read_bytes(), archive.read_bytes())
                if failure == "wrong-release":
                    self.assertFalse(output.exists())
                    self.assertEqual(processes, [])
                self.assertTrue(all(process.stdout.closed for process in processes))

    def test_prepare_release_rejects_ancestry_context_and_disk_before_download(self):
        self.image()
        record = self.record()
        self.save_record(record)
        source = publisher.source_record("tensorfold", self.root)
        threshold = source["archive_bytes"] * 3 + 1024**3
        for failure in ("ancestry", "context", "disk", None):
            work = self.root / ("prepare-" + str(failure))
            commands = []
            def git(arguments, **kwargs):
                commands.append(arguments)
                if arguments[1] == "merge-base":
                    if failure == "ancestry":
                        raise ValueError("Command failed: git")
                    return b""
                return b"other historical context" if failure == "context" else self.context
            with self.subTest(failure=failure), ExitStack() as stack:
                stack.enter_context(patch.object(publisher, "source_record", return_value=source))
                stack.enter_context(patch.object(publisher, "release_record", return_value=record))
                stack.enter_context(patch.object(publisher, "workflow_identity", return_value="veailabs/Ve_Os-next"))
                stack.enter_context(patch.object(publisher, "run", side_effect=git))
                stack.enter_context(patch.dict(os.environ, {"GITHUB_SHA": "b" * 40}))
                stack.enter_context(patch.object(publisher.shutil, "disk_usage", return_value=SimpleNamespace(free=threshold - (failure == "disk"))))
                download = stack.enter_context(patch.object(publisher, "fetch_archive"))
                if failure:
                    with self.assertRaises(ValueError):
                        publisher.prepare_release("tensorfold", work)
                    download.assert_not_called()
                    self.assertFalse(work.exists())
                else:
                    actual = publisher.prepare_release("tensorfold", work)
                    self.assertEqual(actual, (source, "veailabs/Ve_Os-next", work / "image.oci.tar"))
                    download.assert_called_once()
                    self.assertEqual(work.stat().st_mode & 0o777, 0o700)
                self.assertEqual(commands[0], ["git", "merge-base", "--is-ancestor", record["source_commit"], "b" * 40])
                if failure == "ancestry":
                    self.assertEqual(len(commands), 1)
                else:
                    self.assertEqual(commands[1], ["git", "show", record["source_commit"] + ":distribution/local-ai-images/tensorfold/context.tar"])

    def publication_run(self, tag_state="same", failure=None):
        archive = self.image()
        manifest = next(data for name, data in self.members if name == "blobs/sha256/" + self.source["image_digest"][7:])
        work = self.root / ("publish-" + tag_state + "-" + str(failure))
        work.mkdir()
        commands, credentials, events = [], [], []
        package = {"package_type": "container", "name": "ve-os-local-ai/tensorfold", "owner": {"login": "veailabs"}, "repository": {"id": publisher.REPOSITORY_ID, "full_name": "veailabs/Ve_Os-next"}, "visibility": "public"}
        dummy = "fixture-only-noncredential"
        def command(arguments, **kwargs):
            commands.append((arguments, kwargs))
            self.assertNotIn(dummy, " ".join(arguments))
            if arguments[:2] == ["skopeo", "login"]:
                events.append("login")
                auth = Path(arguments[arguments.index("--authfile") + 1])
                self.assertEqual(kwargs["input"], dummy.encode())
                auth.write_text(json.dumps({"auths": {"fixture": dummy}}))
                credentials.append(auth)
                return b""
            self.assertTrue(credentials[0].exists())
            if arguments[:2] == ["skopeo", "copy"]:
                self.assertIn("--preserve-digests", arguments)
                if "--src-no-creds" in arguments:
                    events.append("anonymous-copy")
                    self.assertNotIn("--dest-authfile", arguments)
                    empty = Path(arguments[arguments.index("--src-authfile") + 1])
                    self.assertEqual(json.loads(empty.read_text()), {"auths": {}})
                    self.assertNotEqual(empty, credentials[0])
                    if failure == "anonymous-copy":
                        raise ValueError("Anonymous pull failed")
                    destination = Path(arguments[-1].removeprefix("oci-archive:"))
                    if failure == "anonymous-archive":
                        destination.write_bytes(b"invalid archive")
                    else:
                        shutil.copyfile(archive, destination)
                else:
                    events.append("tag-copy" if ":sha256-" in arguments[-1] else "digest-copy")
                    self.assertEqual(Path(arguments[arguments.index("--dest-authfile") + 1]), credentials[0])
                    if failure == "post-login":
                        raise ValueError("Upload failed")
                return b""
            if arguments[:2] == ["skopeo", "inspect"]:
                events.append("authenticated-inspect")
                return b"wrong manifest" if failure == "authenticated-digest" else manifest
            if arguments[:2] == ["gh", "api"]:
                events.append("package")
                result = copy.deepcopy(package)
                if failure == "package":
                    result["repository"]["id"] = 1
                return encoded(result)
            raise AssertionError(arguments)
        if tag_state == "same":
            existing = SimpleNamespace(returncode=0, stdout=manifest, stderr=b"")
        elif tag_state == "conflict":
            existing = SimpleNamespace(returncode=0, stdout=b"different manifest", stderr=b"")
        else:
            stderr = {"missing": b"manifest unknown", "missing-name": b"name unknown", "error": b"permission denied"}[tag_state]
            existing = SimpleNamespace(returncode=1, stdout=b"", stderr=stderr)
        stdout = io.StringIO()
        error, result = None, None
        with ExitStack() as stack:
            stack.enter_context(patch.object(publisher, "prepare_release", return_value=(self.source, "veailabs/Ve_Os-next", archive)))
            identity = stack.enter_context(patch.object(publisher, "workflow_identity", return_value="veailabs/Ve_Os-next"))
            stack.enter_context(patch.object(publisher, "run", side_effect=command))
            inspect = stack.enter_context(patch.object(publisher.subprocess, "run", return_value=existing))
            stack.enter_context(patch.dict(os.environ, {"GH_TOKEN": dummy, "GITHUB_ACTOR": "fixture"}, clear=True))
            stack.enter_context(redirect_stdout(stdout))
            try:
                result = publisher.publish("tensorfold", work)
            except (ValueError, tarfile.TarError) as caught:
                error = caught
        self.assertTrue(credentials)
        self.assertFalse(credentials[0].exists())
        self.assertFalse(credentials[0].parent.exists())
        self.assertEqual(list(work.glob("ve-os-registry-*")), [])
        self.assertNotIn(dummy, stdout.getvalue())
        self.assertEqual(error is None, result is not None)
        if error:
            self.assertEqual(stdout.getvalue(), "")
        if inspect.called:
            args = inspect.call_args.args[0]
            self.assertEqual(args[:3], ["skopeo", "inspect", "--raw"])
            self.assertTrue(args[-1].endswith(":sha256-" + self.source["image_digest"][7:]))
        return SimpleNamespace(result=result, error=error, events=events, commands=commands, identity_checks=identity.call_count)

    def test_publication_tag_permissions_and_credential_cleanup(self):
        for state in ("same", "conflict", "missing", "missing-name", "error"):
            with self.subTest(tag_state=state):
                outcome = self.publication_run(tag_state=state)
                self.assertEqual(outcome.events.count("digest-copy"), 1)
                self.assertEqual(outcome.events.count("tag-copy"), state in ("missing", "missing-name"))
                self.assertEqual(outcome.identity_checks, 2 if state in ("missing", "missing-name") else 1)
                if state in ("conflict", "error"):
                    self.assertIsNotNone(outcome.error)
                    self.assertNotIn("authenticated-inspect", outcome.events)
                    self.assertNotIn("anonymous-copy", outcome.events)
                else:
                    self.assertIsNone(outcome.error)
                    self.assertTrue(outcome.result["anonymous_pull_verified"])
                    self.assertFalse(outcome.result["catalog_updated"])
                    self.assertFalse(outcome.result["gpu_inference_tested"])
                    self.assertEqual(outcome.events[-3:], ["authenticated-inspect", "package", "anonymous-copy"])

    def test_publication_failure_stages_never_report_success_and_remove_credentials(self):
        for failure, last in (("post-login", "digest-copy"), ("authenticated-digest", "authenticated-inspect"), ("package", "package"), ("anonymous-copy", "anonymous-copy"), ("anonymous-archive", "anonymous-copy")):
            with self.subTest(failure=failure):
                outcome = self.publication_run(failure=failure)
                self.assertIsNotNone(outcome.error)
                self.assertEqual(outcome.events[-1], last)
                self.assertIsNone(outcome.result)


if __name__ == "__main__":
    unittest.main()
