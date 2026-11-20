import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
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

    def image(self, config_change=None, manifest_change=None):
        raw_layer = io.BytesIO()
        with tarfile.open(fileobj=raw_layer, mode="w") as archive:
            member = tarfile.TarInfo("runtime-proof")
            member.size = 5
            archive.addfile(member, io.BytesIO(b"proof"))
        layer = gzip.compress(raw_layer.getvalue(), mtime=0)
        config = {
            "os": "linux", "architecture": "arm64",
            "config": {"Labels": {
                "org.opencontainers.image.revision": "sha256:" + self.context_hash,
                "org.opencontainers.image.source": "urn:ve-os:local-source:sha256:" + self.context_hash,
            }},
            "rootfs": {"type": "layers", "diff_ids": [digest(raw_layer.getvalue())]},
        }
        if config_change:
            config_change(config)
        config_bytes = encoded(config)
        manifest = {"schemaVersion": 2, "mediaType": publisher.MANIFEST, "config": descriptor(config_bytes, publisher.CONFIG), "layers": [descriptor(layer, publisher.LAYER)]}
        if manifest_change:
            manifest_change(manifest)
        manifest_bytes = encoded(manifest)
        self.members = [("oci-layout", encoded({"imageLayoutVersion": "1.0.0"})), ("index.json", encoded({"schemaVersion": 2, "manifests": [descriptor(manifest_bytes, publisher.MANIFEST)]}))]
        self.members += [("blobs/sha256/" + digest(data)[7:], data) for data in (manifest_bytes, config_bytes, layer)]
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
        with patch.dict(os.environ, environment, clear=True), patch.object(publisher, "public_api", side_effect=answers), patch.object(publisher, "run", return_value=sha.encode()):
            self.assertEqual(publisher.workflow_identity(), "veailabs/Ve_Os-next")
        variants = [(0, "private", True), (0, "id", 1), (1, "protected", False), (1, "commit", {"sha": "b" * 40}), (2, "protection_rules", []), (2, "deployment_branch_policy", None), (2, "can_admins_bypass", True), (2, "can_admins_bypass", None), (2, "id", 1)]
        for index, key, value in variants:
            rejected = copy.deepcopy(answers)
            rejected[index][key] = value
            with self.subTest(key=key), patch.dict(os.environ, environment, clear=True), patch.object(publisher, "public_api", side_effect=rejected), patch.object(publisher, "run", return_value=sha.encode()):
                with self.assertRaises(ValueError):
                    publisher.workflow_identity()
        for key, value in [("GITHUB_EVENT_NAME", "pull_request_target"), ("GITHUB_REF", "refs/heads/feature"), ("GITHUB_REPOSITORY_ID", "1"), ("GITHUB_REPOSITORY", "someone/Ve_Os")]:
            with self.subTest(key=key), patch.dict(os.environ, dict(environment, **{key: value}), clear=True), patch.object(publisher, "public_api") as api:
                with self.assertRaises(ValueError):
                    publisher.workflow_identity()
                api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
