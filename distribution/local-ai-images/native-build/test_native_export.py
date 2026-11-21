import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import native_export as export
import release_export as release
from native_profile import PROFILE, QualificationError, REPOSITORY_ID


def fixture():
    payloads = {"image.oci.tar": b"fixture-image", "llamacpp-source-test.tar": b"fixture-source",
                "source.json": b'{"test":"source"}', "source-delivery.json": b'{"test":"delivery"}', "native-provenance.json": b'{"test":"provenance"}'}
    assets = []
    for name, data in payloads.items():
        role = "image" if name == "image.oci.tar" else "metadata" if name.endswith(".json") else "source"
        assets.append({"name": "llamacpp-amd64.oci.tar.part01" if role == "image" else name, "path": name, "role": role,
                       "offset": 0, "bytes": len(data), "file_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    manifest = {"schema_version": 1, "repository_id": REPOSITORY_ID, "runtime": "llamacpp", "platform": "linux/amd64",
                "source_commit": "a" * 40, "run_id": "123", "attempt": "1", "image": {"bytes": len(payloads["image.oci.tar"]),
                "sha256": hashlib.sha256(payloads["image.oci.tar"]).hexdigest()},
                "source_delivery_sha256": hashlib.sha256(payloads["source-delivery.json"]).hexdigest(), "assets": assets}
    payloads["export-manifest.json"] = export.canonical_manifest(manifest)
    return manifest, payloads


class FakeClient:
    repository = "veailabs/Ve_Os-next"
    prefix = "/repos/" + repository

    def __init__(self, manifest):
        self.manifest = manifest
        self.release = None
        self.assets = {}
        self.payloads = {}
        self.calls = []
        self.uploaded = 0
        self.downloaded = 0
        self.branch_sha = manifest["source_commit"]
        self.environment_id = 321
        self.lose_upload_response = False

    def json(self, method, endpoint, data=None, accepted=(200,)):
        self.calls.append((method, endpoint, data))
        if endpoint == "/repositories/" + str(REPOSITORY_ID):
            return 200, {"id": REPOSITORY_ID, "full_name": self.repository, "private": False, "default_branch": "master"}
        if endpoint.endswith("/branches/master"):
            return 200, {"protected": True, "commit": {"sha": self.branch_sha}}
        if "/environments/" in endpoint:
            return 200, {"id": self.environment_id, "can_admins_bypass": False,
                         "deployment_branch_policy": {"protected_branches": True, "custom_branch_policies": False},
                         "protection_rules": [{"type": "required_reviewers", "reviewers": [{"type": "User", "reviewer": {"id": release.OWNER_REVIEWER_ID}}]}]}
        if method == "GET" and "/releases?" in endpoint:
            return 200, [] if self.release is None else [self.release]
        if method == "POST":
            if data.get("make_latest") != "false" or data.get("draft") is not True or data.get("prerelease") is not True:
                raise AssertionError("Only an explicit nonlatest draft prerelease may be created")
            self.release = {**data, "id": 45, "upload_url": "https://uploads.github.com" + self.prefix + "/releases/45/assets{?name,label}"}
            return 201, self.release
        if endpoint.endswith("/releases/45"):
            return 200, self.release
        raise AssertionError("Unexpected fixture API call")

    def asset_list(self, release_id):
        return list(self.assets.values())

    def upload(self, release_id, asset, stream):
        body = stream.read(asset["bytes"])
        self.uploaded += len(body)
        actual = {"id": 100 + len(self.assets), "name": asset["name"], "size": len(body), "state": "uploaded",
                  "digest": "sha256:" + hashlib.sha256(body).hexdigest()}
        self.assets[asset["name"]] = actual
        self.payloads[actual["id"]] = body
        if self.lose_upload_response:
            self.lose_upload_response = False
            raise OSError("fixture lost response")
        return actual

    def readback(self, asset_id, expected):
        body = self.payloads[asset_id]
        self.downloaded += len(body)
        if len(body) != expected["bytes"] or hashlib.sha256(body).hexdigest() != expected["sha256"]:
            raise QualificationError("fixture bytes differ")


class FrozenManifestTests(unittest.TestCase):
    def test_ordered_image_parts_and_complete_source_bundles_admit(self):
        manifest, _ = fixture()
        totals = export.validate_manifest(manifest)
        self.assertEqual(totals["image"], manifest["image"]["bytes"])
        self.assertEqual(export.release_tag(manifest), "ve-ai-build-llamacpp-" + "a" * 40 + "-123-1")
        self.assertEqual(export.upload_assets(manifest)[-1]["name"], "export-manifest.json")

    def test_partial_sources_and_path_traversal_fail(self):
        for change in ({"path": "../secret"}, {"offset": 1, "file_bytes": 100}, {"name": "arbitrary.bin"}):
            manifest, _ = fixture()
            manifest["assets"][1].update(change)
            with self.subTest(change=change), self.assertRaises(QualificationError):
                export.validate_manifest(manifest)

    def test_omitted_source_or_evidence_fails(self):
        for role in ("source", "metadata"):
            manifest, _ = fixture()
            manifest["assets"] = [asset for asset in manifest["assets"] if asset["role"] != role]
            with self.assertRaises(QualificationError):
                export.validate_manifest(manifest)

    def test_image_gap_duplicate_and_changed_manifest_binding_fail(self):
        for change in ("gap", "duplicate", "binding"):
            manifest, _ = fixture()
            if change == "gap":
                manifest["assets"][0]["offset"] = 1
            elif change == "duplicate":
                manifest["assets"].append(copy.deepcopy(manifest["assets"][0]))
            else:
                manifest["source_delivery_sha256"] = "b" * 64
            with self.subTest(change=change), self.assertRaises(QualificationError):
                export.validate_manifest(manifest)

    def test_asset_total_and_document_caps_are_enforced(self):
        manifest, _ = fixture()
        for cap, value in (("asset_count", 3), ("source_bytes", 1), ("metadata_bytes", 1), ("export_bytes", 1), ("document_bytes", 1)):
            with patch.dict(PROFILE, {cap: value}), self.subTest(cap=cap), self.assertRaises(QualificationError):
                export.validate_manifest(manifest)

    def test_exact_open_stream_is_hashed_and_rewound_for_upload(self):
        data = b"prefix-payload-suffix"
        asset = {"offset": 7, "bytes": 7, "sha256": hashlib.sha256(b"payload").hexdigest()}
        stream = io.BytesIO(data)
        export.verify_stream(stream, asset)
        self.assertEqual(stream.tell(), 7)
        self.assertEqual(stream.read(7), b"payload")
        with self.assertRaises(QualificationError):
            export.verify_stream(io.BytesIO(b"changed"), asset)

    def test_frozen_root_requires_root_owned_readonly_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "export"
            root.mkdir()
            with self.assertRaises(QualificationError):
                export.validate_frozen_root(root)


class DraftTransportTests(unittest.TestCase):
    def setUp(self):
        self.manifest, self.payloads = fixture()
        self.client = FakeClient(self.manifest)
        def opened(root, asset):
            stream = io.BytesIO(self.payloads[asset["path"]])
            stream.seek(asset["offset"])
            return stream
        self.patcher = patch.object(release, "open_asset", side_effect=opened)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    def export(self):
        return release.upload_export(self.client, Path("/fixture"), self.manifest, 321)

    def test_complete_transport_returns_actual_fixture_ids_after_full_readback(self):
        receipt = self.export()
        self.assertEqual(receipt["release_id"], 45)
        self.assertEqual(len(receipt["assets"]), 6)
        self.assertFalse(receipt["public_release"])
        self.assertFalse(receipt["registry_publication"])
        self.assertGreater(self.client.downloaded, 0)
        self.assertTrue(all(method in {"GET", "POST"} for method, _, _ in self.client.calls))

    def test_identical_existing_draft_assets_are_reused_without_upload(self):
        self.export()
        uploaded = self.client.uploaded
        receipt = self.export()
        self.assertEqual(self.client.uploaded, uploaded)
        self.assertEqual(len([call for call in self.client.calls if call[0] == "POST"]), 1)
        self.assertEqual(receipt["release_id"], 45)

    def test_uncertain_upload_response_recovers_only_after_byte_readback(self):
        self.client.lose_upload_response = True
        receipt = self.export()
        self.assertEqual(len(receipt["assets"]), 6)
        self.assertEqual(len(self.client.assets), 6)

    def test_changed_local_bytes_fail_before_network(self):
        self.payloads["image.oci.tar"] = b"bad"
        with self.assertRaises(QualificationError):
            self.export()
        self.assertEqual(self.client.calls, [])

    def test_whole_archive_hash_mismatch_fails_before_network(self):
        self.manifest["image"]["sha256"] = "b" * 64
        self.payloads["export-manifest.json"] = export.canonical_manifest(self.manifest)
        with self.assertRaisesRegex(QualificationError, "Complete frozen image"):
            self.export()
        self.assertEqual(self.client.calls, [])

    def test_moved_master_or_wrong_environment_prevents_release_creation(self):
        self.client.branch_sha = "b" * 40
        with self.assertRaises(QualificationError):
            self.export()
        self.assertFalse(any(call[0] == "POST" for call in self.client.calls))
        self.client.branch_sha = self.manifest["source_commit"]
        self.client.environment_id = 999
        with self.assertRaises(QualificationError):
            self.export()
        self.assertFalse(any(call[0] == "POST" for call in self.client.calls))

    def test_published_or_changed_draft_is_never_replaced(self):
        self.export()
        self.client.release["draft"] = False
        calls = len(self.client.calls)
        with self.assertRaises(QualificationError):
            self.export()
        self.assertFalse(any(call[0] == "POST" for call in self.client.calls[calls:]))
        self.client.release["draft"] = True
        self.client.release["body"] = "different frozen bytes"
        with self.assertRaises(QualificationError):
            self.export()

    def test_conflicting_or_incomplete_asset_is_retained_and_rejected(self):
        self.export()
        first = next(iter(self.client.assets.values()))
        first["state"] = "starter"
        with self.assertRaises(QualificationError):
            self.export()
        self.assertEqual(first["state"], "starter")
        first["state"] = "uploaded"
        first["digest"] = "sha256:" + "0" * 64
        with self.assertRaises(QualificationError):
            self.export()

    def test_remote_bytes_must_match_even_when_metadata_digest_is_correct(self):
        self.export()
        identifier = next(iter(self.client.payloads))
        self.client.payloads[identifier] = b"tampered"
        with self.assertRaises(QualificationError):
            self.export()

    def test_unexpected_asset_is_not_deleted_or_ignored(self):
        self.export()
        self.client.assets["other"] = {"id": 99, "name": "other"}
        with self.assertRaises(QualificationError):
            self.export()
        self.assertIn("other", self.client.assets)


class HttpBoundaryTests(unittest.TestCase):
    def client(self):
        return release.GitHubReleaseClient("veailabs/Ve_Os-next", "fixture-token", time.monotonic() + 30)

    def test_byte_caps_are_atomic_and_shared(self):
        client = self.client()
        with patch.dict(PROFILE, {"upload_body_bytes": 10, "readback_body_bytes": 10, "network_body_bytes": 15}):
            client.consume("upload", 8)
            client.consume("download", 7)
            with self.assertRaises(QualificationError):
                client.consume("upload", 1)
            self.assertEqual((client.uploaded, client.downloaded), (8, 7))

    def test_expired_stage_cannot_start_request(self):
        client = self.client()
        client.deadline = time.monotonic() - 1
        with patch.object(release.http.client, "HTTPSConnection") as connect:
            with self.assertRaises(QualificationError):
                client.json("GET", client.prefix)
            connect.assert_not_called()

    def test_token_or_destination_injection_is_rejected_without_echo(self):
        with self.assertRaises(QualificationError) as raised:
            release.GitHubReleaseClient("veailabs/Ve_Os-next", "DO_NOT_ECHO\nsecret", time.monotonic() + 30)
        self.assertNotIn("DO_NOT_ECHO", str(raised.exception))
        with self.assertRaises(QualificationError):
            release.GitHubReleaseClient("attacker/repository", "fixture-token", time.monotonic() + 30)
        client = self.client()
        for method, endpoint in (("DELETE", client.prefix + "/releases/1"), ("POST", client.prefix + "/contents/file"),
                                 ("GET", "/repos/attacker/repo/releases")):
            with self.assertRaises(QualificationError):
                client.json(method, endpoint)

    def test_upload_sends_exact_authenticated_endpoint_length_and_body(self):
        payload = b"bounded upload bytes" * 8000
        asset = {"name": "llamacpp source.tar", "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
        connection = FakeConnection(FakeResponse(201, b'{"id":321}', {}))
        client = self.client()
        with patch.object(release.http.client, "HTTPSConnection", return_value=connection) as connect:
            result = client.upload(45, asset, io.BytesIO(payload + b"excluded suffix"))
        self.assertEqual(connect.call_args.args, ("uploads.github.com",))
        self.assertEqual(connection.upload_request, ("POST", "/repos/veailabs/Ve_Os-next/releases/45/assets?name=llamacpp%20source.tar", True))
        self.assertEqual(connection.headers["Authorization"], "Bearer fixture-token")
        self.assertEqual(connection.headers["Content-Length"], str(len(payload)))
        self.assertEqual(connection.headers["Content-Type"], "application/octet-stream")
        self.assertEqual(b"".join(connection.sent), payload)
        self.assertTrue(all(len(chunk) <= 65536 for chunk in connection.sent))
        self.assertTrue(connection.ended)
        self.assertTrue(connection.closed)
        self.assertEqual(client.uploaded, len(payload))
        self.assertEqual(result, {"id": 321})

    def test_upload_rejects_non_success_and_still_closes_connection(self):
        payload = b"fixture"
        asset = {"name": "source.tar", "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
        for status in (200, 302, 403, 422, 500):
            connection = FakeConnection(FakeResponse(status, b'{"id":321}', {}))
            with self.subTest(status=status), patch.object(release.http.client, "HTTPSConnection", return_value=connection):
                with self.assertRaisesRegex(QualificationError, "upload did not complete"):
                    self.client().upload(45, asset, io.BytesIO(payload))
                self.assertTrue(connection.closed)

    def test_allowed_download_redirect_never_receives_token(self):
        payload = b"verified fixture"
        expected = {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
        first = FakeConnection(FakeResponse(302, b"", {"Location": "https://release-assets.githubusercontent.com/path?signature=fixture"}))
        second = FakeConnection(FakeResponse(200, payload, {"Content-Length": str(len(payload))}))
        with patch.object(release.http.client, "HTTPSConnection", side_effect=[first, second]):
            self.client().readback(123, expected)
        self.assertIn("Authorization", first.requests[0][2])
        self.assertNotIn("Authorization", second.requests[0][2])

    def test_unapproved_redirect_is_never_followed(self):
        first = FakeConnection(FakeResponse(302, b"", {"Location": "https://attacker.example/token"}))
        with patch.object(release.http.client, "HTTPSConnection", return_value=first) as connect:
            with self.assertRaises(QualificationError):
                self.client().readback(123, {"bytes": 1, "sha256": "0" * 64})
            self.assertEqual(connect.call_count, 1)

    def test_extra_readback_bytes_are_rejected(self):
        connection = FakeConnection(FakeResponse(200, b"ab", {}))
        with patch.object(release.http.client, "HTTPSConnection", return_value=connection):
            with self.assertRaises(QualificationError):
                self.client().readback(123, {"bytes": 1, "sha256": hashlib.sha256(b"a").hexdigest()})


class FakeResponse:
    def __init__(self, status, body, headers):
        self.status = status
        self.body = io.BytesIO(body)
        self.headers = headers

    def read(self, count):
        return self.body.read(count)

    def getheader(self, name, default=None):
        return self.headers.get(name, default)


class FakeConnection:
    def __init__(self, response):
        self.response = response
        self.requests = []
        self.headers = {}
        self.sent = []
        self.ended = False
        self.closed = False

    def putrequest(self, method, endpoint, skip_accept_encoding=False):
        self.upload_request = method, endpoint, skip_accept_encoding

    def putheader(self, name, value):
        self.headers[name] = value

    def endheaders(self):
        self.ended = True

    def send(self, data):
        if not self.ended:
            raise AssertionError("Body sent before headers")
        self.sent.append(data)

    def request(self, method, endpoint, body=None, headers=None):
        self.requests.append((method, endpoint, headers))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


if __name__ == "__main__":
    unittest.main()
