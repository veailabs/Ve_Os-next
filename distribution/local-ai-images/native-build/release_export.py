import hashlib
import http.client
import json
import re
import time
from urllib.parse import quote, urlsplit

from native_export import canonical_manifest, open_asset, release_tag, upload_assets, validate_manifest, verify_stream
from native_inputs import unique_object
from native_profile import PROFILE, REPOSITORY_ID, require


API_VERSION = "2026-03-10"
DOWNLOAD_HOSTS = {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}
ENVIRONMENT = "ve-os-image-build-export"
OWNER_REVIEWER_ID = 214956837


class GitHubReleaseClient:
    def __init__(self, repository, token, deadline):
        require(repository in {"veailabs/Ve_Os-next", "veailabs/VE-OS"}, "Unexpected release repository")
        require(isinstance(token, str) and 0 < len(token) <= 4096 and all(32 < ord(value) < 127 for value in token),
                "Invalid temporary upload credential")
        self.repository = repository
        self.prefix = "/repos/" + repository
        self._token = token
        self.deadline = deadline
        self.uploaded = 0
        self.downloaded = 0

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "Release export deadline reached")
        return min(30, remaining)

    def consume(self, direction, size):
        require(type(size) is int and size >= 0, "Invalid release byte accounting")
        self.remaining()
        require(direction in {"upload", "download"}, "Invalid release byte direction")
        uploaded = self.uploaded + (size if direction == "upload" else 0)
        downloaded = self.downloaded + (size if direction == "download" else 0)
        require(uploaded <= PROFILE["upload_body_bytes"], "Release upload byte cap reached")
        require(downloaded <= PROFILE["readback_body_bytes"], "Release retrieval byte cap reached")
        require(uploaded + downloaded <= PROFILE["network_body_bytes"], "Release network byte cap reached")
        self.uploaded, self.downloaded = uploaded, downloaded

    def headers(self, accept="application/vnd.github+json", authenticated=True):
        headers = {"Accept": accept, "Accept-Encoding": "identity", "User-Agent": "Ve-OS-native-release-export",
                   "X-GitHub-Api-Version": API_VERSION}
        if authenticated:
            headers["Authorization"] = "Bearer " + self._token
        return headers

    def json(self, method, endpoint, data=None, accepted=(200,)):
        require(method in {"GET", "POST"}, "Unsupported release API mutation")
        require(endpoint == "/repositories/" + str(REPOSITORY_ID) or endpoint.startswith(self.prefix + "/") or endpoint == self.prefix,
                "Release API escaped repository boundary")
        require(method != "POST" or endpoint == self.prefix + "/releases", "Only draft creation is permitted")
        body = None if data is None else json.dumps(data, separators=(",", ":")).encode()
        require(body is None or len(body) <= PROFILE["document_bytes"], "Release API document exceeds limit")
        connection = http.client.HTTPSConnection("api.github.com", timeout=self.remaining())
        try:
            headers = self.headers()
            if body is not None:
                headers["Content-Type"] = "application/json"
                self.consume("upload", len(body))
            connection.request(method, endpoint, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read(PROFILE["document_bytes"] + 1)
            self.consume("download", len(raw))
            require(len(raw) <= PROFILE["document_bytes"], "Release API response exceeds limit")
            require(response.status in accepted, "Unexpected release API status: " + str(response.status))
            return response.status, json.loads(raw, object_pairs_hook=unique_object) if raw else None
        finally:
            connection.close()

    def asset_list(self, release_id):
        require(type(release_id) is int and release_id > 0, "Invalid release identity")
        _, assets = self.json("GET", self.prefix + f"/releases/{release_id}/assets?per_page=100")
        require(isinstance(assets, list) and len(assets) <= PROFILE["asset_count"], "Unexpected release asset count")
        require(len({asset["name"] for asset in assets}) == len(assets), "Duplicate release asset names")
        return assets

    def upload(self, release_id, asset, stream):
        require(type(release_id) is int and release_id > 0, "Invalid release identity")
        endpoint = self.prefix + f"/releases/{release_id}/assets?name=" + quote(asset["name"], safe="")
        connection = http.client.HTTPSConnection("uploads.github.com", timeout=self.remaining())
        try:
            connection.putrequest("POST", endpoint, skip_accept_encoding=True)
            for name, value in {**self.headers(), "Content-Type": "application/octet-stream", "Content-Length": str(asset["bytes"])}.items():
                connection.putheader(name, value)
            connection.endheaders()
            remaining = asset["bytes"]
            digest = hashlib.sha256()
            while remaining:
                data = stream.read(min(65536, remaining))
                require(data, "Frozen upload stream was truncated")
                self.consume("upload", len(data))
                connection.send(data)
                digest.update(data)
                remaining -= len(data)
            require(digest.hexdigest() == asset["sha256"], "Uploaded bytes differ from frozen identity")
            response = connection.getresponse()
            raw = response.read(PROFILE["document_bytes"] + 1)
            self.consume("download", len(raw))
            require(response.status == 201 and len(raw) <= PROFILE["document_bytes"], "Release upload did not complete")
            return json.loads(raw, object_pairs_hook=unique_object)
        finally:
            connection.close()

    def readback(self, asset_id, expected):
        require(type(asset_id) is int and asset_id > 0, "Invalid uploaded asset identity")
        connection = http.client.HTTPSConnection("api.github.com", timeout=self.remaining())
        try:
            connection.request("GET", self.prefix + f"/releases/assets/{asset_id}", headers=self.headers("application/octet-stream"))
            response = connection.getresponse()
            if response.status == 302:
                location = urlsplit(response.getheader("Location", ""))
                require(location.scheme == "https" and location.hostname in DOWNLOAD_HOSTS and location.port in {None, 443}
                        and location.username is None and location.password is None and not location.fragment, "Unapproved asset redirect")
                connection.close()
                connection = http.client.HTTPSConnection(location.hostname, timeout=self.remaining())
                endpoint = location.path + ("?" + location.query if location.query else "")
                connection.request("GET", endpoint, headers=self.headers("application/octet-stream", authenticated=False))
                response = connection.getresponse()
            require(response.status == 200, "Uploaded asset readback failed")
            require(response.getheader("Content-Encoding", "identity") == "identity", "Encoded asset readback is unsupported")
            length = response.getheader("Content-Length")
            require(length is None or (length.isdigit() and int(length) == expected["bytes"]), "Uploaded asset response size differs")
            size = 0
            digest = hashlib.sha256()
            while True:
                self.remaining()
                block = response.read(min(65536, expected["bytes"] - size + 1))
                if not block:
                    break
                self.consume("download", len(block))
                size += len(block)
                require(size <= expected["bytes"], "Uploaded asset exceeded frozen length")
                digest.update(block)
            require(size == expected["bytes"] and digest.hexdigest() == expected["sha256"], "Uploaded asset byte verification failed")
        finally:
            connection.close()


def verify_destination(client, source_sha, environment_id):
    require(type(environment_id) is int and environment_id > 0, "Actual reviewed environment identity is required")
    _, repository = client.json("GET", "/repositories/" + str(REPOSITORY_ID))
    require(repository.get("id") == REPOSITORY_ID and repository.get("full_name") == client.repository and repository.get("private") is False
            and repository.get("default_branch") == "master", "Release destination repository differs")
    _, branch = client.json("GET", client.prefix + "/branches/master")
    require(branch.get("protected") is True and branch.get("commit", {}).get("sha") == source_sha, "Protected master moved before export")
    _, environment = client.json("GET", client.prefix + "/environments/" + ENVIRONMENT)
    require(environment.get("id") == environment_id and environment.get("can_admins_bypass") is False, "Build/export environment changed")
    policy = environment.get("deployment_branch_policy") or {}
    require(policy.get("protected_branches") is True and policy.get("custom_branch_policies") is False, "Build/export branch policy changed")
    rules = [rule for rule in environment.get("protection_rules", []) if rule.get("type") == "required_reviewers"]
    require(len(rules) == 1, "Build/export owner approval rule changed")
    reviewers = rules[0].get("reviewers", [])
    require(len(reviewers) == 1 and reviewers[0].get("type") == "User" and reviewers[0].get("reviewer", {}).get("id") == OWNER_REVIEWER_ID,
            "Build/export must require only the owner reviewer")


def release_body(manifest):
    identity = {"runtime": manifest["runtime"], "source_commit": manifest["source_commit"], "run_id": manifest["run_id"],
                "attempt": manifest["attempt"], "manifest_sha256": hashlib.sha256(canonical_manifest(manifest)).hexdigest()}
    return "Unreviewed Ve OS native build candidate. Draft transport only; no registry publication or GPU qualification.\n\n```json\n" + json.dumps(identity, sort_keys=True) + "\n```\n"


def validate_release(client, release, manifest):
    require(type(release.get("id")) is int and release["id"] > 0, "Missing actual release identity")
    require(release.get("tag_name") == release_tag(manifest) and release.get("target_commitish") == manifest["source_commit"], "Release source or tag collision")
    require(release.get("draft") is True and release.get("prerelease") is True, "Existing release is not the owned draft prerelease")
    require(release.get("body") == release_body(manifest), "Existing release belongs to different build bytes")
    expected_upload = "https://uploads.github.com" + client.prefix + f"/releases/{release['id']}/assets{{?name,label}}"
    require(release.get("upload_url") == expected_upload, "Unexpected release upload endpoint")


def obtain_release(client, manifest):
    tag = release_tag(manifest)
    found = None
    for page in range(1, 11):
        _, releases = client.json("GET", client.prefix + f"/releases?per_page=100&page={page}")
        require(isinstance(releases, list) and len(releases) <= 100, "Invalid release listing")
        matches = [release for release in releases if release.get("tag_name") == tag]
        require(len(matches) <= 1 and not (matches and found is not None), "Ambiguous draft release identity")
        if matches:
            found = matches[0]
            break
        if len(releases) < 100:
            break
    else:
        require(False, "Release listing exceeded bounded lookup")
    if found is None:
        _, found = client.json("POST", client.prefix + "/releases", {"tag_name": tag, "target_commitish": manifest["source_commit"],
                                "name": "Ve OS llama.cpp unreviewed build " + manifest["run_id"] + "/" + manifest["attempt"],
                                "body": release_body(manifest), "draft": True, "prerelease": True, "make_latest": "false"}, accepted=(201,))
    validate_release(client, found, manifest)
    return found


def validate_remote_asset(actual, expected):
    require(type(actual.get("id")) is int and actual["id"] > 0, "Missing actual release asset identity")
    require(actual.get("name") == expected["name"] and actual.get("size") == expected["bytes"] and actual.get("state") == "uploaded",
            "Existing release asset conflicts with frozen bytes")
    require(actual.get("digest") in {None, "sha256:" + expected["sha256"]}, "Release asset digest conflicts")


def verified_readback(client, actual, expected):
    validate_remote_asset(actual, expected)
    for attempt in range(PROFILE["readback_attempts"]):
        try:
            client.readback(actual["id"], expected)
            return {"id": actual["id"], "name": expected["name"], "bytes": expected["bytes"], "sha256": expected["sha256"]}
        except (OSError, http.client.HTTPException):
            if attempt + 1 == PROFILE["readback_attempts"]:
                raise


def upload_export(client, root, manifest, environment_id):
    validate_manifest(manifest)
    assets = upload_assets(manifest)
    image_digest = hashlib.sha256()
    for asset in assets:
        with open_asset(root, asset) as stream:
            verify_stream(stream, asset)
            if asset["role"] == "image":
                remaining = asset["bytes"]
                while remaining:
                    data = stream.read(min(1024 * 1024, remaining))
                    require(data, "Frozen image stream was truncated")
                    image_digest.update(data)
                    remaining -= len(data)
    require(image_digest.hexdigest() == manifest["image"]["sha256"], "Complete frozen image hash differs")
    verify_destination(client, manifest["source_commit"], environment_id)
    release = obtain_release(client, manifest)
    existing = {asset["name"]: asset for asset in client.asset_list(release["id"])}
    require(set(existing) <= {asset["name"] for asset in assets}, "Owned draft contains unexpected assets")
    receipts = []
    for expected in assets:
        actual = existing.get(expected["name"])
        if actual is None:
            for attempt in range(PROFILE["upload_attempts"]):
                try:
                    with open_asset(root, expected) as stream:
                        verify_stream(stream, expected)
                        actual = client.upload(release["id"], expected, stream)
                    break
                except (OSError, http.client.HTTPException):
                    current = {asset["name"]: asset for asset in client.asset_list(release["id"])}
                    require(set(current) <= {asset["name"] for asset in assets}, "Draft changed during upload retry")
                    if expected["name"] in current:
                        actual = current[expected["name"]]
                        break
                    if attempt + 1 == PROFILE["upload_attempts"]:
                        raise
        require(actual is not None, "Asset upload produced no identity")
        receipts.append(verified_readback(client, actual, expected))
    verify_destination(client, manifest["source_commit"], environment_id)
    _, actual_release = client.json("GET", client.prefix + f"/releases/{release['id']}")
    validate_release(client, actual_release, manifest)
    final_assets = {asset["name"]: asset for asset in client.asset_list(release["id"])}
    require(set(final_assets) == {asset["name"] for asset in assets}, "Final release asset set differs")
    for receipt, expected in zip(receipts, assets):
        validate_remote_asset(final_assets[expected["name"]], expected)
        require(final_assets[expected["name"]]["id"] == receipt["id"], "Release asset identity changed after readback")
    return {"schema_version": 1, "status": "draft-export-verified", "repository_id": REPOSITORY_ID, "release_id": release["id"],
            "release_tag": release_tag(manifest), "source_commit": manifest["source_commit"], "assets": receipts,
            "charged_upload_body_bytes": client.uploaded, "charged_retrieval_body_bytes": client.downloaded, "public_release": False,
            "registry_publication": False, "gpu_qualification": False}
