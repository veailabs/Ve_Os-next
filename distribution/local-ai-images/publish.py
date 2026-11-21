import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from urllib.parse import quote


ROOT = Path(__file__).resolve().parent
REPOSITORY_ID = 1465654995
ENVIRONMENT = "ve-os-image-publication"
ENVIRONMENT_ID = 28014484873
OWNER_REVIEWER_ID = 214956837
PLATFORMS = {
    "tensorfold": "linux/arm64",
    "sdcpp-cuda": "linux/arm64",
    "tensorfold-dsv41": "linux/arm64",
    "tensorfold-glm53": "linux/arm64",
    "tensorfold-nemotron-bolt": "linux/arm64",
    "llamacpp": "linux/amd64",
    "sdcpp": "linux/amd64",
    "acestep": "linux/amd64",
}
SHA = re.compile(r"[0-9a-f]{64}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
CONFIG = "application/vnd.oci.image.config.v1+json"
LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key")
        result[key] = value
    return result


def decode(data):
    require(len(data) <= 16 * 1024 * 1024, "JSON document too large")
    return json.loads(data, object_pairs_hook=unique_object)


def read_json(path):
    with path.open("rb") as stream:
        return decode(stream.read(16 * 1024 * 1024 + 1))


def hash_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def fields(value, expected):
    require(isinstance(value, dict) and set(value) == set(expected), "Unexpected record fields")


def positive(value, maximum):
    return type(value) is int and 0 < value <= maximum


def validate_asset_fields(asset):
    require(isinstance(asset["name"], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", asset["name"]), "Invalid asset name")
    require(positive(asset["bytes"], 2 * 1024**3 - 1), "Invalid asset size")
    require(isinstance(asset["sha256"], str) and SHA.fullmatch(asset["sha256"]), "Invalid asset hash")


def validate_assets(assets):
    require(isinstance(assets, list) and 1 <= len(assets) <= 32, "Invalid asset list")
    ids, names, total = set(), set(), 0
    for asset in assets:
        fields(asset, ("id", "name", "bytes", "sha256"))
        require(positive(asset["id"], 2**63 - 1) and asset["id"] not in ids, "Invalid or repeated asset ID")
        validate_asset_fields(asset)
        require(asset["name"] not in names, "Repeated asset name")
        ids.add(asset["id"])
        names.add(asset["name"])
        total += asset["bytes"]
    return total


def built_sources(value):
    result = set()
    for item in value.split(","):
        match = re.fullmatch(r"([a-z0-9][a-z0-9+.-]*) \(= ([^)]+)\)", item.strip())
        require(match is not None, "Invalid built-source identity")
        result.add(match.groups())
    return result


def expected_system_sources(runtime, root=ROOT):
    mapping = root / runtime / "debian-source-map.tsv"
    require(mapping.is_file(), "System source-package mapping is missing")
    rows = [line.split("\t") for line in mapping.read_text().splitlines()]
    require(rows and all(len(row) == 5 for row in rows), "Invalid system source-package mapping")
    expected = {(row[3], row[4]) for row in rows}
    using = read_json(root / runtime / "built-using.json")
    require(isinstance(using, list), "Invalid built-source record")
    for entry in using:
        require(entry.get("field") in ("Built-Using", "Static-Built-Using"), "Unknown built-source field")
        expected.update(built_sources(entry["sources"]))
    return expected


def status_sources(status):
    sources = set()
    for paragraph in status.split("\n\n"):
        fields, current = {}, None
        for line in paragraph.splitlines():
            if line.startswith((" ", "\t")) and current:
                fields[current] += " " + line.strip()
            elif ":" in line:
                current, value = line.split(":", 1)
                fields[current] = value.strip()
        if fields.get("Status") != "install ok installed":
            continue
        source = fields.get("Source", fields["Package"])
        match = re.fullmatch(r"([^ ()]+)(?: \(([^)]+)\))?", source)
        require(match is not None, "Invalid installed source identity")
        sources.add((match[1], match[2] or fields["Version"]))
        for key in ("Built-Using", "Static-Built-Using"):
            if fields.get(key):
                sources.update(built_sources(fields[key]))
    require(sources, "No installed system source identities")
    return sources


def verify_system_sources(archive_path, source):
    status, unpacked = None, 0
    target = "var/lib/dpkg/status"
    with tarfile.open(archive_path, "r:") as archive:
        manifest = decode(archive.extractfile("blobs/sha256/" + source["image_digest"][7:]).read())
        for layer in manifest["layers"]:
            inherited_removed, replacement = False, None
            with tarfile.open(fileobj=archive.extractfile("blobs/sha256/" + layer["digest"][7:]), mode="r|gz") as contents:
                for member in contents:
                    unpacked += member.size
                    require(unpacked <= 64 * 1024**3, "Image filesystem exceeds validation bound")
                    name = member.name.removeprefix("./")
                    parent, _, leaf = name.rpartition("/")
                    if leaf.startswith(".wh."):
                        deleted = parent if leaf == ".wh..wh..opq" else "/".join(filter(None, (parent, leaf[4:])))
                        if not deleted or target == deleted or target.startswith(deleted + "/"):
                            inherited_removed = True
                    if name == target:
                        require(member.type == tarfile.REGTYPE and member.size <= 2 * 1024 * 1024, "Invalid installed package metadata")
                        replacement = contents.extractfile(member).read().decode()
            if inherited_removed:
                status = None
            if replacement is not None:
                status = replacement
    require(status is not None, "Image has no installed Debian package metadata")
    require(status_sources(status) == expected_system_sources(source["runtime"]), "Source mapping differs from actual image package metadata")


def source_delivery(runtime, root=ROOT):
    path = root / runtime / "source-delivery.json"
    require(path.is_file(), "Corresponding-source delivery record is missing")
    delivery = read_json(path)
    require(type(delivery.get("schema_version")) is int and delivery["schema_version"] == 1, "Unsupported source-delivery schema")
    require(delivery.get("status") == "complete", "Corresponding-source delivery is incomplete")
    expected = expected_system_sources(runtime, root)
    entries = delivery.get("debian_sources", [])
    require(isinstance(entries, list) and len(entries) == len(expected) and {(entry.get("package"), entry.get("version")) for entry in entries} == expected, "Corresponding-source package closure is incomplete")
    upstream = delivery.get("upstream_sources", [])
    require(isinstance(upstream, list) and upstream, "Upstream source delivery is missing")
    if runtime == "tensorfold":
        require({entry.get("name") for entry in upstream} >= {"tensorfold", "libjpeg-turbo", "libwebp"}, "TensorFold upstream source closure is incomplete")
    paths = {}
    for entry in entries + upstream:
        files = entry.get("files", [])
        require(isinstance(files, list) and files, "Source component has no files")
        for file in files:
            name = file.get("path", "")
            require(isinstance(name, str) and name and name == str(PurePosixPath(name)) and not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts and "\\" not in name and "\0" not in name, "Unsafe source bundle path")
            require(positive(file.get("bytes"), 2 * 1024**3 - 1) and isinstance(file.get("sha256"), str) and SHA.fullmatch(file["sha256"]), "Invalid corresponding-source file identity")
            identity = (file["bytes"], file["sha256"])
            require(name not in paths or paths[name] == identity, "Conflicting corresponding-source paths")
            paths[name] = identity
    archives = delivery.get("source_archives", [])
    require(isinstance(archives, list) and 1 <= len(archives) <= 32, "Actual corresponding-source bundles have not been built")
    for archive in archives:
        fields(archive, ("name", "bytes", "sha256"))
        validate_asset_fields(archive)
    require(len({archive["name"] for archive in archives}) == len(archives), "Repeated corresponding-source bundle name")
    return delivery


def source_record(runtime, root=ROOT):
    require(runtime in PLATFORMS, "Unknown runtime")
    source = read_json(root / runtime / "source.json")
    fields(source, ("schema_version", "runtime", "platform", "context_sha256", "archive_sha256", "archive_bytes", "image_digest", "config_digest"))
    require(type(source["schema_version"]) is int and source["schema_version"] == 1, "Unsupported source schema")
    require(source["runtime"] == runtime and source["platform"] == PLATFORMS[runtime], "Source identity mismatch")
    for name in ("context_sha256", "archive_sha256"):
        require(isinstance(source[name], str) and SHA.fullmatch(source[name]), "Invalid source hash")
    for name in ("image_digest", "config_digest"):
        require(isinstance(source[name], str) and DIGEST.fullmatch(source[name]), "Invalid image digest")
    require(positive(source["archive_bytes"], 32 * 1024**3), "Invalid archive size")
    require(hash_file(root / runtime / "context.tar") == source["context_sha256"], "Source context checksum mismatch")
    return source


def release_record(runtime, source, root=ROOT):
    path = root / runtime / "release.json"
    require(path.is_file(), "No reviewed release asset record; publication is disabled")
    record = read_json(path)
    fields(record, ("schema_version", "repository_id", "runtime", "source_commit", "release_id", "release_tag", "assets", "source_manifest_sha256", "source_assets"))
    require(type(record["schema_version"]) is int and record["schema_version"] == 1, "Unsupported release schema")
    require(type(record["repository_id"]) is int and record["repository_id"] == REPOSITORY_ID, "Wrong repository identity")
    require(record["runtime"] == runtime, "Wrong release runtime")
    require(isinstance(record["source_commit"], str) and re.fullmatch(r"[0-9a-f]{40}", record["source_commit"]), "Invalid source commit")
    require(positive(record["release_id"], 2**63 - 1), "Missing real release ID")
    require(isinstance(record["release_tag"], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", record["release_tag"]), "Invalid release tag")
    require(validate_assets(record["assets"]) == source["archive_bytes"], "Asset sizes do not match reviewed archive")
    delivery = source_delivery(runtime, root)
    require(record["source_manifest_sha256"] == hash_file(root / runtime / "source-delivery.json"), "Source-delivery manifest checksum mismatch")
    validate_assets(record["source_assets"])
    require([{key: asset[key] for key in ("name", "bytes", "sha256")} for asset in record["source_assets"]] == delivery["source_archives"], "Source assets do not match reviewed source bundles")
    all_assets = record["assets"] + record["source_assets"]
    require(len({asset["id"] for asset in all_assets}) == len(all_assets) and len({asset["name"] for asset in all_assets}) == len(all_assets), "Image and source assets must be distinct")
    return record


def validate_oci(path, source, original=True):
    require(path.is_file() and not path.is_symlink(), "Archive must be a regular file")
    if original:
        require(path.stat().st_size == source["archive_bytes"], "Archive size mismatch")
        require(hash_file(path) == source["archive_sha256"], "Archive checksum mismatch")
    require(path.stat().st_size <= 32 * 1024**3, "Archive too large")
    with tarfile.open(path, "r:") as archive:
        members = {}
        for member in archive:
            require(member.name not in members, "Duplicate archive member")
            require(len(members) < 4096, "Too many archive members")
            directory = member.name in ("blobs", "blobs/sha256") and member.isdir()
            regular = member.type == tarfile.REGTYPE and (member.name in ("index.json", "oci-layout") or re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", member.name))
            require(directory or regular, "Unsafe or unexpected archive member")
            require(member.size <= 10_000_000_000, "Blob exceeds registry layer limit")
            if member.isfile() and member.name.startswith("blobs/"):
                require(hashlib.file_digest(archive.extractfile(member), "sha256").hexdigest() == member.name.rsplit("/", 1)[1], "Blob checksum mismatch")
            members[member.name] = member

        def document(name):
            require(name in members and members[name].isfile(), "Missing OCI document")
            require(members[name].size <= 16 * 1024 * 1024, "OCI document too large")
            return decode(archive.extractfile(members[name]).read())

        used = set()

        def descriptor(value, media_type):
            require(isinstance(value, dict) and value.get("mediaType") == media_type, "Unexpected descriptor media type")
            digest = value.get("digest", "")
            require(isinstance(digest, str) and DIGEST.fullmatch(digest), "Invalid descriptor digest")
            name = "blobs/sha256/" + digest[7:]
            require(name in members and type(value.get("size")) is int and value["size"] == members[name].size, "Descriptor size or blob mismatch")
            require(not value.get("urls"), "External OCI blobs are forbidden")
            used.add(name)
            return name

        require(document("oci-layout") == {"imageLayoutVersion": "1.0.0"}, "Unsupported OCI layout")
        index = document("index.json")
        require(index.get("schemaVersion") == 2 and len(index.get("manifests", [])) == 1, "Expected one OCI image")
        entry = index["manifests"][0]
        name = descriptor(entry, MANIFEST)
        require(entry["digest"] == source["image_digest"], "Image manifest mismatch")
        manifest = document(name)
        require(manifest.get("schemaVersion") == 2 and manifest.get("mediaType") == MANIFEST, "Invalid image manifest")
        config_name = descriptor(manifest["config"], CONFIG)
        require(manifest["config"]["digest"] == source["config_digest"], "Image configuration mismatch")
        config = document(config_name)
        require(config.get("os", "") + "/" + config.get("architecture", "") == source["platform"], "Image architecture mismatch")
        labels = config.get("config", {}).get("Labels", {})
        require(labels.get("org.opencontainers.image.revision") == "sha256:" + source["context_sha256"], "Image source revision mismatch")
        require(labels.get("org.opencontainers.image.source") == "urn:ve-os:local-source:sha256:" + source["context_sha256"], "Image source identity mismatch")
        layers = manifest.get("layers", [])
        require(isinstance(layers, list) and 0 < len(layers) <= 256, "Invalid layer list")
        for layer in layers:
            descriptor(layer, LAYER)
        diff_ids = config.get("rootfs", {}).get("diff_ids", [])
        require(config.get("rootfs", {}).get("type") == "layers" and len(diff_ids) == len(layers) and all(isinstance(d, str) and DIGEST.fullmatch(d) for d in diff_ids), "Invalid root filesystem identity")
        require(used == {name for name in members if name.startswith("blobs/sha256/")}, "Unreferenced OCI blobs")
    return source["image_digest"]


def public_api(endpoint):
    request = urllib.request.Request("https://api.github.com/" + endpoint, headers={"Accept": "application/vnd.github+json", "User-Agent": "Ve-OS-image-publication"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return decode(response.read(16 * 1024 * 1024 + 1))


def run(arguments, **kwargs):
    result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    require(result.returncode == 0, "Command failed: " + arguments[0])
    return result.stdout


def workflow_identity():
    require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch", "Publication requires a manually dispatched GitHub workflow")
    require(os.environ.get("GITHUB_REPOSITORY_ID") == str(REPOSITORY_ID) and os.environ.get("GITHUB_REF") == "refs/heads/master", "Wrong workflow repository or ref")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    require(repository in ("veailabs/Ve_Os-next", "veailabs/Ve_Os"), "Unexpected repository name")
    sha = os.environ.get("GITHUB_SHA", "")
    require(re.fullmatch(r"[0-9a-f]{40}", sha), "Invalid workflow commit")
    repo = public_api("repos/" + repository)
    require(repo.get("id") == REPOSITORY_ID and repo.get("private") is False and repo.get("default_branch") == "master", "Repository must be the approved public repository with master default")
    branch = public_api("repos/" + repository + "/branches/master")
    require(branch.get("protected") is True and branch.get("commit", {}).get("sha") == sha, "Master must remain protected at the dispatched commit")
    environment = public_api("repos/" + repository + "/environments/" + ENVIRONMENT)
    require(environment.get("id") == ENVIRONMENT_ID and environment.get("can_admins_bypass") is False, "Publication environment identity or bypass policy changed")
    require((environment.get("deployment_branch_policy") or {}).get("protected_branches") is True, "Publication environment must restrict protected branches")
    reviewer_rules = [rule for rule in environment.get("protection_rules", []) if rule.get("type") == "required_reviewers"]
    require(len(reviewer_rules) == 1, "Publication environment requires exactly one owner reviewer rule")
    reviewers = reviewer_rules[0].get("reviewers", [])
    require(len(reviewers) == 1 and reviewers[0].get("type") == "User" and reviewers[0].get("reviewer", {}).get("id") == OWNER_REVIEWER_ID, "Publication environment requires only the owner reviewer")
    require(run(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip() == sha, "Checkout differs from dispatched commit")
    return repository


def fetch_archive(repository, record, source, destination):
    release = public_api(f"repos/{repository}/releases/{record['release_id']}")
    require(release.get("id") == record["release_id"] and release.get("tag_name") == record["release_tag"] and release.get("draft") is False, "Release identity mismatch or unpublished release")
    assets = {asset["id"]: asset for asset in release.get("assets", [])}
    with destination.open("xb") as output:
        for expected in record["source_assets"] + record["assets"]:
            actual = assets.get(expected["id"], {})
            require(actual.get("name") == expected["name"] and actual.get("size") == expected["bytes"] and actual.get("state") == "uploaded", "Release asset metadata mismatch")
            require(actual.get("digest") in (None, "sha256:" + expected["sha256"]), "GitHub asset digest mismatch")
            arguments = ["gh", "api", f"repos/{repository}/releases/assets/{expected['id']}", "-H", "Accept: application/octet-stream"]
            with subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
                size, digest = 0, hashlib.sha256()
                try:
                    while block := process.stdout.read(1024 * 1024):
                        size += len(block)
                        require(size <= expected["bytes"], "Asset exceeds reviewed size")
                        digest.update(block)
                        if expected in record["assets"]:
                            output.write(block)
                    require(process.wait(timeout=30) == 0, "Asset download failed")
                    require(size == expected["bytes"] and digest.hexdigest() == expected["sha256"], "Asset checksum mismatch")
                finally:
                    if process.poll() is None:
                        process.terminate()
                        process.wait(timeout=10)
    validate_oci(destination, source)
    verify_system_sources(destination, source)


def copy_image(source, destination, authfile=None, source_authfile=None, anonymous=False):
    arguments = ["skopeo", "copy", "--preserve-digests"]
    if authfile:
        arguments += ["--dest-authfile", str(authfile)]
    if source_authfile:
        arguments += ["--src-authfile", str(source_authfile)]
    if anonymous:
        arguments.append("--src-no-creds")
    run(arguments + [source, destination], timeout=1200)


def verify_package_metadata(package, repository, runtime):
    require(package.get("package_type") == "container" and package.get("name") == "ve-os-local-ai/" + runtime, "Registry package identity mismatch")
    require(package.get("owner", {}).get("login") == "veailabs", "Registry package owner mismatch")
    linked = package.get("repository") or {}
    require(linked.get("id") == REPOSITORY_ID and linked.get("full_name") == repository, "Registry package is not linked to the approved repository")
    require(package.get("visibility") == "public", "Package is private; a package administrator must make it public before anonymous verification")


def prepare_release(runtime, work):
    source = source_record(runtime)
    record = release_record(runtime, source)
    repository = workflow_identity()
    run(["git", "merge-base", "--is-ancestor", record["source_commit"], os.environ["GITHUB_SHA"]], cwd=ROOT)
    context_path = f"distribution/local-ai-images/{runtime}/context.tar"
    require(hashlib.sha256(run(["git", "show", record["source_commit"] + ":" + context_path], cwd=ROOT)).hexdigest() == source["context_sha256"], "Reviewed source commit does not contain this context")
    require(not work.exists(), "Publication work directory must be new")
    require(shutil.disk_usage(work.parent).free >= source["archive_bytes"] * 3 + 1024**3, "Insufficient publication disk space")
    work.mkdir(mode=0o700)
    archive = work / "image.oci.tar"
    fetch_archive(repository, record, source, archive)
    return source, repository, archive


def publish(runtime, work):
    source, repository, archive = prepare_release(runtime, work)
    destination = "ghcr.io/veailabs/ve-os-local-ai/" + runtime
    tag = "sha256-" + source["image_digest"][7:]
    with tempfile.TemporaryDirectory(prefix="ve-os-registry-", dir=work) as private:
        auth = Path(private) / "auth.json"
        empty = Path(private) / "anonymous.json"
        empty.write_text('{"auths":{}}\n')
        token = os.environ.get("GH_TOKEN", "")
        require(token and os.environ.get("GITHUB_ACTOR"), "Workflow token is unavailable")
        run(["skopeo", "login", "--authfile", str(auth), "--username", os.environ["GITHUB_ACTOR"], "--password-stdin", "ghcr.io"], input=token.encode(), timeout=30)
        workflow_identity()
        copy_image("oci-archive:" + str(archive), "docker://" + destination + "@" + source["image_digest"], authfile=auth)
        existing = subprocess.run(["skopeo", "inspect", "--raw", "--authfile", str(auth), "docker://" + destination + ":" + tag], capture_output=True, timeout=60)
        if existing.returncode == 0:
            require("sha256:" + hashlib.sha256(existing.stdout).hexdigest() == source["image_digest"], "Refusing to overwrite an existing different tag")
        else:
            failure = existing.stderr.decode(errors="replace").lower()
            require("manifest unknown" in failure or "name unknown" in failure, "Unable to establish whether destination tag exists")
            workflow_identity()
            copy_image("oci-archive:" + str(archive), "docker://" + destination + ":" + tag, authfile=auth)
        authenticated = run(["skopeo", "inspect", "--raw", "--authfile", str(auth), "docker://" + destination + "@" + source["image_digest"]], timeout=60)
        require("sha256:" + hashlib.sha256(authenticated).hexdigest() == source["image_digest"], "Published image digest changed")
        package = decode(run(["gh", "api", "orgs/veailabs/packages/container/" + quote("ve-os-local-ai/" + runtime, safe="")], timeout=30))
        verify_package_metadata(package, repository, runtime)
        anonymous = work / "anonymous.oci.tar"
        copy_image("docker://" + destination + "@" + source["image_digest"], "oci-archive:" + str(anonymous), source_authfile=empty, anonymous=True)
        validate_oci(anonymous, source, original=False)
    result = {"runtime": runtime, "image": destination + "@" + source["image_digest"], "anonymous_pull_verified": True, "catalog_updated": False, "gpu_inference_tested": False}
    print(json.dumps(result))
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("validate", "publish", "preflight", "verify-release"))
    parser.add_argument("runtime", choices=tuple(PLATFORMS))
    parser.add_argument("path", type=Path, nargs="?")
    args = parser.parse_args()
    if args.operation == "preflight":
        release_record(args.runtime, source_record(args.runtime))
        workflow_identity()
        print("Publication preflight passed")
    elif args.operation == "validate":
        require(args.path is not None, "An archive path is required")
        source = source_record(args.runtime)
        result = validate_oci(args.path, source)
        verify_system_sources(args.path, source)
        print(result)
    elif args.operation == "verify-release":
        require(args.path is not None, "A new work directory is required")
        source, repository, archive = prepare_release(args.runtime, args.path)
        print(json.dumps({"image_digest": source["image_digest"], "release_and_source_assets_verified": True, "registry_published": False}))
    else:
        require(args.path is not None, "A new work directory is required")
        publish(args.runtime, args.path)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, AttributeError, json.JSONDecodeError, tarfile.TarError, subprocess.SubprocessError) as error:
        raise SystemExit("Image publication failed: " + str(error))
