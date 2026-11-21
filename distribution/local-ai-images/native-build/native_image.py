import hashlib
import json
from pathlib import Path
import re
import tarfile
import time

from arch_inventory import parse_desc, safe_path
from native_inputs import unique_object
from native_profile import PROFILE, require
from native_sources import document, inventory_records


def matches(expected, actual):
    kind = "file" if expected["kind"] == "hardlink" else expected["kind"]
    actual_kind = "file" if actual["kind"] == "hardlink" else actual["kind"]
    fields = ["mode", "uid", "gid"]
    if kind == "file":
        fields.append("sha256")
    elif kind == "symlink":
        fields.append("target")
    return kind == actual_kind and all(expected.get(field) == actual.get(field) for field in fields)


def verify_package_files(observed, source_root, context, source_proof, deadline):
    receipt = document(source_root / "acquisition.json")
    original = {tuple(item["identity"][name] for name in ("name", "version", "base", "architecture")): item for item in receipt["packages"]}
    files_by_layer = {layer["layer"]: layer["entries"] for layer in observed["physical_files"]}
    covered = set()
    changed = set()
    changed_directories = set()
    for package in observed["physical_packages"]:
        key = tuple(package[name] for name in ("name", "version", "base", "architecture"))
        require(key in original, "Distributed package has no original producer/source binding: " + package["name"] + " " + package["version"])
        proof = original[key]
        owned = set()
        for metadata in package["metadata_versions"]:
            if "mtree" in metadata:
                require(metadata["mtree"] == proof["metadata"][".MTREE"], "Distributed package mtree differs from authenticated original: " + package["name"])
            if "files" in metadata:
                owned.update(safe_path(path) for path in parse_desc(observed["metadata_blobs"][metadata["files"]])["FILES"])
        entry = proof["file_inventory"]
        seen_owned = set()
        with tarfile.open(source_root / entry["archive"], "r:") as archive:
            member = archive.getmember(entry["path"])
            with archive.extractfile(member) as stream:
                for expected in inventory_records(stream, entry, deadline):
                    path = expected["path"]
                    if path == ".INSTALL":
                        installed_script = "var/lib/pacman/local/" + package["name"] + "-" + package["version"] + "/install"
                        for layer in package["layers"]:
                            actual = files_by_layer[layer].get(installed_script)
                            if actual and actual.get("sha256") == expected.get("sha256"):
                                covered.add((layer, installed_script))
                    if path not in owned:
                        continue
                    seen_owned.add(path)
                    for layer in package["layers"]:
                        actual = files_by_layer[layer].get(path)
                        if actual is None:
                            continue
                        identity = (layer, path)
                        if matches(expected, actual):
                            covered.add(identity)
                        else:
                            changed.add(identity)
                            if "directory" in {expected["kind"], actual["kind"]}:
                                changed_directories.add(identity)
        require(seen_owned == owned, "Installed package ownership differs from original archive: " + package["name"])
    output_entry = observed["filesystem"].get("usr/share/ve-os-local-ai/installed-output-files.json")
    require(output_entry is not None and output_entry["sha256"] in observed["metadata_blobs"], "Actual compiler output inventory is missing")
    compiled = json.loads(observed["metadata_blobs"][output_entry["sha256"]], object_pairs_hook=unique_object)
    require(isinstance(compiled, dict) and compiled and all(path.startswith(("usr/bin/", "usr/lib/")) for path in compiled), "Invalid compiled runtime output scope")
    context_files = {}
    for path in context.rglob("*"):
        if path.is_file() and not path.is_symlink():
            context_files[path.relative_to(context).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    source_files = source_proof["upstream_files"]["llama.cpp"]
    generated = []
    unexplained = []
    directories = []
    for layer, entries in files_by_layer.items():
        for path, actual in entries.items():
            require(time.monotonic() < deadline, "Image/source correspondence deadline exceeded")
            if (layer, path) in changed_directories:
                unexplained.append({"layer": layer, "path": path, "reason": "modified-package-file"})
                continue
            if (layer, path) in covered:
                continue
            if actual["kind"] == "directory":
                directories.append((layer, path, actual))
                continue
            expected_context = path.removeprefix("locks/") if path.startswith("locks/") else "pacman.conf" if path == "etc/pacman.conf" else "packaging-LICENSE" if path == "usr/share/licenses/ve-os-local-ai/LICENSE" else None
            if expected_context in context_files and actual.get("sha256") == context_files[expected_context]:
                generated.append({"layer": layer, "path": path, "source": "reviewed-context"})
                continue
            if path in compiled and matches(compiled[path], actual):
                generated.append({"layer": layer, "path": path, "source": "verified-upstream-and-build-tool-sources"})
                continue
            prefix = "usr/share/licenses/llama.cpp/"
            if path.startswith(prefix):
                source_path = path[len(prefix):]
                if source_path.startswith("vendor-original-sources/"):
                    source_path = "vendor/" + source_path[len("vendor-original-sources/"):]
                source = source_files.get(source_path)
                if source and source["kind"] == actual["kind"] and (source.get("sha256") == actual.get("sha256") if source["kind"] == "file" else source.get("target") == actual.get("target")):
                    generated.append({"layer": layer, "path": path, "source": "original-upstream-notice"})
                    continue
            manager_metadata = path == "var/lib/pacman/local/ALPM_DB_VERSION" or re.fullmatch(r"var/lib/pacman/local/[^/]+/(desc|files|mtree)", path)
            build_evidence = re.fullmatch(r"usr/share/ve-os-local-ai/(arch-(build|runtime)-(installed|transaction)\.txt|CMakeCache\.txt|compile-link-inputs\.tar\.gz|installed-elf-dynamic\.txt|upstream-tree\.txt|llama-upstream-source\.tar\.gz|installed-output-files\.json)", path)
            package_evidence = re.fullmatch(r"usr/share/ve-os-local-ai/arch-(build|runtime)-package-evidence/[0-9a-f]{64}/(\.(PKGINFO|BUILDINFO|MTREE)|archive-(filename|bytes)|archive\.sig)", path)
            if manager_metadata or build_evidence or package_evidence:
                generated.append({"layer": layer, "path": path, "source": "package-manager-or-reviewed-build-evidence"})
                continue
            unexplained.append({"layer": layer, "path": path, "reason": "modified-package-file" if (layer, path) in changed else "unowned-distributed-file"})
    generated_parents = {(item["layer"], parent.as_posix()) for item in generated for parent in Path(item["path"]).parents if parent.as_posix() != "."}
    for layer, path, actual in directories:
        if (layer, path) in generated_parents and all(actual[field] == value for field, value in (("uid", 0), ("gid", 0), ("mode", 0o755))):
            generated.append({"layer": layer, "path": path, "source": "reviewed-generated-parent-directory"})
        else:
            unexplained.append({"layer": layer, "path": path, "reason": "unowned-distributed-directory"})
    return {"system_format": "arch-pacman", "physical_packages": [{key: value for key, value in package.items() if key != "metadata_versions"} for package in observed["physical_packages"]],
            "final_packages": observed["final_packages"], "matched_physical_paths": len(covered), "generated_paths": generated,
            "unexplained_paths": unexplained, "complete": not unexplained}
