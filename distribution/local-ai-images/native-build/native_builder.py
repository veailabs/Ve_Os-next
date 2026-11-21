import hashlib
import json
import os
import subprocess
from pathlib import Path, PurePosixPath
import platform
import re
import sys
import time

from native_inputs import context_digest, input_manifest, verify_context
from native_profile import PROFILE, unit_name
from runner_resources import QualificationError, cgroups, mounts, require


ROOT = Path(__file__).resolve().parent


def isolated_environment(work, uid):
    require(type(uid) is int and uid > 0, "Rootless builder requires a non-root user")
    require(work.is_absolute() and work.resolve() == work, "Noncanonical build directory")
    return {"PATH": "/usr/bin:/bin", "HOME": str(work / "home"), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "XDG_CONFIG_HOME": str(work / "config"), "XDG_DATA_HOME": str(work / "data"),
            "XDG_CACHE_HOME": str(work / "cache"), "XDG_RUNTIME_DIR": "/run/user/" + str(uid),
            "TMPDIR": str(work / "tmp"), "REGISTRY_AUTH_FILE": str(work / "empty-auth.json"),
            "PYTHONDONTWRITEBYTECODE": "1"}


def validate_source_identity(source_sha, repository):
    require(re.fullmatch(r"[0-9a-f]{40}", source_sha) is not None, "Invalid reviewed source identity")
    require(repository in {"veailabs/Ve_Os-next", "veailabs/Ve_Os"}, "Unexpected source repository")


def service_command(work, source_sha, repository, run_id, attempt, uid, mode="build"):
    require(mode in {"smoke", "sources", "verify-sources", "build", "assemble", "verify-image"}, "Unsupported native execution mode")
    validate_source_identity(source_sha, repository)
    environment = isolated_environment(work, uid)
    unit = unit_name(run_id, attempt)
    return ["/usr/bin/systemd-run", "--user", "--unit=" + unit, "--wait", "--pipe", "--collect",
            "--expand-environment=no", "--property=Type=exec", "--property=Delegate=memory pids cpu",
            "--property=DelegateSubgroup=supervisor", "--property=MemoryMax=" + str(PROFILE["build_memory_bytes"]),
            "--property=MemorySwapMax=0", "--property=MemoryAccounting=yes",
            "--property=RuntimeMaxSec=" + str(300 if mode == "smoke" else PROFILE["validation_seconds"] if mode.startswith("verify-") else PROFILE["build_seconds"]), "--property=TimeoutStopSec=15",
            "--property=KillMode=control-group", "--working-directory=" + str(work), "/usr/bin/env", "-i",
            *[name + "=" + value for name, value in sorted(environment.items())],
            "/usr/bin/python3", str(ROOT / "native_builder.py"), "--child", mode, str(work), source_sha, repository, unit]


def verify_group(groups, unit):
    require(groups["version"] == 2 and len(groups["ancestors"]) >= 2, "Unified delegated cgroup required")
    require(re.fullmatch(r"ve-os-native-[1-9][0-9]{0,19}-[1-9][0-9]{0,9}\.service", unit), "Invalid build unit")
    current = Path(groups["ancestors"][0]["path"])
    group = Path(groups["ancestors"][1]["path"])
    require(current.name == "supervisor" and current.parent == group and group.name == unit, "Builder is outside its delegated unit")
    require((group / "memory.max").read_text().strip() == str(PROFILE["build_memory_bytes"]), "Build memory limit is not enforced")
    require((group / "memory.swap.max").read_text().strip() == "0", "Build swap is not disabled")
    require(not (group / "cgroup.procs").read_text().strip(), "Build cgroup parent contains processes")
    require("memory" in (group / "cgroup.controllers").read_text().split(), "Memory controller is not delegated")
    return group


def container_command(work, source_sha, repository, parent, context_sha, mode="build", source_image=None, compiled_image=None):
    require(re.fullmatch(r"[0-9a-f]{64}", context_sha), "Invalid context archive digest")
    validate_source_identity(source_sha, repository)
    require(parent.is_absolute() and ".." not in parent.parts, "Invalid container cgroup parent")
    require(mode in {"sources", "build", "assemble"}, "Invalid native build phase")
    if source_image is not None:
        require(mode in {"build", "assemble"} and re.fullmatch(r"sha256:[0-9a-f]{64}", source_image), "Invalid verified local source image")
    if compiled_image is not None:
        require(mode == "assemble" and re.fullmatch(r"sha256:[0-9a-f]{64}", compiled_image), "Invalid exact compiled image")
    arguments = ["/usr/bin/podman", "--cgroup-manager=cgroupfs", "--root=" + str(work / "store"),
            "--runroot=" + str(work / "runroot"), "--tmpdir=" + str(work / "podman-tmp"),
            "--hooks-dir=" + str(work / "empty-hooks"), "build", "--format=oci", "--pull=" + ("never" if source_image else "always"),
            "--no-cache", "--layers=false", "--jobs=1", "--retry=1", "--isolation=oci", "--network=" + ("none" if mode == "build" else "private"),
            "--pid=container", "--ipc=container", "--uts=container", "--userns=container", "--cgroupns=private",
            "--cgroup-parent=" + str(parent), "--http-proxy=false", "--authfile=" + str(work / "empty-auth.json"),
            "--tls-verify=true", "--platform=" + PROFILE["platform"], "--force-rm",
            "--build-arg=BASE=" + PROFILE["base"], "--build-arg=TARGETARCH=amd64",
            "--build-arg=VE_SOURCE_REVISION=sha256:" + context_sha, "--build-arg=VE_SOURCE_URL=urn:ve-os:local-source:sha256:" + context_sha,
            "--label=org.opencontainers.image.revision=sha256:" + context_sha,
            "--label=org.opencontainers.image.source=urn:ve-os:local-source:sha256:" + context_sha,
            "--target=" + {"sources": "source-ready", "build": "build", "assemble": "runtime"}[mode],
            "--iidfile=" + str(work / {"sources": "source-image-id", "build": "compiled-image-id", "assemble": "image-id"}[mode]),
            "--file=" + str(work / "context" / "Containerfile")]
    if source_image:
        arguments.append("--build-arg=SOURCE_BASE=" + source_image)
    if compiled_image:
        arguments.append("--build-arg=BUILD_OUTPUT=" + compiled_image)
    return arguments + [str(work / "context")]


def child(work, source_sha, repository, unit, mode="build"):
    require(mode in {"smoke", "sources", "verify-sources", "build", "assemble", "verify-image"}, "Unsupported native execution mode")
    from native_volume import verify_work_volume

    require(platform.system() == "Linux" and platform.machine() == PROFILE["architecture"], "Native Linux x64 builder required")
    require(os.getuid() == os.geteuid() and os.getuid() > 0, "Rootless user identity required")
    environment = isolated_environment(work, os.getuid())
    verify_work_volume(work, unit)
    require(work.is_dir() and work.stat().st_uid == os.getuid(), "Build directory must belong to the builder")
    require((work / "empty-auth.json").read_text() == '{"auths":{}}\n', "Builder registry auth must be empty")
    require((work / "empty-hooks").is_dir() and not list((work / "empty-hooks").iterdir()), "Builder hook directory must be empty")
    verify_context(work / "context", input_manifest())
    mounted = mounts(Path("/proc/self/mountinfo").read_text())
    groups = cgroups(Path("/proc/self/cgroup").read_text(), mounted)
    group = verify_group(groups, unit)
    (group / "cgroup.subtree_control").write_text("+memory +pids +cpu")
    containers = group / "containers"
    containers.mkdir()
    mount = next(item for item in mounted if item["type"] == "cgroup2" and Path(item["path"]) in group.parents)
    parent = PurePosixPath(mount["root"]) / containers.relative_to(mount["path"])
    if mode == "smoke":
        proof = smoke(work, parent, group, environment)
        proof.update(source_sha=source_sha, unit=unit, runtime=PROFILE["runtime"], status="native-smoke-passed")
        destination = work / "native-smoke.json"
        with destination.open("x") as output:
            json.dump(proof, output, indent=2)
        return
    proof_path = work.parent.parent / "native-smoke.json"
    require(proof_path.is_file() and not proof_path.is_symlink() and proof_path.stat().st_size <= PROFILE["document_bytes"],
            "Same-run native smoke proof is missing")
    proof = json.loads(proof_path.read_text())
    require(proof.get("status") == "native-smoke-passed" and proof.get("source_sha") == source_sha and proof.get("unit") == unit,
            "Native smoke proof does not match this build")
    digest = context_digest(work)
    if mode == "verify-sources":
        from native_sources import copy_sources, validate_sources

        source_image = (work / "source-image-id").read_text().strip()
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", source_image), "Source build did not return an exact image ID")
        prefix = podman_prefix(work)
        records = json.loads(podman_output(prefix + ["image", "inspect", source_image], environment))
        require(len(records) == 1 and records[0]["Id"] == source_image, "Source image identity differs")
        require(records[0]["Architecture"] == "amd64" and records[0]["Os"] == "linux", "Source acquisition used a different platform")
        require(records[0].get("Labels", {}).get("org.opencontainers.image.revision") == "sha256:" + digest,
                "Source acquisition used a different input context")
        deadline = time.monotonic() + PROFILE["validation_seconds"]
        copy_sources(prefix, source_image, work / "source-export", environment, deadline)
        validated = validate_sources(work / "source-export", work / "context", deadline)
        validated.update(source_sha=source_sha, unit=unit, context_sha256=digest, source_image_id=source_image)
        destination = work.parent.parent / "source-validated.json"
        with destination.open("x") as output:
            json.dump(validated, output, indent=2)
        destination.chmod(0o400)
        return
    if mode == "verify-image":
        verify_runtime(work, environment, parent, digest)
        return
    source_image = None
    if mode in {"build", "assemble"}:
        source_proof_path = work.parent.parent / "source-validated.json"
        require(source_proof_path.is_file() and not source_proof_path.is_symlink()
                and source_proof_path.stat().st_size <= PROFILE["document_bytes"], "Same-attempt source validation is missing")
        source_proof = json.loads(source_proof_path.read_text())
        require(source_proof.get("status") == "source-validation-passed" and source_proof.get("source_sha") == source_sha
                and source_proof.get("unit") == unit and source_proof.get("context_sha256") == digest,
                "Source validation does not match this attempt and context")
        source_image = source_proof.get("source_image_id", "")
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", source_image), "Validated source image identity is invalid")
        require((work / "source-image-id").read_text().strip() == source_image, "Source image changed since validation")
    compiled_image = None
    if mode == "assemble":
        compiled_image = (work / "compiled-image-id").read_text().strip()
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", compiled_image), "Compilation did not return an exact image ID")
    command = container_command(work, source_sha, repository, parent, digest, mode, source_image, compiled_image)
    os.execve(command[0], command, environment)


def verify_runtime(work, environment, parent, context_sha):
    from arch_oci import image_inventory
    from native_image import verify_package_files
    from native_sources import document

    deadline = time.monotonic() + PROFILE["validation_seconds"]
    prefix = podman_prefix(work)
    image_id = (work / "image-id").read_text().strip()
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", image_id), "Assembly did not return an exact image ID")
    source_proof = document(work.parent.parent / "source-validated.json")
    require(source_proof.get("status") == "source-validation-passed" and source_proof.get("context_sha256") == context_sha,
            "Runtime validation requires the matching completed source validation")
    commands = []
    for executable, option in (("/usr/bin/llama-server", "--version"), ("/usr/bin/llama-bench", "--help")):
        command = prefix + ["run", "--rm", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                            "--cgroupns=private", "--pid=private", "--ipc=private", "--uts=private", "--userns=private",
                            "--cgroup-parent=" + str(parent), "--http-proxy=false", "--entrypoint=" + executable, image_id, option]
        output = podman_output(command, environment)
        require(output.strip(), "Runtime executable returned no version/help evidence")
        commands.append({"executable": executable, "argument": option, "exit": 0, "output_sha256": hashlib.sha256(output).hexdigest(), "output_bytes": len(output)})
    disposable = [(work / name).read_text().strip() for name in ("compiled-image-id", "source-image-id")]
    require(len(set(disposable + [image_id])) == 3 and all(re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in disposable), "Intermediate image identity is unsafe")
    subprocess.run(prefix + ["rmi", *disposable], env=environment, check=True, timeout=min(120, deadline - time.monotonic()))
    image_path = work / "image.oci.tar"
    require(not image_path.exists(), "Runtime archive already exists")
    subprocess.run(prefix + ["save", "--quiet", "--format=oci-archive", "--uncompressed=false", "--output=" + str(image_path), image_id],
                   env=environment, check=True, timeout=deadline - time.monotonic())
    observed = image_inventory(image_path, context_sha)
    require(observed["source"]["config_digest"] == image_id, "Exported archive differs from tested runtime image")
    correspondence = verify_package_files(observed["inventory"], work / "source-export", work / "context", source_proof, deadline)
    proof = {"source": observed["source"], "source_correspondence": correspondence, "commands": commands,
             "gpu_qualification": False, "status": "image-validation-passed" if correspondence["complete"] else "image-validation-incomplete"}
    encoded = json.dumps(proof, sort_keys=True, indent=2).encode() + b"\n"
    require(len(encoded) <= PROFILE["document_bytes"], "Runtime validation evidence exceeds limit")
    (work / "image-validated.json").write_bytes(encoded)
    require(correspondence["complete"], "Distributed image paths still need original-source explanation: " + ", ".join(item["path"] for item in correspondence["unexplained_paths"][:10]))


def podman_prefix(work):
    return ["/usr/bin/podman", "--cgroup-manager=cgroupfs", "--root=" + str(work / "store"),
            "--runroot=" + str(work / "runroot"), "--tmpdir=" + str(work / "podman-tmp"),
            "--hooks-dir=" + str(work / "empty-hooks")]


def podman_output(command, environment):
    result = subprocess.run(command, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=90, check=False)
    require(result.returncode == 0, "Native container probe command failed")
    require(len(result.stdout) <= PROFILE["document_bytes"], "Native probe output exceeds limit")
    return result.stdout


def validate_probe_environment(raw):
    names = [entry.split(b"=", 1)[0].decode("ascii", errors="strict") for entry in raw.split(b"\0") if entry]
    forbidden = ("GITHUB_", "GH_", "ACTIONS_", "SSH_", "AWS_", "AZURE_", "GOOGLE_", "GIT_CONFIG_", "GIT_ASKPASS")
    require(not any(name.startswith(forbidden) or any(part in name.upper() for part in ("TOKEN", "PASSWORD", "SECRET", "CREDENTIAL", "PROXY"))
                    for name in names), "Unexpected credential channel in native container")
    return sorted(names)


def smoke(work, parent, group, environment):
    prefix = podman_prefix(work)
    name = "ve-native-probe"
    command = prefix + ["run", "--detach", "--name=" + name, "--pull=always", "--authfile=" + str(work / "empty-auth.json"),
                        "--tls-verify=true", "--platform=" + PROFILE["platform"], "--network=none", "--read-only",
                        "--cap-drop=ALL", "--security-opt=no-new-privileges", "--cgroupns=private",
                        "--pid=private", "--ipc=private", "--uts=private", "--userns=private", "--cgroup-parent=" + str(parent),
                        "--http-proxy=false", PROFILE["base"], "/bin/sh", "-c", "while :; do sleep 1; done"]
    try:
        identifier = podman_output(command, environment).decode().strip()
        require(re.fullmatch(r"[0-9a-f]{64}", identifier), "Invalid native probe container identity")
        records = json.loads(podman_output(prefix + ["inspect", identifier], environment))
        require(len(records) == 1 and records[0]["Id"] == identifier, "Ambiguous native container identity")
        state = records[0]["State"]
        require(state["Running"] is True and type(state["Pid"]) is int and state["Pid"] > 0, "Native probe is not running")
        pid = state["Pid"]
        process = Path("/proc") / str(pid)
        observed = cgroups((process / "cgroup").read_text(), mounts(Path("/proc/self/mountinfo").read_text()))
        require(observed["version"] == 2 and observed["ancestors"], "Native process has no unified cgroup")
        actual_group = Path(observed["ancestors"][0]["path"])
        require(group in actual_group.parents and group / "containers" in actual_group.parents,
                "Native container escaped the bounded cgroup")
        namespaces = {}
        for namespace in ("user", "pid", "net", "ipc", "uts", "mnt", "cgroup"):
            value = (process / "ns" / namespace).stat().st_ino
            require(value != (Path("/proc/self/ns") / namespace).stat().st_ino, "Native namespace is shared with the host: " + namespace)
            namespaces[namespace] = value
        mappings = [[int(value) for value in line.split()] for line in (process / "uid_map").read_text().splitlines()]
        require(any(start == 0 and host == os.getuid() and count == 1 for start, host, count in mappings), "Unexpected rootless UID mapping")
        require(not any(host == 0 for _, host, _ in mappings), "Native UID mapping includes host root")
        names = validate_probe_environment(podman_output(prefix + ["exec", identifier, "/usr/bin/env", "-0"], environment))
        images = json.loads(podman_output(prefix + ["image", "inspect", PROFILE["base"]], environment))
        require(len(images) == 1 and images[0]["Architecture"] == "amd64" and images[0]["Os"] == "linux", "Native base platform mismatch")
        require(images[0].get("Digest") == PROFILE["base"].split("@", 1)[1], "Native base digest mismatch")
        marker = work / "filesystem-probe"
        with marker.open("xb") as output:
            output.write(b"ve-os-native-filesystem-probe\n" * 4096)
            output.flush()
            os.fsync(output.fileno())
        require(marker.stat().st_dev == work.stat().st_dev, "Native probe writes outside bounded filesystem")
        marker.unlink()
        return {"container_id": identifier, "base_digest": images[0]["Digest"], "container_cgroup": str(actual_group),
                "memory_max_bytes": int((group / "memory.max").read_text()), "swap_max_bytes": int((group / "memory.swap.max").read_text()),
                "namespaces": namespaces, "uid_map": mappings, "environment_names": names, "filesystem_device": work.stat().st_dev}
    finally:
        podman_output(prefix + ["rm", "--force", "--ignore", name], environment)


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 7 and sys.argv[1] == "--child", "Only the protected resource-child entry is supported")
        child(Path(sys.argv[3]), sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[2])
    except (QualificationError, OSError, ValueError, KeyError) as error:
        print("Native build refused: " + str(error), file=sys.stderr)
        sys.exit(1)
