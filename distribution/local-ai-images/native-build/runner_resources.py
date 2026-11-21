import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import sys
import time

from native_profile import PROFILE, REPOSITORY_ID, QualificationError, admission, require


def run(args, timeout=60, deadline=None):
    if deadline is not None:
        timeout = min(timeout, deadline - time.monotonic())
        require(timeout > 0, "Native stage deadline reached")
    result = subprocess.run(args, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, timeout=timeout)
    require(result.returncode == 0, "Required inventory command failed: " + args[0])
    require(len(result.stdout) <= PROFILE["document_bytes"], "Inventory command output exceeded its limit")
    return result.stdout.strip()


def read_json(path):
    require(path.stat().st_size <= PROFILE["document_bytes"], "Event document exceeds size limit")
    return json.loads(path.read_text())


def validate_identity(environment, event, system, architecture, head):
    require(system == "Linux", "Linux hosted runner required")
    expected = {"GITHUB_ACTIONS": "true", "VERIFIED_RUNNER_ENVIRONMENT": "github-hosted",
                "GITHUB_REPOSITORY_ID": str(REPOSITORY_ID), "GITHUB_REF": "refs/heads/master",
                "VERIFIED_REF_PROTECTED": "true", "GITHUB_EVENT_NAME": "workflow_dispatch"}
    for name, value in expected.items():
        require(environment.get(name) == value, "Unqualified runner identity: " + name)
    repository = event.get("repository", {})
    require(type(repository.get("id")) is int and repository["id"] == REPOSITORY_ID, "Wrong event repository")
    require(repository.get("private") is False, "Public repository required")
    name = repository.get("full_name", "")
    require(name in {"veailabs/Ve_Os-next", "veailabs/Ve_Os"}, "Unexpected repository name")
    require(environment.get("GITHUB_REPOSITORY") == name, "Repository identity differs from event")
    sha = environment.get("GITHUB_SHA", "")
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None and head == sha, "Checkout differs from dispatched source")
    require(architecture in {"x86_64", "aarch64"} and architecture == environment.get("EXPECTED_ARCH"),
            "Native architecture mismatch")
    require(environment.get("RECLAIM_TOOLS", "false") in {"true", "false"}, "Unexpected reclaim input")
    return name


def filesystem(path):
    resolved = Path(path).resolve(strict=True)
    usage = shutil.disk_usage(resolved)
    return {"path": str(resolved), "device": resolved.stat().st_dev, "total_bytes": usage.total,
            "available_bytes": usage.free, "available_inodes": os.statvfs(resolved).f_favail}


def unescape_mount(value):
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), value)


def mounts(text):
    result = []
    for line in text.splitlines():
        fields = line.split()
        separator = fields.index("-")
        result.append({"root": unescape_mount(fields[3]), "path": unescape_mount(fields[4]),
                       "type": fields[separator + 1], "source": unescape_mount(fields[separator + 2]),
                       "options": fields[5].split(",")})
    return result


def cgroups(memberships, mounted):
    unified = [line[3:] for line in memberships.splitlines() if line.startswith("0::")]
    if len(unified) != 1:
        return {"version": None, "ancestors": []}
    member = PurePosixPath(unified[0])
    require(member.is_absolute() and ".." not in member.parts, "Unsafe cgroup membership")
    candidates = [item for item in mounted if item["type"] == "cgroup2" and
                  (PurePosixPath(item["root"]) == member or PurePosixPath(item["root"]) in member.parents)]
    require(len(candidates) == 1, "Cannot resolve unified cgroup mount")
    mount = candidates[0]
    root = Path(mount["path"])
    current = root / member.relative_to(mount["root"])
    result = []
    while True:
        require(current.is_dir(), "Missing current cgroup directory")
        values = {"path": str(current)}
        for name in ("memory.max", "memory.current", "memory.events", "cpu.max", "cpuset.cpus.effective"):
            path = current / name
            if path.exists():
                values[name] = path.read_text().strip()
        result.append(values)
        if current == root:
            break
        current = current.parent
    return {"version": 2, "ancestors": result}


def memory_inventory(text, groups):
    memory = {}
    for line in text.splitlines():
        name, value = line.split(":", 1)
        if name in {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}:
            memory[name] = int(value.split()[0]) * 1024
    require("MemAvailable" in memory and "MemTotal" in memory, "Memory measurements are incomplete")
    available = memory["MemAvailable"]
    maximum = memory["MemTotal"]
    for group in groups["ancestors"]:
        limit = group.get("memory.max", "max")
        if limit != "max":
            require(limit.isdigit() and group.get("memory.current", "").isdigit(), "Invalid cgroup memory measurement")
            maximum = min(maximum, int(limit))
            available = min(available, max(0, int(limit) - int(group["memory.current"])))
    memory["effective_max_bytes"] = maximum
    memory["effective_available_bytes"] = min(available, maximum)
    return memory


def reclaim_candidates(architecture):
    require(architecture in {"x86_64", "aarch64"}, "Unsupported architecture")
    paths = [Path("/usr/share/dotnet"), Path("/usr/share/swift")]
    if architecture == "x86_64":
        paths.append(Path("/usr/local/lib/android"))
    return paths


def validate_reclaim(path, candidates, mounted):
    require(path in candidates, "SDK path is not allowlisted")
    if not path.exists() and not path.is_symlink():
        return False
    require(path.is_dir() and not path.is_symlink() and path.resolve() == path, "Unexpected SDK path")
    require(not any(Path(item["path"]) == path or path in Path(item["path"]).parents for item in mounted),
            "Mounted SDK path cannot be removed")
    return True


def reclaim(architecture):
    candidates = reclaim_candidates(architecture)
    removed = []
    for path in candidates:
        mounted = mounts(Path("/proc/self/mountinfo").read_text())
        if validate_reclaim(path, candidates, mounted):
            run(["sudo", "-n", "rm", "-rf", "--one-file-system", "--", str(path)], timeout=180)
            require(not path.exists() and not path.is_symlink(), "SDK removal did not complete")
            removed.append(str(path))
    os.sync()
    return removed


def inventory(environment, architecture):
    mounted = mounts(Path("/proc/self/mountinfo").read_text())
    groups = cgroups(Path("/proc/self/cgroup").read_text(), mounted)
    paths = ["/", environment["RUNNER_TEMP"], environment["GITHUB_WORKSPACE"]]
    tools = {name: shutil.which(name) for name in ("podman", "skopeo", "git", "python3", "objdump", "flock", "systemd-run")}
    sizes = []
    for path in reclaim_candidates(architecture):
        if path.is_dir() and not path.is_symlink() and path.resolve() == path:
            size = int(run(["sudo", "-n", "du", "-sx", "--block-size=1", str(path)]).split()[0])
            sizes.append({"path": str(path), "allocated_bytes": size})
    return {"architecture": architecture, "filesystems": [filesystem(path) for path in paths],
            "memory": memory_inventory(Path("/proc/meminfo").read_text(), groups), "cgroup": groups,
            "available_cpus": sorted(os.sched_getaffinity(0)), "unused_tool_sizes": sizes, "tools": tools}


def main():
    require(platform.system() == "Linux", "Linux hosted runner required")
    environment = os.environ
    event = read_json(Path(environment["GITHUB_EVENT_PATH"]))
    architecture = platform.machine()
    repository = validate_identity(environment, event, platform.system(), architecture, run(["git", "rev-parse", "HEAD"]))
    master = run(["git", "-c", "credential.helper=", "ls-remote", "https://github.com/" + repository + ".git",
                  "refs/heads/master"]).split()
    require(master == [environment["GITHUB_SHA"], "refs/heads/master"], "Protected master moved since dispatch")
    report = {"source_sha": environment["GITHUB_SHA"], "architecture": architecture,
              "image_os": environment.get("ImageOS"), "image_version": environment.get("ImageVersion"),
              "before": inventory(environment, architecture), "removed": [], "build_qualified": False}
    if environment.get("RECLAIM_TOOLS", "false") == "true":
        report["removed"] = reclaim(architecture)
    report["after"] = inventory(environment, architecture)
    report["llamacpp_admission"] = admission(report["after"])
    encoded = json.dumps(report, indent=2)
    require(len(encoded.encode()) <= PROFILE["document_bytes"], "Resource report exceeds size limit")
    print(encoded)
    with open(environment["GITHUB_STEP_SUMMARY"], "a") as summary:
        summary.write("## Native runner inventory\n\n```json\n" + encoded + "\n```\n\nNo image was built or qualified.\n")


if __name__ == "__main__":
    try:
        main()
    except (QualificationError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print("Runner qualification failed: " + str(error), file=sys.stderr)
        sys.exit(1)
