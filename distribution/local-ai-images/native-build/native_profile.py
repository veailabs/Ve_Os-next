import re


class QualificationError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise QualificationError(message)


def unit_name(run_id, attempt):
    require(re.fullmatch(r"[1-9][0-9]{0,19}", run_id) is not None, "Invalid workflow run identity")
    require(re.fullmatch(r"[1-9][0-9]{0,9}", attempt) is not None, "Invalid workflow attempt")
    return "ve-os-native-" + run_id + "-" + attempt + ".service"


GIB = 1024 ** 3
MIB = 1024 ** 2
REPOSITORY_ID = 1465654995
PROFILE = {
    "runtime": "llamacpp",
    "runner": "ubuntu-24.04",
    "architecture": "x86_64",
    "platform": "linux/amd64",
    "base": "docker.io/library/archlinux@sha256:fcee73ea1b96e236248f53a213f71276cc9072d9025b58bce9915e32f19963ae",
    "source_repository": "https://github.com/ggml-org/llama.cpp",
    "source_commit": "6f311d7ad63dce97a3ad1deaafb7cc044bb8c26c",
    "source_tree": "4f4e5909f01bb09924a9005dc3c94705aff0f9b1",
    "source_tag": "b12521",
    "package_snapshot": "2026/11/19",
    "compiler_jobs": 1,
    "shader_jobs": 1,
    "build_memory_bytes": 8 * GIB,
    "build_swap_bytes": 0,
    "host_memory_reserve_bytes": 2 * GIB,
    "admission_free_bytes": 10 * GIB,
    "disk_growth_bytes": 8 * GIB,
    "disk_floor_bytes": 2 * GIB,
    "job_seconds": 330 * 60,
    "build_seconds": 260 * 60,
    "validation_seconds": 25 * 60,
    "upload_seconds": 35 * 60,
    "image_bytes": 3 * GIB,
    "source_bytes": 4 * GIB,
    "metadata_bytes": 16 * MIB,
    "document_bytes": 4 * MIB,
    "export_bytes": 7 * GIB + 16 * MIB,
    "asset_bytes": GIB,
    "asset_count": 16,
    "upload_attempts": 2,
    "readback_attempts": 2,
    "upload_body_bytes": 15 * GIB,
    "readback_body_bytes": 15 * GIB,
    "network_body_bytes": 30 * GIB,
    "scratch_bytes": GIB,
}


def admission(report):
    reasons = []
    if report["architecture"] != PROFILE["architecture"]:
        reasons.append("The first build profile requires native x86_64")
    for filesystem in report["filesystems"]:
        if filesystem["available_bytes"] < PROFILE["admission_free_bytes"]:
            reasons.append("Insufficient free disk space: " + filesystem["path"])
        if filesystem["available_inodes"] <= 0:
            reasons.append("No free inodes: " + filesystem["path"])
    if not report["filesystems"]:
        reasons.append("Filesystem measurements are missing")
    memory = report["memory"]
    required = PROFILE["build_memory_bytes"] + PROFILE["host_memory_reserve_bytes"]
    if memory["effective_available_bytes"] < required:
        reasons.append("Insufficient effective available memory for build and host reserve")
    if not report["available_cpus"]:
        reasons.append("No available native CPUs")
    if report["cgroup"]["version"] != 2:
        reasons.append("Unified cgroup resource enforcement has not been established")
    for name in ("podman", "git", "python3", "flock", "systemd-run", "skopeo"):
        if not report["tools"].get(name):
            reasons.append("Required tool is missing: " + name)
    return {"runtime": PROFILE["runtime"], "resource_admission_passed": not reasons,
            "reasons": reasons, "build_qualified": False,
            "remaining_checks": ["actual rootless child resource enforcement", "complete reviewed input context",
                                 "native build and executable checks", "complete Arch corresponding-source validation",
                                 "bounded export and readback"]}
