import json
import os
from pathlib import Path
import platform
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time

import native_builder as builder
import native_volume as volume
from native_inputs import stage_context, unique_object, write_context_archive
from native_profile import PROFILE, QualificationError, admission, require, unit_name
import runner_resources as runner
from native_process import controller_environment, stop_unit


class Cancelled(QualificationError):
    pass


def failure_details(error):
    failures = []
    seen = set()
    while error is not None and id(error) not in seen and len(failures) < 8:
        seen.add(id(error))
        failures.append({"type": type(error).__name__, "message": str(error)[:4096]})
        error = error.__cause__ or (None if error.__suppress_context__ else error.__context__)
    return {"failures_latest_first": failures}


def report_failure_log(path):
    if not path.exists():
        return
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as log:
        metadata = os.fstat(log.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_size <= PROFILE["document_bytes"],
                "Invalid native failure log")
        log.seek(max(0, metadata.st_size - 32768))
        tail = log.read(32768).decode(errors="replace")
    print(json.dumps({"status": "native-stage-failed", "stage": path.stem, "bounded_log_tail": tail}))


def bounded_service(command, log_path, unit, deadline, host_path=None):
    require(deadline > time.monotonic(), "Native service deadline reached")
    descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    observed = 0
    process = None
    try:
        with os.fdopen(descriptor, "wb") as log:
            process = subprocess.Popen(command, env=controller_environment(), stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    require(time.monotonic() < deadline, "Native service deadline reached")
                    if host_path is not None:
                        require(shutil.disk_usage(host_path).free >= PROFILE["disk_floor_bytes"], "Host disk floor reached during native stage")
                    for key, _ in selector.select(timeout=min(0.2, max(0, deadline - time.monotonic()))):
                        data = os.read(key.fileobj.fileno(), 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        require(observed + len(data) <= PROFILE["document_bytes"], "Native service log exceeds limit")
                        log.write(data)
                        observed += len(data)
                remaining = deadline - time.monotonic()
                require(remaining > 0, "Native service deadline reached")
                returncode = process.wait(timeout=remaining)
                require(returncode == 0, "Native service did not complete successfully")
        return {"log_bytes": observed, "exit_code": returncode}
    except BaseException:
        if process is not None:
            try:
                stop_unit(unit, time.monotonic() + 30)
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
        raise
    finally:
        if process is not None and process.stdout is not None:
            process.stdout.close()


def read_document(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_size <= PROFILE["document_bytes"],
                "Invalid native evidence file")
        data = source.read(PROFILE["document_bytes"] + 1)
        require(len(data) <= PROFILE["document_bytes"], "Native evidence grew beyond limit")
        return json.loads(data, object_pairs_hook=unique_object)


def write_document(path, value):
    encoded = json.dumps(value, indent=2).encode() + b"\n"
    require(len(encoded) <= PROFILE["document_bytes"], "Native evidence exceeds limit")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(descriptor, "wb") as output:
        output.write(encoded)


def validate_smoke(proof, source_sha, unit):
    require(proof.get("status") == "native-smoke-passed" and proof.get("runtime") == "llamacpp", "Native smoke did not pass")
    require(proof.get("source_sha") == source_sha and proof.get("unit") == unit, "Native smoke source or run changed")
    require(proof.get("base_digest") == PROFILE["base"].split("@", 1)[1], "Native smoke base changed")
    require(proof.get("memory_max_bytes") == PROFILE["build_memory_bytes"] and proof.get("swap_max_bytes") == 0,
            "Native smoke resource limits differ")
    require(set(proof.get("namespaces", {})) == {"user", "pid", "net", "ipc", "uts", "mnt", "cgroup"}, "Native smoke namespaces incomplete")
    require(all(type(value) is int and value > 0 for value in proof["namespaces"].values()), "Invalid native namespace evidence")
    names = proof.get("environment_names")
    require(isinstance(names, list) and all(isinstance(name, str) and name.isascii() and "\0" not in name and "=" not in name for name in names),
            "Invalid native environment evidence")
    builder.validate_probe_environment(b"\0".join(name.encode() + b"=discarded" for name in names))


def prepare_work(work):
    for name in ("home", "config", "data", "cache", "tmp", "store", "runroot", "podman-tmp", "empty-hooks"):
        (work / name).mkdir(mode=0o700)
    with (work / "empty-auth.json").open("x") as auth:
        auth.write('{"auths":{}}\n')
    (work / "empty-auth.json").chmod(0o400)
    proof = stage_context(work / "context")
    proof["archive"] = write_context_archive(work)
    return proof


def workflow_identity():
    require(platform.system() == "Linux" and platform.machine() == PROFILE["architecture"], "Native Linux x64 runner required")
    environment = os.environ
    event = runner.read_json(Path(environment["GITHUB_EVENT_PATH"]))
    repository = runner.validate_identity(environment, event, platform.system(), platform.machine(), runner.run(["git", "rev-parse", "HEAD"]))
    source = environment["GITHUB_SHA"]
    master = runner.run(["git", "-c", "credential.helper=", "ls-remote", "https://github.com/" + repository + ".git", "refs/heads/master"]).split()
    require(master == [source, "refs/heads/master"], "Master moved since native dispatch")
    require(not runner.run(["git", "status", "--porcelain", "--untracked-files=no"]), "Tracked native source was modified")
    return source, repository


def qualify():
    source, repository = workflow_identity()
    report = runner.inventory(os.environ, platform.machine())
    require(admission(report)["resource_admission_passed"], "Native runner resource admission failed")
    require(os.getuid() > 0 and os.getuid() == os.geteuid(), "Non-root native runner required")
    return source, repository, report


def destination_preflight():
    from arch_oci import publisher
    from release_export import verify_destination

    source, repository = workflow_identity()
    require(os.environ.get("VE_OS_IMAGE_BUILD_EXPORT_ENVIRONMENT_ID") == "28071521718", "Approved build/export environment ID is missing or changed")
    class AnonymousDestination:
        def __init__(self):
            self.repository = repository
            self.prefix = "/repos/" + repository
        def json(self, method, endpoint):
            require(method == "GET" and (endpoint.startswith(self.prefix + "/") or endpoint == self.prefix
                    or endpoint == "/repositories/1465654995"), "Unapproved build preflight request")
            result = publisher.public_api(endpoint.lstrip("/"))
            require(len(json.dumps(result).encode()) <= PROFILE["document_bytes"], "Build destination metadata exceeds limit")
            return 200, result
    verify_destination(AnonymousDestination(), source, 28071521718)
    return source, repository


def owned_paths():
    run_id, attempt = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"]
    root = volume.volume_root(Path(os.environ["RUNNER_TEMP"]), run_id, attempt)
    return root, root / "filesystem/build", unit_name(run_id, attempt)


def cleanup_owned():
    root, work, unit = owned_paths()
    if not (root / "volume.json").exists():
        return {"status": "no-owned-volume"}
    receipt = read_document(root / "volume.json")
    if receipt.get("state") == "removed":
        return {"status": "owned-volume-already-removed"}
    deadline = time.monotonic() + 300
    if receipt.get("state") == "mounted":
        stop_unit(unit, deadline)
    volume.remove_volume(Path(os.environ["RUNNER_TEMP"]), receipt, deadline=deadline)
    return {"status": "owned-volume-removed"}


def prepare_export():
    from native_export import freeze_export, stage_export

    started = time.monotonic()
    build_deadline = started + PROFILE["build_seconds"]
    source, repository = destination_preflight()
    qualify()
    root, work, unit = owned_paths()
    run_id, attempt = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"]
    previous = {}
    def cancel(signum, frame):
        raise Cancelled("Native build/export preparation was cancelled")
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.signal(signum, cancel)
    current_log = None
    try:
        root, work, receipt = volume.create_volume(Path(os.environ["GITHUB_WORKSPACE"]), Path(os.environ["RUNNER_TEMP"]), run_id, attempt, deadline=min(build_deadline, started + 300))
        inputs = prepare_work(work)
        for mode in ("smoke", "sources", "verify-sources", "build", "assemble"):
            volume.verify_work_volume(work, unit)
            command = builder.service_command(work, source, repository, run_id, attempt, os.getuid(), mode=mode)
            current_log = work / (mode + ".log")
            stage_deadline = min(build_deadline, time.monotonic() + (300 if mode == "smoke" else PROFILE["validation_seconds"] if mode == "verify-sources" else PROFILE["build_seconds"]))
            bounded_service(command, current_log, unit, stage_deadline, host_path=root)
            if mode == "smoke":
                proof = read_document(work / "native-smoke.json")
                validate_smoke(proof, source, unit)
                proof.update(input_context=inputs, volume_budget=receipt["budget"],
                             runner_image={"os": os.environ.get("ImageOS"), "version": os.environ.get("ImageVersion")})
                write_document(root / "native-smoke.json", proof)
            print(json.dumps({"stage": mode, "status": "passed", "source_sha": source, "run_id": run_id, "attempt": attempt}))
        validation_deadline = min(started + PROFILE["job_seconds"] - PROFILE["upload_seconds"] - 300, time.monotonic() + PROFILE["validation_seconds"])
        current_log = work / "verify-image.log"
        bounded_service(builder.service_command(work, source, repository, run_id, attempt, os.getuid(), mode="verify-image"), current_log, unit, validation_deadline, host_path=root)
        destination_preflight()
        stop_unit(unit, validation_deadline)
        staged, manifest = stage_export(work, source, run_id, attempt)
        frozen = freeze_export(work, staged, manifest, validation_deadline)
        result = {"status": "validated-export-frozen", "source_commit": source, "run_id": run_id, "attempt": attempt,
                  "frozen_directory": str(frozen), "image": manifest["image"], "gpu_qualification": False, "uploaded": False}
        write_document(root / "prepared-export.json", result)
        print(json.dumps(result))
    except BaseException:
        if current_log is not None and current_log.is_file() and not current_log.is_symlink():
            require(current_log.stat().st_size <= PROFILE["document_bytes"], "Failed stage log exceeded limit")
            shutil.copyfile(current_log, root / "native-failure.log")
            report_failure_log(current_log)
        cleanup_owned()
        raise
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def upload_prepared():
    from native_export import load_manifest
    from release_export import GitHubReleaseClient, upload_export

    source, repository = destination_preflight()
    root, work, unit = owned_paths()
    volume.verify_work_volume(work, unit)
    stop_unit(unit, time.monotonic() + 30)
    prepared = read_document(root / "prepared-export.json")
    require(prepared.get("status") == "validated-export-frozen" and prepared.get("source_commit") == source, "No validated export exists for this source")
    frozen = root / "filesystem/frozen"
    manifest = load_manifest(frozen)
    require(manifest["source_commit"] == source and manifest["run_id"] == os.environ["GITHUB_RUN_ID"]
            and manifest["attempt"] == os.environ["GITHUB_RUN_ATTEMPT"], "Frozen export belongs to a different workflow attempt")
    token = os.environ.pop("GH_TOKEN", "")
    deadline = time.monotonic() + PROFILE["upload_seconds"]
    client = GitHubReleaseClient(repository, token, deadline)
    def expired(signum, frame):
        raise QualificationError("Release export reached its hard stage deadline")
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, PROFILE["upload_seconds"])
    try:
        result = upload_export(client, frozen, manifest, 28071521718)
        write_document(root / "release-export.json", result)
        print(json.dumps(result, indent=2))
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def execute_smoke():
    started = time.monotonic()
    deadline = started + 300
    source, repository, inventory = qualify()
    runner_temp = Path(os.environ["RUNNER_TEMP"])
    checkout = Path(os.environ["GITHUB_WORKSPACE"])
    run_id, attempt = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"]
    unit = unit_name(run_id, attempt)
    root = volume.volume_root(runner_temp, run_id, attempt)
    receipt = None
    result = None
    proof = None
    previous = {}
    def cancel(signum, frame):
        raise Cancelled("Native qualification was cancelled")
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.signal(signum, cancel)
    try:
        root, work, receipt = volume.create_volume(checkout, runner_temp, run_id, attempt, deadline=deadline)
        inputs = prepare_work(work)
        command = builder.service_command(work, source, repository, run_id, attempt, os.getuid(), mode="smoke")
        execution = bounded_service(command, root / "native-smoke.log", unit, deadline)
        proof = read_document(work / "native-smoke.json")
        validate_smoke(proof, source, unit)
        volume.verify_work_volume(work, unit)
        proof.update(elapsed_seconds=time.monotonic() - started, input_context=inputs, volume_budget=receipt["budget"],
                     runner_image={"os": os.environ.get("ImageOS"), "version": os.environ.get("ImageVersion")}, execution=execution)
        write_document(root / "native-smoke.json", proof)
        result = {"status": "native-smoke-passed", "source_sha": source, "unit": unit,
                  "proof": str(root / "native-smoke.json"), "build_qualified": False}
    except BaseException:
        report_failure_log(root / "native-smoke.log")
        raise
    finally:
        try:
            if receipt is None and (root / "volume.json").exists():
                receipt = read_document(root / "volume.json")
            if receipt is not None:
                cleanup_deadline = time.monotonic() + 300
                if receipt.get("state") == "mounted":
                    stop_unit(unit, cleanup_deadline)
                volume.remove_volume(runner_temp, receipt, deadline=cleanup_deadline)
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
    require(result is not None, "Native qualification did not produce evidence")
    print(json.dumps({**result, "observed_proof": proof}, indent=2))
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write("## Native isolation smoke\n\n```json\n" + json.dumps(proof, indent=2) + "\n```\n\nNo image compilation or export was performed.\n")


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 2 and sys.argv[1] in {"smoke", "destination-preflight", "prepare-export", "upload", "cleanup"}, "Unsupported native operation")
        if sys.argv[1] == "smoke":
            execute_smoke()
        elif sys.argv[1] == "destination-preflight":
            source, repository = destination_preflight()
            print(json.dumps({"status": "protected-destination-verified", "source_commit": source, "repository": repository, "native_qualified": False}))
        elif sys.argv[1] == "prepare-export":
            prepare_export()
        elif sys.argv[1] == "upload":
            upload_prepared()
        else:
            print(json.dumps(cleanup_owned()))
    except (QualificationError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print("Native execution failed: " + json.dumps(failure_details(error)), file=sys.stderr)
        sys.exit(1)
