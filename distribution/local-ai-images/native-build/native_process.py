import os
import subprocess
import time

from native_profile import require, unit_name


def controller_environment():
    uid = os.getuid()
    require(uid > 0, "Non-root controller required")
    runtime = "/run/user/" + str(uid)
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "XDG_RUNTIME_DIR": runtime,
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=" + runtime + "/bus"}


def validate_unit(unit):
    fields = unit.removeprefix("ve-os-native-").removesuffix(".service").split("-")
    require(len(fields) == 2 and unit == unit_name(*fields), "Invalid owned native unit")


def unit_state(unit, deadline=None):
    validate_unit(unit)
    remaining = 30 if deadline is None else min(30, deadline - time.monotonic())
    require(remaining > 0, "Native unit query deadline reached")
    result = subprocess.run(["/usr/bin/systemctl", "--user", "show", "--property=LoadState", "--property=ActiveState", unit],
                            env=controller_environment(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=remaining, check=False)
    fields = dict(line.split("=", 1) for line in result.stdout.decode().splitlines() if "=" in line)
    require(set(fields) == {"LoadState", "ActiveState"}, "Native unit state is unavailable")
    absent = fields == {"LoadState": "not-found", "ActiveState": "inactive"}
    require(result.returncode == 0 or absent, "Native unit state query failed")
    require(fields["LoadState"] in {"loaded", "not-found"}, "Native unit has unexpected load state")
    return fields["ActiveState"]


def stop_unit(unit, deadline):
    if unit_state(unit, deadline) in {"inactive", "failed"}:
        return
    remaining = min(30, deadline - time.monotonic())
    require(remaining > 0, "Cleanup deadline reached")
    result = subprocess.run(["/usr/bin/systemctl", "--user", "stop", unit], env=controller_environment(),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=remaining, check=False)
    require(result.returncode == 0, "Owned native unit could not be stopped")
    require(unit_state(unit, deadline) in {"inactive", "failed"}, "Owned native unit remains active")
