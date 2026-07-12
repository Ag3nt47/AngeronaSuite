"""autostart.py — launch Angerona automatically at Windows logon.

Angerona always needs to run elevated (see core/privilege.py's ensure_admin(),
which relaunches through a UAC prompt if it isn't). A plain Registry "Run"
key launches UNelevated, so it would pop a fresh UAC prompt on every single
boot — annoying, and exactly the kind of prompt a user reflexively dismisses,
which would defeat the point of a security tool that's supposed to already be
running. A Scheduled Task with runLevel="highest" and a logon trigger solves
both problems: it launches already-elevated, silently, with no UAC prompt at
boot, because Task Scheduler's own elevation is granted once — right here,
when the task is created (which does need an admin token, but Angerona
already has one by the time this ever runs).

Implemented via schtasks.exe (always present on Windows, no extra
dependency) rather than pywin32's COM Task Scheduler API, to keep this
self-contained and easy to read/audit.
"""
from __future__ import annotations

import subprocess
import sys

TASK_NAME = "AngeronaAutostart"


def _target_command() -> str:
    """The exact command line Task Scheduler should launch at logon —
    mirrors core/privilege.py's own packaged-vs-dev resolution logic, so
    autostart always launches the same way a normal elevated run would."""
    if getattr(sys, "frozen", False):
        # Packaged .exe: launch it directly, no extra args needed.
        return f'"{sys.executable}"'
    # Dev checkout: launch the same interpreter as `python -m angerona`.
    return f'"{sys.executable}" -m angerona'


def is_enabled() -> bool:
    """True if the logon scheduled task currently exists."""
    if sys.platform != "win32":
        return False
    try:
        result = subprocess.run(
            ["schtasks", "/query", "/tn", TASK_NAME],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def enable_autostart() -> bool:
    """Create (or refresh) the logon scheduled task. Requires an elevated
    token — safe to call any time Angerona is already running, since
    ensure_admin() guarantees that by the time app code runs. Idempotent:
    safe to call every startup (/f overwrites any existing definition, so
    this also self-heals if the task was ever edited or removed outside
    the app). Returns True on apparent success."""
    if sys.platform != "win32":
        return False
    try:
        subprocess.run(
            ["schtasks", "/create", "/tn", TASK_NAME,
             "/tr", _target_command(),
             "/sc", "onlogon", "/rl", "highest", "/f"],
            capture_output=True, text=True, timeout=15, check=True,
        )
        return True
    except Exception:
        return False


def disable_autostart() -> bool:
    """Remove the logon scheduled task, if present. Safe to call even if
    it doesn't exist (schtasks /delete on a missing task just fails
    quietly, which is fine here)."""
    if sys.platform != "win32":
        return False
    try:
        subprocess.run(
            ["schtasks", "/delete", "/tn", TASK_NAME, "/f"],
            capture_output=True, text=True, timeout=15,
        )
        return True
    except Exception:
        return False


def sync(enabled: bool) -> None:
    """Make the on-disk scheduled task match the desired state. Called on
    every startup (driven by Config.autostart_enabled) and from Settings'
    Save button, so the task always reflects the user's actual choice
    rather than whatever was true the last time someone toggled it."""
    if enabled:
        enable_autostart()
    else:
        disable_autostart()
