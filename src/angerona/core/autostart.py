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

Implemented with Windows' built-in ScheduledTasks PowerShell module rather
than pywin32, so the task can set a hidden GUI executable, working directory,
battery behavior, and restart policy without another dependency.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

TASK_NAME = "AngeronaAutostart"
_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_SYSTEM_ROOT = Path(os.environ.get("SystemRoot", r"C:\Windows"))
_SCHTASKS = _SYSTEM_ROOT / "System32" / "schtasks.exe"
_POWERSHELL = (
    _SYSTEM_ROOT / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
)

_REGISTER_TASK_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$action = New-ScheduledTaskAction `
    -Execute $env:ANGERONA_AUTOSTART_EXE `
    -Argument $env:ANGERONA_AUTOSTART_ARGS `
    -WorkingDirectory $env:ANGERONA_AUTOSTART_CWD
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:ANGERONA_AUTOSTART_USER
$principal = New-ScheduledTaskPrincipal `
    -UserId $env:ANGERONA_AUTOSTART_USER `
    -LogonType Interactive `
    -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -Hidden `
    -MultipleInstances IgnoreNew `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask `
    -TaskName $env:ANGERONA_AUTOSTART_TASK `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Force | Out-Null
"""


def _target_command() -> str:
    """The exact command line Task Scheduler should launch at logon —
    mirrors core/privilege.py's own packaged-vs-dev resolution logic, so
    autostart always launches the same way a normal elevated run would."""
    executable, arguments, _ = _target_action()
    return f'"{executable}" {arguments}'.rstrip()


def _target_action() -> tuple[str, str, str]:
    """Return executable, arguments, and working directory for Task Scheduler.

    Source builds use ``pythonw.exe``. ``python.exe`` creates a blank console at
    logon, and closing that console terminates Angerona with a control-C status.
    Frozen GUI builds already have no console.
    """
    from angerona.core.data_paths import project_root

    working_directory = str(project_root())
    if getattr(sys, "frozen", False):
        return sys.executable, "", working_directory

    interpreter = Path(sys.executable)
    windowed = interpreter.with_name("pythonw.exe")
    executable = windowed if windowed.is_file() else interpreter
    return str(executable), "-m angerona", working_directory


def _current_user() -> str:
    domain = os.environ.get("USERDOMAIN", "").strip()
    username = os.environ.get("USERNAME", "").strip()
    if domain and username:
        return f"{domain}\\{username}"
    return username


def is_enabled() -> bool:
    """True if the logon scheduled task currently exists."""
    if sys.platform != "win32":
        return False
    try:
        result = subprocess.run(
            [str(_SCHTASKS), "/query", "/tn", TASK_NAME],
            capture_output=True, text=True, timeout=10,
            creationflags=_CREATE_NO_WINDOW,
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
        executable, arguments, working_directory = _target_action()
        user = _current_user()
        if not user:
            return False
        env = os.environ.copy()
        env.update({
            "ANGERONA_AUTOSTART_EXE": executable,
            "ANGERONA_AUTOSTART_ARGS": arguments,
            "ANGERONA_AUTOSTART_CWD": working_directory,
            "ANGERONA_AUTOSTART_USER": user,
            "ANGERONA_AUTOSTART_TASK": TASK_NAME,
        })
        subprocess.run(
            [str(_POWERSHELL), "-NoProfile", "-NonInteractive", "-Command",
             _REGISTER_TASK_SCRIPT],
            capture_output=True, text=True, timeout=20, check=True, env=env,
            creationflags=_CREATE_NO_WINDOW,
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
            [str(_SCHTASKS), "/delete", "/tn", TASK_NAME, "/f"],
            capture_output=True, text=True, timeout=15,
            creationflags=_CREATE_NO_WINDOW,
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
