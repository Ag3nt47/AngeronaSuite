"""Platform-native per-user autostart for Angerona.

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

Windows uses a highest-privilege Scheduled Task. Linux uses the freedesktop XDG
autostart directory. macOS uses a current-user LaunchAgent with ``KeepAlive``
disabled so an intentional quit is never mistaken for a crash.
"""
from __future__ import annotations

import os
import plistlib
import secrets
import subprocess
import sys
from pathlib import Path

TASK_NAME = "AngeronaAutostart"
LAUNCH_AGENT_LABEL = "org.angerona.security-suite"
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


def _target_argv() -> list[str]:
    executable, arguments, _working_directory = _target_action()
    return [executable, *(["-m", "angerona"] if arguments else [])]


def _validated_entry_text(value: str) -> str:
    if not value or any(char in value for char in ("\x00", "\r", "\n")):
        raise ValueError("autostart path contains an unsupported character")
    return value


def _desktop_exec_argument(value: str) -> str:
    # Desktop Entry Exec quoting is not shell parsing. Backslash-escape the
    # characters the specification reserves inside a double-quoted argument.
    clean = _validated_entry_text(value)
    escaped = clean.replace("\\", "\\\\").replace('"', '\\"').replace("`", "\\`")
    return f'"{escaped}"'


def _linux_autostart_path() -> Path:
    configured = os.environ.get("XDG_CONFIG_HOME", "").strip()
    base = Path(configured).expanduser() if configured else Path.home() / ".config"
    if not base.is_absolute():
        base = Path.home() / ".config"
    return base / "autostart" / "angerona.desktop"


def _macos_autostart_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LAUNCH_AGENT_LABEL}.plist"


def _atomic_private_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    temp: Path | None = None
    descriptor: int | None = None
    try:
        for _ in range(16):
            candidate = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
            try:
                descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                temp = candidate
                break
            except FileExistsError:
                continue
        if descriptor is None or temp is None:
            raise RuntimeError("could not allocate an autostart temporary file")
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        os.chmod(path, 0o600)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temp is not None:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass


def ui_copy() -> tuple[str, str, str, str]:
    """Return section title, checkbox label, explanation, and backend name."""
    if sys.platform == "win32":
        return (
            "Windows startup",
            "Launch Angerona automatically at Windows logon",
            "Uses a highest-privilege Windows Scheduled Task and starts silently at logon.",
            "Windows Scheduled Task (AngeronaAutostart)",
        )
    if sys.platform == "darwin":
        return (
            "macOS startup",
            "Launch Angerona automatically when I sign in",
            "Uses a current-user LaunchAgent. Intentional Quit remains stopped.",
            "macOS LaunchAgent",
        )
    if sys.platform.startswith("linux"):
        return (
            "Linux startup",
            "Launch Angerona automatically when I sign in",
            "Uses the freedesktop XDG autostart standard for the current desktop session.",
            "Linux XDG autostart entry",
        )
    return (
        "Startup",
        "Launch Angerona automatically when I sign in",
        "Autostart is unavailable on this platform.",
        "unsupported platform",
    )


def _current_user() -> str:
    domain = os.environ.get("USERDOMAIN", "").strip()
    username = os.environ.get("USERNAME", "").strip()
    if domain and username:
        return f"{domain}\\{username}"
    return username


def is_enabled() -> bool:
    """True if the platform-native current-user autostart entry is current."""
    if sys.platform.startswith("linux"):
        path = _linux_autostart_path()
        try:
            text = path.read_text(encoding="utf-8")
            expected = "Exec=" + " ".join(
                _desktop_exec_argument(item) for item in _target_argv()
            )
            return (
                not path.is_symlink()
                and "X-Angerona-Autostart=true" in text
                and "Hidden=false" in text
                and expected in text
            )
        except (OSError, UnicodeError, ValueError):
            return False
    if sys.platform == "darwin":
        path = _macos_autostart_path()
        try:
            if path.is_symlink():
                return False
            value = plistlib.loads(path.read_bytes())
            return (
                value.get("Label") == LAUNCH_AGENT_LABEL
                and value.get("ProgramArguments") == _target_argv()
                and value.get("RunAtLoad") is True
                and value.get("KeepAlive") is False
            )
        except (OSError, ValueError, TypeError, plistlib.InvalidFileException):
            return False
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
    if sys.platform.startswith("linux"):
        try:
            _executable, _arguments, working_directory = _target_action()
            command = " ".join(_desktop_exec_argument(item) for item in _target_argv())
            payload = (
                "[Desktop Entry]\n"
                "Type=Application\n"
                "Version=1.0\n"
                "Name=Angerona Security Suite\n"
                "Comment=Local-first endpoint security\n"
                f"Exec={command}\n"
                f"Path={_validated_entry_text(working_directory)}\n"
                "Terminal=false\n"
                "Hidden=false\n"
                "X-GNOME-Autostart-enabled=true\n"
                "X-Angerona-Autostart=true\n"
            ).encode("utf-8")
            _atomic_private_write(_linux_autostart_path(), payload)
            return is_enabled()
        except Exception:
            return False
    if sys.platform == "darwin":
        try:
            _executable, _arguments, working_directory = _target_action()
            payload = plistlib.dumps({
                "Label": LAUNCH_AGENT_LABEL,
                "ProgramArguments": _target_argv(),
                "WorkingDirectory": _validated_entry_text(working_directory),
                "RunAtLoad": True,
                "KeepAlive": False,
                "ProcessType": "Interactive",
            }, fmt=plistlib.FMT_XML, sort_keys=True)
            _atomic_private_write(_macos_autostart_path(), payload)
            return is_enabled()
        except Exception:
            return False
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
    if sys.platform.startswith("linux") or sys.platform == "darwin":
        path = (
            _linux_autostart_path()
            if sys.platform.startswith("linux")
            else _macos_autostart_path()
        )
        try:
            path.unlink(missing_ok=True)
            return not path.exists()
        except OSError:
            return False
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
