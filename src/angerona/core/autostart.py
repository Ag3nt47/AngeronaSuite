"""Platform-native per-user autostart for Angerona.

Windows deliberately registers a *limited* current-user Scheduled Task.  An
editable checkout, virtual-environment interpreter, or unsigned per-user build
must never become a silent highest-privilege persistence path.  Angerona's
normal privilege gate can still request UAC when full sensors are needed, but
that consent is explicit at each logon instead of being inherited by mutable
code. A future signed, machine-protected service installer can provide silent
elevated startup through a separately reviewed broker.

Linux uses the freedesktop XDG autostart directory. macOS uses a current-user
LaunchAgent with ``KeepAlive`` disabled so an intentional quit is never
mistaken for a crash.
"""
from __future__ import annotations

import ntpath
import os
import plistlib
import secrets
import shlex
import stat
import subprocess
import sys
from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException
from pathlib import Path

TASK_NAME = "AngeronaAutostart"
LAUNCH_AGENT_LABEL = "org.angerona.security-suite"
_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_MAX_TASK_XML_CHARS = 1_000_000
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
    -RunLevel Limited
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
    """The exact command line Task Scheduler should launch at logon."""
    executable, arguments, _ = _target_action()
    return f'"{executable}" {arguments}'.rstrip()


def _target_action() -> tuple[str, str, str]:
    """Return executable, arguments, and working directory for Task Scheduler.

    Windows starts the independent startup assistant, which checks prerequisites
    and closes after the dashboard confirms readiness. Source builds use
    ``pythonw.exe`` to avoid a console whose closure would kill the application.
    Frozen Windows builds require the existing package authority before selecting
    their sibling helper; missing or redirected helpers never fall back to a
    direct dashboard launch.
    """
    from angerona.core.data_paths import project_root

    working_directory = str(project_root())
    if getattr(sys, "frozen", False):
        if sys.platform == "win32":
            from angerona.core.windows_package_identity import verify_current_msix_authority

            authority = verify_current_msix_authority()
            if not authority.trusted:
                raise RuntimeError(f"Startup package authority is unavailable: {authority.reason}")
            helper = Path(sys.executable).absolute().with_name("AngeronaStartup.exe")
            try:
                if not helper.is_file():
                    raise OSError("the startup helper is missing or not a file")
                for path in (*helper.parents, helper):
                    metadata = path.lstat()
                    if stat.S_ISLNK(metadata.st_mode) or (
                        getattr(metadata, "st_file_attributes", 0) & 0x400
                    ) or (stat.S_ISREG(metadata.st_mode) and metadata.st_nlink > 1):
                        raise OSError("the startup helper path is redirected")
            except OSError as exc:
                raise RuntimeError(
                    "The bundled startup helper is unavailable. Repair the signed installation."
                ) from exc
            return str(helper), "--chill", str(helper.parent)
        return sys.executable, "--chill", working_directory

    interpreter = Path(sys.executable)
    windowed = interpreter.with_name("pythonw.exe")
    executable = windowed if windowed.is_file() else interpreter
    module = "angerona.startup" if sys.platform == "win32" else "angerona"
    return str(executable), f"-m {module} --chill", working_directory


def _target_argv() -> list[str]:
    executable, arguments, _working_directory = _target_action()
    return [executable, *(shlex.split(arguments) if arguments else [])]


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
            "Uses a least-privilege Scheduled Task. Windows may request UAC when full sensors start.",
            "least-privilege Windows Scheduled Task (AngeronaAutostart)",
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


def _xml_local_name(element: ET.Element) -> str:
    """Return a Task Scheduler XML tag without its schema namespace."""
    return str(element.tag).rsplit("}", 1)[-1]


def _xml_direct_child(element: ET.Element, name: str) -> ET.Element | None:
    return next(
        (child for child in list(element) if _xml_local_name(child) == name),
        None,
    )


def _xml_child_text(element: ET.Element, name: str) -> str:
    child = _xml_direct_child(element, name)
    return str(child.text or "").strip() if child is not None else ""


def _xml_enabled(element: ET.Element, *, default: bool = True) -> bool:
    value = _xml_child_text(element, "Enabled").casefold()
    if not value:
        return bool(default)
    return value in {"true", "1"}


def _normal_windows_path(value: str) -> str:
    # Task Scheduler stores Execute/WorkingDirectory without shell quoting, but
    # tolerate one harmless outer quote pair when validating hand-migrated XML.
    clean = str(value or "").strip()
    if len(clean) >= 2 and clean[0] == clean[-1] == '"':
        clean = clean[1:-1]
    return ntpath.normcase(ntpath.normpath(clean)) if clean else ""


def _windows_task_xml_is_current(payload: str) -> bool:
    """Validate the complete security-relevant autostart contract.

    Merely finding a task with Angerona's name is insufficient: an older task
    may still launch ``python.exe`` (blank console), point at a moved checkout,
    be disabled, or retain the unsafe legacy elevated trigger. Returning ``False``
    lets the startup reconciler rebuild that stale definition.
    """
    if not payload or len(payload) > _MAX_TASK_XML_CHARS:
        return False
    try:
        root = ET.fromstring(payload.lstrip("\ufeff"))
    except (ET.ParseError, DefusedXmlException, ValueError, TypeError):
        return False
    if _xml_local_name(root) != "Task":
        return False

    settings = next(
        (node for node in root.iter() if _xml_local_name(node) == "Settings"),
        None,
    )
    if settings is None or not _xml_enabled(settings):
        return False

    triggers = next(
        (node for node in root.iter() if _xml_local_name(node) == "Triggers"),
        None,
    )
    if triggers is None:
        return False
    enabled_triggers = [child for child in list(triggers) if _xml_enabled(child)]
    if len(enabled_triggers) != 1 or _xml_local_name(enabled_triggers[0]) != "LogonTrigger":
        return False

    principals = [
        node for node in root.iter() if _xml_local_name(node) == "Principal"
    ]
    if len(principals) != 1:
        return False
    principal = principals[0]
    if _xml_child_text(principal, "LogonType").casefold() != "interactivetoken":
        return False
    run_level_node = _xml_direct_child(principal, "RunLevel")
    if run_level_node is not None:
        # Task Scheduler omits RunLevel when Register-ScheduledTask receives
        # ``-RunLevel Limited`` because Limited is the schema default. Accept
        # only that omission/default; any explicit elevated or unknown value
        # remains stale and is rebuilt.
        run_level = str(run_level_node.text or "").strip().casefold()
        if run_level not in {"leastprivilege", "limited"}:
            return False

    actions = next(
        (node for node in root.iter() if _xml_local_name(node) == "Actions"),
        None,
    )
    if actions is None:
        return False
    action_nodes = list(actions)
    if len(action_nodes) != 1 or _xml_local_name(action_nodes[0]) != "Exec":
        return False
    action = action_nodes[0]
    expected_executable, expected_arguments, expected_cwd = _target_action()
    return (
        _normal_windows_path(_xml_child_text(action, "Command"))
        == _normal_windows_path(expected_executable)
        and _xml_child_text(action, "Arguments").strip()
        == str(expected_arguments or "").strip()
        and _normal_windows_path(_xml_child_text(action, "WorkingDirectory"))
        == _normal_windows_path(expected_cwd)
    )


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
            [str(_SCHTASKS), "/query", "/tn", TASK_NAME, "/xml"],
            capture_output=True, text=True, timeout=10,
            creationflags=_CREATE_NO_WINDOW,
        )
        return (
            result.returncode == 0
            and _windows_task_xml_is_current(str(result.stdout or ""))
        )
    except Exception:
        return False


def enable_autostart() -> bool:
    """Create (or refresh) the least-privilege logon scheduled task.

    Registration may require an elevated token, but the resulting task never
    grants silent administrator execution to the mutable source tree. Idempotent:
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
