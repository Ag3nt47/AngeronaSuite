"""Native per-user persistence for the detached engine; no elevation or shell.

Installation is explicit. These are user-session services: they survive GUI
closure, but Windows/macOS stop at sign-out and systemd depends on the user's
session manager. Machine-wide protection requires separately signed packaging.
"""
from __future__ import annotations

import os
from pathlib import Path
import plistlib
import subprocess
import sys

from .engine_transport import EngineError
from .persistent_engine import _require_user, engine_command

LABEL = "com.angerona.protection-engine"
UNIT = "angerona-engine.service"
TASK = "Angerona Protection Engine"


def _systemd_quote(value: str) -> str:
    if any(ord(char) < 32 for char in value):
        raise EngineError("Control characters are not permitted in service arguments")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'


def systemd_unit(command: list[str], data_root: Path) -> str:
    return ("[Unit]\nDescription=Angerona user protection engine\n"
            "StartLimitIntervalSec=300\nStartLimitBurst=3\n\n[Service]\nType=exec\n"
            "ExecStart=" + " ".join(_systemd_quote(item) for item in command) + "\n"
            "Environment=" + _systemd_quote("ANGERONA_DATA=" + str(data_root)) + "\n"
            "Restart=on-failure\nRestartSec=10\nTimeoutStopSec=45\n"
            "UMask=0077\nNoNewPrivileges=yes\nStandardOutput=null\nStandardError=journal\n"
            "\n[Install]\nWantedBy=default.target\n")


def launchd_plist(command: list[str], data_root: Path) -> bytes:
    return plistlib.dumps({"Label": LABEL, "ProgramArguments": command,
                           "RunAtLoad": True, "KeepAlive": {"SuccessfulExit": False},
                           "ThrottleInterval": 30, "ExitTimeOut": 45,
                           "EnvironmentVariables": {"ANGERONA_DATA": str(data_root)},
                           "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null"})


def _write_new(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Existing definitions may belong to an operator; explicit remove is
    # required before replacement, and symlinks are never followed.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _native(command: list[str]) -> None:
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=30, check=False)
    if result.returncode:
        raise EngineError(f"Native service manager exited with status {result.returncode}")


def _windows_install() -> str:
    import pythoncom
    import win32com.client
    import win32security
    from .engine_transport import _windows_identity
    pythoncom.CoInitialize()
    try:
        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        folder = scheduler.GetFolder("\\")
        task = scheduler.NewTask(0)
        task.RegistrationInfo.Description = (
            "Keeps Angerona protection running when its desktop console closes. "
            "Ordinary user only; stops at sign-out.")
        sid = win32security.ConvertSidToStringSid(_windows_identity())
        task.Principal.UserId = sid
        task.Principal.LogonType = 3  # TASK_LOGON_INTERACTIVE_TOKEN
        task.Principal.RunLevel = 0  # TASK_RUNLEVEL_LUA, never highest
        settings = task.Settings
        settings.Enabled = True
        settings.DisallowStartIfOnBatteries = False
        settings.StopIfGoingOnBatteries = False
        settings.ExecutionTimeLimit = "PT0S"
        settings.MultipleInstances = 2  # TASK_INSTANCES_IGNORE_NEW
        settings.RestartInterval = "PT1M"
        settings.RestartCount = 3
        trigger = task.Triggers.Create(9)  # TASK_TRIGGER_LOGON
        trigger.UserId = sid
        action = task.Actions.Create(0)
        command = engine_command()
        action.Path = command[0]
        action.Arguments = subprocess.list2cmdline(command[1:])
        action.WorkingDirectory = str(Path(sys.executable).resolve().parent)
        # TASK_CREATE rather than CREATE_OR_UPDATE protects an existing task.
        registered = folder.RegisterTaskDefinition(TASK, task, 2, sid, "", 3)
        registered.Run("")
        return TASK
    finally:
        pythoncom.CoUninitialize()


def install_user_service() -> str:
    _require_user()
    if getattr(sys, "frozen", False):
        raise EngineError("Packaged service provisioning belongs to the signed package installer")
    from .data_paths import data_dir
    root = data_dir()
    command = engine_command()
    if sys.platform == "win32":
        return _windows_install()
    if sys.platform == "darwin":
        path = Path.home() / "Library" / "LaunchAgents" / (LABEL + ".plist")
        _write_new(path, launchd_plist(command, root))
        _native(["/bin/launchctl", "bootstrap", f"gui/{os.getuid()}", str(path)])
        return str(path)
    if sys.platform.startswith("linux"):
        path = Path.home() / ".config" / "systemd" / "user" / UNIT
        _write_new(path, systemd_unit(command, root).encode("utf-8"))
        _native(["/usr/bin/systemctl", "--user", "daemon-reload"])
        _native(["/usr/bin/systemctl", "--user", "enable", "--now", UNIT])
        return str(path)
    raise EngineError("No supported native per-user service manager on this platform")


def remove_user_service() -> None:
    _require_user()
    if sys.platform == "win32":
        import pythoncom
        import win32com.client
        pythoncom.CoInitialize()
        try:
            scheduler = win32com.client.Dispatch("Schedule.Service")
            scheduler.Connect()
            folder = scheduler.GetFolder("\\")
            task = folder.GetTask(TASK)
            expected = engine_command()
            action = task.Definition.Actions.Item(1)
            if (str(action.Path) != expected[0]
                    or str(action.Arguments) != subprocess.list2cmdline(expected[1:])):
                raise EngineError("Existing task does not match this Angerona installation")
            folder.DeleteTask(TASK, 0)
            # Removing automatic startup does not kill a live engine. Use its
            # explicit authenticated stop action when protection should stop.
        finally:
            pythoncom.CoUninitialize()
        return
    from .data_paths import data_dir
    command = engine_command()
    if sys.platform == "darwin":
        path = Path.home() / "Library" / "LaunchAgents" / (LABEL + ".plist")
        expected = launchd_plist(command, data_dir())
        unload = ["/bin/launchctl", "bootout", f"gui/{os.getuid()}/{LABEL}"]
    elif sys.platform.startswith("linux"):
        path = Path.home() / ".config" / "systemd" / "user" / UNIT
        expected = systemd_unit(command, data_dir()).encode("utf-8")
        unload = ["/usr/bin/systemctl", "--user", "disable", "--now", UNIT]
    else:
        raise EngineError("Unsupported service manager")
    if path.is_symlink() or path.read_bytes() != expected:
        raise EngineError("Existing service definition does not match this Angerona installation")
    _native(unload)
    path.unlink()
    if sys.platform.startswith("linux"):
        _native(["/usr/bin/systemctl", "--user", "daemon-reload"])
