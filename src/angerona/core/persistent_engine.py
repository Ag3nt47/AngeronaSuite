"""A real detachable protection process and its narrow desktop client.

Closing a client never stops protection. Source installations run only with
ordinary-user rights; machine service deployment is a separate package gate.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

from .engine_transport import EngineError, EngineServer, exchange, private_directory


def engine_directory() -> Path:
    from .data_paths import data_dir
    return data_dir() / "engine"


class EngineClient:
    def __init__(self, directory: Path | None = None):
        self.directory = directory or engine_directory()

    def status(self) -> dict:
        return exchange(self.directory, {"operation": "status"})

    def events(self, cursor: int = -1) -> dict:
        return exchange(self.directory, {"operation": "events", "cursor": cursor})

    def settings(self) -> dict:
        return exchange(self.directory, {"operation": "settings"})

    def metrics(self) -> dict:
        return exchange(self.directory, {"operation": "metrics"})

    def patch_settings(self, changes: dict) -> dict:
        return exchange(self.directory, {"operation": "settings_patch", "settings": changes})

    def set_chill(self, enabled: bool) -> dict:
        return self.patch_settings({"eco_mode": enabled})

    def set_module(self, name: str, enabled: bool) -> dict:
        return exchange(self.directory, {"operation": "module_enable", "name": name, "enabled": enabled})

    def restart_module(self, name: str) -> dict:
        return exchange(self.directory, {"operation": "module_restart", "name": name})

    def self_test(self, name: str) -> dict:
        return exchange(self.directory, {"operation": "module_selftest", "name": name})

    def operation_status(self, identity: str) -> dict:
        return exchange(self.directory, {"operation": "operation_status", "id": identity})

    def stop_engine(self, *, confirmation: str) -> dict:
        return exchange(self.directory, {"operation": "stop_engine", "confirmation": confirmation})


def _require_user() -> None:
    from .privilege import is_admin
    if (os.name == "nt" and is_admin()) or (os.name != "nt" and os.geteuid() == 0):
        raise EngineError("The detachable desktop engine requires an ordinary-user session. "
                          "Use the separately verified package service for privileged protection.")


def engine_command() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, "--engine-serve"]
    # Isolated Python avoids ambient PYTHONPATH and user-site imports. Source
    # developer installs deliberately import their exact current source tree.
    root = Path(__file__).resolve().parents[2]
    from .data_paths import data_dir
    bootstrap = (f"import os,sys;os.environ['ANGERONA_DATA']={str(data_dir())!r};"
                 f"sys.path.insert(0,{str(root)!r});"
                 "from angerona.core.persistent_engine import main;raise SystemExit(main())")
    return [sys.executable, "-I", "-c", bootstrap, "serve"]


def _child_environment() -> dict[str, str]:
    allowed = {"SystemRoot", "WINDIR", "COMSPEC", "ProgramFiles", "ProgramFiles(x86)",
               "ProgramW6432", "LOCALAPPDATA", "APPDATA", "USERPROFILE", "HOME",
               "TEMP", "TMP", "TMPDIR", "PATH", "LANG", "LC_ALL", "XDG_RUNTIME_DIR",
               "XDG_STATE_HOME", "DBUS_SESSION_BUS_ADDRESS", "DISPLAY", "WAYLAND_DISPLAY"}
    allowed_folded = {key.casefold() for key in allowed}
    environment = {key: value for key, value in os.environ.items() if key.casefold() in allowed_folded}
    from .data_paths import data_dir
    environment["ANGERONA_DATA"] = str(data_dir())
    environment["PYTHONIOENCODING"] = "utf-8"
    if os.environ.get("ANGERONA_RUNTIME_METRICS") == "1":
        environment["ANGERONA_RUNTIME_METRICS"] = "1"
    return environment


def ensure_engine(*, timeout: float = 15.0) -> EngineClient:
    """Reconnect or launch one ordinary-user engine, never duplicate sensors.

    A successful return may still report ``starting``. The desktop polls state
    without blocking its event loop. A failed/stale endpoint is not proof of
    protection, and is reported as an error if the OS singleton remains held.
    """
    _require_user()
    client = EngineClient()
    try:
        client.status()
        return client
    except (OSError, EngineError):
        pass
    private_directory(client.directory)
    command = engine_command()
    options = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
               "stderr": subprocess.DEVNULL, "close_fds": True,
               "cwd": str(Path(sys.executable).resolve().parent), "env": _child_environment()}
    if os.name == "nt":
        options["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        options["start_new_session"] = True
    child = subprocess.Popen(command, **options)
    deadline = time.monotonic() + max(1.0, min(60.0, timeout))
    while time.monotonic() < deadline:
        try:
            client.status()
            return client
        except (OSError, EngineError):
            if child.poll() is not None:
                # Another concurrent launch may have won the single-instance
                # lease but not yet published its endpoint; give it one beat.
                time.sleep(0.15)
                try:
                    client.status()
                    return client
                except (OSError, EngineError) as exc:
                    raise EngineError("Engine did not start. Close an existing embedded Angerona "
                                      "window before enabling detached protection; inspect crash logs.") from exc
        time.sleep(0.1)
    raise EngineError("Engine startup status unavailable; do not assume protection is running")


def serve(*, stop_event: threading.Event | None = None) -> int:
    _require_user()
    from .data_paths import configure_runtime_environment
    configure_runtime_environment()
    from .singleton import acquire_single_instance
    lease = acquire_single_instance()
    if lease is None:
        return 3
    from .engine_control import EngineControl
    stop = stop_event or threading.Event()
    control = EngineControl(stop)
    server = None
    try:
        from .crashlog import install
        install()
        from .hardening import apply_process_mitigations
        apply_process_mitigations()
        server = EngineServer(engine_directory(), control.dispatch)
        control.instance = server.instance
        server.start()
        from .headless import run_headless
        return run_headless(stop_event=stop, runtime_control=control)
    except Exception as exc:
        control.fail(type(exc).__name__)
        raise
    finally:
        control.close()
        if server is not None:
            server.close()
        lease.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Angerona persistent ordinary-user protection engine")
    parser.add_argument("command", choices=("serve", "status", "start", "stop"))
    parser.add_argument("--confirm-stop-protection", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "serve":
            return serve()
        client = ensure_engine() if args.command == "start" else EngineClient()
        if args.command == "stop":
            if not args.confirm_stop_protection:
                parser.error("stop requires --confirm-stop-protection")
            result = client.stop_engine(confirmation="stop-protection")
        else:
            result = client.status()
        import json
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 0
    except (EngineError, OSError) as exc:
        print(f"Angerona engine unavailable: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
