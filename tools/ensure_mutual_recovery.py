"""One-shot, STOP-aware supervision check using existing signed restart inboxes.

This tool never creates a core heartbeat, attaches a manager to another process,
terminates a process, enables disabled features, or clears operator intent.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
from contextlib import ExitStack
import json
import math
import os
from pathlib import Path
import stat
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
MODULES = {"core": "angerona", "watchdog": "angerona.resilience.watchdog",
           "scanner": "angerona.resilience.scanner"}
DEADLINES = {"core": 12.0, "watchdog": 10.0, "scanner": 8.0, "blackbox": 10.0}


class Held(RuntimeError):
    pass


def _read_private(path: Path, limit: int) -> bytes:
    from angerona.core.engine_transport import verify_private
    verify_private(path.parent, directory=True)
    verify_private(path)
    with path.open("rb") as stream:
        held = os.fstat(stream.fileno())
        named = path.lstat()
        if ((held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)
                or not stat.S_ISREG(held.st_mode) or held.st_nlink != 1):
            raise Held("Private runtime evidence changed during read")
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise Held("Private runtime evidence exceeds its bound")
    return raw


def _shutdown_key(root: Path) -> bytes:
    # Do not call _load_key: inspection must never create or repair authority.
    text = _read_private(root / "shutdown.key", 128).decode("ascii").strip()
    key = bytes.fromhex(text)
    if len(text) != 64 or len(key) != 32:
        raise Held("Existing shutdown authority is unavailable")
    return key


def _stop_hold(root: Path) -> bool:
    from angerona.resilience import shutdown_token
    path = root / "ipc" / "standdown.cmd"
    if not os.path.lexists(path):
        return False
    # Valid STOP, expired maintenance and malformed/ambiguous intent all hold
    # this automatic repair tool. A normal explicit launcher owns any resume.
    raw = _read_private(path, 4096)
    shutdown_token._verify_standdown_bytes(raw, key=_shutdown_key(root))
    return True


def _expected_argv(role: str) -> list[str]:
    if role == "blackbox":
        return [sys.executable, str(ROOT / "blackbox_recorder.py")]
    return [sys.executable, "-m", MODULES[role]]


def _required_peers(root: Path) -> tuple[str, ...]:
    path = root / "settings.json"
    if not os.path.lexists(path):
        return ("watchdog", "scanner", "blackbox")
    def closed(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Held("Duplicate settings key makes Black Box consent ambiguous")
            result[key] = value
        return result
    settings = json.loads(_read_private(path, 64 * 1024).decode("utf-8"), object_pairs_hook=closed)
    if not isinstance(settings, dict) or type(settings.get("blackbox_enabled", True)) is not bool:
        raise Held("Black Box preference is unavailable")
    return ("watchdog", "scanner", "blackbox") if settings.get("blackbox_enabled", True) else ("watchdog", "scanner")


class ReadOnlyGeneration:
    """Retain a native generation with query/synchronize rights only."""
    def __init__(self, pid: int, role: str):
        import psutil
        from angerona.core.windows_process_lease import _Native
        from angerona.resilience.supervisor import _invocation_identity
        process = psutil.Process(pid)
        invocation = _invocation_identity(process, tuple(_expected_argv(role)))
        if invocation is None:
            raise Held("Runtime invocation does not match this installation and role")
        self.native = _Native()
        self.handle = self.native.open(pid, 0x101000, False)
        try:
            self.identity = self.native.identity(self.handle)
            if (self.identity.pid != pid
                    or abs(self.identity.create_time - invocation["birth"]) > .001
                    or os.path.normcase(self.identity.image) != os.path.normcase(invocation["image"])):
                raise Held("Native runtime identity changed during inspection")
            self.validate()
        except BaseException:
            self.close()
            raise

    def validate(self) -> None:
        if (self.native.identity(self.handle) != self.identity
                or self.native.wait(self.handle, 0)):
            raise Held("Retained runtime generation is no longer active")

    def close(self) -> None:
        if self.handle is not None:
            handle, self.handle = self.handle, None
            self.native.close(handle)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def _core_owner(root: Path, stack: ExitStack):
    from angerona.core import singleton
    from angerona.core.engine_transport import verify_private
    path = root / "angerona.instance.lock"
    if not os.path.lexists(path):
        return None
    verify_private(root, directory=True)
    verify_private(path)
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "r+b", buffering=0) as stream:
        held, named = os.fstat(stream.fileno()), path.lstat()
        if (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino):
            raise Held("Instance lock identity changed")
        try:
            singleton._try_lock(stream)
        except OSError as error:
            if not singleton._is_contention(error):
                raise Held("Instance lease cannot be inspected") from error
        else:
            singleton._unlock(stream)
            return None
    _read_private(root / "angerona.instance.json", 4096)
    record = singleton._read_record(root / "angerona.instance.json")
    if not singleton._verified_incumbent(record):
        raise Held("An occupied instance lease has no verified core owner")
    return stack.enter_context(ReadOnlyGeneration(int(record["pid"]), "core"))


def _heartbeat(root: Path, role: str, key: bytes, stack: ExitStack, owner=None):
    from angerona.resilience.heartbeat import HeartbeatReader, RECORD_SIZE
    path = root / "heartbeats" / (role + ".hb")
    if len(_read_private(path, RECORD_SIZE)) != RECORD_SIZE:
        raise Held("Heartbeat record size is unavailable")
    reader = HeartbeatReader(role, path=path, key_raw=key)
    record = reader.read()
    if not record or reader.authentication_status(record=record) != "authenticated":
        raise Held("Heartbeat authentication is unavailable")
    age = (time.time_ns() - int(record["ts_ns"])) / 1e9
    if record["flags"] != 1 or not 0 <= age < DEADLINES[role]:
        raise Held("Heartbeat is stopped, stale or future-dated")
    generation = owner or stack.enter_context(ReadOnlyGeneration(int(record["pid"]), role))
    generation.validate()
    if (generation.identity.pid != int(record["pid"])
            or record["ts_ns"] / 1e9 < generation.identity.create_time):
        raise Held("Heartbeat does not belong to the retained generation")
    return generation


def _guarded_launch() -> dict:
    from angerona.core.privilege import sanitized_child_environment, trusted_windows_directories
    launcher = ROOT / "start-angerona.bat"
    if not launcher.is_file() or launcher.is_symlink() or launcher.stat().st_nlink != 1:
        raise Held("The canonical guarded source launcher is unavailable")
    if any(character in str(launcher) for character in '&|<>^%!\r\n"'):
        raise Held("The source launcher path cannot be represented safely for the Windows command host")
    _windows, system = trusted_windows_directories()
    environment = sanitized_child_environment({"ANGERONA_SUPERVISED_RECOVERY": "1"})
    process = subprocess.Popen([str(system / "cmd.exe"), "/d", "/c", str(launcher)],
                               cwd=ROOT, env=environment, close_fds=True)
    # The launcher owns its own pins, leases, STOP/resume boundary and readiness.
    # It must remain alive if this one-shot observation ends first.
    return {"launcher_pid": process.pid, "outcome": "launch-requested"}


def ensure(*, check_only: bool = False, wait_seconds: float = 10.0) -> dict:
    from angerona.core.data_paths import data_dir
    from angerona.resilience.supervisor import request_restart
    result = {"schema": 1, "outcome": "held", "supervision_verified": False,
              "protection_verified": False, "actions": []}
    if os.name != "nt":
        return dict(result, reason="This helper currently requires retained Windows process identity")
    if not math.isfinite(wait_seconds) or not 0 <= wait_seconds <= 30:
        raise ValueError("wait_seconds must be between 0 and 30")
    root = data_dir(create=False)
    try:
        if _stop_hold(root):
            return dict(result, reason="Operator/maintenance intent is present; use the normal explicit launcher to resume")
        with ExitStack() as stack:
            core = _core_owner(root, stack)
            if core is None:
                if check_only:
                    return dict(result, outcome="not-running", reason="No occupied core instance lease was found")
                if _stop_hold(root):
                    raise Held("Operator intent changed before guarded startup")
                return dict(result, **_guarded_launch(), actions=["canonical-guarded-source-launch"])
            try:
                key = _shutdown_key(root)
                _heartbeat(root, "core", key, stack, owner=core)
            except Exception:
                return dict(result, outcome="controlled-restart-required",
                            reason="An active core lacks authenticated supervision evidence; no manager was attached or process terminated")
            missing = []
            for role in _required_peers(root):
                try:
                    _heartbeat(root, role, key, stack)
                except Exception:
                    missing.append(role)
            if not missing:
                return dict(result, outcome="supervision-live", supervision_verified=True,
                            reason="Recent authenticated component liveness; security coverage is not established")
            if check_only:
                return dict(result, outcome="needs-attention", missing=missing, reason="No repair requested in check-only mode")
            # Give a just-starting peer one bounded observation opportunity.
            # Recheck every missing role before publishing a force-restart so a
            # peer that has already recovered is not restarted for display.
            if wait_seconds:
                time.sleep(min(1.0, wait_seconds))
            still_missing = []
            for role in missing:
                try:
                    _heartbeat(root, role, key, stack)
                except Exception:
                    still_missing.append(role)
            missing = still_missing
            if not missing:
                return dict(result, outcome="supervision-live", supervision_verified=True,
                            reason="Peers recovered during the bounded read-only observation; no restart requested")
            core.validate()
            if _stop_hold(root):
                raise Held("Operator intent changed before the signed restart request")
            # Existing supervisors consume only their registered targets. The
            # helper neither starts a competing daemon nor enables Black Box.
            written = request_restart(*missing)
            if len(written) != len(missing):
                raise Held("Existing signed restart inbox publication did not complete")
            result["actions"] = ["signed-restart:" + role for role in missing]
        deadline = time.monotonic() + wait_seconds
        while time.monotonic() < deadline:
            time.sleep(min(.25, max(0, deadline - time.monotonic())))
            observed = ensure(check_only=True, wait_seconds=0)
            if observed["supervision_verified"]:
                observed["actions"] = result["actions"]
                return observed
            if observed["outcome"] in {"controlled-restart-required", "held", "not-running"}:
                break
        return dict(result, outcome="restart-requested", missing=missing,
                    reason="Bounded signed requests were issued; fresh supervision has not yet been observed")
    except Exception as error:
        return dict(result, reason=str(error)[:512])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-only", action="store_true", help="Read only; do not create keys, files, processes or restart requests")
    parser.add_argument("--wait-seconds", type=float, default=10.0, help="Bounded observation after an explicit request (0 to 30)")
    options = parser.parse_args(argv)
    report = ensure(check_only=options.check_only, wait_seconds=options.wait_seconds)
    print(json.dumps(report, ensure_ascii=True, sort_keys=True))
    return 0 if report["supervision_verified"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
