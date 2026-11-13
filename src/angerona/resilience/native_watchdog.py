"""Installed native third-watchdog admission and read-only observation.

The installer owns registration and startup.  This module never starts, kills,
re-registers or repairs a process, and source checkouts cannot admit a launch.
Observed heartbeats describe authenticated activity, not response authority or
proof that a recovery action succeeded.
"""
from __future__ import annotations

import json
import ntpath
import os
import re
import stat
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

from angerona.resilience import heartbeat as hb


BINARY_NAME = "watchdog3.exe"
ALERT_NAME = "watchdog3-peer-alerts.jsonl"
_MAX_CONFIG = 16 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CONFIG_FIELDS = frozenset({"schema", "data_dir", "launcher_path", "launcher_sha256",
                            "launcher_args", "working_directory"})
_WINDOWS_EPOCH = 116444736000000000
_QUERY_CLOSE_HOLDS: list[tuple[object, int]] = []


class NativeWatchdogError(ValueError):
    """Native-watchdog install intent or retained custody is unavailable."""


def _local_path(value: object, *, executable: bool = False) -> str:
    if (type(value) is not str or not value or len(value) > 2048
            or any(ord(char) < 32 for char in value)
            or value.startswith(("\\\\", "//"))):
        raise NativeWatchdogError("Watchdog path must be an explicit local Windows path")
    path = PureWindowsPath(value)
    if (not path.is_absolute() or not re.fullmatch(r"[A-Za-z]:", path.drive)
            or ntpath.normpath(value) != value or str(path) != value
            or any(part in {".", ".."} or ":" in part or part.endswith((".", " "))
                   for part in path.parts[1:])
            or (executable and path.suffix.casefold() != ".exe")):
        raise NativeWatchdogError("Watchdog path is not a plain absolute local path")
    return str(path)


def parse_install_config(raw: bytes) -> dict:
    """Validate bounded installer intent; this grants no install/launch authority."""
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_CONFIG:
        raise NativeWatchdogError("Watchdog configuration exceeds its bound")

    def closed_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise NativeWatchdogError("Watchdog configuration has duplicate fields")
            result[key] = value
        return result

    try:
        body = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=closed_pairs)
    except (ValueError, UnicodeError) as error:
        raise NativeWatchdogError("Watchdog configuration is malformed") from error
    if (type(body) is not dict or set(body) != _CONFIG_FIELDS
            or type(body["schema"]) is not int or body["schema"] != 2):
        raise NativeWatchdogError("Watchdog configuration schema is not supported")
    body["data_dir"] = _local_path(body["data_dir"])
    body["launcher_path"] = _local_path(body["launcher_path"], executable=True)
    if PureWindowsPath(body["launcher_path"]).name.casefold() != "angerona.exe":
        raise NativeWatchdogError("Watchdog launcher must be the installed Angerona executable")
    body["working_directory"] = _local_path(body["working_directory"])
    digest = body["launcher_sha256"]
    if type(digest) is not str or not _SHA256.fullmatch(digest):
        raise NativeWatchdogError("Watchdog launcher digest must be an exact SHA-256 pin")
    if body["launcher_args"] != ["--engine-service"] or type(body["launcher_args"]) is not list:
        raise NativeWatchdogError("Watchdog service image must have the fixed SCM dispatcher arguments")
    if ntpath.normcase(body["working_directory"]) != ntpath.normcase(
            str(PureWindowsPath(body["launcher_path"]).parent)):
        raise NativeWatchdogError("Watchdog working directory must be the install directory")
    return body


def build_install_config(*, data_dir: str, launcher_path: str, launcher_sha256: str,
                         working_directory: str) -> bytes:
    """Serialize reviewed installer values without reading or pinning live files."""
    body = {"schema": 2, "data_dir": data_dir, "launcher_path": launcher_path,
            "launcher_sha256": launcher_sha256, "launcher_args": ["--engine-service"],
            "working_directory": working_directory}
    encoded = json.dumps(body, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    parse_install_config(encoded)
    return encoded + b"\n"


def installed_config_path() -> Path:
    """The Windows known-folder path; no environment-derived ProgramData."""
    from angerona.resilience.control_authority import _known_program_data
    return _known_program_data() / "Angerona" / "watchdog3" / "config.json"


def alert_path(data_dir: Path) -> Path:
    """Return the separate outbox name without creating a directory or a key."""
    return Path(data_dir) / "diagnostics" / ALERT_NAME


class NativeAlertReader:
    """Read a separate chain from protected installed intent, not Core's root."""
    def __init__(self, *, _data_dir: Path | None = None):
        # This private injection is for inert codec/path fixtures only. No
        # production consumer supplies it or accepts a path from an event/env.
        self._fixture_root = Path(_data_dir) if _data_dir is not None else None
        self.path = None
        self._reader = None
        if self._fixture_root is None and not _installed_mode():
            raise NativeWatchdogError("Source runs do not consume installed native authority")

    def _check_paths(self) -> None:
        from angerona.core.source_activation_file import plain_path
        plain_path(self.path.parent, directory=True)
        for path in (self.path, self.path.with_suffix(".jsonl.1"), self.path.with_suffix(".cursor")):
            if os.path.lexists(path):
                plain_path(path)

    def drain(self) -> list[dict]:
        from angerona.resilience.peer_alerts import PeerAlertReader
        with _observation_root(self._fixture_root) as root:
            path = alert_path(root)
            if path != self.path:
                self.path, self._reader = path, None
            self._check_paths()
            if self._reader is None:
                key = hb.read_existing_optional_authority(root)
                self._reader = PeerAlertReader(path=path, key_raw=key)
            return self._reader.drain()


def _release_pins() -> tuple[str, str]:
    from angerona import _release_integrity
    return (str(getattr(_release_integrity, "WATCHDOG3_SHA256", "")),
            str(getattr(_release_integrity, "WATCHDOG3_PUBLISHER", "")))


def _installed_mode() -> bool:
    return sys.platform == "win32" and bool(getattr(sys, "frozen", False))


def _config_protected(path: Path) -> bool:
    from angerona.core.source_activation_file import plain_path
    try:
        # ProgramData is selected by the OS.  The fixed Angerona subtree and
        # file must be admin-owned/write-protected, with no redirected ancestor.
        plain_path(path)
        import win32security
        from angerona.core.windows_engine_custody import _descriptor, check_descriptor
        trusted = frozenset({"S-1-5-18", "S-1-5-32-544",
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"})
        for candidate in (path, path.parent, path.parent.parent):
            descriptor = _descriptor(win32security.GetNamedSecurityInfo(
                str(candidate), win32security.SE_FILE_OBJECT, 0x5))
            check_descriptor(descriptor, trusted, outside_allowed=0xA01200A9)
        return True
    except Exception:
        return False


def _private_native_root(path: Path) -> bool:
    from angerona.core.source_activation_file import plain_path
    from angerona.core.startup_recovery import private_directory, _windows_security
    try:
        plain_path(path, directory=True)
        return (private_directory(path, create=False)
                or (os.name == "nt" and _windows_security(path, create=False, allow_inherited=True)))
    except Exception:
        return False


def _acquire_configuration():
    """Open the one installed intent; caller owns/retains the returned file."""
    if not _installed_mode():
        raise NativeWatchdogError("Source runs do not read native installer intent")
    digest, publisher = _release_pins()
    if not _SHA256.fullmatch(digest) or not publisher:
        raise NativeWatchdogError("Native third-watchdog release pins are unavailable")
    from angerona.core.source_activation_file import RetainedFile
    path = installed_config_path()
    if not _config_protected(path):
        raise NativeWatchdogError("Native watchdog installer configuration is not protected")
    held = RetainedFile(path)
    try:
        body = parse_install_config(held.read(_MAX_CONFIG + 1))
        if ntpath.normcase(body["launcher_path"]) != ntpath.normcase(sys.executable):
            raise NativeWatchdogError("Native watchdog service image does not match this installation")
        if not _private_native_root(Path(body["data_dir"])):
            raise NativeWatchdogError("Native watchdog's own state root is not private")
        held.check()
        if not _config_protected(path):
            raise NativeWatchdogError("Native watchdog installer intent changed custody")
        return held, body
    except BaseException:
        held.close()
        raise


@contextmanager
def _observation_root(fixture_root: Path | None):
    if fixture_root is not None:
        yield fixture_root
        return
    held, body = _acquire_configuration()
    try:
        yield Path(body["data_dir"])
        held.check()
    finally:
        held.close()


@dataclass
class InstalledWatchdogAdmission:
    """Retained supervisor, service image and fixed config; never a started child."""
    executable: object
    launcher: object
    config: object
    body: dict

    @property
    def argv(self) -> tuple[str, ...]:
        return (str(self.executable.path), "--config", str(self.config.path))

    def revalidate(self) -> None:
        self.config.check()
        if (not _config_protected(self.config.path)
                or not _private_native_root(Path(self.body["data_dir"]))
                or not self.executable.still_valid(rehash=True)
                or not self.launcher.still_valid(rehash=True)):
            raise NativeWatchdogError("Native watchdog install custody changed")

    def close(self) -> None:
        try:
            self.config.close()
        finally:
            try:
                self.launcher.close()
            finally:
                self.executable.close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()


def acquire_installed_watchdog() -> InstalledWatchdogAdmission:
    """Admit only a signed/pinned frozen install and its protected fixed intent.

    The signed installer can retain this receipt across its native start.  The
    core deliberately does not invoke a start: its death must not kill this
    independently registered supervisor.
    """
    if not _installed_mode():
        raise NativeWatchdogError("Source runs do not start the native third watchdog")
    from angerona.core.executable_trust import acquire_pinned_executable

    digest, publisher = _release_pins()
    if not _SHA256.fullmatch(digest) or not publisher:
        raise NativeWatchdogError("Native third-watchdog release pins are unavailable")
    held = executable = launcher = None
    try:
        held, body = _acquire_configuration()
        install_launcher = Path(sys.executable)
        executable = acquire_pinned_executable(install_launcher.parent / BINARY_NAME,
            expected_sha256=digest, expected_publisher=publisher)
        launcher = acquire_pinned_executable(install_launcher,
            expected_sha256=body["launcher_sha256"], expected_publisher=publisher)
        admitted = InstalledWatchdogAdmission(executable, launcher, held, body)
        admitted.revalidate()
        return admitted
    except BaseException:
        try:
            if held is not None:
                held.close()
        finally:
            try:
                if launcher is not None:
                    launcher.close()
            finally:
                if executable is not None:
                    executable.close()
        raise


@dataclass(frozen=True)
class ObservedProcess:
    pid: int
    birth_ticks: int
    image: str


def _query_process(pid: int) -> ObservedProcess | None:
    if _QUERY_CLOSE_HOLDS:
        raise NativeWatchdogError("A prior native observation handle has unverified cleanup")
    from angerona.core.windows_process_lease import _Native
    native = _Native()
    handle = native.open(pid, 0x1000 | 0x00100000, False)  # query + synchronize, never terminate
    try:
        identity = native.identity(handle)
        if native.wait(handle, 0):
            return None
        return ObservedProcess(identity.pid, identity.birth_ticks, identity.image)
    finally:
        try:
            native.close(handle)
        except Exception as error:
            # Retain exact custody and allocate no more observers. A numeric
            # handle with an uncertain close must never be retried after reuse.
            _QUERY_CLOSE_HOLDS.append((native, handle))
            raise NativeWatchdogError("Native observation handle cleanup remains held") from error


class NativeWatchdogObserver:
    """Background-thread observation only; no launch, repair or response actions."""
    def __init__(self, *, _data_dir: Path | None = None, _clock=time.monotonic, _time_ns=time.time_ns,
                 _probe=_query_process):
        self._fixture_root = Path(_data_dir) if _data_dir is not None else None
        self.root = None
        self._clock, self._time_ns, self._probe = _clock, _time_ns, _probe
        self._reader = None
        self._last = None
        self._last_advance = 0.0

    def snapshot(self) -> dict:
        if not _installed_mode():
            return {"state": "source-disabled", "reason": "Source runs do not auto-start the native third watchdog"}
        digest, publisher = _release_pins()
        if not _SHA256.fullmatch(digest) or not publisher:
            return {"state": "not-packaged", "reason": "Signed native third-watchdog release pins are unavailable"}
        try:
            with _observation_root(self._fixture_root) as root:
                return self._snapshot_root(root)
        except FileNotFoundError:
            return {"state": "absent", "reason": "Native third watchdog has not reported a heartbeat"}
        except Exception:
            return {"state": "unavailable", "reason": "Native watchdog observation or native-query cleanup could not be verified"}

    def _snapshot_root(self, root: Path) -> dict:
        try:
            if self.root != root:
                self.root, self._reader, self._last = root, None, None
                self._last_advance = 0.0
            if self._reader is None:
                key = hb.read_existing_optional_authority(self.root)
                self._reader = hb.HeartbeatReader("watchdog3",
                    path=self.root / "heartbeats" / "watchdog3.hb", key_raw=key)
            from angerona.core.source_activation_file import plain_path
            path = plain_path(self._reader.path)
            before = path.lstat()
            if (before.st_size != hb.RECORD_SIZE or not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1):
                return {"state": "unverified", "reason": "Native watchdog heartbeat is not one fixed-size file"}
            record = self._reader.read()
            after = plain_path(path).lstat()
            if (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size):
                return {"state": "unverified", "reason": "Native watchdog heartbeat changed file identity"}
            if (record is None or self._reader.authentication_status(
                    record=record, update_replay_state=False) != "authenticated"):
                return {"state": "unverified", "reason": "Native watchdog heartbeat did not authenticate"}
            process = self._probe(record["pid"])
            if process is None:
                return {"state": "absent", "reason": "Authenticated native watchdog process has exited"}
            expected_image = str(Path(sys.executable).parent / BINARY_NAME)
            if (type(process) is not ObservedProcess or process.pid != record["pid"]
                    or process.birth_ticks <= _WINDOWS_EPOCH
                    or ntpath.normcase(process.image) != ntpath.normcase(expected_image)
                    or record["ts_ns"] < (process.birth_ticks - _WINDOWS_EPOCH) * 100):
                return {"state": "unverified", "reason": "Native watchdog process generation does not match"}
            now, wall = self._clock(), self._time_ns()
            age = (wall - record["ts_ns"]) / 1e9
            if age < -5 or age >= 10 or now < self._last_advance:
                return {"state": "stale", "reason": "Native watchdog heartbeat clock/freshness is not verified"}
            generation = (process.pid, process.birth_ticks)
            current = (generation, record["ts_ns"], record["counter"])
            if self._last is not None:
                old_generation, old_ts, old_count = self._last
                wrapped = old_count > 0xFFFF0000 and record["counter"] < 0x0000FFFF
                if (record["ts_ns"] < old_ts
                        or (generation == old_generation and record["counter"] < old_count and not wrapped)
                        or (generation != old_generation and record["ts_ns"] <= old_ts)):
                    return {"state": "unverified", "reason": "Native watchdog heartbeat regressed or was replayed"}
            if self._last is None or generation != self._last[0] or record["counter"] != self._last[2]:
                self._last_advance = now
            self._last = current
            if record["flags"] == 0:
                return {"state": "stopped", "reason": "Authenticated writer stopped; only verified STOP grants stand-down"}
            if now - self._last_advance >= 10:
                return {"state": "stale", "reason": "Native watchdog heartbeat is not fresh and advancing"}
            return {"state": "observed", "reason": "Authenticated native heartbeat observed; recovery is not verified",
                    "pid": process.pid, "age_s": round(max(0.0, age), 3)}
        except FileNotFoundError:
            return {"state": "absent", "reason": "Native third watchdog has not reported a heartbeat"}
        except Exception:
            return {"state": "unavailable", "reason": "Native watchdog observation or native-query cleanup could not be verified"}
