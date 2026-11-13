"""Installed native third-watchdog admission and read-only observation.

The installer owns registration and startup.  The installed path never starts, kills, re-registers or repairs a process.
An explicitly opted-in ordinary-user observer is separately owned and cannot
consume installed authority or recover Core independently.
Observed heartbeats describe authenticated activity, not response authority or
proof that a recovery action succeeded.
"""
from __future__ import annotations

import json
import math
import ntpath
import os
import re
import stat
import sys
import time
import threading
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

    @contextmanager
    def _admitted_reader(self):
        from angerona.resilience.peer_alerts import PeerAlertReader
        with _observation_root(self._fixture_root) as root:
            path = alert_path(root)
            if path != self.path:
                self.path, self._reader = path, None
            self._check_paths()
            if self._reader is None:
                key = hb.read_existing_optional_authority(root)
                self._reader = PeerAlertReader(path=path, key_raw=key)
            yield self._reader

    def peek(self) -> list[dict]:
        with self._admitted_reader() as reader:
            return reader.peek()

    def ack(self, record: dict) -> None:
        with self._admitted_reader() as reader:
            reader.ack(record)

    def drain(self) -> list[dict]:
        """Compatibility consumer; production uses peek/publish/ack."""
        with self._admitted_reader() as reader:
            return reader.drain()


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


# The optional ordinary-user native monitor is a different failure domain from
# the installed, signed service above. It has no privileged response authority.
_OBSERVE_DEADLINE = 10.0
_OBSERVE_MAX_FRAME = 16384
_OBSERVE_RECOVERY_HOLD = (
    "Independent recovery is unavailable: this monitor is bound to Core's private "
    "child Job. It cannot outlive Core, override STOP/Quit, or relaunch the app. "
    "Use Safe Startup manually; signed service supervision requires enrollment."
)
_OBSERVE_CACHE = {"state": "disabled", "reason": "Optional ordinary-user third watchdog is off",
                  "mode": "unsigned-observe", "reduced_protection": True,
                  "heartbeat_verified": False, "response_authorized": False,
                  "recovery_available": False, "recovery_verified": False,
                  "recovery_reason": _OBSERVE_RECOVERY_HOLD,
                  "signature_verified": False, "signature_state": "unverified", "signed": None,
                  "independent_supervision": False, "same_user_failure_domain": True,
                  "trust_scope": "Bundle/source-build hash is an accidental-corruption pin, not publisher authenticity"}
_OBSERVE_OWNER = None
_OBSERVE_OWNER_LOCK = threading.Lock()
_OBSERVE_START_HOLD = None
_OBSERVE_CLOSE_HOLDS = []


def _cache_observe(**updates) -> None:
    global _OBSERVE_CACHE
    _OBSERVE_CACHE = {**_OBSERVE_CACHE, **updates}


def third_watchdog_status() -> dict:
    """Copied process-memory projection only; safe for GUI/heartbeat refreshes."""
    value = dict(_OBSERVE_CACHE)
    stamp = value.get("last_heartbeat_monotonic")
    if type(stamp) in (int, float) and stamp >= 0:
        age = max(0.0, time.monotonic() - stamp)
        value["age_s"] = round(age, 3)
        if value.get("state") in {"active-unsigned", "active-reduced"} and age > _OBSERVE_DEADLINE:
            value.update(state="stale", heartbeat_verified=False,
                         reason="Third-watchdog progress is stale; process presence is not liveness")
    if value.get("signature_verified") is True:
        from datetime import datetime, timezone
        try:
            checked = value["signing_checked_monotonic"]
            expiry = datetime.fromisoformat(value["not_after"].replace("Z", "+00:00"))
            fresh = (type(checked) in (int, float) and 0 <= time.monotonic() - checked <= 900.0
                     and expiry.tzinfo is not None and datetime.now(timezone.utc) < expiry)
        except (KeyError, TypeError, ValueError, OverflowError):
            fresh = False
        if not fresh or value.get("state") not in {"active-unsigned", "active-reduced"}:
            value.update(signature_verified=False, signature_state="unverified", signed=None,
                         signature_reason="Startup signature snapshot is stale, expired or outside its live generation")
            if value.get("state") == "active-reduced":
                value.update(state="active-unsigned", reason="Active · Unsigned/unverified · Reduced protection")
    return value


def third_watchdog_heartbeat() -> dict:
    status = third_watchdog_status()
    return {"role": "watchdog3", "generation_id": status.get("generation_id", ""),
            "pid": status.get("pid", 0), "state": "running" if status.get("heartbeat_verified") is True else status["state"],
            "last_heartbeat_monotonic": status.get("last_heartbeat_monotonic"),
            "deadline_seconds": _OBSERVE_DEADLINE, "reason": status.get("reason", ""),
            "mode": "unsigned-observe", "signature_verified": status.get("signature_verified", False),
            "signature_state": status.get("signature_state", "unverified")}


def _closed_json(raw: bytes, *, maximum: int) -> dict:
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        raise NativeWatchdogError("Native diagnostic data exceeds its bound")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise NativeWatchdogError("Native diagnostic data repeats a field")
            result[key] = value
        return result
    try:
        body = json.loads(raw.decode("utf-8-sig", "strict"), object_pairs_hook=pairs,
                          parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite")))
    except (ValueError, UnicodeError) as error:
        raise NativeWatchdogError("Native diagnostic JSON is invalid") from error
    if type(body) is not dict:
        raise NativeWatchdogError("Native diagnostic object is invalid")
    return body


def _ordinary_observer_session() -> None:
    """Reject elevated/service/unknown tokens BEFORE executing a source binary."""
    if os.name != "nt" or _OBSERVE_CLOSE_HOLDS:
        raise NativeWatchdogError("Ordinary-user Windows observation or prior cleanup is unavailable")
    import ctypes as c
    from ctypes import wintypes as w
    kernel = c.WinDLL("kernel32", use_last_error=True)
    security = c.WinDLL("advapi32", use_last_error=True)
    for library, name, arguments, result in (
        (kernel, "GetCurrentProcess", [], w.HANDLE),
        (kernel, "GetCurrentThread", [], w.HANDLE),
        (kernel, "ProcessIdToSessionId", [w.DWORD, c.POINTER(w.DWORD)], w.BOOL),
        (kernel, "CloseHandle", [w.HANDLE], w.BOOL),
        (kernel, "LocalFree", [c.c_void_p], c.c_void_p),
        (security, "OpenProcessToken", [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)], w.BOOL),
        (security, "OpenThreadToken", [w.HANDLE, w.DWORD, w.BOOL, c.POINTER(w.HANDLE)], w.BOOL),
        (security, "GetTokenInformation", [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)], w.BOOL),
        (security, "ConvertSidToStringSidW", [c.c_void_p, c.POINTER(c.c_void_p)], w.BOOL)):
        function = getattr(library, name)
        function.argtypes, function.restype = arguments, result
    token = w.HANDLE()
    if security.OpenThreadToken(kernel.GetCurrentThread(), 0x8, True, c.byref(token)):
        if not kernel.CloseHandle(token):
            _OBSERVE_CLOSE_HOLDS.append((kernel, token))
        raise NativeWatchdogError("Ordinary-user observation refuses impersonation")
    if c.get_last_error() != 1008:  # ERROR_NO_TOKEN
        raise NativeWatchdogError("Thread token could not be verified")
    if not security.OpenProcessToken(kernel.GetCurrentProcess(), 0x8, c.byref(token)):
        raise NativeWatchdogError("Process token could not be verified")
    try:
        elevated, size = w.DWORD(), w.DWORD()
        if (not security.GetTokenInformation(token, 20, c.byref(elevated), c.sizeof(elevated), c.byref(size))
                or size.value != 4 or elevated.value != 0):
            raise NativeWatchdogError("Optional monitor requires a verified non-elevated user token")
        user = c.create_string_buffer(1024)
        if not security.GetTokenInformation(token, 1, user, len(user), c.byref(size)):
            raise NativeWatchdogError("Ordinary-user identity is unavailable")
        sid_text = c.c_void_p()
        if not security.ConvertSidToStringSidW(c.c_void_p.from_buffer(user), c.byref(sid_text)):
            raise NativeWatchdogError("Ordinary-user SID is unavailable")
        try:
            sid = c.wstring_at(sid_text)
        finally:
            if kernel.LocalFree(sid_text):
                _OBSERVE_CLOSE_HOLDS.append((kernel, sid_text))
                raise NativeWatchdogError("SID allocation cleanup is held")
        session = w.DWORD()
        if (sid in {"S-1-5-18", "S-1-5-19", "S-1-5-20"}
                or not kernel.ProcessIdToSessionId(os.getpid(), c.byref(session)) or session.value == 0):
            raise NativeWatchdogError("Optional monitor refuses service identities and Session 0")
    finally:
        if not kernel.CloseHandle(token):
            _OBSERVE_CLOSE_HOLDS.append((kernel, token))
            raise NativeWatchdogError("Token cleanup is held")



_OBSERVE_MAX_SOURCE_ENTRIES = 256
_OBSERVE_ADMISSION_SECONDS = 5.0


def _observe_admission_deadline(deadline: float) -> None:
    now = time.monotonic()
    if not math.isfinite(now) or not math.isfinite(deadline) or now >= deadline:
        raise NativeWatchdogError("Third-watchdog source/bundle admission deadline expired; no helper was launched")


def _observe_source_inventory(source: Path, deadline: float) -> dict[str, Path]:
    """Bound the directory stream itself, including non-source entries."""
    files = {}
    _observe_admission_deadline(deadline)
    # Path.iterdir in supported Python versions can allocate os.listdir's entire
    # result before yielding. scandir streams at most one entry into this loop.
    with os.scandir(source) as entries:
        for count, entry in enumerate(entries, 1):
            _observe_admission_deadline(deadline)
            if count > _OBSERVE_MAX_SOURCE_ENTRIES:
                raise NativeWatchdogError("Third-watchdog source directory exceeds its entry budget; no helper was launched")
            name = entry.name
            if name in {"go.mod", "go.sum"} or name.endswith(".go") and not name.endswith("_test.go"):
                files[name] = source / name
    _observe_admission_deadline(deadline)
    return files


@contextmanager
def _admit_observe_bundle():
    """Hold a bundled digest or explicit current-source build record, not signer trust."""
    from angerona.core.source_activation_file import RetainedFile, plain_path
    leases = []
    deadline = time.monotonic() + _OBSERVE_ADMISSION_SECONDS
    _observe_admission_deadline(deadline)
    try:
        if getattr(sys, "frozen", False):
            from angerona import _release_integrity
            path = Path(sys.executable).parent / BINARY_NAME
            expected = getattr(_release_integrity, "WATCHDOG3_BUNDLE_SHA256", "")
            if type(expected) is not str or not _SHA256.fullmatch(expected):
                raise NativeWatchdogError("Bundled third-watchdog corruption pin is unavailable")
        else:
            root = Path(__file__).resolve().parents[3]
            path = root / "build" / "watchdog3" / BINARY_NAME
            record = RetainedFile(path.with_suffix(".exe.build.json")); leases.append(record)
            body = _closed_json(record.read(limit=65536), maximum=65536)
            if (body.get("schema") != 1 or type(body.get("schema")) is not int
                    or body.get("artifact") != BINARY_NAME or body.get("language") != "Go"
                    or body.get("python_runtime_required") is not False or body.get("cgo_enabled") is not False
                    or not isinstance(body.get("compiler"), str) or not body["compiler"].startswith("go version go")
                    or not _SHA256.fullmatch(str(body.get("sha256", "")))):
                raise NativeWatchdogError("Explicit source-build record is unavailable or invalid")
            source = root / "frz" / "watchdog3"
            plain_path(source, directory=True)
            files = _observe_source_inventory(source, deadline)
            inputs = body.get("source_inputs")
            if type(inputs) is not list or not 2 <= len(inputs) <= 128 or len(inputs) != len(files):
                raise NativeWatchdogError("Source-build input inventory differs")
            names = set()
            for item in inputs:
                _observe_admission_deadline(deadline)
                if (type(item) is not dict or set(item) != {"name", "sha256"}
                        or type(item["name"]) is not str or item["name"] in names or item["name"] not in files
                        or type(item["sha256"]) is not str or not _SHA256.fullmatch(item["sha256"])):
                    raise NativeWatchdogError("Source-build input record is invalid")
                names.add(item["name"])
                held = RetainedFile(files[item["name"]]); leases.append(held)
                digest, _size = held.digest(limit=2 * 1024 * 1024)
                _observe_admission_deadline(deadline)
                if digest != item["sha256"]:
                    raise NativeWatchdogError("Source changed since the explicit third-watchdog build")
            expected = body["sha256"]
        _observe_admission_deadline(deadline)
        binary = RetainedFile(path); leases.append(binary)
        digest, size = binary.digest(limit=32 * 1024 * 1024)
        _observe_admission_deadline(deadline)
        if digest != expected or size < 1024:
            raise NativeWatchdogError("Third-watchdog bytes differ from their corruption pin")
        for held in leases:
            held.check()
        _observe_admission_deadline(deadline)
        yield path, digest
        for held in leases:
            held.check()
    finally:
        errors = []
        for held in reversed(leases):
            try:
                held.close()
            except Exception as error:
                errors.append(error)
        if errors:
            _OBSERVE_CLOSE_HOLDS.extend(leases)
            raise NativeWatchdogError("Third-watchdog file-custody cleanup remains held")


class _ObserveCommand:
    """A suspended, exact-object owned, hidden native child in a private Job."""
    def __init__(self, path: Path, arguments: list[str]):
        import subprocess
        from angerona.core.privilege import sanitized_child_environment
        from angerona.telemetry.process_snapshot_worker import _Job, _Pin, _resume_owned_primary
        self.process = self.pin = self.job = self.file = None
        self.closed = False
        try:
            from angerona.core.source_activation_file import RetainedFile
            self.file = RetainedFile(path)
            self.job = _Job()
            self.process = subprocess.Popen([str(path), *arguments], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True, bufsize=_OBSERVE_MAX_FRAME,
                cwd=str(path.parent), env=sanitized_child_environment(source={}),
                creationflags=subprocess.CREATE_NO_WINDOW | 0x4)
            self.pin = _Pin(self.process.pid, process=self.process)
            identity = self.pin.native.identity(self.pin.handle)
            if ntpath.normcase(identity.image) != ntpath.normcase(str(path)):
                raise NativeWatchdogError("Owned native child image differs")
            self.job.assign(self.pin)
            if not self.job.contains(self.pin):
                raise NativeWatchdogError("Native child Job membership is unverified")
            _resume_owned_primary(self.pin)
        except Exception:
            self.close()
            raise

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            if self.pin is not None:
                if not self.pin.retire(2.0, terminate=True):
                    raise NativeWatchdogError("Exact third-watchdog retirement remains held")
            elif self.process is not None:
                # Before _Pin admission only the Popen-retained kernel handle is
                # owned. Do not look up or terminate any numeric PID.
                self.process.terminate()
                self.process.wait(timeout=2.0)
            if self.job is not None:
                if self.job.members():
                    raise NativeWatchdogError("Native child Job is not empty")
                self.job.close()
            if self.process is not None:
                self.process.wait(timeout=2.0)
                for stream in (self.process.stdin, self.process.stdout):
                    if stream is not None:
                        stream.close()
                self.process._handle.Close()
            if self.file is not None:
                self.file.close()
        except Exception as error:
            _OBSERVE_CLOSE_HOLDS.append(self)
            raise NativeWatchdogError("Third-watchdog process cleanup remains held") from error


def _signature_projection(body: dict, digest: str) -> dict:
    matches = type(body) is dict and body.get("watchdog_sha256") == digest
    verified = matches and body.get("signature_valid") is True
    if verified:
        verified = bool(_SHA256.fullmatch(str(body.get("certificate_sha256", "")))
                        and type(body.get("publisher")) is str and body["publisher"]
                        and type(body.get("not_after")) is str and body["not_after"])
    # A failed trust/chain/revocation query is unverified, not proof of no signature.
    return {"signature_verified": verified, "signature_state": "verified" if verified else "unverified",
            "signed": True if verified else None, "watchdog_sha256": body.get("watchdog_sha256", "") if matches else "",
            "certificate_sha256": body.get("certificate_sha256", "") if verified else "",
            "publisher": body.get("publisher", "") if verified else "",
            "not_after": body.get("not_after", "") if verified else "",
            "signature_reason": str(body.get("reason", "Native signature is unverified"))[:512],
            "activation_enrolled": False}


def _parse_observe_frame(raw: bytes, *, key: bytes, nonce: str, pid: int, birth: str,
                         image: str, core_pid: int, core_birth: str, previous: int) -> dict:
    import hmac
    import hashlib
    outer = _closed_json(raw, maximum=_OBSERVE_MAX_FRAME)
    if (set(outer) != {"payload", "mac"} or type(outer["payload"]) is not str
            or type(outer["mac"]) is not str or not _SHA256.fullmatch(outer["mac"])):
        raise NativeWatchdogError("Third-watchdog progress envelope is invalid")
    payload = outer["payload"].encode("utf-8", "strict")
    expected = hmac.new(key, b"angerona-watchdog3-observe-v1\0" + payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, outer["mac"]):
        raise NativeWatchdogError("Third-watchdog progress authentication failed")
    value = _closed_json(payload, maximum=8192)
    fields = {"schema", "nonce", "pid", "birth_ticks", "executable_path", "counter", "core_pid",
              "core_birth_ticks", "core_counter", "core_state", "signature", "recovery_available"}
    if (set(value) != fields or value["schema"] != 1 or type(value["schema"]) is not int
            or value["nonce"] != nonce or type(value["pid"]) is not int or value["pid"] != pid
            or value["birth_ticks"] != birth or type(value["executable_path"]) is not str
            or ntpath.normcase(value["executable_path"]) != ntpath.normcase(image)
            or type(value["core_pid"]) is not int or value["core_pid"] != core_pid
            or value["core_birth_ticks"] != core_birth or value["recovery_available"] is not False
            or type(value["counter"]) is not int or not previous < value["counter"] <= 2**64 - 1
            or type(value["core_counter"]) is not int or not 0 <= value["core_counter"] <= 2**32 - 1
            or value["core_state"] not in {"pending", "verified", "stale", "unavailable", "exited"}
            or type(value["signature"]) is not dict):
        raise NativeWatchdogError("Third-watchdog progress generation, scope or counter differs")
    return value


def _make_observe_thread(target):
    # Constructing a Thread does not spawn it. Keep the actual start attempt
    # separate so an uncertain start outcome cannot release singleton custody.
    return threading.Thread(target=target, name="native-watchdog3-observe", daemon=True)


class UnsignedWatchdogMonitor:
    """Explicit opt-in observation; no startup registration or independent recovery."""
    def __init__(self, core_beat):
        self._beat = core_beat
        self._stop = threading.Event()
        self._thread = None
        self._start_claimed = False
        self._start_attempted = False
        self._start_custody_held = False
        self._admission_gate = threading.Event()
        self._admission_committed = False

    def start(self) -> bool:
        global _OBSERVE_OWNER, _OBSERVE_START_HOLD
        with _OBSERVE_OWNER_LOCK:
            # A monitor object is single-use, even after its worker retired.
            # Reusing its already-open gate would reopen target-before-return.
            # Reject without changing the current owner or its cached status.
            if self._start_claimed:
                return False
            self._start_claimed = True
            if _OBSERVE_START_HOLD is not None or _OBSERVE_OWNER is not None:
                _cache_observe(state="unavailable", heartbeat_verified=False,
                               reason="Optional native monitor start held: another exact owner or uncertain start already owns this session",
                               start_custody_held=_OBSERVE_START_HOLD is not None)
                return False
            _OBSERVE_OWNER = self
            _cache_observe(state="starting", reason="Checking optional native monitor and ordinary-user scope",
                           heartbeat_verified=False, start_custody_held=False)
        try:
            self._thread = _make_observe_thread(self._run)
            self._start_attempted = True
            self._thread.start()
        except Exception as error:
            with _OBSERVE_OWNER_LOCK:
                if self._start_attempted:
                    # An exception from start is not proof that a native thread
                    # cannot bootstrap late. Stop cooperatively, retain exact
                    # ownership, and never retry or join that uncertain object.
                    self._start_custody_held = True
                    self._stop.set()
                    _OBSERVE_START_HOLD = self
                elif _OBSERVE_OWNER is self:
                    # Thread construction failed before any start/native child
                    # attempt. This owner is provably unspawned and can release.
                    _OBSERVE_OWNER = None
                _cache_observe(state="unavailable", heartbeat_verified=False,
                               start_custody_held=self._start_custody_held,
                               reason=("Optional native monitor start outcome remains held: "
                                       if self._start_custody_held else "Optional native monitor could not start: ")
                                      + (str(error) or type(error).__name__)[:256])
                # A target may already be waiting. Publish STOP/held ownership
                # before releasing it; failed start must admit no native work.
                self._admission_gate.set()
            return False
        with _OBSERVE_OWNER_LOCK:
            if self._stop.is_set() or _OBSERVE_OWNER is not self or _OBSERVE_START_HOLD is not None:
                self._admission_gate.set()
                return False
            # Thread.start has returned successfully. Only this commit releases
            # the target into native admission; target-before-return is held.
            self._admission_committed = True
            self._admission_gate.set()
        return True

    def request_stop(self):
        self._stop.set()
        with _OBSERVE_OWNER_LOCK:
            if self._start_custody_held:
                _cache_observe(state="unavailable", heartbeat_verified=False, start_custody_held=True,
                               reason="STOP/Quit requested; uncertain optional-monitor thread ownership remains held")
            elif _OBSERVE_OWNER is self or (_OBSERVE_OWNER is None and _OBSERVE_START_HOLD is None):
                _cache_observe(state="stopped", heartbeat_verified=False,
                               reason="STOP/Quit requested; no native relaunch is authorized")

    def stop(self):
        self.request_stop()
        if self._start_custody_held:
            return
        if self._thread is not None:
            self._thread.join(timeout=6.0)
            if self._thread.is_alive():
                _cache_observe(state="unavailable", reason="Native monitor owner retirement remains held", heartbeat_verified=False)

    def _run(self):
        import queue
        import secrets
        import threading
        command = reader = None
        messages = queue.Queue(maxsize=2)
        try:
            self._admission_gate.wait()
            if not self._admission_committed or self._start_custody_held or self._stop.is_set():
                return
            _ordinary_observer_session()
            if self._stop.is_set():
                return
            core = _query_process(os.getpid())
            key = getattr(self._beat, "_key", None)
            if core is None or type(key) is not bytes or len(key) != 32:
                raise NativeWatchdogError("Exact Core identity or component-only heartbeat key is unavailable")
            nonce, mac_key = secrets.token_hex(32), secrets.token_bytes(32)
            with _admit_observe_bundle() as (path, digest):
                if self._stop.is_set():
                    return
                command = _ObserveCommand(path, ["--observe"])
                pid, birth = command.pin.pid, command.pin.birth
                request = {"schema": 1, "nonce": nonce, "mac_key": mac_key.hex(), "core_pid": core.pid,
                           "core_birth_ticks": str(core.birth_ticks), "core_image": core.image,
                           "core_heartbeat": str(self._beat.path), "core_heartbeat_key": key.hex()}
                raw = json.dumps(request, separators=(",", ":")).encode("ascii") + b"\n"
                if len(raw) > 8192:
                    raise NativeWatchdogError("Native monitor bootstrap exceeds its bound")
                command.process.stdin.write(raw); command.process.stdin.flush(); command.process.stdin.close()
                def read_frames():
                    try:
                        while not self._stop.is_set():
                            line = command.process.stdout.readline(_OBSERVE_MAX_FRAME + 1)
                            if not line or len(line) > _OBSERVE_MAX_FRAME or not line.endswith(b"\n"):
                                raise NativeWatchdogError("Native monitor progress pipe ended or exceeded its bound")
                            try:
                                messages.put(line, timeout=1.0)
                            except queue.Full:
                                raise NativeWatchdogError("Native progress owner is not draining") from None
                    except Exception as error:
                        try:
                            messages.put(error, timeout=1.0)
                        except queue.Full:
                            pass
                reader = threading.Thread(target=read_frames, name="native-watchdog3-pipe", daemon=True)
                reader.start()
                previous, last = 0, time.monotonic()
                signing_seen = False
                _cache_observe(pid=pid, birth_ticks=birth, image_sha256=digest, executable_path=str(path),
                               generation_id=f"{pid}:{birth}:{nonce}")
                while not self._stop.wait(0.1):
                    try:
                        item = messages.get(timeout=0.2)
                    except queue.Empty:
                        deadline = 20.0 if previous == 0 else _OBSERVE_DEADLINE
                        if not command.pin.alive() or time.monotonic() - last > deadline:
                            raise NativeWatchdogError("Native monitor progress deadline expired")
                        continue
                    if isinstance(item, Exception):
                        raise item
                    value = _parse_observe_frame(item, key=mac_key, nonce=nonce, pid=pid, birth=birth,
                        image=str(path), core_pid=core.pid, core_birth=str(core.birth_ticks), previous=previous)
                    if not command.pin.alive():
                        raise NativeWatchdogError("Native monitor process generation has exited")
                    if self._stop.is_set():
                        break
                    advancing = previous > 0
                    previous, last = value["counter"], time.monotonic()
                    signature = _signature_projection(value["signature"], digest)
                    if not signing_seen:
                        from datetime import datetime, timezone
                        signing_seen = True
                        _cache_observe(signing_checked_at=datetime.now(timezone.utc).isoformat(),
                                       signing_checked_monotonic=last)
                    state = "active-reduced" if signature["signature_verified"] else "active-unsigned"
                    label = ("Active · Unsigned/unverified · Reduced protection" if not signature["signature_verified"]
                             else "Active · Signature verified · Reduced protection")
                    _cache_observe(state=state if advancing else "starting", heartbeat_verified=advancing,
                        counter=previous, last_heartbeat_monotonic=last, core_state=value["core_state"],
                        core_heartbeat_verified=value["core_state"] == "verified", core_counter=value["core_counter"],
                        label=label if advancing else "Starting",
                        reason=(label + f" · Core heartbeat: {value['core_state']}. "
                                "No privileged or independent recovery authority.") if advancing else "Awaiting advancing native progress",
                        **signature)
        except Exception as error:
            if not self._stop.is_set():
                _cache_observe(state="unavailable", heartbeat_verified=False,
                               reason=(str(error) or type(error).__name__)[:512])
        finally:
            retirement_held = False
            if command is not None:
                try:
                    command.close()
                except Exception as error:
                    retirement_held = True
                    _cache_observe(state="unavailable", heartbeat_verified=False, reason=str(error)[:512])
            if reader is not None:
                reader.join(timeout=2.0)
                if reader.is_alive():
                    retirement_held = True
                    _OBSERVE_CLOSE_HOLDS.append(reader)
                    _cache_observe(state="unavailable", heartbeat_verified=False, reason="Native progress reader retirement remains held")
            if self._stop.is_set() and not retirement_held and not self._start_custody_held:
                _cache_observe(state="stopped", heartbeat_verified=False,
                               reason="STOP/Quit requested; exact native owner retired without relaunch")
            if not retirement_held:
                global _OBSERVE_OWNER
                with _OBSERVE_OWNER_LOCK:
                    if _OBSERVE_OWNER is self and _OBSERVE_START_HOLD is not self:
                        _OBSERVE_OWNER = None


def inspect_watchdog_candidate(path) -> dict:
    """Bounded background-only review using the admitted helper, NEVER the candidate."""
    import queue
    import threading
    from angerona.telemetry.process_snapshot_worker import on_gui_thread
    unavailable = {"schema": 1, "signature_valid": False, "watchdog_sha256": "",
                   "certificate_sha256": "", "publisher": "", "not_after": "",
                   "activation_eligible": False, "mode_state": "diagnostic",
                   "activation_status": "not-assessed-by-diagnostic"}
    command = reader = None
    try:
        if on_gui_thread():
            raise NativeWatchdogError("Signing review must run on its bounded background worker")
        selected = _local_path(str(path), executable=True)
        _ordinary_observer_session()
        with _admit_observe_bundle() as (helper, _digest):
            command = _ObserveCommand(helper, ["--inspect-signing", selected])
            command.process.stdin.close()
            messages = queue.Queue(maxsize=1)
            def read_result():
                try:
                    messages.put(command.process.stdout.read(_OBSERVE_MAX_FRAME + 1), timeout=1.0)
                except Exception as error:
                    try:
                        messages.put(error, timeout=1.0)
                    except queue.Full:
                        pass
            reader = threading.Thread(target=read_result, name="watchdog3-signing-review-pipe", daemon=True)
            reader.start()
            raw = messages.get(timeout=15.0)
            if isinstance(raw, Exception):
                raise raw
            command.process.wait(timeout=2.0)
            if command.process.returncode != 0:
                raise NativeWatchdogError("Native signing diagnostic did not finish successfully")
            value = _closed_json(raw, maximum=_OBSERVE_MAX_FRAME)
            if value.get("activation_eligible") is not False:
                raise NativeWatchdogError("Read-only diagnostic unexpectedly claimed activation authority")
        return value
    except Exception as error:
        return {**unavailable, "reason": (str(error) or type(error).__name__)[:512]}
    finally:
        if command is not None:
            try:
                command.close()
            except Exception as error:
                # No successful review may survive uncertain native custody.
                _OBSERVE_CLOSE_HOLDS.append(command)
                return {**unavailable, "reason": str(error)[:512]}
        if reader is not None:
            reader.join(timeout=2.0)
            if reader.is_alive():
                _OBSERVE_CLOSE_HOLDS.append(reader)
                return {**unavailable, "reason": "Signing review reader retirement remains held"}
