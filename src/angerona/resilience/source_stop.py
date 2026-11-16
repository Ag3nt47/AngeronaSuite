"""Ordinary-user source-session STOP coordination, separate from admin control.

This key is owned by the interactive user. It coordinates that user's admitted
source peers; it does not protect against code already running as that user,
replace installed control authority, or authorize privileged process actions.
Only callers explicitly given one of these contexts consult this namespace.
The latest-epoch fence inhibits older same-user source families; it is not an
independent freshness floor against same-user storage/root rollback. A missing
fence holds an initialized scope; a new scope may initialize after explicit
singleton admission, without inferring authority over old or foreign actors.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
import threading
import time
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from pathlib import Path

SOURCE_SESSION_ENV = "ANGERONA_SOURCE_STOP_SESSION"
SOURCE_LAUNCH_ENV = "ANGERONA_SOURCE_LAUNCH_INTENT"
_DIRECTORY = "source-stop-v1"
_DOMAIN = b"angerona-source-stop-coordination-v1\x00"
_MAX_RECORD = 16384
_MAX_SESSIONS = 256
_RETAIN_CLOSED = 8
_MAX_PATH = 2048
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SID = re.compile(r"S-1-(?:[0-9]+-){1,14}[0-9]+\Z")
_SCOPE_FIELDS = {"source", "storage", "owner", "session"}
_STOP_PENDING_NAMES = tuple(f"stop-publish-{index}.tmp" for index in range(4))
_NATIVE_CLOSE_HOLDS = []
_NATIVE_CLOSE_HOLDS_LOCK = threading.Lock()


@dataclass(frozen=True)
class _NativeCloseHold:
    operation: str
    token: object
    native: object
    handle: object


def _retain_native_close_hold(operation, *, token=None, native=None, handle=None):
    """Keep uncertain owners alive; never retry a possibly closed handle value."""
    hold = _NativeCloseHold(operation, token, native, handle)
    with _NATIVE_CLOSE_HOLDS_LOCK:
        _NATIVE_CLOSE_HOLDS.append(hold)


@dataclass(frozen=True)
class _Identity:
    owner: str
    session: int
    pid: int
    birth: int
    image: str


def _source_root() -> Path:
    # The actual imported source module, never a launch environment hint.
    return Path(__file__).resolve(strict=True).parents[3]


def _effective_identity() -> _Identity | None:
    """Native ordinary-desktop identity; failures do not admit a source domain.

    The private probe is the test seam. Production never accepts an injected
    identity, an environment opt-in, or a writable administrative-state hint.
    """
    if _NATIVE_CLOSE_HOLDS or os.name != "nt" or getattr(sys, "frozen", False):
        return None
    token = handle = None
    native = None
    try:
        import pywintypes
        import win32api
        import win32con
        import win32security
        from angerona.core.privilege import _validated_watchdog_context
        from angerona.core.windows_engine_custody import active_engine_custody
        from angerona.core.windows_process_lease import _Native

        if active_engine_custody() is not None:
            return None
        if _validated_watchdog_context(os.environ):
            return None
        try:
            token = win32security.OpenThreadToken(
                win32api.GetCurrentThread(), win32con.TOKEN_QUERY, True)
        except pywintypes.error as error:
            if error.winerror != 1008:  # ERROR_NO_TOKEN, not an unknown token.
                return None
            token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        get = lambda kind: win32security.GetTokenInformation(token, kind)
        owner = win32security.ConvertSidToStringSid(get(win32security.TokenUser)[0])
        session = get(win32security.TokenSessionId)
        groups = {win32security.ConvertSidToStringSid(sid)
                  for sid, _attributes in get(win32security.TokenGroups)}
        if (get(win32security.TokenElevation) != 0
                or type(session) is not int or session <= 0
                or owner in {"S-1-5-18", "S-1-5-19", "S-1-5-20"}
                or "S-1-5-6" in groups  # SERVICE logon, including virtual SIDs.
                or not groups.intersection({"S-1-5-4", "S-1-5-14"})):
            return None
        native = _Native()
        handle = native.open(os.getpid(), 0x1000 | 0x00100000, False)
        identity = native.identity(handle)
        result = _Identity(owner, session, identity.pid,
                           identity.birth_ticks, identity.image)
        return result if _valid_identity(result) else None
    except Exception:
        return None
    finally:
        # Each owner gets its own close attempt even if the other fails. A lost
        # close acknowledgement retains exact owners and holds future probes;
        # a new probe must not leak more handles or GC/retry an uncertain token.
        pending_signal = sys.exc_info()[1]
        close_interrupt = None
        if token is not None:
            try:
                token.Close()
            except BaseException as error:
                _retain_native_close_hold("token", token=token, native=native, handle=handle)
                if not isinstance(error, Exception):
                    close_interrupt = error
        if handle is not None and native is not None:
            try:
                native.close(handle)
            except BaseException as error:
                _retain_native_close_hold("process", token=token, native=native, handle=handle)
                if not isinstance(error, Exception) and close_interrupt is None:
                    close_interrupt = error
        if close_interrupt is not None:
            raise close_interrupt
        if _NATIVE_CLOSE_HOLDS and (pending_signal is None or isinstance(pending_signal, Exception)):
            return None


def _valid_identity(value: object) -> bool:
    return (type(value) is _Identity and type(value.owner) is str
            and _SID.fullmatch(value.owner) is not None
            and type(value.session) is int and 0 < value.session < 2**32
            and type(value.pid) is int and 0 < value.pid < 2**32
            and type(value.birth) is int and 0 < value.birth < 2**64
            and type(value.image) is str and _valid_text(value.image, _MAX_PATH)
            and Path(value.image).is_absolute())


def source_runtime_admitted() -> bool:
    """Classify the current ordinary source runtime without authority-file I/O.

    False includes packaged/privileged/native protected-parent contexts and
    unknown identity. True does not promise that session storage is available.
    """
    return _valid_identity(_effective_identity())


def _valid_text(value: object, maximum: int) -> bool:
    return (type(value) is str and 0 < len(value) <= maximum
            and all(ord(char) >= 32 for char in value))


def _plain_chain(path: Path) -> None:
    for item in reversed((path, *path.parents)):
        info = item.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & 0x400):
            raise ValueError("Source STOP directory is not a plain directory")


def _canonical_path(path: Path) -> str:
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("Source STOP roots must be absolute")
    _plain_chain(path)
    value = os.path.normcase(str(path.resolve(strict=True)))
    if not _valid_text(value, _MAX_PATH):
        raise ValueError("Source STOP root exceeds its bound")
    return value


def _scope(storage: Path, identity: _Identity) -> dict:
    return {"source": _canonical_path(_source_root()),
            "storage": _canonical_path(Path(storage)),
            "owner": identity.owner, "session": identity.session}


def _scope_digest(scope: dict) -> str:
    return hashlib.sha256(_DOMAIN + b"namespace\x00" + _encode(scope)).hexdigest()


def _namespace(scope: dict) -> Path:
    # A legitimate new desktop logon or relocated source tree must not consume
    # another scope's pointer. This digest is a locator, never admission: every
    # record still authenticates the complete closed scope with its epoch key.
    return Path(scope["storage"]) / "ipc" / _DIRECTORY / _scope_digest(scope)


def _latest_path(scope: dict) -> Path:
    # Native SID + current trusted storage only. Source/session changes must
    # inhibit earlier source peers rather than leaving a dormant restart loop.
    family = {"owner": scope["owner"], "storage": scope["storage"]}
    digest = hashlib.sha256(_DOMAIN + b"latest-family\x00" + _encode(family)).hexdigest()
    return Path(scope["storage"]) / "ipc" / _DIRECTORY / ("latest-" + digest + ".json")


def _mkdir(path: Path) -> None:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    _plain_chain(path)


def _file_identity(info) -> tuple:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _read_bytes(path: Path, maximum: int = _MAX_RECORD) -> bytes:
    _plain_chain(path.parent)
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or getattr(before, "st_file_attributes", 0) & 0x400
            or before.st_nlink != 1 or not 0 < before.st_size <= maximum):
        raise ValueError("Source STOP file is not a bounded plain file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        stream = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    with stream:
        if _file_identity(os.fstat(stream.fileno())) != _file_identity(before):
            raise ValueError("Source STOP file changed during open")
        raw = stream.read(maximum + 1)
        if not 0 < len(raw) <= maximum:
            raise ValueError("Source STOP file exceeds its bound")
        return raw


def _json(raw: bytes) -> dict:
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("Duplicate source STOP field")
            value[key] = item
        return value
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                       parse_constant=lambda _value: (_ for _ in ()).throw(
                           ValueError("Non-finite source STOP value")))
    if type(value) is not dict:
        raise ValueError("Source STOP record must be an object")
    return value


def _encode(value: dict) -> bytes:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii")
    if not 0 < len(raw) <= _MAX_RECORD:
        raise ValueError("Source STOP record exceeds its bound")
    return raw


def _signed(body: dict, key: bytes) -> dict:
    signature = hmac.new(key, _DOMAIN + body["purpose"].encode("ascii")
                         + b"\x00" + _encode(body), hashlib.sha256).hexdigest()
    return {**body, "sig": signature}


def _verified(path: Path, key: bytes, purpose: str, scope: dict,
              epoch: str, extra: set[str]) -> dict:
    return _verified_raw(_read_bytes(path), key, purpose, scope, epoch, extra)


def _verified_raw(raw: bytes, key: bytes, purpose: str, scope: dict,
                  epoch: str, extra: set[str]) -> dict:
    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_RECORD:
        raise ValueError("Source STOP record exceeds its bound")
    value = _json(raw)
    required = {"schema", "purpose", "epoch", "sig"} | _SCOPE_FIELDS | extra
    if (set(value) != required or type(value.get("schema")) is not int
            or value["schema"] != 1 or value.get("purpose") != purpose
            or value.get("epoch") != epoch
            or any(type(value.get(k)) is not type(v) or value[k] != v
                   for k, v in scope.items())
            or type(value.get("sig")) is not str
            or _HEX64.fullmatch(value["sig"]) is None):
        raise ValueError("Source STOP record has the wrong scope or schema")
    body = {key: item for key, item in value.items() if key != "sig"}
    if not hmac.compare_digest(value["sig"], _signed(body, key)["sig"]):
        raise ValueError("Source STOP signature mismatch")
    return value


def _issuer(value: object) -> bool:
    return (type(value) is dict and set(value) == {"pid", "birth", "image"}
            and type(value["pid"]) is int and 0 < value["pid"] < 2**32
            and type(value["birth"]) is int and 0 < value["birth"] < 2**64
            and _valid_text(value["image"], _MAX_PATH)
            and Path(value["image"]).is_absolute())


def _identity_record(identity: _Identity) -> dict:
    return {"pid": identity.pid, "birth": identity.birth, "image": identity.image}


def _verify_stop_raw(raw: bytes, key: bytes, scope: dict, epoch: str) -> dict:
    value = _verified_raw(raw, key, "stop", scope, epoch,
                          {"issuer", "nonce", "issued_ms", "reason"})
    if (not _issuer(value["issuer"]) or type(value["nonce"]) is not str
            or _HEX32.fullmatch(value["nonce"]) is None
            or type(value["issued_ms"]) is not int or not 0 < value["issued_ms"] < 2**63
            or not _valid_text(value["reason"], 256)):
        raise ValueError("Source STOP command is malformed")
    return value


def _write_new(path: Path, raw: bytes) -> None:
    _plain_chain(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _close_stop_descriptor(descriptor, owner=None):
    try:
        os.close(descriptor)
    except BaseException:
        _retain_native_close_hold("stop-publication", token=owner, native=os, handle=descriptor)
        raise  # Unknown close acknowledgement is never retried or dropped.


@contextmanager
def _stop_directory(path: Path):
    from angerona.core.alert_retention import _Directory
    from angerona.core.source_sandbox import _hold_plain_directories
    descriptor = None
    with _hold_plain_directories(path):
        try:
            if os.name != "nt":
                descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            yield _Directory(path, descriptor)
        finally:
            if descriptor is not None:
                _close_stop_descriptor(descriptor)


def _write_stop_pending(directory, name: str, raw: bytes) -> tuple:
    flags = (os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_BINARY", 0))
    descriptor = os.open(directory.path / name, flags, 0o600) if directory.descriptor is None else os.open(
        name, flags | os.O_CLOEXEC, 0o600, dir_fd=directory.descriptor)
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if not 0 < written <= len(raw) - offset:
                raise OSError("STOP pending write made no progress")
            offset += written
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        return info.st_dev, info.st_ino
    finally:
        _close_stop_descriptor(descriptor)


def _stop_pending_bytes(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    raw = os.read(descriptor, _MAX_RECORD + 1)
    if not 0 < len(raw) <= _MAX_RECORD:
        raise ValueError("STOP pending record exceeds its bound")
    return raw


def _finish_linked_stop(context, directory, name: str, descriptor: int) -> bool:
    """Retire only a valid signed pending duplicate of the exact target inode."""
    info, pending, target = os.fstat(descriptor), directory.stat(name), directory.stat("stop.json")
    expected = info.st_dev, info.st_ino
    for value in (info, pending, target):
        if (not stat.S_ISREG(value.st_mode) or stat.S_ISLNK(value.st_mode)
                or getattr(value, "st_file_attributes", 0) & 0x400
                or value.st_nlink != 2 or (value.st_dev, value.st_ino) != expected):
            return False
    context._stop_raw(_stop_pending_bytes(descriptor))
    # Anchored unlink of this known, signed duplicate; the target is untouched.
    # Other/unknown pending entries are never removed.
    if _file_identity(directory.stat(name)) != _file_identity(pending):
        return False
    os.unlink(name, dir_fd=directory.descriptor)
    final = os.fstat(descriptor)
    target = directory.stat("stop.json")
    if (final.st_nlink != 1 or target.st_nlink != 1
            or (final.st_dev, final.st_ino) != expected
            or (target.st_dev, target.st_ino) != expected):
        raise ValueError("STOP publication duplicate cleanup is unproven")
    os.fsync(directory.descriptor)
    return True


def _recover_linked_stop(context, directory) -> bool:
    if os.name == "nt":
        return False
    try:
        if directory.stat("stop.json").st_nlink != 2:
            return False
    except FileNotFoundError:
        return False
    import fcntl
    for name in _STOP_PENDING_NAMES:
        descriptor = None
        try:
            descriptor = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                                 dir_fd=directory.descriptor)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if _finish_linked_stop(context, directory, name, descriptor):
                return True
        except (FileNotFoundError, ValueError, BlockingIOError):
            continue
        finally:
            if descriptor is not None:
                _close_stop_descriptor(descriptor)
    return False


def _publish_stop_no_replace(context, directory, held, name: str):
    if os.name == "nt":
        held.rename("stop.json")  # Existing retained rename has ReplaceIfExists=False.
    else:
        os.link(name, "stop.json", src_dir_fd=directory.descriptor,
                dst_dir_fd=directory.descriptor, follow_symlinks=False)
        if not _finish_linked_stop(context, directory, name, held.descriptor):
            raise ValueError("STOP linked publication differs from its retained pending inode")


def _publish_stop(context, raw: bytes) -> None:
    """STOP-only bounded temp publication; never replace an existing command."""
    with _stop_directory(context._command_path().parent) as directory:
        for name in _STOP_PENDING_NAMES:
            expected = None
            try:
                expected = _write_stop_pending(directory, name, raw)
            except FileExistsError:
                pass  # Validate a prior complete signed attempt, or preserve it.
            held = None
            try:
                held = directory.open(name)
                info = held.info()
                if expected is not None and (info.st_dev, info.st_ino) != expected:
                    raise ValueError("STOP pending inode changed before publication")
                context._stop_raw(_stop_pending_bytes(held.descriptor))
                os.fsync(held.descriptor)  # Retry durability of a prior fsync-failed signed attempt.
                try:
                    _publish_stop_no_replace(context, directory, held, name)
                except FileExistsError:
                    # A racing valid/invalid original is never replaced. Its
                    # existing authentication result decides what STOP reports.
                    if directory.exists("stop.json"):
                        if os.name != "nt":
                            _recover_linked_stop(context, directory)
                        context._read_stop()
                        return
                    raise
                return
            except ValueError:
                if expected is not None:
                    raise
                continue  # Preserve an unknown/partial prior slot; try the next fixed slot.
            finally:
                if held is not None:
                    descriptor, held.descriptor = held.descriptor, -1
                    _close_stop_descriptor(descriptor, held)
        raise RuntimeError("STOP pending slots are retained; no original was overwritten")


def _base(purpose: str, epoch: str, scope: dict) -> dict:
    return {"schema": 1, "purpose": purpose, "epoch": epoch, **scope}


class SourceLaunchStopped(ValueError):
    """An automatic canonical helper must preserve an existing source STOP."""


def _launch_scope(storage: Path, identity: _Identity) -> dict:
    root = Path(storage)
    if not root.is_absolute() or ".." in root.parts:
        raise ValueError("Source launch storage must be absolute")
    for item in reversed((root, *root.parents)):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue  # First launch may precede creation of the trusted plan root.
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & 0x400):
            raise ValueError("Source launch storage is redirected")
    value = os.path.normcase(str(root.resolve(strict=False)))
    if not _valid_text(value, _MAX_PATH):
        raise ValueError("Source launch storage exceeds its bound")
    return {"source": _canonical_path(_source_root()), "storage": value,
            "owner": identity.owner, "session": identity.session}


def _launch_state(scope: dict) -> tuple[str, str]:
    latest, _fingerprint = _latest_transition_state(scope)
    if latest is None:
        return "", ""
    old_scope = {name: latest[name] for name in _SCOPE_FIELDS}
    directory = Path(scope["storage"]) / "ipc" / _DIRECTORY / latest["scope_hash"] / latest["epoch"]
    try:
        raw = _read_bytes(directory / "stop.json")
    except FileNotFoundError:
        command = ""
    else:
        # A helper cannot construct an admitted foreign-session context. Reuse
        # its complete STOP validator with only already-verified scope/key data.
        key = _epoch_key(directory)
        value = _verify_stop_raw(raw, key, old_scope, latest["epoch"])
        command = hashlib.sha256(_encode(value)).hexdigest()
    return hashlib.sha256(_encode(latest)).hexdigest(), command


def capture_source_launch_intent(storage: Path, *, automatic: bool = False) -> str | None:
    """Read-only canonical-helper snapshot; never admission or privilege authority."""
    identity = _effective_identity()
    if not _valid_identity(identity):
        return None
    if type(automatic) is not bool:
        raise ValueError("Source launch mode must be boolean")
    scope = _launch_scope(storage, identity)
    latest, command = _launch_state(scope)
    if automatic and command:
        raise SourceLaunchStopped("Authenticated source STOP is active; automatic startup remains stopped")
    return _encode({"schema": 1, "purpose": "canonical-source-launch", **scope,
                    "automatic": automatic, "latest": latest, "stop": command}).decode("ascii")


def _launch_intent_matches(scope: dict, raw: str) -> bool:
    try:
        if type(raw) is not str or not 0 < len(raw) <= _MAX_RECORD:
            return False
        value = _json(raw.encode("ascii"))
        if (set(value) != _SCOPE_FIELDS | {"schema", "purpose", "automatic", "latest", "stop"}
                or type(value["schema"]) is not int or value["schema"] != 1
                or value["purpose"] != "canonical-source-launch" or type(value["automatic"]) is not bool
                or any(type(value[name]) is not type(item) or value[name] != item for name, item in scope.items())
                or any(type(value[name]) is not str or value[name] != "" and _HEX64.fullmatch(value[name]) is None
                       for name in ("latest", "stop"))
                or value["automatic"] and value["stop"]):
            return False
        return _launch_state(scope) == (value["latest"], value["stop"])
    except (OSError, ValueError, UnicodeError, TypeError, RecursionError):
        return False


def source_launch_intent_current(storage: Path, raw: str) -> bool:
    identity = _effective_identity()
    if not _valid_identity(identity):
        return False
    try:
        return _launch_intent_matches(_launch_scope(storage, identity), raw)
    except (OSError, ValueError, TypeError):
        return False


def activate_source_launch_intent(storage: Path, raw: str):
    """Actual singleton-owning Core alone may consume unchanged helper state."""
    if not source_launch_intent_current(storage, raw):
        return None
    return create_source_session(storage, _expected_launch=raw)


def _epoch_key(directory: Path) -> bytes:
    key = _read_bytes(directory / "key", 64)
    if len(key) != 64 or _HEX64.fullmatch(key.decode("ascii")) is None:
        raise ValueError("Source STOP session key is malformed")
    return bytes.fromhex(key.decode("ascii"))


def _latest_transition_state(scope: dict) -> tuple[dict | None, tuple | None]:
    """Verify an old same-SID/storage fence using only fixed local key paths.

    Old source paths are signed data, never paths to follow, resolve or execute.
    The result can inhibit old peer respawn/self-retire only; it grants no
    authority over another process, privileged control or another user SID.
    """
    path = _latest_path(scope)
    try:
        before = _file_identity(path.lstat())
    except FileNotFoundError:
        return None, None
    raw = _read_bytes(path)
    value = _json(raw)
    fields = {"schema", "purpose", "epoch", "sig", "scope_hash"} | _SCOPE_FIELDS
    if (set(value) != fields or type(value.get("schema")) is not int
            or value["schema"] != 1 or value.get("purpose") != "latest-source-epoch"
            or type(value.get("epoch")) is not str or _HEX32.fullmatch(value["epoch"]) is None
            or type(value.get("scope_hash")) is not str or _HEX64.fullmatch(value["scope_hash"]) is None
            or type(value.get("owner")) is not str or value["owner"] != scope["owner"]
            or type(value.get("storage")) is not str or value["storage"] != scope["storage"]
            or type(value.get("session")) is not int or not 0 < value["session"] < 2**32
            or not _valid_text(value.get("source"), _MAX_PATH)
            or not Path(value["source"]).is_absolute()):
        raise ValueError("Latest source fence has the wrong scope or schema")
    old_scope = {name: value[name] for name in _SCOPE_FIELDS}
    if value["scope_hash"] != _scope_digest(old_scope):
        raise ValueError("Latest source fence scope digest differs")
    # Only these validated hex components are appended to our ALREADY trusted
    # storage root. No old storage/source/path supplied by a record is followed.
    directory = (Path(scope["storage"]) / "ipc" / _DIRECTORY
                 / value["scope_hash"] / value["epoch"])
    key = _epoch_key(directory)
    session = _verified(directory / "session.json", key, "session", old_scope,
                        value["epoch"], {"creator"})
    if not _issuer(session["creator"]):
        raise ValueError("Latest source fence session is malformed")
    _verified_raw(raw, key, "latest-source-epoch", old_scope,
                  value["epoch"], {"scope_hash"})
    if raw != _encode(value) or _file_identity(path.lstat()) != before:
        raise ValueError("Latest source fence changed or is noncanonical")
    return value, before


@dataclass(frozen=True)
class SourceStopContext:
    """One admitted epoch captured once; never follows a newer current pointer."""
    epoch: str
    _scope_items: tuple = field(repr=False)
    _identity: _Identity = field(repr=False)
    _key: bytes = field(repr=False)
    _role: str = field(repr=False)
    _session_sig: str = field(repr=False)

    def __post_init__(self):
        if (type(self.epoch) is not str or _HEX32.fullmatch(self.epoch) is None
                or type(self._key) is not bytes or len(self._key) != 32
                or not _valid_identity(self._identity)
                or type(self._session_sig) is not str
                or _HEX64.fullmatch(self._session_sig) is None
                or type(self._role) is not str or self._role not in {"core", "peer"}
                or type(self._scope_items) is not tuple
                or len(self._scope_items) != len(_SCOPE_FIELDS)
                or any(type(item) is not tuple or len(item) != 2
                       or type(item[0]) is not str for item in self._scope_items)):
            raise ValueError("Malformed source STOP context")
        scope = dict(self._scope_items)
        if (set(scope) != _SCOPE_FIELDS or scope["owner"] != self._identity.owner
                or type(scope["session"]) is not int
                or scope["session"] != self._identity.session
                or any(not _valid_text(scope[name], _MAX_PATH)
                       or not Path(scope[name]).is_absolute()
                       for name in ("source", "storage"))):
            raise ValueError("Malformed source STOP context scope")

    def _scope(self) -> dict:
        return dict(self._scope_items)

    def _admitted(self) -> bool:
        identity = _effective_identity()
        if identity != self._identity or not _valid_identity(identity):
            return False
        try:
            return _scope(Path(self._scope()["storage"]), identity) == self._scope()
        except (OSError, ValueError):
            return False

    def _command_path(self) -> Path:
        return _namespace(self._scope()) / self.epoch / "stop.json"

    def admission_current(self) -> bool:
        """Validate this captured epoch; do not follow the current pointer.

        Missing/corrupt session state is a held source family, not an unsigned
        STOP or permission to launch another Core.
        """
        if not self._admitted():
            return False
        try:
            directory = self._command_path().parent
            if not hmac.compare_digest(_read_bytes(directory / "key", 64),
                                       self._key.hex().encode("ascii")):
                return False
            session = _verified(directory / "session.json", self._key, "session",
                                self._scope(), self.epoch, {"creator"})
            return (_issuer(session["creator"])
                    and hmac.compare_digest(session["sig"], self._session_sig))
        except (OSError, ValueError, UnicodeError, TypeError, RecursionError):
            return False

    def respawn_allowed(self) -> bool:
        """Only a valid, unstopped and unretired captured epoch may respawn."""
        if not self.admission_current():
            return False
        try:
            latest = _verified(_latest_path(self._scope()), self._key,
                               "latest-source-epoch", self._scope(), self.epoch,
                               {"scope_hash"})
            if latest["scope_hash"] != _scope_digest(self._scope()):
                return False
            # Even corrupt/uncertain retirement state holds recovery. It never
            # becomes authenticated operator intent via is_stop_requested().
            try:
                (self._command_path().parent / "retired.json").lstat()
            except FileNotFoundError:
                pass
            else:
                return False
            try:
                self._read_stop()
            except FileNotFoundError:
                return True
            return False
        except (OSError, ValueError, UnicodeError, TypeError, RecursionError):
            return False

    def is_superseded(self) -> bool:
        """Verified new same-user source epoch permits graceful SELF exit only.

        Missing/corrupt/foreign fences merely hold respawn. They do not become
        STOP intent, and this method never grants foreign-PID termination.
        """
        identity = _effective_identity()
        if identity != self._identity or not _valid_identity(identity):
            return False
        try:
            scope = self._scope()
            if _canonical_path(Path(scope["storage"])) != scope["storage"]:
                return False
            latest, _fingerprint = _latest_transition_state(scope)
            return (latest is not None and (latest["epoch"] != self.epoch
                    or latest["scope_hash"] != _scope_digest(scope)))
        except (OSError, ValueError, UnicodeError, TypeError, RecursionError):
            return False

    def _read_stop(self) -> dict:
        return self._stop_raw(_read_bytes(self._command_path()))

    def _stop_raw(self, raw: bytes) -> dict:
        # No liveness or expiry check: an intentional STOP survives Core exit.
        return _verify_stop_raw(raw, self._key, self._scope(), self.epoch)

    def is_stop_requested(self) -> bool:
        if not self._admitted():
            return False
        try:
            self._read_stop()
            return True
        except (OSError, ValueError, UnicodeError, TypeError, RecursionError):
            return False

    def request_stop(self, reason: str = "dashboard STOP") -> dict:
        if self._role != "core" or not self.admission_current():
            raise PermissionError("Source STOP requires its admitted source Core")
        if not _valid_text(reason, 256):
            raise ValueError("Source STOP reason must be 1-256 printable characters")
        try:
            return self._read_stop()
        except FileNotFoundError:
            pass
        except ValueError:
            # POSIX may have crashed between atomic no-replace link and removal
            # of its own signed duplicate. Repair only that exact two-link case.
            with _stop_directory(self._command_path().parent) as directory:
                if _recover_linked_stop(self, directory):
                    return self._read_stop()
            raise
        body = {**_base("stop", self.epoch, self._scope()),
                "issuer": _identity_record(self._identity),
                "nonce": secrets.token_hex(16), "issued_ms": time.time_ns() // 1_000_000,
                "reason": reason}
        value = _signed(body, self._key)
        _publish_stop(self, _encode(value))
        return self._read_stop()

    def _retirement_raw(self, raw: bytes) -> dict:
        value = _verified_raw(raw, self._key, "retired", self._scope(), self.epoch,
                              {"issuer", "nonce", "retired_ms"})
        if (not _issuer(value["issuer"]) or type(value["nonce"]) is not str
                or _HEX32.fullmatch(value["nonce"]) is None
                or type(value["retired_ms"]) is not int
                or not 0 < value["retired_ms"] < 2**63
                or value["retired_ms"] > time.time_ns() // 1_000_000 + 60_000):
            raise ValueError("Source retirement record is malformed")
        return value

    def mark_retired(self) -> dict:
        """Core receipt after its caller proves ALL owned work retired.

        The application must not call this merely because shutdown was requested
        or a cleanup thread returned. Reclamation additionally needs native proof
        that this exact closing Core generation has exited.
        """
        if self._role != "core" or not self.admission_current():
            raise PermissionError("Source retirement requires its admitted source Core")
        self._read_stop()  # No clean-retirement claim without a valid STOP.
        value = _signed({**_base("retired", self.epoch, self._scope()),
                         "issuer": _identity_record(self._identity),
                         "nonce": secrets.token_hex(16),
                         "retired_ms": time.time_ns() // 1_000_000}, self._key)
        path = self._command_path().parent / "retired.json"
        try:
            _write_new(path, _encode(value))
        except FileExistsError:
            return self._retirement_raw(_read_bytes(path))
        return self._retirement_raw(_read_bytes(path))


def _join(scope: dict, identity: _Identity, epoch: str | None,
          role: str) -> SourceStopContext:
    namespace = _namespace(scope)
    pointer = None
    if epoch is None:
        pointer = _json(_read_bytes(namespace / "current.json"))
        epoch = pointer.get("epoch")
    if type(epoch) is not str or _HEX32.fullmatch(epoch) is None:
        raise ValueError("Source STOP epoch must be lowercase 32-hex")
    directory = namespace / epoch
    key = _epoch_key(directory)
    session = _verified(directory / "session.json", key, "session", scope,
                        epoch, {"creator"})
    if not _issuer(session["creator"]):
        raise ValueError("Source STOP session creator is malformed")
    if pointer is not None:
        _verified(namespace / "current.json", key, "current", scope, epoch, set())
    return SourceStopContext(epoch, tuple(scope.items()), identity, key, role, session["sig"])


def join_source_session(storage: Path, epoch: str | None = None,
                        role: str = "core") -> SourceStopContext | None:
    """Join once without writes, rotation or clearing an existing STOP.

    A supplied epoch is exact. Only automatic recovery without a reference may
    read current.json; already joined peers never follow that pointer again.
    Unavailable/corrupt source coordination does not authorize another domain.
    """
    identity = _effective_identity()
    if (not _valid_identity(identity) or type(role) is not str
            or role not in {"core", "peer"}):
        return None
    try:
        return _join(_scope(Path(storage), identity), identity, epoch, role)
    except (OSError, ValueError, UnicodeError, TypeError, RecursionError):
        return None


def _closing_core_exited(issuer: dict) -> bool | None:
    """Prove this exact native generation exited; denied/unknown is not proof."""
    if _NATIVE_CLOSE_HOLDS or os.name != "nt" or not _issuer(issuer):
        return None
    handle = native = None
    try:
        from angerona.core.windows_process_lease import _Native
        native = _Native()
        handle = native.api.OpenProcess(0x1000 | 0x00100000, False, issuer["pid"])
        if not handle:
            # OpenProcess documents ERROR_INVALID_PARAMETER for an absent PID;
            # access denial and every other error preserve the closed epoch.
            error = native.ctypes.get_last_error()
            handle = None
            return True if error == 87 else None
        identity = native.identity(handle)
        if identity.pid != issuer["pid"]:
            return None
        if identity.birth_ticks != issuer["birth"]:
            return True  # Reused PID; never act on that different live process.
        if identity.image != issuer["image"]:
            return None
        return native.wait(handle, 0)
    except Exception:
        return None
    finally:
        pending_signal = sys.exc_info()[1]
        if handle is not None and native is not None:
            try:
                native.close(handle)
            except BaseException as error:
                _retain_native_close_hold("retirement-process", native=native, handle=handle)
                if not isinstance(error, Exception):
                    raise
        if _NATIVE_CLOSE_HOLDS and (pending_signal is None or isinstance(pending_signal, Exception)):
            return None


def _epoch_names(namespace: Path) -> list[str]:
    names = []
    with os.scandir(namespace) as entries:
        for entry in entries:
            if entry.name == "current.json":
                continue
            if (_HEX32.fullmatch(entry.name) is None
                    or not entry.is_dir(follow_symlinks=False)
                    or len(names) >= _MAX_SESSIONS):
                raise ValueError("Source STOP namespace has uncertain or excess entries")
            names.append(entry.name)
    return names


def _complete_closed_directory(directory: Path) -> bool:
    expected = {"key", "session.json", "stop.json", "retired.json"}
    seen = set()
    with os.scandir(directory) as entries:
        for entry in entries:
            if (entry.name not in expected or entry.name in seen
                    or not entry.is_file(follow_symlinks=False)):
                return False
            seen.add(entry.name)
    return seen == expected


def _delete_closed_epoch(context: SourceStopContext, expected: dict) -> bool:
    """Delete only four authenticated, retained plain files; never recurse."""
    from angerona.core.alert_retention import _Directory, _identity
    from angerona.core.source_sandbox import _hold_plain_directories

    directory = context._command_path().parent
    descriptor = None
    with _hold_plain_directories(directory.parent):
        before = directory.lstat()
        with _hold_plain_directories(directory):
            if not _complete_closed_directory(directory):
                return False
            try:
                if os.name != "nt":
                    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY
                                         | os.O_NOFOLLOW | os.O_CLOEXEC)
                retained = _Directory(directory, descriptor)
                with ExitStack() as stack:
                    held = {name: stack.enter_context(retained.open(name))
                            for name in ("key", "session.json", "stop.json", "retired.json")}
                    def raw(name):
                        stream = held[name]
                        os.lseek(stream.descriptor, 0, os.SEEK_SET)
                        value = os.read(stream.descriptor, _MAX_RECORD + 1)
                        if not 0 < len(value) <= _MAX_RECORD:
                            raise ValueError("Retired source record exceeds its bound")
                        return value
                    if not hmac.compare_digest(raw("key"), context._key.hex().encode("ascii")):
                        return False
                    session = _verified_raw(raw("session.json"), context._key, "session",
                                            context._scope(), context.epoch, {"creator"})
                    if (not _issuer(session["creator"])
                            or not hmac.compare_digest(session["sig"], context._session_sig)):
                        return False
                    context._stop_raw(raw("stop.json"))
                    marker = context._retirement_raw(raw("retired.json"))
                    if marker != expected or _closing_core_exited(marker["issuer"]) is not True:
                        return False
                    if not _complete_closed_directory(directory):
                        return False
                    # Admission is removed first, so even a stale captured peer
                    # holds respawn throughout the remaining exact-file cleanup.
                    for name in ("session.json", "stop.json", "retired.json", "key"):
                        held[name].delete(_identity(held[name].info()))
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        after = directory.lstat()
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            return False
        _plain_chain(directory)
        directory.rmdir()  # Empty directory only; no recursive/path-following removal.
        return True


def _reclaim_closed(scope: dict, identity: _Identity, names: list[str],
                    current_epoch: str | None, latest_epoch: str | None = None) -> None:
    candidates = []
    for epoch in names:
        if epoch in {current_epoch, latest_epoch}:
            continue
        try:
            context = _join(scope, identity, epoch, "peer")
            directory = context._command_path().parent
            if not _complete_closed_directory(directory):
                continue
            context._read_stop()
            marker = context._retirement_raw(_read_bytes(directory / "retired.json"))
            if _closing_core_exited(marker["issuer"]) is True:
                candidates.append((marker["retired_ms"], epoch, context, marker))
        except (OSError, ValueError, UnicodeError, TypeError, RecursionError):
            continue  # Uncertain/corrupt/live epochs are never cleanup targets.
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    retain = max(0, min(_RETAIN_CLOSED, _MAX_SESSIONS - 2))
    for _stamp, _epoch, context, marker in candidates[retain:]:
        try:
            _delete_closed_epoch(context, marker)
        except (OSError, ValueError, UnicodeError, TypeError, RecursionError):
            continue


def create_source_session(storage: Path, *, _expected_launch: str | None = None) -> SourceStopContext | None:
    """Create one fresh explicit-launch epoch, preserving all prior STOPs.

    Caller must first prove explicit single-instance Core ownership. Before the
    pointer advances, the previous valid source epoch is stopped. Clean closed
    epochs are reclaimed only after exact closing-Core exit proof; recent
    receipts are retained. Unknown/live/corrupt state is preserved within the
    fixed session ceiling; exhaustion returns unavailable without a startup veto.
    """
    identity = _effective_identity()
    if not _valid_identity(identity):
        return None
    try:
        scope = _scope(Path(storage), identity)
        if _expected_launch is not None and not _launch_intent_matches(scope, _expected_launch):
            return None
        namespace = _namespace(scope)
        # Fixed, checked components only. Never recursively create through an
        # unknown ancestor or enumerate other owners'/sessions' scope folders.
        _mkdir(Path(scope["storage"]) / "ipc")
        _mkdir(namespace.parent)
        _mkdir(namespace)
        latest, previous_latest = _latest_transition_state(scope)
        pointer_path = namespace / "current.json"
        previous = old = None
        try:
            previous = _file_identity(pointer_path.lstat())
        except FileNotFoundError:
            pass
        if previous is not None:
            old = _join(scope, identity, None, "core")  # Never replace uncertain bytes.
        names = _epoch_names(namespace)
        if latest is None and (old is not None or names):
            return None  # Absence cannot reinitialize an existing local scope.
        latest_epoch = (latest["epoch"] if latest is not None
                        and latest["scope_hash"] == _scope_digest(scope) else None)
        _reclaim_closed(scope, identity, names, old.epoch if old is not None else None, latest_epoch)
        if len(_epoch_names(namespace)) >= _MAX_SESSIONS:
            return None
        if _expected_launch is not None and not _launch_intent_matches(scope, _expected_launch):
            return None  # A new STOP/latest change during preflight cannot be consumed as resume.
        if old is not None:
            old.request_stop("superseded by explicit source launch")
        epoch, key = secrets.token_hex(16), secrets.token_bytes(32)
        directory = namespace / epoch
        directory.mkdir(mode=0o700)  # A collision is not adopted or overwritten.
        _write_new(directory / "key", key.hex().encode("ascii"))
        session = {**_base("session", epoch, scope), "creator": _identity_record(identity)}
        _write_new(directory / "session.json", _encode(_signed(session, key)))
        pointer = _encode(_signed(_base("current", epoch, scope), key))
        # A fixed temporary path inside this new epoch bounds interrupted writes.
        temporary = directory / "current.pending"
        _write_new(temporary, pointer)
        latest_temporary = directory / "latest.pending"
        latest_value = {**_base("latest-source-epoch", epoch, scope),
                        "scope_hash": _scope_digest(scope)}
        _write_new(latest_temporary, _encode(_signed(latest_value, key)))
        try:
            current = _file_identity(pointer_path.lstat())
        except FileNotFoundError:
            current = None
        if current != previous:
            return None  # Preserve a concurrent launch's pointer and our bytes.
        _plain_chain(namespace)
        os.replace(temporary, pointer_path)
        try:
            current_latest = _file_identity(_latest_path(scope).lstat())
        except FileNotFoundError:
            current_latest = None
        if current_latest != previous_latest:
            return None  # Preserve a changed/uncertain storage-global fence.
        _plain_chain(namespace.parent)
        os.replace(latest_temporary, _latest_path(scope))
        return _join(scope, identity, epoch, "core")
    except (OSError, ValueError, UnicodeError, TypeError, RecursionError):
        return None
