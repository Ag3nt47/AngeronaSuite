"""Explicit, authenticated baselines for agent instructions, memory and tools.

Files are untrusted bytes: nothing here imports, parses instructions, or executes
their contents. Enrollment accepts an exact observed digest, never trust on first
use. This protects configured Angerona tool integrations, not arbitrary agents or
network traffic. An attacker with write access can replay all old signed local
state across a restart without knowing the signing key; no independent rollback
authority is claimed. POSIX drift checks are point-in-time observations only;
mapped mutations fail closed there because kernel write-denial is unavailable.
"""
from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import hmac
import json
import os
import re
import stat
import threading
from pathlib import Path

from angerona.core.executable_trust import _open_sealed
from angerona.core.source_sandbox import (
    _atomic_bytes_write, _ensure_directory, _hold_plain_directories, _validate_regular_file,
)

MAX_FILES = 64
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
KINDS = frozenset({"instruction", "memory", "tool-definition"})
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TOOL = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z")
_DOMAIN = b"Angerona agent file baseline v1\0"
_LOCK = threading.RLock()


class AgentIntegrityError(PermissionError):
    """Configured agent input is unavailable, altered or unauthenticated."""


@dataclasses.dataclass(frozen=True)
class AgentFileObservation:
    path: str
    kind: str
    tools: tuple[str, ...]
    sha256: str
    size: int

    @property
    def target_id(self):
        return hashlib.sha256(os.path.normcase(self.path).encode("utf-8")).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AgentIntegrityError("Duplicate agent baseline fields")
        result[key] = value
    return result


def _path(value):
    path = Path(value)
    if (not path.is_absolute() or ".." in path.parts or len(str(path)) > 32767
            or any(":" in part for part in path.parts[1:])):
        raise AgentIntegrityError("Use an absolute agent file path without aliases or streams")
    normalized = Path(os.path.abspath(path))
    if os.name == "nt":
        # Extended/device path spellings can bypass ordinary Win32 path rules.
        if str(path).startswith(("\\\\?\\", "\\\\.\\")):
            raise AgentIntegrityError("Device aliases are not agent file paths")
        if any(part.endswith((".", " ")) for part in path.parts[1:]):
            raise AgentIntegrityError("Ambiguous agent file path component")
        if len(path.drive) != 2 or path.drive[1] != ":":
            raise AgentIntegrityError("Agent baselines require a local drive path")
        # Refuse 8.3 aliases instead of resolving/accepting a different spelling:
        # runtime-root exclusion and target IDs must use the same long pathname.
        import ctypes
        from ctypes import wintypes
        expand = ctypes.WinDLL("kernel32", use_last_error=True).GetLongPathNameW
        expand.argtypes = (wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD)
        expand.restype = wintypes.DWORD
        buffer = ctypes.create_unicode_buffer(32768)
        count = expand(str(normalized), buffer, len(buffer))
        if not count and ctypes.get_last_error() not in {2, 3}:
            raise AgentIntegrityError("Agent file canonical path could not be verified")
        if count and (count >= len(buffer) or os.path.normcase(buffer.value) != os.path.normcase(str(normalized))):
            raise AgentIntegrityError("Agent file paths must use canonical long names, not aliases")
    return normalized


def _mutation_custody_available():
    return os.name == "nt"


@contextlib.contextmanager
def _held_bytes(path, maximum):
    try:
        with _hold_plain_directories(path.parent):
            _validate_regular_file(path)
            with _open_sealed(path) as stream:
                before = os.fstat(stream.fileno())
                if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                        or before.st_size > maximum):
                    raise AgentIntegrityError("Agent file must be bounded and single-link")
                content = stream.read(maximum + 1)
                after = os.fstat(stream.fileno())
                named = path.stat(follow_symlinks=False)
                fields = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
                if (len(content) > maximum or fields(before) != fields(after)
                        or fields(before) != fields(named)):
                    raise AgentIntegrityError("Agent file changed during observation")
                yield content
    except AgentIntegrityError:
        raise
    except (OSError, ValueError) as exc:
        raise AgentIntegrityError("Agent file custody or availability could not be verified") from exc


def observe_agent_file(path, kind, tools=("*",)):
    path = _path(path)
    if not isinstance(kind, str) or kind not in KINDS:
        raise AgentIntegrityError("Unknown agent file kind")
    if (not isinstance(tools, (tuple, list)) or len(tools) > 32
            or any(not isinstance(name, str) or (name != "*" and not _TOOL.fullmatch(name))
                   for name in tools) or len(set(tools)) != len(tools)):
        raise AgentIntegrityError("Use bounded canonical tool identifiers or *")
    with _held_bytes(path, MAX_FILE_BYTES) as raw:
        return AgentFileObservation(str(path), kind, tuple(sorted(tools)),
                                    hashlib.sha256(raw).hexdigest(), len(raw))


@contextlib.contextmanager
def _lease(directory):
    """Create/open a no-follow lease without ever writing to its contents."""
    path = directory / ".authority.lock"
    descriptor = -1
    if os.name == "nt":
        import ctypes
        import msvcrt
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                      wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        handle = kernel.CreateFileW(str(path), 0xC0000000, 0, None, 4, 0x00200000, None)
        if handle == wintypes.HANDLE(-1).value:
            raise AgentIntegrityError("Agent enrollment is busy or its lease is unavailable")
        try:
            descriptor = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
        except BaseException:
            kernel.CloseHandle(handle)
            raise
    else:
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        _validate_regular_file(path)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise AgentIntegrityError("Agent enrollment authority lease is aliased")
        if os.name != "nt":
            import fcntl
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


class AgentIntegrityStore:
    def __init__(self, data_root, *, key=None):
        self.root = _path(data_root)
        self.directory = self.root / "agent-integrity"
        self.path = self.directory / "baseline.json"
        self.marker = self.root / "agent-integrity.enrolled"
        if key is not None and (type(key) is not bytes or len(key) != 32):
            raise ValueError("Agent baseline authority requires a 32-byte key")
        self._key_override = key
        self._was_configured = False
        self._head_lock = threading.Lock()
        self._highest_generation = 0
        self._head_digest = ""

    @classmethod
    def current(cls):
        from angerona.core.data_paths import data_dir
        return cls(data_dir())

    def _key(self):
        if self._key_override is not None:
            return self._key_override
        # Never silently generate/rotate an authority during an integrity check.
        with _held_bytes(self.root / "bus.key", 128) as raw:
            try:
                key = bytes.fromhex(raw.decode("ascii").strip())
            except (ValueError, UnicodeError) as exc:
                raise AgentIntegrityError("Agent baseline signing authority is malformed") from exc
        if len(key) != 32:
            raise AgentIntegrityError("Agent baseline signing authority is unavailable")
        return key

    def _signature(self, body):
        return hmac.new(self._key(), _DOMAIN + _canonical(body), hashlib.sha256).hexdigest()

    def _remember_head(self, body):
        generation = body["generation"]
        digest = hashlib.sha256(_canonical(body)).hexdigest()
        with self._head_lock:
            if (generation < self._highest_generation
                    or (generation == self._highest_generation and self._head_digest != digest)):
                raise AgentIntegrityError("Agent baseline rollback or conflicting generation detected")
            self._highest_generation = generation
            self._head_digest = digest

    def _decode(self, raw):
        try:
            document = json.loads(raw, object_pairs_hook=_unique_object)
            if type(document) is not dict or set(document) != {"body", "hmac"}:
                raise ValueError
            body = document["body"]
            supplied = document["hmac"]
            if (type(body) is not dict or set(body) != {"schema", "generation", "entries"}
                    or type(body["schema"]) is not int or body["schema"] != 1
                    or type(body["generation"]) is not int
                    or not 1 <= body["generation"] <= 2**53
                    or type(body["entries"]) is not dict or not 1 <= len(body["entries"]) <= MAX_FILES
                    or not isinstance(supplied, str) or not _DIGEST.fullmatch(supplied)
                    or not hmac.compare_digest(supplied, self._signature(body))):
                raise ValueError
            for identifier, entry in body["entries"].items():
                if type(entry) is not dict or set(entry) != {"path", "kind", "tools", "sha256", "size"}:
                    raise ValueError
                path = _path(entry["path"])
                if (not isinstance(entry["sha256"], str) or not _DIGEST.fullmatch(entry["sha256"])
                        or type(entry["size"]) is not int or not 0 <= entry["size"] <= MAX_FILE_BYTES
                        or entry["kind"] not in KINDS or type(entry["tools"]) is not list
                        or len(entry["tools"]) > 32 or len(set(entry["tools"])) != len(entry["tools"])
                        or any(not isinstance(tool, str) or (tool != "*" and not _TOOL.fullmatch(tool))
                               for tool in entry["tools"])
                        or identifier != hashlib.sha256(os.path.normcase(str(path)).encode()).hexdigest()):
                    raise ValueError
            if sum(entry["size"] for entry in body["entries"].values()) > MAX_TOTAL_BYTES:
                raise ValueError
            self._remember_head(body)
            return body
        except (TypeError, ValueError, KeyError, UnicodeError) as exc:
            raise AgentIntegrityError("Agent baseline authentication or schema failed") from exc

    @contextlib.contextmanager
    def _read(self):
        with _hold_plain_directories(self.root):
            marker_exists = os.path.lexists(self.marker)
            if not os.path.lexists(self.path):
                if marker_exists or self._was_configured:
                    raise AgentIntegrityError("Previously enrolled agent baseline is missing")
                yield None
                return
            self._was_configured = True
            if not marker_exists:
                raise AgentIntegrityError("Agent enrollment marker is missing")
            with _held_bytes(self.marker, 32) as marker:
                if marker != b"Agent file enrollment v1\n":
                    raise AgentIntegrityError("Agent enrollment marker is invalid")
            with _held_bytes(self.path, MAX_MANIFEST_BYTES) as raw:
                yield self._decode(raw)

    def enrolled(self):
        with self._read() as body:
            return [] if body is None else [dict(entry, target_id=identifier)
                                           for identifier, entry in body["entries"].items()]

    def enroll(self, observation, *, approved=False, replace=False):
        """Accept exactly the operator-reviewed bytes; drift requires replace=True."""
        if approved is not True or not isinstance(observation, AgentFileObservation):
            raise AgentIntegrityError("Explicit approval of an observed digest is required")
        with _LOCK, _hold_plain_directories(self.root):
            _ensure_directory(self.directory)
            with _hold_plain_directories(self.directory), _lease(self.directory):
                with self._read() as current:
                    body = ({"schema": 1, "generation": 0, "entries": {}}
                            if current is None else json.loads(json.dumps(current)))
                old = body["entries"].get(observation.target_id)
                if old is not None and not replace:
                    raise AgentIntegrityError("Existing enrollment requires explicit change acceptance")
                if old is None and replace:
                    raise AgentIntegrityError("Cannot accept changes to an unenrolled file")
                if old is None and len(body["entries"]) >= MAX_FILES:
                    raise AgentIntegrityError("Agent enrollment file limit reached")
                path = _path(observation.path)
                if path == self.root or self.root in path.parents:
                    raise AgentIntegrityError("Agent inputs must be outside Angerona runtime authority data")
                with _held_bytes(path, MAX_FILE_BYTES) as raw:
                    checked = observe_agent_file(path, observation.kind, observation.tools)
                    if checked != observation or hashlib.sha256(raw).hexdigest() != observation.sha256:
                        raise AgentIntegrityError("The reviewed agent bytes changed before acceptance")
                    body["generation"] += 1
                    body["entries"][observation.target_id] = dataclasses.asdict(observation)
                    if sum(entry["size"] for entry in body["entries"].values()) > MAX_TOTAL_BYTES:
                        raise AgentIntegrityError("Agent enrollment total byte limit reached")
                    payload = _canonical({"body": body, "hmac": self._signature(body)})
                    if len(payload) > MAX_MANIFEST_BYTES:
                        raise AgentIntegrityError("Agent enrollment manifest limit reached")
                    if not self.marker.exists():
                        _atomic_bytes_write(self.marker, b"Agent file enrollment v1\n", root=self.root)
                    _atomic_bytes_write(self.path, payload, root=self.root)
                    self._remember_head(body)
                self._was_configured = True
        return observation.target_id

    def accept_change(self, observation, *, approved=False):
        return self.enroll(observation, approved=approved, replace=True)

    @contextlib.contextmanager
    def guard_tool(self, tool, expected=None, *, mutation=False):
        """Bind previews to approved bytes; Windows alone can hold mutation custody."""
        if not isinstance(tool, str) or not _TOOL.fullmatch(tool):
            raise AgentIntegrityError("Invalid integrated tool identifier")
        with self._read() as body, contextlib.ExitStack() as stack:
            selected = [] if body is None else [
                (identifier, entry) for identifier, entry in body["entries"].items()
                if tool in entry["tools"] or "*" in entry["tools"]
            ]
            if selected and mutation and not _mutation_custody_available():
                raise AgentIntegrityError(
                    "Configured agent-file mutations require Windows handle custody; "
                    "this platform provides read-only, point-in-time drift observation"
                )
            fingerprint = ""
            for identifier, entry in sorted(selected):
                raw = stack.enter_context(_held_bytes(_path(entry["path"]), MAX_FILE_BYTES))
                if len(raw) != entry["size"] or hashlib.sha256(raw).hexdigest() != entry["sha256"]:
                    raise AgentIntegrityError("Configured agent instructions or tool definition changed; action withheld")
            if selected:
                fingerprint = hashlib.sha256(_canonical([body["generation"], selected])).hexdigest()
            if expected is not None and not hmac.compare_digest(expected, fingerprint):
                raise AgentIntegrityError("Agent baseline changed after preview; approval revoked")
            yield fingerprint

    def verify(self):
        """Bounded read-only inventory; report hashes and state, never file contents."""
        entries = self.enrolled()
        findings = []
        for entry in entries:
            status, observed = "approved", ""
            try:
                with _held_bytes(_path(entry["path"]), MAX_FILE_BYTES) as raw:
                    observed = hashlib.sha256(raw).hexdigest()
                    if observed != entry["sha256"] or len(raw) != entry["size"]:
                        status = "changed"
            except AgentIntegrityError:
                status = "unavailable"
            findings.append({"target_id": entry["target_id"], "kind": entry["kind"],
                             "status": status, "expected_sha256": entry["sha256"],
                             "observed_sha256": observed})
        return {"status": "unconfigured" if not entries else
                ("approved" if all(row["status"] == "approved" for row in findings) else "drift"),
                "files": findings}
