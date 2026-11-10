"""Private inherited Red Team transport. Messages never confer response authority.

Only framing is shared with inventory IPC. A distinct domain, strict closed
verbs, complete native-session binding and independent directional counters
prevent cross-protocol, replay and sibling-generation substitution.
"""
from __future__ import annotations

import array
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import socket
import threading
import time
from collections import deque

from angerona.telemetry.process_snapshot_worker import _receive, _send

PROTOCOL = "angerona-red-team-tool-v1"
DOMAIN = b"angerona-red-team-tool-v1\0"
MAX_FRAME = 2 * 1024 * 1024
MAX_ARTIFACT = 1024 * 1024
MAX_NODES = 40_000
VERIFICATION_SECONDS = 90.0
PRESENTATION_SECONDS = 15.0
WHOLE_STARTUP_SECONDS = VERIFICATION_SECONDS + PRESENTATION_SECONDS
STARTUP_PREFIX = b"ANGERONA_REDTEAM_STARTUP "
MAX_STARTUP_BYTES = 64 * 1024
MAX_STARTUP_LINES = 256
MAX_STARTUP_LINE = 512
MAX_STARTUP_RECORDS = 16
STARTUP_PHASES = frozenset({"entry", "source-pending-guard", "stdio", "bootstrap",
    "parent-binding", "source-seal", "hello", "initialize", "qt-ui"})
STARTUP_ERRORS = frozenset({"Exception", "EOFError", "OSError", "RuntimeError", "ValueError", "TypeError",
    "ImportError", "ModuleNotFoundError", "PermissionError", "InventoryWorkerError", "ToolProtocolError",
    "SourceGuardError", "SourceGuardTimeout", "SourceGuardCancelled", "EntryGuardHeld"})
_HEX = re.compile(r"[0-9a-f]{32}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_BIRTH = re.compile(r"(?:[1-9][0-9]{0,19}|0x[0-9a-f]+(?:\.[0-9a-f]+)?p[+-][0-9]+)\Z")
CHILD_KINDS = frozenset({"launch", "stop", "cancel", "readiness", "history-list", "history-read",
    "device-lab", "close", "reply", "marker-written", "probe-started", "probe-ended", "ui-ready"})
CORE_KINDS = frozenset({"initialize", "display", "narration", "readiness-result", "reply", "write-marker",
    "start-probe", "retire-probe", "close-ready", "show", "select-tab", "report"})


class ToolProtocolError(ValueError):
    """Unsupported or unauthenticated local protocol data; no execution fallback."""


def _startup_record(phase, status, error_type, elapsed_ms):
    if (type(phase) is not str or phase not in STARTUP_PHASES
            or type(status) is not str or status not in {"started", "completed", "failed"}
            or type(error_type) is not str
            or (error_type not in STARTUP_ERRORS if status == "failed" else error_type != "")
            or type(elapsed_ms) is not int or not 0 <= elapsed_ms <= int(WHOLE_STARTUP_SECONDS * 1000)):
        raise ToolProtocolError("Startup observation is outside its closed diagnostic schema")
    return dict(phase=phase, status=status, error_type=error_type, elapsed_ms=elapsed_ms)


def emit_startup_observation(phase, status, started, error=None):
    """Fixed advisory stderr only. Never write keys, protocol frames or paths."""
    kind = type(error).__name__ if error is not None else ""
    if status == "failed" and kind not in STARTUP_ERRORS:
        kind = "Exception"
    try:
        elapsed = min(int(WHOLE_STARTUP_SECONDS * 1000), max(0, int((time.monotonic() - started) * 1000)))
        raw = STARTUP_PREFIX + canonical(_startup_record(phase, status, kind, elapsed)) + b"\n"
        if len(raw) > MAX_STARTUP_LINE:
            return
        offset = 0
        while offset < len(raw):
            count = os.write(2, raw[offset:])
            if count <= 0:
                return
            offset += count
    except (OSError, RuntimeError, ValueError, TypeError, OverflowError):
        # Optional diagnostics cannot grant authority or replace the handshake.
        return


class ToolStartupObservations:
    """Finite raw input and fixed observations; all child claims are advisory."""
    def __init__(self):
        self._lock = threading.Lock()
        self._records = deque(maxlen=MAX_STARTUP_RECORDS)
        self._line = bytearray()
        self._discard_line = False
        self._bytes = self._lines = self._omitted_bytes = self._omitted_records = 0
        self._unrecognized = self._malformed = self._oversized = 0
        self._exhausted = False

    def feed(self, data, *, received_after_ms=0):
        if (type(data) is not bytes or type(received_after_ms) is not int
                or not 0 <= received_after_ms <= int(WHOLE_STARTUP_SECONDS * 1000)):
            raise ToolProtocolError("Startup diagnostic reader input is unavailable")
        with self._lock:
            remaining = max(0, MAX_STARTUP_BYTES - self._bytes)
            count = min(len(data), remaining)
            self._bytes += count
            self._omitted_bytes = min(2**31 - 1, self._omitted_bytes + len(data) - count)
            if len(data) > count:
                self._exhausted = True
            for value in memoryview(data)[:count]:
                if value == 10:
                    if self._lines >= MAX_STARTUP_LINES:
                        self._exhausted = True
                        self._line.clear()
                        break
                    self._lines += 1
                    if not self._discard_line:
                        self._consume_line(bytes(self._line), received_after_ms)
                    self._line.clear()
                    self._discard_line = False
                elif not self._discard_line:
                    if len(self._line) >= MAX_STARTUP_LINE:
                        self._oversized += 1
                        self._line.clear()
                        self._discard_line = True
                    else:
                        self._line.append(value)
            return not self._exhausted

    def _consume_line(self, line, received_after_ms):
        if not line.startswith(STARTUP_PREFIX):
            self._unrecognized += 1
            return
        try:
            def unique(pairs):
                values = {}
                for key, value in pairs:
                    if key in values:
                        raise ValueError("Duplicate diagnostic field")
                    values[key] = value
                return values
            value = json.loads(line[len(STARTUP_PREFIX):], object_pairs_hook=unique)
            if type(value) is not dict or set(value) != {"phase", "status", "error_type", "elapsed_ms"}:
                raise ValueError("Diagnostic fields differ")
            row = _startup_record(**value)
        except (UnicodeError, ValueError, TypeError):
            self._malformed += 1
            return
        if len(self._records) == MAX_STARTUP_RECORDS:
            self._omitted_records += 1
        self._records.append(dict(row, received_after_ms=received_after_ms))

    def snapshot(self):
        with self._lock:
            return dict(advisory_only=True, records=[dict(row) for row in self._records],
                raw_bytes=self._bytes, lines=self._lines, omitted_bytes=self._omitted_bytes,
                omitted_records=self._omitted_records, unrecognized_lines=self._unrecognized,
                malformed_lines=self._malformed, oversized_lines=self._oversized,
                partial_line=bool(self._line) or self._discard_line, exhausted=self._exhausted)


def _plain(value, *, depth=0, budget=None):
    if budget is None:
        budget = [MAX_NODES]
    budget[0] -= 1
    if budget[0] < 0 or depth > 24:
        raise ToolProtocolError("Tool payload structural bound exceeded")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if not -(1 << 63) <= value < (1 << 64):
            raise ToolProtocolError("Tool integer width exceeded")
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ToolProtocolError("Tool number must be finite")
        return
    if type(value) is str:
        if len(value) > MAX_ARTIFACT * 2:
            raise ToolProtocolError("Tool string bound exceeded")
        return
    if type(value) is list:
        if len(value) > 4096:
            raise ToolProtocolError("Tool sequence bound exceeded")
        for item in value:
            _plain(item, depth=depth + 1, budget=budget)
        return
    if type(value) is dict:
        if len(value) > 128 or any(type(key) is not str or len(key) > 128 for key in value):
            raise ToolProtocolError("Tool mapping schema unavailable")
        for item in value.values():
            _plain(item, depth=depth + 1, budget=budget)
        return
    raise ToolProtocolError("Tool payload requires plain JSON values")


def canonical(value):
    _plain(value)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    if not 0 < len(encoded) <= MAX_FRAME:
        raise ToolProtocolError("Tool frame byte bound exceeded")
    return encoded


def _pid(value):
    return type(value) is int and 1 <= value <= 0xffffffff


@dataclass(frozen=True)
class ToolBinding:
    session: str
    parent_pid: int
    parent_birth: str
    wrapper_pid: int
    wrapper_birth: str
    child_pid: int
    child_birth: str

    def __post_init__(self):
        if type(self.session) is not str or not _HEX.fullmatch(self.session):
            raise ToolProtocolError("Tool session identity unavailable")
        for pid, birth in ((self.parent_pid, self.parent_birth), (self.wrapper_pid, self.wrapper_birth),
                           (self.child_pid, self.child_birth)):
            if not _pid(pid) or type(birth) is not str or len(birth) > 64 or not _BIRTH.fullmatch(birth):
                raise ToolProtocolError("Tool native process generation unavailable")
        if self.parent_pid in {self.wrapper_pid, self.child_pid}:
            raise ToolProtocolError("Tool process ownership is contradictory")


def bootstrap(key, session, parent_pid, parent_birth, wrapper_pid, wrapper_birth, *,
              startup_deadline_ns, fd_channel=None):
    if type(key) is not bytes or len(key) != 32:
        raise ToolProtocolError("Tool ephemeral key unavailable")
    ToolBinding(session, parent_pid, parent_birth, wrapper_pid, wrapper_birth, wrapper_pid, wrapper_birth)
    if fd_channel is not None and (type(fd_channel) is not int or not 3 <= fd_channel < 1 << 20):
        raise ToolProtocolError("Inherited descriptor channel unavailable")
    if type(startup_deadline_ns) is not int or not 0 < startup_deadline_ns < 1 << 64:
        raise ToolProtocolError("Original startup monotonic deadline unavailable")
    return dict(protocol=PROTOCOL, kind="bootstrap", key=key.hex(), session=session,
        parent_pid=parent_pid, parent_birth=parent_birth, wrapper_pid=wrapper_pid,
        wrapper_birth=wrapper_birth, fd_channel=fd_channel, startup_deadline_ns=startup_deadline_ns)


def parse_bootstrap(value):
    fields = {"protocol", "kind", "key", "session", "parent_pid", "parent_birth", "wrapper_pid", "wrapper_birth", "fd_channel", "startup_deadline_ns"}
    if (type(value) is not dict or set(value) != fields or value.get("protocol") != PROTOCOL
            or value.get("kind") != "bootstrap" or type(value.get("key")) is not str
            or not _HASH.fullmatch(value["key"])):
        raise ToolProtocolError("Tool inherited bootstrap schema unavailable")
    verified = bootstrap(bytes.fromhex(value["key"]), value["session"], value["parent_pid"],
        value["parent_birth"], value["wrapper_pid"], value["wrapper_birth"], fd_channel=value["fd_channel"],
        startup_deadline_ns=value["startup_deadline_ns"])
    if canonical(verified) != canonical(value):
        raise ToolProtocolError("Tool inherited bootstrap mismatch")
    return verified


def seal_hello(binding, key):
    body = {"protocol": PROTOCOL, "kind": "hello", **asdict(binding)}
    return {"body": body, "mac": hmac.new(key, DOMAIN + b"hello\0" + canonical(body), hashlib.sha256).hexdigest()}


def open_hello(value, key, expected):
    if (type(value) is not dict or set(value) != {"body", "mac"} or type(value["body"]) is not dict
            or type(value["mac"]) is not str or not _HASH.fullmatch(value["mac"])):
        raise ToolProtocolError("Tool hello envelope unavailable")
    body = value["body"]
    if set(body) != {"protocol", "kind", *ToolBinding.__dataclass_fields__} or body["protocol"] != PROTOCOL or body["kind"] != "hello":
        raise ToolProtocolError("Tool hello schema unavailable")
    binding = ToolBinding(**{key: body[key] for key in ToolBinding.__dataclass_fields__})
    if any(type(body.get(name)) is not type(item) or body[name] != item for name, item in expected.items()):
        raise ToolProtocolError("Tool hello parent/session binding differs")
    if not hmac.compare_digest(value["mac"], seal_hello(binding, key)["mac"]):
        raise ToolProtocolError("Tool hello authentication failed")
    return binding


class ToolChannel:
    """One receive owner and a serialized sender; independent directional epochs."""

    def __init__(self, source, sink, binding, key, *, side, alive=lambda: True):
        if type(binding) is not ToolBinding or type(key) is not bytes or len(key) != 32 or side not in {"core", "child"}:
            raise ToolProtocolError("Tool channel admission unavailable")
        ToolBinding.__post_init__(binding)
        self.source, self.sink, self.binding = source, sink, binding
        self._key, self.side, self.alive = key, side, alive
        self._sent = self._received = 0
        self._send_lock, self._read_lock = threading.Lock(), threading.Lock()

    def send(self, kind, payload, *, reply_to=""):
        allowed = CORE_KINDS if self.side == "core" else CHILD_KINDS
        if kind not in allowed or type(payload) is not dict or type(reply_to) is not str or reply_to and not _HEX.fullmatch(reply_to):
            raise ToolProtocolError("Tool command is outside the closed direction")
        with self._send_lock:
            if self.alive() is not True:
                raise ToolProtocolError("Tool native generation unavailable")
            sequence = self._sent + 1
            body = dict(protocol=PROTOCOL, **asdict(self.binding), sequence=sequence,
                        nonce=secrets.token_hex(16), reply_to=reply_to, kind=kind, payload=payload)
            domain = b"core\0" if self.side == "core" else b"child\0"
            envelope = dict(body=body, mac=hmac.new(self._key, DOMAIN + domain + canonical(body), hashlib.sha256).hexdigest())
            _send(self.sink, envelope, MAX_FRAME)
            self._sent = sequence
            return body["nonce"]

    def receive(self):
        with self._read_lock:
            if self.alive() is not True:
                raise ToolProtocolError("Tool native generation unavailable")
            envelope = _receive(self.source, MAX_FRAME)
            if (type(envelope) is not dict or set(envelope) != {"body", "mac"} or type(envelope["body"]) is not dict
                    or type(envelope["mac"]) is not str or not _HASH.fullmatch(envelope["mac"])):
                raise ToolProtocolError("Tool envelope schema unavailable")
            body = envelope["body"]
            expected = {"protocol", *ToolBinding.__dataclass_fields__, "sequence", "nonce", "reply_to", "kind", "payload"}
            if (set(body) != expected or body["protocol"] != PROTOCOL
                    or any(type(body.get(name)) is not type(value) or body[name] != value for name, value in asdict(self.binding).items())
                    or type(body["sequence"]) is not int or body["sequence"] != self._received + 1
                    or type(body["nonce"]) is not str or not _HEX.fullmatch(body["nonce"])
                    or type(body["reply_to"]) is not str or body["reply_to"] and not _HEX.fullmatch(body["reply_to"])
                    or body["kind"] not in (CHILD_KINDS if self.side == "core" else CORE_KINDS)
                    or type(body["payload"]) is not dict):
                raise ToolProtocolError("Tool sequence, command or native-session binding differs")
            domain = b"child\0" if self.side == "core" else b"core\0"
            digest = hmac.new(self._key, DOMAIN + domain + canonical(body), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(envelope["mac"], digest) or self.alive() is not True:
                raise ToolProtocolError("Tool authentication or native lifetime unavailable")
            self._received = body["sequence"]
            return body


def send_descriptor(channel, descriptor, nonce):
    """One inherited Unix socketpair endpoint, never a pathname or public socket."""
    if os.name == "nt" or type(nonce) is not str or not _HEX.fullmatch(nonce) or type(descriptor) is not int or descriptor < 0:
        raise ToolProtocolError("Descriptor transfer unavailable")
    rights = array.array("i", [descriptor])
    if channel.sendmsg([nonce.encode("ascii")], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)]) != 32:
        raise ToolProtocolError("Descriptor transfer incomplete")


def receive_descriptor(channel, nonce):
    if os.name == "nt" or type(nonce) is not str or not _HEX.fullmatch(nonce):
        raise ToolProtocolError("Descriptor transfer unavailable")
    integers = array.array("i")
    data, ancillary, flags, _address = channel.recvmsg(33, socket.CMSG_SPACE(integers.itemsize * 2))
    received = []
    try:
        unsupported = False
        for level, kind, raw in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                unsupported = True
                continue
            values = array.array("i")
            usable = len(raw) - len(raw) % integers.itemsize
            values.frombytes(raw[:usable])
            received.extend(values)
            unsupported |= usable != len(raw)
        if unsupported:
            raise ToolProtocolError("Unsupported descriptor transfer")
        if flags & (getattr(socket, "MSG_TRUNC", 0) | getattr(socket, "MSG_CTRUNC", 0)) or data != nonce.encode("ascii") or len(received) != 1:
            raise ToolProtocolError("Descriptor transfer binding differs")
        descriptor = received[0]
        os.set_inheritable(descriptor, False)
        received.pop()
        return descriptor
    finally:
        for descriptor in received:
            os.close(descriptor)
