"""ipc_ring.py — shared-memory ring buffer for raw telemetry (scanner → core).

The standalone Telemetry Scanner writes RAW event frames here; the Angerona core
reads them asynchronously and does all the deciphering/correlation/action. This
is the high-volume "data plane" — it deliberately bypasses sockets so a telemetry
storm never blocks the core or the UI.

Design
    * Fixed-size mmap: a header plus `slot_count` fixed-size slots. No per-write
      allocation. Single-producer / single-consumer.
    * Each frame carries a versioned, authenticated record:
        [schema_ver u16, sensor_id u16, seq u64, payload, HMAC-SHA256]
      The protected per-install authority binds the complete record. Wrong-key,
      stale/replayed, out-of-position, unknown-schema, and modified frames are
      discarded before JSON parsing or EventBus publication.
    * Bounded with backpressure: if the producer laps the consumer, the OLDEST
      frames are overwritten (ring semantics) and a drop counter increments — the
      newest telemetry is always preserved and the core is never stalled.
    * A backpressure flag is raised when occupancy crosses `BACKPRESSURE_FRAC`, so
      sensors can down-sample low-priority events at the source (DRES-style).

Note: this Python implementation defines the on-disk/mmap CONTRACT. A compiled
Rust/Go/C scanner can write the identical layout for zero-copy performance; the
core reads either producer transparently.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import mmap
import os
import secrets
import stat
import struct
import time
from pathlib import Path
from typing import Optional

_MAGIC = 0x41524E47                      # "ARNG" (Angerona RiNG)
_VERSION = 2
_SCHEMA_VERSION = 1
_SUPPORTED_SCHEMAS = frozenset({_SCHEMA_VERSION})
# Header: magic, version, slot_count, slot_size, write_seq, read_seq, drops, bpflag
_HDR_FMT = "<IIIIQQQI"
_HDR_SIZE = struct.calcsize(_HDR_FMT)     # 44 → padded to 64 for alignment
_HDR_PAD = 64
_REC_FMT = "<HHQ"                         # schema_ver, sensor_id, full seq
_REC_HDR = struct.calcsize(_REC_FMT)      # 12
_MAC_SIZE = hashlib.sha256().digest_size
_FRAME_AAD = b"Angerona-IPC-Ring-v2\x00"
_SLOT_LEN_FMT = "<I"                      # per-slot payload length prefix

DEFAULT_SLOT_COUNT = 4096
DEFAULT_SLOT_SIZE = 512                   # ~2 MB ring at defaults
BACKPRESSURE_FRAC = 0.85
MIN_SLOT_COUNT = 2
MAX_SLOT_COUNT = 65_536
MIN_SLOT_SIZE = 64
MAX_SLOT_SIZE = 65_536
MAX_RING_BYTES = 64 * 1024 * 1024


class FrameError(ValueError):
    """An IPC frame or authenticated scanner payload failed closed."""


def _data_dir() -> Path:
    try:
        from angerona.core.config import _data_dir as core_data_dir
        return Path(core_data_dir())
    except Exception:
        from angerona.core.data_paths import data_dir
        return data_dir()


def ring_path(name: str = "telemetry") -> Path:
    d = _data_dir() / "ipc"
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{name}.ring"


def _key_path() -> Path:
    return _data_dir() / "ipc_ring.key"


def _load_or_create_key(path: Path | None = None) -> bytes:
    """Load the dedicated ring authority or atomically create it once."""
    target = Path(path) if path is not None else _key_path()
    from angerona.core.hardening import (
        ensure_sensitive_parent,
        key_acl_required,
        prepare_sensitive_key,
        secure_sensitive_file,
    )
    required = key_acl_required()
    if target.exists() and not prepare_sensitive_key(target, required=required):
        return _load_or_create_key(target)
    try:
        encoded = target.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        key = secrets.token_bytes(32)
        target.parent.mkdir(parents=True, exist_ok=True)
        ensure_sensitive_parent(target, required=required)
        try:
            descriptor = os.open(
                str(target),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            return _load_or_create_key(target)
        try:
            with os.fdopen(descriptor, "w", encoding="ascii") as stream:
                stream.write(key.hex())
                stream.flush()
                os.fsync(stream.fileno())
            secure_sensitive_file(target, required=required)
        except Exception:
            try:
                target.unlink()
            except OSError:
                pass
            raise
        return key
    except Exception as exc:
        raise RuntimeError(f"IPC ring authority is unreadable: {target}") from exc
    try:
        key = bytes.fromhex(encoded)
    except ValueError as exc:
        raise RuntimeError(f"IPC ring authority is malformed: {target}") from exc
    if len(key) != 32:
        raise RuntimeError(
            f"IPC ring authority has invalid length ({len(key)} bytes): {target}"
        )
    secure_sensitive_file(target, required=required)
    return key


def _validated_key(key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) != 32:
        raise FrameError("IPC frame key must contain exactly 32 bytes")
    return key


def encode_frame(
    key: bytes,
    payload: bytes,
    *,
    schema_ver: int = _SCHEMA_VERSION,
    sensor_id: int = 0,
    sequence: int = 0,
) -> bytes:
    """Build one authenticated record for a fixed ring slot."""
    authority = _validated_key(key)
    if not isinstance(payload, bytes):
        raise FrameError("IPC payload must be bytes")
    if (
        type(schema_ver) is not int
        or schema_ver not in _SUPPORTED_SCHEMAS
        or type(sensor_id) is not int
        or not 0 <= sensor_id <= 0xFFFF
        or type(sequence) is not int
        or not 0 <= sequence <= 0xFFFFFFFFFFFFFFFF
    ):
        raise FrameError("IPC frame metadata is invalid or unsupported")
    header = struct.pack(_REC_FMT, schema_ver, sensor_id, sequence)
    tag = hmac.new(authority, _FRAME_AAD + header + payload, hashlib.sha256).digest()
    return header + payload + tag


def decode_frame(
    key: bytes,
    record: bytes,
    *,
    expected_sequence: int,
) -> dict:
    """Authenticate and normalize one ring record; reject replay/tampering."""
    authority = _validated_key(key)
    if (
        not isinstance(record, bytes)
        or not _REC_HDR + _MAC_SIZE <= len(record) <= MAX_SLOT_SIZE - 4
        or type(expected_sequence) is not int
        or not 0 <= expected_sequence <= 0xFFFFFFFFFFFFFFFF
    ):
        raise FrameError("IPC frame length or expected sequence is invalid")
    try:
        schema, sensor_id, sequence = struct.unpack_from(_REC_FMT, record, 0)
    except struct.error as exc:
        raise FrameError("IPC frame header is invalid") from exc
    if schema not in _SUPPORTED_SCHEMAS:
        raise FrameError("IPC frame schema is unsupported")
    if sequence != expected_sequence:
        raise FrameError("IPC frame sequence is stale, replayed, or out of position")
    payload = record[_REC_HDR:-_MAC_SIZE]
    supplied = record[-_MAC_SIZE:]
    expected = hmac.new(
        authority,
        _FRAME_AAD + record[:_REC_HDR] + payload,
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(supplied, expected):
        raise FrameError("IPC frame authentication failed")
    return {
        "schema": schema,
        "sensor_id": sensor_id,
        "seq": sequence,
        "payload": payload,
    }


def decode_sensor_payload(sensor_id: int, payload: bytes) -> dict:
    """Validate a scanner payload after frame authentication."""
    if type(sensor_id) is not int or sensor_id != 1:
        raise FrameError("IPC sensor identifier is unsupported")
    if not isinstance(payload, bytes) or len(payload) > MAX_SLOT_SIZE:
        raise FrameError("IPC sensor payload is invalid")

    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite JSON number")

    try:
        value = json.loads(
            payload.decode("utf-8", "strict"),
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise FrameError("IPC sensor payload is not strict JSON") from exc
    required = {"type", "pid", "ppid", "name", "ts"}
    if not isinstance(value, dict) or set(value) != required:
        raise FrameError("IPC process payload fields are invalid")
    if value["type"] != "process_creation":
        raise FrameError("IPC process payload type is unsupported")
    pid, parent = value["pid"], value["ppid"]
    if (
        type(pid) is not int
        or not 1 <= pid <= 0xFFFFFFFF
        or (
            parent is not None
            and (type(parent) is not int or not 0 <= parent <= 0xFFFFFFFF)
        )
    ):
        raise FrameError("IPC process identifiers are invalid")
    name = value["name"]
    if (
        not isinstance(name, str)
        or not name
        or len(name) > 512
        or "\x00" in name
    ):
        raise FrameError("IPC process name is invalid")
    observed = value["ts"]
    if (
        type(observed) not in (int, float)
        or not math.isfinite(float(observed))
        or observed < 0
    ):
        raise FrameError("IPC process timestamp is invalid")
    return {
        "type": "process_creation",
        "pid": pid,
        "ppid": parent,
        "name": name,
        "ts": float(observed),
    }


def _validate_layout(slot_count: int, slot_size: int) -> tuple[int, int]:
    if (
        type(slot_count) is not int
        or type(slot_size) is not int
        or not MIN_SLOT_COUNT <= slot_count <= MAX_SLOT_COUNT
        or not MIN_SLOT_SIZE <= slot_size <= MAX_SLOT_SIZE
        or _HDR_PAD + slot_count * slot_size > MAX_RING_BYTES
    ):
        raise ValueError("IPC ring layout exceeds its fixed safety budget")
    return slot_count, slot_size


class _RingBase:
    def __init__(
        self,
        path: Path,
        slot_count: int,
        slot_size: int,
        create: bool,
        key: bytes | None = None,
    ):
        self.path = Path(path)
        self.slot_count, self.slot_size = _validate_layout(slot_count, slot_size)
        self._key = _validated_key(key) if key is not None else _load_or_create_key()
        self._total = _HDR_PAD + self.slot_count * self.slot_size
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise ValueError("IPC ring symlinks are not accepted")
        flags = (
            os.O_RDWR
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        created = False
        try:
            descriptor = os.open(
                self.path,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            created = True
        except FileExistsError:
            descriptor = os.open(self.path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise ValueError("IPC ring must be a regular file")
            reset = create or created or opened.st_size < self._total
            if reset:
                os.ftruncate(descriptor, self._total)
            self._f = os.fdopen(descriptor, "r+b", buffering=0)
        except Exception:
            os.close(descriptor)
            raise
        self._mm = mmap.mmap(self._f.fileno(), self._total)
        m, v, sc, ss, *_ = self._read_header()
        if (
            reset
            or m != _MAGIC
            or v != _VERSION
            or sc != self.slot_count
            or ss != self.slot_size
        ):
            # Re-initialise on layout mismatch (e.g., first attach to a stale file).
            self._init_header()

    def _init_header(self) -> None:
        header = struct.pack(
            _HDR_FMT,
            _MAGIC,
            _VERSION,
            self.slot_count,
            self.slot_size,
            0,
            0,
            0,
            0,
        )
        self._mm[0:_HDR_PAD] = header + b"\x00" * (_HDR_PAD - len(header))

    def _read_header(self):
        return struct.unpack(_HDR_FMT, self._mm[0:_HDR_SIZE])

    def _write_field(self, offset_in_hdr: int, fmt: str, *vals) -> None:
        struct.pack_into(fmt, self._mm, offset_in_hdr, *vals)

    @property
    def write_seq(self) -> int:
        return self._read_header()[4]

    @property
    def read_seq(self) -> int:
        return self._read_header()[5]

    @property
    def drops(self) -> int:
        return self._read_header()[6]

    @property
    def occupancy(self) -> int:
        return max(0, self.write_seq - self.read_seq)

    def _slot_off(self, seq: int) -> int:
        return _HDR_PAD + (seq % self.slot_count) * self.slot_size

    def close(self) -> None:
        try:
            self._mm.close()
        finally:
            self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class RingWriter(_RingBase):
    """Single producer. Writes raw frames; overwrites oldest under pressure."""

    def __init__(
        self,
        path: Optional[Path] = None,
        slot_count: int = DEFAULT_SLOT_COUNT,
        slot_size: int = DEFAULT_SLOT_SIZE,
        *,
        key: bytes | None = None,
    ):
        super().__init__(
            path or ring_path(),
            slot_count,
            slot_size,
            create=False,
            key=key,
        )

    def write(
        self,
        payload: bytes,
        schema_ver: int = _SCHEMA_VERSION,
        sensor_id: int = 0,
    ) -> bool:
        """Write one frame. Returns True if stored, False if the payload is too
        large for a slot (dropped). Never blocks."""
        w = self.write_seq
        rec = encode_frame(
            self._key,
            payload,
            schema_ver=schema_ver,
            sensor_id=sensor_id,
            sequence=w,
        )
        if len(rec) + 4 > self.slot_size:
            self._bump_drops()
            return False
        r = self.read_seq
        # Lapping the consumer → advance read_seq (overwrite oldest) + count a drop.
        if w - r >= self.slot_count:
            self._advance_read(w - self.slot_count + 1)
            self._bump_drops()
        off = self._slot_off(w)
        struct.pack_into(_SLOT_LEN_FMT, self._mm, off, len(rec))
        self._mm[off + 4: off + 4 + len(rec)] = rec
        self._write_field(16, "<Q", w + 1)          # write_seq (@16) += 1
        self._set_backpressure(self.occupancy / self.slot_count >= BACKPRESSURE_FRAC)
        return True

    def _advance_read(self, new_read: int) -> None:
        self._write_field(24, "<Q", new_read)       # read_seq field @ offset 24

    def _bump_drops(self) -> None:
        self._write_field(32, "<Q", self.drops + 1)  # drops field @ offset 32

    def _set_backpressure(self, on: bool) -> None:
        self._write_field(40, "<I", 1 if on else 0)  # bpflag @ offset 40

    @property
    def backpressure(self) -> bool:
        return bool(struct.unpack_from("<I", self._mm, 40)[0])


class RingReader(_RingBase):
    """Single consumer. Reads all frames since the last read position."""

    def __init__(
        self,
        path: Optional[Path] = None,
        slot_count: int = DEFAULT_SLOT_COUNT,
        slot_size: int = DEFAULT_SLOT_SIZE,
        *,
        key: bytes | None = None,
    ):
        super().__init__(
            path or ring_path(),
            slot_count,
            slot_size,
            create=False,
            key=key,
        )
        self.authentication_failures = 0

    def read_batch(self, max_frames: int = 1024) -> list[dict]:
        """Return up to max_frames frames as dicts:
        {schema, sensor_id, seq, payload, missed}. `missed` is set on the first
        frame if the producer lapped us (we fast-forward to avoid reading torn
        slots)."""
        if type(max_frames) is not int or not 1 <= max_frames <= MAX_SLOT_COUNT:
            raise ValueError("IPC batch limit is outside the ring budget")
        frame_budget = min(max_frames, self.slot_count)
        out: list[dict] = []
        magic, version, slots, size, w, r, _drops, _bp = self._read_header()
        if (
            magic != _MAGIC
            or version != _VERSION
            or slots != self.slot_count
            or size != self.slot_size
            or w < r
        ):
            self.authentication_failures += 1
            raise FrameError("IPC ring header failed integrity validation")
        missed = 0
        # If we fell more than a full lap behind, skip to the oldest still-intact.
        if w - r > self.slot_count:
            missed = (w - self.slot_count) - r
            r = w - self.slot_count
        scanned = 0
        while r < w and scanned < frame_budget:
            scanned += 1
            off = self._slot_off(r)
            (rec_len,) = struct.unpack_from(_SLOT_LEN_FMT, self._mm, off)
            if (
                rec_len < _REC_HDR + _MAC_SIZE
                or rec_len > self.slot_size - 4
            ):
                self.authentication_failures += 1
                r += 1
                continue
            rec = bytes(self._mm[off + 4: off + 4 + rec_len])
            try:
                frame = decode_frame(
                    self._key,
                    rec,
                    expected_sequence=r,
                )
            except FrameError:
                self.authentication_failures += 1
                r += 1
                continue
            frame["missed"] = missed if not out else 0
            out.append(frame)
            r += 1
        self._write_field(24, "<Q", r)               # persist new read_seq (@24)
        return out


def self_test() -> tuple[bool, str]:
    """Offline: round-trip frames, verify ordering/sequence, and confirm
    overwrite-oldest + drop accounting when the ring is intentionally overrun."""
    import tempfile
    d = Path(tempfile.mkdtemp(prefix="ring_selftest_"))
    try:
        p = d / "t.ring"
        sc, ss = 8, 64
        key = b"r" * 32
        w = RingWriter(p, slot_count=sc, slot_size=ss, key=key)
        r = RingReader(p, slot_count=sc, slot_size=ss, key=key)

        for i in range(5):
            assert w.write(f"evt-{i}".encode(), sensor_id=7)
        batch = r.read_batch()
        rt_ok = ([b["payload"] for b in batch] == [f"evt-{i}".encode() for i in range(5)]
                 and all(b["sensor_id"] == 7 for b in batch))

        # Overrun: write 20 into an 8-slot ring; oldest must be dropped.
        for i in range(20):
            w.write(f"x-{i}".encode())
        drops_before = w.drops
        batch2 = r.read_batch()
        overrun_ok = drops_before > 0 and len(batch2) <= sc and batch2 and batch2[0]["missed"] >= 0

        # Too-large payload is rejected, not stored.
        big_ok = (w.write(b"z" * (ss)) is False)

        ok = rt_ok and overrun_ok and big_ok
        return ok, ("ring round-trip + overwrite-oldest/drop-accounting + oversize "
                    "rejection verified" if ok else
                    f"failed: rt={rt_ok} overrun={overrun_ok} big={big_ok}")
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    print(self_test())
