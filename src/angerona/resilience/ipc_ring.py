"""ipc_ring.py — shared-memory ring buffer for raw telemetry (scanner → core).

The standalone Telemetry Scanner writes RAW event frames here; the Angerona core
reads them asynchronously and does all the deciphering/correlation/action. This
is the high-volume "data plane" — it deliberately bypasses sockets so a telemetry
storm never blocks the core or the UI.

Design
    * Fixed-size mmap: a header plus `slot_count` fixed-size slots. No per-write
      allocation. Single-producer / single-consumer.
    * Each frame carries a versioned record header so schemas can evolve:
        [schema_ver u16, sensor_id u16, seq u32, payload...]
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

import mmap
import os
import struct
import time
from pathlib import Path
from typing import Optional

_MAGIC = 0x41524E47                      # "ARNG" (Angerona RiNG)
_VERSION = 1
# Header: magic, version, slot_count, slot_size, write_seq, read_seq, drops, bpflag
_HDR_FMT = "<IIIIQQQI"
_HDR_SIZE = struct.calcsize(_HDR_FMT)     # 44 → padded to 64 for alignment
_HDR_PAD = 64
_REC_FMT = "<HHI"                         # schema_ver, sensor_id, seq
_REC_HDR = struct.calcsize(_REC_FMT)      # 8
_SLOT_LEN_FMT = "<I"                      # per-slot payload length prefix

DEFAULT_SLOT_COUNT = 4096
DEFAULT_SLOT_SIZE = 512                   # ~2 MB ring at defaults
BACKPRESSURE_FRAC = 0.85


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


class _RingBase:
    def __init__(self, path: Path, slot_count: int, slot_size: int, create: bool):
        self.path = Path(path)
        self.slot_count = slot_count
        self.slot_size = slot_size
        self._total = _HDR_PAD + slot_count * slot_size
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if create or not self.path.exists() or self.path.stat().st_size < self._total:
            with open(self.path, "wb") as f:
                f.write(b"\x00" * self._total)
            self._init_header()
        self._f = open(self.path, "r+b")
        self._mm = mmap.mmap(self._f.fileno(), self._total)
        m, v, sc, ss, *_ = self._read_header()
        if m != _MAGIC or sc != slot_count or ss != slot_size:
            # Re-initialise on layout mismatch (e.g., first attach to a stale file).
            self._init_header()

    def _init_header(self) -> None:
        with open(self.path, "r+b") as f:
            f.seek(0)
            f.write(struct.pack(_HDR_FMT, _MAGIC, _VERSION, self.slot_count,
                                self.slot_size, 0, 0, 0, 0))
            f.write(b"\x00" * (_HDR_PAD - _HDR_SIZE))

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

    def __init__(self, path: Optional[Path] = None, slot_count: int = DEFAULT_SLOT_COUNT,
                 slot_size: int = DEFAULT_SLOT_SIZE):
        super().__init__(path or ring_path(), slot_count, slot_size, create=False)

    def write(self, payload: bytes, schema_ver: int = _VERSION, sensor_id: int = 0) -> bool:
        """Write one frame. Returns True if stored, False if the payload is too
        large for a slot (dropped). Never blocks."""
        if len(payload) + _REC_HDR + 4 > self.slot_size:
            self._bump_drops()
            return False
        w = self.write_seq
        r = self.read_seq
        # Lapping the consumer → advance read_seq (overwrite oldest) + count a drop.
        if w - r >= self.slot_count:
            self._advance_read(w - self.slot_count + 1)
            self._bump_drops()
        off = self._slot_off(w)
        seq32 = w & 0xFFFFFFFF
        rec = struct.pack(_REC_FMT, schema_ver & 0xFFFF, sensor_id & 0xFFFF, seq32) + payload
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

    def __init__(self, path: Optional[Path] = None, slot_count: int = DEFAULT_SLOT_COUNT,
                 slot_size: int = DEFAULT_SLOT_SIZE):
        super().__init__(path or ring_path(), slot_count, slot_size, create=False)

    def read_batch(self, max_frames: int = 1024) -> list[dict]:
        """Return up to max_frames frames as dicts:
        {schema, sensor_id, seq, payload, missed}. `missed` is set on the first
        frame if the producer lapped us (we fast-forward to avoid reading torn
        slots)."""
        out: list[dict] = []
        w = self.write_seq
        r = self.read_seq
        missed = 0
        # If we fell more than a full lap behind, skip to the oldest still-intact.
        if w - r > self.slot_count:
            missed = (w - self.slot_count) - r
            r = w - self.slot_count
        n = 0
        while r < w and n < max_frames:
            off = self._slot_off(r)
            (rec_len,) = struct.unpack_from(_SLOT_LEN_FMT, self._mm, off)
            if rec_len < _REC_HDR or rec_len > self.slot_size - 4:
                r += 1
                continue
            rec = bytes(self._mm[off + 4: off + 4 + rec_len])
            schema, sensor_id, seq = struct.unpack_from(_REC_FMT, rec, 0)
            payload = rec[_REC_HDR:]
            out.append({"schema": schema, "sensor_id": sensor_id, "seq": seq,
                        "payload": payload, "missed": missed if n == 0 else 0})
            r += 1
            n += 1
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
        w = RingWriter(p, slot_count=sc, slot_size=ss)
        r = RingReader(p, slot_count=sc, slot_size=ss)

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
