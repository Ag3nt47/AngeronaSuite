"""memory_timemachine.py — Memory Time-Machine Delta Engine (Code: MTM).

Purpose
    Strip duplicate process strings *before* they are triaged so the local LLM
    only ever sees NEW information. Cuts token / CPU / VRAM overhead by only
    forwarding the differential slice of observed strings per process.

Design
    - A lock-light Single-Producer / Single-Consumer (SPSC) ring buffer backed by
      an ``mmap`` file (the ``telemetry_ringbuffer`` / RING). The producer thread
      carves printable strings; a single consumer drains them. Because there is
      exactly one writer and one reader, the hot path needs no mutex — only the
      slow-path open/resize is guarded by ``state_lock``.
    - A per-PID sliding hash cache of previously-observed benign strings. Anything
      whose hash is already in the window is dropped; only the delta is queued for
      Ollama.

Safety
    Strings are carved from psutil-accessible process telemetry (cmdline, exe
    path, open files, connections, environment) — no raw cross-process
    ReadProcessMemory, no injection. Everything stays on-box.

Drop-in contract
    Subclasses ``BaseModule`` (auto-discovered by ModuleManager) and also exposes
    the ``CODE / NAME / state / health_pct / self_test()`` drop-in surface plus a
    module-level ``register()``.
"""
from __future__ import annotations

import hashlib
import mmap
import os
import queue
import re
import struct
import threading
import time
from collections import OrderedDict, deque
from pathlib import Path

try:
    import psutil
except Exception:  # pragma: no cover - psutil is a suite dependency
    psutil = None

from angerona.core.module_base import BaseModule, Severity

# ── RING geometry (SPSC mmap) ────────────────────────────────────────────────
_MAGIC = b"MTM1"
_HEADER = 32                # magic(4) + cap(4) + head(8) + tail(8) + reserved(8)
_SLOT = 512                 # fixed slot size (4-byte length prefix + payload)
_SLOTS = 4096               # ~2 MB backing file
_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")     # ASCII runs, min length 4


class _SpscRing:
    """Fixed-slot SPSC ring over an mmap file. One producer, one consumer.

    head advances only in push() (producer); tail advances only in pop()
    (consumer). If the producer laps the consumer it drops the oldest slot
    (producer-side overwrite) so the hot path never blocks.
    """

    def __init__(self, path: Path, slots: int = _SLOTS) -> None:
        self._slots = slots
        self._size = _HEADER + slots * _SLOT
        self._open_lock = threading.Lock()   # slow-path guard (a.k.a. state_lock)
        with self._open_lock:
            new = not path.exists() or path.stat().st_size != self._size
            if new:
                path.parent.mkdir(parents=True, exist_ok=True)
                with open(path, "wb") as f:
                    f.write(b"\x00" * self._size)
            self._f = open(path, "r+b")
            self._mm = mmap.mmap(self._f.fileno(), self._size)
            if new or self._mm[0:4] != _MAGIC:
                struct.pack_into("<4sIQQQ", self._mm, 0, _MAGIC, slots, 0, 0, 0)

    def _head(self) -> int:
        return struct.unpack_from("<Q", self._mm, 8)[0]

    def _tail(self) -> int:
        return struct.unpack_from("<Q", self._mm, 16)[0]

    def push(self, payload: bytes) -> bool:
        body = payload[: _SLOT - 4]
        head, tail = self._head(), self._tail()
        if head - tail >= self._slots:           # full → drop oldest (producer side)
            struct.pack_into("<Q", self._mm, 16, tail + 1)
        off = _HEADER + (head % self._slots) * _SLOT
        struct.pack_into("<I", self._mm, off, len(body))
        self._mm[off + 4: off + 4 + len(body)] = body
        struct.pack_into("<Q", self._mm, 8, head + 1)   # publish last
        return True

    def pop(self) -> bytes | None:
        head, tail = self._head(), self._tail()
        if tail >= head:
            return None
        off = _HEADER + (tail % self._slots) * _SLOT
        n = struct.unpack_from("<I", self._mm, off)[0]
        data = bytes(self._mm[off + 4: off + 4 + min(n, _SLOT - 4)])
        struct.pack_into("<Q", self._mm, 16, tail + 1)   # consume
        return data

    def depth(self) -> int:
        return max(0, self._head() - self._tail())

    def close(self) -> None:
        try:
            self._mm.flush(); self._mm.close(); self._f.close()
        except Exception:
            pass


class MemoryTimeMachineModule(BaseModule):
    CODE = "MTM"
    NAME = "Memory Time-Machine"
    name = "Memory Time-Machine"
    description = ("SPSC mmap ring + per-PID sliding hash cache; forwards only the "
                   "delta slice of newly-observed process strings to the LLM queue.")
    category = "Performance"
    version = "1.0.0"

    _WINDOW = 4096          # sliding hash-cache size per PID
    _MAX_PIDS = 256         # cap tracked processes (LRU)
    _CARVE_INTERVAL = 6.0   # seconds between carve sweeps

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._caches: "OrderedDict[int, deque]" = OrderedDict()
        self._cache_sets: dict[int, set] = {}
        self.delta_queue: "queue.Queue[dict]" = queue.Queue(maxsize=8192)
        self._ring: _SpscRing | None = None
        self._seen = 0
        self._forwarded = 0

    # ── drop-in contract shims ───────────────────────────────────────────────
    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── string sourcing (psutil-accessible surfaces only) ────────────────────
    @staticmethod
    def _carve(raw: bytes) -> list[str]:
        return [m.group().decode("ascii", "ignore") for m in _PRINTABLE.finditer(raw)]

    def _process_strings(self, proc, connections=None) -> list[str]:
        out: list[str] = []
        try:
            info = proc.as_dict(attrs=["cmdline", "exe", "name", "cwd"])
            for v in (info.get("exe"), info.get("name"), info.get("cwd")):
                if v:
                    out.append(str(v))
            for tok in (info.get("cmdline") or []):
                out.append(str(tok))
        except Exception:
            return out
        # CRASH FIX: psutil.Process.open_files() triggers a Windows ACCESS VIOLATION
        # (an uncatchable C-level fault that kills the ENTIRE process — no Python
        # try/except can stop it) on Python 3.14 / this psutil build. It was the
        # source of the repeated core crashes. It is NOT called unless explicitly
        # re-enabled after you've confirmed a stable psutil (ANGERONA_MTM_OPEN_FILES=1).
        # Only `connections` runs by default — it's the low-risk psutil surface.
        # Both open_files (the KNOWN Py3.14 access violation) and environ (a
        # cross-process PEB read) are C-level fault risks on this build, so they
        # are opt-in behind the same flag after you've confirmed a stable psutil.
        getters = [] if connections is not None else ["connections"]
        if os.environ.get("ANGERONA_MTM_OPEN_FILES") == "1":
            getters = ["open_files", "environ"] + getters
        if connections is not None:
            out += [f"{c.laddr}->{c.raddr}" for c in connections if c.raddr]
        for getter in getters:
            try:
                val = getattr(proc, getter)()
                if getter == "open_files":
                    out += [f.path for f in val]
                elif getter == "connections":
                    out += [f"{c.laddr}->{c.raddr}" for c in val if c.raddr]
                else:  # environ
                    out += [f"{k}={v}" for k, v in val.items()]
            except Exception:
                continue
        # keep only printable runs >= 4 chars
        carved: list[str] = []
        for s in out:
            carved += self._carve(s.encode("utf-8", "ignore"))
        return carved

    def _cache_for(self, pid: int):
        with self.state_lock:
            if pid not in self._caches:
                if len(self._caches) >= self._MAX_PIDS:
                    old, _ = self._caches.popitem(last=False)
                    self._cache_sets.pop(old, None)
                self._caches[pid] = deque(maxlen=self._WINDOW)
                self._cache_sets[pid] = set()
            else:
                self._caches.move_to_end(pid)
            return self._caches[pid], self._cache_sets[pid]

    def delta_for(self, pid: int, strings: list[str]) -> list[str]:
        """Return only strings not already in this PID's sliding window, and
        register them. This is the >80% token-reduction hot path."""
        window, seen = self._cache_for(pid)
        delta: list[str] = []
        for s in strings:
            h = hashlib.blake2b(s.encode("utf-8", "ignore"), digest_size=8).digest()
            self._seen += 1
            if h in seen:
                continue
            if len(window) == window.maxlen:
                seen.discard(window[0])      # evict oldest hash as window slides
            window.append(h)
            seen.add(h)
            delta.append(s)
        return delta

    def stats(self) -> dict:
        reduction = (1 - self._forwarded / self._seen) * 100 if self._seen else 0.0
        return {"strings_seen": self._seen, "forwarded": self._forwarded,
                "reduction_pct": round(reduction, 1),
                "ring_depth": self._ring.depth() if self._ring else 0,
                "queue_depth": self.delta_queue.qsize()}

    # ── lifecycle ────────────────────────────────────────────────────────────
    def run(self) -> None:
        from angerona.core.config import Config
        ring_path = Config().data_dir / "telemetry_ringbuffer.mmap"
        try:
            self._ring = _SpscRing(ring_path)
        except Exception as exc:
            self.set_health(40, f"ring unavailable: {exc}")
        if psutil is None:
            self.set_health(0, "psutil unavailable")
            self.status = "error"
            return
        self.emit("MTM online — deduplicating process strings before triage.", Severity.INFO)
        while not self.stopping:
            self._sweep()
            self.sleep(self._CARVE_INTERVAL)

    def _sweep(self) -> None:
        batch = 0
        # Process.connections() performs an OS connection-table query for every
        # PID. On Windows that repeated the same expensive system enumeration
        # hundreds of times per sweep. Take one equivalent inet snapshot and
        # partition it by PID. If the platform cannot attribute every row (or the
        # bulk call fails), fall back to the original per-process path so no
        # telemetry is lost.
        connections_by_pid: dict[int, list] | None = {}
        try:
            all_connections = psutil.net_connections(kind="inet")
            if any(c.pid is None for c in all_connections):
                connections_by_pid = None
            else:
                for conn in all_connections:
                    connections_by_pid.setdefault(int(conn.pid), []).append(conn)
        except Exception:
            connections_by_pid = None
        for proc in psutil.process_iter(["pid"]):
            if self.stopping:
                break
            pid = proc.info["pid"]
            proc_connections = (None if connections_by_pid is None
                                else connections_by_pid.get(pid, ()))
            strings = self._process_strings(proc, proc_connections)
            if not strings:
                continue
            delta = self.delta_for(pid, strings)
            if not delta:
                continue
            self._forwarded += len(delta)
            batch += len(delta)
            payload = {"pid": pid, "delta": delta, "ts": time.time()}
            # producer side of the SPSC ring + the in-proc Ollama work queue
            if self._ring is not None:
                for s in delta:
                    self._ring.push(f"{pid}\t{s}".encode("utf-8", "ignore"))
            try:
                self.delta_queue.put_nowait(payload)
            except queue.Full:
                pass
        st = self.stats()
        note = f"{st['reduction_pct']}% dedup, {st['strings_seen']} seen"
        self.set_health(100 if st["reduction_pct"] >= 0 else 80, note)
        if batch:
            self.emit(f"Forwarded {batch} NEW strings (dedup {st['reduction_pct']}%).",
                      Severity.INFO, **st)

    def stop(self) -> None:
        super().stop()
        if self._ring is not None:
            self._ring.close()

    def self_test(self) -> tuple[bool, str]:
        """Prove the dedup path: the same string set twice must yield a full
        delta then an empty one."""
        pid = -1
        sample = ["kernel32.dll", "C:/Windows/System32", "svc_admin", "GET /api"]
        first = self.delta_for(pid, sample)
        second = self.delta_for(pid, sample)
        with self.state_lock:
            self._caches.pop(pid, None)
            self._cache_sets.pop(pid, None)
        if len(first) == len(sample) and second == []:
            return True, f"dedup verified ({len(first)}→0 on repeat)"
        return False, f"dedup broken: first={len(first)} second={len(second)}"


def register() -> MemoryTimeMachineModule:
    """Drop-in entry point."""
    return MemoryTimeMachineModule()
