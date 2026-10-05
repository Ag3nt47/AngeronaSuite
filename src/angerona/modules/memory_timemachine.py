"""memory_timemachine.py — Memory Time-Machine Delta Engine (Code: MTM).

Purpose
    Strip duplicate process strings *before* they are triaged so the local LLM
    only ever sees NEW information. Cuts token / CPU / VRAM overhead by only
    forwarding the differential slice of observed strings per process.

Design
    - A lock-light Single-Producer / Single-Consumer (SPSC) ring buffer backed by
      an ``mmap`` file (the ``telemetry_ringbuffer`` / RING). The producer thread
      carves printable strings; a single consumer drains them. Because there is
      exactly one writer and one reader, each bounded slot operation shares a
      short lock with close so retiring a ring cannot invalidate its readers.
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
_MAGIC = b"MTM2"
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
        self._open_lock = threading.Lock()   # slot access and native lifetime
        self._closed = False
        self._closed_overwrites = 0
        with self._open_lock:
            new = not path.exists() or path.stat().st_size != self._size
            if new:
                path.parent.mkdir(parents=True, exist_ok=True)
                with open(path, "wb") as f:
                    f.write(b"\x00" * self._size)
                try:
                    path.chmod(0o600)
                except OSError:
                    pass
            self._f = open(path, "r+b")
            self._mm = mmap.mmap(self._f.fileno(), self._size)
            if new or self._mm[0:4] != _MAGIC:
                # MTM1 stored raw strings in slots.  A format change must erase
                # the complete mapping, not just replace the header, otherwise
                # credentials from an old environment/cmdline observation can
                # remain recoverable in unused slots after an upgrade.
                self._mm[:] = b"\x00" * self._size
                struct.pack_into("<4sIQQQ", self._mm, 0, _MAGIC, slots, 0, 0, 0)

    def _head(self) -> int:
        return struct.unpack_from("<Q", self._mm, 8)[0]

    def _tail(self) -> int:
        return struct.unpack_from("<Q", self._mm, 16)[0]

    def push(self, payload: bytes) -> bool:
        with self._open_lock:
            if self._closed:
                return False
            return self._push_locked(payload)

    def _push_locked(self, payload: bytes) -> bool:
        body = payload[: _SLOT - 4]
        head, tail = self._head(), self._tail()
        admitted_without_loss = True
        if head - tail >= self._slots:           # full → drop oldest (producer side)
            struct.pack_into("<Q", self._mm, 16, tail + 1)
            overwrites = struct.unpack_from("<Q", self._mm, 24)[0]
            struct.pack_into("<Q", self._mm, 24, overwrites + 1)
            admitted_without_loss = False
        off = _HEADER + (head % self._slots) * _SLOT
        struct.pack_into("<I", self._mm, off, len(body))
        self._mm[off + 4: off + 4 + len(body)] = body
        struct.pack_into("<Q", self._mm, 8, head + 1)   # publish last
        return admitted_without_loss

    def pop(self) -> bytes | None:
        with self._open_lock:
            if self._closed:
                return None
            return self._pop_locked()

    def _pop_locked(self) -> bytes | None:
        head, tail = self._head(), self._tail()
        if tail >= head:
            return None
        off = _HEADER + (tail % self._slots) * _SLOT
        n = struct.unpack_from("<I", self._mm, off)[0]
        data = bytes(self._mm[off + 4: off + 4 + min(n, _SLOT - 4)])
        struct.pack_into("<Q", self._mm, 16, tail + 1)   # consume
        return data

    def depth(self) -> int:
        with self._open_lock:
            return 0 if self._closed else max(0, self._head() - self._tail())

    def overwrite_count(self) -> int:
        with self._open_lock:
            return (self._closed_overwrites if self._closed else
                    struct.unpack_from("<Q", self._mm, 24)[0])

    def close(self) -> None:
        with self._open_lock:
            if self._closed:
                return
            self._closed_overwrites = struct.unpack_from("<Q", self._mm, 24)[0]
            self._closed = True
            try:
                try:
                    self._mm.flush()
                finally:
                    try:
                        self._mm.close()
                    finally:
                        self._f.close()
            except Exception:
                pass


class MemoryTimeMachineModule(BaseModule):
    background_pacing_allowed = True
    CODE = "MTM"
    NAME = "Memory Time-Machine"
    name = "Memory Time-Machine"
    description = ("SPSC mmap ring + per-PID sliding hash cache; forwards only the "
                   "delta slice of newly-observed process strings to the LLM queue.")
    category = "Performance"
    version = "1.13.0"

    _WINDOW = 4096          # sliding hash-cache size per PID
    # A PID-only limit of 256 thrashed on a 257-process host: a complete sweep
    # evicted every previous PID before it could be revisited. Share the same
    # historical fingerprint budget across a larger bounded inventory instead.
    _MAX_PIDS = 4096
    _MAX_FINGERPRINTS = 256 * 4096
    _CARVE_INTERVAL = 6.0   # seconds between carve sweeps
    _MAX_DELTA_STRINGS = 256
    _MAX_DELTA_BYTES = 128 * 1024
    _MAX_STRING_BYTES = 4096

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._caches: "OrderedDict[int, deque]" = OrderedDict()
        self._cache_sets: dict[int, set] = {}
        self._cached_fingerprints = 0
        self.delta_queue: "queue.Queue[dict]" = queue.Queue(maxsize=8192)
        self._ring: _SpscRing | None = None
        self._seen = 0
        self._forwarded = 0
        self._queue_drops = 0
        self._queue_highwater = 0
        self._ring_overwrites = 0
        self._collector_failures = 0
        self._payload_truncations = 0
        self._last_delivery_failure_at = 0.0
        self._delivery_incomplete = False
        self._last_sweep_collector_failures = 0

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
            self._collector_failures += 1
            self._last_sweep_collector_failures += 1
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
                else:  # environ — names only; values may contain credentials.
                    out += [f"ENV_KEY:{str(k)[:128]}" for k in val]
            except Exception:
                self._collector_failures += 1
                self._last_sweep_collector_failures += 1
                continue
        # keep only printable runs >= 4 chars
        carved: list[str] = []
        for s in out:
            carved += self._carve(s.encode("utf-8", "ignore"))
        return carved

    def _cache_for(self, pid: int):
        with self.state_lock:
            return self._cache_for_locked(pid)

    def _discard_cache_locked(self, pid: int) -> None:
        window = self._caches.pop(pid, None)
        if window is not None:
            self._cached_fingerprints -= len(window)
        self._cache_sets.pop(pid, None)

    def _cache_for_locked(self, pid: int):
        if pid not in self._caches:
            while len(self._caches) >= self._MAX_PIDS:
                self._discard_cache_locked(next(iter(self._caches)))
            self._caches[pid] = deque(maxlen=self._WINDOW)
            self._cache_sets[pid] = set()
        else:
            self._caches.move_to_end(pid)
        return self._caches[pid], self._cache_sets[pid]

    def _trim_cache_locked(self) -> None:
        while self._cached_fingerprints > self._MAX_FINGERPRINTS and self._caches:
            # Eviction forgets suppression only. An evicted observation is sent
            # again, never silently treated as delivered or omitted.
            self._discard_cache_locked(next(iter(self._caches)))

    @staticmethod
    def _string_fingerprint(value: str) -> bytes:
        return hashlib.blake2b(
            value.encode("utf-8", "ignore"),
            digest_size=8,
            person=b"Angerona-MTM-v1",
        ).digest()

    def delta_for(
        self, pid: int, strings: list[str], *, commit: bool = True
    ) -> list[str]:
        """Return only strings not already in this PID's sliding window, and
        optionally register them.

        ``commit=False`` is the delivery-safe preview used by ``_sweep``.  The
        hashes are committed only after the downstream queue accepts a chunk,
        so backpressure cannot silently turn undelivered observations into
        "already seen" data.
        """
        delta: list[str] = []
        with self.state_lock:
            window, seen = self._cache_for_locked(pid)
            candidate_window = None
            candidate_seen = seen
            for s in strings:
                h = self._string_fingerprint(s)
                self._seen += 1
                if h in candidate_seen:
                    continue
                if candidate_window is None:
                    # Quiet sweeps need no copy/rewrite of a full historical
                    # cache. Simulate window eviction only once a novel string
                    # appears; preview mode still cannot acknowledge delivery.
                    candidate_window = deque(window, maxlen=window.maxlen)
                    candidate_seen = set(seen)
                if len(candidate_window) == candidate_window.maxlen:
                    candidate_seen.discard(candidate_window[0])
                candidate_window.append(h)
                candidate_seen.add(h)
                delta.append(s)
            if commit and candidate_window is not None:
                old_count = len(window)
                window.clear()
                window.extend(candidate_window)
                seen.clear()
                seen.update(candidate_seen)
                self._cached_fingerprints += len(window) - old_count
                self._trim_cache_locked()
        return delta

    def _commit_delta(self, pid: int, strings: list[str]) -> None:
        """Commit an already-admitted delta without double-counting it."""
        with self.state_lock:
            window, seen = self._cache_for_locked(pid)
            old_count = len(window)
            for value in strings:
                fingerprint = self._string_fingerprint(value)
                if fingerprint in seen:
                    continue
                if len(window) == window.maxlen:
                    seen.discard(window[0])
                window.append(fingerprint)
                seen.add(fingerprint)
            self._cached_fingerprints += len(window) - old_count
            self._trim_cache_locked()

    def _bounded_delta(self, values: list[str]) -> list[list[str]]:
        """Bound individual and aggregate work-queue payloads."""
        chunks: list[list[str]] = []
        current: list[str] = []
        current_bytes = 0
        for value in values:
            raw = value.encode("utf-8", "ignore")
            if len(raw) > self._MAX_STRING_BYTES:
                digest = hashlib.sha256(raw).hexdigest()
                suffix = f"...[truncated sha256={digest}]"
                suffix_bytes = suffix.encode("ascii")
                prefix = raw[: max(0, self._MAX_STRING_BYTES - len(suffix_bytes))]
                value = prefix.decode("utf-8", "ignore") + suffix
                raw = value.encode("utf-8", "ignore")
                self._payload_truncations += 1
            size = len(raw)
            if current and (
                len(current) >= self._MAX_DELTA_STRINGS
                or current_bytes + size > self._MAX_DELTA_BYTES
            ):
                chunks.append(current)
                current = []
                current_bytes = 0
            current.append(value)
            current_bytes += size
        if current:
            chunks.append(current)
        return chunks

    def stats(self) -> dict:
        with self.state_lock:
            ring = self._ring
            ring_available = ring is not None and not getattr(ring, "_closed", False)
            ring_depth = ring.depth() if ring_available else 0
            cached_pids = len(self._caches)
            cached_fingerprints = self._cached_fingerprints
        reduction = (1 - self._forwarded / self._seen) * 100 if self._seen else 0.0
        return {"strings_seen": self._seen, "forwarded": self._forwarded,
                "reduction_pct": round(reduction, 1),
                "ring_depth": ring_depth,
                "queue_depth": self.delta_queue.qsize(),
                "queue_drops": self._queue_drops,
                "queue_highwater": self._queue_highwater,
                "ring_overwrites": self._ring_overwrites,
                "collector_failures": self._collector_failures,
                "payload_truncations": self._payload_truncations,
                "cached_pids": cached_pids,
                "cached_fingerprints": cached_fingerprints,
                "fingerprint_limit": self._MAX_FINGERPRINTS,
                "delivery_incomplete": self._delivery_incomplete,
                "ring_available": ring_available}

    # ── lifecycle ────────────────────────────────────────────────────────────
    def run(self) -> None:
        from angerona.core.config import Config
        ring_path = Config().data_dir / "telemetry_ringbuffer.mmap"
        ring = None
        try:
            try:
                ring = _SpscRing(ring_path)
                with self.state_lock:
                    self._ring = ring
                    self._ring_overwrites = ring.overwrite_count()
            except Exception as exc:
                self.set_health(40, f"ring unavailable: {exc}")
            if self.stopping:
                return
            if psutil is None:
                self.set_health(0, "psutil unavailable")
                self.status = "error"
                return
            self.emit("MTM online — deduplicating process strings before triage.", Severity.INFO)
            while not self.stopping:
                self._sweep()
                self.sleep(self._CARVE_INTERVAL)
        finally:
            # The worker owns this generation's native ring. Stop signals it;
            # destruction waits until its potentially blocking collection ends.
            with self.state_lock:
                if self._ring is ring:
                    self._ring = None
            if ring is not None:
                ring.close()

    def _sweep(self) -> None:
        stop_event = self.generation_stop_event()
        if stop_event.is_set():
            return
        ring = self._ring
        batch = 0
        self._last_sweep_collector_failures = 0
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
                self._collector_failures += 1
                self._last_sweep_collector_failures += 1
            else:
                for conn in all_connections:
                    connections_by_pid.setdefault(int(conn.pid), []).append(conn)
        except Exception:
            connections_by_pid = None
            self._collector_failures += 1
            self._last_sweep_collector_failures += 1
        if stop_event.is_set():
            return
        # Keep only a bounded snapshot of existing cache keys. A PID absent
        # from a complete inventory has exited; releasing its suppression also
        # ensures a later process reusing that PID is observed afresh. Incomplete
        # enumeration must not be mistaken for confirmed process exits.
        with self.state_lock:
            # Negative keys belong to synthetic self-tests, not OS processes;
            # the self-test owns their lifetime even if a sweep overlaps it.
            unseen_cached_pids = {pid for pid in self._caches if pid >= 0}
        inventory_complete = True
        try:
            processes = psutil.process_iter(["pid"])
            for process_index, proc in enumerate(processes):
                if not self.background_checkpoint(process_index, batch_size=8):
                    return
                if stop_event.is_set():
                    break
                try:
                    pid = int(proc.info["pid"])
                except Exception:
                    inventory_complete = False
                    self._collector_failures += 1
                    self._last_sweep_collector_failures += 1
                    continue
                unseen_cached_pids.discard(pid)
                proc_connections = (None if connections_by_pid is None
                                    else connections_by_pid.get(pid, ()))
                strings = self._process_strings(proc, proc_connections)
                if stop_event.is_set():
                    return
                if not strings:
                    continue
                delta = self.delta_for(pid, strings, commit=False)
                if not delta:
                    continue
                source_offset = 0
                for admitted in self._bounded_delta(delta):
                    originals = delta[source_offset:source_offset + len(admitted)]
                    source_offset += len(admitted)
                    # Serialize only bounded admission/receipt work with stop;
                    # never hold this lock across native process collection.
                    with self._lifecycle_lock:
                        if (stop_event.is_set() or stop_event is not self._stop
                                or ring is not self._ring):
                            return
                        payload = {"pid": pid, "delta": admitted, "ts": time.time()}
                        try:
                            self.delta_queue.put_nowait(payload)
                        except queue.Full:
                            self._queue_drops += len(admitted)
                            self._delivery_incomplete = True
                            self._last_delivery_failure_at = time.time()
                            continue

                        # Commit dedup only after queue admission. The mmap
                        # receives pseudonymous receipts, never source strings.
                        # Admission is for this bounded representation of the
                        # original strings. Retain their original fingerprints;
                        # hashing the truncated payload re-forwarded every long
                        # command line on every later sweep.
                        self._commit_delta(pid, originals)
                        self._forwarded += len(admitted)
                        batch += len(admitted)
                        if ring is not None:
                            for value in admitted:
                                receipt = hashlib.blake2b(
                                    value.encode("utf-8", "ignore"),
                                    digest_size=16,
                                    person=b"Angerona-MTM-v1",
                                ).hexdigest()
                                if not ring.push(f"{pid}\t{receipt}".encode("ascii")):
                                    self._last_delivery_failure_at = time.time()
                            self._ring_overwrites = ring.overwrite_count()
                        self._queue_highwater = max(
                            self._queue_highwater, self.delta_queue.qsize()
                        )
        except Exception:
            inventory_complete = False
            self._collector_failures += 1
            self._last_sweep_collector_failures += 1
        if stop_event.is_set():
            return
        if inventory_complete:
            with self.state_lock:
                for pid in unseen_cached_pids:
                    self._discard_cache_locked(pid)
        st = self.stats()
        health = 100
        reasons: list[str] = []
        if self._ring is None:
            health = min(health, 40)
            reasons.append("ring unavailable")
        if self._delivery_incomplete:
            health = min(health, 55)
            reasons.append(f"{self._queue_drops} queue admissions refused; retry required")
        if self._ring_overwrites:
            health = min(health, 70)
            reasons.append(f"{self._ring_overwrites} ring records overwritten")
        if self._last_sweep_collector_failures:
            health = min(health, 65)
            reasons.append(
                f"{self._last_sweep_collector_failures} collector gaps this sweep"
            )
        if self._payload_truncations:
            health = min(health, 80)
            reasons.append(f"{self._payload_truncations} bounded payloads")
        note = (
            f"{st['reduction_pct']}% dedup, {st['strings_seen']} seen"
            + ("; " + "; ".join(reasons) if reasons else "; complete delivery")
        )
        self.set_health(health, note)
        if batch and not stop_event.is_set():
            self.emit(f"Forwarded {batch} NEW strings (dedup {st['reduction_pct']}%).",
                      Severity.INFO, **st)

    def self_test(self) -> tuple[bool, str]:
        """Prove the dedup path: the same string set twice must yield a full
        delta then an empty one."""
        pid = -1
        sample = ["kernel32.dll", "C:/Windows/System32", "svc_admin", "GET /api"]
        first = self.delta_for(pid, sample)
        second = self.delta_for(pid, sample)
        with self.state_lock:
            self._discard_cache_locked(pid)
        if len(first) == len(sample) and second == []:
            return True, f"dedup verified ({len(first)}→0 on repeat)"
        return False, f"dedup broken: first={len(first)} second={len(second)}"


def register() -> MemoryTimeMachineModule:
    """Drop-in entry point."""
    return MemoryTimeMachineModule()
