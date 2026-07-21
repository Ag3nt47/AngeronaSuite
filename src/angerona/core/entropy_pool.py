r"""entropy_pool.py — optional process-pool offload for the entropy/hash scan.

The ransomware heuristic reads the first 64 KB of every recently-modified file
in the watched directories each tick and computes its Shannon entropy. Even with
the NumPy-vectorised histogram, that work runs *on the calling thread*, so on a
big scan it still holds CPU (and, for the Python parts, the GIL) that the UI and
the response path would rather have.

This module is an **opt-in** offload: it hands a batch of file paths to a small
pool of *worker processes* (true parallelism, no shared GIL), each of which reads
and scores its files and returns ``{path: entropy}``. Only paths cross the IPC
boundary — never the file bytes — so the transfer stays tiny.

Design constraints (this is defensive software watching its own host):
  • Opt-in only — enabled by ``ANGERONA_ENTROPY_POOL=1`` (Settings publishes it).
    With it off, ``compute_entropies`` runs exactly the in-process path.
  • Spawn-safe — uses a ``spawn`` context so it behaves identically on Windows
    (where it's the only option) and Linux, and imports nothing heavy at module
    top so each spawned worker starts cheap.
  • Bounded — worker count is capped at ``min(4, cpu-2)``; the pool is only used
    when a batch is big enough to out-earn the IPC/spawn overhead; everything is
    wrapped so any pool failure falls back to the in-process path instead of
    taking the scan (or the agent) down.
  • Self-healing — a broken pool is torn down and the module reverts to inline.

Run ``python -m angerona.core.entropy_pool --bench`` on the target host to
measure whether the offload actually pays off there (see ``_bench``).
"""
from __future__ import annotations

import math
import os
import threading
from typing import Dict, Iterable, List, Optional, Tuple

# Bytes read from the head of each file for the entropy estimate — matches
# ransomware_heuristics.SAMPLE_BYTES. Module-level so spawned workers (which
# re-import this module) see the same value without it crossing the IPC line.
_SAMPLE_BYTES = 65536


# ── Pure entropy primitives (also run inside the worker processes) ────────────
def _entropy_of_bytes(data: bytes) -> float:
    """Shannon entropy (bits/byte, 0–8). NumPy histogram when available, else a
    pure-Python fallback. Kept self-contained so a spawned worker needs only this
    module — not the whole modules package — to do its job."""
    n = len(data)
    if not n:
        return 0.0
    try:
        import numpy as _np
        counts = _np.bincount(_np.frombuffer(data, dtype=_np.uint8), minlength=256)
    except Exception:
        counts = [0] * 256
        for b in data:
            counts[b] += 1
    inv_n = 1.0 / n
    ent = 0.0
    for c in counts:
        if c:
            p = c * inv_n
            ent -= p * math.log2(p)
    return ent


def entropy_of_path(path: str) -> Tuple[str, Optional[float]]:
    """Read the head of ``path`` and return ``(path, entropy)`` — ``(path, None)``
    if it can't be read. This is the picklable unit of work the pool distributes;
    reading happens in the worker so only the path (not the bytes) crosses IPC."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(_SAMPLE_BYTES)
    except Exception:
        return (path, None)
    return (path, _entropy_of_bytes(data))


def _inline(paths: List[str]) -> Dict[str, Optional[float]]:
    return {p: e for p, e in (entropy_of_path(p) for p in paths)}


# ── Bounded, self-healing process pool ────────────────────────────────────────
class EntropyPool:
    def __init__(self, max_workers: Optional[int] = None, *,
                 min_batch: int = 24, map_timeout: float = 60.0) -> None:
        self.max_workers = int(max_workers or max(1, min(4, (os.cpu_count() or 2) - 2)))
        self.min_batch = int(min_batch)
        self.map_timeout = float(map_timeout)
        self._ex = None
        self._broken = False
        self._lock = threading.Lock()

    def _ensure(self):
        if self._ex is not None or self._broken:
            return self._ex
        with self._lock:
            if self._ex is None and not self._broken:
                try:
                    import concurrent.futures as _cf
                    import multiprocessing as _mp
                    ctx = _mp.get_context("spawn")
                    self._ex = _cf.ProcessPoolExecutor(
                        max_workers=self.max_workers, mp_context=ctx)
                except Exception:
                    self._broken = True
                    self._ex = None
        return self._ex

    def map_entropy(self, paths: Iterable[str]) -> Dict[str, Optional[float]]:
        items = list(paths)
        if not items:
            return {}
        ex = self._ensure()
        if ex is None:
            return _inline(items)
        try:
            chunk = max(1, len(items) // (self.max_workers * 4))
            out: Dict[str, Optional[float]] = {}
            for path, ent in ex.map(entropy_of_path, items,
                                    chunksize=chunk, timeout=self.map_timeout):
                out[path] = ent
            return out
        except Exception:
            # A broken pool (timeout, worker crash, spawn failure mid-run) must
            # never fail the scan: tear it down and finish the batch in-process.
            self._broken = True
            try:
                self._ex.shutdown(cancel_futures=True)
            except Exception:
                pass
            self._ex = None
            return _inline(items)

    def shutdown(self) -> None:
        with self._lock:
            if self._ex is not None:
                try:
                    self._ex.shutdown(cancel_futures=True)
                except Exception:
                    pass
                self._ex = None


# ── Module-level convenience API ──────────────────────────────────────────────
_SINGLETON: Optional[EntropyPool] = None
_SINGLETON_LOCK = threading.Lock()


def enabled() -> bool:
    """True when the operator has opted into the process-pool offload."""
    return os.environ.get("ANGERONA_ENTROPY_POOL", "").strip().lower() in (
        "1", "true", "yes", "on")


def get_pool() -> EntropyPool:
    global _SINGLETON
    if _SINGLETON is None:
        with _SINGLETON_LOCK:
            if _SINGLETON is None:
                _SINGLETON = EntropyPool()
    return _SINGLETON


def compute_entropies(paths: Iterable[str],
                      prefer_pool: Optional[bool] = None) -> Dict[str, Optional[float]]:
    """Return ``{path: entropy}`` for ``paths``.

    Uses the worker pool when the offload is enabled AND the batch is large
    enough to be worth it; otherwise computes in-process. ``prefer_pool``
    overrides the env-var decision (used by the benchmark)."""
    items = list(paths)
    use = enabled() if prefer_pool is None else bool(prefer_pool)
    if use and len(items) >= get_pool().min_batch:
        return get_pool().map_entropy(items)
    return _inline(items)


def shutdown_pool() -> None:
    """Tear the shared pool down (call on module/app stop)."""
    global _SINGLETON
    if _SINGLETON is not None:
        _SINGLETON.shutdown()
        _SINGLETON = None


def self_test() -> "tuple[bool, str]":
    """Prove the primitive is correct and the inline path returns per-path scores."""
    try:
        assert abs(_entropy_of_bytes(bytes(range(256)) * 4) - 8.0) < 1e-9, "uniform → 8.0"
        assert _entropy_of_bytes(b"A" * 4096) == 0.0, "constant → 0.0"
        import tempfile
        d = tempfile.mkdtemp(prefix="entpool_")
        paths = []
        for i in range(3):
            p = os.path.join(d, f"f{i}.bin")
            with open(p, "wb") as fh:
                fh.write(bytes((i * 7 + k) % 256 for k in range(8192)))
            paths.append(p)
        res = compute_entropies(paths, prefer_pool=False)
        assert set(res) == set(paths) and all(v is not None for v in res.values()), \
            "inline compute returns a score per path"
        return True, ("OK — entropy primitive matches reference (uniform→8.0, "
                      "constant→0.0) and batch compute scores every path.")
    except AssertionError as exc:
        return False, f"FAIL — {exc}"
    except Exception as exc:  # pragma: no cover
        return False, f"ERROR — {type(exc).__name__}: {exc}"


# ── Benchmark: does the offload actually help on THIS host? ────────────────────
def _bench(n_files: int = 400, file_kb: int = 64) -> None:
    """Measure inline vs pool: total wall time AND — the number that matters for
    GIL contention — how long the *calling thread* is stalled (a heartbeat thread
    samples its own scheduling latency while the batch runs)."""
    import tempfile
    import time
    import statistics as stats

    # Build a realistic batch of random (high-entropy) files.
    d = tempfile.mkdtemp(prefix="entpool_bench_")
    blob = os.urandom(file_kb * 1024)
    paths = []
    for i in range(n_files):
        p = os.path.join(d, f"f{i}.bin")
        with open(p, "wb") as fh:
            fh.write(blob)
        paths.append(p)

    def run(prefer_pool: bool):
        stop = threading.Event()
        gaps: List[float] = []

        def heartbeat():
            # A responsive main thread would tick this every ~5 ms. Whatever it
            # actually measures beyond that is time it was starved of the CPU/GIL.
            last = time.perf_counter()
            while not stop.is_set():
                now = time.perf_counter()
                gaps.append((now - last - 0.005) * 1000.0)  # ms of stall beyond target
                last = now
                time.sleep(0.005)

        hb = threading.Thread(target=heartbeat, daemon=True)
        hb.start()
        t0 = time.perf_counter()
        res = compute_entropies(paths, prefer_pool=prefer_pool)
        wall = time.perf_counter() - t0
        stop.set(); hb.join(timeout=1.0)
        pos = [g for g in gaps if g > 0]
        worst = max(pos) if pos else 0.0
        p95 = stats.quantiles(pos, n=20)[-1] if len(pos) > 20 else worst
        return wall, worst, p95, len(res)

    print(f"[entropy_pool bench] {n_files} files × {file_kb} KB, "
          f"workers={get_pool().max_workers}, cpu={os.cpu_count()}")
    for label, pref in (("inline (in-process)", False), ("process pool  ", True)):
        wall, worst, p95, got = run(pref)
        print(f"  {label}: wall={wall*1000:7.0f} ms | "
              f"caller-thread stall p95={p95:6.1f} ms worst={worst:6.1f} ms | scored={got}")
    print("  (Lower caller-thread stall = the UI/response path keeps running while "
          "the scan proceeds. On a single/dual-core host the pool rarely wins.)")
    shutdown_pool()


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()  # safe if this app is ever frozen (PyInstaller)
    import sys
    if "--bench" in sys.argv:
        _bench()
    else:
        ok, detail = self_test()
        print(f"[entropy_pool] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
        raise SystemExit(0 if ok else 1)
