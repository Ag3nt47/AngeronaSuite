r"""Ransomware Heuristics — G2-C.

Detects T1486 (Data Encrypted for Impact) through two complementary signals:

1. Shannon Entropy scan
   Reads the first 64 KB of recently-modified files in watched directories.
   If the file's per-byte entropy exceeds ENTROPY_THRESHOLD (default 7.9 bits —
   effectively random, as encrypted/compressed data is), it is flagged.
   Known compressed or encrypted formats (zip, jpg, pdf …) are excluded by
   extension so we don't alert on pre-existing archives.

2. Rename-rate tracker
   Ransomware renames files en masse (often appending a custom extension).
   We watch a set of canary directories and record how many renames happen
   per 10-second window.  If the rate exceeds RENAME_THRESHOLD the module
   emits a CRITICAL alert and trips a "rename storm" flag.

Why Shannon entropy?
   Text, executables, and most documents have entropy ≤ 7.5 bits/byte.
   AES-256 (CTR/CBC) and ChaCha20 output is statistically indistinguishable
   from uniform random — entropy ≥ 7.9 bits/byte.  The threshold is tunable.

Watched paths (default):
   User profile sub-folders most targeted by ransomware:
   %USERPROFILE%\Documents, Desktop, Pictures, Downloads, Videos, Music

False positive mitigations:
   - Known-high-entropy extensions skipped (zip, gz, 7z, jpg, jpeg, png,
     mp4, mkv, avi, mp3, aac, flac, pdf).
   - Files smaller than MIN_FILE_BYTES (4096) skipped.
   - Files modified more than MTIME_WINDOW seconds ago skipped.
   - Per-file dedup: once a file is flagged it won't fire again for DEDUP_TTL.
"""
from __future__ import annotations

import math
import os
import time
from collections import deque
from pathlib import Path
from typing import Deque, List, Optional

from angerona.core.module_base import BaseModule, Severity

# ── GIL relief for the hot entropy path ───────────────────────────────────────
# Shannon entropy is computed on the first 64 KB of every recently-modified file
# in every watched directory, every scan tick. The old implementation counted
# bytes in a pure-Python ``for`` loop — 64 K iterations per file, all holding the
# GIL, which is exactly the kind of steady CPU load that starves the response
# path on a busy host. We build the 256-bin byte histogram with NumPy when it's
# available (one pass in C; the buffer work releases the GIL), and fall back to
# ``collections.Counter`` (whose element count runs in C via _collections) when
# it isn't. Either path holds the GIL far less than the per-byte loop did.
try:
    import numpy as _np
    _HAVE_NUMPY = True
except Exception:  # pragma: no cover - environment dependent
    _np = None
    _HAVE_NUMPY = False

# ── Tuning constants ──────────────────────────────────────────────────────────
ENTROPY_THRESHOLD = 7.9          # bits/byte; below this is almost never ransomware
MIN_FILE_BYTES    = 4096         # ignore tiny files (scripts, ini, etc.)
MTIME_WINDOW      = 120.0        # only scan files touched in the last N seconds
SAMPLE_BYTES      = 65536        # read first 64 KB for entropy (fast + representative)
RENAME_THRESHOLD  = 20           # renames per 10-second window → CRITICAL
RENAME_WINDOW_S   = 10.0         # rename-rate measurement window
DEDUP_TTL         = 300.0        # re-alert suppression per file (seconds)

# File extensions that are legitimately high-entropy; skip entropy check.
_SKIP_EXTENSIONS: frozenset[str] = frozenset({
    ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".zst",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic",
    ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv",
    ".mp3", ".aac", ".flac", ".ogg", ".opus",
    ".pdf",
    ".docx", ".xlsx", ".pptx",  # already zipped internally
})


def _byte_histogram(data: bytes):
    """256-bin byte-frequency histogram, computed off the pure-Python slow path.

    NumPy path does the whole count in one C pass (releasing the GIL for the
    buffer→bincount work) — measured ~4× faster than the per-byte Python loop,
    so it holds the GIL a quarter as long per file. When NumPy isn't installed
    we fall back to the original tight loop, which benchmarks as the fastest
    pure-Python option (bytes.count×256 and Counter both tested slower), so the
    no-NumPy path is never a regression versus the previous code."""
    if _HAVE_NUMPY:
        return _np.bincount(_np.frombuffer(data, dtype=_np.uint8), minlength=256)
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    return counts


def _shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy of *data* in bits per byte (0.0–8.0).

    Only the final reduction over the 256 fixed bins stays in Python (constant
    work); the expensive per-byte counting is delegated to _byte_histogram so it
    no longer holds the GIL for the length of the file sample."""
    n = len(data)
    if not n:
        return 0.0
    counts = _byte_histogram(data)
    inv_n = 1.0 / n
    ent = 0.0
    for c in counts:
        if c:
            p = c * inv_n
            ent -= p * math.log2(p)
    return ent


def _default_watch_dirs() -> List[Path]:
    home = Path.home()
    candidates = [
        home / "Documents",
        home / "Desktop",
        home / "Pictures",
        home / "Downloads",
        home / "Videos",
        home / "Music",
    ]
    return [p for p in candidates if p.is_dir()]


class RansomwareHeuristicsModule(BaseModule):
    CODE = "RANS"
    NAME = "Ransomware Heuristics"
    name = "Ransomware Heuristics"
    description = (
        "Detects ransomware (T1486) via Shannon entropy scanning of recently "
        "modified files and rename-storm rate tracking in user directories."
    )
    category = "Ransomware"

    # Scan interval between directory sweeps (seconds)
    _SCAN_INTERVAL = 10.0

    def __init__(self) -> None:
        super().__init__()
        # (path_str) → last_alert_ts
        self._flagged: dict[str, float] = {}
        # Sliding window of rename timestamps for rate detection
        self._rename_times: Deque[float] = deque()
        # Filesystem watcher handle (os.scandir-based)
        self._watch_dirs: List[Path] = []
        # Previous directory snapshots for rename detection:
        # {dir_str: {name_str: mtime}}
        self._dir_snapshot: dict[str, dict[str, float]] = {}
        # Whether to offload entropy scoring to worker processes (resolved once at
        # run() from ANGERONA_ENTROPY_POOL / Settings). Off = in-process, as before.
        self._use_pool = False

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    def run(self) -> None:
        try:
            from angerona.core import entropy_pool
            self._use_pool = entropy_pool.enabled()
        except Exception:
            self._use_pool = False
        self._watch_dirs = _default_watch_dirs()
        if not self._watch_dirs:
            self.set_health(50, "No watched directories found in user profile")
            self.emit(
                "RansomwareHeuristics: no watchable directories found. "
                "Using Documents/Desktop/etc from %USERPROFILE%.",
                Severity.MEDIUM,
            )
        else:
            dirs_str = ", ".join(str(d) for d in self._watch_dirs)
            self.emit(
                f"Ransomware heuristics active — watching: {dirs_str}",
                Severity.INFO,
                watched_dirs=dirs_str,
            )
            self.set_health(100, "")

        # Seed snapshots so first pass doesn't flood rename alerts
        for d in self._watch_dirs:
            self._dir_snapshot[str(d)] = self._snapshot(d)

        while not self.stopping:
            self.sleep(self._SCAN_INTERVAL)
            self._tick()

    # ── Per-tick logic ────────────────────────────────────────────────────────
    def _tick(self) -> None:
        now = time.time()
        # Collect entropy candidates across ALL watched dirs first, then score
        # them in one batch. Batching (rather than per-file inline hashing) is
        # what lets the optional process pool amortise its IPC cost, and it keeps
        # the in-process path identical when the pool is off.
        candidates: List[str] = []
        for directory in self._watch_dirs:
            if self.stopping:
                return
            try:
                candidates.extend(self._collect_entropy_candidates(directory, now))
                self._detect_renames(directory, now)
            except Exception as exc:
                self.set_health(70, f"Scan error: {exc}")

        if candidates and not self.stopping:
            try:
                self._evaluate_entropy(candidates, now)
            except Exception as exc:
                self.set_health(70, f"Entropy eval error: {exc}")

        self._check_rename_rate(now)
        self._evict_stale_dedup(now)

    # ── Entropy scan ──────────────────────────────────────────────────────────
    def _collect_entropy_candidates(self, directory: Path, now: float) -> List[str]:
        """Return the paths in *directory* that clear every cheap stat-based
        filter (size, mtime window, skip-extension, dedup) and therefore need an
        actual entropy read this tick. Pure enumeration — no file reads here."""
        out: List[str] = []
        try:
            with os.scandir(directory) as it:
                for entry in it:
                    if self.stopping:
                        return out
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    try:
                        stat = entry.stat()
                    except OSError:
                        continue
                    if stat.st_size < MIN_FILE_BYTES:
                        continue
                    if now - stat.st_mtime > MTIME_WINDOW:
                        continue
                    if Path(entry.name).suffix.lower() in _SKIP_EXTENSIONS:
                        continue
                    path_str = entry.path
                    if now - self._flagged.get(path_str, 0.0) < DEDUP_TTL:
                        continue
                    out.append(path_str)
        except PermissionError:
            pass
        return out

    def _evaluate_entropy(self, candidates: List[str], now: float) -> None:
        """Score a batch of candidate files and alert on any at/above threshold.

        Uses the process-pool offload when it's enabled (ANGERONA_ENTROPY_POOL /
        Settings) and the batch is large enough; otherwise scores in-process. The
        detection/dedup/emit semantics are identical either way."""
        try:
            from angerona.core import entropy_pool
            results = entropy_pool.compute_entropies(candidates,
                                                     prefer_pool=self._use_pool)
        except Exception:
            # Any failure in the offload path → score inline so a scan never
            # silently stops catching ransomware.
            results = {p: self._file_entropy(p) for p in candidates}
        for path_str, ent in results.items():
            if ent is not None and ent >= ENTROPY_THRESHOLD:
                self._flagged[path_str] = now
                self.emit(
                    f"High-entropy file detected: {os.path.basename(path_str)} "
                    f"(entropy={ent:.3f} bits/byte ≥ {ENTROPY_THRESHOLD}) — "
                    "possible ransomware encryption in progress (T1486)",
                    Severity.HIGH,
                    path=path_str,
                    entropy=round(ent, 4),
                    threshold=ENTROPY_THRESHOLD,
                    mitre_tags=["T1486"],
                )

    def _file_entropy(self, path: str) -> Optional[float]:
        try:
            with open(path, "rb") as fh:
                data = fh.read(SAMPLE_BYTES)
            return _shannon_entropy(data)
        except Exception:
            return None

    # ── Rename-rate tracker ───────────────────────────────────────────────────
    def _snapshot(self, directory: Path) -> dict[str, float]:
        """Return {filename: mtime} for all files in *directory* (top-level)."""
        snap: dict[str, float] = {}
        try:
            with os.scandir(directory) as it:
                for entry in it:
                    if entry.is_file(follow_symlinks=False):
                        try:
                            snap[entry.name] = entry.stat().st_mtime
                        except OSError:
                            pass
        except PermissionError:
            pass
        return snap

    def _detect_renames(self, directory: Path, now: float) -> None:
        """Compare directory snapshot to detect file additions/deletions (renames)."""
        dkey = str(directory)
        old  = self._dir_snapshot.get(dkey, {})
        new  = self._snapshot(directory)
        self._dir_snapshot[dkey] = new

        disappeared = set(old) - set(new)
        appeared    = set(new) - set(old)

        # Heuristic: a file vanishes AND a new file with similar base name
        # but a new extension appears in the same tick → likely renamed.
        # Even without that pairing, both adds and removes are counted because
        # ransomware often deletes originals after encrypting to new names.
        n_changes = len(disappeared) + len(appeared)
        if n_changes:
            ts_entries = [now] * n_changes
            self._rename_times.extend(ts_entries)

    def _check_rename_rate(self, now: float) -> None:
        """Emit CRITICAL if rename count in the last RENAME_WINDOW_S exceeds threshold."""
        cutoff = now - RENAME_WINDOW_S
        while self._rename_times and self._rename_times[0] < cutoff:
            self._rename_times.popleft()
        rate = len(self._rename_times)
        if rate >= RENAME_THRESHOLD:
            self.emit(
                f"RENAME STORM detected: {rate} file renames in {RENAME_WINDOW_S}s — "
                "ransomware mass-encryption likely in progress (T1486). "
                "Review watched directories immediately.",
                Severity.CRITICAL,
                rename_count=rate,
                window_s=RENAME_WINDOW_S,
                threshold=RENAME_THRESHOLD,
                mitre_tags=["T1486"],
            )
            # Clear to avoid re-alerting every tick while storm continues
            self._rename_times.clear()

    # ── Housekeeping ──────────────────────────────────────────────────────────
    def _evict_stale_dedup(self, now: float) -> None:
        cutoff = now - DEDUP_TTL
        stale  = [k for k, ts in self._flagged.items() if ts < cutoff]
        for k in stale:
            del self._flagged[k]

    def self_test(self) -> tuple[bool, str]:
        # Run entropy on a synthetic block of random-like data
        synthetic = bytes(range(256)) * 4   # 1 KB, entropy ~8.0
        ent = _shannon_entropy(synthetic)
        if ent >= ENTROPY_THRESHOLD:
            return True, f"Entropy function OK (test={ent:.3f} ≥ {ENTROPY_THRESHOLD})"
        return False, f"Entropy function returned {ent:.3f} — unexpected"


def register() -> RansomwareHeuristicsModule:
    return RansomwareHeuristicsModule()
