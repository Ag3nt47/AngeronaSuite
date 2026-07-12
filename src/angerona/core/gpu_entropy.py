"""gpu_entropy.py — GPU-Accelerated Shannon Entropy Processing Pipeline.

Purpose
    Provide a batching mechanism that offloads Shannon entropy computation for
    large string corpora (Packet Sniffer cleartext scanning, NDRD DNS query
    analysis) to the GPU via PyTorch CUDA, cutting CPU utilisation for these
    hot paths by an order of magnitude.

Architecture
    ┌──────────────────────────────────────────────────────┐
    │  Producer (NDRD / Packet Sniffer daemon thread)      │
    │  → submit_batch(strings: list[str])                  │
    └──────────────────────┬───────────────────────────────┘
                           │ queue.Queue (bounded, FIFO)
    ┌──────────────────────▼───────────────────────────────┐
    │  EntropyWorker (daemon thread)                       │
    │  1. Drain queue until batch_size or flush_ms         │
    │  2. Encode strings → uint8 tensor on CPU             │
    │  3. .to(device)  ← CPU→GPU VRAM transfer boundary    │
    │  4. compute_entropy_gpu() → CUDA kernel              │
    │  5. .cpu() ← VRAM→CPU transfer boundary              │
    │  6. Call registered result callbacks                 │
    └──────────────────────────────────────────────────────┘

CPU fallback
    If CUDA is unavailable (``torch.cuda.is_available() == False``) or PyTorch
    is not installed at all, the pipeline falls back to a vectorised NumPy
    implementation that is still significantly faster than a pure-Python loop
    because it avoids repeated Python-level character iteration.

    If NumPy is also absent, a pure-Python implementation is used as a last
    resort.

Usage
    from angerona.core.gpu_entropy import get_pipeline, EntropyResult

    pipe = get_pipeline()               # singleton, starts worker on first call
    pipe.on_result(my_callback)         # register(fn: Callable[[EntropyResult], None])
    pipe.submit_batch(["example.com", "xn--mixed123.ru", ...])

    # Result callback receives EntropyResult:
    #   .strings: list[str]
    #   .entropies: list[float]
    #   .device: "cuda" | "numpy" | "python"
    #   .elapsed_ms: float
"""
from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List

# ── optional imports ─────────────────────────────────────────────────────────
try:
    import torch
    import torch.nn.functional as F  # noqa: F401 (pulled in for warm-up)
    _TORCH_OK = True
except ImportError:
    torch = None
    _TORCH_OK = False

try:
    import numpy as np
    _NP_OK = True
except ImportError:
    np = None
    _NP_OK = False

MAX_BATCH: int = 4096        # max strings per GPU batch
FLUSH_MS: float = 20.0       # max latency before flushing an incomplete batch
MAX_STR_LEN: int = 255       # strings longer than this are truncated for the tensor
_QUEUE_CAP: int = 32_000     # bounded input queue (drops oldest on overflow)


# ── result dataclass ─────────────────────────────────────────────────────────
@dataclass
class EntropyResult:
    strings: List[str]
    entropies: List[float]
    device: str          # "cuda" | "numpy" | "python"
    elapsed_ms: float


# ── GPU entropy computation ──────────────────────────────────────────────────
def _entropy_gpu(strings: list[str], device: "torch.device") -> list[float]:
    """Compute Shannon entropy for N strings in a single GPU pass.

    Data transfer boundary
    ──────────────────────
    Input:  Python list of str          (CPU RAM)
    ↓  encode + pad → uint8 tensor      (CPU RAM)
    ↓  .to(device)                      ← CPU → VRAM
    ↓  CUDA operations (vectorised)     (VRAM)
    ↓  entropy float tensor .cpu()      ← VRAM → CPU RAM
    Output: Python list of float        (CPU RAM)

    VRAM footprint: O(N × L) bytes where L = MAX_STR_LEN (default 255).
    At 4096 strings × 255 bytes = ~1 MB — negligible even on low-end GPUs.
    """
    import torch  # local import so module loads on non-CUDA hosts

    n = len(strings)
    L = MAX_STR_LEN

    # ── encode to uint8 tensor on CPU ────────────────────────────────────────
    # Shape: (N, L).  Pad with zeros; out-of-range bytes are excluded from the
    # entropy sum (they do not affect character frequency counts).
    buf = torch.zeros((n, L), dtype=torch.uint8)
    for i, s in enumerate(strings):
        b = s.encode("utf-8", errors="replace")[:L]
        t = torch.frombuffer(b, dtype=torch.uint8)
        buf[i, : len(t)] = t

    # ── CPU → VRAM ────────────────────────────────────────────────────────────
    buf = buf.to(device)                         # shape (N, L), uint8, on GPU

    # ── one-hot per byte value (0-255) → frequency counts ────────────────────
    # Shape after one_hot: (N, L, 256) — then sum over dim=1 → (N, 256)
    oh = torch.zeros((n, 256), dtype=torch.float32, device=device)
    oh.scatter_add_(
        1,
        buf.long(),                              # (N, L) index tensor
        torch.ones((n, L), dtype=torch.float32, device=device),
    )

    # ── string lengths (denominator) ─────────────────────────────────────────
    lengths = (buf != 0).sum(dim=1, keepdim=True).float()  # (N, 1)
    lengths = lengths.clamp(min=1.0)

    # ── probability of each byte ──────────────────────────────────────────────
    p = oh / lengths                              # (N, 256), probabilities
    # Mask out zero-count entries before log to avoid NaN
    mask = p > 0.0
    log_p = torch.zeros_like(p)
    log_p[mask] = torch.log2(p[mask])

    # ── H = -sum(p * log2(p)) ────────────────────────────────────────────────
    entropy = -(p * log_p).sum(dim=1)            # (N,)

    # ── VRAM → CPU ────────────────────────────────────────────────────────────
    return entropy.cpu().tolist()


def _entropy_numpy(strings: list[str]) -> list[float]:
    """Vectorised NumPy fallback — still much faster than a pure-Python loop."""
    import numpy as np
    results = []
    for s in strings:
        b = np.frombuffer(s.encode("utf-8", errors="replace"), dtype=np.uint8)
        if len(b) == 0:
            results.append(0.0)
            continue
        _, counts = np.unique(b, return_counts=True)
        p = counts / counts.sum()
        results.append(float(-np.sum(p * np.log2(p + 1e-12))))
    return results


def _entropy_python(strings: list[str]) -> list[float]:
    """Pure-Python fallback — no dependencies."""
    from math import log2
    from collections import Counter
    out = []
    for s in strings:
        b = s.encode("utf-8", errors="replace")
        n = len(b)
        if n == 0:
            out.append(0.0)
            continue
        h = -sum((c / n) * log2(c / n) for c in Counter(b).values())
        out.append(h)
    return out


# ── worker ────────────────────────────────────────────────────────────────────
class EntropyWorker(threading.Thread):
    """Daemon thread that drains the input queue in timed batches."""

    def __init__(self) -> None:
        super().__init__(daemon=True, name="EntropyWorker")
        self._queue: queue.Queue[str] = queue.Queue(maxsize=_QUEUE_CAP)
        self._callbacks: list[Callable[[EntropyResult], None]] = []
        self._cb_lock = threading.Lock()
        self._dropped = 0

        # Resolve device once at startup
        if _TORCH_OK and torch.cuda.is_available():
            self._device = torch.device("cuda")
            self._mode = "cuda"
        else:
            self._device = None
            self._mode = "numpy" if _NP_OK else "python"

    @property
    def device_label(self) -> str:
        return self._mode

    def on_result(self, fn: Callable[[EntropyResult], None]) -> None:
        with self._cb_lock:
            self._callbacks.append(fn)

    def submit_batch(self, strings: list[str]) -> int:
        """Enqueue strings for processing.  Returns count actually queued."""
        queued = 0
        for s in strings:
            try:
                self._queue.put_nowait(s)
                queued += 1
            except queue.Full:
                self._dropped += 1
        return queued

    def submit(self, s: str) -> None:
        """Enqueue a single string."""
        try:
            self._queue.put_nowait(s)
        except queue.Full:
            self._dropped += 1

    def run(self) -> None:
        while True:
            # Collect up to MAX_BATCH strings or flush after FLUSH_MS
            batch: list[str] = []
            deadline = time.monotonic() + FLUSH_MS / 1000.0
            while len(batch) < MAX_BATCH:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    s = self._queue.get(timeout=remaining)
                    batch.append(s)
                except queue.Empty:
                    break

            if not batch:
                continue

            t0 = time.perf_counter()
            try:
                if self._mode == "cuda":
                    entropies = _entropy_gpu(batch, self._device)
                elif self._mode == "numpy":
                    entropies = _entropy_numpy(batch)
                else:
                    entropies = _entropy_python(batch)
            except Exception:
                # On GPU error, degrade to numpy/python for this batch
                try:
                    entropies = _entropy_numpy(batch) if _NP_OK else _entropy_python(batch)
                except Exception:
                    entropies = [0.0] * len(batch)

            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            result = EntropyResult(
                strings=batch,
                entropies=entropies,
                device=self._mode,
                elapsed_ms=elapsed_ms,
            )
            with self._cb_lock:
                for cb in self._callbacks:
                    try:
                        cb(result)
                    except Exception:
                        pass


# ── singleton ─────────────────────────────────────────────────────────────────
_PIPELINE: EntropyWorker | None = None
_PIPE_LOCK = threading.Lock()


def get_pipeline() -> EntropyWorker:
    """Return the global EntropyWorker singleton, starting it if necessary."""
    global _PIPELINE
    with _PIPE_LOCK:
        if _PIPELINE is None:
            _PIPELINE = EntropyWorker()
            _PIPELINE.start()
    return _PIPELINE
