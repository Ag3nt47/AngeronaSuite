"""
core/hw_profile.py — dynamic hardware-patching layer.

Profiles the host GPU's VRAM at runtime (via pynvml, best-effort) and returns a
tiered execution config: local Ollama model, max batch size, and context window.
The tiers scale down for small cards (e.g. a 6 GB GTX 1060) and up for larger
GPUs, so the AI/telemetry pipeline stays inside the card's memory budget instead
of OOM-crashing.

Everything degrades gracefully: with no GPU or no pynvml it returns the CPU tier.
The tiering logic (``tier_for_vram``) is pure and unit-testable.
"""
from __future__ import annotations

# Tier table: (max_vram_mb_inclusive, config). First match wins; last is the
# catch-all for high-end cards.
_TIERS = [
    (0,      {"tier": "cpu",     "model": "gemma:2b",  "max_batch_size": 1024,
              "num_ctx": 2048,  "note": "no GPU detected — lean CPU profile"}),
    (6144,   {"tier": "6gb",     "model": "gemma:2b",  "max_batch_size": 4096,
              "num_ctx": 4096,  "note": "GTX 1060-class — capped batch + free pools after use"}),
    (12288,  {"tier": "12gb",    "model": "llama3:8b", "max_batch_size": 8192,
              "num_ctx": 8192,  "note": "mid-range GPU"}),
    (float("inf"), {"tier": "highend", "model": "llama3:8b", "max_batch_size": 16384,
                    "num_ctx": 16384, "note": "high-VRAM GPU"}),
]


def profile_vram_mb() -> int | None:
    """Total VRAM of GPU 0 in MB via pynvml, or None if unavailable."""
    try:
        import pynvml
        pynvml.nvmlInit()
        try:
            h = pynvml.nvmlDeviceGetHandleByIndex(0)
            info = pynvml.nvmlDeviceGetMemoryInfo(h)
            return int(info.total // (1024 * 1024))
        finally:
            pynvml.nvmlShutdown()
    except Exception:
        return None


def tier_for_vram(vram_mb: int | None) -> dict:
    """Pure: map a VRAM size (MB) to an execution-config tier."""
    if not vram_mb or vram_mb <= 0:
        return dict(_TIERS[0][1])
    for ceiling, cfg in _TIERS[1:]:
        if vram_mb <= ceiling:
            return dict(cfg)
    return dict(_TIERS[-1][1])


def free_gpu_pools() -> bool:
    """Best-effort explicit memory-pool clearance after host retrieval (prevents
    OOM on small cards). No-ops cleanly when no CUDA framework is present."""
    freed = False
    try:                                   # PyTorch
        import torch
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
            freed = True
    except Exception:
        pass
    try:                                   # CuPy
        import cupy
        cupy.get_default_memory_pool().free_all_blocks()
        freed = True
    except Exception:
        pass
    return freed


def apply_profile() -> dict:
    """Profile VRAM and return the active config, annotated with the reading."""
    vram = profile_vram_mb()
    cfg = tier_for_vram(vram)
    cfg["vram_mb"] = vram
    return cfg
