"""core/alert_ack.py — acknowledge / ignore individual alerts.

The dashboard threat level is driven by recent HIGH/CRITICAL events. Some of
those are false positives or already-handled. This lets the operator ACKNOWLEDGE
(ignore) a specific alert from the Resolve Center: the alert is flagged and kept
with a history, and — crucially — EXCLUDED from the threat-level calculation, so
cleaning up false alerts actually brings the posture back to Secure. Every ack is
revertable.

Alerts are matched by a stable signature (module + normalised message), so an
ack also suppresses future identical repeats of a known-benign alert. Store at
``shared_logs/alert_acks.json``. Local-only; no network.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from pathlib import Path

# Volatile tokens that make otherwise-identical alerts look unique (per-run canary
# IDs, hashes, counters). Normalising them means ignoring ONE alert also suppresses
# future repeats of the same CLASS — e.g. a flood of DRILLCANARY_<hex> / "N
# consecutive canaries missed" collapses to a single ignorable signature. IP
# addresses are deliberately preserved (they're semantically meaningful).
_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_HEX_RE  = re.compile(r"(?=[0-9a-f]*\d)[0-9a-f]{8,}")   # hex run that contains a digit
_INT_RE  = re.compile(r"(?<![\d.])\d+(?![\d.])")         # standalone int, not an IP octet


def _normalize_msg(msg: str) -> str:
    msg = " ".join((msg or "").strip().lower().split())
    msg = _UUID_RE.sub("<uuid>", msg)
    msg = _HEX_RE.sub("<hex>", msg)
    msg = _INT_RE.sub("<n>", msg)
    return msg[:160]

_LOCK = threading.Lock()
_CACHE: set[str] | None = None
_CACHE_MTIME: float = -1.0
_REPO_ROOT: Path | None = None


def _repo_root() -> Path:
    global _REPO_ROOT
    if _REPO_ROOT is not None:
        return _REPO_ROOT
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "shared_logs").exists():
            _REPO_ROOT = parent
            return _REPO_ROOT
    _REPO_ROOT = here.parents[3]
    return _REPO_ROOT


def _store_path() -> Path:
    return _repo_root() / "shared_logs" / "alert_acks.json"


def signature(ev) -> str:
    """Stable CLASS signature for an event: module + normalised message (volatile
    per-run tokens stripped), so ignoring one alert clears its whole class."""
    module = str(getattr(ev, "module", "") or "")
    msg = _normalize_msg(str(getattr(ev, "message", "") or ""))
    return hashlib.sha1(f"{module}|{msg}".encode("utf-8", "replace")).hexdigest()[:16]


def load() -> dict:
    p = _store_path()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save(data: dict) -> None:
    global _CACHE, _CACHE_MTIME
    p = _store_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    _CACHE = {s for s, r in data.items() if r.get("acked")}
    try:
        _CACHE_MTIME = p.stat().st_mtime
    except Exception:
        _CACHE_MTIME = time.time()


def acked_signatures() -> set[str]:
    """Cached set of currently-acked signatures; reloads only when the file changes.
    Cheap enough to call from threat_level() on every dashboard refresh."""
    global _CACHE, _CACHE_MTIME
    p = _store_path()
    try:
        mtime = p.stat().st_mtime if p.exists() else -1.0
    except Exception:
        mtime = -1.0
    if _CACHE is None or mtime != _CACHE_MTIME:
        data = load()
        _CACHE = {s for s, r in data.items() if r.get("acked")}
        _CACHE_MTIME = mtime
    return _CACHE


def is_acked(ev) -> bool:
    return signature(ev) in acked_signatures()


def ack(ev, reason: str = "") -> dict:
    """Acknowledge/ignore *ev* (and future identical alerts). Returns its record."""
    sig = signature(ev)
    with _LOCK:
        data = load()
        rec = data.setdefault(sig, {
            "module": str(getattr(ev, "module", "") or ""),
            "sample": str(getattr(ev, "message", "") or "")[:200],
            "acked": False, "history": [],
        })
        rec["acked"] = True
        rec["reason"] = reason or rec.get("reason", "")
        rec["history"].append(_event("ack", reason))
        _save(data)
        return rec


def unack(sig_or_ev, reason: str = "") -> dict:
    """Revert an acknowledgement (accepts a signature string or an event)."""
    sig = sig_or_ev if isinstance(sig_or_ev, str) else signature(sig_or_ev)
    with _LOCK:
        data = load()
        rec = data.setdefault(sig, {"module": "", "sample": "", "acked": False, "history": []})
        rec["acked"] = False
        rec["history"].append(_event("unack", reason))
        _save(data)
        return rec


def acked_records() -> list[dict]:
    return [{"sig": s, **r} for s, r in load().items() if r.get("acked")]


def filter_active(events: list) -> list:
    """Return only events whose signature is NOT acknowledged."""
    acked = acked_signatures()
    return [e for e in events if signature(e) not in acked]


def _event(action: str, reason: str) -> dict:
    now = time.time()
    return {"action": action, "ts": now,
            "iso": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
            "reason": reason or ""}


def self_test() -> tuple[bool, str]:
    """Round-trip ack→filter→unack against an isolated temp store."""
    import tempfile
    global _store_path, _CACHE, _CACHE_MTIME
    orig = _store_path

    class _Ev:
        def __init__(self, module, message):
            self.module, self.message = module, message

    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "shared_logs").mkdir()
        _store_path = lambda: Path(td) / "shared_logs" / "alert_acks.json"  # type: ignore
        _CACHE = None; _CACHE_MTIME = -1.0
        try:
            e1 = _Ev("BEAC", "Possible C2 beacon: evil.exe → 1.2.3.4")
            e2 = _Ev("FIM", "file changed: notes.txt")
            e1b = _Ev("BEAC", "Possible C2 beacon: evil.exe → 1.2.3.4")  # identical repeat
            ack(e1, "known test host")
            a = is_acked(e1) and is_acked(e1b)           # repeat also suppressed
            b = not is_acked(e2)
            active = filter_active([e1, e2, e1b])
            filtered_ok = active == [e2]
            unack(e1, "re-open")
            c = not is_acked(e1)
            ok = a and b and filtered_ok and c
            return ok, ("ack suppresses alert + identical repeats, filter + revert verified"
                        if ok else f"failed: a={a} b={b} filt={filtered_ok} c={c}")
        finally:
            _store_path = orig  # type: ignore
            _CACHE = None; _CACHE_MTIME = -1.0
