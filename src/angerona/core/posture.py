"""posture.py — composite Threat Posture score (0–100) for at-a-glance awareness.

Blends four live signals into one number the operator can read in a second:

    active threats   (recent HIGH/CRITICAL detections)     up to −40
    module health    (unhealthy / stopped-but-enabled)     up to −30
    KEV exposure     (host-applicable CISA CVEs)           up to −20
    ATT&CK heat      (recent technique activity)           up to −10

100 = fully secure & healthy; lower = worse. Every input is best-effort and the
function never raises — a missing signal simply contributes 0.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from angerona.core.eventbus import Severity

_META_MODULES = {"Self-Test", "Status", "Console"}


def _band(score: int):
    """(label, hex colour) for a score."""
    if score >= 85:
        return "Secure", "#22c55e"
    if score >= 70:
        return "Guarded", "#84cc16"
    if score >= 50:
        return "Elevated", "#f59e0b"
    if score >= 30:
        return "High", "#f97316"
    return "Critical", "#ef4444"


def _threat_penalty(bus, window: float = 600.0) -> tuple[int, int]:
    """Return (penalty, active_threat_count)."""
    try:
        events = bus.recent(200)
    except Exception:
        return 0, 0
    now = time.time()
    threats = [e for e in events
               if (now - e.ts) <= window and e.severity >= Severity.HIGH
               and e.module not in _META_MODULES]
    if not threats:
        return 0, 0
    crit = sum(1 for e in threats if e.severity == Severity.CRITICAL)
    if crit:
        return min(40, 25 + crit * 5), len(threats)
    return min(40, 12 + len(threats) * 3), len(threats)


def _health_penalty(manager) -> tuple[int, int]:
    """Return (penalty, degraded_count) from enabled modules that are unhealthy
    or stopped when they should be running."""
    try:
        mods = manager.modules
    except Exception:
        return 0, 0
    enabled = 0
    degraded = 0
    for name, mod in mods.items():
        try:
            if not manager.is_enabled(name):
                continue
        except Exception:
            pass
        enabled += 1
        status = getattr(mod, "status", "")
        health = getattr(mod, "health", 100)
        if status == "error" or (status != "running") or health < 50:
            degraded += 1
    if enabled == 0:
        return 0, 0
    frac = degraded / enabled
    return int(round(frac * 30)), degraded


# Cache the KEV file read — posture() is called on a UI cadence and this file
# changes at most hourly, so re-reading + JSON-parsing it constantly is wasteful.
_KEV_CACHE: dict = {"ts": 0.0, "mtime": -1.0, "count": 0}
_KEV_TTL = 30.0


def _kev_penalty() -> tuple[int, int]:
    """Return (penalty, kev_count) from shared_logs/upstream_threats.json (cached)."""
    try:
        now = time.time()
        from angerona.core.data_paths import data_dir
        repo_root = data_dir()
        path = repo_root / "shared_logs" / "upstream_threats.json"
        if not path.exists():
            _KEV_CACHE.update(count=0, mtime=-1.0, ts=now)
            return 0, 0
        mtime = path.stat().st_mtime
        # Reuse the cached count unless the file changed or the TTL elapsed.
        if mtime == _KEV_CACHE["mtime"] and (now - _KEV_CACHE["ts"]) < _KEV_TTL:
            n = _KEV_CACHE["count"]
            return min(20, n * 4), n
        data = json.loads(path.read_text(encoding="utf-8"))
        items = data if isinstance(data, list) else data.get("threats", data.get("items", []))
        n = len(items or [])
        _KEV_CACHE.update(count=n, mtime=mtime, ts=now)
        return min(20, n * 4), n
    except Exception:
        return 0, 0


def _attack_penalty() -> int:
    """Return a small penalty from recent MITRE ATT&CK heat, if the tracker is up."""
    try:
        from angerona.core.attack_tracker import get_tracker
        tracker = get_tracker()
        if tracker is None:
            return 0
        snap = tracker.snapshot()
        heats = []
        if isinstance(snap, dict):
            for v in snap.values():
                if isinstance(v, dict) and "heat" in v:
                    heats.append(float(v.get("heat", 0)))
        hot = sum(1 for h in heats if h > 0.15)
        return min(10, hot)
    except Exception:
        return 0


def posture(bus, manager, config=None) -> dict:
    """Compute the composite posture. Returns a dict:

        {score:int, label:str, color:str, factors:{...}}
    """
    tp, threats = _threat_penalty(bus)
    hp, degraded = _health_penalty(manager)
    kp, kev = _kev_penalty()
    ap = _attack_penalty()
    score = max(0, min(100, 100 - tp - hp - kp - ap))
    label, color = _band(score)
    return {
        "score": score,
        "label": label,
        "color": color,
        "factors": {
            "active_threats": threats,
            "degraded_modules": degraded,
            "kev_exposure": kev,
            "attack_heat": ap,
        },
    }


def posture_tooltip(p: dict) -> str:
    f = p.get("factors", {})
    return (f"Threat Posture {p['score']}/100 — {p['label']}\n"
            f"• active threats (10 min): {f.get('active_threats', 0)}\n"
            f"• degraded/stopped modules: {f.get('degraded_modules', 0)}\n"
            f"• host-applicable KEV CVEs: {f.get('kev_exposure', 0)}\n"
            f"• ATT&CK heat: {f.get('attack_heat', 0)}\n"
            "Higher is safer. Click for detail.")
