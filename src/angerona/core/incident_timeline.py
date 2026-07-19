"""core/incident_timeline.py — reconstruct incidents as MITRE kill-chains.

The heatmap shows *which* techniques fired; this shows the *story*: it groups
related HIGH+ events (by process / pid) into an **incident** and lays the
techniques out along the ATT&CK kill-chain (Recon → … → Impact). That's what an
analyst actually wants during triage — "what did this thing do, in order, and
how far did it get."

Pure read side: it consumes events already on the EventBus (via ``recent()``),
maps their MITRE tags to tactics using attack_tracker's catalog, and returns a
serialisable timeline. ``write_timeline()`` persists it to shared_logs so the
dashboard / mobile / an artifact can render it. No network, no host change.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from angerona.core.attack_tracker import (
    TACTIC_ORDER, _TID_TO_META,
)

# tactic_id → (order_index, short_name)
_TACTIC_INDEX: dict[str, tuple[int, str]] = {
    tid: (i, name) for i, (tid, name) in enumerate(TACTIC_ORDER)
}
_STAGE_LABEL = {tid: name for tid, name in TACTIC_ORDER}

# Tactics that mean the attacker reached the damaging end of the chain.
_TERMINAL_TACTICS = {"TA0010", "TA0040"}          # Exfiltration, Impact
_SERIOUS_TACTICS = {"TA0006", "TA0008", "TA0011"} # Cred Access, Lateral, C2


def _extract_tids(ev) -> list[str]:
    """Pull MITRE technique ids off an event (details dict or attribute)."""
    out: list[str] = []
    det = getattr(ev, "details", None) or {}
    for src in (det.get("mitre") if isinstance(det, dict) else None,
                getattr(ev, "mitre", None)):
        if not src:
            continue
        if isinstance(src, (list, tuple, set)):
            out.extend(str(t) for t in src)
        else:
            # may be "T1071" or "T1091/T1204"
            out.extend(part.strip() for part in str(src).replace(",", "/").split("/"))
    return [t for t in out if t.startswith("T")]


# Techniques emitted by Angerona modules that aren't in the curated heatmap
# catalog — mapped to their primary ATT&CK tactic so incidents place correctly.
_SUPPLEMENT_TACTIC: dict[str, str] = {
    "T1091": "TA0001",   # Replication Through Removable Media (Initial Access)
    "T1200": "TA0001",   # Hardware Additions
    "T1052": "TA0010",   # Exfiltration Over Physical Medium
    "T1571": "TA0011",   # Non-Standard Port (C2)
    "T1074": "TA0009",   # Data Staged (Collection)
}


def _tactic_of(tid: str) -> tuple[str, str, int]:
    """Return (tactic_id, tactic_name, order) for a technique id (parent-fallback)."""
    meta = _TID_TO_META.get(tid) or _TID_TO_META.get(tid.split(".")[0])
    tactic_id = meta[1] if meta else _SUPPLEMENT_TACTIC.get(
        tid, _SUPPLEMENT_TACTIC.get(tid.split(".")[0], ""))
    if not tactic_id:
        # Truly unknown — place at the very start of the chain, never inflate progress.
        return ("TA0000", "Other", 0)
    order, name = _TACTIC_INDEX.get(tactic_id, (0, tactic_id))
    return (tactic_id, name, order)


def build_timeline(bus, lookback: int = 400, min_events: int = 1) -> list[dict]:
    """Group recent MITRE-tagged events into per-process incident kill-chains.

    Returns a list of incident dicts sorted by how far along the chain they got
    (most advanced / most recent first).
    """
    events = list(bus.recent(lookback)) if bus is not None else []
    incidents: dict[str, dict] = {}

    for ev in events:
        tids = _extract_tids(ev)
        if not tids:
            continue
        det = getattr(ev, "details", None) or {}
        pid = det.get("pid") if isinstance(det, dict) else None
        name = (det.get("name") if isinstance(det, dict) else None) or getattr(ev, "module", "?")
        key = f"pid:{pid}" if isinstance(pid, int) else f"mod:{getattr(ev,'module','?')}"

        inc = incidents.setdefault(key, {
            "key": key, "pid": pid, "actor": name,
            "first_ts": getattr(ev, "ts", time.time()),
            "last_ts": getattr(ev, "ts", time.time()),
            "stages": {},          # tactic_id -> stage dict
            "event_count": 0,
        })
        inc["event_count"] += 1
        ts = getattr(ev, "ts", time.time())
        inc["first_ts"] = min(inc["first_ts"], ts)
        inc["last_ts"] = max(inc["last_ts"], ts)
        inc["actor"] = name or inc["actor"]

        for tid in set(tids):
            tactic_id, tactic_name, order = _tactic_of(tid)
            stage = inc["stages"].setdefault(tactic_id, {
                "tactic": tactic_id, "tactic_name": tactic_name,
                "order": order, "techniques": {}, "first_ts": ts, "last_ts": ts,
            })
            stage["first_ts"] = min(stage["first_ts"], ts)
            stage["last_ts"] = max(stage["last_ts"], ts)
            tinfo = stage["techniques"].setdefault(tid, {
                "tid": tid, "label": (_TID_TO_META.get(tid) or ("?",))[0],
                "count": 0, "sample": (getattr(ev, "message", "") or "")[:140],
            })
            tinfo["count"] += 1

    # finalise: order stages along the kill chain, compute severity/progress
    out: list[dict] = []
    for inc in incidents.values():
        if inc["event_count"] < min_events:
            continue
        stages = sorted(inc["stages"].values(), key=lambda s: s["order"])
        for s in stages:
            s["techniques"] = sorted(s["techniques"].values(), key=lambda t: -t["count"])
        reached = {s["tactic"] for s in stages}
        if reached & _TERMINAL_TACTICS:
            sev = "CRITICAL"
        elif reached & _SERIOUS_TACTICS:
            sev = "HIGH"
        elif len(stages) >= 3:
            sev = "MEDIUM"
        else:
            sev = "LOW"
        max_order = max((s["order"] for s in stages), default=0)
        out.append({
            **{k: inc[k] for k in ("key", "pid", "actor", "event_count")},
            "first_seen": time.strftime("%H:%M:%S", time.localtime(inc["first_ts"])),
            "last_seen": time.strftime("%H:%M:%S", time.localtime(inc["last_ts"])),
            "severity": sev,
            "stages": [
                {"tactic": s["tactic"], "tactic_name": s["tactic_name"],
                 "techniques": s["techniques"]}
                for s in stages
            ],
            "chain": " → ".join(s["tactic_name"] for s in stages),
            "progress_pct": min(100, round(100 * (max_order + 1) / len(TACTIC_ORDER))),
        })

    out.sort(key=lambda i: (i["progress_pct"], i["event_count"]), reverse=True)
    return out


def write_timeline(bus, path: str | Path | None = None) -> Path:
    """Build the timeline and persist it as JSON for dashboards / mobile."""
    if path is None:
        from angerona.core.data_paths import data_dir
        path = data_dir() / "shared_logs" / "incident_timeline.json"
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
               "incidents": build_timeline(bus)}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def self_test() -> tuple[bool, str]:
    """Feed a synthetic phishing→cred-access→C2→impact chain through the builder."""
    class _Ev:
        def __init__(self, ts, module, message, mitre, pid=None):
            self.ts, self.module, self.message = ts, module, message
            self.mitre = mitre
            self.details = {"mitre": mitre, "pid": pid, "name": "evil.exe"}

    class _Bus:
        def __init__(self, evs): self._e = evs
        def recent(self, n): return self._e[-n:]

    t0 = time.time()
    bus = _Bus([
        _Ev(t0 + 0, "ETW", "user ran macro", "T1204", pid=42),
        _Ev(t0 + 1, "ETW", "powershell spawned", "T1059.001", pid=42),
        _Ev(t0 + 2, "CREDG", "lsass dump", "T1003.001", pid=42),
        _Ev(t0 + 3, "BEAC", "beacon to C2", "T1071", pid=42),
        _Ev(t0 + 4, "VSSG", "shadow delete", "T1490", pid=42),
        _Ev(t0 + 5, "USBW", "unrelated usb", "T1091", pid=99),
    ])
    incs = build_timeline(bus)
    top = incs[0] if incs else {}
    ok = (
        len(incs) == 2 and
        top.get("pid") == 42 and
        top.get("severity") == "CRITICAL" and
        len(top.get("stages", [])) >= 4 and
        top["stages"][0]["tactic_name"] == "Execution" and       # ordered
        top["stages"][-1]["tactic_name"] == "Impact"
    )
    return ok, (f"kill-chain reconstructed: {top.get('chain','')} "
                f"({top.get('progress_pct')}% progress, sev={top.get('severity')})"
                if ok else f"failed: incidents={len(incs)} top={top!r}")
