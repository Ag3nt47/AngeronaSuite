"""core/cortex.py — the Angerona Cortex: a unified correlation brain.

Angerona has ~60 modules that each emit alerts independently. Cortex turns those
independent signals into ONE reasoning layer: a live entity graph where every
event contributes a decay-weighted signal to the entities it touches (process,
file, user, remote IP, …), and a per-entity **malice score** rises as *multiple
independent weak signals converge on the same entity*.

The insight: three unrelated MEDIUMs are noise, but three MEDIUMs from three
different modules across three ATT&CK tactics on the SAME process are one HIGH —
"this process is bad, here's the chain." Cortex makes that fusion explicit and
explainable (it reports WHICH signals, modules and tactics drove a score).

Additive + read-only: it subscribes to the EventBus, never emits or acts, and is
bounded (capped entities/signals, time decay). Wire with `attach(bus)` at startup;
read with `snapshot()` from the GUI. Local-only, no network.
"""
from __future__ import annotations

import math
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

try:
    from angerona.core.eventbus import Severity
    _SEV_WEIGHT = {
        Severity.INFO: 0.0, Severity.LOW: 1.0, Severity.MEDIUM: 2.0,
        Severity.HIGH: 4.0, Severity.CRITICAL: 8.0,
    }
except Exception:  # pragma: no cover - standalone/test
    Severity = None
    _SEV_WEIGHT = {}

# tuning
_HORIZON_S   = 1800.0   # signal weight decays with this exponential horizon (30 min)
_MAX_ENTITIES = 500     # evict lowest-score/stale beyond this
_MAX_SIGNALS  = 60      # per-entity recent-signal cap
_SCALE_K      = 4.2     # maps fused raw score into the ~0-100 band
_META_MODULES = {"Self-Test", "Status", "Console", "SOAR Automation"}
_TID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def _sev_weight(sev) -> float:
    if sev in _SEV_WEIGHT:
        return _SEV_WEIGHT[sev]
    # tolerate ints / names
    try:
        return {0: 0.0, 1: 1.0, 2: 2.0, 3: 4.0, 4: 8.0}.get(int(sev), 1.0)
    except Exception:
        return 1.0


def _techniques(details: dict) -> list[str]:
    if not isinstance(details, dict):
        return []
    raw = details.get("mitre") or details.get("technique") or details.get("mitre_tags")
    if not raw:
        return []
    if isinstance(raw, (list, tuple, set)):
        text = " ".join(str(x) for x in raw)
    else:
        text = str(raw)
    return sorted({m.group(0).split(".")[0] for m in _TID_RE.finditer(text)})


def _entities_of(event) -> list[tuple[str, str]]:
    """Extract the entities an event references. Returns [(type, id), ...]."""
    det = getattr(event, "details", None) or {}
    if not isinstance(det, dict):
        det = {}
    out: list[tuple[str, str]] = []
    pid = det.get("pid")
    if isinstance(pid, int):
        out.append(("proc", str(pid)))
    ppid = det.get("ppid")
    if isinstance(ppid, int):
        out.append(("proc", str(ppid)))
    for k in ("name", "image", "proc"):
        v = det.get(k)
        if v:
            out.append(("procname", str(v).lower().split("\\")[-1].split("/")[-1])); break
    for k in ("remote", "raddr", "ip", "dest_ip"):
        v = det.get(k)
        if v:
            out.append(("ip", str(v).split(":")[0])); break
    for k in ("path", "file", "target_path"):
        v = det.get(k)
        if v:
            out.append(("file", str(v).lower())); break
    for k in ("user", "username", "account"):
        v = det.get(k)
        if v:
            out.append(("user", str(v).lower())); break
    for k in ("mountpoint", "rule", "hash"):
        v = det.get(k)
        if v:
            out.append((k, str(v))); break
    return out


@dataclass
class Entity:
    etype: str
    eid: str
    first_ts: float = 0.0
    last_ts: float = 0.0
    signals: list = field(default_factory=list)   # {ts, module, weight, tids, msg}

    @property
    def key(self) -> str:
        return f"{self.etype}:{self.eid}"

    def add(self, ts, module, weight, tids, msg) -> None:
        if self.first_ts == 0.0:
            self.first_ts = ts
        self.last_ts = ts
        self.signals.append({"ts": ts, "module": module, "weight": weight,
                             "tids": tids, "msg": (msg or "")[:160]})
        if len(self.signals) > _MAX_SIGNALS:
            self.signals = self.signals[-_MAX_SIGNALS:]

    def score(self, now: Optional[float] = None) -> float:
        """0-100 malice score: decayed signal energy × convergence multiplier."""
        now = now if now is not None else time.time()
        base = 0.0
        modules: set[str] = set()
        tids: set[str] = set()
        for s in self.signals:
            decay = math.exp(-(now - s["ts"]) / _HORIZON_S)
            if decay < 0.02:
                continue
            base += s["weight"] * decay
            if s["weight"] > 0:
                modules.add(s["module"])
                tids.update(s["tids"])
        if base <= 0:
            return 0.0
        # Convergence: independent modules and distinct tactics fusing on ONE
        # entity is the whole point — reward it super-linearly but bounded.
        mult = 1.0 + 0.5 * (len(modules) - 1) + 0.3 * (len(tids) - 1)
        mult = max(1.0, mult)
        return min(100.0, round(base * mult * _SCALE_K, 1))

    def explain(self, now: Optional[float] = None) -> dict:
        now = now if now is not None else time.time()
        modules = sorted({s["module"] for s in self.signals if s["weight"] > 0})
        tids = sorted({t for s in self.signals for t in s["tids"]})
        recent = sorted(self.signals, key=lambda s: s["ts"], reverse=True)[:6]
        return {
            "entity": self.key, "type": self.etype, "id": self.eid,
            "score": self.score(now), "signals": len(self.signals),
            "modules": modules, "techniques": tids,
            "first_seen": time.strftime("%H:%M:%S", time.localtime(self.first_ts)),
            "last_seen": time.strftime("%H:%M:%S", time.localtime(self.last_ts)),
            "why": [f"{s['module']}: {s['msg']}" for s in recent],
        }


class Cortex:
    """Entity-graph correlation engine. Thread-safe; feed() from the bus thread,
    snapshot() from the GUI thread."""

    def __init__(self) -> None:
        self._entities: dict[str, Entity] = {}
        self._lock = threading.RLock()

    def feed(self, event) -> None:
        """Called for every published event (bus subscriber). Never raises."""
        try:
            module = getattr(event, "module", "") or ""
            if module in _META_MODULES:
                return
            weight = _sev_weight(getattr(event, "severity", None))
            ts = float(getattr(event, "ts", time.time()) or time.time())
            det = getattr(event, "details", None) or {}
            tids = _techniques(det)
            msg = getattr(event, "message", "") or ""
            ents = _entities_of(event)
            if not ents:
                return
            with self._lock:
                for etype, eid in ents:
                    key = f"{etype}:{eid}"
                    ent = self._entities.get(key)
                    if ent is None:
                        ent = Entity(etype, eid)
                        self._entities[key] = ent
                    ent.add(ts, module, weight, tids, msg)
                if len(self._entities) > _MAX_ENTITIES:
                    self._evict()
        except Exception:
            pass

    def _evict(self) -> None:
        now = time.time()
        ranked = sorted(self._entities.values(), key=lambda e: e.score(now))
        for ent in ranked[: len(self._entities) - _MAX_ENTITIES]:
            self._entities.pop(ent.key, None)

    def snapshot(self, top: int = 20, min_score: float = 1.0) -> dict:
        now = time.time()
        with self._lock:
            scored = [(e.score(now), e) for e in self._entities.values()]
        scored = [(s, e) for s, e in scored if s >= min_score]
        scored.sort(key=lambda t: t[0], reverse=True)
        top_entities = [e.explain(now) for _s, e in scored[:top]]
        hottest = top_entities[0] if top_entities else None
        return {
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "entities_tracked": len(self._entities),
            "active": len(scored),
            "top": top_entities,
            "hottest_entity": hottest["entity"] if hottest else None,
            "hottest_score": hottest["score"] if hottest else 0.0,
        }

    def top_entity_score(self) -> float:
        now = time.time()
        with self._lock:
            if not self._entities:
                return 0.0
            return max(e.score(now) for e in self._entities.values())

    def attach(self, bus) -> bool:
        """Subscribe read-only to the EventBus. Returns True on success."""
        try:
            bus.subscribe(self.feed)
            return True
        except Exception:
            return False

    def reset(self) -> None:
        with self._lock:
            self._entities.clear()


# ── module-level singleton (mirrors attack_tracker) ──────────────────────────
_cortex: Cortex | None = None


def init_cortex() -> Cortex:
    global _cortex
    if _cortex is None:
        _cortex = Cortex()
    return _cortex


def get_cortex() -> Cortex | None:
    return _cortex


def self_test() -> tuple[bool, str]:
    """Prove the fusion: converging weak signals on one entity outrank isolated
    ones, and diversity (distinct modules + tactics) drives the score."""
    if Severity is None:
        return False, "eventbus.Severity unavailable"

    class _Ev:
        def __init__(self, module, sev, msg, **details):
            self.module, self.severity, self.message = module, sev, msg
            self.details = details
            self.ts = time.time()

    cx = Cortex()
    # Entity A (pid 42): three MEDIUMs from THREE modules across THREE tactics.
    cx.feed(_Ev("CREDG", Severity.MEDIUM, "lsass touch", pid=42, mitre="T1003.001"))
    cx.feed(_Ev("BEAC", Severity.MEDIUM, "beacon", pid=42, mitre="T1071"))
    cx.feed(_Ev("VSSG", Severity.MEDIUM, "shadow delete", pid=42, mitre="T1490"))
    # Entity B (pid 99): a single isolated MEDIUM.
    cx.feed(_Ev("FIM", Severity.MEDIUM, "file changed", pid=99, mitre="T1074"))
    # Entity C (pid 7): a single HIGH (strong but lone signal).
    cx.feed(_Ev("YARA", Severity.HIGH, "rule hit", pid=7, mitre="T1027"))

    snap = cx.snapshot()
    scores = {e["entity"]: e["score"] for e in snap["top"]}
    a = scores.get("proc:42", 0.0)
    b = scores.get("proc:99", 0.0)
    c = scores.get("proc:7", 0.0)
    top = snap["hottest_entity"]
    # A (fused 3× MEDIUM/3 modules/3 tactics) must beat both a lone MEDIUM and a
    # lone HIGH, and be the hottest entity; the fusion multiplier is the point.
    ok = (a > b and a > c and top == "proc:42" and a >= 40 and b < 20)
    return ok, (f"fusion verified: proc:42={a} (3 modules/3 tactics) > lone HIGH proc:7={c} "
                f"> lone MEDIUM proc:99={b}; hottest={top}"
                if ok else f"failed: A={a} B={b} C={c} top={top}")
