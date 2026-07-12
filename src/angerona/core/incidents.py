"""core/incidents.py — live alert-to-incident correlation.

The event stream is flat: hundreds of individual alerts, each meaningless on its
own. This correlator rolls related alerts into *incidents* — a burst of activity
close together in time — and scores each incident's risk, so the analyst (and the
AI) sees "one HIGH-risk incident spanning 4 modules" instead of 40 loose lines.

Design constraints:
  * O(1) per event — this runs on the bus's publish path (producer threads), so
    it must never do real work per event beyond a couple of comparisons.
  * Never raises into the producer (a bad subscriber must not crash a module).
  * Bounded memory — a deque of the most recent incidents only.

An event joins the current OPEN incident if it arrives within WINDOW seconds of
the incident's last activity; otherwise the open incident is closed and a new one
opens. Pure INFO/low-noise bookkeeping events are ignored so they can't inflate
a score or hold an incident open forever.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional

from angerona.core.eventbus import Event, Severity

# Risk weight per severity — non-linear so one CRITICAL outweighs many INFOs.
_WEIGHT = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 3,
           Severity.HIGH: 7, Severity.CRITICAL: 15}
# Modules whose chatter should never open or extend an incident.
_IGNORE_MODULES = {"Self-Test", "Status", "Console", "StatusReporter"}
_WINDOW_SECONDS = 120          # gap that ends an incident
_MAX_INCIDENTS = 200
_MAX_EVENTS_PER_INCIDENT = 60


@dataclass
class Incident:
    iid: str
    started: float
    last: float = 0.0
    max_severity: Severity = Severity.INFO
    score: int = 0
    status: str = "open"       # "open" | "closed"
    modules: set = field(default_factory=set)
    mitre: set = field(default_factory=set)
    count: int = 0
    events: List[tuple] = field(default_factory=list)   # (ts, module, sev, message)

    def risk_band(self) -> str:
        if self.score >= 60:
            return "CRITICAL"
        if self.score >= 30:
            return "HIGH"
        if self.score >= 12:
            return "MEDIUM"
        return "LOW"

    def as_dict(self) -> dict:
        return {"id": self.iid, "started": self.started, "last": self.last,
                "status": self.status, "score": self.score, "band": self.risk_band(),
                "max_severity": self.max_severity.label, "count": self.count,
                "modules": sorted(self.modules), "mitre": sorted(self.mitre)}


class IncidentCorrelator:
    def __init__(self, window_seconds: int = _WINDOW_SECONDS) -> None:
        self.window = window_seconds
        self._incidents: Deque[Incident] = deque(maxlen=_MAX_INCIDENTS)
        self._open: Optional[Incident] = None
        self._lock = threading.Lock()
        self._seq = 0

    # ── bus subscriber (hot path — keep it cheap) ────────────────────────────
    def on_event(self, event: Event) -> None:
        try:
            if event.module in _IGNORE_MODULES or event.severity < Severity.LOW:
                return
            now = event.ts or time.time()
            with self._lock:
                inc = self._open
                if inc is None or (now - inc.last) > self.window:
                    if inc is not None:
                        inc.status = "closed"
                    self._seq += 1
                    inc = Incident(iid=f"INC-{int(now)}-{self._seq:03d}", started=now)
                    self._open = inc
                    self._incidents.append(inc)
                inc.last = now
                inc.count += 1
                inc.modules.add(event.module)
                mid = (event.details or {}).get("mitre")
                if mid:
                    inc.mitre.add(str(mid))
                if event.severity > inc.max_severity:
                    inc.max_severity = event.severity
                # Score: severity weight + a small breadth bonus (distinct modules).
                inc.score = min(100, inc.score + _WEIGHT.get(event.severity, 0)
                                + (1 if len(inc.modules) > 1 else 0))
                if len(inc.events) < _MAX_EVENTS_PER_INCIDENT:
                    inc.events.append((now, event.module, int(event.severity), event.message))
        except Exception:
            # Must never crash a producer thread.
            pass

    # ── read API (GUI / console) ─────────────────────────────────────────────
    def incidents(self, limit: int = 20) -> List[Incident]:
        with self._lock:
            items = list(self._incidents)
        return items[::-1][:limit]

    def render(self, limit: int = 12) -> str:
        incs = self.incidents(limit)
        if not incs:
            return "No incidents correlated yet."
        out = [f"{'ID':<20} {'BAND':<9} {'SCORE':>5}  {'SEV':<9} {'#EV':>4}  MODULES",
               "-" * 78]
        for i in incs:
            when = time.strftime("%H:%M:%S", time.localtime(i.started))
            mods = ", ".join(sorted(i.modules))[:32]
            flag = "•" if i.status == "open" else " "
            out.append(f"{flag}{i.iid:<19} {i.risk_band():<9} {i.score:>5}  "
                       f"{i.max_severity.label:<9} {i.count:>4}  {mods}  [{when}]")
        return "\n".join(out)

    def detail(self, iid_fragment: str) -> str:
        with self._lock:
            match = next((i for i in reversed(self._incidents)
                          if iid_fragment.lower() in i.iid.lower()), None)
        if match is None:
            return f"no incident matching '{iid_fragment}'"
        lines = [f"{match.iid}  [{match.risk_band()} risk, score {match.score}, "
                 f"{match.status}]",
                 f"  span    : {time.strftime('%H:%M:%S', time.localtime(match.started))} "
                 f"→ {time.strftime('%H:%M:%S', time.localtime(match.last))}",
                 f"  modules : {', '.join(sorted(match.modules))}",
                 f"  mitre   : {', '.join(sorted(match.mitre)) or '—'}",
                 f"  events  : {match.count} (showing up to {_MAX_EVENTS_PER_INCIDENT})",
                 "  ── timeline ──"]
        for ts, mod, sev, msg in match.events:
            lines.append(f"    {time.strftime('%H:%M:%S', time.localtime(ts))} "
                         f"[{Severity(sev).label:<8}] {mod}: {msg}")
        return "\n".join(lines)


# ── process-wide singleton (app.py subscribes it; console/GUI read it) ───────
_CORRELATOR: Optional[IncidentCorrelator] = None


def get_correlator() -> IncidentCorrelator:
    global _CORRELATOR
    if _CORRELATOR is None:
        _CORRELATOR = IncidentCorrelator()
    return _CORRELATOR
