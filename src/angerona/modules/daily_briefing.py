"""daily_briefing.py — Scheduled AI Security Briefing (Code: BRIEF).

Once a day (configurable) this module compiles what Angerona saw — alert volume
by severity, the top techniques, active incident kill-chains, and what active
defense actually did — and turns it into a short plain-English briefing. If the
local Ollama model is reachable it writes the prose; otherwise a deterministic
template is used, so a briefing is ALWAYS produced (never blocks on the LLM).

The briefing is emitted to the bus and written to shared_logs/daily_briefing.txt
(+ .json) so the dashboard, a scheduled task, or the mobile bridge can surface it.

Local-first: the only network call is to 127.0.0.1 Ollama. Read-only.

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from collections import Counter
from pathlib import Path

from angerona.core.module_base import BaseModule, Severity

_SYSTEM_PROMPT = (
    "You are a SOC analyst writing a short daily security briefing for a single "
    "Windows endpoint. Be concise, factual, and calm. 4-8 sentences. Lead with the "
    "overall posture (quiet / notable / under attack), then the most important "
    "findings and what was done about them. No markdown headers."
)


def _shared_logs() -> Path:
    from angerona.core.data_paths import data_dir
    return data_dir() / "shared_logs"


def _summarize_events(events) -> dict:
    """Turn raw bus events into a compact, countable summary (pure function)."""
    sev_counts: Counter = Counter()
    tech_counts: Counter = Counter()
    modules: Counter = Counter()
    criticals: list[str] = []
    for ev in events:
        sev = (getattr(getattr(ev, "severity", None), "name", None) or str(
            getattr(ev, "severity", ""))).upper()
        sev_counts[sev] += 1
        modules[getattr(ev, "module", "?")] += 1
        det = getattr(ev, "details", None) or {}
        mit = det.get("mitre") if isinstance(det, dict) else None
        if mit:
            for t in str(mit).replace(",", "/").split("/"):
                t = t.strip()
                if t.startswith("T"):
                    tech_counts[t] += 1
        try:
            if getattr(ev, "severity", None) is not None and ev.severity >= Severity.CRITICAL:
                criticals.append((getattr(ev, "message", "") or "")[:120])
        except Exception:
            pass
    return {
        "total": sum(sev_counts.values()),
        "by_severity": dict(sev_counts),
        "top_techniques": tech_counts.most_common(5),
        "top_modules": modules.most_common(5),
        "criticals": criticals[:5],
    }


def _read_remediation() -> dict:
    try:
        return json.loads((_shared_logs() / "remediation_stats.json").read_text("utf-8"))
    except Exception:
        return {}


def _heuristic_briefing(summary: dict, remediation: dict, incidents: list) -> str:
    """Deterministic briefing text — used when Ollama is unavailable."""
    total = summary.get("total", 0)
    crit = summary.get("by_severity", {}).get("CRITICAL", 0)
    high = summary.get("by_severity", {}).get("HIGH", 0)
    contained = remediation.get("contained", 0)
    if crit or (incidents and incidents[0].get("severity") == "CRITICAL"):
        posture = "UNDER ATTACK / serious activity"
    elif high or total > 20:
        posture = "notable activity"
    else:
        posture = "quiet"
    lines = [f"Daily security briefing — posture: {posture}.",
             f"{total} events in the review window "
             f"({crit} critical, {high} high)."]
    if summary.get("top_techniques"):
        techs = ", ".join(f"{t} (x{n})" for t, n in summary["top_techniques"])
        lines.append(f"Most-seen techniques: {techs}.")
    if incidents:
        top = incidents[0]
        lines.append(f"Top incident: {top.get('actor','?')} (pid {top.get('pid')}) reached "
                     f"{top.get('progress_pct')}% of the kill-chain — {top.get('chain','')}.")
    lines.append(f"Active defense contained {contained} process(es)."
                 if contained else "No automated containment was required.")
    if summary.get("criticals"):
        lines.append("Critical items: " + " | ".join(summary["criticals"][:3]))
    return " ".join(lines)


class DailyBriefingModule(BaseModule):
    CODE = "BRIEF"
    NAME = "Scheduled AI Security Briefing"
    name = "Scheduled AI Security Briefing"
    description = ("Compiles a daily plain-English security briefing (alert volume, top "
                   "techniques, incidents, containment) via local AI with a deterministic fallback.")
    category = "Reporting"
    version = "1.0.0"

    def __init__(self) -> None:
        super().__init__()
        self._host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        self._model = os.environ.get("ANGERONA_MODEL", "llama3")
        try:
            self._interval_s = float(os.environ.get("ANGERONA_BRIEFING_INTERVAL_H", "24")) * 3600
        except Exception:
            self._interval_s = 24 * 3600
        self._last_run = 0.0
        self._count = 0

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    def run(self) -> None:
        self.emit(f"BRIEF online — daily AI briefing every {self._interval_s/3600:.0f}h.",
                  Severity.INFO)
        # Give the suite a moment to accumulate events before the first briefing.
        self.sleep(min(60.0, self._interval_s))
        while not self.stopping:
            try:
                self._make_briefing()
                self.set_health(100, f"{self._count} briefing(s) generated")
            except Exception as exc:
                self.last_error = str(exc)
                self.set_health(70, f"briefing error: {exc}")
            # sleep in small slices so shutdown is responsive
            waited = 0.0
            while not self.stopping and waited < self._interval_s:
                self.sleep(5.0)
                waited += 5.0

    def _gather(self) -> tuple[dict, dict, list]:
        events = list(self._bus.recent(500)) if self._bus is not None else []
        summary = _summarize_events(events)
        remediation = _read_remediation()
        incidents: list = []
        try:
            from angerona.core.incident_timeline import build_timeline, write_timeline
            incidents = build_timeline(self._bus)
            write_timeline(self._bus)      # refresh the persisted timeline too
        except Exception:
            pass
        return summary, remediation, incidents

    def _ask_ollama(self, facts: str) -> str | None:
        payload = json.dumps({
            "model": self._model,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": facts},
            ],
            "stream": False,
            "keep_alive": "30m",
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self._host}/api/chat", data=payload,
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=90) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return ((data.get("message", {}) or {}).get("content", "") or "").strip() or None
        except Exception as exc:
            self.last_error = str(exc)
            return None

    def _make_briefing(self) -> None:
        summary, remediation, incidents = self._gather()
        facts = json.dumps({
            "events": summary, "remediation": remediation,
            "incidents": [{"actor": i.get("actor"), "pid": i.get("pid"),
                           "severity": i.get("severity"), "chain": i.get("chain"),
                           "progress_pct": i.get("progress_pct")}
                          for i in incidents[:5]],
        }, indent=2)
        text = self._ask_ollama(facts)
        source = "AI"
        if not text:
            text = _heuristic_briefing(summary, remediation, incidents)
            source = "rules"
        self._count += 1
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        full = f"[{stamp}] Security Briefing ({source})\n\n{text}\n"
        sev = (Severity.HIGH if summary.get("by_severity", {}).get("CRITICAL")
               else Severity.INFO)
        self.emit(f"📋 Daily briefing ready ({source}): {text[:180]}", sev,
                  briefing=text, source=source, events=summary.get("total", 0))
        try:
            root = _shared_logs(); root.mkdir(parents=True, exist_ok=True)
            (root / "daily_briefing.txt").write_text(full, encoding="utf-8")
            (root / "daily_briefing.json").write_text(json.dumps({
                "generated": stamp, "source": source, "text": text,
                "summary": summary, "remediation": remediation,
            }, indent=2, default=str), encoding="utf-8")
        except Exception:
            pass

    def self_test(self) -> tuple[bool, str]:
        """Offline: verify the summary + deterministic briefing without Ollama."""
        class _Ev:
            def __init__(self, sev, module, msg, mitre):
                self.severity, self.module, self.message = sev, module, msg
                self.details = {"mitre": mitre}
        evs = [
            _Ev(Severity.CRITICAL, "CREDG", "lsass dump", "T1003.001"),
            _Ev(Severity.HIGH, "BEAC", "beacon", "T1071"),
            _Ev(Severity.HIGH, "BEAC", "beacon", "T1071"),
            _Ev(Severity.INFO, "ETW", "ok", None),
        ]
        summary = _summarize_events(evs)
        text = _heuristic_briefing(
            summary, {"contained": 2},
            [{"actor": "evil.exe", "pid": 7, "severity": "CRITICAL",
              "chain": "Cred Access → C2", "progress_pct": 85}])
        ok = (summary["total"] == 4
              and summary["by_severity"].get("CRITICAL") == 1
              and ("T1071", 2) in summary["top_techniques"]
              and "UNDER ATTACK" in text
              and "contained 2" in text)
        return ok, ("briefing builder verified (severity tally, technique ranking, "
                    "posture + containment line)" if ok else f"failed: {summary} | {text}")


def register() -> DailyBriefingModule:
    return DailyBriefingModule()
