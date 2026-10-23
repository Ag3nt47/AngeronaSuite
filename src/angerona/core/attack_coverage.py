"""core/attack_coverage.py — MITRE ATT&CK coverage map + text heatmap.

The curated registry declares shipped capabilities, not successful runtime work:
  D = detector mapping; S = available drill; R = vetted response action.
Actual readiness is separate: fresh current-generation sensor work, followed by
dated, expiring, narrowly scoped detection and response verification evidence.

The registry below is CURATED (not scraped from code — that's fragile), but the
Remediate column is cross-checked at runtime against the real ACTIONS allow-list
so the map cannot declare a response we do not ship. Existence never earns
response-verified credit; unavailable sensors and missing tests remain gaps.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List
import weakref

from angerona.core.verified_readiness import VerifiedReadiness


_readiness_ref: weakref.ReferenceType | None = None


def bind_manager(manager) -> VerifiedReadiness:
    """Install one manager-owned advisory cache after normal composition."""
    global _readiness_ref
    service = VerifiedReadiness(manager)
    _readiness_ref = weakref.ref(service)
    return service


def readiness_snapshot(manager=None) -> dict:
    service = (getattr(manager, "verified_readiness", None) if manager is not None
               else _readiness_ref() if _readiness_ref is not None else None)
    if service is not None:
        return service.snapshot(COVERAGE)
    return {"schema": "angerona.verified-readiness.v1", "available": False,
            "reason": "no live registered readiness service", "history": [],
            "techniques": [{"tid": t.tid, "stage": "declared", "collecting": False,
                            "sources": [], "evidence": None,
                            "gaps": ["no live registered readiness service"]} for t in COVERAGE]}


@dataclass(frozen=True)
class Technique:
    tid: str
    name: str
    tactic: str
    detect: List[str] = field(default_factory=list)      # module names
    simulate: List[str] = field(default_factory=list)    # drill names
    remediate: List[str] = field(default_factory=list)   # remediation_actions keys


# Ordered by the ATT&CK kill-chain tactics. ``remediate`` lists executable,
# postcondition-verifiable actions only; review-only proposals (including
# driver-service disablement) deliberately do not count as response coverage.
COVERAGE: List[Technique] = [
    Technique("T1566", "Phishing (lure)", "Initial Access",
              simulate=["Shark Attack"]),
    Technique("T1059", "Command & Scripting Interpreter", "Execution",
              detect=["Persistence Sweep", "Process Monitor"]),
    Technique("T1053.005", "Scheduled Task", "Execution/Persistence",
              detect=["Persistence Sweep"]),
    Technique("T1547.001", "Registry Run Keys / Startup Folder", "Persistence",
              detect=["Persistence Sweep"]),
    Technique("T1547.004", "Winlogon Helper", "Persistence",
              detect=["Persistence Sweep"]),
    Technique("T1543.003", "Windows Service", "Persistence/Priv Esc",
              detect=["Persistence Sweep"]),
    Technique("T1546.003", "WMI Event Subscription", "Persistence",
              detect=["Persistence Sweep"], simulate=["Red Team"]),
    Technique("T1068", "Exploitation for Priv Esc (BYOVD)", "Privilege Escalation",
              detect=["File Integrity Monitor", "Intel Sync"],
              simulate=["Shark Attack"]),
    Technique("T1562", "Impair Defenses (AMSI / Defender)", "Defense Evasion",
              simulate=["Red Team"]),
    Technique("T1070", "Indicator Removal (log clear)", "Defense Evasion",
              simulate=["Red Team"]),
    Technique("T1112", "Modify Registry", "Defense Evasion",
              detect=["Persistence Sweep"]),
    Technique("T1003", "OS Credential Dumping (LSASS)", "Credential Access",
              simulate=["Red Team"], remediate=["registry_hardening"]),
    Technique("T1057", "Process Discovery", "Discovery",
              detect=["Process Monitor"], simulate=["Red Team"]),
    Technique("T1082", "System Information Discovery", "Discovery",
              simulate=["Red Team"]),
    Technique("T1021", "Remote Services (lateral)", "Lateral Movement",
              detect=["Network Monitor"]),
    Technique("T1071", "Application Layer Protocol (C2)", "Command and Control",
              detect=["Network Monitor", "Network Protocol Deep Decoder"]),
    Technique("T1041", "Exfiltration Over C2 Channel", "Exfiltration",
              detect=["Network Monitor"], simulate=["Shark Attack"]),
    Technique("T1486", "Data Encrypted for Impact (ransomware)", "Impact",
              detect=["File Integrity Monitor"]),
]

# Tactic order for rendering the heatmap.
_TACTIC_ORDER = [
    "Initial Access", "Execution", "Execution/Persistence", "Persistence",
    "Privilege Escalation", "Persistence/Priv Esc", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement",
    "Command and Control", "Exfiltration", "Impact",
]


def _valid_action_keys() -> set:
    """The real vetted-action allow-list — so the Remediate column can't lie."""
    try:
        from angerona.modules.remediation_actions import ACTIONS
        return {a.key for a in ACTIONS}
    except Exception:
        return set()


def summary() -> dict:
    """Separate curated declarations from current verified runtime readiness."""
    valid = _valid_action_keys()
    d = s = r = 0
    for t in COVERAGE:
        d += bool(t.detect)
        s += bool(t.simulate)
        r += bool(valid and any(k in valid for k in t.remediate))
    n = len(COVERAGE)
    # "Covered" = at least a detection OR a remediation for the technique.
    covered = sum(1 for t in COVERAGE
                  if t.detect or any(k in valid for k in t.remediate))
    live = readiness_snapshot()
    states = live["techniques"]
    collecting = sum(bool(row["collecting"]) for row in states)
    tested = sum(row["stage"] in {"detection-tested", "response-verified"} for row in states)
    responded = sum(row["stage"] == "response-verified" for row in states)
    return {"techniques": n, "detect": d, "simulate": s, "remediate": r,
            "declared_covered": covered,
            "declared_coverage_pct": round(100 * covered / n) if n else 0,
            "collecting": collecting, "detection_tested": tested, "response_verified": responded,
            "covered": tested, "coverage_pct": round(100 * tested / n) if n else 0}


def render() -> str:
    """Compact text heatmap: one row per technique, D/S/R capability flags,
    grouped by tactic. '·' = gap. Cross-checks remediation against ACTIONS."""
    valid = _valid_action_keys()
    by_tactic: dict = {}
    for t in COVERAGE:
        by_tactic.setdefault(t.tactic, []).append(t)

    def flag(present, ch):
        return ch if present else "·"

    readiness = {r["tid"]: r for r in readiness_snapshot()["techniques"]}
    lines = ["MITRE ATT&CK declarations — D=Detect S=Simulate R=Remediate (· = gap)",
             "Readiness requires fresh sensor work; scoped test/response proof expires.",
             "=" * 72]
    order = _TACTIC_ORDER + [x for x in by_tactic if x not in _TACTIC_ORDER]
    for tactic in order:
        techs = by_tactic.get(tactic)
        if not techs:
            continue
        lines.append(f"\n[{tactic}]")
        for t in techs:
            r_ok = bool(valid and any(k in valid for k in t.remediate))
            caps = (flag(t.detect, "D") + flag(t.simulate, "S") + flag(r_ok, "R"))
            who = t.detect or t.remediate or t.simulate
            src = f"  ({who[0]})" if who else ""
            state = readiness.get(t.tid, {})
            lines.append(f"  {caps}  {t.tid:<11} {t.name}{src}  [{state.get('stage', 'declared')}]")
            if state.get("gaps"):
                lines.append("       gap: " + "; ".join(state["gaps"]))
    s = summary()
    lines.append("\n" + "-" * 72)
    lines.append(f"Declared {s['declared_covered']}/{s['techniques']}; collecting={s['collecting']}; "
                 f"detection-tested={s['detection_tested']}; response-verified={s['response_verified']}.")
    lines.append("Practice proof covers inert marker/process controls only, not real exploit coverage.")
    return "\n".join(lines)
