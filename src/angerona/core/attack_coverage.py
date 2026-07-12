"""core/attack_coverage.py — MITRE ATT&CK coverage map + text heatmap.

Turns "we detect stuff" into a defensible, honest matrix: for every technique the
suite touches, which of the three capabilities we actually have —
  D = Detect      (a live sensor/module raises on it)
  S = Simulate    (a red-team / shark drill exercises it, so detection is tested)
  R = Remediate   (a vetted action in remediation_actions.py can respond)

The registry below is CURATED (not scraped from code — that's fragile), but the
Remediate column is cross-checked at runtime against the real ACTIONS allow-list
so the map can't silently claim a response we don't ship. Gaps are shown, not
hidden — the point of the view is to make blind spots obvious.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class Technique:
    tid: str
    name: str
    tactic: str
    detect: List[str] = field(default_factory=list)      # module names
    simulate: List[str] = field(default_factory=list)    # drill names
    remediate: List[str] = field(default_factory=list)   # remediation_actions keys


# Ordered by the ATT&CK kill-chain tactics.
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
              detect=["Persistence Sweep"], remediate=["disable_driver_service"]),
    Technique("T1546.003", "WMI Event Subscription", "Persistence",
              detect=["Persistence Sweep"], simulate=["Red Team"]),
    Technique("T1068", "Exploitation for Priv Esc (BYOVD)", "Privilege Escalation",
              detect=["File Integrity Monitor", "Intel Sync"],
              simulate=["Shark Attack"], remediate=["disable_driver_service"]),
    Technique("T1562", "Impair Defenses (AMSI / Defender)", "Defense Evasion",
              simulate=["Red Team"], remediate=["defender_hardening"]),
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
              detect=["Network Monitor"], remediate=["network_isolation"]),
    Technique("T1071", "Application Layer Protocol (C2)", "Command and Control",
              detect=["Network Monitor", "Network Protocol Deep Decoder"],
              remediate=["network_isolation"]),
    Technique("T1041", "Exfiltration Over C2 Channel", "Exfiltration",
              detect=["Network Monitor"], simulate=["Shark Attack"],
              remediate=["network_isolation"]),
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
    """Counts of techniques with each capability, plus overall coverage %."""
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
    return {"techniques": n, "detect": d, "simulate": s, "remediate": r,
            "covered": covered, "coverage_pct": round(100 * covered / n) if n else 0}


def render() -> str:
    """Compact text heatmap: one row per technique, D/S/R capability flags,
    grouped by tactic. '·' = gap. Cross-checks remediation against ACTIONS."""
    valid = _valid_action_keys()
    by_tactic: dict = {}
    for t in COVERAGE:
        by_tactic.setdefault(t.tactic, []).append(t)

    def flag(present, ch):
        return ch if present else "·"

    lines = ["MITRE ATT&CK coverage  —  D=Detect  S=Simulate  R=Remediate   (· = gap)",
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
            lines.append(f"  {caps}  {t.tid:<11} {t.name}{src}")
    s = summary()
    lines.append("\n" + "-" * 72)
    lines.append(f"{s['covered']}/{s['techniques']} techniques covered "
                 f"({s['coverage_pct']}%)  ·  detect={s['detect']}  "
                 f"simulate={s['simulate']}  remediate={s['remediate']}")
    return "\n".join(lines)
