"""core/angerona_score.py — one authoritative security score + next best action.

Angerona surfaces several indicators (threat level, posture, ATT&CK coverage %,
heatmap heat, Cortex top-entity). This collapses them into ONE explainable 0-100
score (higher = safer) plus a single ranked "do this now" recommendation — a pane
of glass instead of five gauges.

Pure function + a live convenience that reads the singletons if present. No
network, no side effects.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ScoreResult:
    score: int                 # 0-100, higher = safer
    band: str                  # SECURE / GUARDED / ELEVATED / CRITICAL
    drivers: list              # human-readable reasons
    next_action: str           # single recommended action
    detail: dict


def _band(score: int) -> str:
    if score >= 85:
        return "SECURE"
    if score >= 65:
        return "GUARDED"
    if score >= 40:
        return "ELEVATED"
    return "CRITICAL"


def compute(*, threat_level: str = "INFO", posture_pct: float = 100.0,
            coverage_pct: float = 100.0, cortex_top_score: float = 0.0,
            active_criticals: int = 0, active_highs: int = 0) -> ScoreResult:
    """Blend the inputs into a 0-100 safety score + the next best action.

    threat_level: INFO/HIGH/CRITICAL (the dashboard threat level).
    posture_pct / coverage_pct: 0-100 "good" metrics.
    cortex_top_score: 0-100 malice of the hottest entity (Cortex).
    active_criticals / active_highs: unresolved alert counts.
    """
    good = 0.5 * max(0.0, min(100.0, posture_pct)) + 0.5 * max(0.0, min(100.0, coverage_pct))

    drivers: list[str] = []
    penalty = 0.0
    tl = (threat_level or "INFO").upper()
    if tl == "CRITICAL":
        penalty += 45; drivers.append("threat level CRITICAL (-45)")
    elif tl == "HIGH":
        penalty += 22; drivers.append("threat level HIGH (-22)")

    if cortex_top_score >= 60:
        p = min(30.0, cortex_top_score * 0.4)
        penalty += p; drivers.append(f"Cortex hottest entity {cortex_top_score:.0f}/100 (-{p:.0f})")
    elif cortex_top_score >= 35:
        penalty += 10; drivers.append(f"Cortex entity elevated {cortex_top_score:.0f}/100 (-10)")

    if active_criticals:
        p = min(25.0, active_criticals * 6.0)
        penalty += p; drivers.append(f"{active_criticals} unresolved CRITICAL (-{p:.0f})")
    if active_highs:
        p = min(12.0, active_highs * 2.0)
        penalty += p; drivers.append(f"{active_highs} unresolved HIGH (-{p:.0f})")

    if coverage_pct < 70:
        drivers.append(f"detection coverage only {coverage_pct:.0f}%")
    if not drivers:
        drivers.append("no active threats; posture + coverage healthy")

    score = int(max(0, min(100, round(good - penalty))))

    # Single next-best-action, highest priority first.
    if cortex_top_score >= 60:
        action = "Contain the top Cortex entity and review its chain (Resolve Center → Detail)."
    elif active_criticals > 0 or tl == "CRITICAL":
        action = "Open the Resolve Center: triage or ignore the CRITICAL alerts to return to Secure."
    elif active_highs > 0 or tl == "HIGH":
        action = "Review the HIGH alerts in the Resolve Center."
    elif coverage_pct < 70:
        action = "Run the purple-team loop to close detection-coverage gaps."
    elif posture_pct < 80:
        action = "Address open posture weaknesses (After-Action Report → Attempt Fix)."
    else:
        action = "Secure — keep monitoring. Consider a Red Team drill to validate."

    return ScoreResult(
        score=score, band=_band(score), drivers=drivers, next_action=action,
        detail={"good_base": round(good, 1), "penalty": round(penalty, 1),
                "threat_level": tl, "posture_pct": posture_pct,
                "coverage_pct": coverage_pct, "cortex_top_score": cortex_top_score,
                "active_criticals": active_criticals, "active_highs": active_highs})


def live() -> ScoreResult:
    """Compute from the live singletons where available (best-effort)."""
    kw: dict = {}
    try:
        from angerona.core.cortex import get_cortex
        cx = get_cortex()
        if cx is not None:
            kw["cortex_top_score"] = cx.top_entity_score()
    except Exception:
        pass
    try:
        from angerona.core import attack_coverage
        kw["coverage_pct"] = attack_coverage.summary().get("coverage_pct", 100.0)
    except Exception:
        pass
    return compute(**kw)


def self_test() -> tuple[bool, str]:
    quiet = compute(threat_level="INFO", posture_pct=92, coverage_pct=85,
                    cortex_top_score=0, active_criticals=0)
    under_attack = compute(threat_level="CRITICAL", posture_pct=60, coverage_pct=70,
                           cortex_top_score=72, active_criticals=3)
    ok = (quiet.score >= 80 and quiet.band in ("SECURE", "GUARDED")
          and "Secure" in quiet.next_action
          and under_attack.score <= 40 and under_attack.band in ("ELEVATED", "CRITICAL")
          and "Contain" in under_attack.next_action)
    return ok, (f"score: quiet={quiet.score}/{quiet.band}, attack={under_attack.score}/"
                f"{under_attack.band} → '{under_attack.next_action[:40]}...'"
                if ok else f"failed: quiet={quiet} attack={under_attack}")
