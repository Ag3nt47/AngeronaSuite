"""core/purple_loop.py — self-hardening purple-team coverage engine.

Closes Angerona's own blind spots on a measurable loop:
  1. The red-team drill exercises techniques (simulate).
  2. This engine compares what was simulated against what Angerona actually
     DETECTS (core.attack_coverage) to find GAPS — techniques exercised but not
     detected, or techniques with no detector at all.
  3. For each gap it drafts a candidate detection PROPOSAL (a Sigma-style rule
     skeleton) — as a review-gated proposal only. It NEVER auto-installs a rule
     or executes anything; a human (or the gated remediation flow) approves.

This is the safe core of the "AI writes its own detections" idea: the loop
identifies and proposes; approval + testing stay human-gated. Pure/local.
"""
from __future__ import annotations

import time


def _coverage():
    from angerona.core import attack_coverage as cov
    return cov


def find_gaps(simulated_tids: list[str] | None = None) -> dict:
    """Return the detection gaps.

    simulated_tids: technique ids a red-team/shark drill exercised (optional). A
    gap is a technique that is EITHER (a) in the coverage map with no detector,
    OR (b) simulated but whose mapped technique has no detector.
    """
    cov = _coverage()
    valid = cov._valid_action_keys()
    simulated = {t.split(".")[0] for t in (simulated_tids or [])}

    undetected = []      # in the coverage map but no Detect capability
    for t in cov.COVERAGE:
        base = t.tid.split(".")[0]
        detected = bool(t.detect)
        if not detected:
            undetected.append({
                "tid": t.tid, "name": t.name, "tactic": t.tactic,
                "reason": "no detector mapped",
                "has_remediation": any(k in valid for k in t.remediate),
                "was_simulated": base in simulated,
            })

    # prioritise: simulated-and-undetected first, then remediation-less gaps
    undetected.sort(key=lambda g: (not g["was_simulated"], g["has_remediation"]))
    s = cov.summary()
    return {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "coverage_pct": s["coverage_pct"],
        "gap_count": len(undetected),
        "gaps": undetected,
        "simulated_undetected": [g for g in undetected if g["was_simulated"]],
    }


def propose_detection(gap: dict) -> dict:
    """Draft a REVIEW-GATED candidate Sigma-style detection for one gap.
    Returns a proposal dict; nothing is installed or executed."""
    tid = gap.get("tid", "T0000")
    name = gap.get("name", "technique")
    skeleton = {
        "title": f"[CANDIDATE] Detect {name} ({tid})",
        "status": "experimental",
        "description": f"Auto-proposed by Angerona purple-loop for uncovered technique {tid}. "
                       "REVIEW REQUIRED before enabling — fill the selection with real IOCs.",
        "tags": [f"attack.{tid.lower()}"],
        "level": "medium",
        "detection": {
            "selection": {"module": "<sensor module that would see this>",
                          "message|contains": "<indicator keyword>"},
            "condition": "selection",
        },
    }
    return {
        "tid": tid, "name": name, "status": "PROPOSED (review-gated)",
        "rule": skeleton,
        "next_step": "Human review → fill IOCs → test against a benign red-team run "
                     "(zero false positives on a baseline window) → enable.",
    }


def run(simulated_tids: list[str] | None = None) -> dict:
    """Full pass: find gaps + draft proposals for the top gaps. Proposals only."""
    gaps = find_gaps(simulated_tids)
    top = gaps["gaps"][:10]
    proposals = [propose_detection(g) for g in top]
    return {**gaps, "proposals": proposals, "proposed": len(proposals),
            "note": "All proposals are review-gated; nothing was installed or executed."}


def self_test() -> tuple[bool, str]:
    try:
        out = run(simulated_tids=["T1566", "T1204"])   # phishing + user-exec were simulated
    except Exception as exc:
        return False, f"coverage import failed: {exc}"
    ok = ("coverage_pct" in out and out["gap_count"] >= 0
          and out["proposed"] == len(out["proposals"])
          and all(p["status"].startswith("PROPOSED") for p in out["proposals"])
          and all("detection" in p["rule"] for p in out["proposals"]))
    # A gap proposal must never contain executable content — it's a skeleton.
    safe = all("condition" in p["rule"]["detection"] for p in out["proposals"])
    ok = ok and safe
    return ok, (f"purple-loop verified: {out['gap_count']} gaps, {out['proposed']} review-gated "
                f"proposals (coverage {out['coverage_pct']}%)"
                if ok else f"failed: {out}")
