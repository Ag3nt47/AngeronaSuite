"""Versioned enterprise-readiness assessment for Angerona.

This is an evidence-based local snapshot, not a marketing grade. Implemented
controls receive points only when their runtime state can be checked. Missing
fleet features remain visible as explicit gaps so a healthy standalone endpoint
is never mislabeled as a complete enterprise deployment.
"""
from __future__ import annotations

from typing import Any


ASSESSMENT_VERSION = 1


def _control(
    control_id: str,
    name: str,
    status: str,
    score: int,
    maximum: int,
    detail: str,
    action: str = "",
) -> dict[str, Any]:
    return {
        "id": control_id,
        "name": name,
        "status": status,
        "score": max(0, min(int(maximum), int(score))),
        "max_score": int(maximum),
        "detail": detail,
        "action": action,
    }


def assess(manager, bus, config, remediation_log=None) -> dict[str, Any]:
    controls: list[dict[str, Any]] = []

    signed_bus = bool(getattr(bus, "integrity_enabled", False))
    controls.append(_control(
        "telemetry.integrity",
        "Authenticated event telemetry",
        "pass" if signed_bus else "gap",
        10 if signed_bus else 0,
        10,
        (
            "New EventBus records are HMAC authenticated."
            if signed_bus else
            "The EventBus is not armed with its per-install signing authority."
        ),
        "Arm the EventBus from the FlightRecorder authority before modules start.",
    ))

    try:
        extension = manager.extension_security_summary()
    except Exception as exc:
        extension = {
            "unsigned_development_override": False,
            "loaded_external": 0,
            "signed_external": 0,
            "rejected_external": 0,
            "error": str(exc),
        }
    unsigned_override = bool(extension.get("unsigned_development_override"))
    loaded_external = int(extension.get("loaded_external", 0))
    signed_external = int(extension.get("signed_external", 0))
    extension_ok = not unsigned_override and signed_external == loaded_external
    controls.append(_control(
        "extensions.trust",
        "Signed capability extension gate",
        "pass" if extension_ok else "warn",
        10 if extension_ok else 4,
        10,
        (
            f"{loaded_external} external module(s) loaded; {signed_external} carry "
            f"a trusted publisher signature; {int(extension.get('rejected_external', 0))} "
            "were rejected before import."
        ),
        (
            "Disable ANGERONA_ALLOW_UNSIGNED_EXTERNAL_MODULES and trust only reviewed "
            "Ed25519 publisher keys."
        ),
    ))

    if remediation_log is None:
        try:
            from angerona.core.remediation_log import get_log

            remediation_log = get_log()
        except Exception:
            remediation_log = None
    if remediation_log is None:
        proof = {
            "valid": True,
            "verified_receipts": 0,
            "reason": "remediation ledger is not initialized",
        }
    else:
        try:
            proof = remediation_log.verify_receipt_chain(limit=2_000)
        except Exception as exc:
            proof = {"valid": False, "verified_receipts": 0, "reason": str(exc)}
    proof_count = int(proof.get("verified_receipts", 0))
    if not proof.get("valid"):
        proof_status, proof_score = "gap", 0
    elif proof_count == 0:
        proof_status, proof_score = "warn", 6
    else:
        proof_status, proof_score = "pass", 10
    controls.append(_control(
        "remediation.proof",
        "Proof-carrying remediation",
        proof_status,
        proof_score,
        10,
        (
            f"{proof_count} retained signed receipt(s); {proof.get('reason', '')}"
        ),
        (
            "Run a verified drill remediation to create the first proof receipt."
            if proof_count == 0 else
            "Investigate and preserve the ledger if any chain verification fails."
        ),
    ))

    controls.append(_control(
        "incidents.causal_graph",
        "Bounded causal incident graph",
        "pass",
        10,
        10,
        (
            "Entity-aware, PID-generation-aware graphing is available as a pure "
            "read-side builder with explicit confidence and hard size limits."
        ),
    ))

    signed_aar = bool(getattr(config, "require_signed_aar", False))
    controls.append(_control(
        "hardening.input_integrity",
        "Signed self-hardening reports",
        "pass" if signed_aar else "warn",
        5 if signed_aar else 2,
        5,
        (
            "Unsigned or forged After-Action Reports are refused."
            if signed_aar else
            "Legacy unsigned reports can currently enter the learning pipeline."
        ),
        "Enable Require signed After-Action Reports.",
    ))

    egress_fields = (
        "aria_voice_cloud_tts",
        "aria_cloud_fallback",
        "alert_analysis_cloud_fallback",
        "aria_push_enabled",
        "aria_inbox_enabled",
        "aria_research_egress",
        "teams_bot_enabled",
        "mobile_enabled",
    )
    active_egress = [
        name for name in egress_fields if bool(getattr(config, name, False))
    ]
    controls.append(_control(
        "privacy.egress",
        "Local-first privacy boundary",
        "pass" if not active_egress else "warn",
        5 if not active_egress else 3,
        5,
        (
            "Optional cloud and remote egress paths are disabled."
            if not active_egress else
            f"Operator-enabled egress controls: {', '.join(active_egress)}."
        ),
        "Review every active connector and document its data-flow approval.",
    ))

    try:
        inventory = manager.capability_inventory()
    except Exception:
        inventory = []
    enabled = [row for row in inventory if row.get("enabled")]
    failed = [
        row for row in enabled
        if row.get("status") == "error" or int(row.get("health", 0)) <= 0
    ]
    degraded = [
        row for row in enabled
        if row not in failed and int(row.get("health", 0)) < 50
    ]
    if not inventory:
        health_status, health_score = "warn", 4
        health_detail = "Module discovery has not completed."
    elif failed:
        health_status, health_score = "gap", 2
        health_detail = (
            f"{len(failed)} of {len(enabled)} enabled modules are failed."
        )
    elif degraded:
        health_status, health_score = "warn", 7
        health_detail = (
            f"{len(degraded)} of {len(enabled)} enabled modules are degraded."
        )
    else:
        health_status, health_score = "pass", 10
        health_detail = f"{len(enabled)} enabled modules report no failed state."
    controls.append(_control(
        "operations.module_health",
        "Module lifecycle readiness",
        health_status,
        health_score,
        10,
        health_detail,
        "Resolve failed modules and require a clean staged-start readiness report.",
    ))

    controls.append(_control(
        "storage.bounds",
        "Bounded local evidence retention",
        "pass",
        5,
        5,
        "Recent telemetry, incidents, and remediation ledgers have hard retention caps.",
    ))
    controls.append(_control(
        "interop.ocsf",
        "Normalized security export",
        "pass",
        5,
        5,
        "OCSF export and privacy-reviewed IR bundle surfaces are present.",
        "Pin and validate the exported payload against a published OCSF schema version.",
    ))

    # These are deliberately visible and unscored until a real fleet control
    # plane exists. A local remote bridge is not equivalent to enterprise
    # enrollment, authorization, policy, or high availability.
    controls.extend([
        _control(
            "fleet.enrollment",
            "mTLS endpoint enrollment and device identity",
            "gap",
            0,
            10,
            "No central certificate-backed fleet enrollment authority is implemented.",
            "Build per-device identity, revocation, health, and staged agent upgrades.",
        ),
        _control(
            "fleet.rbac",
            "RBAC and immutable administrator audit",
            "gap",
            0,
            8,
            "Standalone operator controls do not yet provide organization-scoped RBAC.",
            "Add roles, tenants, approval separation, and append-only admin audit.",
        ),
        _control(
            "fleet.policy",
            "Centrally signed policy and content distribution",
            "gap",
            0,
            7,
            "Module settings are local; there is no signed fleet policy rollout.",
            "Add canary deployment, compatibility checks, rollback, and policy signatures.",
        ),
        _control(
            "fleet.scale",
            "Fleet search, retention, and high availability",
            "gap",
            0,
            5,
            "The local FlightRecorder is not a horizontally scalable enterprise index.",
            "Add an optional central OCSF ingestion tier without weakening local operation.",
        ),
    ])

    score = sum(int(row["score"]) for row in controls)
    maximum = sum(int(row["max_score"]) for row in controls)
    gaps = [row for row in controls if row["status"] == "gap"]
    warnings = [row for row in controls if row["status"] == "warn"]
    return {
        "assessment_version": ASSESSMENT_VERSION,
        "score": score,
        "max_score": maximum,
        "percent": round((score / maximum) * 100) if maximum else 0,
        "band": (
            "enterprise-ready foundation" if score >= 85
            else "strong standalone foundation" if score >= 65
            else "developing foundation"
        ),
        "controls": controls,
        "summary": {
            "passed": sum(1 for row in controls if row["status"] == "pass"),
            "warnings": len(warnings),
            "gaps": len(gaps),
            "modules": len(inventory),
            "enabled_modules": len(enabled),
        },
        "next_priorities": [
            row["action"] for row in gaps + warnings if row.get("action")
        ][:8],
    }


def render_text(report: dict[str, Any]) -> str:
    lines = [
        (
            f"Enterprise readiness: {report.get('score', 0)}/"
            f"{report.get('max_score', 100)} ({report.get('percent', 0)}%)"
            f" - {report.get('band', 'unknown')}"
        ),
        "",
    ]
    icons = {"pass": "PASS", "warn": "WARN", "gap": "GAP"}
    for row in report.get("controls", []):
        lines.append(
            f"[{icons.get(row.get('status'), 'INFO')}] "
            f"{row.get('name')}: {row.get('score')}/{row.get('max_score')}"
        )
        lines.append(f"  {row.get('detail', '')}")
        if row.get("status") != "pass" and row.get("action"):
            lines.append(f"  Next: {row['action']}")
    return "\n".join(lines)
