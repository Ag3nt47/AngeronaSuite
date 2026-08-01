"""Versioned enterprise-readiness assessment for Angerona.

This is an evidence-based local snapshot, not a marketing grade. Operational
passes require runtime evidence; installed foundations remain warnings with
partial credit until exercised. Missing fleet features remain visible as
explicit gates so a healthy standalone endpoint is never mislabeled as a
complete enterprise deployment.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from angerona.core.privacy import redact_text


ASSESSMENT_VERSION = 4
EVIDENCE_SCHEMA = "angerona.enterprise-evidence/v1"


def _safe(value: object, limit: int = 1_000) -> str:
    """Keep readiness evidence public-safe, bounded, and single-record."""
    return " ".join(redact_text(str(value or ""), limit=limit).split())


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
        "detail": _safe(detail),
        "action": _safe(action),
    }


def assess(
    manager, bus, config, remediation_log=None, runtime: dict[str, object] | None = None
) -> dict[str, Any]:
    controls: list[dict[str, Any]] = []
    runtime = dict(runtime or {})

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

    extension_error = ""
    try:
        extension = dict(manager.extension_security_summary())
        unsigned_override = bool(
            extension.get("unsigned_development_override")
        )
        loaded_external = max(
            0, min(int(extension.get("loaded_external", 0)), 100_000)
        )
        signed_external = max(
            0, min(int(extension.get("signed_external", 0)), 100_000)
        )
        rejected_external = max(
            0, min(int(extension.get("rejected_external", 0)), 100_000)
        )
    except Exception as exc:
        # A missing trust summary is unknown evidence, never evidence of trust.
        extension_error = _safe(type(exc).__name__, 80) or "Exception"
        unsigned_override = False
        loaded_external = 0
        signed_external = 0
        rejected_external = 0
    extension_ok = (
        not extension_error
        and not unsigned_override
        and signed_external == loaded_external
    )
    if extension_error:
        extension_status, extension_score = "gap", 0
        extension_detail = (
            "Extension trust state is unknown because its summary failed "
            f"({extension_error}); no trust conclusion was made."
        )
        extension_action = (
            "Restore extension inventory reporting and rerun the trust assessment."
        )
    else:
        extension_status = "pass" if extension_ok else "warn"
        extension_score = 10 if extension_ok else 4
        extension_detail = (
            f"{loaded_external} external module(s) loaded; {signed_external} carry "
            f"a trusted publisher signature; {rejected_external} were rejected "
            "before import."
        )
        extension_action = (
            "Disable ANGERONA_ALLOW_UNSIGNED_EXTERNAL_MODULES and trust only reviewed "
            "Ed25519 publisher keys."
        )
    controls.append(_control(
        "extensions.trust",
        "Signed capability extension gate",
        extension_status,
        extension_score,
        10,
        extension_detail,
        extension_action,
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
            proof = {
                "valid": False,
                "verified_receipts": 0,
                "reason": f"verification unavailable ({type(exc).__name__})",
            }
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
        "Bounded causal incident graph foundation",
        "warn",
        5,
        10,
        (
            "Entity-aware, PID-generation-aware graphing is installed as a pure "
            "read-side builder with explicit confidence and hard size limits; this "
            "snapshot does not include an exercised incident graph."
        ),
        "Exercise the graph against retained telemetry and review its confidence evidence.",
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

    inventory_error = ""
    try:
        inventory = list(manager.capability_inventory() or ())
        enabled = [row for row in inventory if row.get("enabled")]
        failed = [
            row for row in enabled
            if row.get("status") == "error" or int(row.get("health", 0)) <= 0
        ]
        degraded = [
            row for row in enabled
            if row not in failed and int(row.get("health", 0)) < 50
        ]
    except Exception as exc:
        inventory_error = _safe(type(exc).__name__, 80) or "Exception"
        inventory = []
        enabled = []
        failed = []
        degraded = []
    if inventory_error:
        health_status, health_score = "gap", 0
        health_detail = (
            "Module lifecycle state is unknown because inventory failed "
            f"({inventory_error})."
        )
    elif not inventory:
        health_status, health_score = "warn", 0
        health_detail = "No module inventory evidence is available."
    elif not enabled:
        health_status, health_score = "warn", 0
        health_detail = (
            f"{len(inventory)} module(s) were discovered, but none are enabled."
        )
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
        "Bounded local evidence retention foundation",
        "warn",
        2,
        5,
        (
            "Telemetry, incident, and remediation ledger implementations have hard "
            "retention caps; this snapshot does not prove configured retention or "
            "successful pruning."
        ),
        "Verify configured retention limits and exercise pruning against a staged dataset.",
    ))
    controls.append(_control(
        "interop.ocsf",
        "Normalized security export foundation",
        "warn",
        2,
        5,
        (
            "OCSF normalization and privacy-reviewed IR bundle libraries are installed; "
            "this snapshot has no evidence that export is configured, exercised, or "
            "validated against a published schema version."
        ),
        "Configure an export and validate its payload against a pinned OCSF schema version.",
    ))

    # Credit the shipped, tested local primitives while keeping their deployment
    # limits explicit. None of these warnings is a claim that the loopback fleet
    # preview is a production control plane.
    fleet_enabled = bool(getattr(config, "fleet_service_enabled", False))
    fleet_running = runtime.get("fleet_service") == "running"
    identity_state = _safe(runtime.get("endpoint_identity", "not-initialized"), 40)
    registered_devices = max(
        0, min(int(runtime.get("registered_devices", 0) or 0), 100_000)
    )
    ingestion_state = _safe(runtime.get("fleet_ingestion", "unknown"), 40)
    stored_events = max(
        0, min(int(runtime.get("stored_events", 0) or 0), 100_000_000)
    )
    duplicate_retries = max(
        0, min(int(runtime.get("duplicate_retries", 0) or 0), 100_000_000)
    )
    uncertain_clock_events = max(
        0,
        min(int(runtime.get("uncertain_clock_events", 0) or 0), 100_000_000),
    )
    api_contract_sha256 = _safe(
        runtime.get("fleet_api_contract_sha256", "unavailable"), 80
    )
    controls.extend([
        _control(
            "fleet.enrollment",
            "Endpoint identity and enrollment foundation",
            "warn",
            6,
            10,
            (
                "Ed25519 per-endpoint identity, proof-of-possession enrollment, "
                "key rotation, revocation states, signed connection envelopes, and "
                "durable replay protection are implemented locally."
            ),
            (
                "Deploy an external certificate authority and mutually authenticated "
                "TLS transport; prefer non-exportable hardware-backed endpoint keys."
            ),
        ),
        _control(
            "fleet.rbac",
            "Scoped role-based access control foundation",
            "warn",
            5,
            8,
            (
                "Nine least-privilege standard roles, explicit-deny precedence, "
                "tenant/fleet scopes, expiring service accounts, binding-time "
                "separation of duties, idempotent decisions, and authenticated "
                "decision receipts are available as local control-plane primitives."
            ),
            (
                "Connect the authorization layer to an external identity provider, "
                "organization lifecycle, and append-only administrator ledger."
            ),
        ),
        _control(
            "fleet.policy",
            "Signed policy and content rollout foundation",
            "warn",
            5,
            7,
            (
                "Ed25519 policy bundles support fleet/group/local precedence, locked "
                "keys, staged and canary rollout, dry-run diffs, last-known-good "
                "fallback, expiry, and two-person approval for high-impact changes."
            ),
            "Add authenticated fleet distribution, rollout health gates, and rollback orchestration.",
        ),
        _control(
            "fleet.scale",
            "Tenant-isolated local fleet preview",
            "warn",
            4 if fleet_running else 3,
            5,
            (
                "The authenticated loopback service is running with a "
                f"{identity_state} endpoint identity and {registered_devices} "
                "registered device record(s). Tenant-scoped inventory, "
                "device-bound deduplicated ingestion, quarantine, signed receipts, "
                f"and a versioned API contract are active. Ingestion is {ingestion_state}; "
                f"{stored_events} event(s) are stored, {duplicate_retries} duplicate "
                f"ingestion attempt(s) were deduplicated, and {uncertain_clock_events} "
                "carry uncertain endpoint clock evidence."
                if fleet_running else
                "Tenant-scoped inventory, device-bound deduplicated ingestion, "
                "clock-quality evidence, quarantine, signed receipts, and a versioned "
                "API contract are installed; the loopback preview is "
                + ("awaiting restart." if fleet_enabled else "disabled.")
            ),
            "Deploy an optional high-availability ingestion/search tier and prove tenant isolation under load.",
        ),
        _control(
            "operations.recovery",
            "Encrypted backup and controlled restore foundation",
            "warn",
            7,
            10,
            (
                "Streaming authenticated encryption, SQLite-safe snapshots, bounded "
                "manifests, restore planning, independent approval, and verified "
                "restore receipts are implemented."
            ),
            "Schedule backups and prove recovery point and recovery time objectives on a separate host.",
        ),
        _control(
            "supply_chain.release",
            "Verifiable release and update foundation",
            "warn",
            6,
            10,
            (
                "Strict signed release envelopes, safe update extraction, preflight "
                "checks, staged-install plans, CycloneDX inventory, SLSA provenance, "
                "and content-addressed quality evidence are implemented."
            ),
            "Apply an externally protected publisher signature and enforce repository release gates.",
        ),
        _control(
            "audit.export",
            "Privacy-minimized audit export foundation",
            "warn",
            3,
            8,
            (
                "Bounded tenant/scope/time export code minimizes fields, tokenizes "
                "actors, redacts free text, chains records, and provides shared-secret "
                "HMAC authentication for its manifest; this snapshot does not show an "
                "operational export."
            ),
            (
                "Configure and exercise an audit export, protect and rotate its shared "
                "HMAC key, and verify the resulting manifest."
            ),
        ),
    ])

    # Production gates are intentionally separate from the local engineering
    # score. This prevents a missing external dependency from hiding the quality
    # of the local foundation, while making it impossible to mistake the score
    # for General Availability certification.
    external_gates = [
        {
            "id": "production.transport",
            "name": "Mutual Transport Layer Security (mTLS) fleet transport",
            "status": "external-required",
            "detail": "Loopback preview only; no remote listener is enabled.",
        },
        {
            "id": "production.identity",
            "name": "Single Sign-On (SSO) / OpenID Connect (OIDC)",
            "status": "external-required",
            "detail": "No organization identity provider is configured by the local application.",
        },
        {
            "id": "production.availability",
            "name": "High availability and disaster-recovery proof",
            "status": "external-required",
            "detail": "Clustering and independent-host recovery drills require deployment infrastructure.",
        },
        {
            "id": "production.publisher",
            "name": "Protected release publisher identity",
            "status": "external-required",
            "detail": "Publisher signing keys and repository enforcement must be established outside the source tree.",
        },
    ]

    score = sum(int(row["score"]) for row in controls)
    maximum = sum(int(row["max_score"]) for row in controls)
    percent = round((score / maximum) * 100) if maximum else 0
    gaps = [row for row in controls if row["status"] == "gap"]
    warnings = [row for row in controls if row["status"] == "warn"]
    return {
        "assessment_version": ASSESSMENT_VERSION,
        "deployment_class": "fleet-preview foundation",
        "runtime": {
            "fleet_service": "running" if fleet_running else (
                "configured" if fleet_enabled else "disabled"
            ),
            "fleet_transport": "loopback",
            "endpoint_identity": identity_state,
            "registered_devices": registered_devices,
            "fleet_ingestion": ingestion_state,
            "stored_events": stored_events,
            "duplicate_retries": duplicate_retries,
            "uncertain_clock_events": uncertain_clock_events,
            "fleet_api_contract_sha256": api_contract_sha256,
        },
        "score": score,
        "max_score": maximum,
        "percent": percent,
        "band": (
            "advanced local enterprise foundation" if percent >= 85
            else "strong standalone foundation" if percent >= 70
            else "developing foundation"
        ),
        "controls": controls,
        "external_gates": external_gates,
        "summary": {
            "passed": sum(1 for row in controls if row["status"] == "pass"),
            "warnings": len(warnings),
            "gaps": len(gaps),
            "external_gates": len(external_gates),
            "modules": len(inventory),
            "enabled_modules": len(enabled),
        },
        "next_priorities": [
            row["action"] for row in gaps + warnings if row.get("action")
        ][:8],
    }


def evidence_pack(report: dict[str, Any]) -> dict[str, Any]:
    """Create deterministic, public-safe, content-addressed readiness evidence."""
    controls = []
    for row in list(report.get("controls", ()))[:64]:
        controls.append({
            "id": _safe(row.get("id"), 100),
            "name": _safe(row.get("name"), 200),
            "status": _safe(row.get("status"), 30),
            "score": int(row.get("score", 0)),
            "max_score": int(row.get("max_score", 0)),
            "detail": _safe(row.get("detail"), 1_000),
            "action": _safe(row.get("action"), 1_000),
        })
    gates = []
    for row in list(report.get("external_gates", ()))[:32]:
        gates.append({
            "id": _safe(row.get("id"), 100),
            "name": _safe(row.get("name"), 200),
            "status": _safe(row.get("status"), 30),
            "detail": _safe(row.get("detail"), 1_000),
        })
    core = {
        "schema": EVIDENCE_SCHEMA,
        "assessment_version": int(report.get("assessment_version", 0)),
        "deployment_class": _safe(report.get("deployment_class"), 100),
        "score": int(report.get("score", 0)),
        "max_score": int(report.get("max_score", 0)),
        "percent": int(report.get("percent", 0)),
        "band": _safe(report.get("band"), 100),
        "runtime": {
            "fleet_service": _safe(
                dict(report.get("runtime", {})).get("fleet_service"), 40
            ),
            "fleet_transport": _safe(
                dict(report.get("runtime", {})).get("fleet_transport"), 40
            ),
            "endpoint_identity": _safe(
                dict(report.get("runtime", {})).get("endpoint_identity"), 40
            ),
            "registered_devices": max(0, min(int(
                dict(report.get("runtime", {})).get("registered_devices", 0) or 0
            ), 100_000)),
            "fleet_ingestion": _safe(
                dict(report.get("runtime", {})).get("fleet_ingestion"), 40
            ),
            "stored_events": max(0, min(int(
                dict(report.get("runtime", {})).get("stored_events", 0) or 0
            ), 100_000_000)),
            "duplicate_retries": max(0, min(int(
                dict(report.get("runtime", {})).get(
                    "duplicate_retries", 0
                ) or 0
            ), 100_000_000)),
            "uncertain_clock_events": max(0, min(int(
                dict(report.get("runtime", {})).get(
                    "uncertain_clock_events", 0
                ) or 0
            ), 100_000_000)),
            "fleet_api_contract_sha256": _safe(
                dict(report.get("runtime", {})).get(
                    "fleet_api_contract_sha256"
                ),
                80,
            ),
        },
        "controls": controls,
        "external_gates": gates,
    }
    canonical = json.dumps(
        core, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    if len(canonical) > 128 * 1024:
        raise ValueError("enterprise evidence exceeds 128 KiB")
    return {
        **core,
        "evidence_sha256": hashlib.sha256(canonical).hexdigest(),
        "privacy": "Public-safe summary; no hostnames, usernames, paths, keys, or event payloads.",
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
    gates = report.get("external_gates", [])
    if gates:
        lines.extend(("", "PRODUCTION DEPLOYMENT GATES (not included in local score)"))
        for row in gates:
            lines.append(f"[EXTERNAL] {row.get('name')}")
            lines.append(f"  {row.get('detail', '')}")
    return "\n".join(lines)
