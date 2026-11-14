"""Threat-level calculation (calibrated to avoid false positives).

The dashboard threat level must reflect *actual threats*, not operational
chatter. Degradation notices ("Ollama offline", "YARA not configured"),
routine connection logs, and self-test/console output are NOT threats. Only
genuine HIGH/CRITICAL detections from security modules — within a recent time
window — raise the level. With nothing active, the state is SECURE.
"""
from __future__ import annotations

import math
from pathlib import PurePosixPath, PureWindowsPath
import time

from angerona.core.eventbus import Severity

# Modules whose output is meta/operational, never an intrusion signal. These
# report the SUITE's OWN state — a module crashed, a watchdog restarted, a
# self-improvement pass needs work, a synthetic probe didn't echo. That is
# important health information, but it belongs to a resilience/health indicator,
# NOT the external-threat level. Counting it as CRITICAL is what makes the
# dashboard read "Critical" when nothing malicious is actually happening.
_META_MODULES = {
    "Self-Test", "Status", "Console",
    "Watchdog Monitor", "Resilience Supervisor", "Resilience Manager",
    "Evolution Engine", "CHAOS",
    # Analysis, reporting, and self-repair layers describe evidence or the
    # suite's own state. Their HIGH result must not manufacture a second live
    # incident when the originating detector was practice/exposure/health.
    "AI Triage (Ollama)", "Speculative Triage Pre-Warm",
    "Scheduled AI Security Briefing", "Cloud CTI Escalation", "HEAL",
    # SOAR is a RESPONSE tier: its "UNDER ATTACK" is a summary of detections the
    # primary modules already emitted. Scoring it too double-counts and lets a
    # burst of upstream noise cascade the level to Critical. The underlying
    # detections still score on their own.
    "SOAR Automation", "Active Response SOAR", "Adversary Combat",
}

# Lifecycle health is recognized by exact producer contracts below.
# Untrusted file paths and prose never gain health status by containing a word.

_PRACTICE_MODULES = {
    "chaos",
    "red team",
    "red team simulation",
    "shark attack",
    "red team practice lab",
    "telemetry canary drills",
}
_EXPOSURE_MODULES = {
    "upstream threat intel sync",
    "vulnerability assessment",
    "vulnerability scanner",
    "cisa kev",
}
_EXPOSURE_KINDS = {
    "exposure",
    "passive_vulnerability",
    "vulnerability_assessment",
}
_EXPOSURE_EVENT_TYPES = {
    # Removable-media insertion and policy/approval state are local exposure
    # signals, not proof that hostile code is executing.  If a USB detector
    # later supplies explicit ``active_attack=True`` evidence, the active check
    # below deliberately wins before this classification is consulted.
    "usb_approval_required",
    "usb_approval_decision",
    "usb_approval_rejected",
    "usb_autorun_policy",
    "usb_media_removed",
    "usb_media_risk",
    "usb_pin_lockout",
}

_FLEET_UNBOUND_COUNTS = (
    "evidence_rows", "retention_drops", "reported_drops", "backpressure_devices",
    "unhealthy_devices", "enrolled_devices", "fresh_devices", "missing_devices", "stale_devices",
)
_FLEET_UNBOUND_FIELDS = frozenset({
    "schema", "health_percent", "exact_reason", "finding_code", "fabric_bound",
    "observation_only", "enforcement_performed", "response_authorized", "response_authority",
    "remote_shell_available", "arbitrary_command_available", "transport_enabled", "transport_available",
    *_FLEET_UNBOUND_COUNTS,
})


def _is_health_noise(event) -> bool:
    """Recognize current BaseModule crash envelopes, never detector prose.

    File paths, commands and evidence text can contain lifecycle words. Only
    the producer's anchored format, severity and exact bounded metadata count
    as health; unknown legacy strings retain normal threat classification.
    """
    message = getattr(event, "message", None)
    details = getattr(event, "details", None)
    severity = getattr(event, "severity", None)
    if (type(message) is not str or not 0 < len(message) <= 16384
            or type(details) is not dict or type(severity) is not Severity
            or type(details.get("traceback")) is not str
            or not 0 < len(details["traceback"]) <= 500):
        return False
    if severity is Severity.HIGH and set(details) == {"traceback"}:
        return message.startswith((
            "Module crashed (attempt 1/3), restarting in 5s: ",
            "Module crashed (attempt 2/3), restarting in 30s: ",
        ))
    if severity is not Severity.CRITICAL or set(details) != {"traceback", "crash_snapshot_outcome"}:
        return False
    outcome = details["crash_snapshot_outcome"]
    if type(outcome) is not str or outcome not in (
            "published", "published_finalization_gap", "published_durability_gap", "published_cleanup_gap",
            "held_directory", "held_accounting", "held_storage_budget", "held_custody_unknown",
            "held_space_unknown", "held_free_space", "held_capture_bound", "held_busy", "held_capture_text",
            "held_capture", "held_write", "held_publication_unknown", "held_cleanup_gap"):
        return False
    note = (
        "Crash snapshot published in diagnostics/." if outcome == "published"
        else "Crash snapshot published; finalization remains unconfirmed." if outcome.startswith("published_")
        else "Crash snapshot publication held for this process; native file-handle custody is unknown."
        if outcome == "held_custody_unknown"
        else f"Crash snapshot publication held or unconfirmed ({outcome})."
    )
    return (message.startswith("Module QUARANTINED after 3 crashes: ")
            and message.endswith(". Sensor blind — " + note))


def _is_self_or_drill(event) -> bool:
    """True for Angerona's own synthetic/drill activity (CHAOS probes, shark/
    red-team drills, self-IOC decoy traffic) so it never scores as a threat."""
    d = getattr(event, "details", None) or {}
    if not isinstance(d, dict):
        d = {}
    # Practice is an authorization decision, not a string heuristic.  Only an
    # exact, live entry registered by Angerona's in-process drill may downgrade
    # detector evidence.  A malicious file named ``_redteam_*`` (or an event
    # claiming ``simulated=True``) remains an active alert.
    try:
        from angerona.core.practice_scope import is_practice_event
        if is_practice_event(event):
            return True
    except Exception:
        # Fail closed: registry failure must never suppress a detection.
        pass
    module = str(getattr(event, "module", "") or "").strip().casefold()
    if module in _PRACTICE_MODULES:
        return True
    try:
        from angerona.core.self_ioc import is_self_ioc
    except Exception:
        return False
    for key in ("qname", "domain", "host", "origin_message"):
        v = d.get(key)
        if isinstance(v, str) and is_self_ioc(v):
            return True
    return False


def _legacy_indicator_only(event, details: dict, module: str) -> bool:
    """Recognize the precise older detector records that overstated evidence.

    Do not rewrite stored events or trust a filename/allowlist to establish
    safety. These policies only measured an indicator, even though their old
    producers set active_attack. Independent exploitation/corroboration still
    takes precedence; severity remains unchanged in the retained evidence.
    """
    if (
        details.get("active_exploitation") is True
        or details.get("threat_intel_corroborated") is True
        or details.get("entropy_corroborated") is True
    ):
        return False
    policy = details.get("detector_policy")
    # These two producers historically marked unrelated tool mentions as
    # CRITICAL + active_attack. A complete process identity distinguishes parser
    # rejection from an exact dangerous command lacking a safe response target.
    # Other critical findings and authorized responses remain active.
    if (
        module in {
            "lsass credential-access guard",
            "shadow-copy / recovery tamper guard",
        }
        and policy == "semantic-indicator-alert-only"
    ):
        pid = details.get("pid")
        birth = details.get("process_create_time")
        if type(pid) is not int or not 0 < pid <= 0xFFFFFFFF or type(birth) not in (int, float):
            return False
        try:
            if not math.isfinite(birth) or birth <= 0:
                return False
        except OverflowError:
            return False
        return (
            details.get("response_authorized") is not True
            and "response_contract" not in details
        )
    if getattr(event, "severity", Severity.INFO) > Severity.HIGH:
        return False
    if module == "memory injection scanner":
        return policy == "rwx-memory-indicator-alert-only"
    if module == "c2 beacon detector":
        return (
            policy == "cadence-indicator-alert-only"
            and details.get("threat_intel_corroborated") is False
        )
    if module == "ransomware heuristics":
        if policy == "authenticated-content-transition":
            return details.get("transition") in ("changed", "missing")
        return (
            policy == "reviewed-semantic-indicator"
            and isinstance(details.get("path"), str)
            and type(details.get("entropy")) in (int, float)
            and type(details.get("threshold")) in (int, float)
        )
    return False


# Exact collector-failure envelopes. Detection, custody and runtime-error
# records from these producers remain subject to ordinary active classification.
_COLLECTION_FAILURE_CONTRACTS = {
    "app control decision evidence": (
        Severity.HIGH, "failure_type", {
            "schema": "angerona.app-control-collection-health.v1",
            "finding_code": "app_control.collection.failed",
            "source_channel": "Microsoft-Windows-CodeIntegrity/Operational",
            "disposition": "health",
            "sensor_state": "blind",
            "collector_status": "unknown",
            "health_percent": 25,
            "collection_complete": False,
            "observation_only": True,
            "enforcement_performed": False,
            "response_authorized": False,
            "response_authority": "observe-only",
        },
    ),
    "peripheral and dma posture guard": (
        Severity.CRITICAL, "error_type", {
            "schema": "angerona.peripheral-dma-collection-health.v1",
            "finding_code": "peripheral.collection.failed",
            "collector_status": "unknown",
            "health_percent": 10,
            "collection_complete": False,
            "enforcement_performed": False,
            "unknown_state": True,
            "raw_device_identifiers_omitted": True,
            "device_control_performed": False,
            "observation_only": True,
            "malicious_firmware_protection_claimed": False,
            "firmware_and_kernel_tampering_out_of_scope": True,
            "response_authorized": False,
            "response_authority": "observe-only",
        },
    ),
    "authentication extension integrity guard": (
        Severity.HIGH, "failure_type", {
            "schema": "angerona.auth-extension-collection-health.v1",
            "finding_code": "auth_extension.collection.failed",
            "collector_status": "unknown",
            "health_percent": 15,
            "collection_complete": False,
            "observation_only": True,
            "enforcement_performed": False,
            "read_only": True,
            "response_authorized": False,
            "response_authority": "observe-only",
            "attribution": "not-assessed",
            "capability_mode": "observe",
            "egress": "none",
            "raw_paths_omitted": True,
            "credentials_collected": False,
            "lsass_memory_accessed": False,
        },
    ),
}


def _unavailable_collection_health(event, details: dict, module: str) -> bool:
    """Admit known unavailable collectors, never an arbitrary error or label."""
    contract = _COLLECTION_FAILURE_CONTRACTS.get(module)
    if contract is None:
        return False
    severity, error_field, fixed = contract
    if (
        type(getattr(event, "severity", None)) is not Severity
        or event.severity is not severity
        or set(details) != set(fixed) | {error_field, "native_error_code"}
        or any(type(details[key]) is not type(value) or details[key] != value
               for key, value in fixed.items())
    ):
        return False
    error = details[error_field]
    code = details["native_error_code"]
    if type(error) is not str or (code is not None and type(code) is not int):
        return False
    if error == "PermissionError":
        return code in (None, 5)
    if error == "FileNotFoundError":
        return code in (None, 2, 3)
    if error in ("ImportError", "ModuleNotFoundError"):
        return code is None
    # pywintypes.error reports a native Windows error rather than the Python
    # subclasses above. Missing Event Log channels are meaningful only here.
    return error == "error" and (
        code == 5
        or (module == "app control decision evidence" and code == 15007)
    )


def _bounded_coverage_notice_health(event, details: dict, module: str) -> bool:
    """Recognize two fixed coverage-only producers, never a health label alone.

    Severity and original evidence remain unchanged. These exact envelopes
    describe unavailable measurement, not an observed attacker or response.
    Unknown fields, malformed counts and other findings remain unclassified
    here; ordinary active/exposure handling still decides their disposition.
    """
    message = getattr(event, "message", None)
    if (type(details) is not dict
            or type(getattr(event, "severity", None)) is not Severity
            or event.severity is not Severity.HIGH
            or type(message) is not str):
        return False
    if module == "file integrity monitor":
        fixed = {
            "complete": False, "disposition": "health", "active_attack": False,
            "response_authorized": False,
            "count_unit": "scan coverage opportunities, not distinct file changes",
        }
        if (set(details) != set(fixed) | {
                "blocked_roots", "blocked_root_count", "omitted_blocked_roots",
                "suppressed_observations"}
                or any(type(details[key]) is not type(value) or details[key] != value
                       for key, value in fixed.items())):
            return False
        roots = details["blocked_roots"]
        count = details["blocked_root_count"]
        omitted = details["omitted_blocked_roots"]
        suppressed = details["suppressed_observations"]
        if (type(roots) is not list
                or type(count) is not int or not 0 < count <= 0x7fffffffffffffff
                or type(omitted) is not int or omitted < 0
                or type(suppressed) is not int or not 0 <= suppressed <= 0x7fffffffffffffff
                or len(roots) != min(count, 32) or omitted != count - len(roots)):
            return False
        paths = []
        for row in roots:
            if (type(row) is not dict or set(row) != {"root", "reason", "blocking_object"}
                    or type(row["root"]) is not str or not 0 < len(row["root"]) <= 32768
                    or type(row["reason"]) is not str or not 0 < len(row["reason"]) <= 500
                    or type(row["blocking_object"]) is not str or len(row["blocking_object"]) > 500
                    or any("\x00" in row[key] for key in ("root", "reason", "blocking_object"))
                    or not (PurePosixPath(row["root"]).is_absolute()
                            or PureWindowsPath(row["root"]).is_absolute())):
                return False
            paths.append(row["root"])
        return (paths == sorted(set(paths))
                and message == "FIM coverage incomplete: " + roots[0]["reason"])
    if module == "zero-trust network path monitor":
        fixed = {
            "schema": "angerona.network-trust-finding.v1",
            "finding_type": "network.telemetry_incomplete", "trust_label": "untrusted",
            "endpoint_resources_trusted": False, "local_network_identifiers_omitted": True,
            "response_authorized": False, "response_authority": "observe-only",
        }
        if (set(details) != set(fixed) | {
                "path_token", "link_kind", "evidence", "recommendations"}
                or any(type(details[key]) is not type(value) or details[key] != value
                       for key, value in fixed.items())
                or message != ("Zero-trust network finding: required per-interface "
                               "or address-family evidence is incomplete")
                or type(details["path_token"]) is not str
                or len(details["path_token"]) != 28
                or not details["path_token"].startswith("tok_")
                or any(char not in "0123456789abcdef" for char in details["path_token"][4:])
                or type(details["link_kind"]) is not str
                or details["link_kind"] not in ("wifi", "ethernet")
                or type(details["recommendations"]) is not list
                or details["recommendations"] != ["restore-network-inventory-sources", "keep-path-untrusted"]):
            return False
        evidence = details["evidence"]
        if (type(evidence) is not dict or set(evidence) not in (
                {"missing_sources"}, {"missing_sources", "baseline_gateway_evidence_unproven"})):
            return False
        missing = evidence["missing_sources"]
        sources = {
            "interfaces", "addresses", "dns", "dhcp", "routes-ipv4", "routes-ipv6",
            "neighbors", "profile", "wireless", "gateway-identities-interface-bound",
        }
        if (type(missing) not in (list, tuple) or not 0 < len(missing) <= len(sources)
                or any(type(item) is not str or item not in sources for item in missing)
                or list(missing) != sorted(set(missing))):
            return False
        return ("baseline_gateway_evidence_unproven" not in evidence
                or (evidence["baseline_gateway_evidence_unproven"] is True
                    and "gateway-identities-interface-bound" in missing))
    return False


def _collection_health(details: dict, module: str) -> bool:
    """Recognize exact collector notices, including retained pre-schema records.

    A missed collection is a serious assurance gap, but does not establish an
    intrusion. Do not accept an arbitrary producer's ``health`` label or hide
    integrity failures, response requests, or explicit hostile evidence.
    """
    if (
        (details.get("response_authorized") is not None
         and details.get("response_authorized") is not False)
        or details.get("response_authority") not in (None, "observe-only")
        or any(key in details for key in (
            "response_contract", "target", "tamper", "hardening", "active_exploitation",
        ))
    ):
        return False
    schema = details.get("schema")
    if module == "self-integrity monitor":
        return (
            schema in (None, "angerona.self-integrity-acl-health.v1")
            and details.get("disposition") == "health"
            and details.get("acl_status") == "collection-failed"
            and isinstance(details.get("acl_path"), str)
        )
    if module == "persistence sweep":
        coverage = details.get("coverage")
        return (
            schema in (None, "angerona.persistence-coverage.v1")
            and details.get("finding_code") == "persistence.collector.incomplete"
            and details.get("response_authorized") is False
            and isinstance(coverage, dict)
            and bool(coverage)
            and all(
                isinstance(name, str) and isinstance(value, dict)
                and value.get("status") in ("complete", "partial", "unknown")
                and isinstance(value.get("error"), str)
                for name, value in coverage.items()
            )
            and any(value["status"] != "complete" for value in coverage.values())
        )
    if module == "sysmon event bridge":
        return (
            schema is None
            and details.get("disposition") == "health"
            and details.get("state") in (
                "generation-gap-replay", "tail-anchor-missing-replay", "verified",
                "first-run-tail-anchored", "empty-generation-anchored",
            )
            and isinstance(details.get("current_generation"), str)
            and len(details["current_generation"]) == 64
            and all(char in "0123456789abcdef" for char in details["current_generation"])
            and all(
                type(details.get(key)) is int and details[key] >= 0
                for key in ("cursor", "oldest_record", "newest_record", "replay_from")
            )
            and details.get("cursor_persistence") in ("durable", "failed")
        )
    return False


def _coverage_health(details: dict, module: str) -> bool:
    """Recognize producer-specific coverage notices, never detector findings.

    New sensors may report a serious coverage gap at HIGH/CRITICAL severity.
    Keep that evidence and health warning without waking deep scanners merely
    because another unavailable sensor was added to the installation.
    """
    if (
        details.get("response_authorized") is not False
        or details.get("response_authority") != "observe-only"
    ):
        return False
    schema = details.get("schema")
    if module == "fleet health monitor":
        # Only the default unbound-store producer contract is operational
        # health. Custody failures, bound fleet findings and response requests
        # must retain their normal threat classification, even at this source.
        return (
            schema == "angerona.fleet-health-status.v1"
            and set(details) == _FLEET_UNBOUND_FIELDS
            and details.get("finding_code") == "fleet.coverage.unbound"
            and details.get("fabric_bound") is False
            and details.get("observation_only") is True
            and details.get("enforcement_performed") is False
            and details.get("remote_shell_available") is False
            and details.get("arbitrary_command_available") is False
            and details.get("transport_enabled") is False
            and details.get("transport_available") is False
            and type(details.get("health_percent")) is int and details["health_percent"] == 35
            and isinstance(details.get("exact_reason"), str)
            and 0 < len(details["exact_reason"]) <= 512
            and all(type(details.get(key)) is int and details[key] == 0 for key in _FLEET_UNBOUND_COUNTS)
        )
    if module == "process egress lease guard":
        return (
            schema == "angerona.process-egress-guard-status.v1"
            and type(details.get("audit_complete")) is bool
            and type(details.get("lost_records")) is int
            and details.get("observation_only") is True
            and details.get("enforcement_performed") is False
        )
    if module == "temporal tradecraft correlator":
        state = details.get("temporal_state")
        return (
            schema == "angerona.temporal-tradecraft.v1"
            # Blind combines unavailable and unauthenticated upstream evidence;
            # that contract cannot safely distinguish a health-only notice.
            and state in ("missing", "overflow")
            and details.get("finding_code") == f"temporal.coverage.{state}"
            and details.get("persistence_status") == "authenticated"
            and isinstance(details.get("continuity_reason"), str)
            and not any(key in details for key in ("signal_kinds", "evidence_digests"))
        )
    if module == "audit log integrity guard":
        return (
            details.get("sensor_state") == "blind"
            and isinstance(details.get("source_channel"), str)
            and (
                details.get("error_class") in (
                    "FileNotFoundError", "PermissionError", "ModuleNotFoundError", "ImportError",
                )
                # pywintypes.error: access denied or missing Event Log channel.
                or (details.get("error_class") == "error"
                    and type(details.get("reader_error_code")) is int
                    and details["reader_error_code"] in (5, 15007))
            )
            and not any(key in details for key in (
                "event_id", "record_id", "provider", "classification",
                "telemetry_quality",
            ))
        )
    if module == "aegispath exposure graph guard":
        return (
            schema == "angerona.aegis-path.graph-health.v1"
            and details.get("observation_only") is True
            and details.get("enforcement_performed") is False
            and (
                (details.get("snapshot_available") is False
                 and details.get("snapshot_valid") is False
                 and details.get("coverage_reason") == "no-snapshot")
                or (details.get("snapshot_valid") is True
                    and details.get("semantic_coverage_verified") is True)
            )
        )
    if module == "driver provenance guard":
        return (
            schema == "angerona.driver-provenance-coverage.v1"
            and isinstance(details.get("reason_code"), str)
            and details.get("driver_control_performed") is False
        )
    return False


def _legacy_persistence_baseline(event, details: dict, module: str) -> bool:
    """Recognize only the old pre-existing, unreviewed configuration envelope.

    These seven fields described startup inventory, not observed execution.
    A closed field set refuses every explicit classification, active signal,
    response contract, corroboration and unknown future field. The original
    signed event and its HIGH/CRITICAL review priority remain unchanged.
    """
    if (
        module != "persistence sweep"
        or getattr(event, "severity", Severity.INFO) not in (Severity.HIGH, Severity.CRITICAL)
        or type(details) is not dict
        or details.keys() != {
            "change", "surface", "entry", "value", "mitre", "baseline_trust",
            "response_authorized",
        }
    ):
        return False
    return (
        all(type(details[key]) is str for key in (
            "change", "surface", "entry", "value", "mitre", "baseline_trust",
        ))
        and details["change"] == "baseline_enrollment"
        and details["baseline_trust"] == "unreviewed"
        and details["response_authorized"] is False
    )



_PLATFORM_POSTURE_RISKS = frozenset({
    "secure-boot-disabled", "vbs-not-running", "hvci-not-running",
    "code-integrity-disabled", "test-signing-enabled", "boot-debug-enabled",
    "kernel-dma-protection-unavailable", "external-dma-policy-permissive",
})
_PLATFORM_UNKNOWN_FIELDS = frozenset({
    "secure_boot", "vbs_running", "hvci_running", "code_integrity_enabled",
    "test_signing", "boot_debug", "dma_protection_available",
    "external_dma_policy_restrictive", "tpm.present", "tpm.quote.verifier",
})


def _platform_posture_only(event, details: dict, module: str) -> bool:
    """Recognize this producer's exact OS posture envelope, including history.

    Disabled DMA/HVCI is an exposure, not an observed malicious process to kill.
    Quote-integrity failures, explicit attacks and unknown future fields retain
    ordinary active classification. Stored severity, bytes and trust are intact.
    """
    fixed = {
        "schema": "angerona.measured-boot-assessment.v1",
        "state": "insecure-posture", "posture_consistent": False,
        "raw_quote_omitted": True, "response_authorized": False,
        "response_authority": "observe-only", "user_mode_observation": True,
        "attribution": "not-assessed",
    }
    if (module != "platform attestation guard"
            or type(getattr(event, "severity", None)) is not Severity
            or event.severity is not Severity.HIGH
            or type(details) is not dict
            or set(details) != set(fixed) | {
                "hardware_attested", "quote_state", "evidence_sha256",
                "risk_codes", "unknown_fields", "mitre_tags",
            }
            or any(type(details[key]) is not type(value) or details[key] != value
                   for key, value in fixed.items())):
        return False
    risks, unknown = details["risk_codes"], details["unknown_fields"]
    digest = details["evidence_sha256"]
    quote = details["quote_state"]
    hardware = details["hardware_attested"]
    return (
        type(risks) is list and 0 < len(risks) <= len(_PLATFORM_POSTURE_RISKS)
        and all(type(code) is str and code in _PLATFORM_POSTURE_RISKS for code in risks)
        and risks == sorted(set(risks))
        and type(unknown) is list and len(unknown) <= len(_PLATFORM_UNKNOWN_FIELDS)
        and all(type(name) is str and name in _PLATFORM_UNKNOWN_FIELDS for name in unknown)
        and unknown == sorted(set(unknown))
        and type(digest) is str and len(digest) == 64
        and all(char in "0123456789abcdef" for char in digest)
        and type(quote) is str and quote in {"absent", "unverified", "verified"}
        and type(hardware) is bool and hardware is (quote == "verified")
        and type(details["mitre_tags"]) is list
        and all(type(tag) is str for tag in details["mitre_tags"])
        and details["mitre_tags"] == ["T1547", "T1562.001"]
    )


def _release_source_posture_only(event, details: dict, module: str) -> bool:
    """Recognize only the producer's exact unprovisioned source observation."""
    expected = {
        "schema": "angerona.release-transparency-status.v1",
        "finding_code": "release-transparency.source-bundle-unprovisioned",
        "state": "unavailable",
        "runtime": "source",
        "observation_only": True,
        "response_authority": "observe-only",
        "response_authorized": False,
        "automatic_install_authorized": False,
    }
    return (
        module == "release transparency / anti-rollback guard"
        and getattr(event, "severity", None) is Severity.HIGH
        and getattr(event, "message", None) == "Installed release evidence is unprovisioned in this source run."
        and type(details) is dict
        and details.keys() == expected.keys()
        and all(type(details[key]) is type(value) and details[key] == value
                for key, value in expected.items())
    )


def event_disposition(event) -> str:
    """Classify an event without rewriting its evidentiary severity.

    ``severity`` records how important the observation is inside its own
    domain.  ``disposition`` answers the separate dashboard question: is this
    an active hostile incident, a practice result, a passive exposure, or suite
    health?  Keeping those concepts separate prevents a critical drill result
    or an applicable CVE from falsely claiming that the host is under attack.
    """
    if _is_self_or_drill(event):
        return "practice"
    if (
        getattr(event, "module", "") in _META_MODULES
        or _is_health_noise(event)
    ):
        return "health"
    details = getattr(event, "details", None)
    details = details if isinstance(details, dict) else {}
    module = str(getattr(event, "module", "") or "").strip().casefold()
    if _legacy_indicator_only(event, details, module):
        return "observation"
    if details.get("active_exploitation") is True or details.get("active_attack") is True:
        return "active"
    if (
        _bounded_coverage_notice_health(event, details, module)
        or _unavailable_collection_health(event, details, module)
        or _collection_health(details, module)
        or _coverage_health(details, module)
    ):
        return "health"
    finding_kind = str(details.get("finding_kind") or "").strip().casefold()
    disposition = str(details.get("disposition") or "").strip().casefold()
    source = str(details.get("source") or "").strip().casefold()
    event_type = str(details.get("event_type") or "").strip().casefold()
    if disposition == "observation":
        return "observation"
    # Old NDRD records were lexical scores, sometimes extracted from prose.
    # Keep the original evidence available without asserting a live attack.
    if (
        module == "network protocol deep decoder"
        and getattr(event, "severity", Severity.INFO) <= Severity.HIGH
        and details.get("verdict") == "DGA/tunneling-suspect"
        and details.get("suspicious") is True
        and isinstance(details.get("qname"), str)
        and isinstance(details.get("reasons"), list)
    ):
        return "observation"
    # Posture Hardening emits practice-gap metadata only after authenticating a
    # signed Shark/Red-Team report.  Its AAR integrity errors intentionally do
    # not carry these fields, so "verification failed" stays an active alert.
    if (
        module == "posture hardening"
        and finding_kind == "practice_gap"
        and source in {"redteam", "shark"}
    ):
        return "practice"
    # Hardening gaps and Defender protection-state/action notifications are
    # important posture/response evidence, but do not prove that hostile code
    # is currently executing. A producer can still override this safely with
    # the explicit active_attack/active_exploitation flags handled above.
    if details.get("hardening") is True:
        return "exposure"
    if module == "av telemetry bridge":
        try:
            defender_eid = int(details.get("eid", 0))
        except (TypeError, ValueError):
            defender_eid = 0
        if defender_eid in {1117, 5001}:
            return "health"
        if (
            disposition == "health"
            and details.get("continuity_complete") is False
            and details.get("response_authorized") is False
            and str(details.get("reason_code", "")).startswith("defender.")
        ):
            return "health"
    if (
        module == "kernel-boundary posture ledger"
        and details.get("user_mode_observation") is True
        and isinstance(details.get("risks"), list)
        and isinstance(details.get("evidence_sha256"), str)
    ):
        return "exposure"
    if (
        module in _EXPOSURE_MODULES
        or disposition in _EXPOSURE_KINDS
        or finding_kind in _EXPOSURE_KINDS
        or event_type in _EXPOSURE_EVENT_TYPES
        or source in {"cisa_kev", "cisa-kev", "vulnerability_assessment"}
    ):
        return "exposure"
    if (_platform_posture_only(event, details, module)
            or _release_source_posture_only(event, details, module)):
        return "exposure"
    if _legacy_persistence_baseline(event, details, module):
        return "observation"
    if getattr(event, "severity", Severity.INFO) >= Severity.HIGH:
        return "active"
    return "informational"


def is_active_threat(event) -> bool:
    """Return True only for HIGH/CRITICAL live-hostile evidence."""
    return (
        getattr(event, "severity", Severity.INFO) >= Severity.HIGH
        and event_disposition(event) == "active"
    )


def recent_threat_candidates(bus, limit: int = 200) -> list:
    """Merge the recent presentation tail with retained HIGH/CRITICAL events.

    EventBus's public revision snapshot joins its bounded general and priority
    lanes atomically, using global publication revisions to retain order and
    avoid duplicates. INFO traffic therefore cannot hide serious evidence that
    is still in the priority lane. This is a retained view, not proof of complete
    coverage of a time window; priority overflow and process restarts can still
    lose older evidence. Classification and operator policy remain separate.

    Minimal read-only bus adapters without a revision API retain their existing
    recent-event behavior. No disk or source-evidence query is added here.
    """
    reader = getattr(bus, "records_since", None)
    if not callable(reader):
        return bus.recent(limit)
    current, records, _overflow = reader(-1)
    first_recent = current - max(1, int(limit))
    return [
        event for revision, event in records
        if revision > first_recent or event.severity >= Severity.HIGH
    ]


def active_threat_events(events, window: float = 600.0) -> list:
    """Return unresolved, non-allowlisted active threats in the time window."""
    now = time.time()
    candidates = [
        event for event in events
        if 0.0 <= now - getattr(event, "ts", 0.0) <= window
        and is_active_threat(event)
    ]
    if not candidates:
        return []
    try:
        from angerona.core.alert_ack import acked_signatures, signature
        acked = acked_signatures()
    except Exception:
        acked, signature = set(), None
    try:
        from angerona.core.process_allowlist import is_event_allowed, policy_snapshot
        process_policy = policy_snapshot()
    except Exception:
        is_event_allowed = lambda _event, **_kwargs: False
        process_policy = ()
    try:
        from angerona.core.drill_resolution import is_resolved_event, resolution_snapshot
        resolutions = resolution_snapshot()
    except Exception:
        is_resolved_event = lambda _event, **_kwargs: False
        resolutions = {}
    return [
        event for event in candidates
        if not (signature and signature(event) in acked)
        and not is_event_allowed(event, policy=process_policy)
        and not is_resolved_event(event, resolutions=resolutions)
    ]

# label, colour for each computed level
THREAT_LABEL = {
    Severity.INFO: ("Secure", "#22c55e"),
    Severity.HIGH: ("High", "#f97316"),
    Severity.CRITICAL: ("Critical", "#ef4444"),
}


def threat_level(events, window: float = 600.0) -> Severity:
    """Return INFO (secure), HIGH, or CRITICAL based on real detections in the
    last ``window`` seconds. Operator-acknowledged (ignored) alerts are excluded
    so cleaning up false alerts in the Resolve Center returns the level to Secure."""
    threats = active_threat_events(events, window)
    if any(e.severity == Severity.CRITICAL for e in threats):
        return Severity.CRITICAL
    if threats:
        return Severity.HIGH
    return Severity.INFO


def threat_label(events, window: float = 600.0):
    """Convenience: returns (label, colour)."""
    return THREAT_LABEL[threat_level(events, window)]


def threat_label_from_active(active_events):
    """Label an already evaluated snapshot without rereading policy or files."""
    level = Severity.INFO
    for event in active_events:
        if event.severity == Severity.CRITICAL:
            return THREAT_LABEL[Severity.CRITICAL]
        level = Severity.HIGH
    return THREAT_LABEL[level]
