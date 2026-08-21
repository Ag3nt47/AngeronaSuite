"""Evidence-backed capability inventory and canonical operator destinations.

This module is deliberately free of GUI imports.  Settings, Help, ARIA and the
console can therefore render one honest inventory instead of maintaining
slightly different capability claims.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from enum import Enum
from typing import Iterable


class CapabilityMaturity(str, Enum):
    """How much of a capability is currently supportable by local evidence."""

    OPERATIONAL = "operational"
    CONFIGURABLE_PREVIEW = "configurable-preview"
    INTERNAL_CONTROL = "internal-control"
    CLI_ONLY = "cli-only"
    LIBRARY_ONLY = "library-only"
    EXTERNAL_GATED = "external-gated"
    UNAVAILABLE = "unavailable"


class DestinationKind(str, Enum):
    """The type of canonical operator surface."""

    SETTINGS = "settings"
    WINDOW = "window"
    NONE = "none"


class DestinationAvailability(str, Enum):
    """Whether the declared destination exists in this build."""

    AVAILABLE = "available"
    CONDITIONAL = "conditional"
    UNAVAILABLE = "unavailable"


class DestinationActionability(str, Enum):
    """How precisely a destination can place the operator."""

    DIRECT = "direct"
    CONTEXTUAL = "contextual"
    GUIDANCE_ONLY = "guidance-only"


@dataclass(frozen=True)
class CapabilityGuide:
    key: str
    name: str
    category: str
    definition: str
    steps: tuple[str, ...]
    verify: str
    privacy: str
    destination: str
    destination_kind: DestinationKind = DestinationKind.SETTINGS
    maturity: CapabilityMaturity = CapabilityMaturity.OPERATIONAL
    evidence: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    destination_availability: DestinationAvailability = (
        DestinationAvailability.AVAILABLE
    )
    destination_actionability: DestinationActionability = (
        DestinationActionability.DIRECT
    )

    @property
    def is_actionable(self) -> bool:
        """Return whether a UI may honestly offer a navigation action."""

        return (
            self.destination_availability is DestinationAvailability.AVAILABLE
            and self.destination_actionability
            is not DestinationActionability.GUIDANCE_ONLY
            and self.destination_kind is not DestinationKind.NONE
        )

    @property
    def maturity_label(self) -> str:
        return self.maturity.value.replace("-", " ").title()

    @property
    def destination_label(self) -> str:
        if self.destination_kind is DestinationKind.WINDOW:
            return self.name
        return self.destination or "Guidance only"


_BASE_GUIDES = (
    CapabilityGuide(
        "local-ai", "Local AI and ARIA", "Assistant",
        "A local conversational security assistant that explains evidence and "
        "recommends defensive actions without granting the model host authority.",
        ("Install Ollama.", "Select a local model.", "Enable ARIA.",
         "Use the microphone button to select and test an input device."),
        "Ask ARIA for the current posture and confirm the answer cites live evidence.",
        "Local by default; cloud fallback is a separate opt-in.",
        "ARIA",
    ),
    CapabilityGuide(
        "trusted-processes", "Trusted Processes", "False positives",
        "Exact-path trust for known software such as a Virtual Private Network "
        "(VPN), with manual review plus opt-in conservative learning and no "
        "blanket memory-scan bypass.",
        ("Open Trusted Processes.", "Optionally enable conservative learning.",
         "Review stable signed candidates or scan running processes.",
         "Approve only the exact executable path.", "Verify later events."),
        "Confirm the approval is SHA-256-bound and later events from an unchanged "
        "exact path no longer affect posture.",
        "Stores executable name, canonical path, SHA-256, publisher and bounded "
        "observation metadata locally; no command lines or usernames.",
        "Trusted Processes",
    ),
    CapabilityGuide(
        "performance", "Eco Mode and Performance", "Reliability",
        "Sequentially schedules heavy scanners and applies bounded resource "
        "governance so the interface and response path remain responsive.",
        ("Keep Start in Eco Mode enabled.", "Turn Eco off when a full scan is needed.",
         "Watch System Pulse and module resource details."),
        "Run the self-test and confirm the interface remains responsive during wake-up.",
        "Host performance metrics remain local.",
        "System",
    ),
    CapabilityGuide(
        "mobile", "Mobile Response Bridge", "Integration",
        "Optional Signal-based notification and tightly scoped remote response channel.",
        ("Install signal-cli.", "Enable Mobile Integration.",
         "Choose the local account and operator destination.",
         "Set a protected four-digit command PIN.", "Restart and send a test alert."),
        "The test message arrives and an unauthorized sender is rejected.",
        "Optional outbound transport; disabled by default.",
        "Mobile Integration",
    ),
    CapabilityGuide(
        "api-keys", "Optional AI Providers", "Integration",
        "Encrypted provider credentials used only for explicitly enabled cloud assistance.",
        ("Open API Keys.", "Paste only the providers you intend to use.",
         "Set provider order.", "Enable the separate cloud feature that needs them."),
        "Run its explicit test and inspect the egress preview.",
        "Keys are protected outside settings.json; cloud use is off by default.",
        "API Keys",
    ),
    CapabilityGuide(
        "red-team", "Red Team Simulation", "Validation",
        "A safe, reversible drill that evaluates detection, evidence and remediation.",
        ("Open Red Team Simulation.", "Choose a benign profile and intensity.",
         "Run the drill.", "Review the After-Action Report.",
         "Build and verify fixes, then rerun to prove closure."),
        "A rerun detects the marker and the report records a passing closure receipt.",
        "Uses inert local markers and never deploys real exploitation.",
        "_open_simulation", DestinationKind.WINDOW,
    ),
    CapabilityGuide(
        "device-security-lab", "Device Security Lab", "Validation",
        "Owner-authorized passive assessment for this computer and fresh signed "
        "posture evidence from an explicitly enrolled companion device.",
        ("Open Red Team Simulation > Device Security Lab.",
         "Attest ownership or explicit authorization and choose the connection scope.",
         "Inspect this computer, or export a short-lived companion challenge.",
         "Import the companion's Ed25519-signed response and posture evidence.",
         "Review redacted weaknesses, remediation, patch guidance, and limitations."),
        "A forged, replayed, stale, target-swapped, or out-of-scope evidence file is refused.",
        "Private device keys never leave companion devices. Evidence is bounded and "
        "excludes usernames, addresses, commands, packets, and raw device identifiers.",
        "_open_device_lab", DestinationKind.WINDOW,
    ),
    CapabilityGuide(
        "scan-center", "Scan Center", "Exposure",
        "Local malware-indicator, selected-folder, listening-port, network-posture, "
        "and Microsoft Defender scan orchestration attached to Live Alerts.",
        ("Open Live Alerts and press Scan Center.",
         "Choose a local folder or drive for bounded Angerona scanning.",
         "Optionally confirm a Microsoft Defender custom or quick scan on Windows.",
         "Run passive listening-port or aggregate interface posture review.",
         "Review or export the privacy-redacted result."),
        "The result identifies the local operation, resource bounds, support state, "
        "findings, errors, and whether Defender actually executed.",
        "This-host only. It returns no IP, MAC, SSID, username, PID, or full path, "
        "and performs no remote probing, packet capture, exploitation, or credential test.",
        "_open_scan_center", DestinationKind.WINDOW,
    ),
    CapabilityGuide(
        "attack-map", "MITRE ATT&CK Coverage", "Visibility",
        "Maps observed activity and verified detection coverage to ATT&CK techniques.",
        ("Open ATT&CK Map.", "Review Coverage and blind spots.",
         "Select a technique for evidence and remediation detail."),
        "Coverage entries resolve to real detectors or simulations.",
        "Local evidence; links to MITRE require an explicit browser action.",
        "_open_attack_heatmap", DestinationKind.WINDOW,
    ),
    CapabilityGuide(
        "threat-intel", "Threat Intelligence", "Exposure",
        "Correlates trusted vulnerability intelligence with locally observed software.",
        ("Open Threat Intel.", "Refresh intelligence when online access is allowed.",
         "Review host-applicable entries.", "Stage rather than auto-run a fix."),
        "Confirm ignored or remediated entries no longer inflate posture incorrectly.",
        "Feed retrieval is inbound; host evidence is not uploaded.",
        "_open_threat_intel", DestinationKind.WINDOW,
    ),
    CapabilityGuide(
        "forensics", "Forensics Workbench", "Investigation",
        "Opens the shipped collision, blast-radius, network, kill-chain, sandbox, "
        "and privacy-minimized incident-response bundle tools.",
        ("Open Forensics.", "Choose the evidence view that matches the question.",
         "Inspect the bounded local evidence.",
         "Create and review a sanitized triage bundle when sharing is required."),
        "Verify the selected view and review the bundle privacy manifest before sharing.",
        "The dashboard workbench does not yet expose the library-only case-management "
        "and custody workflow.",
        "_open_forensics_hub", DestinationKind.WINDOW,
    ),
    CapabilityGuide(
        "enterprise", "Enterprise Readiness", "Administration",
        "Evidence-based status for signing, identity, policy, fleet, privacy and release gates.",
        ("Open Enterprise Settings.", "Refresh assessment.",
         "Review partial and externally gated controls.", "Open the canonical roadmap."),
        "Every completed claim has a test or committed evidence reference.",
        "Assessment reads local metadata only.",
        "Enterprise",
    ),
    CapabilityGuide(
        "fleet-preview", "Local Fleet Control Plane", "Administration",
        "An opt-in authenticated loopback service for tenant-isolated device "
        "inventory, device-bound deduplicated ingestion, clock-quality evidence, "
        "and a versioned OpenAPI contract. It is a local preview boundary, not "
        "an internet-facing enterprise server.",
        ("Open Enterprise Settings.", "Choose a tenant and unused loopback port.",
         "Enable the fleet service and save.", "Restart Angerona.",
         "Use signed, fresh, one-time requests from a local integration.",
         "Inspect /v1/openapi and the tenant ingestion-health route."),
        "The loopback health endpoint responds, signed requests work once, and "
        "replayed, stale, tampered, cross-tenant, cross-device, or quarantined "
        "requests fail. Uncertain endpoint clocks are explicit rather than trusted.",
        "Disabled by default, bound to 127.0.0.1, and stores data under the "
        "configured Angerona data directory.",
        "Enterprise",
    ),
    CapabilityGuide(
        "enterprise-rbac", "Enterprise Roles and Separation of Duties",
        "Administration",
        "A local Role-Based Access Control (RBAC) policy boundary with nine "
        "least-privilege roles, canonical tenant/fleet scopes, explicit-deny "
        "precedence, expiring service principals, signed decisions, and binding-"
        "time separation-of-duty checks.",
        ("Choose the smallest standard role that fits the task.",
         "Bind it to the narrowest tenant, fleet, group, or host scope.",
         "Keep auditors separate from operational roles.",
         "Keep detection authors separate from overlapping policy activation.",
         "Verify the authenticated authorization receipt."),
        "Out-of-scope and unlisted actions default deny; overlapping auditor/admin "
        "or detection-author/policy-approver bindings fail before activation.",
        "Policy identifiers, scopes and decisions remain local. Production identity "
        "provider and directory lifecycle integration are separate deployment gates.",
        "Enterprise",
    ),
    CapabilityGuide(
        "response-broker", "Enterprise Response Broker", "Response",
        "A typed response boundary with no generic shell: operations must be "
        "registered, validated, expiring, idempotent and approval-gated.",
        ("Preview the proposed response.", "Review the exact target and rollback.",
         "Collect a distinct approval; high-impact actions require two.",
         "Execute only the registered operation.", "Verify the signed receipt."),
        "A repeated proposal returns one receipt, changed arguments conflict, "
        "and an expired or under-approved response is refused.",
        "Response arguments and receipts remain local unless a separately "
        "approved connector exports a minimized record.",
        "Enterprise",
    ),
    CapabilityGuide(
        "identity-defense", "Identity Threat Analytics", "Identity",
        "Local authentication analytics for password spray, distributed account "
        "targeting, repeated failures, new privileged sources, and interactive "
        "service-account use.",
        ("Collect supported local authentication events.",
         "Normalize account, source, success, privilege, and logon type.",
         "Review tokenized findings and corroborating endpoint evidence.",
         "Use the response broker to preview any containment."),
        "Benign fixtures remain quiet; threshold fixtures produce the expected "
        "rule and no raw account or source appears in retained analytics state.",
        "Accounts and sources are HMAC-tokenized before retention; passwords "
        "and credential material are never accepted.",
        "Enterprise",
    ),
    CapabilityGuide(
        "network-behavior", "Network Behavior Analytics", "Network",
        "Privacy-minimized Network Detection and Response (NDR) analytics for "
        "periodic beaconing, lateral fanout, external fanout, and asymmetric upload.",
        ("Normalize new flow observations.", "Tokenize process and destination.",
         "Correlate within the bounded local window.",
         "Review the finding with DNS, process, and identity evidence."),
        "Periodic and fanout fixtures alert while raw process and destination "
        "values never appear in retained analytics state.",
        "Destinations and process identities are HMAC-tokenized before retention; "
        "packet payloads are neither accepted nor stored.",
        "Enterprise",
    ),
    CapabilityGuide(
        "exposure-management", "Vulnerability and Exposure Management", "Exposure",
        "A durable lifecycle for assigning, mitigating, accepting, resolving, "
        "and auditing host-applicable vulnerabilities.",
        ("Correlate inventory with trusted vulnerability intelligence.",
         "Assign an owner and deadline.", "Stage and verify remediation.",
         "Attach a SHA-256 closure artifact or a bounded risk exception."),
        "Stale updates conflict, expired exceptions return to the due queue, and "
        "resolved findings contain immutable evidence identity.",
        "Stores vulnerability and asset identifiers locally; diagnostic export "
        "must pass the separate privacy minimization boundary.",
        "Enterprise",
    ),
    CapabilityGuide(
        "signed-plugins", "Signed Plugin Lifecycle", "Extensions",
        "Offline staging, revalidation, activation, revocation, quarantine, "
        "history, and audit catalog for reviewed capability extensions.",
        ("Trust a reviewed publisher key.", "Stage the signed source and manifest.",
         "Review permissions, privacy, egress, and resource budgets.",
         "Activate for the next restart or revoke to quarantine."),
        "Tampering, revoked trust, missing manifests, entrypoint collisions, and "
        "unsigned content fail before import.",
        "Plugins are disabled by default and receive no implied egress permission.",
        "Enterprise",
    ),
    CapabilityGuide(
        "interop", "Offline Interoperability Gateway", "Integration",
        "A durable signed queue for privacy-reviewed OCSF, STIX, OTLP, and "
        "Angerona envelopes with idempotency, backoff, and dead-letter handling.",
        ("Choose a standard schema.", "Preview minimization and destination.",
         "Explicitly permit external egress if required.", "Queue locally.",
         "Deliver through a separately configured connector and acknowledge."),
        "Restricted fields are removed, sensitive fields tokenize, retries back "
        "off, and payload/signature verification succeeds before delivery.",
        "External egress is denied by default; queued payloads are minimized first.",
        "Enterprise",
    ),
    CapabilityGuide(
        "fleet-hunts", "Safe Fleet Hunts and Collections", "Investigation",
        "Typed fleet-wide evidence collection with an allowlisted artifact "
        "catalog, explicit targets, approvals, budgets, durable state, "
        "non-executable notebooks and receipts.",
        ("Choose registered artifacts.", "Set exact device/group targets.",
         "Set host, byte, duration, and expiry budgets.", "Collect approvals.",
         "Run through the typed endpoint collector.",
         "Record typed queries, notes and immutable evidence references.",
         "Review authenticated progress and coded failures.",
         "Promote verified result references into an investigating case.",
         "Verify the workspace snapshot, custody chain and result receipt."),
        "Arbitrary command/path fields fail, restricted artifacts require two "
        "approvers, state tampering fails, over-budget results are rejected, and "
        "sanitized export omits restricted results and device identifiers.",
        "Artifact privacy classes determine approval. Notebooks contain no "
        "executable cells, generic shell, or unbounded content collection.",
        "Enterprise",
    ),
    CapabilityGuide(
        "safe-live-response", "Safe Live Response Session", "Response",
        "A maximum 30-minute target-bound session exposing only registered "
        "read-only queries and separately approval-gated typed response operations.",
        ("Open Enterprise Settings.", "Choose the exact endpoint and capabilities.",
         "Set the shortest useful expiry.", "Collect an independent approval; "
         "host-changing sessions require two.",
         "Run registered queries or approved Response Broker proposals.",
         "Close the session and verify its transcript receipt."),
        "Unregistered queries, target changes, executable fields, expired sessions "
        "and under-approved host changes fail; duplicate requests do not execute twice.",
        "The persisted transcript contains action identities, outcome and request/"
        "result digests rather than raw result content. It forms an authenticated "
        "hash chain and there is no generic shell.",
        "Enterprise",
    ),
    CapabilityGuide(
        "release-evidence", "Local Release Evidence Gate", "Assurance",
        "A fixed-command quality gate that records content digests, redacted "
        "summaries, limitations and the exact source commit without storing raw logs.",
        ("Open Enterprise Settings.", "Review the release limitations.",
         "Run tools/run_release_gate.py from the project environment.",
         "Verify every required check is present and passing.",
         "Apply the separate publisher signature before public release."),
        "The manifest digest verifies, incomplete or failed checks fail the gate, "
        "and no credential, username or local path appears in summaries.",
        "Raw command output is not retained in the evidence pack. Local evidence "
        "is content-addressed; publisher signing remains a separate release gate.",
        "Enterprise",
    ),
    CapabilityGuide(
        "reliability-drills", "Reliability and Recovery Drills", "Reliability",
        "Deterministic failure exercises with registered scenarios, explicit "
        "retryable errors, bounded attempts, time budgets and evidence digests.",
        ("Open Enterprise Settings.", "Review current reliability evidence.",
         "Run the fixed local test suite.", "Inspect failed recovery evidence.",
         "Do not treat local drills as long-duration physical-host soak proof."),
        "Transient faults recover within budget, permanent faults stop at the "
        "declared limit, and unknown failures surface immediately.",
        "The harness invokes only a caller-supplied defensive operation; it has "
        "no shell, network action, or production fault-injection switch.",
        "Enterprise",
    ),
    CapabilityGuide(
        "backup-restore", "Encrypted Backup and Offline Restore", "Resilience",
        "Streaming authenticated backup for selected local configuration, "
        "identity, audit, case and evidence files, including consistent SQLite "
        "snapshots and a two-person offline restore boundary.",
        ("Open Enterprise Settings.", "Choose an external backup destination.",
         "Select exact data-root items and create the encrypted archive.",
         "Verify its receipt and perform a test restore.",
         "For a real restore, stop Angerona and collect two independent approvals.",
         "Keep the generated rollback scope until verification completes."),
        "The archive decrypts with the protected key, all item digests verify, "
        "a wrong key or changed archive fails, and an interrupted restore returns "
        "the previous file to its original location.",
        "Paths, filenames and payloads are inside the encrypted stream. Keys are "
        "never embedded in the archive; destination and key custody remain an "
        "operator responsibility.",
        "Enterprise",
    ),
    CapabilityGuide(
        "recovery-objectives", "Recovery Objectives and Drills", "Resilience",
        "Explicit per-scenario Recovery Point Objective (RPO), Recovery Time "
        "Objective (RTO), verified-copy, ownership, review and drill evidence.",
        ("Open Enterprise Settings.", "Choose a named recovery scenario.",
         "Set reviewed RPO, RTO and minimum-copy objectives.",
         "Run a controlled restore exercise.", "Verify archive, manifest, "
         "service health and rollback.", "Review every violation and sign the evidence."),
        "Measured backup age and recovery duration meet the objective, the "
        "minimum verified copies exist, all four verification gates pass, and "
        "the drill evidence HMAC verifies.",
        "The policy engine records objectives and evidence only. It never starts "
        "a backup, deletes retained archives or performs recovery by itself.",
        "Enterprise",
    ),
    CapabilityGuide(
        "audit-export", "Signed Audit Export", "Governance",
        "Tenant, scope and time-bounded audit exchange with privacy minimization, "
        "actor tokenization, record chaining, manifest signing and truncation honesty.",
        ("Open Enterprise Settings.", "Choose the exact tenant, scopes and time range.",
         "Set a bounded record limit.", "Generate the local export.",
         "Verify its chain and manifest before sharing."),
        "Cross-tenant/out-of-scope records are absent, restricted fields are "
        "removed, sensitive values tokenize, free text redacts, and any record or "
        "manifest change fails verification.",
        "The default export removes restricted fields and raw actors, tokenizes "
        "sensitive fields, and records when the requested result was truncated.",
        "Enterprise",
    ),
    CapabilityGuide(
        "world-view", "World View and System Pulse", "Observability",
        "Explains Angerona resource use, sensor continuity and internal service health.",
        ("Open World View.", "Inspect sensor and pipeline status.",
         "Click System Pulse for CPU, memory and network history."),
        "Unknown or stale sensors appear degraded rather than healthy.",
        "Host metrics remain local.",
        "_open_worldview", DestinationKind.WINDOW,
    ),
    CapabilityGuide(
        "advanced-console", "Advanced Console", "Operations",
        "Operational diagnostics for models, watchdog, telemetry and service recovery; "
        "saved configuration remains exclusively in Settings.",
        ("Open Advanced Console.", "Choose the diagnostic area.",
         "Review status before restarting a component.", "Return to Settings to configure it."),
        "A diagnostic action records its result without creating duplicate settings.",
        "May expose local diagnostic metadata on screen; no automatic egress.",
        "_open_upgrade_console", DestinationKind.WINDOW,
    ),
)


@dataclass(frozen=True)
class _CapabilityMetadata:
    maturity: CapabilityMaturity
    evidence: tuple[str, ...]
    limitations: tuple[str, ...]
    aliases: tuple[str, ...] = ()
    destination_availability: DestinationAvailability = (
        DestinationAvailability.AVAILABLE
    )
    destination_actionability: DestinationActionability = (
        DestinationActionability.DIRECT
    )


_METADATA: dict[str, _CapabilityMetadata] = {
    "local-ai": _CapabilityMetadata(
        CapabilityMaturity.OPERATIONAL,
        ("tests/test_ollama_transport.py", "tests/test_ai_security_broker.py"),
        ("Answer quality depends on the installed local model; ARIA has no direct host authority.",),
        ("aria", "voice", "microphone", "local assistant"),
    ),
    "trusted-processes": _CapabilityMetadata(
        CapabilityMaturity.OPERATIONAL,
        ("tests/test_process_baseline.py",),
        ("Trust is an operator decision and does not prove that an approved binary is benign.",),
        ("trusted apps", "allowlist", "false positives"),
    ),
    "performance": _CapabilityMetadata(
        CapabilityMaturity.OPERATIONAL,
        ("tests/test_performance_lifecycle.py", "tests/test_operational_slo.py"),
        ("Resource governance reduces contention but cannot guarantee latency on an overloaded host.",),
        ("eco mode", "system performance", "resource governance"),
    ),
    "mobile": _CapabilityMetadata(
        CapabilityMaturity.EXTERNAL_GATED,
        ("tests/test_remote_bridge_security.py",),
        ("Delivery requires a separately installed and configured Signal client and account.",),
        ("signal", "phone", "mobile response"),
    ),
    "api-keys": _CapabilityMetadata(
        CapabilityMaturity.EXTERNAL_GATED,
        ("tests/test_provider_credentials.py",),
        ("Provider availability, terms, cost, and remote data handling remain external controls.",),
        ("ai providers", "provider credentials", "cloud keys"),
    ),
    "red-team": _CapabilityMetadata(
        CapabilityMaturity.OPERATIONAL,
        ("tests/test_drill_remediation_lifecycle.py", "tests/test_purple_remediation_e2e.py"),
        ("Inert simulations validate Angerona paths; they are not a substitute for an authorized penetration test.",),
        ("shark attack", "red team drill", "after action report"),
    ),
    "device-security-lab": _CapabilityMetadata(
        CapabilityMaturity.CONFIGURABLE_PREVIEW,
        ("tests/test_device_security_lab.py", "tests/test_device_scan_ui.py"),
        ("The current cross-device transport is a signed file exchange. A separately "
         "reviewed pinned-mTLS companion transport remains a deployment gate.",
         "Passive local USB and Bluetooth detail depends on safe platform APIs and may "
         "honestly report unsupported."),
        ("device lab", "companion assessment", "usb security", "bluetooth security", "hdmi security"),
    ),
    "scan-center": _CapabilityMetadata(
        CapabilityMaturity.OPERATIONAL,
        ("tests/test_security_scan_center.py", "tests/test_device_scan_ui.py"),
        ("Angerona complements rather than replaces Microsoft Defender's kernel, AMSI, "
         "cloud, reputation, and platform protections.",
         "Defender orchestration is Windows-only; quick/full scans may apply the "
         "actions configured in Windows Security."),
        ("scan center", "malware scan", "drive scan", "listening ports", "defender scan"),
    ),
    "attack-map": _CapabilityMetadata(
        CapabilityMaturity.OPERATIONAL,
        ("tests/test_enterprise_telemetry_coverage.py",),
        ("Displayed coverage proves mapped local evidence, not complete protection against a technique.",),
        ("mitre attack", "attack coverage", "coverage map"),
    ),
    "threat-intel": _CapabilityMetadata(
        CapabilityMaturity.EXTERNAL_GATED,
        ("tests/test_exposure_management.py",),
        ("Fresh intelligence depends on explicitly permitted third-party feeds and network availability.",),
        ("threat intelligence", "vulnerability feed", "cve intelligence"),
    ),
    "forensics": _CapabilityMetadata(
        CapabilityMaturity.OPERATIONAL,
        ("tests/test_ir_bundle_privacy.py", "tests/test_cycle4_round3_state_bounds.py"),
        ("Case management and custody primitives exist as libraries but are not wired "
         "into this operator destination.",),
        ("forensics", "ir bundle", "incident investigation", "kill chain"),
    ),
    "enterprise": _CapabilityMetadata(
        CapabilityMaturity.OPERATIONAL,
        ("tests/test_enterprise_readiness_api.py", "tests/test_evidence_claims.py"),
        ("Several production deployment, identity-provider, signing, and independent-assurance gates remain external.",),
        ("enterprise readiness", "readiness assessment", "assurance status"),
    ),
    "fleet-preview": _CapabilityMetadata(
        CapabilityMaturity.CONFIGURABLE_PREVIEW,
        ("tests/test_cycle14_fleet_tenant_auth.py", "tests/test_cycle14_fleet_integrity.py"),
        ("The service is loopback-only and is not an internet-facing or multi-host production control plane.",),
        ("fleet", "fleet control plane", "device inventory"),
        destination_actionability=DestinationActionability.CONTEXTUAL,
    ),
    "enterprise-rbac": _CapabilityMetadata(
        CapabilityMaturity.INTERNAL_CONTROL,
        ("tests/test_authorization.py",),
        ("Local authorization is implemented; directory lifecycle and production identity-provider integration are not.",),
        ("rbac", "role based access control", "separation of duties"),
        destination_actionability=DestinationActionability.CONTEXTUAL,
    ),
    "response-broker": _CapabilityMetadata(
        CapabilityMaturity.LIBRARY_ONLY,
        ("tests/test_response_broker.py",),
        ("Only registered typed operations are supported; endpoint-specific rollback still requires an implementation.",),
        ("typed response", "approval broker", "containment approval"),
        destination_actionability=DestinationActionability.CONTEXTUAL,
    ),
    "identity-defense": _CapabilityMetadata(
        CapabilityMaturity.LIBRARY_ONLY,
        ("tests/test_identity_analytics.py",),
        ("Findings depend on supported authentication evidence and are not a full identity-provider replacement.",),
        ("identity analytics", "password spray", "account defense"),
        destination_actionability=DestinationActionability.CONTEXTUAL,
    ),
    "network-behavior": _CapabilityMetadata(
        CapabilityMaturity.LIBRARY_ONLY,
        ("tests/test_network_behavior.py",),
        ("Flow analytics omit packet payloads and cannot inspect traffic that the host does not observe.",),
        ("ndr", "network detection response", "beaconing"),
        destination_actionability=DestinationActionability.CONTEXTUAL,
    ),
    "exposure-management": _CapabilityMetadata(
        CapabilityMaturity.LIBRARY_ONLY,
        ("tests/test_exposure_management.py", "tests/test_exposure_recovery.py"),
        ("Applicability and closure depend on accurate inventory and trusted vulnerability intelligence.",),
        ("vulnerability management", "exposure lifecycle", "risk exception"),
        destination_actionability=DestinationActionability.CONTEXTUAL,
    ),
    "signed-plugins": _CapabilityMetadata(
        CapabilityMaturity.LIBRARY_ONLY,
        ("tests/test_plugin_lifecycle.py",),
        ("Signature validity establishes provenance and integrity, not the safety of publisher code.",),
        ("plugin lifecycle", "signed extensions", "plugin quarantine"),
        destination_actionability=DestinationActionability.CONTEXTUAL,
    ),
    "interop": _CapabilityMetadata(
        CapabilityMaturity.LIBRARY_ONLY,
        ("tests/test_interop_gateway.py",),
        ("Local envelopes and queues are implemented; delivery still needs an approved destination connector.",),
        ("interoperability", "ocsf", "stix", "otlp"),
        destination_actionability=DestinationActionability.CONTEXTUAL,
    ),
    "fleet-hunts": _CapabilityMetadata(
        CapabilityMaturity.LIBRARY_ONLY,
        ("tests/test_fleet_hunts.py", "tests/test_hunt_workspace.py"),
        ("Collections are limited to registered artifacts and reachable enrolled endpoints.",),
        ("fleet hunt", "fleet collection", "hunt workspace"),
        destination_actionability=DestinationActionability.CONTEXTUAL,
    ),
    "safe-live-response": _CapabilityMetadata(
        CapabilityMaturity.LIBRARY_ONLY,
        ("tests/test_safe_response_session.py",),
        ("Sessions expose only registered operations and do not provide a generic remote shell.",),
        ("live response", "response session", "endpoint session"),
        destination_actionability=DestinationActionability.CONTEXTUAL,
    ),
    "release-evidence": _CapabilityMetadata(
        CapabilityMaturity.CLI_ONLY,
        ("tests/test_release_evidence.py", "tests/test_release_integrity.py"),
        ("Local evidence is content-addressed; publisher identity and external review remain separate gates.",),
        ("release gate", "release assurance", "evidence manifest"),
        destination_actionability=DestinationActionability.CONTEXTUAL,
    ),
    "reliability-drills": _CapabilityMetadata(
        CapabilityMaturity.LIBRARY_ONLY,
        ("tests/test_reliability_lab.py",),
        ("Deterministic local drills do not constitute long-duration physical-host soak evidence.",),
        ("chaos drill", "recovery drill", "reliability lab"),
        destination_actionability=DestinationActionability.CONTEXTUAL,
    ),
    "backup-restore": _CapabilityMetadata(
        CapabilityMaturity.LIBRARY_ONLY,
        ("tests/test_backup_restore.py",),
        ("Operators remain responsible for offline key custody, destination durability, and restore exercises.",),
        ("encrypted backup", "offline restore", "disaster recovery"),
        destination_actionability=DestinationActionability.CONTEXTUAL,
    ),
    "recovery-objectives": _CapabilityMetadata(
        CapabilityMaturity.LIBRARY_ONLY,
        ("tests/test_recovery_policy.py",),
        ("The policy records evidence and objectives but does not independently perform backup or recovery.",),
        ("rpo", "rto", "recovery policy"),
        destination_actionability=DestinationActionability.CONTEXTUAL,
    ),
    "audit-export": _CapabilityMetadata(
        CapabilityMaturity.LIBRARY_ONLY,
        ("tests/test_audit_export.py", "tests/test_admin_audit.py"),
        ("Export authenticity depends on protected signing-key custody and recipient verification.",),
        ("signed audit", "audit export", "worm audit"),
        destination_actionability=DestinationActionability.CONTEXTUAL,
    ),
    "world-view": _CapabilityMetadata(
        CapabilityMaturity.OPERATIONAL,
        ("tests/test_operational_slo.py",),
        ("Host metrics are sampled observations and may be temporarily unknown after sleep or resume.",),
        ("system pulse", "resource monitor", "world view"),
    ),
    "advanced-console": _CapabilityMetadata(
        CapabilityMaturity.OPERATIONAL,
        ("tests/test_upgrade_console_shutdown.py",),
        ("The console is a diagnostic surface; durable configuration remains owned by Settings.",),
        ("operations console", "diagnostics", "service recovery"),
    ),
}


class CatalogValidationError(ValueError):
    """Raised when a capability catalog could make an ambiguous or false claim."""


_KEY_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _normalise(value: object) -> str:
    return " ".join(_TOKEN_RE.findall(str(value or "").casefold()))


def _require_text(value: object, field: str, key: str) -> None:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise CatalogValidationError(f"{key}: {field} must be non-empty and trimmed")


def validate_catalog(
    guides: Iterable[CapabilityGuide],
) -> tuple[CapabilityGuide, ...]:
    """Validate and freeze a catalog, rejecting ambiguity and incomplete claims."""

    catalog = tuple(guides)
    if not catalog:
        raise CatalogValidationError("capability catalog must not be empty")
    seen_keys: set[str] = set()
    seen_names: set[str] = set()
    intent_owners: dict[str, str] = {}
    for guide in catalog:
        if not isinstance(guide, CapabilityGuide):
            raise CatalogValidationError("catalog entries must be CapabilityGuide values")
        if not _KEY_RE.fullmatch(guide.key):
            raise CatalogValidationError(f"invalid capability key: {guide.key!r}")
        if guide.key in seen_keys:
            raise CatalogValidationError(f"duplicate capability key: {guide.key}")
        seen_keys.add(guide.key)
        _require_text(guide.name, "name", guide.key)
        name_key = _normalise(guide.name)
        if name_key in seen_names:
            raise CatalogValidationError(f"duplicate capability name: {guide.name}")
        seen_names.add(name_key)
        for field in ("category", "definition", "verify", "privacy"):
            _require_text(getattr(guide, field), field, guide.key)
        for field in ("steps", "evidence", "limitations"):
            values = getattr(guide, field)
            if not isinstance(values, tuple) or not values:
                raise CatalogValidationError(f"{guide.key}: {field} must be a non-empty tuple")
            for value in values:
                _require_text(value, field, guide.key)
        if not isinstance(guide.aliases, tuple):
            raise CatalogValidationError(f"{guide.key}: aliases must be a tuple")
        if not isinstance(guide.maturity, CapabilityMaturity):
            raise CatalogValidationError(f"{guide.key}: invalid maturity state")
        if not isinstance(guide.destination_kind, DestinationKind):
            raise CatalogValidationError(f"{guide.key}: invalid destination kind")
        if not isinstance(guide.destination_availability, DestinationAvailability):
            raise CatalogValidationError(f"{guide.key}: invalid destination availability")
        if not isinstance(guide.destination_actionability, DestinationActionability):
            raise CatalogValidationError(f"{guide.key}: invalid destination actionability")
        if guide.destination_kind is DestinationKind.NONE:
            if guide.destination or guide.destination_actionability is not DestinationActionability.GUIDANCE_ONLY:
                raise CatalogValidationError(f"{guide.key}: non-navigable destination must be guidance-only")
        else:
            _require_text(guide.destination, "destination", guide.key)
        if (
            guide.destination_availability is DestinationAvailability.UNAVAILABLE
            and guide.destination_actionability is not DestinationActionability.GUIDANCE_ONLY
        ):
            raise CatalogValidationError(f"{guide.key}: unavailable destination cannot be actionable")
        identities = (guide.key, guide.name, *guide.aliases)
        for identity in identities:
            _require_text(identity, "search identity", guide.key)
            intent = _normalise(identity)
            owner = intent_owners.setdefault(intent, guide.key)
            if owner != guide.key:
                raise CatalogValidationError(
                    f"ambiguous search intent {identity!r}: {owner} and {guide.key}"
                )
    return catalog


def _build_catalog() -> tuple[CapabilityGuide, ...]:
    base_keys = {guide.key for guide in _BASE_GUIDES}
    metadata_keys = set(_METADATA)
    if base_keys != metadata_keys:
        missing = sorted(base_keys - metadata_keys)
        extra = sorted(metadata_keys - base_keys)
        raise CatalogValidationError(
            f"capability metadata parity failure; missing={missing}, extra={extra}"
        )
    non_operator_maturity = {
        CapabilityMaturity.INTERNAL_CONTROL,
        CapabilityMaturity.CLI_ONLY,
        CapabilityMaturity.LIBRARY_ONLY,
        CapabilityMaturity.UNAVAILABLE,
    }

    def enrich(guide: CapabilityGuide) -> CapabilityGuide:
        metadata = _METADATA[guide.key]
        has_operator_surface = metadata.maturity not in non_operator_maturity
        return replace(
            guide,
            maturity=metadata.maturity,
            evidence=metadata.evidence,
            limitations=metadata.limitations,
            aliases=metadata.aliases,
            destination=guide.destination if has_operator_surface else "",
            destination_kind=(
                guide.destination_kind if has_operator_surface
                else DestinationKind.NONE
            ),
            destination_availability=(
                metadata.destination_availability if has_operator_surface
                else DestinationAvailability.UNAVAILABLE
            ),
            destination_actionability=(
                metadata.destination_actionability if has_operator_surface
                else DestinationActionability.GUIDANCE_ONLY
            ),
        )

    enriched = (enrich(guide) for guide in _BASE_GUIDES)
    return validate_catalog(enriched)


GUIDES = _build_catalog()
GUIDE_BY_KEY = {guide.key: guide for guide in GUIDES}


def get_guide(key: str) -> CapabilityGuide | None:
    """Return a capability by canonical key or an exact, unambiguous alias."""

    intent = _normalise(key)
    if not intent:
        return None
    direct = GUIDE_BY_KEY.get(intent.replace(" ", "-"))
    if direct is not None:
        return direct
    for guide in GUIDES:
        if intent in {_normalise(alias) for alias in guide.aliases}:
            return guide
    return None


def actionable_guides() -> tuple[CapabilityGuide, ...]:
    """Return the stable subset for which a UI may enable navigation."""

    return tuple(guide for guide in GUIDES if guide.is_actionable)


def _matches(token: str, searchable_tokens: tuple[str, ...]) -> bool:
    return any(word == token or word.startswith(token) for word in searchable_tokens)


def _search_rank(
    guide: CapabilityGuide,
    phrase: str,
    query_tokens: tuple[str, ...],
    catalog_index: int,
) -> tuple[int, int, int, int] | None:
    key = _normalise(guide.key)
    name = _normalise(guide.name)
    aliases = tuple(_normalise(alias) for alias in guide.aliases)
    identities = (key, name, *aliases)
    searchable = _normalise(
        " ".join(
            (
                *identities,
                guide.category,
                guide.definition,
                " ".join(guide.steps),
                guide.verify,
                guide.privacy,
                " ".join(guide.evidence),
                " ".join(guide.limitations),
            )
        )
    )
    searchable_tokens = tuple(searchable.split())
    if not all(_matches(token, searchable_tokens) for token in query_tokens):
        return None
    identity_tokens = tuple(" ".join(identities).split())
    identity_hits = sum(_matches(token, identity_tokens) for token in query_tokens)
    if phrase in (key, name):
        tier = 0
    elif phrase in aliases:
        tier = 1
    elif any(identity.startswith(phrase) for identity in identities):
        tier = 2
    elif any(phrase in identity for identity in identities):
        tier = 3
    else:
        tier = 4
    return (tier, -identity_hits, len(name.split()), catalog_index)


def search_guides(query: str) -> tuple[CapabilityGuide, ...]:
    """Return deterministic intent-ranked results for a free-text query.

    Exact canonical keys/names rank first, followed by exact aliases, then
    identity phrases and finally all-token matches in the evidence-backed body.
    Catalog order is the final stable tie-breaker.
    """

    phrase = _normalise(query)
    if not phrase:
        return GUIDES
    query_tokens = tuple(phrase.split())
    ranked: list[tuple[tuple[int, int, int, int], CapabilityGuide]] = []
    for index, guide in enumerate(GUIDES):
        rank = _search_rank(guide, phrase, query_tokens, index)
        if rank is not None:
            ranked.append((rank, guide))
    ranked.sort(key=lambda item: item[0])
    return tuple(guide for _, guide in ranked)
