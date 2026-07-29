"""Searchable operator guidance and canonical destinations for capabilities."""
from __future__ import annotations

from dataclasses import dataclass


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
    destination_kind: str = "settings"  # settings | window


GUIDES = (
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
        "(VPN), with supervised discovery and no blanket memory-scan bypass.",
        ("Open Trusted Processes.", "Scan running processes.",
         "Select the exact executable path.", "Save and verify new events."),
        "Restart the application and confirm the trusted exact path remains listed.",
        "Stores executable name, canonical path and trust metadata locally.",
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
        "_open_simulation", "window",
    ),
    CapabilityGuide(
        "attack-map", "MITRE ATT&CK Coverage", "Visibility",
        "Maps observed activity and verified detection coverage to ATT&CK techniques.",
        ("Open ATT&CK Map.", "Review Coverage and blind spots.",
         "Select a technique for evidence and remediation detail."),
        "Coverage entries resolve to real detectors or simulations.",
        "Local evidence; links to MITRE require an explicit browser action.",
        "_open_attack_heatmap", "window",
    ),
    CapabilityGuide(
        "threat-intel", "Threat Intelligence", "Exposure",
        "Correlates trusted vulnerability intelligence with locally observed software.",
        ("Open Threat Intel.", "Refresh intelligence when online access is allowed.",
         "Review host-applicable entries.", "Stage rather than auto-run a fix."),
        "Confirm ignored or remediated entries no longer inflate posture incorrectly.",
        "Feed retrieval is inbound; host evidence is not uploaded.",
        "_open_threat_intel", "window",
    ),
    CapabilityGuide(
        "forensics", "Forensics and Cases", "Investigation",
        "Preserves evidence references, timelines, custody, privacy-minimized exports "
        "and investigation context.",
        ("Open Forensics.", "Select an incident or evidence source.",
         "Build the timeline.", "Add references to a case.", "Export a sanitized view."),
        "Verify the custody chain and privacy manifest before sharing.",
        "Restricted references and free-form comments are excluded by default.",
        "_open_forensics_hub", "window",
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
        "inventory and deduplicated event ingestion. It is a local preview "
        "boundary, not an internet-facing enterprise server.",
        ("Open Enterprise Settings.", "Choose a tenant and unused loopback port.",
         "Enable the fleet service and save.", "Restart Angerona.",
         "Use signed, fresh, one-time requests from a local integration."),
        "The loopback health endpoint responds, signed requests work once, and "
        "replayed, stale, tampered, cross-tenant, or quarantined requests fail.",
        "Disabled by default, bound to 127.0.0.1, and stores data under the "
        "configured Angerona data directory.",
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
        "world-view", "World View and System Pulse", "Observability",
        "Explains Angerona resource use, sensor continuity and internal service health.",
        ("Open World View.", "Inspect sensor and pipeline status.",
         "Click System Pulse for CPU, memory and network history."),
        "Unknown or stale sensors appear degraded rather than healthy.",
        "Host metrics remain local.",
        "_open_worldview", "window",
    ),
    CapabilityGuide(
        "advanced-console", "Advanced Console", "Operations",
        "Operational diagnostics for models, watchdog, telemetry and service recovery; "
        "saved configuration remains exclusively in Settings.",
        ("Open Advanced Console.", "Choose the diagnostic area.",
         "Review status before restarting a component.", "Return to Settings to configure it."),
        "A diagnostic action records its result without creating duplicate settings.",
        "May expose local diagnostic metadata on screen; no automatic egress.",
        "_open_upgrade_console", "window",
    ),
)


def search_guides(query: str) -> tuple[CapabilityGuide, ...]:
    terms = tuple(part for part in str(query or "").casefold().split() if part)
    if not terms:
        return GUIDES
    result = []
    for guide in GUIDES:
        text = " ".join((
            guide.key, guide.name, guide.category, guide.definition,
            " ".join(guide.steps), guide.verify, guide.privacy,
        )).casefold()
        if all(term in text for term in terms):
            result.append(guide)
    return tuple(result)
