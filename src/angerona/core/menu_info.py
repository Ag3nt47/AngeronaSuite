"""Canonical plain-language Info topics for Angerona's tabbed menus."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class MenuInfoTopic:
    """User-facing meaning, implementation evidence, and sandbox scope."""

    key: str
    title: str
    overview: str
    functions: tuple[tuple[str, str], ...]
    source_paths: tuple[str, ...]
    locations: tuple[str, ...] = ()


def _topic(
    key: str,
    title: str,
    overview: str,
    functions: tuple[tuple[str, str], ...],
    *source_paths: str,
    locations: tuple[str, ...] = (),
) -> MenuInfoTopic:
    return MenuInfoTopic(
        key, title, overview, functions, tuple(source_paths), locations
    )


MENU_INFO: dict[str, tuple[MenuInfoTopic, ...]] = {
    "help": (
        _topic(
            "help-center", "Help & Info",
            "The end-user guide for setup, capabilities, privacy boundaries, verification, and troubleshooting. Each topic is read-only guidance and links back to the canonical operational surface.",
            (
                ("Topic tab", "A focused guide for one capability or common task."),
                ("Interactive tour", "Highlights the live dashboard controls without changing configuration."),
                ("Evidence and limitations", "Shows what supports a capability claim and what remains unavailable or incomplete."),
            ),
            "src/angerona/gui/main_window.py", "src/angerona/gui/help_content.py",
            "src/angerona/core/capability_guide.py",
            locations=("{data}/settings.json",),
        ),
    ),
    "dashboard": (
        _topic(
            "live-alerts", "Live Alerts",
            "The current security-event stream. It combines module findings into a bounded, readable queue without changing the underlying evidence.",
            (
                ("Severity", "The assessed urgency: Info, Low, Medium, High, or Critical."),
                ("Analyze", "Requests an explanation through the configured local-first AI path."),
                ("Resolve", "Opens the review workflow; it does not silently suppress evidence."),
            ),
            "src/angerona/gui/pages.py", "src/angerona/core/eventbus.py",
            locations=("{data}/flight-recorder.db", "{data}/shared_logs"),
        ),
        _topic(
            "soar-queue", "SOAR Queue",
            "A reviewable queue of proposed response actions. Consequential actions stay behind policy and operator-confirmation gates.",
            (
                ("Queued", "An action has been proposed but not executed."),
                ("Approve", "Authorizes only the selected bounded action."),
                ("Reject", "Closes or declines the proposal while retaining its audit trail."),
            ),
            "src/angerona/gui/pages.py", "src/angerona/modules/soar.py",
            "src/angerona/core/action_policy.py",
            locations=("{data}/shared_logs/soar_queue.json",),
        ),
        _topic(
            "scan-center", "Scan Center",
            "Runs bounded local file, port, network, and platform scans away from the interface thread and presents redacted results.",
            (
                ("Path scan", "Inspects the chosen local path within configured size and time limits."),
                ("Quick scan", "Checks a small set of security-sensitive locations."),
                ("Stop", "Requests cooperative cancellation of the active scan."),
            ),
            "src/angerona/gui/scan_center.py", "src/angerona/resilience/scanner.py",
            "src/angerona/modules/yara_scanner.py",
            locations=("{data}/diagnostics", "{data}/shared_logs"),
        ),
    ),
    "settings": (
        _topic(
            "settings-overview", "Overview",
            "A map showing which Settings area owns each configuration choice, its privacy boundary, and whether it applies live or after restart.",
            (("Area", "The single canonical editor for that configuration."), ("Apply", "Live means immediate; Restart means the service must be relaunched.")),
            "src/angerona/gui/pages.py", "src/angerona/core/settings_catalog.py",
            locations=("{data}/settings.json",),
        ),
        _topic(
            "settings-information", "Information",
            "A searchable capability guide covering purpose, procedure, verification, privacy, maturity, evidence, limitations, and direct navigation.",
            (("Maturity", "How completely the capability is exposed and verified."), ("Take me there", "Navigates only when the declared destination exists in this build.")),
            "src/angerona/gui/pages.py", "src/angerona/core/capability_guide.py",
            "src/angerona/gui/help_content.py",
        ),
        _topic(
            "settings-general", "General",
            "Controls the local AI endpoint, visual presentation, integrity behavior, dashboard mode, and update source.",
            (("Local AI", "Ollama stays on the configured local service unless separate cloud consent is enabled."), ("Appearance", "Theme, scale, motion, dashboard, and minimized-orb presentation."), ("Integrity", "Guards signed learning inputs and optional performance paths.")),
            "src/angerona/gui/pages.py", "src/angerona/core/config.py",
            "src/angerona/gui/theme.py", "src/angerona/updater/github_updater.py",
            locations=("{data}/settings.json",),
        ),
        _topic(
            "settings-system", "System",
            "Controls startup registration, loopback services, resource behavior, USB approval, the Black Box, deception placement, and platform telemetry.",
            (("Startup", "Registers Angerona with the platform-specific boot mechanism."), ("MCP", "Optional loopback-only integration service."), ("USB approval", "Session-locked inspection consent backed by protected credentials."), ("Platform sensors", "Optional privileged supplements; the desktop remains usable without them.")),
            "src/angerona/gui/pages.py", "src/angerona/core/autostart.py",
            "src/angerona/core/config.py", "src/angerona/app.py",
            locations=("{data}/settings.json", "{data}/diagnostics"),
        ),
        _topic(
            "settings-enterprise", "Enterprise",
            "Shows evidence-backed readiness and configures the authenticated loopback fleet preview, signed content, policy, and proof controls.",
            (("Readiness", "An engineering assessment, not a certification or marketing grade."), ("Fleet service", "Loopback-only authenticated API; remote fleet access is not implied."), ("Evidence", "Bounded public-safe proof with local identifiers removed.")),
            "src/angerona/gui/pages.py", "src/angerona/core/enterprise_readiness.py",
            "src/angerona/core/fleet_service.py", "src/angerona/core/capability_manifest.py",
            locations=("{data}/settings.json", "{data}/enterprise"),
        ),
        _topic(
            "settings-aria", "ARIA",
            "Configures the optional local-first assistant, voice, conversation, hand controls, inbox, research, notifications, and every related egress consent.",
            (("Assistant", "The HUD and local question/answer layer; off on a fresh install."), ("Voice and awareness", "Opt-in microphone features with visible state and bounded transient context."), ("Cloud fallback", "Separate, default-off consent for sanitized provider requests."), ("Restore privacy defaults", "Stages all optional listeners and egress controls off; Save commits it.")),
            "src/angerona/gui/pages.py", "src/angerona/core/assistant.py",
            "src/angerona/connectors/voice.py", "src/angerona/core/config.py",
            locations=("{data}/settings.json", "{data}/models"),
        ),
        _topic(
            "settings-trusted", "Trusted Processes",
            "Manages exact-path process trust and supervised baseline learning to reduce false positives without broad name-only exclusions.",
            (("Exact path", "Trust is tied to a specific executable location."), ("Publisher", "Authenticode identity may strengthen the trust decision."), ("Baseline", "A supervised snapshot for review, not an automatic allow-all rule.")),
            "src/angerona/gui/pages.py", "src/angerona/core/process_allowlist.py",
            "src/angerona/core/process_baseline.py",
            locations=("{data}/settings.json", "{data}/process_baseline.json"),
        ),
        _topic(
            "settings-mobile", "Mobile Integration",
            "Configures the optional Signal bridge, operator destination, and protected command PIN. It is off by default and requires explicit egress consent.",
            (("Signal client", "The locally installed transport used for confirmed messages."), ("Destination", "The explicit operator endpoint; it is not shown in status dashboards."), ("Command PIN", "Stored in the operating-system protected credential store, never plaintext settings.")),
            "src/angerona/gui/pages.py", "src/angerona/modules/mobile_bridge.py",
            "src/angerona/gui/upgrade_console.py",
            locations=("{data}/settings.json", "Operating-system protected credential store"),
        ),
        _topic(
            "settings-api-keys", "API Keys",
            "Stores optional provider credentials and their preference order. Angerona remains fully local when none are configured.",
            (("Configured", "A protected value exists; the UI never reveals it after storage."), ("Provider order", "The explicit fallback sequence for eligible cloud actions."), ("Clear and save", "Removes that provider credential from protected storage.")),
            "src/angerona/gui/pages.py", "src/angerona/core/provider_credentials.py",
            "src/angerona/engines/ai_consult.py",
            locations=("Operating-system protected credential store", "{data}/settings.json (preferences only; no secrets)"),
        ),
    ),
    "operations": (
        _topic("operations-overview", "Overview", "A local SOC summary of cases, evidence, audit records, assets, and detection content.", (("Metric cards", "Bounded counts from the local stores."), ("Local only", "This workspace does not expose a remote shell.")), "src/angerona/gui/operations_center.py", "src/angerona/core/operations_center.py", locations=("{data}/evidence.db",)),
        _topic("operations-cases", "Cases", "Creates and manages incident cases that organize evidence and analyst decisions.", (("Status", "The case lifecycle from open through closed."), ("Severity", "The analyst-assigned urgency of the case.")), "src/angerona/gui/operations_center.py", "src/angerona/core/case_management.py", locations=("{data}/cases.db",)),
        _topic("operations-hunt", "Hunt", "Runs bounded local queries over collected evidence and presents their results without arbitrary remote execution.", (("Template", "A constrained, predeclared hunt shape."), ("Limit", "The maximum bounded result count.")), "src/angerona/gui/operations_center.py", "src/angerona/core/hunt_workspace.py", locations=("{data}/evidence.db",)),
        _topic("operations-assets", "Assets", "Shows locally observed devices, endpoints, and identity metadata used to understand coverage.", (("Asset", "A bounded local inventory record."), ("Last seen", "The latest observation time, not a guarantee the asset is online.")), "src/angerona/gui/operations_center.py", "src/angerona/core/asset_inventory.py", locations=("{data}/asset_inventory.json",)),
        _topic("operations-detections", "Detection Content", "Reviews local detection packages and their trust, version, and lifecycle state.", (("Signed", "Content identity and digest have passed the configured trust gate."), ("Enabled", "The package is eligible to contribute detections.")), "src/angerona/gui/operations_center.py", "src/angerona/core/detection_packages.py", "src/angerona/core/detection_registry.py", locations=("{data}/detection-packages",)),
        _topic("operations-interop", "Parity & Interop", "Shows bounded interoperability status for schemas and external query tooling without claiming unsupported parity.", (("Parity", "The portion of the declared contract currently implemented."), ("Interop", "Translation or export support; it does not transfer data by itself.")), "src/angerona/gui/operations_center.py", "src/angerona/core/security_interop.py", "src/angerona/core/ocsf_export.py", locations=("{data}/interop",)),
        _topic("operations-audit", "Audit", "Reviews the local tamper-evident operator and security action trail.", (("Actor", "The local identity recorded for an action."), ("Digest", "The content fingerprint used for integrity verification."), ("Export", "Creates a bounded signed review artifact.")), "src/angerona/gui/operations_center.py", "src/angerona/core/admin_audit.py", "src/angerona/core/audit_export.py", locations=("{data}/audit",)),
    ),
    "attack-map": (
        _topic("attack-live", "Live Heat", "Maps recent observed activity to MITRE ATT&CK techniques with time-decaying intensity.", (("Heat", "Recent mapped activity; it is not by itself proof of compromise."), ("Active only", "Hides currently cold techniques without deleting history."), ("Actor filter", "Compares the view to a known playbook; it does not attribute an attacker.")), "src/angerona/gui/attack_heatmap.py", "src/angerona/core/attack_tracker.py"),
        _topic("attack-coverage", "Coverage", "An honest detect/simulate/remediate matrix that keeps unsupported and partial techniques visible.", (("Detect", "A real evidence path can identify the technique."), ("Simulate", "A benign drill can exercise it."), ("Remediate", "A vetted bounded response exists.")), "src/angerona/gui/attack_heatmap.py", "src/angerona/core/attack_coverage.py"),
        _topic("attack-top", "Top Techniques", "Ranks the currently hottest mapped techniques for fast review.", (("Rank", "Order by current decayed heat."), ("Technique", "The ATT&CK identifier and readable behavior name.")), "src/angerona/gui/attack_heatmap.py", "src/angerona/core/attack_tracker.py"),
    ),
    "red-team": (
        _topic("redteam-run", "Run", "Configures and launches non-destructive adversary simulations made from reversible markers and bounded local behaviors.", (("Intensity", "Scales the number, pace, and noise of benign stages."), ("Campaign", "Runs stages in kill-chain order."), ("Auto-remediate", "Exercises eligible reviewed response paths after findings.")), "src/angerona/gui/red_team_console.py", "src/angerona/shark/red_team.py", "src/angerona/shark/shark_attack.py", locations=("{data}/redteam_history.json",)),
        _topic("redteam-history", "History", "Reviews prior simulation runs and their recorded outcomes.", (("Run", "One bounded simulation attempt."), ("Result", "Recorded detector/remediation evidence from that run.")), "src/angerona/gui/red_team_console.py", "src/angerona/shark/aar_report.py", locations=("{data}/redteam_history.json", "{data}/redteam_aar.json")),
        _topic("redteam-device", "Device Security Lab", "Runs safe, consented checks against enrolled device targets without treating enrollment as broad execution authority.", (("Enrollment", "An explicitly registered device test target."), ("Scan", "A bounded security check for that target.")), "src/angerona/gui/red_team_console.py", "src/angerona/core/device_security_lab.py", locations=("{data}/device-security-lab",)),
        _topic("redteam-editor", "Sandbox Editor", "Edits the red-team engine behind syntax checks and explicit save/revert controls. The Info-tab sandbox is a separate non-production working copy.", (("Save", "Writes the embedded editor's explicitly selected red-team source."), ("Revert", "Restores the previous editor-session version.")), "src/angerona/gui/red_team_console.py", "src/angerona/shark/red_team.py"),
    ),
    "advanced-console": (
        _topic("advanced-mobile", "Mobile Integration", "Shows privacy-minimized readiness and routes configuration to its single Settings owner.", (("Readiness", "Whether required local components are configured, without revealing destinations or secrets."), ("Test", "Sends one explicitly confirmed message with no event evidence.")), "src/angerona/gui/upgrade_console.py", "src/angerona/modules/mobile_bridge.py"),
        _topic("advanced-ai", "AI Sandbox & Models", "Shows provider readiness, local Ollama models, and a staging area for AI-proposed code.", (("Provider readiness", "Only configured/not configured; secrets remain hidden."), ("Implement", "Writes to an operator-chosen sandbox file, not an automatic production deployment.")), "src/angerona/gui/upgrade_console.py", "src/angerona/engines/ollama_client.py", "src/angerona/core/provider_credentials.py"),
        _topic("advanced-watchdog", "Watchdog Hub", "Shows live module supervision and resilience status from the attached runtime.", (("Watchdog", "The out-of-process guardian for liveness and bounded recovery."), ("Safe mode", "A restart backoff state that prevents uncontrolled loops.")), "src/angerona/gui/upgrade_console.py", "src/angerona/resilience/watchdog.py", "src/angerona/resilience/supervisor.py", locations=("{data}/diagnostics",)),
        _topic("advanced-telemetry", "Telemetry Hub", "Summarizes running modules, bounded event-ring activity, CPU, memory, and recent terminal-safe telemetry.", (("Ring events", "Bounded in-memory event records."), ("CPU/RAM", "Presentation snapshots, not long-term capacity guarantees.")), "src/angerona/gui/upgrade_console.py", "src/angerona/core/eventbus.py", "src/angerona/telemetry/sensors.py", locations=("{data}/diagnostics",)),
    ),
}


def normalize_tab_label(label: object) -> str:
    """Remove decorative glyphs and punctuation for stable topic lookup."""
    folded = str(label or "").casefold()
    return " ".join(re.findall(r"[a-z0-9]+", folded))


def topics_for(surface: str) -> tuple[MenuInfoTopic, ...]:
    return MENU_INFO.get(str(surface).strip().casefold(), ())


def get_menu_info(surface: str, tab_label: str) -> MenuInfoTopic | None:
    wanted = normalize_tab_label(tab_label)
    if not wanted:
        return None
    candidates = topics_for(surface)
    for topic in candidates:
        title = normalize_tab_label(topic.title)
        if wanted == title or wanted.endswith(" " + title):
            return topic
    return None


def validate_menu_info(catalog=MENU_INFO) -> None:
    seen: set[str] = set()
    for surface, topics in catalog.items():
        if not surface or not topics:
            raise ValueError("menu Info surfaces require at least one topic")
        titles: set[str] = set()
        for topic in topics:
            if topic.key in seen:
                raise ValueError(f"duplicate menu Info key: {topic.key}")
            seen.add(topic.key)
            title = normalize_tab_label(topic.title)
            if not title or title in titles:
                raise ValueError(f"duplicate menu Info title in {surface}: {topic.title}")
            titles.add(title)
            if not topic.overview or not topic.functions or not topic.source_paths:
                raise ValueError(f"incomplete menu Info topic: {topic.key}")
            for path in topic.source_paths:
                normalized = path.replace("\\", "/")
                if normalized.startswith("/") or ".." in normalized.split("/"):
                    raise ValueError(f"unsafe menu Info source path: {path}")


validate_menu_info()
