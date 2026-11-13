"""Operator guidance for the reviewed, bundled module diagnostics."""
from __future__ import annotations

from angerona.core.module_usage import module_identity


# The built-in capability ID uses the same module leaf. Display names and
# diagnostic messages are not used to select guidance or authorize actions.
_BUILTIN_GUIDANCE = {
    "adversary_combat": (
        "Review response readiness, host authority and the action journal. "
        "Use verified recovery for a journal hold before retesting response readiness."
    ),
    "ai_model_integrity": (
        "Check the configured Ollama model directory and compare its bytes with the approved "
        "model baseline. Investigate a hash mismatch before approving a replacement."
    ),
    "ai_triage": (
        "In Full Mode, verify the configured local Ollama endpoint and installed model. "
        "Review a missing or stale model attestation in AI Model Integrity Guard."
    ),
    "amsi_bridge": (
        "Check Windows AMSI provider registration and the native probe result. If initialization "
        "failed, repair the approved antivirus provider through its supported installer."
    ),
    "api_patch_detector": (
        "Review the affected export and the on-disk Windows DLL version. Compare against the "
        "approved Windows image before investigating a possible in-memory hook."
    ),
    "app_control_monitor": (
        "Check access to the Code Integrity and AppLocker event channels. Review channel gaps "
        "and signature correlation before relying on reported application-control decisions."
    ),
    "arp_watchdog": (
        "Check the selected interface, current gateway and neighbor collection mode. Review a "
        "gateway MAC change against an independently verified gateway before updating trust."
    ),
    "audit_log_guard": (
        "Check Security and System event-log access and the last read cursor. Preserve the "
        "affected channel and record IDs if log-clear evidence is present."
    ),
    "authentication_extension_guard": (
        "Compare the observed authentication-extension registrations with the approved Windows "
        "baseline. Investigate unrecognized package changes before accepting a new baseline."
    ),
    "av_telemetry_bridge": (
        "Check access to the Defender Operational log and inspect the bookmark and continuity "
        "status. Preserve and review any recorded gap before relying on current coverage."
    ),
    "beacon_detector": (
        "Check whether the network collector supplies timestamped outbound connections. Review "
        "recent intervals for the affected destination before treating a cadence as suspicious."
    ),
    "behavioral_tuner": (
        "Check read access to the behavioral baseline database and review its integrity. "
        "Preserve the existing database before any approved restoration."
    ),
    "canary_drill": (
        "In Telemetry Canary Drills, compare the expected source with the actual echo. "
        "Check ETW Core Listener first when the kernel-loopback echo is missing."
    ),
    "chaos_harness": (
        "Open the CHAOS scenario results and inspect the first failed invariant. Reproduce the "
        "same scenario in the harness's isolated fixture before changing live settings."
    ),
    "cloud_escalation": (
        "Review the redaction and response-parser controls. If cloud use was enabled, check the "
        "approved provider configuration separately using a non-sensitive test request."
    ),
    "compliance_mapper": (
        "Check the failed ATT&CK technique and its NIST or STIG mapping. Confirm the source "
        "mapping and control implementation state before exporting compliance evidence."
    ),
    "counter_agentic": (
        "Check for process and action telemetry from the affected agent. Review advisory "
        "discovery and action-cadence evidence with the benign control before escalating."
    ),
    "daily_briefing": (
        "Check the reporting window, alert counts and output access. If the deterministic "
        "briefing works but AI enrichment is absent, test AI Triage separately."
    ),
    "deception": (
        "Review admitted canary identities and mutation/deletion coverage. Windows new "
        "deployment and its disposable diagnostic are held pending a safe native provider."
    ),
    "detection_runtime": (
        "Check per-lane queue pressure, drops and observe-mode authority. Trace saturation to "
        "the affected collector before changing queue limits or response policy."
    ),
    "driver_provenance_guard": (
        "Check driver inventory completeness, verifier availability and the load-to-hash evidence "
        "join. Compare the exact driver hash and signer with the approved source."
    ),
    "dynamic_resource": (
        "Check psutil initialization and access to the current process priority. Compare the "
        "observed setting with the module's selected resource profile."
    ),
    "ebpf_sensor": (
        "On Linux, review the eBPF opt-in setting, supported kernel and BCC availability. "
        "Use the approved deployment to restore the reader, then verify event delivery."
    ),
    "etw_listener": (
        "Check pywin32, Security event 4688 access and the current ETW collection mode. "
        "Compare the documented process-polling fallback with the coverage you need."
    ),
    "etw_realtime_sensor": (
        "Check pywintrace, ETW session authorization and Kernel-Process delivery. Confirm a "
        "fresh ETW event after repair and review any gap covered only by fallback."
    ),
    "evidence_lattice": (
        "Review source event identities, correlation windows and deduplication. Confirm the "
        "source modules still deliver distinct records for the entity under review."
    ),
    "evolution_engine": (
        "Check synthesis queue and circuit state, then review the generated YARA rule in an "
        "offline fixture before admitting it into the active ruleset."
    ),
    "exposure_graph_guard": (
        "Check that the graph snapshot is current and covers the affected entity and "
        "relationships. Restore the missing observation before assessing the exposure path."
    ),
    "fast_path": (
        "Review the loaded deterministic rules and the exact failed pattern. Verify matching "
        "with the built-in inert fixture and inspect the input event source."
    ),
    "file_integrity": (
        "Check the affected watch root, filesystem coverage and baseline access. Preserve "
        "unexpected hashes and investigate changes before reviewing baseline updates."
    ),
    "fleet_health_monitor": (
        "Review the signed fleet health bundle, rollout identity and evidence freshness. "
        "Refresh the affected collector's approved receipt before reassessing the rollout."
    ),
    "flight_cache": (
        "Check cache database access, retained row counts and eviction pressure. Use a fresh "
        "cache diagnostic after correcting the storage or capacity issue."
    ),
    "forensics": (
        "Check the exact process birth identity and capture output access. Review retention "
        "and deduplication limits before requesting a new capture."
    ),
    "frz_heartbeat": (
        "Compare heartbeat age and process generation. Check whether the pinned native "
        "watchdog or authenticated Python heartbeat is active, then verify a fresh pulse."
    ),
    "hardware_crypto": (
        "On Windows, check DPAPI access for the current identity and review TPM availability "
        "separately. Retest with the disposable secret before using live protected data."
    ),
    "hermetic_packager": (
        "Review package signature, release provenance and filesystem custody in packaging "
        "diagnostics. Reacquire a verified package if its signature or provenance fails."
    ),
    "identity_session_guard": (
        "Check identity event source enrollment, timestamps and privacy-filtered fields. "
        "Restore the missing feed and verify recent session evidence."
    ),
    "immutable_recovery_guard": (
        "Review the signed recovery policy, offline or immutable target, and its verification "
        "receipt. Resolve missing independent custody before relying on that recovery copy."
    ),
    "intel_sync": (
        "Check configured threat-intelligence feeds, last verified refresh and source errors. "
        "Confirm a fresh approved feed before relying on KEV or driver correlations."
    ),
    "ipc_guard": (
        "Check the authenticated local endpoint and key custody. Repeat the isolated valid-key "
        "and wrong-key loopback checks before diagnosing peer enrollment."
    ),
    "kernel_bridge": (
        "Check whether the approved Angerona kernel driver is installed, its identity verifies, "
        "and its protocol matches this build. Restore it through the supported installer."
    ),
    "kernel_posture_ledger": (
        "Inspect driver inventory freshness, truncation and authenticated ledger continuity. "
        "Recollect incomplete posture evidence before accepting a new snapshot."
    ),
    "linux_observe": (
        "On Linux, check access to process and network inventory from the current account. "
        "Review which reads failed, then compare with a fresh Observe snapshot."
    ),
    "lsass_guard": (
        "Check process creation and command-line telemetry for the relevant time window. "
        "Use the inert dump-signature fixture to verify the rule without touching LSASS."
    ),
    "macos_observe": (
        "On macOS, inspect process and network snapshot errors from the current account. "
        "Verify the repaired Observe collector with a fresh snapshot."
    ),
    "mem_inject_scanner": (
        "Check the Windows memory-query provider and target access limitations. Verify the "
        "scanner using its own process, then review inaccessible targets as coverage gaps."
    ),
    "memory_timemachine": (
        "Check retained timeline capacity and the identity used for snapshot deduplication. "
        "Preserve relevant timeline entries before addressing a storage or capture gap."
    ),
    "mobile_bridge": (
        "Check the optional mobile integration, approved signal-cli identity and authenticated "
        "receipt. Verify the configured bridge separately before trusting message delivery."
    ),
    "network_monitor": (
        "Inspect IPv4 and IPv6 connection collection and process-attribution coverage. "
        "Compare a fresh connection to its tuple and process identity after fixing the collector."
    ),
    "network_protocol_decoder": (
        "Verify upstream packet or DNS observations are present and decodable. Recheck the DGA "
        "fixture and review which protocol data was unavailable."
    ),
    "network_trust_monitor": (
        "Review the current route, Wi-Fi security and profile-trust evidence. Verify the "
        "connected network independently before making a trusted-profile change."
    ),
    "packet_sniffer": (
        "Check the approved capture backend, interface selection and capture isolation. "
        "After restoring capture access, verify receipt of a benign packet."
    ),
    "peripheral_dma_guard": (
        "Check peripheral inventory completeness and platform DMA protection evidence. "
        "Investigate unexpected device changes and use supported firmware settings for DMA posture."
    ),
    "persistence_sweep": (
        "Review the failing persistence source and its read access. Compare suspicious startup "
        "entries with known-good software and use the classifier fixture to verify rule changes."
    ),
    "platform_attestation_guard": (
        "Review the attestation provider, signature and freshness. Refresh the approved "
        "platform evidence before relying on code-integrity or DMA posture claims."
    ),
    "posture_hardening": (
        "Check authenticated after-action report intake and the weakness inventory. "
        "Review the specific finding and validate a proposed change in the supported sandbox."
    ),
    "process_egress_guard": (
        "Review PID-birth attribution, lease receipts and the active enforcement backend. "
        "Check connection evidence after recovery before relying on process-level blocking."
    ),
    "process_monitor": (
        "Check process inventory freshness and the affected process birth time and lineage. "
        "Compare a benign process creation with the active collector's result."
    ),
    "provenance_graph": (
        "Review the graph entity's parent chain and source event availability. Restore missing "
        "upstream process, file or network evidence before rechecking the graph."
    ),
    "purple_guard": (
        "Review the exact drill marker, owning scenario and source telemetry. Rerun the bounded "
        "fixture after correcting source coverage or rule matching."
    ),
    "rag_provenance_guard": (
        "Check the pinned reference source, digest and provenance. Review a changed source "
        "before admitting it back into the reference collection."
    ),
    "ransomware_heuristics": (
        "Check monitored roots, durable change tracking and traversal holds. Preserve "
        "suspicious changes and compare the affected source with its last verified checkpoint."
    ),
    "release_transparency_guard": (
        "Compare release signatures, metadata expiry and the minimum accepted version. "
        "Reacquire official release metadata if freshness or threshold verification fails."
    ),
    "remote_bridge": (
        "Check the configured peer, enrollment and shared-secret custody. Verify the "
        "authenticated handshake before attempting a new remote session."
    ),
    "resource_governor": (
        "Check psutil sampling, current pacing and active resource leases. Verify that normal "
        "throttle returns when an approved priority task releases its lease."
    ),
    "self_healer": (
        "Check crash-snapshot directory access and the staged repair status. Review an "
        "authenticated snapshot and its candidate change before activating source repair."
    ),
    "self_integrity": (
        "Compare the integrity baseline, release identity and source custody. Preserve any "
        "tamper evidence and use verified recovery for a confirmed file mismatch."
    ),
    "shadow_shield": (
        "Review recovery-cache access, capacity and available snapshots. Verify a known-good "
        "recovery source before relying on an affected restore point."
    ),
    "shadowcopy_guard": (
        "Check process-command telemetry for shadow-copy or boot recovery changes. "
        "Verify the classifier with the inert recovery-tamper fixture."
    ),
    "siem_forwarder": (
        "Review approved SIEM endpoint settings, delivery errors and backlog. Verify encoding "
        "locally, then confirm receipt of an approved diagnostic event at the destination."
    ),
    "smart_deception": (
        "Review unresolved trips, exact-object custody and the quarantine ledger. Resolve "
        "the relevant custody or witness hold before requesting recovery."
    ),
    "soar": (
        "Review the corroborating event sources, policy and response cursor for the affected "
        "playbook. Verify protected-process exclusions in the offline fixture."
    ),
    "soar_engine": (
        "Review Active Response SOAR mode, policy and admitted response authority. Verify the "
        "approved playbook in simulation before enabling host actions."
    ),
    "speculative_triage": (
        "Review the high-risk marker and its source event. If AI enrichment is unavailable, "
        "verify AI Triage readiness separately before retesting enrichment."
    ),
    "spyware_guard": (
        "Open SpywareGuard and inspect collector coverage and the last scan report. Test the "
        "detection fixture and review response receipts separately for any claimed isolation."
    ),
    "ssh_surface_guard": (
        "Check OpenSSH configuration, included files and event-channel access. Compare key "
        "or tunnel drift with the approved baseline before accepting a change."
    ),
    "storage_hygiene": (
        "Check managed storage roots, available space and the proposed cleanup list. Review "
        "retained evidence and use the storage review controls for approved cleanup."
    ),
    "sys_bridge": (
        "Check the sealed native bridge identity and active fallback mode. Restore the bridge "
        "from a verified build and retest syscall resolution before relying on it."
    ),
    "sysmon_listener": (
        "Check Sysmon installation, channel access and the generation-bound cursor. Review "
        "fallback coverage and verify a fresh Sysmon event after repair."
    ),
    "temporal_tradecraft_correlator": (
        "Check the ordered source events and their time window. Restore missing SSH or "
        "identity telemetry before validating the affected correlation sequence."
    ),
    "ugcap_guard": (
        "Review the integrity hold, exact failing gate and recovery evidence. Follow UGCAP's "
        "verified recovery flow before reactivating held modules."
    ),
    "usb_monitor": (
        "Check removable-volume discovery and pending device approval. Verify the mount-change "
        "and approval checks before relying on scanning or allowing a device."
    ),
    "watchdog_monitor": (
        "Compare the affected worker's generation, deadline and first completed cycle. "
        "Verify the watchdog's recovery fixture and check for repeating faults."
    ),
    "wfp_controller": (
        "Check IP Helper connection-table collection and WFP telemetry availability. Verify "
        "ownership of a fresh full-tuple connection after restoring the relevant provider."
    ),
    "wlan_monitor": (
        "Check the Windows WLAN query, current adapter and connection status. Recheck after "
        "restoring adapter or query access."
    ),
    "yara_scanner": (
        "Check the supported YARA backend, ruleset compilation and selected scan roots. "
        "Repeat the in-process marker check before running another scan."
    ),
}

_OVERDRIVE_GUIDANCE = (
    "Review Overdrive's GUI latency and load samples. Verify that its offline tuning profiles "
    "change monotonically with load before relying on the displayed pacing band."
)
_CUSTOM_GUIDANCE = (
    "Review this module's diagnostic output and its publisher's documented prerequisites, "
    "then retest the same module."
)


def module_guidance(mod: object) -> str:
    """Return inert, bundled guidance for a module or a custom-module fallback."""
    identity = module_identity(mod)
    if identity == ("angerona.core.perf_governor", "PerfGovernor"):
        return _OVERDRIVE_GUIDANCE
    package, _, leaf = identity[0].rpartition(".")
    if package == "angerona.modules":
        return _BUILTIN_GUIDANCE.get(leaf, _CUSTOM_GUIDANCE)
    return _CUSTOM_GUIDANCE
