# Exhaustive module review — 2026-09-21

All **84 discovered modules** are represented below. Baseline module results: **68 passed, 0 failed, 16 expected skips**; the event-pipeline check adds one pass. All 24 discovered core self-tests passed. A skip is not a passing live sensor.

This is a source-level review of lifecycle, inactive work, retained state and prerequisite handling, backed by isolated offline self-tests. No sensors, inference, containment or live module run loops were started for the inventory. Module-specific changes are required only where evidence identifies a defect. Shared applicability/count work is coordinated by the parent agent. Required security evidence that is missing or broken must remain visible as degraded; no attached USB device or disconnected WLAN alone does not justify disabling hotplug guards.

The JSON companion retains names/classes, supported platforms, defaults, prerequisites, test details and source-line evidence. Missing `register()` is valid: this manager discovers `BaseModule` subclasses directly. No duplicate declared CODEs or discovery import errors were found.

| Module source | Baseline test | Applicability / dependency | Review and needed change |
| --- | --- | --- | --- |
| `adversary_combat.py` | SKIP | Windows response authority and authenticated action journal | Bounded admission queue, seen ring, recovery journal and generation-aware response lifecycle reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `ai_model_integrity.py` | PASS | Local Ollama model inventory plus separately approved authenticated baseline | File/manifest/inventory caps and cancellation-aware hashing reviewed; absent models are idle, failed attestation remains visible. **SHARED USAGE POLICY REVIEW** |
| `ai_triage.py` | SKIP | Attested local Ollama listener and approved model | Recovery helper ownership, bounded calls and circuit-breaker readiness reviewed. **SHARED USAGE POLICY REVIEW** |
| `amsi_bridge.py` | SKIP | Windows amsi.dll plus functional antimalware provider | Native scan/close lifetime, restart fallback and native error handling reviewed; three fixture-reproduced defects. **BH-01, BH-02, BH-06** |
| `api_patch_detector.py` | PASS | Windows PE exports, readable system DLLs and process memory | Disk size bounds and coverage health reviewed; alert state never expires and suppresses recurrent hooks. **BH-03** |
| `app_control_monitor.py` | PASS | Windows CodeIntegrity Operational event channel | Bounded event batches, authenticated cursor/pending state and owned-source cleanup reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `arp_watchdog.py` | PASS | Windows ARP cache; optional Scapy capture; approved baseline | Authenticated baseline cap, separate capture stop token and polling fallback reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `audit_log_guard.py` | PASS | Windows Event Log read access and authenticated checkpoints | Fixed channel state and resource ownership reviewed; native source close is a no-op, so proposed restart defect ruled out. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `authentication_extension_guard.py` | PASS | Windows registry and authentication-extension evidence | Fixed collection surfaces, privacy-minimized drift and observe-only outputs reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `av_telemetry_bridge.py` | PASS | Defender event channel or bounded PowerShell fallback plus recorder custody | Batch/XML/output bounds and fail-closed fallback custody reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `beacon_detector.py` | PASS | psutil process identity and shared network snapshot | Per-key history cap, stale history eviction and incomplete snapshot handling reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `behavioral_tuner.py` | SKIP | SQLite baseline store and explicit exact-hash trust approval | Candidate learning, periodic event drain and explicit trust gate reviewed; no actionable reproduced regression. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `canary_drill.py` | PASS | Trusted process sensor echo and recorder persistence | Bounded echo queue and expiry reviewed; stopped callback still parses events and advances liveness timestamp. **BH-04** |
| `chaos_harness.py` | PASS | Bound producer assurance receipts for APID/NDRD/FIM/AMSI | Challenge deadlines, explicit receipt evidence and sparse periodic work reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `cloud_escalation.py` | SKIP | Operator opt-in plus protected Gemini credentials | Default-off, dynamic key re-read and 20 calls/hour bound reviewed. **SHARED USAGE POLICY REVIEW** |
| `compliance_mapper.py` | PASS | Local telemetry/recorder plus authenticated reporting state | Bounded 2000-entry retention and durable batch drain reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `counter_agentic.py` | PASS | psutil and shared connection snapshots | Timeline expiry, per-lineage history and incomplete collection health reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `daily_briefing.py` | PASS | Local recorder; optional attested Ollama for narrative | Authenticated cursor, bounded output and deterministic fallback reviewed; stop-aware schedule slices retained. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `deception.py` | PASS | Managed canary directory; user folders require opt-in | Fixed canary set, bounded reads and incremental feed identity/cursor reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `detection_runtime.py` | PASS | Explicitly activated digest-verified detection packages | Separate bounded active/shadow queues, dedupe and stopped ingress gate reviewed. **SHARED USAGE POLICY REVIEW** |
| `driver_provenance_guard.py` | PASS | Windows driver inventory, hashing/signature access; optional kernel receipt verifier | Driver/image/output/replay bounds and observe-only evidence boundary reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `dynamic_resource.py` | SKIP | psutil Windows process-priority support | Fixed counters, cooldown and best-effort priority restoration reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `ebpf_sensor.py` | SKIP | Linux, config.ebpf_enabled, BCC, compatible kernel and privilege | Platform exclusion, explicit opt-in and BPF cleanup reviewed; inactive Linux capability excluded on Windows. **SHARED USAGE POLICY REVIEW** |
| `etw_listener.py` | PASS | Windows Security event channel; psutil fallback | Bounded page/record/outbox reads and delivery acknowledgement reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `etw_realtime_sensor.py` | PASS | Windows, pywintrace and elevated ETW access | Bounded identity cache, owned ETW session stop and polling-sensor fallback disclosure reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `evidence_lattice.py` | PASS | Structured local EventBus evidence | Bounded entities/signals/dedupe and stopped callback gate reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `evolution_engine.py` | PASS | Typed Judgment bypass proposal; optional local model | Concurrent/rate/breaker caps and stop-aware sparse idle lifecycle reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `exposure_graph_guard.py` | PASS | Explicit immutable ExposureSnapshot provider | Digest/freshness/resource contracts and sparse health refresh reviewed; absent provider must not imply protection. **SHARED USAGE POLICY REVIEW** |
| `fast_path.py` | PASS | Local structured telemetry and deterministic rules | Event cursor, stale dedupe cleanup and interruptible cadence reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `file_integrity.py` | PASS | Windows protected roots, reviewed authenticated baseline and driver evidence | File/count/byte budgets, cancellation and partial coverage receipts reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `fleet_health_monitor.py` | PASS | Explicit FleetFabric store/tenant enrollment and endpoint key custody | Typed signed-health boundary, no-command output and absent-integration behavior reviewed. **SHARED USAGE POLICY REVIEW** |
| `flight_cache.py` | PASS | Local recorder database and EventBus subscription | Fixed row cap and cache reopening reviewed; retained stopped callback still invokes closed-cache path. **BH-04** |
| `forensics.py` | SKIP | Operator opt-in; process identity and supported dump backend | Bounded PID/start-time capture dedupe and expiry reviewed. **SHARED USAGE POLICY REVIEW** |
| `frz_heartbeat.py` | PASS | Authenticated mmap; optional separately pinned native watchdog | Fixed heartbeat record and verified watchdog custody/restart reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `hardware_crypto.py` | PASS | Windows DPAPI; optional TPM support | One-shot/recheck work and honest partial hardware assurance reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `hermetic_packager.py` | PASS | Sealed installed binary or explicitly requested build tooling | Build-script size bound, signature assessment and build-job reaping reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `identity_session_guard.py` | PASS | Authenticated structured identity-session producer and local privacy key | Bounded tokenized ingress and stopped/active gates reviewed; EventBus itself deduplicates repeated subscribe calls. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `immutable_recovery_guard.py` | PASS | Pinned independent backup authority and signed recovery evidence | Fixed evidence appraisal and change-only alerting reviewed; absent required backup protection remains disclosed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `intel_sync.py` | PASS | Configured bounded threat-intelligence retrieval and local inventory | Response/indicator caps, one fetch helper and cancellation-aware publication reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `ipc_guard.py` | PASS | Local authenticated IPC key and loopback endpoint | Sixteen-connection admission, generation-owned sockets and joined helpers reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `kernel_bridge.py` | PASS | Optional AngeronaSensor driver service/device with version and identity proof | Bounded IOCTL batches and retry/stop paths reviewed; proven absent optional driver can be parked by shared policy. **SHARED USAGE POLICY REVIEW** |
| `kernel_posture_ledger.py` | PASS | Windows boot/driver posture evidence | 256-record authenticated ledger and bounded driver enumeration reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `linux_observe.py` | SKIP | Linux /proc and psutil; root optional | Platform exclusion and privacy-minimized snapshot loop reviewed. **SHARED USAGE POLICY REVIEW** |
| `lsass_guard.py` | PASS | Windows psutil process and command-line evidence | Process birth identity, live-set pruning and partial-read health reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `macos_observe.py` | SKIP | macOS process/network snapshots; signed host needed for native coverage | Platform exclusion and explicit observe-only/native-coverage disclosure reviewed. **SHARED USAGE POLICY REVIEW** |
| `mem_inject_scanner.py` | SKIP | Windows kernel32 process memory access | Per-process query/time caps, generation cancellation and dedupe expiry reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `memory_timemachine.py` | PASS | psutil plus telemetry mmap ring | Bounded per-PID caches/delta queue/strings and read-only collection reviewed; no live memory scan run. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `mobile_bridge.py` | PASS | config mobile opt-in, trusted sealed Signal CLI and contact enrollment | Pending request/replay/CLI output bounds and disabled-loop behavior reviewed. **SHARED USAGE POLICY REVIEW** |
| `network_monitor.py` | PASS | Shared connection snapshots and process start identity | Bounded recent-state maps, expiry and birth-aware connection identity reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `network_protocol_decoder.py` | PASS | Structured DNS evidence on local EventBus | 4096-entry ordered cooldown bound reviewed; stopped callback still scores DNS and changes counters. **BH-04** |
| `network_trust_monitor.py` | PASS | OS network/link/route evidence; privacy key | Link/route/command output bounds and explicit untrusted-path assessment reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `packet_sniffer.py` | SKIP | Operator opt-in, Scapy and Npcap on Windows | Subprocess capture isolation, bounded output, backoff and stop termination reviewed. **SHARED USAGE POLICY REVIEW** |
| `peripheral_dma_guard.py` | PASS | OS device/DMA posture; hardware evidence needed for stronger claims | Finite posture snapshot and observe-only limitations reviewed; no device policy changes tested. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `persistence_sweep.py` | PASS | Windows registry/startup/task/WMI evidence | Record/output/hash/change caps, partial coverage and unreviewed baseline disclosure reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `platform_attestation_guard.py` | PASS | Windows boot posture; optional enrolled TPM verifier | Bounded posture sampling and truthful OS-only versus hardware-attestation distinction reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `posture_hardening.py` | PASS | Local reviewed drill/after-action evidence and gated mitigations | Fixed report tailing and bounded Judgment receipts reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `process_egress_guard.py` | PASS | Explicit privileged admission adapter, trusted observers and lease broker | 1024-event audit dedupe and observe-only authority reviewed. **SHARED USAGE POLICY REVIEW** |
| `process_monitor.py` | PASS | psutil process snapshot and process-birth evidence | Startup PID boundary, bounded live-set replacement and partial identity health reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `provenance_graph.py` | PASS | EventBus and optional local recorder history | Node/edge/PID index bounds and incremental replay reviewed; stopped callback continues graph ingestion. **BH-04** |
| `purple_guard.py` | PASS | Exact reviewed drill policies and authenticated process/file receipts | Marker limits, bounded custody and stopped subscription admission reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `rag_provenance_guard.py` | PASS | Explicit provenance manifest and root; caller-owned trust-tier verifier | Root confinement, digest pinning, inert excerpts and absent-manifest behavior reviewed. **SHARED USAGE POLICY REVIEW** |
| `ransomware_heuristics.py` | PASS | Watched Windows user roots and authenticated change-state authority | Content/state/tree budgets, fair rotation and generation-aware scanning reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `release_transparency_guard.py` | PASS | Pinned Ed25519 publisher keys and shipped release authorization | Fail-closed validation, signed rollback floor and change-only reporting reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `remote_bridge.py` | SKIP | Operator opt-in, SENDER/RECEIVER mode, strong key, cryptography | Bounded frame, authenticated configuration and receiver retirement/join reviewed. **SHARED USAGE POLICY REVIEW** |
| `resource_governor.py` | PASS | psutil and bound module manager | Only declared adaptive-throttle modules affected; bounded level and lock ordering reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `self_healer.py` | PASS | Authenticated crash snapshots and optional attested model | Bounded snapshot/source/patch/retry/completed state and proposal-only loop reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `self_integrity.py` | PASS | Mandatory runtime enforcement targets, baseline and mutable ACL posture | Fixed target baseline, periodic ACL recheck and degradation disclosure reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `shadow_shield.py` | PASS | Configured protected files/cache and optional Windows VSS | File/version/prune bounds and byte/time work slices reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `shadowcopy_guard.py` | PASS | Windows psutil process/command-line evidence | Process-birth dedupe, live-set pruning and partial coverage health reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `siem_forwarder.py` | SKIP | Operator opt-in plus explicit sink/transport policy | Durable bounded outbox, retained cursor and loss/dead-letter health reviewed. **SHARED USAGE POLICY REVIEW** |
| `smart_deception.py` | PASS | Managed decoy directory; optional local naming model | Trip/quarantine/sample/read caps, authenticated custody and deployment cleanup reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `soar.py` | PASS | Windows typed corroborated response evidence and explicit policy | Distinct-source corroboration, pending expiry and protected-process gates reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `soar_engine.py` | SKIP | Explicit ANGERONA_SOAR_KILL_AND_ROLLBACK arm flag | Idle-by-design event loop and gated response reviewed; no host actions executed. **SHARED USAGE POLICY REVIEW** |
| `speculative_triage.py` | PASS | Supported attested local model and inference opt-in/readiness | Two joined helper workers and bounded queue/cache reviewed; adversary reports inactive callback admissions. **BH-04** |
| `ssh_surface_guard.py` | PASS | Local SSH files/logs when present; psutil and privacy key | Bounded incremental log reads, retry backoff and callback/handle cleanup reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `storage_hygiene.py` | PASS | Configured runtime storage placement | Periodic detect/propose loop and retired mutation path reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `sys_bridge.py` | PASS | Admitted sealed native bridge; explicit ctypes/psutil fallback | Native readiness and truthful degraded fallback reviewed; no indirect operations executed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `sysmon_listener.py` | PASS | Windows Sysmon event channel; documented fallback | Bounded event/cursor anchor reads and generation-bound cursor reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `temporal_tradecraft_correlator.py` | PASS | Authenticated local EventBus evidence and restart-state key | 256-signal pending queue, restart-gap disclosure and stopped/active gates reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `usb_monitor.py` | PASS | psutil mounted-volume evidence and Windows AutoRun policy | Bounded device identity lookup cache and approval gate reviewed; hotplug guard remains relevant with no device attached. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `watchdog_monitor.py` | PASS | Bound module manager and generation health snapshots | Three-attempt restart cap and generation-bound recovery reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `wfp_controller.py` | SKIP | Windows IP Helper ownership snapshots; typed containment policy | Snapshot/ownership evidence and maximum containment TTL reviewed; no WFP capture claim or host changes tested. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `wlan_monitor.py` | PASS | Windows WLAN service/adapter; disconnected is not evidence of absent hardware | SSID/BSSID cardinality caps and authenticated baseline reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |
| `yara_scanner.py` | PASS | YARA runtime/rules plus configured scan roots | File/tree/size caps, fair cursor, interrupted scans and rule activation reviewed. **REVIEWED / NO MODULE-SPECIFIC CHANGE IDENTIFIED** |

## Helper files and declaration checks

Non-capability module package files: `__init__.py`, `packet_sniffer_worker.py`, `remediation_actions.py`.

Declared CODE values: 66 unique; duplicate values: 0. Modules without explicit CODE: 18; modules without register(): 16. These are recorded as compatibility metadata gaps, not broken imports.

## Interpretation

The baseline log includes a number of health-oriented self-tests which pass while stopped. These exercise local logic, parsing or prerequisite queries only; they do not establish live protection. The intentional disabled/unsupported/unstarted results remain separately identified as SKIP in the JSON and baseline log.
