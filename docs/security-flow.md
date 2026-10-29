# Angerona security flow and review map

This map follows the whole suite from launch and evidence collection through
investigation, authority, action, storage and recovery. It identifies attack
surfaces and the code/tests a reviewer should inspect. It is an implementation
map, not proof of complete attack coverage or independent field efficacy.
The [capability register](../ANGERONA_CAPABILITIES.md), per-module contracts and
live coverage state provide the detailed operating scope.

![Security flow from startup through governed action and recovery](../assets/security-flow-overview.png)

## 1 Installation and startup

Source and signed installed releases have different authority. Source setup
uses an ordinary-user development environment and starts in Observe/Chill.
Installed Protect requires an independently trusted signed payload, provisioned
identities and accepted native enforcement. A release tag, hash or source test
alone cannot establish publisher trust or privileged deployment.

The source launcher checks canonical local paths, explicit settings, operational
startup bytes, runtime/dependency consistency, storage and process exclusion.
After operational verification, an independent OS Windows Forms startup dashboard
paints before Python/dependency checks. It reports verification pending and
protection unavailable while the parent runs checks and eligible repairs in
owned background processes. A current-run first-paint receipt is separate from
application readiness. The parent uses fixed repair tools and ordered candidates; every candidate must
pass fresh checks. Readiness is a nonce-bound receipt from a fresh live dashboard
after its event loop responds. It does not certify sensors or response readiness.
[Safe Startup recovery](safe-startup-recovery.md) documents the alternatives,
preserved edits, private transactions, independent UI and disk budgets.

Windows source Safe Startup treats retained diagnostic history and recommended
free-space reserves as advisory for normal dashboard startup. Critical launch
work uses four reusable purposes per canonical temporary-data base, with fixed
admission budgets and managed-output limits. A live
producer's inherited lease prevents reuse until that producer exits. Actual
private storage access, source/runtime trust and process custody remain checked;
optional downloads and repairs retain their separate storage admission.

## 2 Inputs and collection

Inputs include OS process/file/memory/network observations, event logs, Defender
and other supported providers; user-selected files and archives; imported
Syslog/Windows/NetFlow/JSON evidence; approved intelligence/definition packs;
local AI models and documents; optional browser/identity/SSH integrations; and
explicit defensive exercises. They are untrusted at entry, including their text,
paths, timestamps, URLs, embedded instructions and claimed severity.

Collectors retain available source identity, PID and creation time, freshness,
partial results and losses. Shared immutable snapshots reduce duplicate native
collection. Missing permissions, disabled providers, queue overflow and stale
samples cannot become a healthy or negative detection result. Sensor provenance
separately verifies enrolled producer identity, schema, sequence/replay and loss
where supported; an HMAC over stored bytes alone does not prove producer truth.

## 3 Detection and correlation

Modules evaluate their declared inputs: process lineage, YARA file/archives,
memory/persistence indicators, ransomware/recovery tamper, removable media,
authentication, network patterns, vulnerable-driver posture and other listed
capabilities. SentinelLens and evidence/correlation services connect process,
file, network, technique and proof relationships. A heuristic lead remains a
lead unless its evidence contract supports a stronger claim. VPN topology,
timing alone, a practice marker or imported text cannot create containment
authority. Collection loss and an unconfirmed cause remain visible.

Module contracts describe mode, platform, permissions, egress, retention,
dependencies, lifecycle, loss and self-test. The catalog below inventories each
built-in source module. A compatibility declaration does not establish the same
assurance as a natively accepted collector or response path.

## 4 Investigation and optional AI

The dashboard, Scan Center, module inspectors, Black Box, cases and timelines
show evidence and coverage. Worker-prepared bounded snapshots and paint batches
keep slow/native work away from Qt where implemented. Human review annotations
are advisory; they cannot clear authenticated originals or change trust.

Dashboard panels have individual **Minimize / Restore** buttons in their own
headings. Panels start open except **Module health & activity**, which starts
minimized. There is no separate Operations group heading. Collapsing a panel
hides its body while retaining its widgets and state; module lifecycle remains
separate. Collapse choices apply to the current run; folded stat cards retain
their current values. Critical/failed, degraded and live coverage counts remain
visible, as does the CPU/RAM/network footer. Small windows can scroll.

The compact EKG beside that footer shows **Core**, **Watch**, **Scan** and
**BlackBox**. A green pulse requires a real recent heartbeat for the exact
component generation. Missing, stale, disabled, starting, stopped or unavailable
evidence produces a red flatline with its state retained in details. Process
presence alone never produces a pulse. Click the strip or press Enter/Space for
the PID, native birth-bound generation, heartbeat age, deadline and reason;
additional helpers appear there when they publish actual heartbeat evidence.

The GUI consumes only copied in-memory publications. It does not query processes,
read heartbeat files or acquire native inspection locks while painting. Freshness
uses monotonic time and a finite deadline of at most 120 seconds; the configured
component deadline can be shorter. A replacement generation cannot reuse the
preceding generation's timestamp. A pulse reports liveness, not sensor coverage,
response authority or a verified security state.

Modules keeps search visible while its panel is open. Its **Filters** disclosure
retains the active summary, such as **Filters: observe**; **Columns** reveals
optional metadata. Live Alerts **Columns** exposes optional artifact/evidence
and inline actions. Full tooltips and selected-row **Details / Enter** preserve
complete text. Time, Status and Assurance widths account for the native font
rather than relying on a fixed character count.

Manual AI consultation uses a bounded sanitized preview and explicit Send.
Optional Ollama runs through its configured local boundary; Chill blocks its
startup and requests until explicitly disabled. Approved model manifests,
provenance and agent instruction/tool digests have independent integrity gates.
Model prose, retrieval text and URLs remain untrusted proposals. No language
model is needed for deterministic detection or governed response. See
[AI consultation privacy](ai-consult-privacy.md) and
[key and communication integrity](key-and-communication-integrity.md).

## 5 Response authority and execution

![Authority checks before action and receipt verification](../assets/security-flow-response.png)

A supported response begins with typed evidence and exact target identity,
then checks policy, response capability, operator approval and current deployment
authority. Role-Based Access Control (RBAC) and an authenticated approval identity
are distinct from clicking a button. The broker validates the operation before
a separately authorized adapter mutates the target. Where supported, action
journals precede publication and the worker verifies the observable result.

Outcomes can be denied, held, failed, partial, unverified or completed. Undo and
reconciliation require retained original custody; a displayed success message
cannot replace outcome evidence. The suite must not reset a key, delete an alert,
replace a baseline or accept an unknown rollback solely to pass a self-check.
Source Observe and a diagnostic response-service fixture cannot claim a fully
deployed privileged service or process-bound egress adapter.

### STOP and deliberate shutdown

The core-side supervisor watches the watchdog, scanner and BlackBox. The peer
watchdog watches the core and shared helpers. Authenticated advancing heartbeat
records, exact process generations, adoption checks, spawn exclusion and bounded
backoff govern recovery. Repeated failures enter a visible safe mode rather than
an unlimited process-spawn loop. An optional native watchdog requires its own
deployment evidence. These peers remain within the same user-mode failure domain;
they are not independent protection against a hostile administrator or kernel.

The red **STOP** confirmation and tray **Quit** use the same application-owned
teardown. Closing the window hides it to the tray. On explicit operator exit,
the app first durably records authenticated operator standdown. It then fences
new work, AI requests and supervisor respawn, and signals a proven parent before
teardown. Cleanup follows those checks before the app's own final hard exit.
Queued restart requests cannot override that intent. Automatic recovery children
cannot clear it. Modern automatic sign-in launch is also inhibit-only: an
authenticated STOP returns quietly without opening a UI or starting repair.
An explicit source launch can clear an existing authenticated stop once after
full preflight, then tags its child to honor any new STOP during warmup. The
intent has no age expiry. Generic startup-failure cleanup does not create
operator standdown or suppress later recovery.

If the primary stop record cannot be saved, cleanup does not begin and the
window stays open with the failure. If the native-parent bridge fails after
the local record was saved, exit is held and the app can be partly paused.
Follow the reported free-space/permission correction and retry STOP.

Cleanup has a bounded 30-second wait before the app's own hard exit. Direct
Black Box and AI retirement precede supervisor/healer and module/storage drains.
Windows helpers use retained owned Jobs; adopted helpers require exact native
PID/birth/image and validated redirector lineage. Resilience Jobs preserve crash
recovery when an owner handle closes; explicit STOP retires proven owned work.
Ollama Jobs also stop their owned runners on close. Ownership failures remain
explicit rather than authorizing a broad kill. POSIX retains its prior
process/API cleanup and was outside this native tree-custody validation.

The app requests unloading of resident app-selected Ollama models. A shared
pre-existing daemon stays running;
an unload request for a shared model can affect another app using that model.
Downloaded model weights remain on disk. No broad process-name or Python-root
kill is authorized, and a late startup task cannot bypass the shutdown fence.

The durable `ipc/standdown.cmd` uses a dedicated protected `shutdown.key` and
HMAC verification. These user-mode controls do not grant kernel authority.
Source rollback candidates must satisfy the operator-STOP compatibility floor;
that floor is not a trust baseline or signing authority. A local native build
or source test does not establish release acceptance. Release binaries still
need rebuilding, signing and deployment acceptance; this guide does not claim
an already accepted release binary contains these changes.
Legacy installed startup retains its older route until rebuilt and accepted.

## 6 Persistence and capacity

Runtime configuration, IPC keys, approved baselines, authenticated event history,
quarantine originals, forensic cases and recovery transactions are separate data
classes. Retention must distinguish protected originals from disposable logs,
scratch and caches. Bounded readers, archive expansion limits, queues, caches and
worker budgets reduce resource exhaustion; explicit loss states preserve the
limit's effect on coverage.

ShadowShield file recovery uses cache admission, configurable size and free-space
reserve controls in **Settings > System > Drive space and recovery data**.
Startup source backups have their own bounded private quota
and never become security baselines. Diagnostics rotate; unknown interrupted
transactions and unreviewed source edits are preserved and can hold recovery.
An operator can block future cache creation, delete selected copies, or change
policy. Deletion permanently removes the selected restore points.

## 7 Independent trust and recovery

UGCAP requires explicit known-clean vault enrollment and supports selected-path
review/recovery. Strict startup and the rotating local mesh depend on their
freshness and custody gates. An independent witness needs separately deployed
authority, enrolled identity, mTLS and certificate/signing pins; a local process
or deleting retained witness state is not an independent failure domain.

Release integrity validates the approved installed payload and publisher chain.
Source recovery verifies exact candidates but cannot confer signed installed
authority. A writable batch trust anchor, a Python integrity check or a private
HMAC key in the same compromised user context cannot make the suite immune to
that attacker. Recovery never silently enrolls changed files into UGCAP.

## 8 Ring 3 and platform limits

The desktop/source application runs in user mode, commonly called Ring 3.
Administrator/UAC authority remains user mode. Supported OS interfaces can
provide kernel-originated data or authorized enforcement, but availability,
privilege and driver/service deployment must be established separately.
Angerona ships no production kernel driver and promises no control over a hostile
kernel, hypervisor, firmware, compromised OS or hostile administrator. Microsoft
describes [user and kernel execution](https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/user-mode-and-kernel-mode)
and [Windows security boundaries](https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria).

Kernel integrity, Secure Boot, supported OS security, trusted backups and
independent authorities complement the application. On macOS/Linux, module
platform gates and Observe scope remain visible; optional Linux eBPF is a
separately configured capability, not a blanket parity claim.

## 9 Network and extension boundaries

| Path | Data and authority boundary |
| --- | --- |
| Source recovery | Fixed canonical GitHub commit/tree/archive or pinned blob HTTPS reads. No host evidence/failed-edit uploads. GitHub sees ordinary request metadata. Optional GitHub setting and master recovery control apply. |
| Runtime repair | Reviewed signed PSF Python and hash-locked dependencies; successful download does not bypass runtime/source/readiness gates. |
| Local AI | Explicit configured local endpoint and integrity/privacy gates. SentinelLens narrative has a strict loopback boundary; no cloud fallback. Manual consultation needs preview/Send. |
| Intelligence/news/research | Per-feature opt-in/configured source rules. Imported URLs and retrieved prose are data, never executable repair or response instructions. |
| Witness and fleet | Separate enrolled remote authority, endpoint authentication and typed schema. Disabled/unavailable deployment stays a gap. |
| Live Debug and engine IPC | Authenticated bounded local records and typed controls. Read-only review cannot authorize mutation. Shared user context remains part of the threat model. |
| Third-party Python modules | Explicitly loaded code executes in a process with that process's authority. Contract metadata is not sandboxing; review extensions and their dependencies. |

The GitHub recovery implementation follows the official
[blob](https://docs.github.com/en/rest/git/blobs),
[commit](https://docs.github.com/en/rest/git/commits) and
[tree](https://docs.github.com/en/rest/git/trees) object APIs. Each integration's
actual configured endpoint and live contract remain the operating authority.

## Attack surface review matrix

The patch column describes the maintained guard or review action, not an
assertion that every listed historical test was rerun for this change. Test
files are regression entry points; native deployment and efficacy need their
own receipts.

| Surface and failure | Main code | Regression entry points | Guard or patch direction |
| --- | --- | --- | --- |
| Launcher, missing/corrupt operational code | `start-angerona.bat`, `tools/verify_startup_recovery_bundle.ps1`, `tools/build_startup_recovery_manifest.py` | `tests/test_startup_recovery_bundle.py` | Independent pins, exact public Git blob verification, fixed allowlist, private raw originals, exclusion/read leases, partial result held. |
| Corrupt frozen helper or unknown native child state | `tools/packaged_safe_start.cs`, `tools/build_packaged_safe_start.ps1`, strict MSIX entry | `tests/test_packaged_safe_start.py`, `tests/test_msix_package.py` | Independent OS .NET interface, fixed final-helper pin, native ancestry/file/process leases, no timeout kill or unsigned package repair; signing order remains an external acceptance gate. |
| Wrong Python/dependency, native GUI failure | `tools/Invoke-AngeronaStartupRepair.ps1`, `tools/startup_repair_common.ps1`, `tools/source_trust_preflight.py` | `tests/test_startup_repair_tools.py`, `tests/test_startup_python_discovery.py`, `tests/test_startup_repair_storage.py` | Signed interpreter discovery, hash-locked candidate, independent validation, durable runtime transaction and capacity admission. |
| App crash, source edits and interrupted rollback | `tools/Invoke-AngeronaSourceStartup.ps1`, `tools/startup_source_recovery.py` | `tests/test_source_startup_strategies.py`, `tests/test_startup_source_recovery.py` | Fingerprint before launch, preserve failed revision, no live source publication, reconcile only provable generations. |
| Recovery unavailable or hostile log text | `tools/angerona_recovery.py`, `tools/Show-AngeronaStartupRecovery.ps1`, `core/startup_diagnostics.py` | `tests/test_independent_startup_recovery.py`, `tests/test_startup_source_review_ui.py`, `tests/test_startup_diagnostics.py` | No app imports, plain bounded display, safe internal log view, independent native fallback. |
| Dependency timeout misclassified as broken source | `startup.py`, `tools/Invoke-AngeronaSourceStartup.ps1`, `tools/startup_repair_common.ps1` | `tests/test_safe_startup.py`, `tests/test_source_startup_strategies.py` | Separate phase/overall budgets, exact disposable-tree retirement, typed infrastructure/cancellation outcomes, no source rollback from probe failure. |
| Helper presence mistaken for a real heartbeat | `gui/component_heartbeat.py`, `resilience/heartbeat.py`, `resilience/manager.py` | `tests/test_component_heartbeat.py`, `tests/test_resilience_heartbeat_auth.py` | Copied memory only on Qt, exact generation and advancing evidence, finite monotonic freshness, red unavailable/stale flatline. |
| Dashboard density hides context or changes operation | `gui/main_window.py`, `gui/dashboard_sections.py`, `gui/pages.py` | `tests/test_dashboard_compact_sections.py`, `tests/test_dashboard_compact_tables.py` | Individual heading controls, visible coverage summary, active-filter summary, full-text details and native-font column sizing; presentation remains separate from module lifecycle. |
| Operator STOP races queued recovery or AI startup | `app.py`, `gui/main_window.py`, `resilience/shutdown_token.py`, `resilience/supervisor.py`, `core/windows_child_job.py` | `tests/test_operator_stop_lifecycle.py`, `tests/test_cycle8_recovery_supervisor.py` | Explicit-exit intent before teardown, persistent authenticated standdown, inhibit-only automatic recovery, bounded owned-work cleanup and no broad process kill; ordinary startup failure retains recovery eligibility. |
| Spoofed readiness, duplicate engine | `startup.py`, `core/startup_protocol.py`, `core/startup_recovery.py` | `tests/test_safe_startup.py`, `tests/test_startup_dashboard_ready.py`, `tests/test_startup_recovery_flow.py` | Fresh nonce/process generation, event-loop readiness, singleton and owned-process retirement evidence. |
| Storage pressure, lost originals | `core/config.py`, `core/shadow_cache_cleanup.py`, ShadowShield | `tests/test_shadow_storage_controls.py`, `tests/test_shadow_cache_cleanup.py`, `tests/test_startup_recovery_settings.py` | Cache cap/reserve, user controls, bounded state, no eviction of unreviewed source edits. |
| Spoofed/replayed sensor event | `core/sensor_provenance.py`, `core/eventbus.py` | `tests/test_sensor_provenance.py`, `tests/test_provenance_replay_liveness.py` | Enrolled producer/schema/continuity verification; preserve loss and authority separation. |
| PID reuse, partial process/network collection | `telemetry/sensors.py` and process/network modules | `tests/test_process_observation_retry_fairness.py`, `tests/test_scan_center_failure_coverage.py` | PID/birth/freshness binding, bounded retry, partial evidence remains a gap. |
| Forged response target or operation | `core/response_contract.py`, `core/response_broker.py`, `core/response_capability.py` | `tests/test_response_broker.py`, `tests/test_response_capability.py`, `tests/test_semantic_response_contracts.py` | Typed evidence, capability/policy/approval, exact live target and verified outcome. |
| Approval impersonation or privileged IPC | `core/approval_identity.py`, `core/response_service_host.py` | `tests/test_approval_identity.py`, `tests/test_response_service_host.py`, `tests/test_privileged_pipe_response_receipt.py` | Authenticated role/identity, narrow service schema, native deployment boundary. |
| Firewall/quarantine partial publication | response adapters, `core/spyware_quarantine.py` | `tests/test_wfp_containment_transactions.py`, `tests/test_spyware_quarantine.py` | Durable custody, exact target, supported Undo, unresolved reconciliation held. |
| IPC/key replacement or unbounded parser | local IPC/key readers and model integrity readers | `tests/test_ipc_key_custody.py`, `tests/test_shared_ipc_contract.py`, `tests/test_ai_model_parser_normalization.py` | Serialized initialization, bounded no-link reads, identity readback and typed refusal. |
| Prompt injection, model/provenance drift | `core/ai_security_broker.py`, `core/agent_integrity.py`, `core/rag_provenance.py` | `tests/test_ai_security_broker.py`, `tests/test_agent_integrity.py`, `tests/test_ai_consult_privacy.py`, `tests/test_rag_provenance_guard.py` | Advisory output, preview/Send, approved digests and separate mutation authority. |
| Integrity baseline/witness substitution | UGCAP, release integrity, rotating mesh | `tests/test_ugcap_startup_protocol.py`, `tests/test_release_integrity.py`, `tests/test_v12_self_integrity.py` | Explicit enrollment, exact payload/source identities, fresh independently deployed authority where required. |
| Practice marker confused with real evidence | defensive exercise producer/lease and response contracts | `tests/test_practice_provenance.py`, `tests/test_adversary_response_producers.py` | Exact live issuer/owned target, synthetic labels, no text-only authority. |
| Retention hides loss or discards evidence | `core/storage.py`, `core/alert_retention.py`, Live Debug | `tests/test_alert_retention.py`, `tests/test_cleanup_preservation.py`, `tests/test_live_debug_app_startup.py` | Distinct protected/disposable classes, pinned originals, bounded loss-aware review. |
| Supply-chain or public asset drift | release/update code and guarded publisher | `tools/validate_documentation_drift.py`, `tools/verify_published_readme_assets.py` | Reviewed locks, signing/deployment gates, exact public main and byte-identical tracked images. |

Code paths abbreviated to `core/`, `startup.py` or telemetry above are under
`src/angerona`. A patch should preserve authenticated originals, reproduce the
specific fault, add the smallest meaningful regression, run focused checks,
retire exact owned diagnostic processes and observe the changed revision before
claiming runtime improvement. Passing a static test does not prove the cause of
an earlier live failure.

## Validation interpretation

Readiness, test counts, signed receipts and observed performance each answer a
different question. Source tests do not create independent authorities or prove
real-world detection rates. Historical README totals retain their dated scope.
Final offline validation, live observation and exact GitHub publication are
separate completion gates. Raw private captures are not public documentation.

## Built in capability source inventory

The following catalog is generated by static AST inspection of built-in
`BaseModule` classes. It lists declared mode and response authority where those
are explicit in the class. An inherited compatibility contract is labelled
accordingly; consult Capability Center for the validated live contract and
coverage. This catalog includes every built-in source declaration in this
revision and does not load or start the modules.

<!-- CAPABILITY_SOURCE_INVENTORY -->

**86 built-in capability declarations.**

| Capability | Source | Declared mode | Declared response authority |
| --- | --- | --- | --- |
| Adversary Combat | [adversary_combat.py](../src/angerona/modules/adversary_combat.py) | respond | typed-response |
| AI Model Integrity Guard | [ai_model_integrity.py](../src/angerona/modules/ai_model_integrity.py) | inherited contract | inherited contract |
| AI Triage (Ollama) | [ai_triage.py](../src/angerona/modules/ai_triage.py) | detect | inherited contract |
| AMSI Bridge | [amsi_bridge.py](../src/angerona/modules/amsi_bridge.py) | inherited contract | inherited contract |
| API Patch / Anti-Blinding Detector | [api_patch_detector.py](../src/angerona/modules/api_patch_detector.py) | inherited contract | inherited contract |
| App Control Decision Evidence | [app_control_monitor.py](../src/angerona/modules/app_control_monitor.py) | observe | inherited contract |
| ARP Watchdog | [arp_watchdog.py](../src/angerona/modules/arp_watchdog.py) | inherited contract | inherited contract |
| Audit Log Integrity Guard | [audit_log_guard.py](../src/angerona/modules/audit_log_guard.py) | observe | inherited contract |
| AuthenticationExtensionIntegrityGuardModule | [authentication_extension_guard.py](../src/angerona/modules/authentication_extension_guard.py) | observe | none |
| AV Telemetry Bridge | [av_telemetry_bridge.py](../src/angerona/modules/av_telemetry_bridge.py) | inherited contract | inherited contract |
| C2 Beacon Detector | [beacon_detector.py](../src/angerona/modules/beacon_detector.py) | inherited contract | inherited contract |
| TUNE | [behavioral_tuner.py](../src/angerona/modules/behavioral_tuner.py) | inherited contract | inherited contract |
| Telemetry Canary Drills | [canary_drill.py](../src/angerona/modules/canary_drill.py) | inherited contract | inherited contract |
| CHAOS | [chaos_harness.py](../src/angerona/modules/chaos_harness.py) | inherited contract | inherited contract |
| Cloud CTI Escalation | [cloud_escalation.py](../src/angerona/modules/cloud_escalation.py) | inherited contract | inherited contract |
| Compliance Mapper | [compliance_mapper.py](../src/angerona/modules/compliance_mapper.py) | inherited contract | inherited contract |
| Counter-Agentic Detection | [counter_agentic.py](../src/angerona/modules/counter_agentic.py) | inherited contract | inherited contract |
| Scheduled AI Security Briefing | [daily_briefing.py](../src/angerona/modules/daily_briefing.py) | inherited contract | inherited contract |
| Active Deception | [deception.py](../src/angerona/modules/deception.py) | inherited contract | inherited contract |
| DetectionRuntimeModule | [detection_runtime.py](../src/angerona/modules/detection_runtime.py) | detect | none |
| Driver Provenance Guard | [driver_provenance_guard.py](../src/angerona/modules/driver_provenance_guard.py) | observe | inherited contract |
| Dynamic Resource Governor | [dynamic_resource.py](../src/angerona/modules/dynamic_resource.py) | inherited contract | inherited contract |
| Linux eBPF Sensor | [ebpf_sensor.py](../src/angerona/modules/ebpf_sensor.py) | observe | inherited contract |
| ETW Core Listener | [etw_listener.py](../src/angerona/modules/etw_listener.py) | inherited contract | inherited contract |
| ETW Real-Time Process Sensor | [etw_realtime_sensor.py](../src/angerona/modules/etw_realtime_sensor.py) | inherited contract | inherited contract |
| Evidence Lattice Fusion | [evidence_lattice.py](../src/angerona/modules/evidence_lattice.py) | inherited contract | inherited contract |
| Evolution Engine | [evolution_engine.py](../src/angerona/modules/evolution_engine.py) | inherited contract | inherited contract |
| ExposureGraphGuardModule | [exposure_graph_guard.py](../src/angerona/modules/exposure_graph_guard.py) | observe | none |
| Deterministic Fast-Path Interceptor | [fast_path.py](../src/angerona/modules/fast_path.py) | inherited contract | inherited contract |
| File Integrity Monitor | [file_integrity.py](../src/angerona/modules/file_integrity.py) | inherited contract | inherited contract |
| FleetHealthMonitorModule | [fleet_health_monitor.py](../src/angerona/modules/fleet_health_monitor.py) | detect | none |
| In-Memory Flight Cache | [flight_cache.py](../src/angerona/modules/flight_cache.py) | inherited contract | inherited contract |
| Forensics Capture | [forensics.py](../src/angerona/modules/forensics.py) | inherited contract | inherited contract |
| Anti-Suspension Heartbeat | [frz_heartbeat.py](../src/angerona/modules/frz_heartbeat.py) | inherited contract | inherited contract |
| Hardware-Rooted Integrity | [hardware_crypto.py](../src/angerona/modules/hardware_crypto.py) | inherited contract | inherited contract |
| Monolithic Packaging | [hermetic_packager.py](../src/angerona/modules/hermetic_packager.py) | inherited contract | inherited contract |
| IdentitySessionGuardModule | [identity_session_guard.py](../src/angerona/modules/identity_session_guard.py) | observe | inherited contract |
| ImmutableRecoveryGuardModule | [immutable_recovery_guard.py](../src/angerona/modules/immutable_recovery_guard.py) | observe | inherited contract |
| Upstream Threat Intel Sync | [intel_sync.py](../src/angerona/modules/intel_sync.py) | inherited contract | inherited contract |
| Zero-Trust Local IPC Guard | [ipc_guard.py](../src/angerona/modules/ipc_guard.py) | observe | none |
| Kernel Sensor Bridge | [kernel_bridge.py](../src/angerona/modules/kernel_bridge.py) | inherited contract | inherited contract |
| Kernel-Boundary Posture Ledger | [kernel_posture_ledger.py](../src/angerona/modules/kernel_posture_ledger.py) | inherited contract | inherited contract |
| Linux Observe Sensor | [linux_observe.py](../src/angerona/modules/linux_observe.py) | detect | inherited contract |
| LSASS Credential-Access Guard | [lsass_guard.py](../src/angerona/modules/lsass_guard.py) | inherited contract | inherited contract |
| macOS Observe Sensor | [macos_observe.py](../src/angerona/modules/macos_observe.py) | observe | inherited contract |
| Memory Injection Scanner | [mem_inject_scanner.py](../src/angerona/modules/mem_inject_scanner.py) | inherited contract | inherited contract |
| Memory Time-Machine | [memory_timemachine.py](../src/angerona/modules/memory_timemachine.py) | inherited contract | inherited contract |
| Mobile Response Bridge | [mobile_bridge.py](../src/angerona/modules/mobile_bridge.py) | inherited contract | inherited contract |
| Network Monitor | [network_monitor.py](../src/angerona/modules/network_monitor.py) | inherited contract | inherited contract |
| Network Protocol Deep Decoder | [network_protocol_decoder.py](../src/angerona/modules/network_protocol_decoder.py) | inherited contract | inherited contract |
| Zero-Trust Network Path Monitor | [network_trust_monitor.py](../src/angerona/modules/network_trust_monitor.py) | observe | inherited contract |
| Packet Sniffer | [packet_sniffer.py](../src/angerona/modules/packet_sniffer.py) | inherited contract | inherited contract |
| PeripheralDMAGuardModule | [peripheral_dma_guard.py](../src/angerona/modules/peripheral_dma_guard.py) | observe | inherited contract |
| Persistence Sweep | [persistence_sweep.py](../src/angerona/modules/persistence_sweep.py) | detect | none |
| Platform Attestation Guard | [platform_attestation_guard.py](../src/angerona/modules/platform_attestation_guard.py) | observe | inherited contract |
| Posture Hardening | [posture_hardening.py](../src/angerona/modules/posture_hardening.py) | inherited contract | inherited contract |
| ProcessEgressGuardModule | [process_egress_guard.py](../src/angerona/modules/process_egress_guard.py) | observe | inherited contract |
| Process Monitor | [process_monitor.py](../src/angerona/modules/process_monitor.py) | detect | none |
| Data Provenance Graph | [provenance_graph.py](../src/angerona/modules/provenance_graph.py) | inherited contract | inherited contract |
| Purple Remediation Guard | [purple_guard.py](../src/angerona/modules/purple_guard.py) | inherited contract | inherited contract |
| RAGProvenanceGuardModule | [rag_provenance_guard.py](../src/angerona/modules/rag_provenance_guard.py) | observe | inherited contract |
| Ransomware Heuristics | [ransomware_heuristics.py](../src/angerona/modules/ransomware_heuristics.py) | inherited contract | inherited contract |
| ReleaseTransparencyGuardModule | [release_transparency_guard.py](../src/angerona/modules/release_transparency_guard.py) | observe | inherited contract |
| Remote Bridge | [remote_bridge.py](../src/angerona/modules/remote_bridge.py) | observe | none |
| Adaptive Resource Governor | [resource_governor.py](../src/angerona/modules/resource_governor.py) | protect | inherited contract |
| HEAL | [self_healer.py](../src/angerona/modules/self_healer.py) | inherited contract | inherited contract |
| Self-Integrity Monitor | [self_integrity.py](../src/angerona/modules/self_integrity.py) | inherited contract | inherited contract |
| Shadow Shield | [shadow_shield.py](../src/angerona/modules/shadow_shield.py) | inherited contract | inherited contract |
| Shadow-Copy / Recovery Tamper Guard | [shadowcopy_guard.py](../src/angerona/modules/shadowcopy_guard.py) | inherited contract | inherited contract |
| SIEM Forwarder | [siem_forwarder.py](../src/angerona/modules/siem_forwarder.py) | observe | none |
| Smart Deception | [smart_deception.py](../src/angerona/modules/smart_deception.py) | inherited contract | inherited contract |
| SOAR Automation | [soar.py](../src/angerona/modules/soar.py) | respond | typed-response |
| Active Response SOAR | [soar_engine.py](../src/angerona/modules/soar_engine.py) | respond | typed-response |
| Speculative Triage Pre-Warm | [speculative_triage.py](../src/angerona/modules/speculative_triage.py) | inherited contract | inherited contract |
| SpywareGuardModule | [spyware_guard.py](../src/angerona/modules/spyware_guard.py) | detect | typed-response |
| SSH Surface / Key / Tunnel Guard | [ssh_surface_guard.py](../src/angerona/modules/ssh_surface_guard.py) | observe | inherited contract |
| Storage Hygiene Enforcer | [storage_hygiene.py](../src/angerona/modules/storage_hygiene.py) | inherited contract | inherited contract |
| Indirect Syscall Bridge | [sys_bridge.py](../src/angerona/modules/sys_bridge.py) | inherited contract | inherited contract |
| Sysmon Event Bridge | [sysmon_listener.py](../src/angerona/modules/sysmon_listener.py) | inherited contract | inherited contract |
| TemporalTradecraftCorrelatorModule | [temporal_tradecraft_correlator.py](../src/angerona/modules/temporal_tradecraft_correlator.py) | observe | inherited contract |
| UGCAP Integrity Guard | [ugcap_guard.py](../src/angerona/modules/ugcap_guard.py) | protect | typed-response |
| Removable-Media / USB Monitor | [usb_monitor.py](../src/angerona/modules/usb_monitor.py) | inherited contract | inherited contract |
| Watchdog Monitor | [watchdog_monitor.py](../src/angerona/modules/watchdog_monitor.py) | inherited contract | inherited contract |
| WFP Controller | [wfp_controller.py](../src/angerona/modules/wfp_controller.py) | inherited contract | inherited contract |
| WLAN Monitor | [wlan_monitor.py](../src/angerona/modules/wlan_monitor.py) | inherited contract | inherited contract |
| YARA Scanner | [yara_scanner.py](../src/angerona/modules/yara_scanner.py) | inherited contract | inherited contract |
