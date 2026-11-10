# Module reference

This source index lists every built-in `BaseModule` declaration. A declaration, self-test method or capability contract does not establish live collection, detection or containment. Runtime coverage depends on platform, permissions, policy and fresh evidence.

Open a module's inspector for its current lifecycle, configured selection, assurance, dependencies and individual diagnostic results. A healthy worker can remain idle when its separate response policy is off.

Declared modules: **86**.

## Active Deception

Plants canaries/honeytokens, detects file mutation/deletion, and dynamically re-stages traps; audited reads need an external OS source.

Category: Deception. Source: [src/angerona/modules/deception.py:72](../../src/angerona/modules/deception.py#L72).

Individual test: [src/angerona/modules/deception.py:173](../../src/angerona/modules/deception.py#L173). Exercise real planting on an unstarted disposable instance only.

## Active Response SOAR

Opt-in: terminates the offending process and rolls back its file artifact on real CRITICAL alerts.

Category: Response. Source: [src/angerona/modules/soar_engine.py:59](../../src/angerona/modules/soar_engine.py#L59).

Individual test: [src/angerona/modules/soar_engine.py:125](../../src/angerona/modules/soar_engine.py#L125). Exercise real response admission helpers on isolated inert evidence.

## Adaptive Resource Governor

Watches process CPU and throttles heavy non-critical module loops under load (Eco + normal); relaxes them when idle. Never slows the real-time protection path.

Category: Performance. Source: [src/angerona/modules/resource_governor.py:52](../../src/angerona/modules/resource_governor.py#L52).

Individual test: [src/angerona/modules/resource_governor.py:271](../../src/angerona/modules/resource_governor.py#L271). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Adversary Combat

Unattended maximum-response tier: blocks, contains, quarantines, isolates, and activates honeypots with undo receipts.

Category: Response. Source: [src/angerona/modules/adversary_combat.py:1206](../../src/angerona/modules/adversary_combat.py#L1206).

Referenced settings: `breach_auto_isolate_enabled`, `breach_lifted_cases`, `data_dir`.

Individual test: [src/angerona/modules/adversary_combat.py:1462](../../src/angerona/modules/adversary_combat.py#L1462). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## AI Model Integrity Guard

Cryptographically attests local LLM weights (Ollama blobs) against a pinned baseline; flags tampering/poisoning before load.

Category: AI Defense. Source: [src/angerona/modules/ai_model_integrity.py:447](../../src/angerona/modules/ai_model_integrity.py#L447).

Individual test: [src/angerona/modules/ai_model_integrity.py:981](../../src/angerona/modules/ai_model_integrity.py#L981). Offline: prove the hasher detects a single-byte change, and report whether any local models were discovered.

## AI Triage (Ollama)

Explains and scores serious events using a local LLM (Ollama).

Category: AI. Source: [src/angerona/modules/ai_triage.py:112](../../src/angerona/modules/ai_triage.py#L112).

Referenced settings: `ollama_host`, `ollama_model`.

Individual test: [src/angerona/modules/ai_triage.py:767](../../src/angerona/modules/ai_triage.py#L767). Check the existing listener, exact model, and current proof without mutation.

## AMSI Bridge

AMSI scanning consumer — pushes PowerShell/script content from bus events through AmsiScanBuffer after observation; no pre-execution interception. Native scanning requires the controlled compatibility option.

Category: Endpoint. Source: [src/angerona/modules/amsi_bridge.py:202](../../src/angerona/modules/amsi_bridge.py#L202).

Individual test: [src/angerona/modules/amsi_bridge.py:566](../../src/angerona/modules/amsi_bridge.py#L566). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Anti-Suspension Heartbeat

Writes a nanosecond heartbeat to a shared mmap region every 500 ms so the external FRZ watchdog binary can detect thread-suspension attacks.  If the Python process is frozen but alive, the watchdog triggers emergency network isolation and terminates the compromised interpreter.

Category: Resilience. Source: [src/angerona/modules/frz_heartbeat.py:124](../../src/angerona/modules/frz_heartbeat.py#L124).

Individual test: [src/angerona/modules/frz_heartbeat.py:364](../../src/angerona/modules/frz_heartbeat.py#L364). Verify independent authenticated-v2 reads see advancing beats.

## API Patch / Anti-Blinding Detector

Reads pristine ntdll/kernel32 from disk and compares export prologues against live memory to catch inline sensor hooks.

Category: Integrity. Source: [src/angerona/modules/api_patch_detector.py:162](../../src/angerona/modules/api_patch_detector.py#L162).

Individual test: [src/angerona/modules/api_patch_detector.py:563](../../src/angerona/modules/api_patch_detector.py#L563). Verify the hook classifier and separately inspect local PE exports.

## App Control Decision Evidence

Reads Windows Code Integrity audit/block decisions and correlates their signature evidence by ActivityID without changing App Control policy.

Category: Integrity. Source: [src/angerona/modules/app_control_monitor.py:407](../../src/angerona/modules/app_control_monitor.py#L407).

Individual test: [src/angerona/modules/app_control_monitor.py:899](../../src/angerona/modules/app_control_monitor.py#L899). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## ARP Watchdog

Detects ARP poisoning (T1557.002) via ARP cache diff polling and optional real-time scapy gratuitous-ARP sniffing.

Category: Network. Source: [src/angerona/modules/arp_watchdog.py:116](../../src/angerona/modules/arp_watchdog.py#L116).

Individual test: [src/angerona/modules/arp_watchdog.py:619](../../src/angerona/modules/arp_watchdog.py#L619). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Audit Log Integrity Guard

Detects Windows log clearing, audit-policy drift, service impairment, retention gaps, record reuse, and authenticated cursor tampering.

Category: Telemetry. Source: [src/angerona/modules/audit_log_guard.py:63](../../src/angerona/modules/audit_log_guard.py#L63).

Individual test: [src/angerona/modules/audit_log_guard.py:554](../../src/angerona/modules/audit_log_guard.py#L554). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## AuthenticationExtensionIntegrityGuardModule

Read-only fixed-catalog integrity observation for LSA authentication, notification, and security packages; credential providers and filters; and network providers.

Category: Identity. Source: [src/angerona/modules/authentication_extension_guard.py:37](../../src/angerona/modules/authentication_extension_guard.py#L37).

Referenced settings: `data_dir`.

Individual test: [src/angerona/modules/authentication_extension_guard.py:450](../../src/angerona/modules/authentication_extension_guard.py#L450). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## AV Telemetry Bridge

Bridges Windows Defender detection events (EID 1116/1117/5001) into the Angerona bus for cross-sensor correlation.

Category: Endpoint. Source: [src/angerona/modules/av_telemetry_bridge.py:364](../../src/angerona/modules/av_telemetry_bridge.py#L364).

Individual test: [src/angerona/modules/av_telemetry_bridge.py:1529](../../src/angerona/modules/av_telemetry_bridge.py#L1529). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## C2 Beacon Detector

Flags regular-interval outbound callbacks (command-and-control beaconing, T1071/T1571) by timing per-process connections to a host.

Category: Detection. Source: [src/angerona/modules/beacon_detector.py:96](../../src/angerona/modules/beacon_detector.py#L96).

Individual test: [src/angerona/modules/beacon_detector.py:292](../../src/angerona/modules/beacon_detector.py#L292). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## CHAOS

Periodically fires safe synthetic probes and verifies detectors echo back.

Category: Resilience. Source: [src/angerona/modules/chaos_harness.py:75](../../src/angerona/modules/chaos_harness.py#L75).

Individual test: [src/angerona/modules/chaos_harness.py:345](../../src/angerona/modules/chaos_harness.py#L345). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Cloud CTI Escalation

Opt-in: corroborates CRITICAL events with a cloud model (uses your own key).

Category: AI. Source: [src/angerona/modules/cloud_escalation.py:77](../../src/angerona/modules/cloud_escalation.py#L77).

Individual test: [src/angerona/modules/cloud_escalation.py:109](../../src/angerona/modules/cloud_escalation.py#L109). Exercise parsing and privacy gates without credentials or egress.

## Compliance Mapper

Maps live MITRE ATT&CK detections to NIST 800-53 + DoD STIG control relevance and writes an authenticated, coverage-aware artifact.

Category: Compliance. Source: [src/angerona/modules/compliance_mapper.py:164](../../src/angerona/modules/compliance_mapper.py#L164).

Individual test: [src/angerona/modules/compliance_mapper.py:445](../../src/angerona/modules/compliance_mapper.py#L445). Offline: verify technique mapping + sub-technique fallback.

## Counter-Agentic Detection

Reviews timed discovery and action launches, corroborated process-linked outbound activity, and unexpected inference-port matches.

Category: Detection. Source: [src/angerona/modules/counter_agentic.py:141](../../src/angerona/modules/counter_agentic.py#L141).

Individual test: [src/angerona/modules/counter_agentic.py:608](../../src/angerona/modules/counter_agentic.py#L608). Exercise advisory discovery/action cadence with a benign control.

## Data Provenance Graph

Builds a PROC/FIM/NET provenance DAG from the flight recorder + live events; exposes ancestry()/subtree() for blast-radius views.

Category: Forensics. Source: [src/angerona/modules/provenance_graph.py:381](../../src/angerona/modules/provenance_graph.py#L381).

Individual test: [src/angerona/modules/provenance_graph.py:599](../../src/angerona/modules/provenance_graph.py#L599). Build a synthetic PROC→PROC→FIM chain and verify ancestry/subtree.

## DetectionRuntimeModule

Runs digest-bound local detection packages with a reserved active lane and an alert-inert, loss-visible shadow lane for DetectionForge validation.

Category: Detection. Source: [src/angerona/modules/detection_runtime.py:1387](../../src/angerona/modules/detection_runtime.py#L1387).

Individual test: [src/angerona/modules/detection_runtime.py:1515](../../src/angerona/modules/detection_runtime.py#L1515). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Deterministic Fast-Path Interceptor

Checks bus events against a deterministic IOC pattern library and emits CRITICAL alerts immediately — without waiting for Ollama — for high-confidence known-bad patterns.

Category: AI. Source: [src/angerona/modules/fast_path.py:288](../../src/angerona/modules/fast_path.py#L288).

Individual test: [src/angerona/modules/fast_path.py:679](../../src/angerona/modules/fast_path.py#L679). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Driver Provenance Guard

Joins bounded configured-path samples with signer/catalog, blocklist, HVCI, and Secure Boot evidence; loaded-image proof requires a trusted kernel load receipt.

Category: Integrity. Source: [src/angerona/modules/driver_provenance_guard.py:873](../../src/angerona/modules/driver_provenance_guard.py#L873).

Individual test: [src/angerona/modules/driver_provenance_guard.py:1124](../../src/angerona/modules/driver_provenance_guard.py#L1124). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Dynamic Resource Governor

Escalates process priority to HIGH_PRIORITY_CLASS under incident load and restores its original priority after COOLDOWN_S seconds of calm.

Category: System. Source: [src/angerona/modules/dynamic_resource.py:55](../../src/angerona/modules/dynamic_resource.py#L55).

Individual test: [src/angerona/modules/dynamic_resource.py:212](../../src/angerona/modules/dynamic_resource.py#L212). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## ETW Core Listener

Captures process-creation (4688) + logon (4624/4672) telemetry from the Windows Security channel; psutil fallback.

Category: Telemetry. Source: [src/angerona/modules/etw_listener.py:264](../../src/angerona/modules/etw_listener.py#L264).

Individual test: [src/angerona/modules/etw_listener.py:2831](../../src/angerona/modules/etw_listener.py#L2831). Verify the 4688/4624 describers produce well-formed events.

## ETW Real-Time Process Sensor

Event-driven process-creation capture via the Kernel-Process ETW provider (pywintrace); closes the polling blind spot. Requires elevation; defers to polling sensors when unavailable.

Category: Telemetry. Source: [src/angerona/modules/etw_realtime_sensor.py:389](../../src/angerona/modules/etw_realtime_sensor.py#L389).

Individual test: [src/angerona/modules/etw_realtime_sensor.py:566](../../src/angerona/modules/etw_realtime_sensor.py#L566). Verify the Kernel-Process parser produces a well-formed event, and report real-time availability on this host.

## Evidence Lattice Fusion

Fuses MEDIUM signals about the same PID, path/hash, or IP across three independent modules and two sensor domains; emits an explainable HIGH finding and exact-target containment authority for live PIDs/IPs.

Category: Detection. Source: [src/angerona/modules/evidence_lattice.py:254](../../src/angerona/modules/evidence_lattice.py#L254).

Individual test: [src/angerona/modules/evidence_lattice.py:336](../../src/angerona/modules/evidence_lattice.py#L336). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Evolution Engine

Review-gated hardening: turns a typed Judgment bypass receipt into an inert YARA proposal; never auto-activates it.

Category: Resilience. Source: [src/angerona/modules/evolution_engine.py:129](../../src/angerona/modules/evolution_engine.py#L129).

Individual test: [src/angerona/modules/evolution_engine.py:534](../../src/angerona/modules/evolution_engine.py#L534). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## ExposureGraphGuardModule

Monitors immutable exposure-graph generations for invalid receipts, resource truncation, provider-attested semantic scope, stale or missing evidence, and collection age.

Category: Exposure Management. Source: [src/angerona/modules/exposure_graph_guard.py:43](../../src/angerona/modules/exposure_graph_guard.py#L43).

Individual test: [src/angerona/modules/exposure_graph_guard.py:349](../../src/angerona/modules/exposure_graph_guard.py#L349). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## File Integrity Monitor

Detects unauthorized creation, modification, or deletion of watched files.

Category: Integrity. Source: [src/angerona/modules/file_integrity.py:366](../../src/angerona/modules/file_integrity.py#L366).

Individual test: [src/angerona/modules/file_integrity.py:1500](../../src/angerona/modules/file_integrity.py#L1500). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## FleetHealthMonitorModule

Detects bounded Fleet Fabric evidence loss, queue backpressure, policy drift, custody deletion, unhealthy endpoints, and fail-closed coordinator readiness without mutating hosts.

Category: Fleet. Source: [src/angerona/modules/fleet_health_monitor.py:19](../../src/angerona/modules/fleet_health_monitor.py#L19).

Individual test: [src/angerona/modules/fleet_health_monitor.py:269](../../src/angerona/modules/fleet_health_monitor.py#L269). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Forensics Capture

Opt-in encrypted bounded process strings/sockets; exact original native birth and authenticated active local evidence required.

Category: Forensics. Source: [src/angerona/modules/forensics.py:281](../../src/angerona/modules/forensics.py#L281).

Individual test: [src/angerona/modules/forensics.py:547](../../src/angerona/modules/forensics.py#L547). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Hardware-Rooted Integrity

Verifies OS-protected IPC key storage and DPAPI primitives; TPM database-key sealing remains an explicit unsupported outline.

Category: Integrity. Source: [src/angerona/modules/hardware_crypto.py:100](../../src/angerona/modules/hardware_crypto.py#L100).

Individual test: [src/angerona/modules/hardware_crypto.py:219](../../src/angerona/modules/hardware_crypto.py#L219). Prove a DPAPI protect→unprotect round-trip on a throwaway secret.

## HEAL

Diagnoses crashed modules and stages LLM-proposed patches for operator review.

Category: Resilience. Source: [src/angerona/modules/self_healer.py:277](../../src/angerona/modules/self_healer.py#L277).

Individual test: [src/angerona/modules/self_healer.py:1187](../../src/angerona/modules/self_healer.py#L1187). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## IdentitySessionGuardModule

Privacy-tokenized LUID, session, device-code, new-device, browser-store, RMM, and privilege-transition analytics; optional read-only Windows session events and untrusted browser-extension manifest inventory. No credentials or browser contents.

Category: Identity. Source: [src/angerona/modules/identity_session_guard.py:43](../../src/angerona/modules/identity_session_guard.py#L43).

Referenced settings: `data_dir`.

Individual test: [src/angerona/modules/identity_session_guard.py:400](../../src/angerona/modules/identity_session_guard.py#L400). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## ImmutableRecoveryGuardModule

Verifies externally signed backup-copy, failure-domain, immutability, air-gap, offsite, encryption, source-revision, and restore-test evidence.

Category: Resilience. Source: [src/angerona/modules/immutable_recovery_guard.py:57](../../src/angerona/modules/immutable_recovery_guard.py#L57).

Referenced settings: `data_dir`.

Individual test: [src/angerona/modules/immutable_recovery_guard.py:454](../../src/angerona/modules/immutable_recovery_guard.py#L454). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## In-Memory Flight Cache

Bounded sqlite :memory: mirror of the flight recorder for fast, low-I/O reads of hot recent events.

Category: Performance. Source: [src/angerona/modules/flight_cache.py:183](../../src/angerona/modules/flight_cache.py#L183).

Individual test: [src/angerona/modules/flight_cache.py:259](../../src/angerona/modules/flight_cache.py#L259). Verify insert, read-back, eviction cap, and read-only guard.

## Indirect Syscall Bridge

Uses explicit-prototype ctypes/psutil process controls and exposes a truthful unavailable state for the native indirect-syscall bridge until a fixed private, release-manifest-sealed broker is installed.

Category: Response. Source: [src/angerona/modules/sys_bridge.py:124](../../src/angerona/modules/sys_bridge.py#L124).

Individual test: [src/angerona/modules/sys_bridge.py:244](../../src/angerona/modules/sys_bridge.py#L244). Verify the bridge works (SSN probe only — no real process is harmed).

## Kernel Sensor Bridge

Reads process-creation and image-load events from the AngeronaSensor.sys kernel driver ring buffer via DeviceIoControl.  Provides tamper-resistant telemetry that cannot be suppressed from user space.

Category: Endpoint. Source: [src/angerona/modules/kernel_bridge.py:211](../../src/angerona/modules/kernel_bridge.py#L211).

Individual test: [src/angerona/modules/kernel_bridge.py:480](../../src/angerona/modules/kernel_bridge.py#L480). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Kernel-Boundary Posture Ledger

Read-only evidence for Secure Boot, VBS/HVCI, boot integrity flags, Code Integrity telemetry, and kernel-driver-service drift.

Category: Integrity. Source: [src/angerona/modules/kernel_posture_ledger.py:514](../../src/angerona/modules/kernel_posture_ledger.py#L514).

Individual test: [src/angerona/modules/kernel_posture_ledger.py:587](../../src/angerona/modules/kernel_posture_ledger.py#L587). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Linux eBPF Sensor

Native Linux kernel telemetry (execve + tcp_sendmsg) via BCC/eBPF; forwards to the main instance over the Remote Bridge. Linux-only, opt-in.

Category: Sensor. Source: [src/angerona/modules/ebpf_sensor.py:98](../../src/angerona/modules/ebpf_sensor.py#L98).

Referenced settings: `ebpf_enabled`.

Individual test: [src/angerona/modules/ebpf_sensor.py:301](../../src/angerona/modules/ebpf_sensor.py#L301). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Linux Observe Sensor

Rootless, privacy-minimized process, established-flow, and kernel posture observation; optional eBPF adds privileged kernel telemetry separately.

Category: Endpoint. Source: [src/angerona/modules/linux_observe.py:14](../../src/angerona/modules/linux_observe.py#L14).

Referenced settings: `ebpf_enabled`.

Individual test: [src/angerona/modules/linux_observe.py:77](../../src/angerona/modules/linux_observe.py#L77). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## LSASS Credential-Access Guard

Detects LSASS credential-dumping (Mimikatz/procdump/comsvcs MiniDump, T1003.001) by process command line + artifact signatures. Read-only.

Category: Detection. Source: [src/angerona/modules/lsass_guard.py:185](../../src/angerona/modules/lsass_guard.py#L185).

Individual test: [src/angerona/modules/lsass_guard.py:322](../../src/angerona/modules/lsass_guard.py#L322). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## macOS Observe Sensor

Privacy-minimized process and network observation for the macOS sensor preview; native Endpoint Security enforcement is reported separately.

Category: Endpoint. Source: [src/angerona/modules/macos_observe.py:20](../../src/angerona/modules/macos_observe.py#L20).

Individual test: [src/angerona/modules/macos_observe.py:44](../../src/angerona/modules/macos_observe.py#L44). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Memory Injection Scanner

Scans running process address spaces via VirtualQueryEx for anonymous RWX memory regions that indicate T1055 injection (shellcode, process hollowing, reflective DLL loading).

Category: Memory. Source: [src/angerona/modules/mem_inject_scanner.py:274](../../src/angerona/modules/mem_inject_scanner.py#L274).

Individual test: [src/angerona/modules/mem_inject_scanner.py:925](../../src/angerona/modules/mem_inject_scanner.py#L925). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Memory Time-Machine

SPSC mmap ring + per-PID sliding hash cache; forwards only the delta slice of newly-observed process strings to the LLM queue.

Category: Performance. Source: [src/angerona/modules/memory_timemachine.py:160](../../src/angerona/modules/memory_timemachine.py#L160).

Individual test: [src/angerona/modules/memory_timemachine.py:586](../../src/angerona/modules/memory_timemachine.py#L586). Prove the dedup path: the same string set twice must yield a full delta then an empty one.

## Mobile Response Bridge

E2EE (Signal) state-gated remote orchestration: posture queries and token+PIN-gated containment from the operator's phone.

Category: Response. Source: [src/angerona/modules/mobile_bridge.py:456](../../src/angerona/modules/mobile_bridge.py#L456).

Referenced settings: `mobile_enabled`.

Individual test: [src/angerona/modules/mobile_bridge.py:2423](../../src/angerona/modules/mobile_bridge.py#L2423). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Monolithic Packaging

Monitors whether Angerona is running as a signed, monolithic hermetic binary (PyOxidizer).  Loose .py execution is flagged as a hardening gap. Exposes trigger_build() for review-gated rebuild — never auto-executes.

Category: Resilience. Source: [src/angerona/modules/hermetic_packager.py:175](../../src/angerona/modules/hermetic_packager.py#L175).

Individual test: [src/angerona/modules/hermetic_packager.py:434](../../src/angerona/modules/hermetic_packager.py#L434). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Network Monitor

Watches new outbound connections; alerts on suspicious ports and first-seen external hosts.

Category: Network. Source: [src/angerona/modules/network_monitor.py:188](../../src/angerona/modules/network_monitor.py#L188).

Individual test: [src/angerona/modules/network_monitor.py:280](../../src/angerona/modules/network_monitor.py#L280). Validate endpoint, identity and response gates without network I/O.

## Network Protocol Deep Decoder

Decodes DNS query names and scores label entropy to catch DGA beacons and DNS-tunneling exfiltration.

Category: Network. Source: [src/angerona/modules/network_protocol_decoder.py:77](../../src/angerona/modules/network_protocol_decoder.py#L77).

Individual test: [src/angerona/modules/network_protocol_decoder.py:277](../../src/angerona/modules/network_protocol_decoder.py#L277). A random high-entropy name must flag; a normal domain must not.

## Packet Sniffer

Inspects network packets for cleartext credentials in a crash-isolated capture worker.

Category: Network. Source: [src/angerona/modules/packet_sniffer.py:95](../../src/angerona/modules/packet_sniffer.py#L95).

Individual test: [src/angerona/modules/packet_sniffer.py:397](../../src/angerona/modules/packet_sniffer.py#L397). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## PeripheralDMAGuardModule

Observes Kernel DMA/IOMMU, Thunderbolt, USB4, removable-storage, and device-install control posture without changing device state.

Category: Hardware. Source: [src/angerona/modules/peripheral_dma_guard.py:20](../../src/angerona/modules/peripheral_dma_guard.py#L20).

Individual test: [src/angerona/modules/peripheral_dma_guard.py:156](../../src/angerona/modules/peripheral_dma_guard.py#L156). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Persistence Sweep

Baselines and monitors autorun/persistence surfaces (Run keys, services, scheduled tasks, WMI subscriptions, startup folders); flags new and suspicious entries.

Category: Persistence. Source: [src/angerona/modules/persistence_sweep.py:107](../../src/angerona/modules/persistence_sweep.py#L107).

Individual test: [src/angerona/modules/persistence_sweep.py:596](../../src/angerona/modules/persistence_sweep.py#L596). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Platform Attestation Guard

Appraises Secure Boot, VBS/HVCI, Code Integrity, boot flags, and optional nonce-bound TPM quotes without claiming kernel or hardware enforcement.

Category: Integrity. Source: [src/angerona/modules/platform_attestation_guard.py:223](../../src/angerona/modules/platform_attestation_guard.py#L223).

Individual test: [src/angerona/modules/platform_attestation_guard.py:337](../../src/angerona/modules/platform_attestation_guard.py#L337). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Posture Hardening

Self-healing loop: turns red-team SUCCESS into staged, review-gated OS hardening.

Category: SOAR. Source: [src/angerona/modules/posture_hardening.py:163](../../src/angerona/modules/posture_hardening.py#L163).

Individual test: [src/angerona/modules/posture_hardening.py:1327](../../src/angerona/modules/posture_hardening.py#L1327). Verify durable practice memory and its separation from host findings.

## Process Monitor

Flags suspicious process spawns and execution from risky locations.

Category: Processes. Source: [src/angerona/modules/process_monitor.py:57](../../src/angerona/modules/process_monitor.py#L57).

Individual test: [src/angerona/modules/process_monitor.py:727](../../src/angerona/modules/process_monitor.py#L727). Exercise lineage and risky-path rules without enumerating processes.

## ProcessEgressGuardModule

Observes HMAC-authenticated, process/start/user/destination/path-bound egress decisions and detects replay, PID reuse, DNS drift, budget use, and gateway-attestation loss.

Category: Network. Source: [src/angerona/modules/process_egress_guard.py:43](../../src/angerona/modules/process_egress_guard.py#L43).

Individual test: [src/angerona/modules/process_egress_guard.py:174](../../src/angerona/modules/process_egress_guard.py#L174). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Purple Remediation Guard

Turns reviewed red-team misses into exact, rerun-verifiable detector signatures.

Category: Detection. Source: [src/angerona/modules/purple_guard.py:5368](../../src/angerona/modules/purple_guard.py#L5368).

Individual test: [src/angerona/modules/purple_guard.py:6028](../../src/angerona/modules/purple_guard.py#L6028). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## RAGProvenanceGuardModule

Root-confined, digest-bound, signature-injectable provenance validation and inert taint labeling for future retrieval sources.

Category: AI Security. Source: [src/angerona/modules/rag_provenance_guard.py:24](../../src/angerona/modules/rag_provenance_guard.py#L24).

Individual test: [src/angerona/modules/rag_provenance_guard.py:144](../../src/angerona/modules/rag_provenance_guard.py#L144). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Ransomware Heuristics

Detects ransomware (T1486) via Shannon entropy scanning of recently modified files and rename-storm rate tracking in user directories.

Category: Ransomware. Source: [src/angerona/modules/ransomware_heuristics.py:523](../../src/angerona/modules/ransomware_heuristics.py#L523).

Individual test: [src/angerona/modules/ransomware_heuristics.py:3091](../../src/angerona/modules/ransomware_heuristics.py#L3091). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## ReleaseTransparencyGuardModule

Verifies threshold publisher authorization binding the executable, complete payload manifest/catalog, SBOM, provenance, builder, and rollback sequence.

Category: Supply Chain. Source: [src/angerona/modules/release_transparency_guard.py:66](../../src/angerona/modules/release_transparency_guard.py#L66).

Individual test: [src/angerona/modules/release_transparency_guard.py:293](../../src/angerona/modules/release_transparency_guard.py#L293). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Remote Bridge

Secure multi-node telemetry forwarding with PSK-authenticated ephemeral X25519, HKDF, and AES-256-GCM. Off by default.

Category: Integrity. Source: [src/angerona/modules/remote_bridge.py:318](../../src/angerona/modules/remote_bridge.py#L318).

Individual test: [src/angerona/modules/remote_bridge.py:1125](../../src/angerona/modules/remote_bridge.py#L1125). Verify authenticated ephemeral agreement and an AES-GCM round-trip.

## Removable-Media / USB Monitor

Alerts on removable media, keeps it untrusted until a protected-store PIN approves Angerona scanning, and disables Windows AutoRun/AutoPlay. Reviews a bounded file sample after verified Windows volume approval.

Category: Detection. Source: [src/angerona/modules/usb_monitor.py:405](../../src/angerona/modules/usb_monitor.py#L405).

Individual test: [src/angerona/modules/usb_monitor.py:954](../../src/angerona/modules/usb_monitor.py#L954). Verify mount diffing and fail-closed approval without touching media.

## Scheduled AI Security Briefing

Compiles a daily plain-English security briefing (alert volume, top techniques, incidents, containment) via local AI with a deterministic fallback.

Category: Reporting. Source: [src/angerona/modules/daily_briefing.py:143](../../src/angerona/modules/daily_briefing.py#L143).

Individual test: [src/angerona/modules/daily_briefing.py:461](../../src/angerona/modules/daily_briefing.py#L461). Offline: verify the summary + deterministic briefing without Ollama.

## Self-Integrity Monitor

Detects in-memory tampering (monkeypatching) of Angerona's own enforcement functions with mandatory dependency/source coverage and an explicitly approved baseline boundary.

Category: Integrity. Source: [src/angerona/modules/self_integrity.py:604](../../src/angerona/modules/self_integrity.py#L604).

Individual test: [src/angerona/modules/self_integrity.py:791](../../src/angerona/modules/self_integrity.py#L791). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Shadow Shield

Ransomware file shielding via a delta version cache and VSS snapshots.

Category: Response. Source: [src/angerona/modules/shadow_shield.py:79](../../src/angerona/modules/shadow_shield.py#L79).

Referenced settings: `shadow_cache_enabled`, `shadow_cache_max_mib`, `shadow_min_free_mib`, `shadow_vss_enabled`.

Individual test: [src/angerona/modules/shadow_shield.py:1059](../../src/angerona/modules/shadow_shield.py#L1059). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Shadow-Copy / Recovery Tamper Guard

Detects shadow-copy deletion + recovery disabling (vssadmin/wmic/wbadmin/bcdedit, T1490) — a ransomware precursor — and alerts with the pid.

Category: Detection. Source: [src/angerona/modules/shadowcopy_guard.py:143](../../src/angerona/modules/shadowcopy_guard.py#L143).

Individual test: [src/angerona/modules/shadowcopy_guard.py:286](../../src/angerona/modules/shadowcopy_guard.py#L286). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## SIEM Forwarder

Forwards detections to a central SIEM as CEF over Syslog (UDP/TCP). Opt-in: idle until ANGERONA_SIEM_HOST is set.

Category: Integration. Source: [src/angerona/modules/siem_forwarder.py:94](../../src/angerona/modules/siem_forwarder.py#L94).

Individual test: [src/angerona/modules/siem_forwarder.py:531](../../src/angerona/modules/siem_forwarder.py#L531). Offline: verify CEF formatting + escaping without sending anything.

## Smart Deception

AI-generated contextual honeytokens; CRITICAL alert on tamper.

Category: Deception. Source: [src/angerona/modules/smart_deception.py:327](../../src/angerona/modules/smart_deception.py#L327).

Individual test: [src/angerona/modules/smart_deception.py:3316](../../src/angerona/modules/smart_deception.py#L3316). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## SOAR Automation

Runs response playbooks on serious events (recommend, or opt-in auto-contain). G3-B: requires 2-signal corroboration and System32 allowlist before auto-act.

Category: Response. Source: [src/angerona/modules/soar.py:59](../../src/angerona/modules/soar.py#L59).

Referenced settings: `community_playbooks_enabled`.

Individual test: [src/angerona/modules/soar.py:158](../../src/angerona/modules/soar.py#L158). Validate corroboration and cursor safety without executing a response.

## Speculative Triage Pre-Warm

Detects high-risk early markers and pre-streams a snapshot to Ollama so the final triage verdict returns with no cold start.

Category: Performance. Source: [src/angerona/modules/speculative_triage.py:47](../../src/angerona/modules/speculative_triage.py#L47).

Individual test: [src/angerona/modules/speculative_triage.py:366](../../src/angerona/modules/speculative_triage.py#L366). Verify marker detection fires for a temp-dir spawn and not for noise.

## SpywareGuardModule

Advanced surveillanceware evidence, persistence and memory audits, NDR heuristics, reviewed intelligence, exact-target single-rule containment and emergency beacons.

Category: Spyware Defense. Source: [src/angerona/modules/spyware_guard.py:131](../../src/angerona/modules/spyware_guard.py#L131).

Referenced settings: `data_dir`, `spyware_research_urls`, `spyware_scan_priority`.

Individual test: [src/angerona/modules/spyware_guard.py:1987](../../src/angerona/modules/spyware_guard.py#L1987). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## SSH Surface / Key / Tunnel Guard

Read-only OpenSSH posture, authorized-key fingerprint, host-key, service, listener, authentication, and tunnel-drift monitoring with authenticated baselines.

Category: Zero Trust. Source: [src/angerona/modules/ssh_surface_guard.py:177](../../src/angerona/modules/ssh_surface_guard.py#L177).

Referenced settings: `data_dir`.

Individual test: [src/angerona/modules/ssh_surface_guard.py:927](../../src/angerona/modules/ssh_surface_guard.py#L927). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Storage Hygiene Enforcer

Detects Angerona data spilled to the default C: location and proposes relocation to the configured root. Privileged pathname migration/purge is retired until handle-safe execution is available.

Category: Maintenance. Source: [src/angerona/modules/storage_hygiene.py:321](../../src/angerona/modules/storage_hygiene.py#L321).

Individual test: [src/angerona/modules/storage_hygiene.py:472](../../src/angerona/modules/storage_hygiene.py#L472). Verify detection/proposal and that execution/deletion remain retired.

## Sysmon Event Bridge

Reads the current Microsoft-Windows-Sysmon/Operational event range and emits them onto the Angerona bus. Falls back to psutil process-diff when Sysmon or win32evtlog is unavailable.

Category: Endpoint. Source: [src/angerona/modules/sysmon_listener.py:304](../../src/angerona/modules/sysmon_listener.py#L304).

Individual test: [src/angerona/modules/sysmon_listener.py:1338](../../src/angerona/modules/sysmon_listener.py#L1338). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Telemetry Canary Drills

Fires synthetic benign canary subprocesses at regular intervals and listens for the corresponding ETWG 4688 echo on the EventBus.  A missed canary reports an availability gap with unconfirmed cause; repeated misses on a previously verified path retain CRITICAL priority.

Category: Resilience. Source: [src/angerona/modules/canary_drill.py:117](../../src/angerona/modules/canary_drill.py#L117).

Individual test: [src/angerona/modules/canary_drill.py:884](../../src/angerona/modules/canary_drill.py#L884). Verify contracts and reject self/untrusted echoes before ETWG smoke-test.

## TemporalTradecraftCorrelatorModule

Bounded, restart-aware ordered correlation for SSH persistence, sessions, tunnels, network-path drift, and audit-log clearing.

Category: Correlation. Source: [src/angerona/modules/temporal_tradecraft_correlator.py:45](../../src/angerona/modules/temporal_tradecraft_correlator.py#L45).

Referenced settings: `data_dir`.

Individual test: [src/angerona/modules/temporal_tradecraft_correlator.py:351](../../src/angerona/modules/temporal_tradecraft_correlator.py#L351). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## TUNE

Approval-gated behavioural learning; downgrades exact known-good process/file/network events.

Category: Performance. Source: [src/angerona/modules/behavioral_tuner.py:83](../../src/angerona/modules/behavioral_tuner.py#L83).

Individual test: [src/angerona/modules/behavioral_tuner.py:646](../../src/angerona/modules/behavioral_tuner.py#L646). Prove candidate approval and exact matching in an isolated database.

## UGCAP Integrity Guard

User-gated BLAKE3 integrity vault, TPM-bound encrypted baseline, signed isolated verification worker, managed-workspace circuit breaker and reviewed source recovery.

Category: Integrity. Source: [src/angerona/modules/ugcap_guard.py:31](../../src/angerona/modules/ugcap_guard.py#L31).

Referenced settings: `data_dir`, `spyware_beacon_enabled`.

Individual test: [src/angerona/modules/ugcap_guard.py:521](../../src/angerona/modules/ugcap_guard.py#L521). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Upstream Threat Intel Sync

Correlates the CISA KEV catalog against this host's OS + running services; stages review-gated remediation, never auto-applies.

Category: Threat Intel. Source: [src/angerona/modules/intel_sync.py:335](../../src/angerona/modules/intel_sync.py#L335).

Individual test: [src/angerona/modules/intel_sync.py:683](../../src/angerona/modules/intel_sync.py#L683). Offline: verify correlation + MITRE mapping on an embedded sample.

## Watchdog Monitor

Self-healing supervisor: detects crashed/hung modules and restarts them (throttled).

Category: Resilience. Source: [src/angerona/modules/watchdog_monitor.py:53](../../src/angerona/modules/watchdog_monitor.py#L53).

Individual test: [src/angerona/modules/watchdog_monitor.py:286](../../src/angerona/modules/watchdog_monitor.py#L286). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## WFP Controller

WFP-aware containment planner plus full-tuple IP Helper ownership snapshots; health explicitly reports when native WFP net-event telemetry is absent.

Category: Network. Source: [src/angerona/modules/wfp_controller.py:627](../../src/angerona/modules/wfp_controller.py#L627).

Individual test: [src/angerona/modules/wfp_controller.py:765](../../src/angerona/modules/wfp_controller.py#L765). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## WLAN Monitor

Detects Evil Twin / rogue AP attacks by monitoring SSID and BSSID changes on the active wireless interface via netsh.

Category: Network. Source: [src/angerona/modules/wlan_monitor.py:138](../../src/angerona/modules/wlan_monitor.py#L138).

Individual test: [src/angerona/modules/wlan_monitor.py:510](../../src/angerona/modules/wlan_monitor.py#L510). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## YARA Scanner

Scans Downloads and the isolated drill sandbox with in-process YARA.

Category: Signatures. Source: [src/angerona/modules/yara_scanner.py:169](../../src/angerona/modules/yara_scanner.py#L169).

Individual test: [src/angerona/modules/yara_scanner.py:1053](../../src/angerona/modules/yara_scanner.py#L1053). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.

## Zero-Trust Local IPC Guard

Diagnostic HMAC-SHA256 admission probe on 127.0.0.1:65432; authenticates and closes, with no production payload consumer.

Category: Integrity. Source: [src/angerona/modules/ipc_guard.py:199](../../src/angerona/modules/ipc_guard.py#L199).

Individual test: [src/angerona/modules/ipc_guard.py:480](../../src/angerona/modules/ipc_guard.py#L480). Prove HMAC verify (accept valid / reject tampered) AND a real loopback challenge/response round-trip on an ephemeral port (valid vs wrong key).

## Zero-Trust Network Path Monitor

Treats active Wi-Fi and Ethernet paths as untrusted by default and observes tokenized DNS, DHCP, route, gateway, profile, and epoch drift.

Category: Network. Source: [src/angerona/modules/network_trust_monitor.py:817](../../src/angerona/modules/network_trust_monitor.py#L817).

Individual test: [src/angerona/modules/network_trust_monitor.py:1310](../../src/angerona/modules/network_trust_monitor.py#L1310). This module declares a dedicated self-test. Inspect the method for its sample, limits and asserted postconditions.
