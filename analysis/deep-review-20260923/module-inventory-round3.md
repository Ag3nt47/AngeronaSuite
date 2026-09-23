# Module inventory — deep review pass 3

All 84 discovered capabilities are accounted for by the final supported offline SelfTestRunner. No module worker was started by this inventory. Optional/unavailable prerequisite skips remain explicit. Direct core self-tests: 24 passed, 0 failed. The JSON companion includes final source hashes, declaration details and lifecycle method locations.

| Capability | Declared CODE | Self-test | Evidence |
|---|---|---|---|
| AI Model Integrity Guard | AMIG | PASS | chunked SHA-256 tamper-detect verified; model dir: <model-directory> |
| AI Triage (Ollama) | (optional) | SKIP | not started by headless harness / optional prerequisite: Ollama ready, but model llama3 has no fresh approved local attestation: approved model baseline unavailable (approval-required) |
| AMSI Bridge | AMSI | SKIP | not started by headless harness / optional prerequisite: status=stopped, health=100% |
| API Patch / Anti-Blinding Detector | APID | PASS | parsed all 7 required ntdll export prologue(s) from disk |
| ARP Watchdog | ARPW | PASS | ARP parser ready — mode=poll-only; baseline=not-loaded |
| AV Telemetry Bridge | AVTB | PASS | health=100% |
| Active Deception | (optional) | PASS | disposable secret-free canary lifecycle passed |
| Active Response SOAR | (optional) | SKIP | disabled by operator configuration |
| Adaptive Resource Governor | GOV | PASS | governor active; current throttle 1x |
| Adversary Combat | (optional) | SKIP | not started by headless harness / optional prerequisite: MAXIMUM status=stopped; Low+; process=terminate; queue drops=0; The response worker is stopped or restarting. |
| AegisPath Exposure Graph Guard | AEGP | PASS | immutable digest, evidence generation/freshness, resource-limit, and observe-only health contract verified |
| Anti-Suspension Heartbeat | FRZ | PASS | authenticated v2 mmap round-trip OK (pinned v2 watchdog unavailable; authenticated Python heartbeat only) |
| App Control Decision Evidence | ACDS | PASS | bounded 3076/3077/3089 parser and ActivityID join verified |
| Audit Log Integrity Guard | ALIG | PASS | strict clear-event parser and privacy boundary verified |
| Authentication Extension Integrity Guard | AEIG | PASS | bounded path-minimized drift and observe-only event contract verified |
| C2 Beacon Detector | BEAC | PASS | beacon cadence detected (mean=60s cv=0.00), human traffic ignored, external-IP test OK |
| CHAOS | CHAOS | PASS | cycle 24.0h; 0 runs, 0 with regressions |
| Cloud CTI Escalation | (optional) | SKIP | disabled by operator configuration |
| Compliance Mapper | CMAP | PASS | MITRE→NIST/STIG mapping + sub-technique fallback verified |
| Counter-Agentic Detection | CAGT | PASS | cadence+chain detection verified (agentic fires, benign quiet, offensive subsystems excluded) |
| Data Provenance Graph | PROV | PASS | ancestry/subtree verified on synthetic DAG |
| Detection Runtime | DFRT | PASS | separate bounded lanes and observe-only authority passed |
| Deterministic Fast-Path Interceptor | FPTH | PASS | 17 rules loaded — pattern match verified |
| Driver Provenance Guard | DPVG | PASS | hash/signer/catalog/blocklist/HVCI/boot evidence join passed offline |
| Dynamic Resource Governor | DRES | SKIP | not started by headless harness / optional prerequisite: status=stopped, health=100% |
| ETW Core Listener | ETWG | PASS | 4688 decode verified (Security channel available) |
| ETW Real-Time Process Sensor | ETWR | PASS | Kernel-Process decode verified (pywintrace present but not elevated → run as Administrator for real-time) |
| Evidence Lattice Fusion | ELAT | PASS | entity fusion, dedup, time-window expiry, and false-positive controls passed |
| Evolution Engine | (optional) | PASS | fallback YARA synthesis + BL-07 bounds (concurrency/rate/breaker) OK |
| File Integrity Monitor | FIM | PASS | driver-shield classifier + BL-13 paranoid high-value hashing verified |
| Fleet Health Monitor | FLTH | PASS | typed signed-health shape, exact degraded reason, and no-command rollout boundary verified |
| Forensics Capture | (optional) | SKIP | disabled by operator configuration |
| HEAL | HEAL | PASS | watching crash snapshots; 0 staged this session |
| Hardware-Rooted Integrity | HWID | PASS | DPAPI round-trip verified |
| Identity Session Guard | IDSG | PASS | supplied-only tokenization and bounded transition analytics verified |
| Immutable Recovery Assurance Guard | IRAG | PASS | fail-closed signed recovery policy verified; online F: mirrors do not count as immutable or offline |
| In-Memory Flight Cache | MEMC | PASS | cache verified (cap-held=10, newest=msg24, ro-guard=True) |
| Indirect Syscall Bridge | SYS | PASS | No sealed private native bridge admitted; explicit ctypes/psutil fallback active and health is truthfully degraded. |
| Kernel Sensor Bridge | KRNL | SKIP | disabled by operator configuration |
| Kernel-Boundary Posture Ledger | KBPL | PASS | authenticated bounded ledger: 1 record(s) verified; live posture starts unknown |
| LSASS Credential-Access Guard | CREDG | PASS | LSASS-dump signature matcher verified (comsvcs+procdump flagged, benign ignored) |
| Linux Observe Sensor | (optional) | SKIP | Unavailable on windows; this capability supports linux. |
| Linux eBPF Sensor | EBPF | SKIP | Unavailable on windows; this capability supports linux. |
| Memory Injection Scanner | MINJ | SKIP | not started by headless harness / optional prerequisite: status=stopped, health=100% |
| Memory Time-Machine | MTM | PASS | dedup verified (4→0 on repeat) |
| Mobile Response Bridge | MOB_BRDG | SKIP | disabled by operator configuration |
| Monolithic Packaging | HERMETIC | PASS | Assessment: Running as .py (hardening gap) — hermetic binary present (unsigned (NotSigned)).  Consider running angerona.exe. \| build-hermetic.bat=found \| hermetic=False |
| Network Monitor | (optional) | PASS | offline IPv4/IPv6, Community ID, bounds, and response gates passed |
| Network Protocol Deep Decoder | NDRD | PASS | layered DGA scoring verified (dga E=4.322, evasive E=4.0 caught via ['entropy 4.00≥3.6', 'low vowel-ratio 0%', 'consonant-run 16'], benign clean) |
| Packet Sniffer | (optional) | SKIP | disabled by operator configuration |
| Peripheral and DMA Posture Guard | PDMG | PASS | Kernel DMA/IOMMU, Thunderbolt/USB4/removable control risks and honest UNKNOWN/firmware limitations verified without device changes |
| Persistence Sweep | (optional) | PASS | persistence classifier verified (encoded-PS + Winlogon hijack CRITICAL, temp-path HIGH, clean-default not escalated) |
| Platform Attestation Guard | PATG | PASS | strict OS posture and injected TPM quote verifier passed offline |
| Posture Hardening | (optional) | PASS | probe weaknesses=1, health=40, staged=1 |
| Process Egress Lease Guard | PELG | PASS | process/start/user/DNS/IP/path binding, one-use budget, replay denial, and sanitized observe-only audit verified |
| Process Monitor | (optional) | PASS | offline lineage and risky-path rules passed |
| Purple Remediation Guard | (optional) | PASS | exact file/process markers detected; benign noise ignored |
| RAG Provenance Guard | RAGP | PASS | root confinement, digest pinning, and inert excerpt boundary verified |
| Ransomware Heuristics | RANS | PASS | Entropy function OK (test=8.000 ≥ 7.9); timestamp-independent full/range proof, authenticated durable change transitions/high-water, fixed-window strided scoring, durable fair rotation, and held no-reparse traversal enabled |
| Release Transparency / Anti-Rollback Guard | RTAG | PASS | unsigned, malformed, expired, and below-threshold updates fail closed |
| Remote Bridge | RBRG | SKIP | disabled by operator configuration |
| Removable-Media / USB Monitor | USBW | PASS | new-drive diff + fail-closed approval gate verified |
| SIEM Forwarder | SIEM | SKIP | disabled by operator configuration |
| SOAR Automation | (optional) | PASS | offline distinct-source corroboration, cursor, and protected-process gates passed |
| SSH Surface / Key / Tunnel Guard | SSHG | PASS | bounded parser, privacy tokens, and observe-only contract verified |
| Scheduled AI Security Briefing | BRIEF | PASS | briefing builder verified (severity tally, technique ranking, posture + containment line) |
| Self-Integrity Monitor | SINT | PASS | runtime tamper detection verified — clean baseline is silent, a monkeypatched enforcement function is flagged, restore clears it. |
| Shadow Shield | SHDW | PASS | cache ready; 0 VSS snapshots this session |
| Shadow-Copy / Recovery Tamper Guard | VSSG | PASS | recovery-tamper signatures verified (vssadmin/bcdedit/wmic flagged, 'list shadows' ignored) |
| Smart Deception | SDEC | PASS | 0 honeytokens; 60-byte read cap; 0 unresolved trips; authenticated custody ledger sequence=0; remaining=4096; external-local-witness=0; freshness=local-authenticity-only; namespace-protected=0; capture=not_attempted; digest-sealed quarantine cap=8/1048576B; dedup cap=256 |
| Speculative Triage Pre-Warm | SPEC | PASS | early high-risk marker detection verified |
| Storage Hygiene Enforcer | SHYG | PASS | detect + dry-run proposal + retired mutation verified (sandboxed) |
| Sysmon Event Bridge | SYSL | PASS | offline generation-bound cursor/anchor contract verified |
| TUNE | TUNE | SKIP | not started by headless harness / optional prerequisite: status=stopped, health=100% |
| Telemetry Canary Drills | DRILL | PASS | strict ETWG echo + bounded telemetry contract controls passed |
| Temporal Tradecraft Correlator | TTCR | PASS | authenticated bounded automaton and observe-only output verified |
| Upstream Threat Intel Sync | INTL | PASS | KEV correlation + driver-intel blocklist + IOC fusion verified (offline) |
| WFP Controller | WFPC | SKIP | not started by headless harness / optional prerequisite: status=stopped, health=100% |
| WLAN Monitor | WLAN | PASS | netsh WLAN query succeeded (not connected) |
| Watchdog Monitor | (optional) | PASS | auto-recovered a simulated crashed module: True |
| YARA Scanner | (optional) | PASS | PASS - in-process YARA compiled rules and detected EICAR |
| Zero-Trust Local IPC Guard | AUTH | PASS | isolated HMAC + loopback handshake verified (valid OK, wrong-key DENY) |
| Zero-Trust Network Path Monitor | NZTR | PASS | untrusted-LAN/WLAN monitoring and privacy boundary verified |
| macOS Observe Sensor | (optional) | SKIP | Unavailable on windows; this capability supports macos. |

Missing optional `register()` and explicit `CODE` declarations are preserved compatibility cases: discovery reports no import errors and no duplicate declared codes. This is an exhaustive inventory/self-test record, not a claim that every line of every module was manually re-reviewed or changed.
