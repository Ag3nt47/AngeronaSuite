# Angerona Capabilities

Current status: **v1.12.1**. This is a present-tense capability and boundary
summary. Operating detail is in the [Master Manual](Angerona_Master_Manual.docx);
engineering evidence is in
[`analysis/loop/`](analysis/loop/), including the Cycle 26–30 evidence.

## Core proposition

Angerona is a local-first EDR/NDR/SOAR and digital-forensics workbench for
Windows-focused home labs, defensive research, purple-team practice, and
security-engineering portfolios. It brings telemetry, detection, correlation,
investigation, governed response, recovery, local AI, and non-destructive
validation into one PySide6 desktop application.

The v1.12.1 security model separates four kinds of claims:

- **Integrated:** a production path is connected to the application and covered
  by its local contract.
- **Observe-only:** a module evaluates evidence but cannot mutate the host.
- **Injected authority:** a caller must supply a trusted producer, verifier, or
  separately privileged adapter.
- **Deployment-dependent:** the repository supplies code and fail-closed
  configuration gates, but cannot create external custody, publisher trust,
  hardware state, or an independent failure domain.

## v12 capability contract and operator surfaces

- Exactly **81** built-in capabilities are present in the reproducible
  Windows-target inventory. Every capability receives the same validated v12
  contract and operational lifecycle/freshness/loss snapshot.
- Contract fields cover implementation version, platform, mode, permissions,
  inputs/outputs, egress, retention, response authority, dependencies,
  conflicts, settings, self-test, restart/loss behavior, and resource budget.
- Contract truth is explicit: **6 native contracts** and **75 compatibility
  adapters**. Compatibility metadata gaps remain visible and lower assurance
  even though every shipped built-in module now carries the v1.12.1 release
  implementation label. A shared version does not imply equal platform support,
  evidence completeness, response authority, or independent efficacy.
- Capability Center and Module Inspector provide search, filter, typed sorting,
  bounded details, source/dependency/path information, and live operational
  evidence. Contract export remains machine-readable.

## Endpoint, network, and evidence visibility

- Windows Event Tracing for Windows, Windows Management
  Instrumentation/Common Information Model, Antimalware Scan Interface, Windows
  Filtering Platform, Defender, Security log, Code Integrity, OpenSSH, and
  Sysmon telemetry.
- Process lineage, file integrity, persistence, memory injection, LSASS-access
  indicators, shadow-copy tamper, ransomware, command-and-control cadence,
  removable media, vulnerable-driver posture, deception, YARA/YARA-X, and
  network behavior detection.
- Community ID v1, OCSF 1.8 mappings, Suricata and Zeek evidence, guarded
  read-only osquery snapshots, cases, causal timelines, Evidence Lattice
  correlation, Telemetry Expectation Contracts, and MITRE ATT&CK mapping.
- **SentinelLens** accepts bounded live EventBus evidence plus explicit Syslog,
  Windows Event, NetFlow, JSON, JSONL, and array imports. Its local graph maps
  process, network, file, technique, correlation, and proof relationships;
  clickable nodes and sortable anomaly rows expose exact evidence identity,
  deterministic selection reason, path fields, attack-chain narrative, and
  proposal-only remediation. An app-owned background service uses a bounded
  non-blocking queue and exposes drop/parser/analysis health without slowing
  EventBus producers. Optional language-model narrative is restricted to a
  strict loopback endpoint; there is no cloud fallback, public/LAN listener, or
  telemetry export.
- Authenticated local EventBus persistence protects record bytes. The
  **Sensor Provenance Broker** separately authenticates enrolled producer
  identity, exact event schema, sequence continuity, replay state, and loss
  metadata before a fixed-schema consumer can advance trusted state.
- Source completeness, freshness, loss, overflow, platform, and privilege
  remain explicit. Unknown or incomplete evidence never silently becomes
  healthy.

## Advanced actor-neutral defensive hardening

### SSH, tunnels, and ordered tradecraft

- **SSH Surface / Key / Tunnel Guard** inventories bounded OpenSSH configuration
  and Include graphs, configured key/CA/principals sources, public-key
  fingerprints, file and parent custody, services, listeners, authentication
  evidence, and normalized forwarding activity.
- Live SSH evidence is admitted only through a broker-authenticated
  `OpenSSH Auth Event Collector` identity with an exact event type, fixed
  provider/channel/message schema, and loss-aware sequence continuity.
  Consumer-schema rejection occurs before continuity state advances.
- The guard never reads a private key or credential, attempts a login, probes a
  listener, opens a tunnel, or changes configuration. It does not retain or
  publish full command lines, full commands, or raw endpoints.
- **Temporal Tradecraft Correlator** performs bounded, restart-aware ordered
  correlation across SSH persistence, sessions/tunnels, network-path drift, and
  event-log clear evidence. Supplied evidence without broker provenance is
  confidence-capped and cannot silently seed trusted producer history.

### Event-log clearing and recovery

- **Audit Log Integrity Guard** observes explicit clear/tamper event identities,
  logging-service and audit-policy changes, continuity and generation gaps,
  record reuse, retention regression, provider/channel mismatch, and
  authenticated cursor damage.
- Generation-consistent staging and bounded replay detect clear/refill races.
  The module never clears, changes, exports, or restores an operating-system log.
- **Immutable Recovery Assurance Guard** evaluates externally signed backup
  statements for exact revision/archive/manifest cohorts, copy and
  failure-domain diversity, signer separation, recency, encryption,
  immutability, offline/offsite posture, and digest-bound restore tests.
- Excessive future timestamps, mixed cohorts, unreadable or linked evidence,
  unbounded directories, and unstable files fail closed. Angerona cannot
  recreate log entries or other evidence deleted before collection.

### Identity, platform, drivers, and peripherals

- **Identity Session Guard** performs privacy-tokenized LUID/session,
  device-code, new-device, browser-store, remote-management, and privilege-
  transition analytics over structured supplied evidence. It does not acquire
  credentials, tokens, browser contents, or cloud sessions.
- **Driver Provenance Guard** joins bounded driver image hashes,
  Authenticode/catalog evidence, blocklist disposition, Hypervisor-Protected
  Code Integrity, and Secure Boot posture. Overflow is explicit and missing
  evidence remains unknown. It is read-only and cannot unload, disable, delete,
  or quarantine a driver.
- **Platform Attestation Guard** evaluates Secure Boot, virtualization-based
  security, code integrity, boot flags, and Trusted Platform Module presence.
  It reports hardware attestation only when an injected verifier validates a
  fresh nonce-bound quote; the default collector does not fabricate one.
- **Peripheral and DMA Posture Guard** observes Kernel DMA/IOMMU, Thunderbolt,
  USB4, removable-storage, and device-install posture without changing device
  state. Linux removable absence is complete only when every enumerated flag is
  a stable, no-follow, valid zero.
- These local posture sensors do not prove device firmware, a physical
  transmitter, a malicious kernel, or hardware outside the evidence boundary.

## Zero trust and Personal Sentinel

Intended topology:

```text
Angerona host
  -> operator-controlled Personal Sentinel gateway/firewall
  -> upstream/ISP router
  -> Internet
```

- **Zero-Trust Network Path Monitor** treats every active physical Wi-Fi and
  Ethernet path as untrusted regardless of private address, profile, or
  location. Purpose-specific tokens preserve restart-safe Domain Name System,
  Dynamic Host Configuration Protocol, route, gateway, profile, interface, and
  path-addition drift without retaining raw local identifiers.
- The enrolled **Personal Sentinel gateway client** can attest one exact private
  HTTPS default gateway with ordinary certificate/hostname validation, a leaf
  certificate pin, nonce/freshness, expected policy digest, optional mutual TLS,
  complete IPv4/IPv6 route evidence, and unchanged pre/post route context.
- Introduced in v1.11.0, Angerona supplies a separately operated **Personal Sentinel reference
  authority/server** for mTLS-authenticated requests, Ed25519 response/state
  receipts, trusted time, and monotonic compare-and-swap evidence. The service
  has bounded pre-authentication and authenticated workers, an OS singleton
  lease, durable sequence floors, and an irreversible shutdown lifecycle.
- The reference server is not a bundled appliance or managed service. Operators
  must provision its private host, certificates, key roles, protected state,
  enrollment, monitoring, backup, and recovery.
- Neither Sentinel component performs router discovery, router configuration,
  credential storage, route changes, firewall mutation, remote administration,
  or firmware trust. A positive result labels only the exact observed first-hop
  path and grants no implicit endpoint, identity, application, destination, or
  upstream-router trust.
- Local authenticated floors resist ordinary corruption/replay but not
  privileged whole-host snapshot rollback. That attacker model requires a
  policy-bound Trusted Platform Module or a separately administered witness
  outside the restorable host.

## Guided Host Adaptation and recovery

- **Guided Auto Adapt** presents the closed Balanced, Public, and Emergency
  Lockdown profiles with explicit apply and baseline-enrollment choices.
- The workflow performs one audit, rejects incomplete evidence, constructs an
  immutable plan, and runs a no-write simulation. Accepted choices are copied
  immutably before background work. An optional mutation requires a separate
  confirmation of the exact plan; contextual automation remains proposal-only.
- The explicitly enrolled recovery baseline is HMAC-authenticated, host-bound,
  non-replaceable, and required before mutation. It restores the complete
  Windows Firewall policy, which is the complete mutation scope of Host
  Adaptation. Hardware, services, ports, applications, and network context are
  observations, not whole-host rollback state.
- Every apply also captures a pre-change snapshot. An HMAC transaction journal,
  exact postcondition verification, compensation, startup reconciliation, and
  circuit breaker cover interrupted or failed firewall changes.
- **Run safe automatic checkup** audits once and simulates all registered
  profiles without writing.
- Remote-session anti-lockout uses fresh bounded SSH/current-session evidence,
  Windows Terminal Services enumeration, and common third-party remote-control
  agent process checks. Unknown or failed evidence cannot authorize a mutation.

## Governed defensive response

- Adversary Combat supports exact-peer blocks, exact-executable isolation,
  verified process suspension/termination, exact-file quarantine, bounded
  deception, and explicit host isolation.
- Signed response contracts and capability tokens bind action type, process
  birth, executable/file identity, peer, lifetime, sequence, and escalation
  scope. Durable epochs/high-water state prevent ordinary capability reuse
  across authority restart.
- Durable fsynced intents, verified postconditions, exact Undo, startup
  recovery, idempotency, compensation, and mutation-circuit breakers make
  state changes visible and recoverable.
- Protected/system processes, stale identities, ambiguous evidence, and weak
  cross-entity signals fail closed. SOAR surfaces reconcile signed receipts;
  submitted work is never displayed as verified success.
- The **Process Egress Lease Broker** can authorize/audit narrow, short-lived
  process/start/user/destination/path/budget decisions. The shipped
  **Process Egress Lease Guard** is observe-only. Socket enforcement requires a
  separately privileged injected connection-admission adapter and a retained
  OS process/executable identity lease.

## Release and supply-chain trust

- The only supported **public first-install** Windows contract is a signed,
  full-trust x64 MSIX. Windows validates the package block map and provisioned
  publisher identity before activation.
- Building a public MSIX requires an exact externally configured package name
  and publisher distinguished name, protected publisher certificate, pinned
  Windows SDK toolchain, and clean release gates. The repository makes no
  Microsoft Store deployment claim; enterprise/App Installer trust policy and
  clean-VM acceptance remain deployment work.
- Classic Inno Setup is non-public and prior-approved-install migration-only.
  It performs unelevated preflight and delegates UAC/mutation to the protected
  installed updater; it is not a public asset or first-install trust bootstrap.
- The portable ZIP is upgrade-only. Its installed native verifier reconstructs
  threshold release authorization, validates exact payload manifest/catalog,
  software bill of materials and provenance digests, enforces separately
  enrolled 2-of-2 Ed25519 roots, compares numeric version/sequence floors, and
  advances protected state before target mutation.
- Signer responses contain a signer label, statement digest, and signature—not
  a replacement public root. Finalization requires the exact externally
  supplied root policy and its protected SHA-256 digest.
- Windows access-control lists protect the local portable floor, but a
  privileged whole-host rollback can restore it with the filesystem unless a
  hardware or independent monotonic witness anchors freshness.
- **Release Transparency / Anti-Rollback Guard** remains an observe-only runtime
  verification layer; first-install authenticity is an operating-system
  package/deployment responsibility, not a post-start module claim.

## ARIA, retrieval, and operator visibility

- Local Ollama-backed triage, runbook retrieval, defensive briefings, typed
  assistant tools, and explicit provider controls.
- Typed keyboard confirmation is required for consequential ARIA actions.
  Voice, gestures, callbacks, retrieved text, model output, and untrusted
  content cannot confirm host mutation.
- The governed `aria-defense-llama3` pack uses exact manifest/blob checks,
  bounded resource admission, evaluation, activation, rollback, and removal.
  Knowledge packs and model output are non-executable data.
- **ARIA Defense Memory v1.1.0** is an 18-entry capability, usage, defensive-
  measure, and actor-neutral tradecraft reference. Strict schema, stable
  non-reparse reads, structural/text budgets, and the canonical pinned digest
  `sha256:97a7771a9ce38ac66c6889dc90e0d591b64e07c2f169a0cebd7a57c119d67d57`
  gate admission.
- Defense Memory defines no tool and grants no authority. Local retrieval can
  use the full admitted reference; an already enabled cloud fallback may
  receive at most one highest-ranked canonical excerpt after bounded redaction.
- **RAG Provenance Guard** validates explicitly configured, root-confined,
  digest-bound future retrieval sources and emits inert taint/trust labels. It
  does not mutate an index or Defense Memory and requires a caller-owned
  verifier for publisher-signed tiers.
- **Live Defense Activity** displays five or fewer sanitized public EventBus
  summaries plus coarse module state. It never reads raw event details, source
  code, executing code, private model reasoning, or chain-of-thought.

## Investigation, validation, and operations

- Live Alerts, Resolve Center, SOAR Queue, Scan Center, Top Talkers, cases,
  bounded hunts, legal hold, custody verification, threat intelligence, local
  asset/software-inventory views, audit export, and detection-content lifecycle.
- Flow Dashboard / Local SOC, ATT&CK heat/coverage views, Upgrade Console,
  watchdog, telemetry, AI/model management, and tab-aware Source Sandbox.
- Non-destructive Red Team and Shark Attack campaigns use bounded reversible
  markers rather than exploits, credential theft, persistence, or remote
  infrastructure.
- Maximum Adversary Combat validation exercises detector admission, signed
  response authority, verified closure, Undo/cleanup, and journal integrity.
- Shared tables sort severity and risk by typed values. Live Defense, alert,
  Context Info, adaptation, CVE, capability, and governed-path rows open bounded
  details rather than implying unavailable evidence.
- Alert analysis is bounded to two active workers and six queued exact event
  identities. Temporary suppression is exact-rule, confirmed, 15-minute,
  audited, undoable, and unavailable to integrity alerts.
- SOAR clear is an atomic recoverable archive/restore operation with a digest
  manifest. The digest is not represented as an independent signature. CVE
  detail work is owned, interruption-aware, and nonblocking.

## Delivery, mutation, and standards contracts

- SIEM and Remote Bridge use durable bounded outboxes, revision cursors,
  drain-stage-drain ordering, explicit gap receipts, leases/retry/dead-letter,
  persistent idempotency tombstones, and HMAC-authenticated mutable state. The
  durable queue key is independent of transport-key rotation.
- Settings and protected credentials use atomic replacement and compensation
  across exact settings bytes, secure-store values, environment projection,
  and autostart. Intel Sync uses atomic generation/cancel/status publication.
- Evolution, mitigation tuning, contextual adaptation, and unapproved
  behavioral learning remain proposal-only. Behavioral activation requires an
  exact SHA-256 approval and returns to pending review on hash drift.
- Process, driver, and direction-specific firewall remediation binds exact
  identity, return codes, postconditions, and rollback. Ambiguous ACL lockdown
  is not a production automatic action.
- The curated standards contract is ATT&CK **19.2** across **15 Enterprise
  tactics**, Navigator **5.3.2** / layer **4.5**, constrained-preview OCSF
  **1.8.0**, and a deliberately limited Sigma evaluator with atomic bounded
  admission/refusal receipts.
- IPC Guard is a protected-store authenticated loopback diagnostic admission
  preview. It is not a production payload consumer, remote channel, or
  TPM-backed transport.

## Platform contract and module discovery

| Platform | Current use | Static modules |
| --- | --- | ---: |
| Windows | **Protect:** supported elevated user-mode telemetry and governed response; no unsigned kernel driver ships. | **81** |
| Linux | **Observe + optional eBPF:** rootless shared-core visibility with an explicit privileged BCC/eBPF supplement. | **14** |
| macOS | **Observe preview:** privacy-minimized shared-core visibility; no native enforcement claim. | **13** |

## Best-fit use cases

- Advanced Windows home lab and self-hosted defensive workstation.
- Blue-team, SOC, incident-response, detection-engineering, and ATT&CK learning.
- Safe purple-team validation of detections and response/recovery contracts.
- Defensive investigation of SSH persistence/tunnels, erased or discontinuous
  Windows logs, identity/session anomalies, vulnerable-driver posture, and
  suspicious Wi-Fi/Ethernet path drift without actor attribution.
- Local-AI security research with explicit provenance and authority boundaries.
- Operator-controlled intermediate gateway/firewall experiments with the
  supplied Sentinel contracts and a separately administered reference service.
- Security-engineering portfolio demonstrating GUI, telemetry, response,
  recovery, secure release design, tests, and honest platform boundaries.

## Validation snapshot

- Authoritative v1.12.1 serial release suite:
  **2659 passed; 13 intentional host-platform
  skips; 0 failed**.
- Static platform discovery: **81 Windows / 14 Linux / 13 macOS modules**.
- Product `compileall`: pass.
- Structural inventory: **81 capabilities** with **6 native contracts** and
  **75 compatibility adapters**, without duplicate identity.
- Supported headless selfcheck: **26/26**; workflow policy, dependency audit,
  documentation drift, Ruff, and diff checks pass on the same release tree.

Focused groups overlap. They are not a final-suite total or clean-machine
publisher/deployment proof.

## Honest limits and residuals

- Not independently certified, externally benchmarked, or validated at
  commercial fleet scale; not a drop-in replacement for a supported enterprise
  EDR/XDR product.
- Publisher identity, protected signing environments, enrolled root custody,
  App Installer/enterprise policy, clean-VM release acceptance, external
  backup/witness failure domains, and hardware monotonic state are not created
  by repository code.
- Personal Sentinel is a supplied reference service and client contract—not a
  turnkey appliance, router manager, firmware attestor, or remote-control plane.
- Appraisal and observe-only modules cannot prove truth after Administrator,
  SYSTEM, kernel, firmware, producer, verifier, or external-authority compromise
  inside their declared trust boundary.
- The immutable Host Adaptation baseline is complete for Windows Firewall
  policy only; it is not whole-host configuration or disaster recovery.
- Durable outbox HMACs do not independently witness row deletion or rollback of
  the entire local database. Delivery is at least once and can duplicate;
  transport-key coordination still uses restart epochs.
- The ATT&CK catalog is curated, OCSF/Sigma support is constrained, and IPC
  Guard is diagnostic admission rather than a production transport.
- Event-log continuity evidence cannot reconstruct data already erased.
- In-process admitted extensions retain the suite token; legacy trusted
  PowerShell collectors still have a broad policy surface; path-wide firewall
  mutation still lacks the preferred retained OS process/executable-file lease.
- Long elevated soaks, physical sleep/resume, clean-machine
  install/upgrade/uninstall, native Linux/macOS artifact acceptance, field
  false-positive baselines, and independent defensive efficacy remain external
  gates.
- No offensive payload, hack-back, remote exploitation, credential theft,
  arbitrary response shell, log deletion/evasion, automatic router mutation,
  downloaded executable skill, unverified model, or unsigned kernel component.

## Primary references

- [Velociraptor client monitoring](https://docs.velociraptor.app/docs/clients/monitoring/)
- [Wazuh Active Response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html)
- [Fleet GitOps YAML policies](https://fleetdm.com/docs/configuration/yaml-files)
- [osquery configuration and packs](https://osquery.readthedocs.io/en/5.12.1/deployment/configuration/)
- [Elastic detection-rules](https://github.com/elastic/detection-rules)
- [Velociraptor Artifact Exchange](https://docs.velociraptor.app/docs/artifacts/exchange_reference/)
- [MITRE ATT&CK version history](https://attack.mitre.org/resources/versions/)
- [ATT&CK Navigator layer 4.5](https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md)
- [OCSF 1.8 observables](https://raw.githubusercontent.com/ocsf/ocsf-schema/1.8.0/objects/observable.json)
- [Sigma rule specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
- [CISA AA25-239A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [NIST SP 800-207 Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)
- [MITRE ATT&CK T1070.001 Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)
- [Microsoft OpenSSH Server configuration for Windows](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration)
- [Microsoft Storm-2372 device-code phishing](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)
- [Microsoft Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [Microsoft Windows measured boot and health attestation](https://learn.microsoft.com/en-us/windows/security/operating-system-security/system-security/protect-high-value-assets-by-controlling-the-health-of-windows-10-based-devices)
- [IETF RFC 9334 RATS architecture](https://datatracker.ietf.org/doc/html/rfc9334)

These references guide actor-neutral defensive engineering and do not support
state or agency attribution.
