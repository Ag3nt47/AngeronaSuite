# Cycle 24 — Defense-in-depth and independent-trust hardening

Date: 2026-08-27
Product version: 1.11.0
Mode: actor-neutral, defensive-only research and engineering

## Outcome

Cycle 24 extends Angerona from individual state-grade-pattern detections toward
explicit trust-boundary contracts. The working tree now separates EventBus
record integrity from sensor identity, local authenticity from independent
freshness, observe-only posture from enforcement, public first-install trust
from post-start verification, and AI context from action authority.

The most visible additions are:

- nine additional Windows-discovered defensive modules, bringing static
  platform discovery to **80 Windows / 14 Linux / 13 macOS**;
- a sanitized Live Defense Activity card and four reproducible public
  screenshots;
- ARIA Defense Memory v1.1.0 with 18 canonical-digest-pinned entries;
- authenticated producer, sequence, loss, and consumer-schema contracts;
- ordered SSH/path/log and identity/session analytics;
- driver, platform-attestation, peripheral/DMA, immutable-recovery, process-
  egress, RAG-provenance, and release-transparency guards;
- a separately operated Personal Sentinel reference authority/server for mTLS,
  Ed25519 receipts, trusted time, and monotonic compare-and-swap evidence; and
- an OS-validated signed MSIX public first-install contract plus threshold and
  rollback verification for protected upgrades.

Research and detections remain actor-neutral. Shared SSH, valid-account,
network-device, log-suppression, identity, recovery, driver, peripheral, and
supply-chain techniques cannot prove a state, agency, sponsor, or individual.

## Security design delivered

### Authenticated sensor continuity

`SensorProvenanceBroker` gives enrolled producers distinct credentials and
strict bounded schemas. It tracks exact sequence/replay/loss state and can
apply consumer-specific producer, event-type, and schema constraints before
continuity advances. Temporal, identity, and SSH consumers no longer promote
generic EventBus storage integrity into producer identity.

SSH live evidence is accepted only from the broker-assigned
`OpenSSH Auth Event Collector`, with exact channel/provider/message fields and
loss-aware continuity. Wrong-schema events cannot invisibly consume the trusted
sequence. The guard still never reads credentials/private keys, connects to a
listener, creates a tunnel, or retains/publishes full commands or raw endpoints.

### Event-log and recovery assurance

Audit Log Integrity Guard continues to detect observed clear/tamper identities,
policy/service changes, continuity and generation gaps, record reuse, and
authenticated cursor damage without mutating the log.

Recovery assurance now rejects excessive future timestamps and satisfies
copy/failure-domain/signer/posture/restore requirements within one exact
expected revision/archive/manifest cohort. Directory enumeration and no-follow
stable reads have explicit budgets. The guard verifies externally supplied
evidence; it does not restore data or recreate events deleted before collection.

### Network zero trust and Personal Sentinel

All physical Wi-Fi/Ethernet paths remain untrusted until exact enrolled
evidence passes. The existing direct-HTTPS gateway client binds certificate,
hostname, leaf pin, nonce/freshness, policy digest, optional mTLS, complete
IPv4/IPv6 route evidence, and unchanged pre/post context.

The new reference authority/server adds:

- mandatory production mTLS;
- separate client request and authority response/state key roles;
- Ed25519 verification-only receipt custody on the monitored host;
- bounded pre-authentication and authenticated worker capacity;
- signed state, OS singleton lease, durable response floors, and optional
  external generation floor;
- trusted-time and high-water compare-and-swap domains; and
- admission drain plus irreversible close before lease release.

This is supplied reference code, not a turnkey router/appliance or managed
service. It performs no router discovery/configuration, credential storage,
route/firewall mutation, remote command, or firmware trust. Operators must
deploy it independently for its receipts to represent an independent failure
domain.

### Least privilege and observe-only posture

- Response capability tokens now persist epoch/high-water state so ordinary
  restart cannot revive a consumed authority token.
- Process Egress Lease Broker can bind short-lived policy to exact process
  birth, executable, user, destination, route/path, and budget. The shipped
  guard observes its authenticated audit stream. A separately privileged
  connection-admission adapter is still required for enforcement.
- Driver Provenance Guard makes bounded overflow explicit and evaluates
  visible image hash, Authenticode/catalog, blocklist, HVCI, and Secure Boot
  evidence. It cannot unload/delete/quarantine a driver.
- Platform Attestation Guard reports local boot posture and hardware
  attestation only with an injected nonce-bound quote verifier.
- Peripheral and DMA Posture Guard evaluates local Kernel DMA/IOMMU,
  Thunderbolt, USB4, removable, and device-install posture without device
  control or firmware claims.
- Identity Session Guard consumes structured authenticated evidence; it does
  not collect credentials, browser tokens, or tenant sessions.
- RAG Provenance Guard validates configured future sources and emits inert
  trust/taint labels without mutating an index or Defense Memory.

### Release authorization and rollback policy

The public Windows first-install contract is now a signed full-trust x64 MSIX.
Windows validates the block map and exact configured package publisher before
activation. The build requires protected publisher identity/certificate inputs
and pinned Windows SDK tooling. The repository does not claim Microsoft Store
deployment, enterprise policy provisioning, or clean-VM acceptance.

Classic Inno Setup is non-public and prior-approved-install migration-only. It
performs unelevated preflight and delegates UAC/mutation to the protected
installed updater; it is not a public release asset or first-install trust
bootstrap.

Portable ZIP installation is upgrade-only. An installed native verifier checks
the exact staged payload, catalog/manifest, software inventory and provenance,
threshold authorization, enrolled roots, access-control custody, and protected
numeric version/sequence floor before mutation.

Threshold signer responses no longer carry public keys. Each signer must match
a separately enrolled root, and finalization requires the exact canonical 2-of-2
root policy at a protected SHA-256. A local ACL-protected floor still cannot
defeat privileged whole-host snapshot rollback; TPM-backed or independently
witnessed monotonic state is required for that threat.

### ARIA and public activity

Defense Memory v1.1.0 has 18 capability, use, control, limit, and actor-neutral
tradecraft entries. Stable non-reparse bounded reads, strict duplicate-free
schema validation, text/structure budgets, and canonical digest
`sha256:97a7771a9ce38ac66c6889dc90e0d591b64e07c2f169a0cebd7a57c119d67d57`
gate admission. It defines no tool/action. Local retrieval can use admitted
entries; an already authorized cloud fallback can receive at most one
highest-ranked canonical excerpt after bounded redaction.

Live Defense Activity requests at most 16 public EventBus records and displays
at most five sanitized summaries plus coarse module state. It never reads raw
details, source/executing code, private model reasoning, or chain-of-thought.

## Three-round security disposition

| Round | Audit outcome | Current disposition |
| --- | --- | --- |
| 1 | Ten defects plus one informational runtime/deployment boundary: 1 High, 7 Medium, 2 Low, 1 Info | The first remediation pass fixed capability replay, Sentinel cryptographic roles/locking/TLS/time, recovery cohorting, driver overflow, and temporal/identity provenance. Release trust and runtime-integration boundaries were carried into Round 2. |
| 2 | Seven re-audited issues/residuals: 1 High, 3 Medium, 3 Low | All seven received code remediation and focused regressions. First-install publisher trust, external root custody, and privileged whole-host rollback remain deployment/hardware boundaries, not repository-created guarantees. |
| 3 | Final re-audit found 1 High, 1 Medium, and 2 Low issues: public classic-Setup exposure, incomplete Windows ACL custody, multi-controller Thunderbolt reduction, and documentation drift. | All four were fixed. Bounded enumeration/read, deterministic Sentinel shutdown, pre-continuity SSH schema validation, exact public artifact selection, complete custody, least-protective peripheral reduction, and reproducible screenshots are regression-gated. |

Round totals overlap because Round 2 deliberately revisited Round 1 lineages.
See [prior_findings.md](prior_findings.md) for the exact current disposition and
inherited residuals.

## Focused verification

- Round 2 release remediation: **20 passed**.
- Round 2 core remediation: **88 passed, 1 expected platform skip**.
- Round 3 sensor/SSH/peripheral/recovery/Sentinel reliability paths: **78
  passed, 1 expected platform skip**.
- Round 3 release-boundary remediation: **29 passed**; every workflow
  PowerShell block and both repository release scripts parsed; exact publication
  and installation-contract gates passed.
- Fresh combined high-risk recheck: **111 passed, 1 expected platform skip**.
- Changed-file Ruff and Python compile gates: recorded clean.
- Release workflow YAML, MSIX XML, and embedded/repository PowerShell parsing:
  recorded clean.
- Paired complete gallery capture: eight successful images total, byte-identical
  across the two four-image runs.
- Final converged serial suite: **1,675 collected across 229 files; 1,670
  passed; 5 expected host-capability skips; 0 failed**.

Focused test groups overlap and are not summed. They do not replace a final
serial suite or clean-machine publisher/install validation.

## Performance and reliability

| Change | Measured result | Security behavior |
| --- | ---: | --- |
| Canonical Personal Sentinel unsigned-state reuse | 30.2-39.0% lower measured serialization/signing kernel CPU across 64-4,096 nonces | Signatures, generation, external floor, fsync, atomic replace, and error behavior unchanged. |
| Identity replay membership index | 410.488 us to 0.060 us at the artificial 4,096-event bound | Ordered deque remains authoritative; duplicate and eviction semantics unchanged. |
| Bounded over-limit iteration | 0.0242 ms vs 3.3220 ms for a synthetic 100,000-row source | Consumes exactly limit+1 and fails incomplete; no evidence is silently dropped as healthy. |
| Consumer-constrained provenance | +4.060 us/event in a synthetic 5,000-event benchmark | Fixed producer/type/schema checks occur before continuity mutation. |
| Public gallery capture | Two byte-identical four-image runs | Synthetic data and real GUI surfaces retained; timing variance removed. |

No optimization reduced polling cadence, freshness, cryptographic validation,
stable reads, completeness, or response authority.

## Deployment and architectural residuals

- Public MSIX release requires provisioned publisher identity, certificate
  chain/trust policy, protected release environments, and clean-VM validation.
- Threshold roots and policy must stay outside repository-controlled signer
  responses. Key recovery/rotation and reviewer policy are operator duties.
- Local HMAC/signature/ACL floors do not defeat privileged whole-host rollback.
  TPM or independent monotonic custody is required when that threat is in scope.
- Broker keys, Sentinel state, trusted-time floors, and recovery authorities
  must reside outside a restorable monitored-host snapshot to claim
  independence.
- Personal Sentinel is not a router appliance, routing role, router credential
  store, firewall manager, remote command channel, or firmware attestor.
- Process-egress enforcement adapter, real TPM quote provider/verifier, and
  authoritative cloud identity/session collectors are not shipped.
- Event-log controls cannot reconstruct records deleted before collection.
- In-process admitted-extension authority (A-04), broad legacy PowerShell policy
  surface (A-06), and the preferred retained OS process/executable-file lease
  through path-wide firewall mutation (R6-03) remain visible architectural
  residuals.
- Angerona is user-mode and cannot guarantee truth after Administrator, SYSTEM,
  kernel, firmware, or trusted-authority compromise.

## Highest-value next defensive work

The Round 1 innovation review ranked the following next steps:

1. ATT&CK v19 Detection Strategy/Analytic/Data Component conformance.
2. Authoritative local identity and interactive-access provenance.
3. Privacy-preserving ClickFix/user-intent chain detection.
4. SSH key-to-session provenance and cryptographic-agility posture.
5. Loaded-module/DLL provenance graph.
6. First-hop Wi-Fi/IPv6 attestation improvements.
7. Separately privileged enforcement for process-bound egress leases.
8. WSL/Hyper-V boundary visibility.
9. Peripheral arrival and out-of-band context.
10. Independent Personal Sentinel/TPM witness deployment.

These remain defensive proposals unless their code and tests are present. They
do not authorize credential collection, exploitation, Wi-Fi injection, SSH
login/probing, DLL planting, DMA attempts, firmware mutation, remote scanning,
or hack-back.

## Primary research sources

- CISA, AA25-239A, network-device persistence and off-host logging:
  https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a
- CISA, AA24-038A, critical-infrastructure tradecraft:
  https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf
- NIST SP 800-207, Zero Trust Architecture:
  https://csrc.nist.gov/pubs/sp/800/207/final
- MITRE ATT&CK T1070.001, Clear Windows Event Logs:
  https://attack.mitre.org/techniques/T1070/001/
- Microsoft, OpenSSH Server configuration for Windows:
  https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration
- Microsoft, Storm-2372 device-code phishing:
  https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/
- Microsoft, Kernel DMA Protection:
  https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt
- Microsoft, Windows measured boot and health attestation:
  https://learn.microsoft.com/en-us/windows/security/operating-system-security/system-security/protect-high-value-assets-by-controlling-the-health-of-windows-10-based-devices
- IETF RFC 9334, RATS architecture:
  https://datatracker.ietf.org/doc/html/rfc9334
- NIST FIPS 203, ML-KEM:
  https://csrc.nist.gov/pubs/fips/203/final

These sources support defensive technique selection. Angerona's control design
is an engineering inference and not an attribution claim.
