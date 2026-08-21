# Cycle 19 — Passes 22–23: Visionary / Enterprise Research

**Date:** 2026-08-21  
**Scope:** defensive-only, local-first Windows/macOS/Linux EDR/NDR/SOAR  
**Status:** design proposals only — none of the capabilities below is claimed as implemented

## Executive recommendation

Angerona already has unusually broad local foundations: normalized sensor events,
bounded asynchronous evidence ingestion, a causal graph, HMAC-authenticated local
IPC, signed detection packages, a Sigma subset, an OCSF finding mapper, fleet
identity/policy primitives, supervised recovery, and privacy-governed exports.
The next enterprise step is therefore not more dashboard modules. It is to turn
those foundations into small, independently verifiable trust domains.

The highest-value sequence is:

1. ship native least-privilege sensors without giving the GUI kernel privilege;
2. prove sensor visibility and policy/update authenticity continuously;
3. add bounded multi-event detection contracts and standards-versioned evidence;
4. only then expand fleet rollout and third-party extensibility.

## Ranked shortlist

Scores are relative, 1–5. Ranking is by expected defensive impact divided by
implementation effort, with safety and architectural fit used as tie-breakers.

| Rank | Proposal | Impact | Effort | Main fit |
| ---: | --- | ---: | --- | --- |
| 1 | Cross-platform sensor-health attestations | 5 | S–M | Harden / Detect |
| 2 | Detection Contract v3: ATT&CK v19.2 + Sigma 2.1 | 5 | M | Detect / Visualize |
| 3 | Local behavioral baseline with drift quarantine | 5 | M | Detect / Harden |
| 4 | Versioned OCSF 1.8 + ECS evidence spine | 4 | M | Visualize / Interoperate |
| 5 | TUF client update metadata + Sigstore verification | 5 | M–L | Harden |
| 6 | OS-native least-privilege sensor plane | 5 | L | Detect / Respond |
| 7 | Evidence provenance graph and counterfactual incident view | 4 | M–L | Detect / Visualize |
| 8 | Crash-only, OS-owned resilience supervisor | 4 | M–L | Harden |
| 9 | Capability-based WASM extension host | 4 | L | Harden / Detect |
| 10 | Fleet policy rings with short-lived workload identity | 5 | L | Harden / Respond |

---

## 1. Cross-platform sensor-health attestations

**Pitch:** make “sensor alive, current, and seeing the expected stream” a signed,
continuously verified claim instead of inferring protection from process liveness.

**Why now.** MITRE ATT&CK v19.2 includes a new defensive strategy for Exploitation
for Defense Impairment that explicitly correlates security-product interaction
with service crashes, extension unloads, telemetry gaps, and tamper-state changes.
Microsoft also documents that real-time ETW consumers can lose events when they
cannot keep up, so a running process is not proof of complete visibility.

Sources:

- [MITRE ATT&CK DET0900 — Detection of Defense Impairment](https://attack.mitre.org/detectionstrategies/DET0900/)
- [Microsoft — About Event Tracing: missing events and session statistics](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing)

**Architecture.** Extend `core/telemetry_contracts.py`,
`core/telemetry_coverage.py`, `core/evidence_claims.py`, and
`resilience/recovery_state.py` with a platform-neutral `VisibilityAttestation`:
sensor build digest, boot/session epoch, last sequence, expected-vs-observed
canary family, drop counters, clock quality, policy digest, and expiry. Native
helpers sign the bounded claim; the existing normalized event boundary verifies
it. The dashboard reports `healthy`, `degraded`, `blind`, or `untrusted`, never a
binary “running.” This is **Harden + Detect + Visualize**.

**Implementation gate.** Property-test replay, sequence gaps, forged counters,
clock rollback, sleep/resume, buffer overflow, sensor upgrade, and stale policy.
A missing/expired attestation must reduce posture without creating an infinite
alert storm. No raw telemetry belongs in the claim.

**Risk/dependencies.** Requires a distinct signing key per native helper and safe
rotation. Process-held keys do not prove resistance to a fully compromised peer;
TPM/Secure Enclave binding is a later optional strengthening.

**Safety.** Defensive telemetry-integrity verification only. It cannot suppress,
disable, probe, or exploit another security product.

## 2. Detection Contract v3: ATT&CK v19.2 + Sigma 2.1

**Pitch:** evolve the current single-event Sigma subset into a bounded,
standards-pinned correlation engine that can express real behavior chains across
Windows, macOS, and Linux.

**Why now.** ATT&CK replaced technique-level detection text with Detection
Strategies, platform-specific Analytics, and revised Data Components in v18;
v19.2 is current. Sigma 2.1 formalizes `event_count`, `value_count`, `temporal`,
and `temporal_ordered` correlations, grouping, aliases, time windows, filters,
and chained correlations.

Sources:

- [MITRE — ATT&CK October 2025 defensive model changes](https://attack.mitre.org/resources/updates/updates-october-2025/)
- [MITRE — ATT&CK current version history](https://attack.mitre.org/resources/versions/)
- [Sigma 2.1 correlation-rules specification](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html)

**Architecture.** Add versioned ATT&CK objects and field-mapping contracts to
`core/detection_registry.py` and `core/detection_packages.py`. Extend
`core/sigma_engine.py` only with a deliberately bounded subset: the four core
correlation types, fixed maximum window, fixed entity cardinality, monotonic
time, bounded per-rule state, explicit aliases, and deterministic eviction.
Emit matched evidence references into `core/causal_incident_graph.py`; never
embed raw source events in rule state. This is **Detect + Visualize**.

**Implementation gate.** Pin exact ATT&CK and Sigma schema versions; validate
packages before activation; publish compatibility errors; golden-test Windows,
macOS, and Linux fixtures; fuzz YAML/schema/correlation state; prove per-rule
CPU/memory limits and deterministic results. Unsupported Sigma constructs must
fail closed, not silently approximate.

**Risk/dependencies.** Correlation can amplify false positives and become a
memory/CPU denial-of-service surface. Chained, percentile, average, and arbitrary
backend conversion should remain out of scope until resource proofs exist.

**Safety.** Detection content is declarative and non-executable. It may create
reviewable response proposals but cannot invoke a shell or perform offensive
emulation.

## 3. Local behavioral baseline with drift quarantine

**Pitch:** learn a privacy-minimized model of normal executable relationships and
network behavior locally, while treating novelty as evidence—not automatic guilt.

**Why now.** MITRE's current Analytics are explicitly behavior-chain and
platform-specific; examples correlate rare processes, unexpected destinations,
account context, and temporal order. Microsoft's App Control guidance likewise
uses audit/evaluation before enforcement and emphasizes code identity rather
than filename reputation alone.

Sources:

- [MITRE ATT&CK — platform-specific Analytics](https://attack.mitre.org/analytics/)
- [Microsoft — Application Control for Windows](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol)

**Architecture.** Evolve `core/process_baseline.py`,
`core/network_behavior.py`, `core/executable_trust.py`, and `core/cortex.py` into
a shared local baseline keyed by privacy-preserving executable identity:
publisher/team ID/package signature + file digest + canonical install-zone
token. Learn bounded parent-child edges, destination categories, schedule bands,
and privilege transitions. New observations enter a `learning`, `stable`,
`drifted`, or `revoked` state. Only multi-signal convergence raises severity;
the existing supervised allowlist remains the explicit trust authority. This is
**Detect + Harden**.

**Implementation gate.** Thirty-day synthetic/recorded-fixture backtests,
poisoning tests, clean software-update migration, maximum-entity caps, decay,
explainable feature contribution, and one-click reset/export. Baselines must be
local by default and exclude command lines, document names, usernames, and raw
destinations unless the operator explicitly enables a higher-privacy tier.

**Risk/dependencies.** Baseline poisoning, concept drift, shared-device ambiguity,
and alert fatigue. Never auto-trust based on frequency, basename, install age, or
model output. Keep deterministic rules as the authoritative fast path.

**Safety.** Observation and supervised defensive tuning only. The model cannot
execute, block, or remediate without the existing response authorization path.

## 4. Versioned OCSF 1.8 + ECS evidence spine

**Pitch:** make one normalized, provenance-bearing Angerona event map
deterministically to both OCSF and ECS without leaking host-specific raw fields.

**Why now.** OCSF 1.8 was released in March 2026, while ECS 9.4 defines stable
source-independent categorization through `event.kind`, `event.category`,
`event.type`, and `event.outcome`. Angerona currently exports only a narrow OCSF
Detection Finding shape, so its internal schema cannot yet prove interoperability
or round-trip loss.

Sources:

- [OCSF schema official releases — v1.8.0](https://github.com/ocsf/ocsf-schema/releases)
- [Elastic Common Schema 9.4 reference](https://www.elastic.co/docs/reference/ecs)
- [ECS categorization fields](https://www.elastic.co/guide/en/ecs/current/ecs-category-field-values-reference.html)

**Architecture.** Introduce a versioned mapping registry adjacent to
`core/sensor_events.py` and `core/ocsf_export.py`. Cover process, file, network,
authentication, finding, device inventory, and sensor-health classes; add a
separate ECS adapter in `core/interop_gateway.py`. Preserve source schema version,
mapping version, evidence digest, redaction policy, clock quality, and omitted-
field reasons. `event.original` must remain absent from public/fleet export. This
is **Visualize + Interoperate + Harden**.

**Implementation gate.** Vendor schema fixtures, JSON-schema validation, golden
round-trip tests, unknown-field preservation only inside bounded local evidence,
and privacy snapshots for every export tier. CI must fail when a schema upgrade
changes required mappings or semantic meaning.

**Risk/dependencies.** Mapping one taxonomy to another can create false semantic
precision. Preserve `unknown` instead of inventing values; never claim complete
OCSF/ECS conformance until official validators pass.

**Safety.** Export is consent-gated and privacy-minimized. This proposal adds no
collection and no outbound destination.

## 5. TUF client update metadata + Sigstore verification

**Pitch:** turn current checksums and GitHub attestations into a client-enforced
update policy resistant to rollback, freeze, mix-and-match, and signing-key loss.

**Why now.** TUF 1.0.35 specifies threshold roles, versioned metadata, expiry,
consistent snapshots, and rollback/freeze defenses. Sigstore binds short-lived
certificates to OIDC identities and records signing events in Rekor. SLSA 1.1
distinguishes the existence of provenance from signed and hardened builds.

Sources:

- [The Update Framework specification 1.0.35](https://github.com/theupdateframework/specification/blob/master/tuf-spec.md)
- [Sigstore — keyless signing overview](https://docs.sigstore.dev/cosign/signing/overview/)
- [SLSA 1.1 build levels](https://slsa.dev/spec/v1.1/levels)

**Architecture.** Extend `core/release_integrity.py`,
`core/release_assurance.py`, and the updater with an offline-pinned TUF root;
separate root/targets/snapshot/timestamp roles; threshold root rotation; delegated
targets by OS/architecture/channel; expiry and minimum-version policy; and
atomic verified activation/rollback. Verify a Sigstore bundle and expected
GitHub workflow identity as an additional provenance requirement, not a
replacement for TUF. Apply the same target metadata to detection packages and
optional native helpers. This is **Harden**.

**Implementation gate.** Air-gapped bootstrap ceremony; two-person root-key
rotation; expired/frozen/mixed repository fixtures; compromised online targets
key exercise; interrupted update and disk-full recovery; downgrade refusal;
explicit emergency rollback with an audited operator override.

**Risk/dependencies.** Operational key custody is the hard part. Incorrect expiry
or clock assumptions can strand offline users. Maintain an offline/manual release
path, but never silently bypass metadata verification.

**Safety.** Only authenticated defensive software/content is installed. Update
metadata cannot carry generic commands or executable remediation scripts.

## 6. OS-native least-privilege sensor plane

**Pitch:** add production-grade native telemetry and narrowly scoped response
without ever running the Qt GUI, local AI, or general Python runtime as root.

**Why now.** Linux libbpf CO-RE uses BTF relocations to make one compiled BPF
object portable across kernel configurations without shipping a runtime compiler.
Apple Endpoint Security provides subscribed NOTIFY/AUTH events and Network
Extension content filters can pass/block flows inside a privacy-restrictive
sandbox. eBPF for Windows exposes familiar libbpf APIs and selected Windows hooks,
but calls itself work-in-progress; ETW remains the stable efficient kernel-level
tracing path.

Sources:

- [Linux kernel — libbpf CO-RE overview](https://www.kernel.org/doc/html/latest/bpf/libbpf/libbpf_overview.html)
- [Apple — Endpoint Security client](https://developer.apple.com/documentation/endpointsecurity/client)
- [Apple — privacy-separated content filter providers](https://developer.apple.com/documentation/networkextension/content-filter-providers)
- [Microsoft — eBPF for Windows](https://microsoft.github.io/ebpf-for-windows/)
- [Microsoft — Event Tracing for Windows](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing)

**Architecture.** One small signed Rust/Swift/C helper per OS emits only
`SensorEvent` and `VisibilityAttestation` frames over the existing authenticated
native boundary. Linux: libbpf skeleton with tracepoint/LSM/cgroup hooks selected
by capability and a tiny root-owned loader that drops privilege. macOS: signed,
notarized Endpoint Security system extension in NOTIFY-first mode; a separate
Network Extension data provider for reviewed flow verdicts. Windows: ETW/WFP are
the production default; evaluate eBPF-for-Windows only for supported network
hooks behind a capability flag. The Response Broker remains the sole action
authority. This is **Detect + Respond + Harden**.

**Implementation gate.** Independent threat model and audit for each helper;
driver/system-extension signing; kernel/OS compatibility matrix; verifier-failure
tests; queue backpressure; safe unload; boot, upgrade, sleep/resume, VPN, full-disk,
and lost-GUI tests. macOS AUTH or network blocking remains disabled until latency,
timeout, entitlement, and recovery proofs pass. Linux must never load arbitrary
operator-supplied BPF bytecode.

**Risk/dependencies.** Kernel hooks increase blast radius and release burden.
Apple entitlements and Developer ID/notarization are external gates. Linux BTF/
LSM capabilities vary. eBPF-for-Windows is not a replacement for stable ETW/WFP.

**Safety.** Defensive visibility and reviewed containment only. No stealth,
credential access, exploit primitives, arbitrary packet mutation, or offensive
kernel capability is in scope.

## 7. Evidence provenance graph and counterfactual incident view

**Pitch:** let an analyst see not only “what correlated,” but which immutable
evidence caused each conclusion and what conclusion would remain if a noisy
signal were removed.

**Why now.** ATT&CK's current Detection Strategies organize multiple
platform-specific Analytics into cohesive methodologies rather than isolated
alerts. OCSF's expanding schema provides a stable interoperability vocabulary,
but provenance and causal confidence still need an Angerona-owned evidence
contract.

Sources:

- [MITRE ATT&CK — Detection Strategies](https://attack.mitre.org/detectionstrategies/)
- [OCSF official schema repository and releases](https://github.com/ocsf/ocsf-schema/releases)

**Architecture.** Extend `core/causal_incident_graph.py`, `core/evidence_store.py`,
and `core/evidence_claims.py` with typed nodes (`observation`, `analytic-match`,
`correlation`, `decision`, `action`, `verification`) and typed edges
(`derived-from`, `same-entity`, `precedes`, `corroborates`, `contradicts`). Each
node stores only content-addressed references and mapping/rule versions. A
bounded counterfactual query recomputes score/coverage after excluding selected
claims without mutating evidence. This is **Detect + Visualize + Audit**.

**Implementation gate.** Acyclic derivation subgraph, maximum nodes/edges/depth,
deterministic traversal, tenant scoping, custody verification, redacted exports,
and tests proving that deleted/expired evidence changes confidence without
rewriting history. Graph layout must remain off the Qt thread.

**Risk/dependencies.** Correlation is not causation. UI wording must distinguish
observed, inferred, contradicted, and verified. Avoid graph explosion and
identity linkage that could expose personal behavior.

**Safety.** Read-only defensive explanation. Counterfactual analysis cannot
trigger actions or generate attack steps.

## 8. Crash-only, OS-owned resilience supervisor

**Pitch:** make core recovery an operating-system service contract with bounded
restart budgets, health handshakes, and deterministic safe mode—not a collection
of mutually respawning desktop processes.

**Why now.** Windows Service Control Manager supports delayed failure actions;
systemd supplies restart/watchdog controls; launchd is designed to own service
lifecycle and may suppress jobs that crash repeatedly. These mechanisms are more
authoritative than sibling processes attempting to revive one another.

Sources:

- [Microsoft — service failure actions](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w)
- [systemd.service manual](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
- [Apple — creating launchd jobs](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)

**Architecture.** Keep `resilience/recovery_state.py` as the durable authenticated
state machine but make a single OS-owned sensor service authoritative. The GUI is
optional and never a restart dependency. Add startup generation IDs, readiness
handshake, watchdog ping, clean-stop token, exponential backoff with jitter,
sliding crash budget, safe-mode reason, last-known-good build/policy digest, and
manual recovery receipt. Use Windows SCM, a hardened systemd service, and
launchd/XPC; retire peer-to-peer respawn once migration is proven. This is
**Harden + Availability**.

**Implementation gate.** Fault-injection matrix: early crash, hung event loop,
deadlocked sensor, corrupted recovery state, sleep/resume, update-in-progress,
full disk, locked key store, and intentional Stop. Require 24-hour storm and
multi-day soak evidence before enabling by default.

**Risk/dependencies.** A bad restart policy can create boot loops or undo an
operator Stop. Windows protected-service status requires special signing and
must not be claimed. launchd `KeepAlive` must be conditional to avoid the prior
reopen loop class.

**Safety.** Availability only. The supervisor starts exact allowlisted binaries
and cannot run arbitrary commands, download code, or defeat operator shutdown.

## 9. Capability-based WASM extension host

**Pitch:** replace general-purpose third-party Python execution with portable,
resource-metered detection extensions that receive only explicitly granted data
and host calls.

**Why now.** Wasmtime documents WebAssembly memory isolation and WASI's
capability-based filesystem model, but a February 2026 advisory also shows why
embedders must explicitly cap guest resources and host-call payloads. A sandbox
is useful only when it is patched, metered, and separated from the broker.

Sources:

- [Wasmtime — security and capability-based WASI access](https://docs.wasmtime.dev/security.html)
- [Wasmtime 2026 guest resource-exhaustion advisory](https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-852m-cvvp-9p4w)

**Architecture.** Add a separate, low-privilege extension-host process beside
`core/plugin_lifecycle.py`. Signed WASM components receive bounded normalized
events and can return findings/proposals through typed WIT interfaces. Grant no
filesystem, environment, clock, randomness, or network by default; add explicit
read-only capabilities only when a signed manifest requires them. Apply fuel,
epoch deadlines, memory/table/handle counts, response-size caps, and one-instance
failure isolation. Keep `ResponseBroker` out of the guest address space. This is
**Harden + Detect**.

**Implementation gate.** Pin a patched Wasmtime LTS/release; adversarial WASM
corpus; host-call fuzzing; no-network verification; symlink/path escape tests;
fuel/memory/handle exhaustion; kill-and-recover; publisher revocation; exact
reproducible SDK and WIT version. Existing signed Python plugins remain a
developer-only compatibility path during migration.

**Risk/dependencies.** Runtime vulnerabilities, JIT attack surface, ABI churn,
and false confidence in sandboxing. Prefer AOT where practical and run the host
under OS process restrictions as defense in depth.

**Safety.** Guest APIs are read-only detection APIs. No shell, process creation,
arbitrary file/network access, kernel loading, or direct response authority.

## 10. Fleet policy rings with short-lived workload identity

**Pitch:** promote the loopback fleet preview into an optional, authenticated
policy plane with staged rollout and rapid revocation, while standalone local
operation remains the default.

**Why now.** SPIFFE 1.15.2 defines a stable platform-neutral Workload API with
short-lived X.509/JWT identities, rotating trust bundles, and federation across
trust domains. TUF provides the complementary signed metadata needed to prevent
rollback and freeze of policy/content.

Sources:

- [SPIFFE Workload API v1.15.2](https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/)
- [SPIFFE federation specification](https://spiffe.io/docs/latest/spiffe-specs/spiffe_federation/)
- [The Update Framework specification](https://github.com/theupdateframework/specification/blob/master/tuf-spec.md)

**Architecture.** Extend `core/endpoint_identity.py`, `core/fleet_credentials.py`,
`core/policy_bundle.py`, and `core/fleet_service.py` behind an explicit fleet
edition flag. Accept short-lived X.509-SVID identity from an external SPIRE
deployment or an equivalent reviewed local issuer; keep current HMAC credentials
for single-host mode. Policy targets are TUF-versioned, tenant-scoped, and rolled
through `lab -> canary -> cohort -> broad` rings with health gates, automatic
pause, signed approval, expiry, and last-known-good rollback. No generic command
route. This is **Harden + Respond + Fleet**.

**Implementation gate.** Production mTLS; issuer/trust-bundle rotation; revoked
device tests; tenant-isolation review; offline endpoint behavior; partial rollout;
rollback/freeze/replay fixtures; quorum/approval separation; regional HA/DR and
external penetration test. Prove standalone mode has zero listener and zero
fleet egress.

**Risk/dependencies.** This is operationally the largest proposal. SPIFFE assumes
workload isolation strong enough to protect issued credentials; Angerona must not
claim that merely installing an agent creates that isolation. An enterprise
deployment also needs administrators, PKI/key ceremony, backups, monitoring,
and incident ownership outside this repository.

**Safety.** Policy distributes defensive configuration and signed detection
content only. It cannot provide remote shell, arbitrary code execution, covert
collection, or unreviewed containment.

---

## Delivery gates and sequencing

### Phase A — local trust closure (S–M)

- Visibility attestations and explicit degraded/blind posture.
- ATT&CK v19.2 registry and bounded Sigma 2.1 correlation subset.
- Privacy-minimized local baseline with poisoning/drift tests.
- OCSF/ECS versioned mappings and validation fixtures.

### Phase B — release and native trust (M–L)

- TUF client metadata verification and offline root ceremony.
- Native Linux/macOS/Windows sensor-helper prototypes behind capability flags.
- OS-owned supervision and multi-day fault/soak evidence.
- Developer ID/notarization, Windows publisher signing, and signed Linux packages.

### Phase C — ecosystem and fleet (L)

- WASM extension host only after the native and update trust boundaries exist.
- Fleet rings only after mTLS/workload identity, tenant isolation, external
  penetration testing, and HA/DR exercises are operationally owned.

## Deliberate non-proposals

- No new offensive framework, exploit runner, credential dumper, persistence
  mechanism, EDR bypass, arbitrary packet injector, or stealth component.
- No autonomous AI remediation. Local AI can explain and draft; typed policy and
  human authorization remain authoritative.
- No claim that eBPF, Endpoint Security, Network Extension, WASM, SPIFFE, TUF, or
  Sigma 2.1 is shipped merely because an architecture proposal exists.
- No recommendation to run the GUI or model runtime as Administrator/root.
- No cloud telemetry requirement; fleet and interoperability remain optional.

## Research conclusion

The fastest credible path to enterprise capability is **proof before breadth**:
prove visibility, provenance, policy version, schema meaning, and recovery state
at every boundary. The “revolutionary” part is not another detector; it is an
endpoint that can explain exactly what it saw, what it missed, why it decided,
which signed content caused the decision, and whether that claim survives a
sensor crash, update rollback, or compromised extension—without exporting the
user's private activity.
