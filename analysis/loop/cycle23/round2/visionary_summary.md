# Cycle 23 Round 2 — Visionary Summary

Date: 2026-08-26  
Mode: actor-neutral defensive design; existing Round 1 primary-source research
only; no additional web research

## Outcome

Five candidates were reviewed and **none was selected for implementation** in
this round. The only design that closes R2-01 is a genuinely separate monotonic
authority. Building another service, receipt, HMAC file, registry value, or
database on the Angerona host would simulate independence without providing it.
The separately administered witness therefore remains **PROPOSED/DEFERRED**.

The obvious local correlation and telemetry-expectation variants also did not
clear the novelty bar. Angerona already has entity-scoped Evidence Lattice
fusion, the generic incident correlator, bounded telemetry expectation
contracts, and Canary Drill sensor-silence checks. A new wrapper over those
mechanisms would add alert duplication and false-positive risk without a new
trust boundary or independent evidence source.

## Candidate scorecard

Scores are 1–5. Higher is better for novelty, defensive value, suite fit, and
privacy; higher means more cost/risk for effort, false positives, and required
privilege.

| Candidate | Novelty | Value | Fit | Effort | FP risk | Privacy | Privilege | Round 2 disposition |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| Separately administered Personal Sentinel monotonic witness | 4 | 5 | 5 | 5 | 1 | 5 | 4 | **PROPOSED/DEFERRED** |
| Semantic control-plane sequence correlator | 2 | 3 | 3 | 2 | 4 | 5 | 1 | **PROPOSED, deprioritized as overlapping** |
| Ambient sensor-coverage SLA / negative-space monitor | 1 | 3 | 2 | 2 | 4 | 5 | 1 | **PROPOSED, deprioritized as redundant** |
| Resource-scoped gateway egress-assurance lease broker | 4 | 4 | 4 | 4 | 3 | 4 | 4 | **PROPOSED** |
| SSH authorized-key-to-session provenance receipt | 4 | 4 | 5 | 3 | 3 | 4 | 3 | **PROPOSED** |

## Proof against the current tree

- `core/independent_high_water.py` contains a strict `IndependentHighWater`
  protocol, but no production implementation. The only concrete
  `compare_and_advance()` behavior is a test fixture. The Personal Sentinel
  compact receipt is explicitly not promoted to this authority.
- `modules/evidence_lattice.py` already joins MEDIUM evidence about the same
  PID, path/hash, or IP across modules and sensor domains. `core/incidents.py`
  already groups alert activity by time. Another local sequence wrapper would
  not create independent evidence and could double-count existing alerts.
- `core/telemetry_contracts.py` already provides bounded deadline/echo
  expectations, and `modules/canary_drill.py` already reports prolonged sensor
  silence. Renaming those behaviors as an ambient SLA is not a novel control.
- The gateway client attests a route and pinned policy digest while retaining
  `endpoint_resources_trusted=False`; there is no resource/destination-bound
  assurance lease that online features can consume.
- SSH inventory retains authorized-key fingerprints and SSH log analysis
  retains privacy tokens for accounts/sources, but the reviewed tree has no
  strict provider-versioned join from one authenticated session to one enrolled
  key fingerprint.

## Highest-value design: independent monotonic witness

### Required architecture and trust boundary

```text
Angerona host state pair
  -> strict IndependentHighWater client
  -> pinned mTLS over the explicitly enrolled Personal Sentinel path
  -> separately administered witness appliance/service
  -> transactional per-installation, per-domain monotonic namespace
  -> authenticated current-head response
```

The witness must be on a separate device or service with separate
administration and durable backup custody. For the audit and network domains it
must atomically compare the prior revision, prior state digest, and prior head;
accept exactly the next revision; reject duplicate, behind, forked, cloned, or
installation-mismatched transitions; durably commit before acknowledging; and
return an authenticated head that Angerona validates on every load. A router or
service controlled by the same compromised Windows administrator is not
independent custody.

Only the existing privacy-minimal schema may cross the boundary: schema and
installation identifiers, domain, revision, exact state-pair digest, prior
state digest, and opaque prior/current heads. Raw event rows, network
identifiers, SSH paths or commands, credentials, and arbitrary payloads remain
local.

### Availability, recovery, and threat model

- Witness loss or an authenticated outage remains explicit
  `provisional-offline`; state cannot be called independently fresh or silently
  advanced.
- External-ahead/local-behind crashes enter recovery and never auto-rewind the
  witness. Backup restore, clone, migration, re-enrollment, witness loss, and
  device replacement require explicit authenticated policy.
- This detects local filesystem replay/fork under its trust assumptions. It
  does not prevent Administrator/SYSTEM denial, kernel or firmware compromise,
  theft of the enrolled device identity, TPM clearing, witness destruction, or
  compromise of the separately administered service.
- Firmware/secure-boot attestation for the Personal Sentinel remains a
  different hardware-dependent project and is not implied by an mTLS witness.

This design is not implemented because the checkout cannot establish or test
the necessary independent physical/administrative boundary, appliance
durability, device authentication, backup policy, or operational recovery.

## Other candidates and why they remain proposals

### Semantic control-plane sequence correlator

The attractive sequence is audit continuity loss or clear evidence followed by
SSH access-surface drift and network-route/DNS drift. It is actor-neutral and
privacy-friendly, but current events do not provide one consistent recovery
contract, and Angerona already has Evidence Lattice plus incident correlation.
Without a carefully versioned semantic schema and non-duplicating threat
disposition, a quick implementation could manufacture an extra active incident
from health events. A future experiment must first prove unique operator value
against those existing layers.

### Ambient sensor-coverage SLA / negative-space monitor

Telemetry Expectations and Canary Drill already cover bounded expected echoes
and prolonged sensor silence. A broader passive cadence monitor would need
per-sensor startup, sleep/resume, disabled-policy, Eco/Chill, recovery, and
platform contracts. Until those states are typed, it would mostly restate
existing module health with more false positives.

### Resource-scoped gateway egress-assurance lease broker

This would bind a short-lived, destination-class-specific permission to a fresh
Personal Sentinel route/policy attestation, then require online AI, updates, or
exports to present that lease. It fits NIST's resource-specific zero-trust
model better than treating a verified network location as trust. It remains
proposed because policy ownership, offline behavior, destination taxonomy,
privileged enforcement, revocation, and recovery require operator design and
cross-feature integration. A path lease must never make an endpoint, identity,
application, or destination implicitly trusted.

### SSH authorized-key-to-session provenance receipt

A versioned adapter could join fixed-provider OpenSSH authentication evidence
to the already inventoried authorized-key fingerprint and emit a privacy-safe
session provenance result. This could distinguish an enrolled key from an
unmapped or newly introduced key without retaining usernames or endpoints.
Windows OpenSSH provider/event variants and logging-level differences must be
authoritatively enumerated first; an ambiguous text match would create noisy or
misleading attribution, so no parser was added.

## Research basis

The design uses the already collected primary sources in
`analysis/loop/cycle23/innovation_ideas.md`: CISA AA25-239A and AA24-038A for
router/SSH persistence and audit suppression; the FBI/NSA router advisory and
NSA router-hygiene guidance for compromised network-path risk; NIST SP 800-207
for resource-specific zero trust; Microsoft OpenSSH configuration/logging
documentation; and MITRE ATT&CK T1070.001 for Windows event-log clearing. The
engineering inference is actor-neutral and does not claim agency attribution.

## Gate evidence

No product, test, configuration, asset, README, manual, or `llms.txt` file was
changed, so changed-file compile, lint, module self-test, headless selfcheck,
and focused regression gates are **not applicable** to this proposal-only
phase. The immediately preceding Round 2 Bug Test remains the frozen baseline:
321/321 package files compiled, direct and batch selfcheck passed 26/26, and the
complete suite passed 1,455 tests with five intentional host-capability skips
and zero failures. This phase makes no new claim beyond that evidence.

## Next experiments and honest limits

1. Specify a wire-level witness protocol and server state machine, then review
   it independently before selecting appliance hardware or a deployment model.
2. Build an isolated conformance harness that proves duplicate/fork/clone,
   external-first crash, backup restore, migration, outage, and re-enrollment
   behavior without representing the harness as independent production custody.
3. Measure whether a semantic control-plane sequence produces unique,
   actionable cases beyond Evidence Lattice, incidents, Telemetry Expectations,
   Canary Drill, and module health before considering an MVP.
4. Collect authoritative Windows OpenSSH event schemas across supported
   versions/logging modes before designing key-to-session provenance.

| Candidate | Novelty / value / effort | Final status |
|---|---|---|
| Separately administered monotonic witness | 4 / 5 / 5 | **PROPOSED/DEFERRED** |
| Semantic control-plane sequence correlator | 2 / 3 / 2 | **PROPOSED (deprioritized)** |
| Ambient sensor-coverage SLA | 1 / 3 / 2 | **PROPOSED (deprioritized)** |
| Resource-scoped gateway assurance lease | 4 / 4 / 4 | **PROPOSED** |
| SSH key-to-session provenance receipt | 4 / 4 / 3 | **PROPOSED** |

