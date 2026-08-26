# Cycle 23 Round 3 — Visionary Summary

Date: 2026-08-26  
Mode: final convergence review; actor-neutral, defensive-only, and based solely
on the primary-source research collected in Round 1

## Outcome

The final tree does not justify another local MVP. **No candidate was selected
for implementation.** Round 3 fixed R3-01 with explicit privacy-safe
`network.path_added` evidence, authenticated provisional pending-path custody,
restart-safe comparison, and unchanged-path promotion. That removes the one
remaining reason to build another local topology-reconciliation layer.

The strategic ranking otherwise remains stable. A separately administered
monotonic witness is still the highest-value missing capability and remains
**PROPOSED/DEFERRED** because independence cannot be supplied by another
same-host component. Resource-scoped egress assurance and SSH key-to-session
provenance remain promising designs, but both require policy or authoritative
event contracts beyond a safe final-round patch. Local correlation and ambient
telemetry wrappers remain low-novelty duplicates of controls already present.

## Candidate scorecard

Scores are 1–5. Higher is better for novelty, defensive value, suite fit, and
privacy; higher means more cost/risk for effort, false positives, and required
privilege.

| Candidate | Novelty | Value | Fit | Effort | FP risk | Privacy | Privilege | Round 3 disposition |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| Separately administered Personal Sentinel monotonic witness | 4 | 5 | 5 | 5 | 1 | 5 | 4 | **PROPOSED/DEFERRED** |
| Resource-scoped gateway egress-assurance lease broker | 4 | 4 | 4 | 4 | 3 | 4 | 4 | **PROPOSED** |
| SSH authorized-key-to-session provenance receipt | 4 | 4 | 5 | 3 | 3 | 4 | 3 | **PROPOSED** |
| Personal Sentinel measured-boot / firmware-policy attestation | 4 | 4 | 3 | 5 | 2 | 5 | 5 | **PROPOSED/DEFERRED** |
| Local semantic correlation / ambient health fusion wrapper | 1 | 2 | 2 | 2 | 4 | 5 | 1 | **PROPOSED, deprioritized as redundant** |

## Effect of R3-01 on the ranking

R3-01 previously exposed a restart boundary for newly observed physical paths.
The final implementation now gives a new path an explicit finding, persists a
bounded tokenized pending set as authenticated provisional state, requires the
path to remain active and unchanged before promotion, and refuses advancement
on other drift, incomplete evidence, freshness loss, persistence failure, or
bounded-history eviction. Consequently:

- a proposed local topology-reconciliation module is no longer novel or useful;
- the resource-scoped egress lease remains a distinct policy/enforcement idea,
  not a replacement for baseline reconciliation;
- the external witness remains necessary because authenticated local state is
  still replayable without independently administered monotonic custody; and
- no candidate's external trust or hardware prerequisites were reduced.

## Candidate decisions and architecture boundaries

### 1. Separately administered monotonic witness — highest value, deferred

The required flow remains:

```text
authenticated audit/network state pair
  -> strict IndependentHighWater client
  -> explicitly enrolled, pinned mTLS path
  -> separately administered witness appliance/service
  -> durable per-installation and per-domain monotonic CAS namespace
  -> authenticated current-head response
```

The witness must run on a separate device or service with different
administrative and backup custody. It must atomically bind the installation,
domain, prior revision, prior state digest, prior head, next revision, and next
state-pair digest; reject duplicates, rollback, forks, clones, and mismatches;
durably commit before acknowledging; and return an authenticated head. A local
HMAC/DPAPI file, registry value, database, loopback server, Personal Sentinel
compact receipt, or in-memory fixture does not meet this boundary.

Only privacy-minimal identifiers, revisions, SHA-256 digests, and opaque heads
may cross the boundary. Raw event rows, network identifiers, SSH evidence,
paths, commands, credentials, and arbitrary payloads remain local. Outage stays
explicitly provisional and non-advancing. Restore, migration, clone,
re-enrollment, external-ahead crash, witness loss, and device replacement need
authenticated operator policy. This design detects replay under its stated
custody assumptions; it cannot prevent Administrator/SYSTEM denial, kernel or
firmware compromise, device-identity theft, witness destruction, or compromise
of the external service.

### 2. Resource-scoped gateway egress-assurance lease — proposed

A short-lived lease could bind a specific destination class and purpose—such as
model fallback, update retrieval, or evidence export—to a fresh Personal
Sentinel route/policy attestation. Consumers would verify the lease without
turning network location into implicit endpoint, identity, application, or
resource trust. It remains proposal-only because destination taxonomy,
operator policy, offline behavior, revocation, process binding, privileged
enforcement, and recovery cross several established egress paths. Shipping a
partial broker in the final round would risk availability failures or a false
trust claim.

### 3. SSH key-to-session provenance receipt — proposed

The current SSH guard inventories authorized-key fingerprints and separately
tokenizes authentication sources/accounts. A strict adapter could join one
fixed-provider authentication record to one enrolled public-key fingerprint
and report enrolled, newly introduced, or unmapped provenance without retaining
raw users/endpoints. Supported Windows OpenSSH provider versions, event IDs,
logging modes, field schemas, and downgrade behavior must be authoritatively
enumerated first. A rendered-text heuristic would be too ambiguous for this
claim, so no parser was added.

### 4. Personal Sentinel measured-boot / firmware-policy attestation — deferred

A future supported appliance could bind its attestation response to a hardware
root of trust, signed boot measurements, installed firmware identity, and the
active firewall/policy digest. This could improve confidence that the
intermediate gateway itself has not been silently replaced or downgraded. It
requires specific hardware, measured-boot semantics, vendor update and key
rotation policy, rollback protection, recovery, and independent validation.
mTLS and a policy digest alone do not constitute firmware attestation, so the
current client must not imply it.

### 5. Local semantic correlation / ambient health fusion — deprioritized

Evidence Lattice already fuses independent entity-scoped evidence; the incident
correlator groups alert activity; Telemetry Expectations validates bounded
echoes; Canary Drill detects prolonged sensor silence; and each module exposes
health. R3-01 also adds the missing typed path-addition transition. Another
local wrapper would create no independent sensor or trust boundary and could
double-count health as attack evidence. It remains worth reconsidering only if
measured cases prove unique operator value and a versioned recovery/disposition
contract prevents duplicate threat escalation.

## Research and safety basis

The Round 1 primary sources remain the basis: CISA AA25-239A and AA24-038A for
router/SSH persistence and audit suppression; FBI/NSA and NSA router guidance
for compromised routing, DNS, and DHCP paths; NIST SP 800-207 for
resource-specific zero trust; Microsoft OpenSSH configuration and logging
documentation; and MITRE ATT&CK T1070.001 for Windows event-log clearing. The
candidate designs are engineering inferences, remain actor-neutral, and make no
agency attribution claim.

No candidate introduces offensive execution, secret collection, cloud
dependency, hidden egress, destructive response, router management, firmware
mutation, or automatic execution of AI output. No same-host component is
represented as independent custody.

## Gate evidence

This phase changed no product, test, configuration, asset, README, Word manual,
or `llms.txt` file, so changed-file compile, lint, module self-test, headless
selfcheck, and focused regression gates are **not applicable**. The final
pre-visionary QA baseline remains:

- package compile: **321/321**;
- direct and batch selfcheck: **26/26** each;
- standalone core/Shark self-tests: **22/22**;
- focused Cycle 23/R3 gate: **155 passed, 2 expected skips, 0 failed**;
- complete serial pytest: **1,460 passed, 5 intentional host-capability skips,
  0 failed** across 1,465 tests and 208 files;
- final network performance gate: **36 passed**, Ruff PASS, and both affected
  self-tests PASS.

No new claim is made beyond that frozen evidence.

## Next experiments and honest limits

1. Specify and independently review the witness wire protocol, server state
   machine, storage durability, device enrollment, backup, and recovery policy
   before choosing appliance hardware.
2. Run an isolated witness conformance harness for rollback, fork, clone,
   outage, external-first crash, restore, migration, and re-enrollment, while
   labeling the harness as a test—not independent production custody.
3. Inventory every existing online egress consumer and policy owner before
   designing resource-scoped assurance leases.
4. Collect authoritative OpenSSH authentication schemas across supported
   Windows versions and logging modes before attempting key-to-session joins.
5. Treat firmware attestation as a hardware release project with signed-update,
   key-rotation, recovery, and third-party validation gates.

| Candidate | Novelty / value / effort | Final status |
|---|---|---|
| Separately administered monotonic witness | 4 / 5 / 5 | **PROPOSED/DEFERRED** |
| Resource-scoped gateway assurance lease | 4 / 4 / 4 | **PROPOSED** |
| SSH key-to-session provenance receipt | 4 / 4 / 3 | **PROPOSED** |
| Personal Sentinel measured-boot / firmware attestation | 4 / 4 / 5 | **PROPOSED/DEFERRED** |
| Local semantic correlation / ambient health fusion | 1 / 2 / 2 | **PROPOSED (deprioritized)** |

