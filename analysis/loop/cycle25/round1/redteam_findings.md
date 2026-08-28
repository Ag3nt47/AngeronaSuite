# Cycle 25 / Round 1 — Adversarial findings

Date: 2026-08-27
Product target: 1.12.0
Mode: defensive secure-code review with benign local fixtures

## Scope and scoring note

The Round 1 adversary pass inspected every discovered built-in capability plus
the shared lifecycle, event, settings, response, adaptation, integration, and
GUI boundaries. It recorded twelve traceable risk/reliability lineages. The
pass did not retain a contemporaneous CVSS ledger, so this reconstruction does
not invent severity scores. Statuses are reconciled against the merged code and
the independent Round 2/3 QA evidence.

## Findings

| ID | Finding | Final disposition |
| --- | --- | --- |
| C25-R1-01 | Module metadata was not uniformly machine-readable, so callers could not distinguish an explicit capability declaration from a legacy default. | **Fixed.** All 80 discovered capabilities receive a validated v12 contract. Five are native declarations; 75 are visibly labeled compatibility adapters with metadata gaps. |
| C25-R1-02 | Host Adaptation needed one guided workflow, immutable accepted choices, and a recovery prerequisite before any firewall mutation. | **Fixed.** Auto Adapt performs audit, completeness gating, immutable planning, no-write simulation, and optional separate exact-plan confirmation. Context automation is proposal-only. |
| C25-R1-03 | A replaceable or implicit “baseline” could create false recovery confidence. | **Fixed within declared scope.** Baseline enrollment is explicit, authenticated, host-bound, non-replaceable, and limited to the complete Windows Firewall policy that Host Adaptation can mutate. It is not whole-host rollback. |
| C25-R1-04 | AI- or observation-derived recommendations could be confused with response authority. | **Fixed.** Evolution, mitigation tuning, contextual adaptation, and unapproved behavioral learning remain inert proposals. Judgment bypass receipts are typed, HMAC-authenticated, and single-use. |
| C25-R1-05 | Process, driver, and firewall remediation needed exact identities, verified postconditions, and compensating rollback. | **Fixed.** Process actions bind PID, creation time, executable/name and immediate revalidation; driver and direction-specific firewall actions verify return codes and exact restored state. Ambiguous ACL mutation was removed from production actions. |
| C25-R1-06 | Behavioral learning could silently turn untrusted observations or changed content into suppression authority. | **Fixed.** Learning epochs, explicit approval logs, exact SHA-256 approval, and compare-and-swap drift proposals separate observation from approved policy. High/Critical candidates are not learned into suppression. |
| C25-R1-07 | Self-integrity hashing did not cover every callable semantic that could change behavior. | **Fixed.** Integrity now covers the full marshalled code object plus defaults, keyword defaults, closures, and bounded canonical extra values. |
| C25-R1-08 | Persistence checks could report success when evidence was partial, unknown, truncated, or not reviewed. | **Fixed.** Results use typed COMPLETE/PARTIAL/UNKNOWN states, bounded tasks and registry/WMI reads, strict error propagation, exact Winlogon parsing, and review-first startup disposition. |
| C25-R1-09 | IPC secret custody and product wording overstated a local loopback diagnostic path. | **Fixed.** The key is held in the operating-system protected store with exact legacy plaintext migration/removal and fail-closed unavailability. The feature is labeled an authenticated diagnostic admission preview, not a production payload consumer or TPM-backed channel. |
| C25-R1-10 | SIEM/Remote delivery could lose selected events across saturation, restart, or transport-key rotation. | **Fixed with residuals.** Durable outboxes, revision cursors, drain-stage-drain ordering, mutable-state HMACs, and a queue key independent of transport rotation protect normal crash/restart paths. At-least-once duplicates and unwitnessed whole-database rollback remain explicit. |
| C25-R1-11 | ATT&CK, Navigator, OCSF, and Sigma labels could imply broader standards compatibility than implemented. | **Fixed.** The catalog and export versions are pinned; OCSF and Sigma are explicitly constrained subsets, and Sigma admission is atomic with machine-readable acceptance/refusal receipts. |
| C25-R1-12 | Important tables, event rows, paths, and “live thinking” surfaces needed bounded, truthful, clickable evidence instead of decorative or blocking UI behavior. | **Fixed.** Capability/module, adaptation, alert, Live Defense, Context Info, CVE, and SOAR surfaces gained typed sorting, bounded detail views, governed paths, worker ownership/backpressure, and truthful fingerprint/authenticity labels. |

## Adversarial boundaries retained

- User-mode evidence cannot remain authoritative after Administrator, SYSTEM,
  kernel, firmware, protected-store, or trusted-producer compromise.
- The host recovery baseline restores complete Windows Firewall policy only.
- Durable outbox HMACs do not independently witness row deletion or a rollback
  of the entire SQLite database and its local state.
- Transport-key rotation coordination still uses restart epochs; delivery is
  at least once and can duplicate after a crash.
- OCSF 1.8 and Sigma support are constrained structural/subset contracts, not
  complete upstream implementations.
- IPC Guard is local admission diagnostics, not an application protocol,
  remote-management channel, or hardware-backed transport.

Machine-readable traceability is in [redteam_findings.json](redteam_findings.json),
and the final cross-round disposition is in
[../prior_findings.md](../prior_findings.md).
