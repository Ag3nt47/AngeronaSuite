# Angerona v1.12.1 — Cycles 26–30 consolidation

**Date:** 2026-08-29
**Scope:** five three-round, defensive-only hardening loops
**Release:** 1.12.1 (`READY_FOR_PUBLICATION`; guarded publication pending)

## Outcome

Cycles 26–30 expanded and re-audited every discovered built-in capability while
preserving Angerona's local-first, explicit-authority design. The work does not
claim that a user-mode research suite is immune to a privileged attacker. It
creates falsifiable evidence: exact identities, authenticated state transitions,
loss and freshness disclosure, bounded parsers and queues, inert hostile
regressions, and fail-closed response gates.

| Cycle | Main engineering result | Evidence |
| --- | --- | --- |
| 26 | Source and signer boundaries, object-bound scanning, truthful aggregation, resilience custody, and universal sub-100 health evidence with trusted file/line disclosure | 50 findings remediated across three rounds; `cycle26/` |
| 27 | Exhaustive 83-file/81-capability audit, assurance ledger, upstream comparison, repeated independent re-attacks, and Red Team Simulation custody repair | Sharded findings/remediations and independent gates under `cycle27/` |
| 28 | API-patch completeness, hardware-root truth, canonical endpoint/process identity, safe posture paths, and temporal-health custody | 30 focused tests in five `test_cycle28_*` files |
| 29 | Broad per-module upgrades for authenticated baselines, exact object/generation identity, delivery/loss accounting, liveness, typed authorization, forward secrecy, and bounded acquisition | 118 collected tests in 25 `test_cycle29_*` files |
| 30 | Cross-module cursor/CAS/receipt hardening, lifecycle and crash-delivery repair, unsafe legacy response retirement, and SentinelLens | 66 passed / 1 expected skip across 15 `test_cycle30_*` files; SentinelLens-focused 19/1 |

## Major user-facing additions

- Guided Auto Adapt combines audit, security-intent choices, exact preview,
  no-write simulation, and final approval. Incomplete collectors or a missing
  immutable firewall recovery baseline keep the operation proposal-only.
- Capability rows, status cells, event rows, and graph nodes are sortable or
  clickable where applicable. A capability below 100% shows its bounded reason,
  trusted repository-relative file, SHA-256 identity, exact line, and a red
  read-only source highlight when provenance is provable.
- SentinelLens's app-owned background service ingests bounded Syslog, Windows
  Event JSON/JSONL, NetFlow JSON/JSONL, and Angerona EventBus observations into
  an in-memory incident graph through a non-blocking queue with explicit loss
  health. Deterministic anomaly narratives are always available; an optional
  LLM explanation is restricted to a strict loopback local endpoint. Suggested
  remediation remains text-only and proposal-only.
- Red Team Simulation now binds readiness, mandatory-plan denominators, process
  generations, native detector receipts, marker object custody, and signed AAR
  display/action handoff. Its default comprehensive mode authenticates 38
  mandatory stages and 37 scored simulation contracts, including 24 additional
  fixed local markers across major ATT&CK tactics. Stage boxes open exact
  implementation/artifact evidence, while native analytic catches remain
  separate. Simulations do not execute the named behaviors or attempt real
  exploitation.

## Upstream and visionary comparison

The primary-source comparison in `cycle26/round1/upstream_project_comparison.md`
and `cycle27/round1/upstream_and_innovation.md` reviewed Wazuh, Velociraptor,
Fleet/osquery, Falco, Sysmon for Linux, OSV-Scanner, GitHub artifact
attestations, and newer defensive evidence standards. Angerona adopted bounded
patterns that fit a local product—explicit incomplete states, loss evidence,
typed response authority, authenticated content/state, and clickable
provenance—without claiming upstream deployment scale or importing arbitrary
query/command execution.

## Terminal verification

- Combined Cycle 26–30 focused gate: **819 passed / 6 expected platform skips /
  0 failed** across 93 files. Focused groups overlap and are not added to the
  full-suite total.
- Exact v1.12.1 serial gate: **2665 passed /
  13 intentional platform skips / 0 failed**.
- Python `compileall`, repository-wide Ruff, selfcheck **26/26**,
  workflow-policy validation, dependency audit, documentation-drift validation,
  and `git diff --check`: pass on the release tree.
- Public proof remains pending until the guarded publisher fast-forwards
  canonical `Ag3nt47/AngeronaSuite` `main` to the reviewed release commit and
  verifies every README image byte-for-byte. No user-mode defensive patch is a
  proof against every future or privileged attacker.
