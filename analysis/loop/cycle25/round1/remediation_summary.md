# Cycle 25 / Round 1 — Remediation summary

Date: 2026-08-27
Product target: 1.12.0

## Outcome

Round 1 established the v12 safety and truth contracts. Work that required
concurrency, crash-recovery, UI, or standards-specific closure was carried into
Rounds 2 and 3 and is reconciled in the cycle summary.

### Capability and lifecycle truth

- Added a validated machine-readable capability contract with independent
  product and implementation versions, explicit supported platforms, mode,
  permissions, inputs/outputs, egress, retention, response authority,
  dependencies, self-test, resource budget, restart policy, loss behavior, and
  visible metadata gaps.
- Applied the contract to all 80 discovered built-ins. The release inventory
  records five native contracts and 75 compatibility adapters; it does not
  relabel legacy modules as native v12 implementations.
- Added common operational snapshots for lifecycle generation, freshness,
  thread liveness, loss/overflow, throttle, last work, and event revisions.

### Governed adaptation and recovery

- Added Guided Auto Adapt with closed Balanced, Public, and Emergency Lockdown
  choices; an audit/completeness gate; immutable plan construction; and no-write
  simulation before an optional, separately confirmed apply.
- Made contextual automation proposal-only and migrated legacy/tampered
  `auto_apply` state to false.
- Added explicit, authenticated, host-bound and non-replaceable recovery
  baseline enrollment. Apply refuses before mutation without a complete
  baseline. The baseline is scoped to complete Windows Firewall policy, which
  is the only state Host Adaptation mutates.
- Added per-apply snapshots, an HMAC transaction journal, exact postcondition
  checks, startup reconciliation, compensating rollback, and a mutation circuit
  breaker.

### Authority and module hardening

- Made evolution and mitigation output proposal-only; model-generated YARA is
  no longer activated on the live rule path.
- Bound behavioral approval to exact SHA-256 content and review epochs; hash
  drift returns to pending review instead of silently updating trusted policy.
- Strengthened process, driver, and firewall response identity, return-code,
  verification, and rollback contracts. Ambiguous ACL lockdown is not a
  production automatic action.
- Expanded self-integrity, persistence completeness, and protected-store IPC
  key migration/removal without creating new response authority.

## Verification handoff

Round 1 changes entered the focused v12 regression families for capability
contracts, host adaptation, behavioral tuning, evolution, IPC, persistence,
remediation, and self-integrity. Round 2 exercised durability and lifecycle
failure paths; Round 3 ran independent full-package QA.
