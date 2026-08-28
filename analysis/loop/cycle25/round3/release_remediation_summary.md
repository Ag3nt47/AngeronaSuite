# Cycle 25 / Round 3 — Release remediation and closure

Date: 2026-08-28
Release: 1.12.0

## Operator workflow closure

- Guided Auto Adapt presents the closed Balanced, Public, and Emergency
  Lockdown choices; performs audit, completeness gate, immutable plan, and
  no-write simulation; and requires separate exact-plan confirmation for an
  optional apply.
- Baseline enrollment is explicit and cannot replace an existing recovery
  baseline. UI copy states that recovery covers complete Windows Firewall
  policy only. Every mutation also captures pre-change state and uses the HMAC
  transaction journal, exact verification, compensation, startup
  reconciliation, and circuit breaker.
- The safe automatic checkup audits once and simulates all profiles without
  writing. Context automation remains proposal-only.
- Capability Center, Module Inspector, adaptation tables, alerts, Live Defense,
  Context Info, CVE items, and governed paths provide bounded clickable detail
  and typed sorting. Background analysis is owned and bounded.

## Standards and integration closure

- The ATT&CK tracker uses the curated 15-tactic Enterprise 19.2 vocabulary and
  explicitly labels its scope. Navigator JSON declares 5.3.2 and layer 4.5.
- OCSF outputs use resolving typed observable/evidence paths under a constrained
  1.8 mapping with unmapped data kept explicit.
- Sigma support remains a deliberately limited evaluator. Unsupported semantics
  atomically refuse the complete batch with a bounded machine-readable receipt.
- IPC is documented as a protected-store authenticated loopback admission
  diagnostic. No production payload consumer or TPM-backed transport is claimed.

## Final performance closure

- Primary recorder handoff: **22.306 to 15.925 microseconds/event**, a measured
  **28.6%** median improvement.
- Capability summary projection: **43.324 to 1.508 microseconds/call**, a
  measured **96.5%** improvement.
- Unchanged Module Inspector tick: **13.458 to 0.474 milliseconds**, a measured
  **96.5%** improvement with no unchanged table rebuild.
- Batch durable commits, immutable compiled Sigma plans, and a global CVE
  detail-worker cap remain proposals.

No optimization lengthened a detector interval, cached a mutation-authorizing
host probe, weakened cryptography/completeness, or changed response authority.
