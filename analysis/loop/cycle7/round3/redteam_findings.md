# Cycle 7 / Round 3 — Red-Team Findings

See `adversarial_verification.md` in this directory for the complete re-challenge
matrix and proof results.

## C7-R3-01 — Observe-only remote evidence can still mutate local detection policy

- **Severity:** MEDIUM
- **Component:** `src/angerona/modules/remote_bridge.py:411-449`;
  `src/angerona/core/eventbus.py:75-91`;
  `src/angerona/modules/evolution_engine.py:157-171,334-384`;
  `src/angerona/modules/yara_scanner.py:99-132`
- **Status:** FIXED IN ROUND 3

Remote Bridge correctly labels authenticated peer telemetry as observe-only and
strips receiver-local PID/path action keys. Evolution Engine nevertheless trusts
peer-controlled `verified="SUCCESS"` and `technique` fields, then can run local
AI/verification work and persist/replace the active generated YARA rule. A safe
stub proof observed `activate("T1059")` from one observe-only remote event.

**Recommendation:** make remote origin an immutable Event field, default-deny it
for every mutating consumer, and require a typed, local, run/technique-bound
Posture Hardening receipt before Evolution may change a rule.

**Closure:** `EvolutionEngine._on_bus_event()` now rejects receiver-owned
observe-only events before examining peer-supplied receipt fields. The added
authenticated-peer-equivalent regression proves the forged receipt produces
zero activations; the complete Remote Bridge security file passes 4/4. Moving
authority from transport-owned bounded details to an immutable Event field
remains useful defense in depth, but no identified remote mutation path remains.

## Severity summary

| Severity | New findings |
|---|---:|
| Critical | 0 |
| High | 0 |
| Medium | 1 |
| Low | 0 |
| Info | 0 |

Prior C7-R1 reconciliation after in-loop remediation: **6 resolved / 0 open**.
