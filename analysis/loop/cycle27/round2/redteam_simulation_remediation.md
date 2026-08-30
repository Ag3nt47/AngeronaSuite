# Cycle 27 Round 2 — Red Team simulation remediation

Date: 2026-08-28
Scope: inert local marker/process simulation only. No exploit, persistence,
network attack, destructive action, credential access, or publication was run.

## Outcome

The reproducible 12/13 miss condition is closed at the launch and reporting
boundaries. Both GUI launch paths now refuse to create marker one unless the
exact built-in Purple Guard is live on the intended target, has consumed a
fresh 13-contract cycle, and has persisted an authenticated readiness sentinel
through the same EventBus/flight recorder used by the AAR. A stopped Purple
Guard is temporarily started for the explicitly requested drill and restored
without changing the operator's saved module preference.

The AAR no longer treats raw INFO telemetry, simulator/console/orchestration
announcements, or failed/successful response-module rows as analytic detector
credit. It reports four independent evidence planes:

- raw sensor observation;
- native analytic detection;
- Purple Guard simulation-contract validation; and
- successful correlated response.

Simulation validation is explicitly labelled as an inert pipeline canary, not
real-attack, exploit, state-actor, breach-prevention, or native behavioral
coverage.

The independent re-attack reopened five authority bypasses in the first repair.
This second hardening pass closes those bypasses rather than treating the happy
path as sufficient: recorder readiness now proves the exact open canonical
SQLite descriptor and a cryptographically verified persisted echo; the engine
consumes a fresh, expiring, one-use live lease bound to the immutable target;
and production AAR scoring requires both recorder authentication and an
unforgeable run-scoped receipt from the exact registered detector object.

## Finding closure

| Finding | Status | Closure |
|---|---|---|
| RTS-01 | Closed | Atomic validation lease proves exact module, root, target, health, fresh cycle, and recorder echo before launch. |
| RTS-02 | Closed | Detection readiness is acquired regardless of Auto-contain; that toggle authorizes response only. |
| RTS-03 | Closed | Production AAR accepts authenticated stored detector evidence only and rejects self/response/raw-INFO analytic credit. |
| RTS-04 | Closed | Observation, native analytics, simulation validation, and response are separate in text and JSON. |
| RTS-05 | Closed | Target-watch errors and false engine starts abort without polling or stale AAR; evidence holds and leases are restored. |
| RTS-06 | Closed | Custom probes are informational without a complete explicit contract; filenames contain no operator label and cannot collide with standard marker tokens. |
| RTS-07 | Closed | Purple's tagged-process subscriber retains exact nonce events independently of general EventBus floods. |
| RTS-08 | Closed | AAR reads its passed live recorder or `<data_dir>/flight-recorder.db`, never an ambient Config ledger. |
| RTS-09 | Closed | Readiness, report text, and JSON state the canary limitations and preserve native efficacy as a separate rate. |

### Independent re-attack closure

| Finding | Status | Closure |
|---|---|---|
| RTS-R01 | Closed | Exact `FlightRecorder`, canonical `<data_root>/flight-recorder.db`, live SQLite descriptor/file identity, exact shared bus authority, strictly advancing revision, and authenticated persisted nonce are mandatory. The persistence proof invokes the built-in recorder/bus/authority class methods, so instance-method replacements cannot substitute ring contents. Ring-only, foreign-root, closed, wrong-authority, and instance-spoofed recorders fail closed. |
| RTS-R02 | Closed | A gate-issued lease has a read-only target and is short-lived, live-state checked, exact-target/root bound, single-use, HMAC-bound to one run ID, and revoked by release, runtime-target removal, policy change, sensor restart, manager/module replacement, or recorder loss. The engine never rewrites `bound_target`. |
| RTS-R03 | Closed | `generate_aar` rejects structural/foreign recorders, reads through the exact built-in recorder method, and cryptographically verifies every stored event with the bound authority/bus class implementations; writable instance verifier replacements cannot grant trust. |
| RTS-R04 | Closed | Native credit requires a run-scoped receipt issued while the exact registered built-in detector object emits; Purple credit requires the exact live Purple instance, policy/technique, generation, target, and observed-evidence receipt. Producer-name spoofing fails. |
| RTS-R05 | Closed | Both `event_type` and `evidence_type` use the same raw-telemetry taxonomy; process/network/file/ETW/sensor observations cannot become native analytics at MEDIUM/HIGH severity. |

Post-lease UI refresh no longer attempts to rescore ledger rows. It reloads the
persisted Red Team text only after the attested JSON proves the report kind,
basename, run ID, and exact text SHA-256.

## Acceptance evidence

`tests/test_cycle27_redteam_simulation_repair.py` proves:

- raw INFO, simulator self-credit, and failed response rows cannot count as
  analytic detection;
- native, Purple, observation, and response evidence remain independently
  attributed;
- custom `lsass_dump_T1003` labels cannot impersonate T1003 and remain N/A;
- readiness is bound to the run ID/target inside HMAC-signed history;
- a custom-target run resets to the immutable default sandbox afterward;
- two recorder roots cannot cross-credit evidence;
- both GUI launch paths acquire readiness and honor the engine start boolean;
  and
- a safe end-to-end campaign produces 13/13 Purple pipeline validations while
  reporting 0/13 native analytics when no native detector alert was supplied.
- target mismatch, release/replay, policy drift, sensor restart, overlapping
  leases, ring-only/foreign/closed/wrong-authority recorders, fake HMACs,
  structural fake recorders, producer spoofing, and all raw telemetry shapes
  fail closed; and
- post-lease refresh loads only the authenticated persisted report and detects
  text tampering without opening a recorder or re-evaluating coverage.

Latest gates: **29/29 dedicated trust-boundary tests**, **54/54 core Red Team
compatibility tests**, **49/49 Purple/practice/lifecycle tests**, and headless
self-check **26/26** (module runner: **65 passed, 0 failed, 17 expected skips**).
Compilation, Ruff, and `git diff --check` passed for the changed product/test
files. ATT&CK heatmap response coverage now excludes proposal-only
`disable_driver_service` claims for T1543.003/T1068.
