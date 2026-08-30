# Cycle 27 Round 2 — Red Team Simulation Independent Re-attack

Date: 2026-08-28
Disposition: **REOPENED**
Scope: isolated benign markers, synthetic authenticated events, temporary SQLite ledgers, and in-process boundary doubles only. No host control, persistence, network attack, credential access, or destructive action was attempted.

## Executive result

The repair fixes the original presentation error on the honest path, but its readiness and evidence trust boundaries can still be bypassed.

- Original 13-technique reproduction after the repair, with all 13 policies present, Purple Guard stopped, and Process Monitor observations only: **0/13 analytic catches, 13/13 misses, 13/13 raw observations**. This is the correct non-inflated result; raw telemetry is no longer called detection.
- Gated end-to-end focused test: **13/13 simulation-contract validations, 0/13 native analytics**. The report explicitly calls those results pipeline canaries rather than real-attack coverage.
- Adversarial trust-boundary result: **REOPENED** because a non-persistent recorder, a foreign-root recorder, a mismatched or replayed readiness receipt, a structural fake AAR recorder, and producer-name spoofing all gained authority they did not prove.

The repaired happy path is materially better, but it is not yet safe to claim that Red Team Simulation is fail-closed under the requested replay, recorder, target, and fake-producer attacks.

## Gates run

| Gate | Result |
|---|---:|
| Focused Red Team/Purple/runtime/remediation suite | 72 passed, 0 failed in 13.59 s |
| Package compile under `src/angerona` | 352/352 passed |
| Ruff on those files and the two Cycle 27 repair tests | passed |
| `PurpleGuard.self_test()` | passed |
| `red_team.self_test()` | passed |
| Module self-test runner | 65 passed, 0 failed, 17 expected skips |
| Headless `tools/selfcheck.py` | 25 passed, 1 failed |
| 1,000-event INFO-flood regression | passed within the focused suite |
| Complete benign 13-canary campaign | passed within the focused suite |

Focused test files included the Cycle 27 readiness and simulation repair suites plus runtime-target, practice-provenance, Purple remediation, drill lifecycle, and Red Team fix-pipeline coverage.

The sole headless selfcheck failure was outside this Red Team repair: ATT&CK coverage entry `T1543.003` still claimed the now-removed `disable_driver_service` action, so the coverage-to-action cross-check at `tools/selfcheck.py:584` failed. This was reported to the owning C04 remediation stream and was not changed during this read-only re-attack.

## Independent attack matrix

| Attack/check | Expected | Observed | Result |
|---|---|---|---|
| 13 policies + stopped Purple Guard + raw Process Monitor observations | observations only; no analytic credit | 13 observed, 0 native, 0 Purple, 0 caught, 13 missed | CLOSED |
| Authenticated raw INFO | observation only | observed; no native/Purple/catch/response | CLOSED |
| Simulator/self/orchestration event, even CRITICAL | no detector credit | no observation or catch | CLOSED |
| Failed response only | no detector or response credit | no observation/catch/remediation | CLOSED |
| Successful response without detector trigger | no detector or response credit | no observation/catch/remediation | CLOSED |
| Invalid stored HMAC | integrity failure, no credit | one integrity failure, no catch | CLOSED |
| Custom marker containing built-in-looking tokens | informational and non-colliding | rejected by classifier; no catch in focused test | CLOSED |
| Fake/subclass Purple Guard in manager | reject | rejected by exact type gate | CLOSED |
| Built-in Purple Guard bound to wrong data root | reject | rejected | CLOSED |
| Ring-only recorder that reflects the EventBus but persists nothing | reject | readiness lease acquired; revision stayed 0 -> 0; no DB existed | **REOPENED** |
| Real recorder whose database is under a foreign data root | reject | readiness lease acquired | **REOPENED** |
| Lease for target A used to start engine against target B | reject | engine accepted; signed history rewrote `bound_target` to B while original `target` remained A | **REOPENED** |
| Released readiness receipt replayed after Purple Guard stopped | reject | second run accepted; new history HMAC verified; old recorder nonce reused | **REOPENED** |
| Structural fake AAR recorder returning an arbitrary nonempty `hmac_sig` | reject | 1/1 native catch credited | **REOPENED** |
| Authenticated MEDIUM event from an unregistered detector name | observation only/reject | 1/1 native catch credited | **REOPENED** |
| Authenticated event spoofing the Purple Guard module name and fields | reject | 1/1 simulation validation credited | **REOPENED** |
| MEDIUM raw telemetry tagged through `event_type` | observation only | native catch credited | **REOPENED** |

## Reopened findings

### RTS-R01 — Recorder readiness proves an echo shape, not durable root-bound storage (HIGH)

`_wait_for_recorder_echo()` accepts any object with `revision()` and `recent_in_window()`. It does not require the canonical `FlightRecorder`, bind its database path to the supplied data root, or require `revision_after > revision_before`.

Two independent bypasses succeeded:

1. A ring-only double returned the freshly signed EventBus sentinel from memory. No SQLite database existed and its revision stayed `0 -> 0`, yet `acquire_redteam_validation_lease()` returned success.
2. A real `FlightRecorder` rooted under a different temporary directory also returned success for the intended root.

Relevant boundaries: `src/angerona/modules/purple_guard.py:655`, `:674`, `:706`, and `:717`.

Required remediation: accept only the exact canonical recorder instance/type used by the manager, require its resolved database path to equal `<data_root>/flight-recorder.db`, bind the bus authority/recorder authority, and require a strictly advancing committed revision containing the exact verified nonce. The readiness receipt should record a stable recorder identity/digest without exposing secrets.

### RTS-R02 — Readiness receipt is caller data that the engine re-signs, rebinds, and replays (HIGH)

`RedTeamEngine.start()` deep-copies any supplied dictionary, then overwrites `bound_run_id` and `bound_target`. It does not verify an issuer signature, acquisition target, sensor generation, policy digest, expiry, active lease, nonce consumption, or single-use state.

Observed bypasses:

- A receipt acquired for target A started a run against target B. The resulting history passed HMAC verification because the engine signed the altered caller data.
- After the lease was released and Purple Guard was stopped, the same receipt and recorder nonce started a second run and was embedded in another validly signed history.

This means the run-history HMAC protects the replayed claim from later tampering; it does not prove the claim was fresh or authorized.

Relevant boundaries: `src/angerona/shark/red_team.py:338`, `:393`, `:401`, `:402`, and `:426`.

Required remediation: issue an authenticated, immutable, short-lived, single-use receipt from the readiness gate; bind it before issuance to exact target, data root, recorder identity, bus authority identity, module object/generation, policy digest, cycle serial, and an unguessable receipt ID; atomically consume it in `start()`; reject target mismatch rather than rewriting it; invalidate it on lease release, module stop/restart, policy change/loss, or recorder loss.

### RTS-R03 — Production AAR accepts structural recorders and does not cryptographically verify returned events (HIGH)

`generate_aar()` accepts any object exposing `events_in_window()`. `_trusted_stored_event()` treats a nonempty `hmac_sig` plus absence of `_ledger_integrity` as authenticated; it does not verify that HMAC against the bound recorder authority.

A structural fake recorder returned one event with `hmac_sig="not-a-real-hmac"`; the generated production AAR credited **1/1 native detection**. A real recorder from a foreign root also produced **1/1 native detection** for the requested root.

Relevant boundaries: `src/angerona/shark/aar_report.py:165`, `:984`, `:1018`, and `:1027`.

Required remediation: type- and path-bind the recorder, require the expected manager-owned instance for GUI calls, verify every returned event cryptographically with the exact bound authority even after storage decoding, and fail closed if the recorder identity/root/authority does not match the history/readiness receipt.

### RTS-R04 — Detector credit trusts producer strings and severity rather than an authenticated capability identity (HIGH)

The EventBus HMAC authenticates event contents, but not which module object actually emitted the claimed `module` string. `_is_native_analytic()` accepts any non-excluded MEDIUM-or-higher event that exactly matches a step, even from an unregistered name and without an explicit positive detector contract. `_is_purple_validation()` likewise trusts the string `Purple Remediation Guard` plus public detail values.

Observed bypasses:

- `Totally Unregistered Detector`, MEDIUM, exact path, no positive verdict: **1/1 native credit**.
- A caller-created event named `Purple Remediation Guard` with public `mitre`/`detector_policy` fields: **1/1 simulation-validation credit**.

Relevant boundaries: `src/angerona/shark/aar_report.py:211` and `:222`.

Required remediation: bind evidence to a manager-issued producer/capability identity and run-scoped detector receipt, not a free-text module name. For native credit require either a registered detector capability plus its declared positive-evidence contract or an explicit positive verdict whose producer identity is validated. For Purple credit require the active lease ID, run ID, target digest, sensor generation/cycle, and policy digest on the event and receipt.

### RTS-R05 — Raw telemetry classification is inconsistent across `event_type` and `evidence_type` (MEDIUM)

Raw INFO is correctly observation-only. However, a MEDIUM event with `event_type="process_creation"` or `event_type="raw_telemetry"` and no positive verdict is treated as a native analytic catch because `_is_native_analytic()` checks raw values only in `evidence_type`.

Required remediation: normalize both fields through one evidence taxonomy and require an explicit positive analytic verdict for raw sensor event types. Add regression cases for MEDIUM/HIGH raw process, network, file, ETW, and generic sensor observations.

## Checks that remained closed

- Both unified and legacy GUI paths acquire readiness before starting Red Team, independent of Auto-remediate, and inspect the engine start boolean.
- Registration/start failures clear pending AAR state and release the lease in the inspected paths; no stale AAR is scheduled by those failures.
- The intended data root and explicitly supplied recorder are selected rather than ambient `Config` state. The remaining defect is failure to prove that the supplied recorder belongs to that root.
- Raw INFO, simulator/self/orchestration, failed response, and response-only evidence receive no analytic or response credit.
- The JSON/text report separates raw observation, native analytic detection, simulation-contract validation, and successful response, and warns that simulation validation is not real-attack coverage.
- Invalid ledger HMACs are converted to integrity failures and receive no credit when read through the real recorder.
- The dedicated process queue retains T1059 evidence through a 1,000-event INFO flood.
- Custom probes remain informational and their generated filenames cannot collide with built-in Purple patterns.
- Exact built-in Purple Guard type and its data-root binding are enforced.
- The legitimate happy path temporarily starts a stopped Purple Guard, validates all 13 canaries, and restores the prior stopped state and runtime target.

## Closure criteria for the next re-attack

The repair should remain open until all five reopened findings have regression tests and an independent rerun proves:

1. ring-only, foreign-root, closed/stale, and structurally fake recorders are rejected;
2. recorder revision must advance and the exact event must be cryptographically verified from the committed root-bound ledger;
3. receipts are authenticated, exact-target-bound, expiring, single-use, active-lease-bound, and invalidated by release/generation/policy/recorder changes;
4. fake producer names and free-form MEDIUM/HIGH events cannot gain native or Purple credit;
5. all raw telemetry shapes remain observation-only without an authenticated positive detector contract;
6. the legitimate campaign still reports 13/13 simulation canaries, 0/13 native analytics absent real native alerts, and restores all temporary state.
