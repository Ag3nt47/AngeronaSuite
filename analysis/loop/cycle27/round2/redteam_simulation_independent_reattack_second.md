# Cycle 27 Round 2 — Red Team Simulation Second Independent Re-attack

Date: 2026-08-28
Disposition: **REOPENED**
Scope: read-only product review plus inert local temporary files, temporary SQLite
ledgers, synthetic events, and in-process boundary doubles. No real exploit,
credential access, persistence, network attack, destructive action, or host
security-control mutation was performed.

## Executive result

The second remediation materially hardens the production launch and AAR path:
the exact canonical recorder/root/authority checks hold, fake stored HMACs and
producer-name spoofing do not receive production credit, the launch lease is
one-use under concurrency, and an honest gated campaign validates all 13
simulation canaries while correctly reporting zero native analytics when none
were supplied.

The overall boundary is nevertheless **REOPENED**. Seven residual weaknesses
were independently reproduced. The most important practical result is that the
public `evaluate()` default still reproduces the original inflated **1/13
caught, 12/13 missed** result from one raw INFO process observation. Production
`generate_aar()` uses strict mode and produces the correct **0/13 analytic,
13/13 missed, one raw observation** result for the same replay.

Three separate authority bypasses also produced false 1/1 credit in isolated
tests: a stopped exact FIM object acted as a native-receipt signing oracle, a
writable validation-lease verifier method admitted an EventBus-authenticated
event with no detector receipt, and a post-acquisition NTFS hardlink alias was
credited as a Purple simulation validation. These require stronger
prerequisites than the first repair's name-only spoof, but they contradict the
current claims of immutable target binding and unforgeable detector provenance.

## Caught/missed and authority matrix

| Check | Expected | Observed | Verdict |
|---|---|---|---|
| Historical 13-step replay through default `evaluate()` with one raw INFO process event | Raw observation only | **1/13 analytic caught, 12/13 missed** | **REOPENED** |
| Same replay through strict authenticated classifier | 0 analytics; one observation | **0/13 analytic caught, 13/13 missed, 1/13 observed** | CLOSED in production path |
| Honest gated inert campaign (focused regression) | 13 pipeline canaries, no invented native analytics | **13/13 Purple validation, 0/13 native analytics** | CLOSED |
| No live validation lease | Refuse before marker one | Refused; prior history preserved | CLOSED |
| Ring-only, foreign-root, closed, or wrong-authority recorder | Reject | Rejected | CLOSED |
| Fake stored HMAC plus recorder/bus instance verifier replacement | No evidence credit | 0 observations, 0 analytics | CLOSED |
| Released/replayed lease, policy drift, sensor restart, target mismatch through public API | Reject | Rejected | CLOSED |
| 32 concurrent consumes of one lease | Exactly one succeeds | **1 accepted, 31 rejected** | CLOSED |
| Private target mutation plus public registration | Reject immutable-target violation | Lease accepted target B; signed receipt retained readiness target A and bound target B | **REOPENED** |
| Expired lease followed by wall-clock rollback | Remain expired | Rejected after expiry, then accepted after backward clock step | **REOPENED** |
| Caller invokes exact enrolled FIM object's `emit` while FIM is stopped | No native detector receipt | **1/1 native analytic credit** | **REOPENED** |
| Replace exact lease's instance verifier with accepting callable | Exact class authority must remain binding | **1/1 native analytic credit** without detector receipt | **REOPENED** |
| Post-acquisition NTFS hardlink at the exact marker leaf | Reject alias/non-owned object | **1/1 Purple validation**; external file remained unchanged | **REOPENED** |
| Replay an older valid signed report pair into an existing Red Team dialog | Reject report/run rollback | Old run loaded and replaced the dialog's newer run binding | **REOPENED** |

## Reopened findings

### RTS-R2-01 — Non-strict evaluation defaults recreate the original 1/13 inflation (MEDIUM)

Component: `src/angerona/shark/aar_report.py:399-408, 468-494`

`evaluate()` defaults `require_authenticated` to false. In that branch it
overwrites the already-computed semantic classification with `native = not
purple`. Any matching non-Purple event therefore becomes an analytic catch,
including raw INFO process telemetry. A current-code replay of the original 13
detection steps returned one native catch and twelve misses; strict mode returned
zero catches, thirteen misses, and one observation.

Production `generate_aar()` explicitly selects strict mode, so the GUI AAR is
not affected by this exact path. The weakness remains reachable to direct and
legacy library callers and makes the unsafe interpretation the API default.

Impact: callers can still publish the historical inflated coverage result and
misrepresent raw telemetry as detector efficacy.

Recommendation: make semantic taxonomy strict regardless of HMAC mode. Default
to authenticated scoring, and if fixture compatibility is required expose a
clearly named test-only adapter that may skip storage authentication but never
changes raw telemetry into a native verdict.

### RTS-R2-02 — The lease target is read-only by convention, not immutable (MEDIUM)

Component: `src/angerona/modules/purple_guard.py:253-310, 312-354, 641-667`

The public `target` property has no setter, but the backing `_target` remains a
writable instance attribute. After acquiring a lease for target A, registering
target B through the public runtime-target API, and replacing `_target` with B,
`consume_for_run()` accepted B. The signed receipt simultaneously contained the
original readiness `target` A and `bound_target` B. `_state_matches()` checks the
current property against the runtime set but never compares it to the target
captured in readiness.

This requires same-process object access and is therefore bounded by the known
external-extension isolation residual. It still disproves the stronger
"immutable exact target" claim made for this Python object boundary.

Impact: admitted in-process code can rebind where the drill writes and can also
confuse release cleanup because cleanup uses the mutated target.

Recommendation: keep the issued target/root/manager/module tuple in an
issuer-owned registry not derived from writable instance state; compare it to
the readiness target on every consume/attest/verify/release; invoke validation
through exact class implementations. Strong protection from admitted extension
code requires process isolation and a signer unavailable to extension memory.

### RTS-R2-03 — Exact stopped detector objects are receipt-signing oracles (MEDIUM)

Component: `src/angerona/modules/purple_guard.py:492-591`

`bind_native_producers()` replaces the enrolled FIM instance's public `emit`
method. `_native_attestation()` checks object identity, capability ID, severity,
and a short raw-event denylist, but it does not prove the detector is running,
healthy, or executing an internal detection path. Calling `fim.emit(...)`
directly while its status was `stopped` produced a valid run-scoped native
receipt and **1/1 native analytic credit**.

Impact: code with a reference to the exact enrolled module can fabricate native
efficacy without spoofing its name or knowing the receipt key.

Recommendation: do not turn the public/general `emit` method into a signing
oracle. Issue a one-use challenge inside the detector's actual observation
site, bind the receipt to step/run/target and held object identity/content, and
require a live healthy matching generation. Isolate the receipt signer if
untrusted in-process extensions are in scope.

### RTS-R2-04 — AAR dispatches through writable lease verifier methods (MEDIUM)

Component: `src/angerona/shark/aar_report.py:1086-1099, 1124-1144`

The recorder and EventBus checks deliberately invoke exact class methods, but
the run-history, native-event, and Purple-event checks dispatch through writable
attributes on the lease instance. Replacing `verify_run_history` and
`verify_native_event` with accepting callables preserved the exact lease type
and object identity, yet admitted an EventBus-authenticated event containing no
detector receipt as a **1/1 native catch**.

Impact: in-process mutation bypasses the newly added detector-receipt authority
while leaving the report apparently authenticated.

Recommendation: call exact `RedTeamValidationLease` implementations and keep
authoritative lease state in a non-exported issuer registry. Treat this as
defense in depth only until extensions and their verifier/signing authorities
are process-separated.

### RTS-R2-05 — Authenticated prior AAR pairs can be replayed into a newer dialog (MEDIUM)

Component: `src/angerona/gui/pages.py:6517-6558, 6754-6795`

The refresh path verifies the report HMAC, kind, basename, nonempty run ID, and
text digest, but it does not require the run ID or JSON digest captured when the
dialog opened. A valid older signed JSON/text pair was copied into the current
filenames; refresh accepted it and replaced an existing `redteam-new-run`
binding with `redteam-old-run`. Old signed pairs are intentionally retained in
the AAR history, so replay does not require forging an HMAC.

Impact: a filesystem writer can roll back what the operator reviews and which
report a subsequent practice-fix action is bound to.

Recommendation: make the dialog's expected run ID and report digest immutable,
pass both into `_load_verified_aar_text()`, and refuse any replacement. Add a
monotonic current-report sequence/head and read the JSON/text pair through
identity-checked handles to distinguish legitimate new dialogs from rollback.

### RTS-R2-06 — Lease expiry uses rollbackable wall time (LOW)

Component: `src/angerona/modules/purple_guard.py:242-245, 322-353, 356-379, 392-400`

Both acquisition and run expiry use `time.time()`. The test first moved time
past acquisition expiry and confirmed rejection, then moved it backward and the
same unconsumed lease was accepted. This requires system-clock control or
same-process time replacement; normal expiry and release work correctly.

Impact: an elevated local adversary capable of rolling back the wall clock can
extend a validation authorization beyond its intended lifetime.

Recommendation: use `time.monotonic()` for all in-process lease deadlines and
retain wall-clock timestamps only as display/audit metadata. Detect large wall
clock discontinuities in the receipt for operator visibility.

### RTS-R2-07 — Marker validation is not bound to a no-alias file identity (MEDIUM)

Component: `src/angerona/modules/purple_guard.py:1048-1108`; `src/angerona/shark/run_manifest.py:342-369`; `src/angerona/shark/red_team.py:169-181`

Purple Guard globs a name, follows `stat()`, and signs the path string; it does
not require a regular no-reparse file, link count one, engine provenance, or a
held file identity. The history receipt rejects symbolic links but does not
detect NTFS hardlinks. A hardlink created after readiness at the exact expected
marker leaf was recorded as `hashed` and received **1/1 Purple simulation
validation**, while the external benign file remained unchanged. Symbolic-link
creation was unavailable under this host token, so the independently proven
variant is the Windows-native hardlink alias.

Impact: a same-user filesystem race can make an unrelated aliased object prove
the canary path and can leave the underlying external object unaffected by
path-only cleanup/response.

Recommendation: create markers exclusively with no-follow/no-reparse semantics,
retain the opened handle, capture volume/file ID/link count/content digest, and
register that identity with the live lease before writing. Purple must reopen
or consume the held identity, reject directories/reparse points/multi-link
files, and bind its receipt to the run step ID and object identity. AAR scoring
must require an acceptable artifact receipt, not only a matching path.

## Prior-finding disposition

Of the 14 prior Red Team Simulation findings (`RTS-01` through `RTS-09` and
`RTS-R01` through `RTS-R05`), 10 were independently verified closed and four
remain partial/reopened:

- `RTS-03` / `RTS-R05`: strict production scoring is fixed, but the public
  non-strict default still inflates raw telemetry.
- `RTS-R02`: ordinary target mismatch/release/replay/policy/sensor checks hold,
  but writable target state and wall-clock rollback remain.
- `RTS-R04`: producer-name spoofing is fixed, but the exact producer object and
  writable lease verifier remain signing/verification oracles in-process.

## Validation gates

- Focused Red Team/Purple/runtime suite: **41 passed, 0 failed** in 16.43 s.
- Relevant source compilation: **passed**.
- Ruff on relevant product/tests: **passed**.
- Headless self-check: **26 passed, 0 failed**.
- Module self-test runner within self-check: **65 passed, 0 failed, 17 expected skips**.
- `PurpleGuard.self_test()`: **passed**.
- `red_team.self_test()`: **passed**.

The temporary test fixtures were created only under the current user's system
Temp directory. Product and test files were not edited. Automated cleanup of
the two exact temp fixture directories was refused by the execution policy; the
fixtures contain only inert marker text, test keys, and temporary SQLite/report
files.
