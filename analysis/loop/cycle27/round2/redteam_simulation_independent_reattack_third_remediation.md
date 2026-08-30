# Cycle 27 Round 2 — Red Team Simulation Third-Remediation Independent Re-attack

Date: 2026-08-28
Disposition: **REOPENED**

## Scope and safety

This was a fourth independent, read-only hostile review of the Red Team
Simulation evidence boundary after
`redteam_simulation_third_remediation.md`. Product and test code were not
changed. Every dynamic reproduction used only automatically removed temporary
directories, inert marker text, synthetic in-process events, temporary SQLite
ledgers, and reversible runtime monkeypatches. No credential access, real
exploit, persistence, network attack, destructive action, host targeting, or
host security-control mutation occurred.

## Executive result

The seven direct third-remediation regressions pass, and the specifically
claimed controls work in their exact regression cases: raw INFO is observation-only;
private lease-attribute mutation is rejected; stopped and restarted FIM
instances cannot sign receipts; wall-clock rollback cannot revive a lease; an
already-bound dialog rejects a different signed pair; and post-registration
marker hardlinks do not receive Purple credit.

The boundary is nevertheless **REOPENED**. Seven residual weaknesses were
reproduced. Most importantly, Angerona can sign a run as `completed` after only
one of fourteen mandatory phase steps survives, then report that one retained
probe as **1/1 (100%)** simulation validation even though readiness advertised
13 contracts and the preflight projected 15 steps. This directly explains how
missing probes can disappear from the denominator instead of appearing as
misses.

Two other public signing surfaces remain synthetic-evidence oracles: any
in-process EventBus publisher can turn a fabricated INFO process row into a
valid Purple receipt without a process existing, and a caller can invoke the
exact running FIM object's public `emit()` method to obtain a native receipt.
Exact-class dispatch also stops only instance monkeypatches: replacing the
method on the mutable Python class admitted a receipt-free row as a native
catch. These same-process cases are bounded by the remediation's documented
isolation caveat, but they still disprove an unforgeable in-process provenance
claim.

## Claimed-closure matrix

| Claimed control | Independent result | Disposition |
|---|---|---|
| Strict taxonomy/default raw INFO | Direct regression passed: one matching raw INFO event remains one observation and zero analytic catches | **CLOSED for direct evaluation**; synthetic Purple upgrade remains open as RTS-R3-03 |
| Issuer-owned lease target | Public/private lease attribute mutation is rejected | **PARTIAL**: the path is pinned, but the directory object is not; same path/new inode was accepted |
| Stopped/restarted FIM oracle | Stopped object test passed; generation 1→2 restart emitted no receipt | **PARTIAL**: an exact running FIM object's public `emit()` still signs caller-originated evidence |
| Exact-class AAR dispatch | Lease-instance verifier replacements are ignored | **PARTIAL**: replacing the verifier on `RedTeamValidationLease` itself produced 1/1 native credit |
| Dialog run/JSON digest binding | A dialog with an established binding rejects replacement | **PARTIAL**: a valid old pair can win before `_show_aar_dialog()` establishes the binding |
| Monotonic expiry | One-year wall rollback did not revive an expired lease | **CLOSED**; admitted maximum run duration still exceeds the fixed monotonic TTL |
| NTFS hardlink/alias custody | Pre-readiness, post-consumption, and post-registration marker hardlinks were rejected; post-registration link count 2 produced zero receipts | **CLOSED for marker files**; target-directory identity replacement remains open |

## Reproduced findings

### RTS-R3-01 — Missing mandatory probes disappear from a signed “completed” denominator (HIGH)

Components:

- `src/angerona/shark/red_team.py:554-613`
- `src/angerona/shark/run_manifest.py:473-560,611-720`
- `src/angerona/modules/purple_guard.py:591-622`
- `src/angerona/shark/aar_report.py:880-930,1080-1099`

Each step exception is caught at `red_team.py:596-601`, narrated, and omitted.
Unless the operator cancellation flag is set, the final history is still
written with `status="completed"`. The manifest authenticates the realized
list but never compares it with the mandatory Red Team technique multiset or
the preflight projection; lease verification likewise accepts `completed` or
`cancelled` histories of any non-zero subset.

Exact reproduction 1 used the real `_run_playbook()` and injected inert
`OSError` failures into thirteen mandatory step methods. The untouched engine
wrote an HMAC-authenticated history with:

- `status`: `completed`
- preflight `projected_steps`: 15
- actual steps: 1
- retained stage: `Initial Access (simulated)`

Exact reproduction 2 consumed a genuine live lease advertising 13 policies,
created and registered one inert T1003 marker, wrote the accepted one-step
history, and ran the production `generate_aar()` path. Purple Guard produced
one valid receipt and the signed AAR reported denominator 1, simulation count
1, and rate **1.0**.

Impact: a step I/O fault, resource failure, cancellation, or deliberately
induced per-step error can remove untested controls from the denominator and
turn severe incompleteness into a superficially perfect score. `steps_run` is
present for a careful reviewer, but the coverage rate itself is not complete or
safe to compare.

Recommendation: bind preflight to an explicit expected mandatory plan and
per-cycle technique multiset. Record every attempted step, including failures;
mark the run `incomplete`/`failed` when any mandatory probe is absent or failed.
For campaign mode, bind and verify canonical order. AAR generation should
refuse a percentage for incomplete/cancelled runs or retain the planned
denominator and count missing/failed probes as explicit misses.

### RTS-R3-02 — Lease readiness pins a path string, not the target directory identity (MEDIUM)

Component: `src/angerona/modules/purple_guard.py:80-115,225-256,488-538,540-589`

The issuer authority stores a resolved `Path`, but no held directory descriptor,
volume/file ID, creation token, or equivalent object identity. After readiness
completed for an empty temporary target, the reproduction renamed that
directory, created a different directory at the exact same path, and called
the exact-class `consume_for_run()` method. The old and new directory inodes
were different, yet consume succeeded and the receipt showed identical
`readiness_target` and `bound_target` strings.

Impact: a same-user filesystem writer can replace the object that was checked
for aliases and freshness. The drill then validates a different directory than
the one for which readiness was established while every displayed path remains
unchanged.

Recommendation: open and retain a no-reparse directory handle at acquisition,
record its volume/file identity and link/reparse attributes in issuer state,
and compare the path's current object with that held identity at consume,
marker creation/registration, every scan/attestation, history verification,
cleanup, and release. Refuse target disappearance or replacement rather than
silently rebinding the same pathname.

### RTS-R3-03 — Arbitrary INFO publisher becomes a Purple process-receipt oracle (MEDIUM)

Component: `src/angerona/modules/purple_guard.py:1355-1365,1445-1478,1595-1666`

`classify_process_event()` checks only `event_type="process_creation"` and an
`ANGERONA_REDTEAM_<8 hex>` token in command text. It does not require the exact
Process Monitor producer/generation, a detector receipt, an engine-enrolled
PID/birth tuple, a live process handle, or run-bound process provenance.

The reproduction spawned **no process**. An arbitrary in-process publisher sent
one bus-authenticated INFO event with a synthetic PID and token. Purple Guard
accepted it, issued a detector HMAC, and the production AAR reported **1/1
simulation validation** for T1059.

Impact: any admitted module with normal EventBus publication access can fabricate
the process-canary portion of Red Team coverage without observing a process.
The event HMAC proves bus transit, not producer or operating-system provenance.

Recommendation: enroll the engine-created process challenge in issuer-owned
state before launch and bind token, PID, process creation time, exact producer
object/capability/generation, and a held/verifiable process identity. Accept
only an object-bound receipt issued from the canonical Process Monitor
observation site; never upgrade an arbitrary raw EventBus row into Purple proof.

### RTS-R3-04 — The exact running FIM object's public `emit()` remains a signing oracle (MEDIUM)

Component: `src/angerona/modules/purple_guard.py:878-1013,1015-1083`

The third remediation correctly rejects stopped and restarted producer
generations, but `bind_native_producers()` still replaces the exact FIM
instance's general-purpose public `emit()` method. With the exact FIM genuinely
running and its worker thread alive, a caller invoked `fim.emit()` directly
with a marker path, HIGH severity, and the native evidence labels. The wrapper
issued a valid detector receipt, exact verification returned true, and the
production AAR reported **1/1 native analytic detection**.

Impact: code holding the managed FIM object can claim detector efficacy without
the file scanner having observed or classified the object. Requiring a live
thread proves lifecycle, not call provenance.

Recommendation: do not make the shared/public `emit()` path a signer. Issue a
one-use receipt inside the actual stable-handle FIM observation/classification
site and bind it to the scan generation, held file identity/content digest,
run, step/technique, and event. Keep the signing authority outside general
module-call reach; process-isolate it if admitted extensions are in scope.

### RTS-R3-05 — Mutable class-level dispatch bypasses detector receipts (MEDIUM)

Component: `src/angerona/shark/aar_report.py:1066-1093,1111-1144`

Calling `RedTeamValidationLease.verify_*` through the class blocks instance
attribute replacement but the class object is itself mutable. The reproduction
changed only `RedTeamValidationLease.verify_native_event` at runtime, retained
the exact issued lease and valid run history, and published a bus-authenticated
HIGH event with no `detector_receipt_mac`. Production `generate_aar()` reported
native count 1 of denominator 1.

Impact: admitted in-process code can replace the verifier while the report
still appears to use the exact built-in class and exact lease authority.

Recommendation: treat this as an explicit same-process boundary, not an
immutable authority. For meaningful protection, perform scoring and receipt
verification in an isolated helper whose measured code and key are unavailable
to extensions, and return a signed result. As defense in depth, capture and
verify canonical callable/code provenance before scoring and fail closed on any
class/module identity drift, while documenting that Python-level sealing alone
cannot withstand arbitrary code in the same interpreter.

### RTS-R3-06 — Replay can win before the dialog establishes its run/digest binding (MEDIUM)

Components:

- `src/angerona/gui/main_window.py:2296-2310,2422-2428`
- `src/angerona/gui/pages.py:6522-6628,6642-6653,6827-6908`
- `src/angerona/shark/aar_report.py:1002-1010`

The established-dialog high-water works, but the report text and binding reach
the GUI through separate channels. `_show_aar_dialog()` receives the newly
generated text, then independently rereads the mutable fixed JSON filename and
pins whichever run/digest exists at that later moment. That binding read does
not first authenticate the JSON or tie it to the emitted text/current engine
run.

The reproduction generated a new authenticated text/JSON pair, retained the new
text as the worker result, replaced the fixed files with an older valid signed
pair before binding, and executed the binding/load sequence. The dialog would
initially display the new text while its action/refresh binding was
`redteam-old`; the authenticated loader then accepted the old report. No HMAC
forgery was needed.

Impact: a same-user filesystem writer can create a display/action mismatch or
roll a newly opened review back to signed history during the generation-to-GUI
gap. A new dialog or application session has no durable report high-water.

Recommendation: have `generate_aar()` return one immutable result containing
text, run ID, exact signed JSON bytes/digest, and a sequence/head receipt, and
send that object through the GUI signal. Establish the dialog binding from that
result before displaying text. Publish the pair behind one authenticated atomic
manifest and maintain an authenticated durable monotonic report head so an old
valid pair cannot become current merely by replacing fixed filenames.

### RTS-R3-07 — Valid maximum-duration runs cannot fit inside the fixed monotonic lease (LOW)

Components:

- `src/angerona/shark/run_manifest.py:139-191,274-329`
- `src/angerona/modules/purple_guard.py:63-68,540-589`
- `src/angerona/shark/red_team.py:562-603`

Monotonic rollback resistance is correct, but deadline sizing is inconsistent
with accepted preflight values. `cycles=4` and `jitter_range=(60,60)` passes
preflight. Its 56 mandatory steps alone require at least 3,360 seconds of
jitter, while the run lease is fixed at 600 seconds, before probe work and the
45-second settle window.

Impact: an API caller can launch a configuration the safety contract accepts
but whose AAR must fail closed as stale. This is availability and diagnostic
reliability, not an evidence-forgery path.

Recommendation: calculate an upper-bound run/settle budget from the accepted
preflight contract and either reject configurations that exceed a documented
maximum or issue a bounded monotonic deadline sized to that contract. Persist
the admitted budget in readiness/history and surface expiration as an
incomplete run, never a coverage score.

## Validation evidence

- Direct third-remediation regressions: **7 passed, 0 failed**.
- Wider Red Team/Purple/runtime/remediation suite: **87 passed, 0 failed** in
  25.55 seconds.
- Relevant source/test compilation: **passed**.
- Ruff on relevant product/test files: **passed**.
- Headless self-check: **26 passed, 0 failed**.
- Module self-tests inside the self-check: **65 passed, 0 failed, 17 expected
  inactive/platform skips**.
- Independent post-registration NTFS hardlink check: link count 2, Purple hits
  0, detector receipts 0.
- Independent FIM restart check: enrolled generation 1, current generation 2,
  detector receipt absent.
- All `angerona-rts4-*` temporary directories were removed after validation.

## Prior-finding disposition

Of the seven findings claimed closed by the third remediation, three are fully
verified closed in their intended boundary (`RTS-R2-01`, `RTS-R2-06`, and the
marker-file portion of `RTS-R2-07`). Four remain partial/reopened through
adjacent variants (`RTS-R2-02`, `RTS-R2-03`, `RTS-R2-04`, and `RTS-R2-05`).
Three additional gaps were found in campaign completeness, Purple process
provenance, and admitted deadline sizing.

No result here demonstrates a real exploit or host compromise. It demonstrates
that the current local simulation evidence plane can still omit probes or
manufacture/replay proof under the prerequisites stated above, so it must not
be represented as complete real-attack efficacy.
