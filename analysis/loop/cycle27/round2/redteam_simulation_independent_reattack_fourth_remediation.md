# Cycle 27 Round 2 — Red Team Simulation Fourth-Remediation Independent Re-attack

Date: 2026-08-28
Disposition: **REOPENED**

## Scope and safety

This was the fifth independent hostile review of Red Team Simulation, after
`redteam_simulation_fourth_remediation.md`. Product and test code were not
changed. Dynamic checks used automatically removed temporary directories,
inert marker text, bounded no-op Python children, synthetic in-process events,
temporary SQLite ledgers, and reversible runtime instrumentation that widened
an existing cleanup race. No credentials, real exploit payload, persistence,
network target, host security control, or non-temporary host file was touched.

## Executive result

All eight author regressions pass, and the exact fourth-remediation controls do
what their tests claim. Missing, failed, duplicate, mismatched, unexpected, and
reordered campaign rows become `incomplete`; a same-path replacement directory
is rejected at consumption; a process event for a nonexistent PID is rejected;
direct `fim.emit()` and class-level verifier replacement do not grant credit;
the bound report loader rejects an older pair; and the maximum preflight gets a
3,975-second lease.

The evidence boundary is nevertheless **REOPENED** by seven adjacent residuals.
The most consequential is a complete production reproduction: a genuine
one-cycle engine run executed all 14 advertised steps, while a manager with no
Process Monitor still acquired readiness advertising 13/13 contracts. Genuine
Purple evidence was 12/13. Publishing the already-enrolled child's observable
PID, birth time, and token from an arbitrary in-process EventBus producer then
made the production HMAC-authenticated AAR report **13/13 (100%)**. The live
tuple proves that a child existed, but not that Process Monitor observed it.

The FIM signing oracle also moved rather than disappeared. Calling the public
module-level `attest_fim_scan_observation()` with the exact live FIM object,
enrolled marker path, and its digest returned a receipt which the production
native verifier accepted, without `_evaluate_snapshot()` observing the file.
Likewise, replacing the captured verifier's mutable module-global reference
returned `True` while the class method itself remained unchanged.

Additional reproductions found a cleanup TOCTOU that deleted a replacement
file after releasing custody of the enrolled marker, an accepted report-head
rollback that created two different sequence-2 descendants of the same head,
a 4,235-second admitted run whose last detector event is beyond the AAR's fixed
3,600-second query window, and a zero-step authenticated incomplete history
which produces no signed planned-denominator report.

## Fourth-remediation claim matrix

| Prior finding | Exact author regression | Independent direct result | Control disposition |
|---|---|---|---|
| RTS-R3-01 | One retained row must withhold the score and retain the full denominator | Passed; all six missing/failed/duplicate/mismatch/unexpected/order variants also became incomplete | **DIRECT CASE CLOSED**; zero-step diagnostics and maximum-window truncation remain as RTS-R4-06/07 |
| RTS-R3-02 | Same pathname/new directory identity must fail consumption | Passed | **PARTIAL / REOPENED** by post-validation cleanup replacement at RTS-R4-04 |
| RTS-R3-03 | Nonexistent synthetic PID/token must get no receipt | Passed | **REOPENED**: any publisher can claim the real enrolled live tuple, RTS-R4-01 |
| RTS-R3-04 | Calling the running FIM object's public `emit()` must not sign | Passed | **REOPENED**: the public scan attester itself signs, RTS-R4-02 |
| RTS-R3-05 | Replacing the verifier method on the class must not redirect dispatch | Passed | **REOPENED**: replacing the module-global captured callable redirects it, RTS-R4-03 |
| RTS-R3-06 | Old pair replacement after immutable handoff must fail bound reload | Passed | **PARTIAL / REOPENED** by head rollback/fork and mutable handoff text, RTS-R4-05 |
| RTS-R3-07 | Four-cycle/60-second preflight must receive sufficient monotonic TTL | Passed (3,975 seconds; 4,235 with custom probe) | **PARTIAL**: the report query still truncates at 3,600 seconds, RTS-R4-06 |

## Reproduced findings

### RTS-R4-01 — T1059 readiness omits its source sensor and any publisher of the live tuple can manufacture 100% (HIGH)

Components:

- `src/angerona/modules/purple_guard.py:946-1054`
- `src/angerona/modules/purple_guard.py:1847-1857`
- `src/angerona/modules/purple_guard.py:2087-2189`
- `src/angerona/modules/purple_guard.py:2362-2497`
- `src/angerona/shark/aar_report.py:978-991`

Readiness verifies Purple Guard and a 13-technique policy, but it does not
require an exact running Process Monitor object, capability, lifecycle
generation, cursor, first-cycle receipt, or source-producer signature. The raw
classifier checks only `event_type`, command text, and the token. The later OS
check proves that the PID/birth/token tuple is the enrolled live child, but does
not prove who observed or published it.

Independent full-run reproduction:

- engine started and completed normally;
- history was `completed`, `score_eligible=true`, and contained all 14 expected
  mandatory steps;
- readiness reported `policy_count=13` even though the manager had no Process
  Monitor;
- genuine Purple receipts covered the 12 file techniques, so the production
  AAR showed 12/13 (92.3%);
- an arbitrary publisher copied the live child's PID, `create_time`, and
  command-line token into a bus-authenticated INFO row;
- Purple Guard minted the T1059 receipt and a second production AAR showed
  13/13, rate 1.0.

Impact: Angerona can display signed 100% simulation validation even though the
process sensor never observed the process. This is false defensive assurance,
not host compromise; the prerequisite is an admitted in-process EventBus
publisher plus the observable drill-child tuple.

Recommendation: make an exact process producer part of readiness and the
issuer authority. Enroll its object, capability ID, generation, bus binding,
loss-aware cursor, and fresh first-cycle receipt. Mint T1059 proof only inside
that producer's canonical OS-observation site, binding a source receipt to the
run challenge and event. Purple Guard should verify that receipt rather than
upgrade a general bus row. If the producer is absent, stopped, restarted, or
overflowed, refuse launch or mark the probe explicitly incomplete.

### RTS-R4-02 — Public FIM scan attester remains a native signing oracle (MEDIUM)

Components:

- `src/angerona/modules/purple_guard.py:1539-1624`
- `src/angerona/modules/file_integrity.py:775-798`

`attest_fim_scan_observation()` is a public module function. It accepts the FIM
object, message, severity, path, digest, and change kind from its caller. It
checks that the FIM is running and that the marker identity/digest is enrolled,
but it cannot prove the call originated at `_evaluate_snapshot()`.

The reproduction called this function directly with the exact running FIM,
one genuine enrolled marker, and its SHA-256. It returned a detector HMAC. A
normal `fim.emit(..., **receipt)` event then passed
`verify_validation_native_event()`. No FIM snapshot/classification call had
observed the marker.

Impact: in-process code holding the FIM object can claim native detector
efficacy by reading an enrolled inert marker and invoking the signer. Lifecycle
and content custody prove the object exists, not that the detector found it.

Recommendation: move receipt keys and signing into an isolated, measured
verifier/producer process. Accept a one-use observation only over a private
authenticated channel from the FIM worker, bound to its scan generation,
baseline/change token, stable file handle, and event sequence. A Python-level
public/private naming convention is not a security boundary; until isolation
exists, label native proof as same-process-trust-limited.

### RTS-R4-03 — Mutable module globals bypass the captured verifier dispatch (MEDIUM)

Components:

- `src/angerona/modules/purple_guard.py:1498-1536`
- `src/angerona/shark/aar_report.py:1240-1248,1311-1319`

Capturing class callables closes class-attribute replacement, but the captured
objects live in writable module globals. The reproduction left
`RedTeamValidationLease.verify_native_event` unchanged and replaced only
`purple_guard._VERIFY_NATIVE_EVENT_BUILTIN`; the public wrapper accepted a
receipt-free synthetic native event. `generate_aar()` also imports mutable
wrapper functions from that module at call time.

Impact: an admitted same-process extension can redirect the report verifier
while the code still appears to call the exact built-in wrapper. This does not
cross a process boundary, but it invalidates an immutable in-process verifier
claim.

Recommendation: score Red Team evidence in a separate restricted process using
a measured/signed verifier image and a key unavailable to the GUI/module
interpreter. Return a signed result over exact input ledger/history digests.
Callable/code/module provenance checks are useful tamper alarms but cannot make
arbitrary Python code in the same interpreter non-mutating.

### RTS-R4-04 — Cleanup releases marker custody before unlink and can delete a replacement file (MEDIUM)

Component: `src/angerona/modules/purple_guard.py:885-919`

`remove_registered_artifact()` validates the enrolled marker, closes its held
descriptor, reopens/revalidates the pathname, and finally calls
`candidate.unlink()`. The pathname can change after the last identity check.

The inert reproduction widened that existing window after the second genuine
identity read. A concurrent filesystem thread renamed the enrolled marker and
created unrelated content at the same path. Cleanup returned success, the
genuine marker survived under its new name, and the replacement user file was
deleted.

Impact: a same-user writer that wins a narrow race can make cleanup delete a
different file at the known `_redteam_*.txt` path. Scope is limited to the
selected target and exact marker pathname, but that target can be Documents.

Recommendation: perform deletion against the still-held object, not a reopened
pathname. On Windows, retain the handle and apply verified disposition through
the handle with delete sharing and a final file-ID check. On platforms without
an exact handle-delete primitive, atomically move the name into a lease-private
held quarantine/custody directory and verify identity before deletion; if exact
object custody cannot be maintained, refuse cleanup and leave the file for
review. Add an external-thread replacement regression at every pre-unlink
boundary.

### RTS-R4-05 — Current-file report head can be rolled back into a signed fork; frozen handoff is not immutable authority (MEDIUM)

Components:

- `src/angerona/shark/aar_report.py:917-1150`
- `src/angerona/gui/main_window.py:2310-2351`

The writer reads only the current `redteam_aar.head.json`; there is no writer
lease or independently retained high-water. The reproduction generated report
1 and report 2, restored the authentic report-1 text/JSON/head, then generated
report 3. The rollback was accepted: reports 2 and 3 were different signed
heads with sequence 2 and the same sequence-1 predecessor.

The `frozen=True` handoff also provides API immutability, not adversarial
immutability: `object.__setattr__` changed its text after generation, and the
GUI initially displays `result.text` without hashing it against the attested
payload. The bound loader still rejects the direct old-pair replacement tested
by the author, so this is a same-process display/head-continuity residual rather
than a bypass of that exact loader check.

Impact: rollback or concurrent writers can fork the local report sequence and
hide an intervening report; admitted code can alter the displayed handoff text
while remediation remains bound to different persisted digests.

Recommendation: serialize report publication under an OS lease; retain every
authenticated head in an append-only journal and reconcile the maximum trusted
sequence before writing. Pin the high-water to an independent monotonic witness
when available. Carry the exact signed JSON/head bytes (or their signed envelope)
through the GUI and verify the displayed text digest immediately before display
and action. Treat the Python dataclass only as transport, never authority.

### RTS-R4-06 — Accepted 4,235-second campaign exceeds the AAR's fixed 3,600-second evidence query (MEDIUM)

Components:

- `src/angerona/shark/run_manifest.py:381-456`
- `src/angerona/shark/aar_report.py:1197-1205,1289-1297`

A valid four-cycle campaign with 60-second jitter, optional custom marker, and
noise is admitted with a 4,235-second monotonic lease. A canonical 64-row
realization remained `completed` and score eligible. Its final mandatory
detector row began 3,666.1 seconds after the first row. A signed event at that
time was excluded by the production default query ending at
`run_start + window`, where `window=3600`.

Impact: maximum accepted runs can report genuine late detections as misses. The
lease is now large enough, but the evidence reader is not, producing inaccurate
coverage and remediation conclusions.

Recommendation: for Red Team reports, derive the query end from the
authenticated admitted runtime, actual step end, settle reserve, and bounded
per-step detection deadline. Do not let a caller-supplied/default window be
shorter than the authenticated campaign's required evidence horizon. Keep an
absolute cap and report recorder incompleteness explicitly.

### RTS-R4-07 — Zero-step incomplete histories bypass the planned-denominator report (LOW)

Component: `src/angerona/shark/aar_report.py:1221-1233`

`build_run_history()` correctly converted a zero-step attempted completion to
`incomplete` with all 14 mandatory rows missing. `generate_aar()` then returned
`Last run recorded zero steps — nothing to report` before validation and wrote
no signed JSON/head. Thus the most incomplete possible run does not show the
13 detector contracts, exact missing reasons, or score-withheld state.

Impact: this does not create a false 100% score, but it removes the diagnostic
record precisely when every probe is absent or cancellation occurs before row
one.

Recommendation: after authenticating a Red Team history and lease, route an
empty incomplete/cancelled run through `_incomplete_redteam_verdicts()` and
persist the full planned denominator with null rates and exact missing IDs.
Reserve “nothing to report” for the absence of a run, not a signed failed run.

## Independent validation evidence

- Direct fourth-remediation adversarial regressions: **8 passed, 0 failed**.
- Contract adversarial variants (missing, failed, duplicate, mismatched,
  unexpected, and reordered campaign): **6/6 became incomplete and score
  ineligible**.
- Full genuine one-cycle engine exercise: **14/14 advertised steps executed**;
  history completed; 12 genuine file-technique receipts; zero genuine T1059
  receipts without Process Monitor.
- Production AAR before/after arbitrary live-tuple publication: **12/13 (92.3%)
  → 13/13 (100%)**.
- Wider Red Team/Purple/AAR/drill suite: **112 passed, 0 failed** in 22.38s.
- Relevant source/test compilation: **passed**.
- Ruff on relevant product/test files: **passed**.
- Headless self-check: **26 passed, 0 failed**.
- Module self-tests: **65 passed, 0 failed, 17 expected inactive/platform
  skips**.
- All `angerona-rts5-*` temporary directories and no-op child processes were
  removed by their bounded cleanup/finalizers.

## Prior-finding disposition

All seven exact author regressions were independently verified as fixed in
their narrow test shape. Six controls remain partial or reopened through the
adjacent variants above; the mandatory-plan inventory itself is materially
improved and correctly rejects every nonzero malformed plan tested.

No result proves a real exploit or host compromise. It proves that Angerona's
local simulation evidence plane can still manufacture process/native proof,
fork report continuity, truncate a valid long run, or mishandle a cleanup race.
It must not be represented as complete real-attack or state-actor efficacy.
