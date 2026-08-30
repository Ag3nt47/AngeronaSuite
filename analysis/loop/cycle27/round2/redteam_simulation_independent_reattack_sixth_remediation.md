# Cycle 27 Round 2 — Sixth-Remediation Independent Red Team Simulation Re-attack

Date: 2026-08-28
Scope: `RTS-R4-02`, `RTS-R4-03`, and `RTS-R4-05`, plus the mandatory
13-contract denominator, producer object/generation binding, T1059 process
source, and signed display/action handoff
Disposition: **REOPENED — 1 ROOT FINDING CLOSED, 2 REOPENED**

## Safety and method

This was a product-read-only hostile re-attack. It treated the sixth-remediation
claims and author tests as hypotheses, then used only temporary directories,
temporary SQLite recording, inert marker text, local synthetic `Event` objects,
and temporary signed report bundles. It did not launch an exploit, probe a live
host or network, access credentials, persist anything, alter a service/driver/
registry object, or change a host security control. No product file or existing
test was edited.

The independent suite is
`tests/test_cycle27_redteam_simulation_sixth_independent_reattack.py`.

## Verdict summary

| Control | Verdict | Severity | Independent result |
|---|---|---:|---|
| `RTS-R4-02` FIM one-use scan-generation custody | **REOPENED** | **MEDIUM** | A completed empty scan could be mutated after capture to add a later-created marker and recompute all checked digests; the resulting version-4 receipt verified. Resetting the writable consumed flag and pending pointer then minted a second accepted receipt from the same scan generation. |
| `RTS-R4-03` immutable captured verifier / issuer-only receipt authority | **REOPENED** | **MEDIUM** | The captured implementation is writable through `function.__closure__[*].cell_contents`, which redirected a receipt-free row to `True`. Separately, `_lease_authority(lease).key` signed a new synthetic receipt that the normal verifier accepted. |
| `RTS-R4-05` fixed-head/journal rollback and signed handoff | **CLOSED** | — | Cross-report text/bytes/journal-row swaps, prefix removal, stale handoff, and the existing journal-only rollback probes all failed closed. |
| Mandatory 13-contract denominator | **CLOSED** | — | A duplicate-only/missing-inventory signed campaign retained denominator 13, withheld scoring, and kept the validation rate null. |
| Exact producer object and lifecycle generation | **CLOSED** | — | Module-object replacement and lifecycle-generation advance both invalidated a formerly valid native receipt. The existing T1059 OS-source generation gate also remained green. |

The reopened cases affect the truth of Red Team simulation efficacy evidence;
they do not provide a path into the host. They require Python code already
executing inside Angerona, which is the same trust class exercised by the prior
mutable-dispatch and scan-free-evaluator findings.

## `RTS-R4-02` — scan custody remains mutable and replayable

**Verdict: REOPENED (MEDIUM).**

### Post-scan artifact injection

1. Run the genuine FIM `_scan()` against an empty temporary watched root and
   retain the exact `_FIMScanSnapshot` that the module also keeps as pending.
2. After the scan has completed, create and lease-register one inert
   `_redteam_lsass_dump_*.txt` marker.
3. Insert its path/digest into the returned dict, insert its current stat tuple
   into `_fim_identities`, update receipt counters, recompute
   `snapshot_sha256`, and recompute `_fim_coverage_sha256`.
4. Call `_evaluate_snapshot(snapshot)`. The producer capability issues a
   version-4 receipt, and `verify_validation_native_event()` accepts it even
   though the marker did not exist during the scan.

The failure is captured at
`tests/test_cycle27_redteam_simulation_sixth_independent_reattack.py:108-159`.

### Consumed-generation replay

After one normal scan/evaluation produced one accepted receipt, hostile code
set `snapshot._fim_consumed = False`, restored the same object to
`fim._pending_scan_snapshot`, and evaluated it again. Both emitted receipts
verified, with distinct producer serials, while carrying the same FIM scan
generation. The failure is captured at the independent test's `:165-214`.

### Root cause and recommendation

`_FIMScanSnapshot` is a mutable `dict` whose owner token, identity map, baseline,
receipt, coverage digest, and consumed bit are all writable attributes
(`src/angerona/modules/file_integrity.py:199-223`). `_scan()` returns that same
object and stores it at `_pending_scan_snapshot` (`:773-787`). The claimant
recomputes digests over attacker-controlled fields and treats the writable
boolean/pointer as the one-use authority (`:863-917`). The receipt issuer then
authenticates the reconstructed structure (`src/angerona/modules/purple_guard.py:242-500`).

Keep the canonical snapshot, identities, receipt, generation, and consumed
state in producer-owned custody not returned to callers. Pass the evaluator an
opaque claim or an immutable copy, require the exact current generation, and
burn an issuer-owned generation/nonce that cannot be restored by mutating the
snapshot object. A measured isolated producer remains the stronger boundary.

## `RTS-R4-03` — closure and signing authority remain reachable

**Verdict: REOPENED (MEDIUM).**

### Closure-cell dispatch replacement

The sixth remediation removed verifier fields from `_LeaseAuthorityState` and
captured exact class methods in `_build_validation_dispatch()`. That defeats
class replacement, but the returned public wrapper exposes its captured
`verify_native_impl` in an ordinary writable closure cell. Replacing only that
cell's `cell_contents` with a lambda caused a receipt-free synthetic FIM row to
pass. The cell was restored in `finally`, so the probe left no global mutation.

Relevant source is `src/angerona/modules/purple_guard.py:2513-2574`; the red gate
is the independent test at `:217-248`.

### Module-reachable receipt forgery

`_LeaseAuthorityState` still contains the live HMAC key and the ordinary module
function `_lease_authority(lease)` returns that state
(`src/angerona/modules/purple_guard.py:84-154`). Starting from a valid inert FIM
receipt, the probe changed only `event_nonce`, rebuilt the canonical receipt
core, signed it with `state.key`, and created a new synthetic `Event`. The
unchanged public verifier accepted it. No canonical producer capability call or
EventBus publication authenticated the forged object.

The red gate is the independent test at `:285-328`.

The `same-process-object-capability` label accurately discloses the present
trust boundary, but the sixth remediation's stronger “immutable captured
verifier” and issuer-only signing claims do not hold. Python closures are not
immutable, and returning live authority state returns the signing primitive.
Strong closure requires moving signing, replay state, and verification into a
measured restricted process/service, leaving this interpreter only an opaque
handle and public verification key. If that design is deferred, describe these
receipts as same-process simulation validation rather than immutable native
analytic proof.

## `RTS-R4-05` — continuity and handoff remained closed

**Verdict: CLOSED.**

The new independent report test generated two authenticated report bundles and
confirmed that only the current result displayed. It then independently tried:

- report text from result one with result-two metadata;
- result-one text bytes with result-two metadata;
- result-one signed journal row/hash with result-two report/head bytes; and
- removal of journal row one while retaining authentic row two.

Every cross-bundle handoff failed. Prefix removal failed journal chain
validation, and the resulting current handoff also failed. The author sixth
journal-only rollback test, fixed-head replay tests, and older signed display
tests remained green in the broader gate. Relevant source is
`src/angerona/shark/aar_report.py:154-239,1090-1386`; the fresh green gate is the
independent test at `:354-381`.

The already disclosed residual remains accurate: coordinated rollback of all
local witnesses needs a separately administered monotonic witness. No narrower
fixed-head, journal-prefix, byte-swap, replay, or handoff bypass was found.

## Supplemental closure checks

- **Object and generation binding:** a valid native FIM receipt stopped
  verifying when `manager.modules` pointed at a replacement object, and again
  after the enrolled object's lifecycle generation advanced. Fresh gate:
  independent test `:384-417`.
- **Process binding:** the existing independent T1059 test provisioned the exact
  Process Monitor object, produced an OS-reread receipt for an inert child, and
  rejected a receipt-free copy of the live tuple. It passed unchanged in the
  broad run.
- **Mandatory denominator:** a signed duplicate-only campaign with 12 mandatory
  contracts absent produced `detection_steps == 13`,
  `coverage_score_eligible == false`, and a null simulation-validation rate.
  Fresh gate: independent test `:420-483`.
- **Signed display/action handoff:** exact current bytes/row were required by the
  fresh handoff test. The existing signed display replay tests passed in the
  80-test unchanged suite, and the focused displayed-report replacement/action
  gate passed separately.

## Gate evidence

- New independent hostile suite: **4 failed, 3 passed**. The four failures are
  the two `RTS-R4-02` reproductions and two `RTS-R4-03` reproductions above.
- Fresh closure-only subset: **3 passed, 4 deselected**.
- Sixth author remediation plus fifth independent baseline: **10 passed**.
- Broader unchanged Red Team/Purple/validation/drill/AAR suite: **80 passed**.
- Display/action replacement binding gate: **1 passed**.
- `py_compile` for the new independent test: **passed**.
- Ruff for the new independent test: **passed**.

No product remediation, commit, or publication was performed.
