# Cycle 27 Round 2 — Fifth-Remediation Independent Red Team Simulation Re-attack

Date: 2026-08-28
Scope: `RTS-R4-01` through `RTS-R4-07` only, after
`redteam_simulation_fifth_remediation.md`
Disposition: **REOPENED — 4 CLOSED, 3 REOPENED**

## Safety and method

This review treated the remediation report and its six author tests as claims,
not proof. It manually traced the current production authority and data flow,
then used only temporary SQLite ledgers, synthetic signed events, inert marker
text, one bounded no-op Python child, and temporary report files. No exploit
payload, credential access, persistence, network target, live security probe,
host security-control change, service, driver, registry object, or non-temporary
user file was touched. Product code and existing tests were not edited.

## Verdict summary

| Finding | Verdict | Residual severity | Independent result |
|---|---|---:|---|
| `RTS-R4-01` | **CLOSED** | — | Readiness provisioned and lifecycle-bound the exact built-in Process Monitor, the T1059 contract named that source, a genuine held child produced a version-3 OS-reread receipt, and a receipt-free publisher copying the exact live PID/birth/token tuple was rejected. Release stopped and removed the temporary producer. |
| `RTS-R4-02` | **REOPENED / PARTIAL** | **MEDIUM** | The retired public attester is inert and the capability is object/generation/code-site bound. However, `_evaluate_snapshot(current)` remains directly callable with a caller-supplied mapping. It minted an accepted `native_analytic_detection` receipt while `_last_scan_receipt` still said `not scanned`; no `_scan()` result or filesystem change-token/coverage receipt existed. |
| `RTS-R4-03` | **REOPENED** | **MEDIUM** | The former callable alias no longer controls dispatch, but the replacement authority is a mutable module-global weak registry. Ordinary Python code can obtain `_lease_authority(lease)` and replace `state.verify_native_impl`; a receipt-free row was then accepted without modifying the class or former alias. |
| `RTS-R4-04` | **CLOSED** | — | Both sides of the Windows race held. Replacement before DELETE-handle acquisition failed closed. Replacement after the exact DELETE-capable handle opened survived unchanged while disposition deleted only the enrolled original. POSIX source retains the moved object under an unpredictable same-directory custody name and verifies its inode before unlink. |
| `RTS-R4-05` | **REOPENED / PARTIAL** | **MEDIUM** | Cooperative publication is OS-serialized, fixed-file rollback is repaired, byte mutation is rejected, and journal rows are chained/HMAC-bound. But restoring only the ordinary writable journal to its authentic one-row state—leaving the newer fixed bundle untouched—made publication roll the fixed bundle backward and create a second authenticated sequence-2 descendant. The GUI handoff verifier accepted that fork. |
| `RTS-R4-06` | **CLOSED** | — | The authenticated admitted TTL is the minimum query horizon under the 4,500-second cap. The 4,235-second author case reached the late evidence range, and an independently signed history exceeding its admitted timeline was refused. |
| `RTS-R4-07` | **CLOSED** | — | An independently generated signed zero-step incomplete Red Team history persisted 14 verdicts, the 13-contract denominator, `coverage_score_eligible=false`, and a null validation rate. The ordinary no-run/non-Red-Team shortcut remains separate. |

The reopened results affect simulation-evidence truth and continuity, not host
compromise. Each requires code already executing in Angerona's Python process
or same-user write access to local report state. Those are the same trust
classes exercised by the prior findings, so the explicit
`same-process-object-capability` label is honest but does not close the claimed
native/immutable assurance boundary.

## Exact hostile probes

### `RTS-R4-01` — Process Monitor readiness and T1059 source receipt

**Verdict: CLOSED.**

- Starting from a manager with no Process Monitor caused
  `acquire_redteam_validation_lease()` to insert the exact
  `ProcessMonitorModule`, bind the same EventBus, attach the built-in capability
  contract, start a fresh lifecycle generation, capture a startup PID boundary,
  and wait for a loss-free cycle (`src/angerona/modules/purple_guard.py:3051-3258`).
- Readiness carried all 13 detector contracts and identified
  `angerona.builtin.process_monitor` for T1059.
- A token enrolled before a bounded no-op child was spawned became bound to the
  live PID, OS birth time, executable and exact argument. Process Monitor then
  performed its own second `psutil.Process` read at
  `src/angerona/modules/process_monitor.py:78-117` and the lease validated the
  live tuple again at `src/angerona/modules/purple_guard.py:334-425,1497-1540`.
- The resulting version-3 receipt verified. A synthetic Process Monitor event
  containing the exact live PID, birth time and token but no receipt MAC did
  not. After release, the temporarily provisioned module was stopped and
  removed.

This is simulation-contract evidence, not proof against real T1059 tradecraft.
The explicit synchronous reread is sufficient to close the former arbitrary
EventBus-publisher route without being represented as exploit efficacy.

### `RTS-R4-02` — canonical FIM evaluator is still a scan-free signing path

**Verdict: REOPENED / PARTIAL (MEDIUM).**

#### Reproduction

1. Start the exact FIM object, acquire and consume a validation lease, create
   one inert enrolled `_redteam_lsass_dump_*.txt` marker, and retain its exact
   lease handle.
2. Confirm `fim._last_scan_receipt == {"complete": false, "reason": "not scanned"}`.
3. From unrelated in-process test code, call
   `fim._evaluate_snapshot({exact_marker_path: exact_sha256})`. Do not call
   `_scan()` and do not create a scan coverage/change-token receipt.
4. The nested canonical code site invoked `_ProducerReceiptCapability`, which
   issued a version-3 `native_analytic_detection` HMAC. The normal verifier
   accepted it for T1003, while `_last_scan_receipt` remained `not scanned`.

#### Root cause

- `_ProducerReceiptCapability._canonical_caller()` checks only that one of two
  frames has the captured `_evaluate_snapshot` code object and exact producer
  `self` (`src/angerona/modules/purple_guard.py:225-245`).
- `FileIntegrityModule._evaluate_snapshot(current)` accepts its entire current
  snapshot as an ordinary caller argument and does not require a one-use result
  from `_scan()`, a complete `_last_scan_receipt`, a scan generation, root-set
  digest, or the handle change token captured by `_hash_once()`
  (`src/angerona/modules/file_integrity.py:508-549,572-698,773-885`).
- The capability independently proves the enrolled object and content still
  exist, which is valuable, but its receipt binds caller-provided digest/kind,
  serial and code-site digest—not a completed FIM scan transaction
  (`src/angerona/modules/purple_guard.py:246-332,1543-1570`).

#### Impact and remediation

An admitted same-process component holding the FIM object can still manufacture
native detector credit by invoking the canonical classifier with a truthful
marker digest. It proves marker custody, not that FIM discovered the marker in
an OS-derived scan. This is false efficacy evidence, not file or host compromise.

Make `_scan()` produce a one-use authenticated scan-generation capability bound
to the held root set, completeness receipt, exact snapshot digest, per-object
identity/change token, start/end monotonic bounds, and producer lifecycle.
`_evaluate_snapshot()` must consume that exact internal result and refuse direct
unbound mappings. Strong closure still requires a measured isolated producer
whose key/channel is unavailable to other Python modules; until then, classify
this proof as same-process simulation validation rather than native analytic
detection.

### `RTS-R4-03` — lease verifier dispatch remains directly mutable

**Verdict: REOPENED (MEDIUM).**

The remediation captures class implementations at lease issuance, but stores
them in mutable fields `verify_run_impl`, `verify_native_impl`,
`verify_purple_impl`, and `authority_matches_impl` on `_LeaseAuthorityState`
(`src/angerona/modules/purple_guard.py:83-141,922-968`). The state is reachable
through both the module-global `_LEASE_AUTHORITIES` registry and the ordinary
module function `_lease_authority(lease)`.

The independent reproduction left `RedTeamValidationLease` and the retired
`_VERIFY_NATIVE_EVENT_BUILTIN` name untouched. It assigned a lambda only to
`_lease_authority(lease).verify_native_impl`. The public
`verify_validation_native_event()` wrapper at `:2226-2236` immediately accepted
a receipt-free synthetic FIM row.

This requires same-process Python execution, but so did the original mutable
alias attack. Moving the callable into a publicly reachable mutable dataclass
does not create an issuer-only or immutable boundary. It can also expose the
lease key, native capability map and consumed receipt through the same state
object.

Do not claim immutable verification inside the interpreter. Move history/event
verification, secret keys, replay state, and result signing into a restricted
measured process or service that receives canonical byte inputs and returns one
signed verdict bound to their digests. The GUI/module interpreter should hold
only an opaque handle and public verification key. If isolation is deferred,
state explicitly that the mechanism catches accidental alias replacement but
does not resist an admitted Python extension.

### `RTS-R4-04` — exact-object cleanup

**Verdict: CLOSED.**

The original registered descriptor stays live until cleanup. On Windows,
cleanup opens a DELETE-capable no-reparse handle, confirms that handle is the
enrolled single-link file identity, and calls `SetFileInformationByHandle` on
that exact handle (`src/angerona/modules/purple_guard.py:576-732,1350-1391`).

The author case replaces the pathname immediately before the DELETE handle is
opened and correctly gets a false return with both files retained. The fresh
post-open probe replaced the pathname only after the DELETE handle and identity
were captured. Cleanup returned true, the unrelated replacement remained
byte-identical at the public pathname, and the renamed enrolled object alone was
disposed. Thus no remaining pathname unlink window was found.

The POSIX branch atomically moves the current name to an unpredictable
same-directory custody name, revalidates the moved inode, and unlinks only on an
exact match (`:734-749`). A raced replacement may be retained under the custody
name for review, but is not falsely deleted after a mismatched identity.

### `RTS-R4-05` — one-file journal rollback recreates the signed fork

**Verdict: REOPENED / PARTIAL (MEDIUM).**

#### Reproduction

1. Generate report 1 and save only `redteam_aar.heads.jsonl` at its valid
   one-row state.
2. Generate report 2 normally. Leave its fixed text, JSON and head files intact.
3. Restore only the journal to its authentic report-1 bytes.
4. Generate again. `_load_head_journal()` accepted report 1 as the highest
   retained authority. `_publish_report_bundle()` treated the still-newer fixed
   report-2 head as stale, rewrote it backward to report 1, and issued a new
   sequence-2 head from the report-1 predecessor.
5. Both original report 2 and the new fork had valid HMACs and different head
   digests. The resulting two-row journal validated, and
   `verified_aar_handoff_text()` accepted the fork for GUI display.

#### Root cause

- The OS writer lease at `src/angerona/shark/aar_report.py:1190` serializes
  cooperative publishers, but does not make the ordinary same-user journal file
  append-only or independently monotonic.
- `_load_head_journal()` authenticates the rows it sees but has no external
  high-water (`:1048-1094`). A prior valid prefix is therefore indistinguishable
  from the complete retained history.
- When journal and fixed head disagree, the journal always wins and the fixed
  bundle is silently repaired backward (`:1195-1213`). Rolling back the journal
  alone is therefore enough; the attacker does not need the “total rollback of
  every local file” described by the remediation boundary.
- The immutable handoff validates report/head HMACs and byte digests, but checks
  only that `journal_record_sha256` looks like 64 hex characters. It carries no
  signed journal row and consults no journal/high-water authority
  (`:152-197`). A newly signed fork consequently displays normally.

#### Impact and remediation

A same-user writer can hide an intervening report and create two authenticated
descendants at the same sequence. Review/remediation can then bind to a validly
signed but rolled-back branch. Byte mutation and cooperative concurrency remain
closed, but local continuity does not.

Anchor every accepted journal head/sequence to the separately administered
monotonic authority already used elsewhere in Angerona, using an authenticated
precommit outbox and exact compare-and-set. Hold and revalidate the journal file
identity throughout load/append, preserve fail-fast writer exclusion, and
reconcile only exact adjacent crash states. The GUI handoff should carry and
verify the exact signed journal record plus independently witnessed head, not a
free-standing hash string. Without an external witness, disclose the journal as
tamper-evident only—not rollback-resistant or append-only against its owner.

### `RTS-R4-06` — maximum admitted TTL horizon

**Verdict: CLOSED.**

`generate_aar()` derives the Red Team evidence window as the greater of caller
window and authenticated `admitted_run_ttl_seconds`, bounded by 4,500 seconds
(`src/angerona/shark/aar_report.py:1609-1640`). Lease history verification also
requires a finite admitted/receipt TTL and rejects a realized timeline beyond
that bound (`src/angerona/modules/purple_guard.py:1170-1283`).

The recorded 4,235-second case queried through the required late range. A fresh
independent history whose final step ended 1 ms beyond its signed admitted TTL
was rejected. Caller defaults can no longer truncate an admitted campaign, and
overlong realized histories cannot expand the query by assertion.

### `RTS-R4-07` — zero-step denominator

**Verdict: CLOSED.**

The zero-step shortcut now applies only when the history is not Red Team
(`src/angerona/shark/aar_report.py:1541-1554`). A Red Team history first passes
the exact live lease/history authority checks and then routes incomplete status
through `_incomplete_redteam_verdicts()` and normal signed publication
(`:1579-1607`).

The independent zero-step fixture produced an HMAC-valid result with 14 planned
verdicts, denominator/detection steps 13, score eligibility false, and a null
simulation-validation rate. No percentage was synthesized from an empty set.

## Validation evidence

- Author fifth-remediation regression file: **6 passed**.
- New independent hostile reproduction/closure file: **7 passed**.
- Wider Red Team/Purple/validation/drill/AAR/lifecycle compatibility gate:
  **126 passed**.
- Relevant product and independent-test `py_compile`: **passed**.
- Ruff on Purple Guard, Process Monitor, FIM, Red Team, AAR, and the independent
  test: **passed**.
- Module self-test runner: **65 passed, 0 failed, 17 expected inactive/platform
  skips**.
- No live probe or non-temporary mutation occurred.

Dedicated independent tests:
`tests/test_cycle27_redteam_simulation_fifth_independent_reattack.py`.
