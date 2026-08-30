# Cycle 27 Round 1 — Independent verification after Shard C post-reattack remediation

Date: 2026-08-28
Scope: `C27-R1-C09`, `C27-R1-C10`, `C27-R1-C17`, and `C27-R1-C19`
Boundary: product code was read-only. All new probes used temporary files,
authenticated offline fixture state, monkeypatched in-memory policy/ACL evidence,
and a fake Event Log backend. No live host, ACL, event channel, service, process,
network target, or policy was changed.

## Verdict

The frozen hostile file and both author remediation files pass unchanged, but
four genuinely new independent gates reproduce residual authority gaps in three
findings. `C27-R1-C17` closes for the claimed boundary.

| Finding | Verdict | Severity | Independent result |
|---|---|---:|---|
| `C27-R1-C09` | **REOPENED** | MEDIUM | Replaying an older authentic empty healer state erases a pending retry and permits immediate reprocessing. |
| `C27-R1-C10` | **REOPENED** | HIGH | Replacing the mutable injection-policy global disables blocking without an integrity finding; ACL posture is collected only once, so post-enrollment broad-write drift remains health 100. |
| `C27-R1-C17` | **CLOSED for the claimed boundary** | — | Frozen junction/ordinary-object swaps and the author root-identity gates pass; mutation remains retired. |
| `C27-R1-C19` | **REOPENED** | HIGH | A delivery batch can omit retained record 2 yet advance the durable cursor from 1 to 3 with continuity `verified` and health 100. |

## Frozen and author gates

- `tests/test_cycle27_shard_c_final_independent_reattack.py` was run unchanged:
  **14 passed**.
- `tests/test_cycle27_shard_c_post_reattack_remediation.py` and
  `tests/test_cycle27_shard_c_final_remediation.py` were run unchanged:
  **20 passed**.
- No assertion in those files was weakened, skipped, xfailed, or edited.

## C09 — authentic state replay erases retry monotonicity

The authenticated state schema at `src/angerona/modules/self_healer.py:201-217`
contains completion, retry, retry-metadata, and dead-letter collections, but no
state generation or monotonic sequence. Persistence at `:375-383` signs that
same replayable shape. `_load_state()` installs any authentic snapshot at
`:300-317`; processing then trusts only those replayed collections at
`:517-534`.

The new gate at
`tests/test_cycle27_shard_c_post_remediation_independent_verification.py:54`
captured the valid initial empty state, scheduled and persisted a normal retry,
then restored only the older state while retaining the install key and crash
snapshot. Restart observed:

```text
load_state = true
pending retries after replay = 0
snapshot processed immediately = 1
```

This is neither an unsigned edit nor a coordinated rollback of every authority.
It defeats the process-monotonic deadline by rolling back the signed state that
attests the deadline.

Closure requires an authenticated monotonic state sequence/generation with an
independent enrollment or high-water witness. Missing, older, or forked state
must retain degraded health and must not reprocess a pending/dead-lettered item.
The already documented lack of an independent elapsed-time authority while the
process is stopped remains a separate honest limit.

## C10 — security policy and ACL liveness remain outside coverage

### Mutable guardrail policy

`src/angerona/engines/ai_guardrail.py:73-97` keeps injection signatures in the
mutable module global `_INJECTION_RE`; `scan_input()` reads it for every allow/
block decision. The integrity fingerprint at
`src/angerona/modules/self_integrity.py:265-286` binds callable code, defaults,
and closure cells, but not mutable globals referenced by that code. `check()` at
`:373-403` therefore remains clean when this policy changes.

The gate at
`tests/test_cycle27_shard_c_post_remediation_independent_verification.py:88`
first proved that `ignore previous instructions` was blocked, replaced only
`_INJECTION_RE` with an empty list, and observed:

```text
guardrail allow before = false
guardrail allow after  = true
self-integrity findings = []
```

Closure requires immutable policy data or a manifest-backed fingerprint of every
security-decision global used by a watched callable. Callable-only dependency
enumeration is not complete enforcement coverage.

### ACL posture is enrollment-only

The monitor collects ACL evidence once at
`src/angerona/modules/self_integrity.py:481-504`. Its loop at `:505-530` checks
callables repeatedly but reuses the startup `acl` mapping forever.

The inert gate at
`tests/test_cycle27_shard_c_post_remediation_independent_verification.py:107`
returned `ok` on enrollment, changed the fake collector to `weak` after the first
cycle, and ran another cycle. The collector was called once and health remained
100. No filesystem ACL was touched.

Closure requires bounded periodic ACL recollection, with collection failure,
unknown status, or a changed/broad-writer result immediately degrading health
and emitting fresh evidence.

## C17 — claimed source-root object boundary closes

The directory identity at `src/angerona/modules/storage_hygiene.py:151-175` is
checked after the safety walk and after enumeration at `:211-237`. The frozen
junction-swap gate and the author's ordinary-directory swap gate both pass, as
do environment-authority and retired-mutation gates. `migrate_stray()` remains a
proposal-only API at `:266-295`, and purge execution remains retired.

The author already discloses that a swap-and-restore wholly between pathname
checks can affect observation because Python lacks one portable handle-relative
directory enumeration primitive. That is not a new finding from this pass and
cannot redirect a privileged move/delete route because those routes are retired.

## C19 — a retained delivery gap advances the cursor

`_capture_channel_generation()` calculates the authoritative retained range at
`src/angerona/modules/sysmon_listener.py:714-728`. `_reseek_and_drain()` requests
the next record at `:902-915`, but `_consume_records()` at `:682-703` neither
requires the first returned record to equal the requested cursor nor enforces
unit monotonicity inside the batch. It processes what arrived and signs the
largest record number.

The gate at
`tests/test_cycle27_shard_c_post_remediation_independent_verification.py:199`
used a stable fake retained range 1–3 and a cursor at 1. The SEEK delivery
intentionally returned record 3 while record 2 remained in the authoritative
range. Observed state:

```text
durable cursor = 3
continuity = verified
health = 100
missing retained record = 2
```

Closure requires pre-admission validation that a SEEK batch starts at the exact
requested record and that every subsequent record advances by one. A gap,
duplicate/fork, regression, or out-of-range record must not be emitted or
checkpointed; it must trigger a bounded retained replay with degraded continuity.

## Validation and immutable snapshot

| Gate | Result |
|---|---|
| Frozen final independent hostile file | **PASS — 14 passed in 2.54s** |
| Author post-reattack + final remediation files | **PASS — 20 passed in 2.84s** |
| New independent verification | **RED — 4 failed in 2.18s** |
| New-test `py_compile` | **PASS** |
| New-test Ruff | **PASS** |
| Product files edited | **None** |

SHA-256 at the final independent run:

- `self_healer.py` — `8c61154667824a2d6b1878980d857dd3bf17bb86a5d0b636ffa64bd1b8478bd6`
- `self_integrity.py` — `7c41027ed1f89fa39ae66ddf4aaca9a4ccb934c4db5c6595f42ff9f22b0eb876`
- `ai_guardrail.py` — `6c993f9da1ce630258b71a3de9cda958bc12b57b49008f9a3541a35c25d5c4a0`
- `storage_hygiene.py` — `1aa312ac6f69819074f0921ae402754743027c1adc176e40f82933aaded51a96`
- `sysmon_listener.py` — `e1fcfdb1da3559658a4bff7de30d184000977ca87514b739d335e12277565c97`

Final count: **one finding closed, three reopened; two HIGH and one MEDIUM**.
The four red assertions are independent remediation gates and must not be
weakened into assertions of the vulnerable behavior.
