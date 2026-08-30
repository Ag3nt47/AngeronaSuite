# Cycle 27 Round 1 — Independent hostile re-attack of final Shard C

Date: 2026-08-28
Scope: `C27-R1-C09`, `C27-R1-C10`, `C27-R1-C17`, and `C27-R1-C19` only
Method: inert temporary files, authenticated fixture state, a fake Event Log
backend, and temporary link/junction objects. No product file was edited, no live
host attack was performed, and nothing was committed or published.

## Verdict

The final remediation claims do not yet withstand the independent hostile gates.
All four findings are **REOPENED**. The new suite contains 14 tests: **6 passed and
8 failed**. A separate unchanged focused suite exposed one additional C09 API
compatibility regression (**43 passed, 1 failed**).

| Finding | Verdict | Reproduced break(s) | Controls that held |
|---|---|---|---|
| `C27-R1-C09` | **REOPENED** | A wall-clock rollback expands a persisted 5-second retry to 1,005 seconds despite the 300-second cap; a validated package pathname can be swapped to an out-of-root hard-link before the separate source open; the unchanged bounded-state test also shows `_snapshot_candidates` changed its legacy Boolean overflow result to a truthy string. | Unsigned retry/dead-letter edits are rejected; bounded deeply nested malformed state returns non-green without escaping the loader. |
| `C27-R1-C10` | **REOPENED** | Monkeypatching the unlisted `is_active_threat` dependency silently disables threat classification while `check()` remains clean; an unknown ACL collector state falls through to health 100. | A live TOFU baseline remains distinct from an exact approved manifest, and source file/line evidence is present for all 18 currently configured targets. |
| `C27-R1-C17` | **REOPENED** | Swapping the already-validated source directory to a junction before enumeration makes inspection report `clean`; the module would convert that result to health 100. | Mutable environment variables do not redirect the Windows spill root. Hard-linked spill content is preserved because move and purge execution remain retired. |
| `C27-R1-C19` | **REOPENED** | An older, validly signed cursor is accepted after a newer cursor in the same process; a changed generation is rebound instead of replayed when only the cursor record stayed unchanged; the purported exact record digest ignores security-relevant data after 4 KiB. | Deep bounded malformed cursor state is rejected and marked untrusted without escaping the loader. |

## Exact red gates and line mappings

### C09 — durable retry custody and trusted-source confinement

1. `test_c09_wall_clock_rollback_cannot_expand_retry_beyond_bound` fails at
   `tests/test_cycle27_shard_c_final_independent_reattack.py:116`.
   `self_healer.py:229-244` accepts persisted absolute wall-clock timestamps
   without clamping them to the current `_RETRY_MAX_SECONDS` window, while
   `self_healer.py:419-423` compares the raw timestamp to `time.time()`. The
   fixture schedules a normal five-second retry at time 1,000, rolls the clock
   back to zero, restarts the module, and observes a 1,005-second deferral.

2. `test_c09_validated_source_identity_swap_cannot_escape_source_root` fails at
   `tests/test_cycle27_shard_c_final_independent_reattack.py:136`.
   `self_healer.py:564-588` validates one pathname/object, but
   `self_healer.py:592-627` later opens the pathname without carrying the prior
   identity or rechecking root confinement. Replacing the validated file with
   an out-of-root hard-link causes `_read_trusted_source` to ingest the outside
   object instead of rejecting the swap.

3. The unchanged
   `tests/test_cycle4_round3_state_bounds.py::test_heal_snapshot_scan_is_bounded_to_current_regular_candidates`
   gate fails because `self_healer.py:306-322` now returns the truthy string
   `"complete"` where the compatibility contract expected Boolean `False` for
   no overflow. Legacy `if overflow:` consumers therefore misclassify every
   complete scan.

Closure requires bounded retry deadlines after wall-clock anomalies, one
identity-bound validation/open operation (including hard-link/object-swap
handling), and a compatibility-preserving coverage API.

### C10 — complete callable coverage and fail-closed ACL truth

1. `test_c10_unlisted_security_dependency_monkeypatch_is_detected` fails at
   `tests/test_cycle27_shard_c_final_independent_reattack.py:152`.
   `_DEPENDENCIES` at `self_integrity.py:153-177` includes
   `active_threat_events` but omits its direct security decision dependency
   `angerona.core.threat:is_active_threat`, called at `core/threat.py:209`.
   `SelfIntegrityEngine.check()` (`self_integrity.py:372-401`) consequently
   reports no tamper after that decision function is replaced with an
   always-false callable.

2. `test_c10_unknown_acl_collector_state_cannot_score_full_health` fails at
   `tests/test_cycle27_shard_c_final_independent_reattack.py:166`.
   `_assurance_health` handles only `collection-failed` and `weak` at
   `self_integrity.py:454-460`; every unknown status falls through to the
   health-100 return at line 463. Only explicitly valid `ok` or platform-correct
   `not-applicable` evidence may be accepted as non-degrading.

Closure requires coverage of every live security decision dependency (or a
verified automatic dependency-closure mechanism) and fail-closed validation of
the ACL evidence schema/status.

### C17 — collection object identity

`test_c17_source_object_swap_cannot_turn_reparse_collection_green` fails at
`tests/test_cycle27_shard_c_final_independent_reattack.py:282`.
`inspect_stray` checks the initial root at `storage_hygiene.py:169`, completes a
tree safety scan at line 184, then separately enumerates the pathname at line
189 without revalidating the opened root identity. The inert fixture swaps the
validated directory to a Windows junction between those steps; the redirected
empty target is reported as `clean`. `_pass` converts `clean` to health 100 at
`storage_hygiene.py:354-355`.

Privileged mutation is still retired, so this re-opened issue is false-green
collection truth rather than a demonstrated delete/move primitive. Closure
requires identity-bound enumeration or a post-enumeration identity comparison
that treats any object change as `unsafe`/`unavailable`.

### C19 — monotonic cursor, gap replay, and exact anchoring

1. `test_c19_authenticated_cursor_rollback_is_not_accepted_in_process` fails at
   `tests/test_cycle27_shard_c_final_independent_reattack.py:340`.
   `_load_cursor` resets the live sequence and durable record witnesses at
   `sysmon_listener.py:464-470`, then accepts the authenticated file values at
   lines 519-525 without comparing them to the newer values already observed by
   the process. Replaying an older valid schema-3 file regresses record 2 to 1
   with no authentication failure.

2. `test_c19_same_range_refill_with_unchanged_cursor_record_forces_gap_replay`
   fails at `tests/test_cycle27_shard_c_final_independent_reattack.py:363`.
   When the oldest-record generation changes but the exact cursor record remains
   byte-identical, `sysmon_listener.py:820-837` re-signs the old cursor against
   the new generation and resumes at `cursor + 1`. New lower-numbered records in
   a same-range clear/refill are skipped; any generation change must force a
   retained replay unless an independently complete no-gap proof exists.

3. `test_c19_exact_record_anchor_covers_security_data_after_four_kibibytes`
   fails at `tests/test_cycle27_shard_c_final_independent_reattack.py:373`.
   `_record_digest` truncates each StringInsert to 4,096 characters and the list
   to 64 entries at `sysmon_listener.py:433-447`. Two events with identical
   prefixes but different executable data after 4 KiB therefore receive the
   same “exact” anchor, even though the parser accepts event XML up to 1 MiB.

Closure requires an anti-rollback witness at least for the lifetime of the
process (and an explicit durable restart policy), replay on any changed
generation that lacks a complete no-gap proof, and hashing all bounded event
content that can affect parsing or security decisions.

## Green companion gates

- C09 authenticated retry/dead-letter tamper rejection: passed.
- C09 bounded deep malformed-state fail-closed handling: passed.
- C10 approved manifest versus TOFU separation and source line evidence: passed.
- C17 OS-authoritative Windows path despite hostile `LOCALAPPDATA`/`HOME`: passed.
- C17 hard-link spill with all mutation routes retired: passed.
- C19 bounded deep malformed cursor fail-closed handling: passed.

## Validation

- New independent hostile pytest: **6 passed, 8 failed** (expected red evidence).
- Original final remediation pytest: **11 passed, 0 failed** unchanged.
- Broader unchanged focused pytest across the four modules: **43 passed,
  1 failed**; the sole failure is the C09 Boolean compatibility regression above.
- Module self-tests (`HEAL`, `SINT`, `SHYG`, `SYSL`): **4 passed, 0 failed**.
- Targeted `py_compile` for all four product modules plus the new test: **passed**.
- Ruff for all four product modules plus the new test: **passed**.
- Product files modified by this re-attack: **none**.
