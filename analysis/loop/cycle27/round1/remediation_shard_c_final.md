# Cycle 27 Round 1 — Shard C final remediation

Date: 2026-08-28
Scope: `C27-R1-C09`, `C27-R1-C10`, `C27-R1-C17`, and `C27-R1-C19` only
Method: local, inert fixtures and authenticated temporary state; no live attack,
host mutation, publication, commit, or push.

## Outcome

| Finding | Status | Defensive closure |
|---|---|---|
| `C27-R1-C09` | **CLOSED** | Crash snapshots now have authenticated bounded completion/retry/dead-letter state, deterministic idempotent staging, source-root and no-follow input custody, bounded exponential retry metadata, and non-green health for initial persistence loss, incomplete directory coverage, unsafe reads, pending retries, and dead letters. Failed initialization is retried rather than accepted in memory. |
| `C27-R1-C10` | **CLOSED** | All 6 primary enforcement functions plus 12 direct security dependencies are mandatory. Arm/check reports expected, watched, and unresolved coverage; records callable fingerprint plus containing-file SHA-256 and exact source path/line; and never treats an unresolved target as absent-by-design. A live TOFU baseline is explicitly unapproved and capped below full health. Only an exact independently supplied approved manifest can verify. ACL collection now distinguishes `ok`, `weak`, `collection-failed`, and `not-applicable`; weak or failed collection lowers health. |
| `C27-R1-C17` | **CLOSED** | The legacy Windows spill root comes from the Shell known-folder API, not mutable `LOCALAPPDATA`; POSIX uses the account database, not `HOME`. Inspection distinguishes clean, stray, unsafe/reparse, unavailable, and same-root states. Because cross-platform handle-bound mutation was not provable, privileged pathname move and purge execution are retired. Only bounded dry-run proposals remain; unsafe/unreadable state cannot report clean. |
| `C27-R1-C19` | **CLOSED** | Cursor schema 3 HMAC-binds channel generation, exact oldest-record anchor, exact durable-record anchor, monotonic cursor sequence, and update time. Every poll/reopen reloads durable state, captures generation, verifies the exact cursor record, and explicitly seeks/replays. Same-number-range clear/refill is detected by changed record anchors. Authentication/persistence/collection failures degrade health, and continuity events expose generation IDs, replay point, retained range, cursor age/sequence, persistence state, and rejection counters. |

## Adversarial regression coverage

`tests/test_cycle27_shard_c_final_remediation.py` adds 11 deterministic cases:

- C09: denied initial durable write remains unready across repeated passes;
  retry backoff is durable/non-green; unreadable coverage is degraded.
- C10: one missing dependency reduces watched coverage and appears in findings;
  TOFU and ACL collection failure cannot score 100; runtime replacement includes
  exact original and observed source evidence.
- C17: hostile `LOCALAPPDATA` cannot redirect the source; non-dry move/purge
  never executes; unavailable inspection is not clean.
- C19: a clear/refill with the same record-number range forces replay;
  persistence failure scores 25; reopen/resume performs an explicit seek from
  the durable cursor.

## Validation evidence

- Focused/adversarial pytest: **40 passed, 0 failed**.
- Module self-tests (`HEAL`, `SINT`, `SHYG`, `SYSL`): **4 passed, 0 failed**.
- Headless repository self-check: **66 passed, 0 failed, 16 optional skips**.
- Full Cycle27 pytest snapshot: **312 passed, 15 failed, 2 skipped**. All 15
  failures are pre-existing/out-of-scope red gates in Adversary Combat, ETW,
  Ransomware Heuristics, Smart Deception, and a Purple Guard integration test;
  none imports or exercises the four remediated modules as its subject.
- `compileall`/targeted `py_compile`: **passed**.
- Ruff on all four modules and the new test: **passed**.
- `git diff --check` on scoped files: **passed** (line-ending notices only).

The broad-suite exceptions were recorded rather than modified because this pass
was explicitly limited to C09/C10/C17/C19 and the shared worktree contains
concurrent remediation work.
