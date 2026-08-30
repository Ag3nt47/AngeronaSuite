# Cycle 27, Round 1 — Eighth Independent High-A/High-C Re-attack

Date: 2026-08-28
Scope: the eighth remediation of `C27-R1-A01`, `C27-R1-A16`,
`C27-R1-C03`, and `C27-R1-C13` only
Method: independent source review plus inert temporary-directory, fake Security
channel, in-memory protected-store/EventBus/high-water, fake iterator, and
temporary SQLite probes
Verdict: **all four findings remain REOPENED / PARTIAL**

No product source, host Security log, live process, firewall, registry object,
service, driver, credential, user document, or network target was changed.
This re-attack added only the independent test and report artifacts named at
the end. It did not commit or publish.

## Verdict summary

| Finding | Independent verdict | Residual severity | Result |
|---|---|---:|---|
| `C27-R1-A01` | **REOPENED / PARTIAL** | **MEDIUM** | Operator undo now has continuous custody, and protected parser depth/duplicate limits held. Terminal durability loss still leaves the current process armed; restart orphan undo is unpinned; authenticated fractional authority fields are accepted through numeric coercion. |
| `C27-R1-A16` | **REOPENED / PARTIAL** | **HIGH** | Present authenticated batches replay and exact identity ordering is checked. Cursor-new/outbox-missing is silently treated as acknowledged at health 100, and acknowledgement unlinks a mutable pathname after closing the verified object. |
| `C27-R1-C03` | **REOPENED / PARTIAL** | **MEDIUM** | Ordinary adjacent state/witness crash positions recover and coverage is honestly non-green. Cancellation is checked only after `next()`, genesis can strand key-only authority, deep state JSON escapes, and concurrent stale writers can silently replace an authenticated generation. |
| `C27-R1-C13` | **REOPENED / PARTIAL** | **MEDIUM** | Configured external-authority genesis and the enumerated SQLite/head/witness/CAS states recover. Default local-only genesis is still crash-fragile, pending-transition depth escapes, and head/SQLite authority reads allocate or materialize before a bound is enforced. |

## Reopened findings

### `C27-R1-A01-R8-01` — MEDIUM — terminal loss does not disarm the current process

`undo_action()` correctly holds the receipt lock, writer lease, capacity, and
pinned session at `src/angerona/modules/adversary_combat.py:4827-4835`.
`_undo_action_under_custody()` persists the intent and crosses the host reversal
at `:4863-4869`. If the terminal append fails, `:4870-4885` only returns an
error; it does not trip the mutation circuit or lower health.

The independent committed reversible IP-block fixture returned
`ok=false`, left the journal tail at `undo_intent`, and remained
`_mutation_blocked=false`, health 100 after the inert reversal reported
success. This contradicts the prior independent requirement that any failure
after an undo effect may have started must open the in-memory circuit before
restart.

### `C27-R1-A01-R8-02` — LOW — restart orphan undo is outside continuous custody

`_recover_orphaned_journal()` reads at `adversary_combat.py:3986-3989`, but
crosses automatic rollback effects at `:4020-4031` and `:4059-4078` without a
surrounding receipt lock, writer lease, or pinned journal session.
`_reconcile_state()` invokes recovery first at `:4081-4094` and opens its later
custody context only at `:4095-4099`.

A fresh module recovering a valid committed action plus `undo_intent` observed
no active journal session at the inert effect boundary. Removing the temporary
canonical journal succeeded; only the later append/anchor check opened health
0. The eventual fail-closed result limits severity, but the host compensation
can occur after audit custody has already been lost.

### `C27-R1-A01-R8-03` — LOW — authenticated numeric authority is not exact-typed

The bounded value walker explicitly accepts every finite float at
`adversary_combat.py:2486-2494`. Anchor parsing then coerces sequence/counter
fields through `int()` at `:1815-1819`, while `schema=2.0` equals integer schema
2 at `:1824-1826`.

An independently HMAC-authenticated anchor with `schema=2.0` and fractional
`challenge_counter`, `last_journal_sequence`, and
`consumed_terminal_sequence` values reconciled true at health 100. Signing
authority is required, so this is type confusion/robustness rather than an
unauthenticated entry point. Exact authority schemas should require
`type(value) is int` before any conversion.

### `C27-R1-A16-R8-01` — HIGH — missing outbox is accepted as acknowledgement

The outbox is correctly written before cursor persistence at
`src/angerona/modules/etw_listener.py:2194-2216`. However,
`_read_security_delivery_outbox()` deliberately maps an absent file to `None`
at `:2075-2083`; `_read_security_log_locked()` degrades only on an exception or
a present batch at `:2273-2295`. It can then report verified health 100 at
`:2454-2460`.

The inert Security channel enrolled records 1-3, prepared records 4-6, and
durably advanced to cursor 6/sequence 2 with a pending outbox. Removing only
that unacknowledged outbox before simulated publication/restart produced:

```text
restart_replay=[]
restart_cursor=6
restart_sequence=2
restart_gap=""
restart_health=100
```

No cursor, high-water, rollback anchor, witness, or signing identity was rolled
back. A cursor record needs an authenticated pending/acknowledged delivery
state (or equivalent atomic transaction) so absence cannot mean both “never
published” and “acknowledged.” At minimum the ambiguous state must remain
non-green.

### `C27-R1-A16-R8-02` — LOW — acknowledgement does not delete the verified object

Acknowledgement authenticates through a descriptor that is closed by
`_read_security_delivery_outbox()` and then performs two consecutive pathname
`lstat()` checks followed by `Path.unlink()` at `etw_listener.py:2150-2170`.
There is no held exact object through deletion.

At the deterministic unlink boundary, the fixture moved the authentic outbox
aside, installed an inert replacement at the canonical path, and allowed the
unlink. Acknowledgement returned success while the verified outbox object
survived under the alternate name. Because the caller should already have
published this batch, this exact-target break is LOW alone; it still invalidates
the claimed object-bound acknowledgement.

### `C27-R1-C03-R8-01` — MEDIUM — stop/deadline is checked after hostile `next()`

The real held iterator does metadata work before yielding at
`src/angerona/modules/ransomware_heuristics.py:1883-1922`.
`_fair_directory_entries()` requests the next item through `for entry in
iterator` at `:2009-2014` and checks deadline/stop only afterward at
`:2015-2019`.

Two gates failed:

- with `should_stop()` already true, one hostile entry was still produced;
- a 0.25-second deadline allowed a single simulated 10-second `next()` before
  the iterator closed and coverage became truncated.

Iterator close and honest non-green coverage held. The eighth report also
discloses that an arbitrarily slow namespace needs a platform continuation
primitive, so this is not an undisclosed limitation. It does mean the original
bounded-enumeration finding is not fully closed. The same prefix can remain
unvisited every epoch because ranking applies only after an entry is yielded;
there is no durable continuation cursor.

### `C27-R1-C03-R8-02` — MEDIUM — genesis intent follows durable key creation

Fresh enrollment creates the state and enrollment signing keys before writing
the genesis transition at `ransomware_heuristics.py:871-885`. Restart rejects
any partial key/state bundle without an already durable genesis intent at
`:836-870`.

Forcing the transition write to fail left both keys present and state,
witness, and intent absent. A clean restart raised `durable content-state
authority is incomplete`. Genesis must commit its typed intent before any
artifact that turns a pristine directory into a partial enrolled authority, or
retain a separately typed pre-enrollment marker that can be resolved safely.

### `C27-R1-C03-R8-03` — MEDIUM — deep state parser failure escapes startup handling

The state byte ceiling is 16 MiB, but `json.loads()` at
`ransomware_heuristics.py:911-930` has no depth scan and does not normalize
`RecursionError`/`MemoryError`. The module's startup path catches only
`OSError` at `:1211-1215`.

An 8,000-byte, 4,000-level state value—well below the byte ceiling—raised raw
`RecursionError` before authentication or visible state-fault degradation. The
4 KiB witness and transition boundaries did reject their maximum-size nested
fixtures safely.

### `C27-R1-C03-R8-04` — MEDIUM — adjacent transition is not a writer CAS

`_commit_change_cycle()` verifies the witness at
`ransomware_heuristics.py:1151-1161`, computes the new document, and only later
installs the transition and state at `:1183-1202`. There is no cross-process
writer lease or atomic compare-and-swap spanning those operations.

Two instances loaded sequence 0. The fixture paused stale writer B after its
witness check, allowed writer A to commit receipt A at sequence 1, then resumed
B. B installed a different old-0/new-1 transition and committed receipt B
without error. Restart authenticated B's sequence 1 while A's receipt was
silently lost. The adjacent crash proof therefore needs a single-writer lease
and an exact predecessor recheck at intent installation.

### `C27-R1-C13-R8-01` — MEDIUM — default local-only genesis remains crash-fragile

`SmartDeception` defaults to `high_water=None` at
`src/angerona/modules/smart_deception.py:291`. The external-provider path writes
genesis intent first at `:1650-1676`, but the local-only path has no equivalent.
`_open_custody_ledger()` creates the local key before SQLite at `:1492-1510`,
and restart refuses a partial bundle at `:1689-1696`.

An inert interruption immediately after local key creation left no SQLite,
head, witness, or transition. Restart failed permanently with `custody
authority bundle is incomplete`. The configured external-authority genesis
matrix is closed; the normal supported local-only configuration is not.

### `C27-R1-C13-R8-02` — MEDIUM — pending transition parser depth escapes recovery

The transition is byte-bounded to 8 KiB, but
`smart_deception.py:947-973` calls `json.loads()` and omits
`RecursionError`/`MemoryError` from its conversion to `OSError`. An 8,000-byte,
4,000-level value raised raw `RecursionError` during `_load_custody_state()`.
The 4 KiB witness boundary rejected its nested fixture normally.

### `C27-R1-C13-R8-03` — MEDIUM — local head and SQLite reads are resource-unbounded

The custody head uses unbounded `Path.read_text()` before parsing at
`smart_deception.py:1552-1560`. The SQLite ledger executes an ordered query and
calls `fetchall()` before authenticating even row one at `:1713-1718`; the
4,096-event cap is enforced only on append, not hostile startup input.

Independent probes observed an 8 MiB head allocate about 16.8 MiB before
rejection and a 50,000-row/12.1 MiB forged database use about 29.4 MiB and 4.08
seconds before failing the first row. The artifact gates additionally prove a
128 KiB head reaches `json.loads()` and that the valid empty ledger path calls
`fetchall()`. Use identity-pinned byte-bounded head reads and incremental
SQLite iteration with `LIMIT max+1`/row-count rejection before materializing
the authority.

## Closures that held

- `C27-R1-A01-CLOSE-01`: depth 17, duplicate members, oversized protected
  objects, huge integer tokens, and `NaN` become `JournalIntegrityError`;
  duplicate protected authority opens health 0. Normal operator undo now keeps
  the canonical journal pinned through its effect.
- `C27-R1-A16-CLOSE-01`: a present authenticated outbox replays records 4-6 at
  health below 100. Reordered acknowledgement is rejected and retains the
  outbox. Present-but-tampered outbox degrades instead of being accepted.
- `C27-R1-C03-CLOSE-01`: before-state, before-witness, and before-clear adjacent
  transactions recover. Witness-ahead-of-state is rejected. Deadline exit
  closes the iterator and marks coverage incomplete.
- `C27-R1-C13-CLOSE-01`: with a configured exact authority, genesis before
  ledger/head/witness, SQLite-new/head-old, head-new/witness-old,
  fully-local-new/remote-old, authority outage, ambiguous COMMIT, and lost CAS
  response recover. Missing transition after SQLite commit fails closed;
  pre-COMMIT failure rolls back and discards only the exact intent. Forks/gaps
  remain rejected.

## Validation and artifacts

- Author's eighth remediation matrix:
  `tests/test_cycle27_high_ac_eighth_remediation.py` — **16 passed**.
- Independent hostile matrix:
  `tests/test_cycle27_high_ac_eighth_independent_reattack.py` — **14 failed,
  8 passed**. The 14 failures are intentional red gates for the residuals
  above; the eight passes are independent closure/negative-state gates.
- `py_compile` and Ruff for the independent test — **PASS**.
- No broad/full-suite rerun was duplicated.

Independent artifacts:

- `tests/test_cycle27_high_ac_eighth_independent_reattack.py`
- `analysis/loop/cycle27/round1/independent_reattack_high_ac_eighth.md`
- `analysis/loop/cycle27/round1/independent_reattack_high_ac_eighth.json`

These verdicts are release blockers for any claim that the eighth remediation
fully closes A01/A16/C03/C13. They do not invalidate the narrower adjacent
crash-state fixes listed above.
