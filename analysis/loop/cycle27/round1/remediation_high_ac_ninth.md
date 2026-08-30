# Cycle 27, Round 1 — Ninth High-A/C Remediation

Date: 2026-08-28
Scope: independently reopened `C27-R1-A01`, `C27-R1-A16`, `C27-R1-C03`,
and `C27-R1-C13` residuals only
Status: **all 14 reopened gates remediated and author-validated; independent
re-attack required**

Every test used temporary files, fake Security-channel records, inert undo
callbacks, synthetic held-directory streams, temporary SQLite databases, and
in-memory protected/independent authority stand-ins. No live process, firewall,
Security log, user document, decoy, policy, credential, service, driver,
registry object, or network target was attacked or changed.

## `C27-R1-A01` — exact authority types and uninterrupted undo custody

Status: **FIXED — pending independent re-attack**.

- Protected recovery anchors and witnesses now require Python's exact integer
  authority type; floats and booleans cannot be normalized into sequences,
  schemas, counters, or terminal floors.
- If host compensation succeeds but its terminal journal append fails, the
  current process immediately opens the mutation circuit, sets health to zero,
  and retains the signed undo intent for recovery.
- Restart orphan compensation now runs while the receipt lock, OS writer lease,
  and descriptor-pinned journal session remain held through the host effect and
  terminal record. The concurrent A02/A03 journal work was preserved.

## `C27-R1-A16` — crash-safe acknowledgement truth and object custody

Status: **FIXED — pending independent re-attack**.

- A bounded, HMAC-authenticated delivery acknowledgement now binds the exact
  committed cursor sequence/HMAC, generation, terminal record/anchor, and (for
  a delivered batch) the authenticated outbox HMAC.
- Cursor advancement with neither a replayable outbox nor a matching durable
  acknowledgement is a visible continuity gap and cannot report health 100.
- Acknowledgement first verifies the active object, atomically claims it under a
  dedicated custody name, verifies that claimed object and batch again, commits
  the acknowledgement, and then cleans up the custody object. A pathname swap
  cannot make an unverified object count as the acknowledged batch. A crash
  before acknowledgement leaves a replayable custody object; a crash after the
  acknowledgement may duplicate delivery but cannot silently omit it.

## `C27-R1-C03` — bounded iteration and single-writer state authority

Status: **FIXED — pending independent re-attack**.

- Stop and deadline state are checked before requesting every next held entry.
  A 250 ms admission reserve prevents starting a synchronous metadata request at
  the deadline edge; interruption closes the iterator and remains explicitly
  truncated/non-green.
- State, witness, transition, and genesis-marker JSON use a byte-bounded,
  depth-bounded parser that converts recursion/resource failures to ordinary
  fail-closed `OSError` results.
- A durable, closed-schema pre-key genesis marker makes marker-only, partial-key,
  and key-only first-install interruptions restart-reconcilable. It is removed
  only after the exact state/witness genesis is authenticated.
- A re-entrant process lock plus non-blocking OS lease serializes load and
  commit. Transition installation rechecks the exact predecessor witness under
  that lease, so a stale writer cannot replace a competing adjacent commit.

## `C27-R1-C13` — recoverable local genesis and bounded authentication

Status: **FIXED — pending independent re-attack**.

- Default local-only first enrollment now writes a closed-schema marker before
  key/SQLite creation. A crash after key creation can complete only the exact
  empty sequence-zero authority and the marker is removed after verified
  ledger/head/witness initialization.
- Deep witness and transition inputs are depth-bounded and normalize
  `RecursionError`/resource failures to fail-closed `OSError` results.
- The local head reader opens without following aliases, validates regular-file
  identity and an 8 KiB ceiling before JSON allocation, reads exactly once, and
  rechecks object identity.
- SQLite ledger authentication streams at most
  `_CUSTODY_LEDGER_MAX_EVENTS + 1` ordered rows and rejects capacity overflow;
  it no longer materializes an attacker-sized result with `fetchall()`.

## Gates

| Gate | Result |
|---|---|
| Immutable eighth independent re-attack | `PASS` — `22 passed` (previously `14 failed, 8 passed`) |
| New ninth-remediation regressions | `PASS` — `15 passed` |
| Direct product/prior High-A/C compatibility matrix | `PASS` — `160 passed` |
| Additional Cycle 27 matrix | `139 passed, 2 expected skips, 5 unrelated pre-existing/concurrent red gates` (`A02`, `A03`, two `A07`, `A14`) |
| `py_compile` (four product modules + ninth test) | `PASS` |
| Ruff (four product modules + ninth test) | `PASS` |
| Combat armed-state, ETW decoder, RANS, SDEC `self_test()` | `PASS` — `4/4` |
| Owned-file `git diff --check` | `PASS` (line-ending notices only) |

## Honest platform and trust boundaries

- A synchronous platform directory call already in progress cannot be safely
  killed by Python. The module checks stop/deadline before each request and
  retains an admission reserve; any platform call that violates that reserve is
  reported as incomplete rather than complete. A kernel-supported cancellable
  directory continuation would be required for a hard in-flight deadline.
- Genesis markers and signing keys are local authorities. Atomic crash recovery
  is now deterministic, but rollback of every local authority object together
  remains the disclosed whole-host snapshot boundary without TPM monotonic state
  or a separately administered witness.
- ETW acknowledgement proves successful in-process EventBus publication, not
  durable processing by every downstream SIEM/consumer. Those consumers retain
  their own end-to-end acknowledgement responsibility; Angerona delivery is
  deliberately at-least-once.
- The custody ledger is row- and byte-bounded and locally authenticated. Its
  external high-water proves monotonic freshness, not remote/WORM preservation
  of all local evidence bytes.
