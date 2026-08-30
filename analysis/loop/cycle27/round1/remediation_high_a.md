# Cycle 27, Round 1 — High-Severity Remediation, Shard A

Scope was limited to `C27-R1-A01`, `C27-R1-A10`, and `C27-R1-A16`, including the three residual bypasses from the independent High-A re-audit. The changes and reproductions are defensive, local, and inert. No live process was terminated, no Security log or host policy was changed, no network target was contacted, and no commit or publication occurred.

## Seventh remediation — pending independent hostile re-attack

The sixth independent re-attack kept the surviving-witness, writer-lease,
hard-link, partial-commit, and full-identity controls intact but reopened A01
and A16 when the current witness itself was deleted. It also reproduced two
A01 journal-custody/resource residuals. This seventh pass removes runtime
schema-1 migration entirely: both modules reject legacy authority whether a
witness is present or absent, leave it byte-identical, and require an explicit
audited migration/recovery workflow.

Combat now uses one bounded, schema-strict, descriptor-pinned journal session.
The same canonical object, receipt lock, and installation writer lease span
read, append, fsync, protected anchor/witness advance, final verification, host
effect, postcondition, and terminal receipt. Windows denies journal
delete/replace while the effect runs; every platform rejects identity or parent
topology drift. Hard byte, line, record, JSON-depth, container, duplicate-key,
and field-schema budgets convert malformed/resource input into health-0
fail-closed state.

Exact seventh-pass regressions are in
`tests/test_cycle27_high_a_seventh_remediation.py`; implementation and honest
residual boundaries are recorded in `remediation_high_a_seventh.md` and
`remediation_high_a_seventh.json`. The new suite passes 7/7 and the complete
directly affected Combat/ETW matrix passes 99/99. Compile, Ruff, two inert
self-tests, and owned-file diff checks pass. These are author-side results;
independent re-attack remains mandatory before closure.

## Fifth remediation — pending independent hostile re-attack

The fourth independent re-audit reopened A01 at medium severity and A16 at high
severity. This fifth implementation pass does **not** self-close either
finding. It supplies regression and gate evidence for a separate independent
agent to attack again.

### C27-R1-A01 — signing-key-bound recovery high-water

- A schema-2 recovery anchor is now paired with a separate, descriptor-pinned,
  HMAC-authenticated high-water witness derived from the existing Combat
  journal signing key. The witness binds host, signing-key fingerprint,
  installation epoch, journal sequence/tail HMAC, and exact anchor HMAC.
- Every journal phase advances the protected anchor and then the independent
  witness. Missing, unsafe, malformed, MAC-invalid, stale, or mismatched state
  leaves the mutation circuit disarmed. Deleting both journal and protected
  anchor therefore remains detectable because the enrolled witness survives;
  restoring both to their pre-action state conflicts with its later high-water.
- Legacy schema-1 anchors migrate once only after their complete journal tail
  verifies. Once schema 2 exists, witness loss is never interpreted as legacy
  migration or first enrollment.
- Exact inert regressions preserve the journal key while deleting or rolling
  back both journal and protected anchor. Both restart at health 0 with the
  mutation circuit blocked.
- Boundary: an elevated attacker who restores or deletes the journal, protected
  anchor, signing-key-bound witness, signing key, and all other local evidence
  together crosses this software-only trust boundary. TPM NV or an external
  append-only authority is required to prove continuity across that event.

### C27-R1-A16 — complete record identity and serialized durable authority

- Event identity is now a deterministic, length-delimited streaming SHA-256
  over every complete consumed/native field and every full insertion string.
  There is no character truncation and no 64-insert omission. Per-record,
  insertion-count, retained-record, total-byte, and elapsed-time bounds are
  explicit; exceeding any bound leaves the bookmark unadvanced, backlog true,
  health 45, and enrollment inadmissible.
- Cursor, high-water, anchor, and authority-witness reads are descriptor pinned,
  single-link/no-reparse, bounded, and identity checked before and after reads.
  The no-change path now verifies the exact live cursor document, complete
  high-water tail, protected anchor, and signing-identity witness, so deletion
  of cursor, high-water, or anchor becomes visible on the same poll.
- A state-root-scoped re-entrant process lock plus non-blocking OS file lease
  serializes writers. Before a commit, cached durable identities must still
  match. The high-water is appended before cursor replacement, then the
  protected anchor and separate signing-identity witness advance; every
  interruption is fail-incomplete and the completed transaction is reread
  before success.
- A separate HMAC-authenticated authority witness binds the cursor signing-key
  fingerprint, installation epoch, protected-anchor revision/HMAC, cursor
  sequence/HMAC, and high-water HMAC. Restoring cursor, high-water, protected
  anchor, and channel together is rejected while that witness remains current.
- Exact inert regressions cover changed content after character 4096, changed
  insertion 65, over-budget records, live loss of each authority object,
  duplicate writers, and paired cursor/high-water/protected-anchor/channel
  rollback.
- Boundary: complete rollback of the Security channel **and every local
  witness**, including the authority witness and signing identity, cannot be
  distinguished by software on that same host. Health 100 is explicitly
  described as continuity within the local signing-identity witness boundary;
  TPM monotonic state or an independently administered witness is required for
  a whole-host snapshot claim.

### Fifth-pass gates

| Gate | Result |
|---|---|
| Dedicated High-A suite | `PASS` — `41 passed` |
| Dedicated + affected response-contract suites | `PASS` — `104 passed` |
| `py_compile` for both product modules | `PASS` |
| Ruff for both product modules and dedicated tests | `PASS` |
| Independent hostile re-attack | **PENDING — required before closure** |

## Fourth independent re-attack closure

This section supersedes the older A01/A16 implementation descriptions below.
The third independent re-audit kept A10 closed; this pass did not change A10.
It reopened A01's terminal semantics/clock authority and A16's two-file
deletion, paired rollback, and pre-bookmark enrollment race. The exact inert
reproductions are now regression tests.

### C27-R1-A01 — complete terminal semantics and rollback-anchored challenges

- Recovery authorization now issues a random, process-local challenge only for
  the exact latest mutation-started `ORPHAN`. A separately stored,
  OS-protected, host-bound anchor monotonically sequences each challenge and
  witnesses the latest journal sequence/HMAC. Journal rollback, deletion, or
  an interrupted journal/anchor transaction therefore keeps Combat disarmed.
- The approval resource binds the install epoch, durable challenge counter and
  nonce, orphan action/combat/generation/HMAC/sequence, the selected
  `confirmed_applied` or `confirmed_not_applied` disposition, and the complete
  SHA-256 digest of the normalized operator reason. A different result or
  reason requires a different approval.
- Freshness is a one-process `time.monotonic()` deadline plus one-time durable
  challenge consumption. Reversing the host wall clock cannot revive a prior
  resource, and a restart invalidates every unconsumed process challenge.
- The terminal retains the complete `AuthorizationDecision`. Ordered replay
  accepts it only when the exact terminal field set, action ID, combat ID,
  action type, `operator_disposed` status, allowlisted disposition, normalized
  reason/digest, latest orphan/challenge bindings, human principal, permission,
  scope, resource, request digest, policy hash, and receipt HMAC all verify.
  An HMAC-authentic terminal with a wrong action, combat ID, status, or
  disposition has no terminal effect and restart remains health 0.
- Exact tests also prove that a challenge cannot survive restart or wall-clock
  rollback and that retaining the protected anchor while rolling back or
  deleting the journal fails closed. This is a software/OS protected-store
  boundary, not a claim against whole-host rollback that also restores the
  signing key and protected store.

### C27-R1-A16 — protected rollback witness and two-sided channel identity

- Cursor schema v3 and high-water schema v2 are witnessed by a separately
  stored OS-protected, host-bound rollback anchor. It retains a random install
  epoch, monotonic enrollment challenge counter, active random nonce/state,
  latest cursor sequence/HMAC, latest high-water HMAC, generation/bounds, and
  consumed request state.
- Removing both cursor/high-water files after enrollment no longer recreates
  the old approval resource. The retained anchor advances the generation and
  challenge, keeps health 45, rejects the consumed decision, and requires a
  fresh distinct human approval. Restoring an older authentic cursor,
  high-water, and matching channel snapshot is rejected against the protected
  anchor.
- Enrollment freshness uses a process-monotonic deadline. Its resource binds
  the protected install epoch and challenge nonce/counter plus the exact host,
  gap, generation, cursor, bookmark/anchor, bounds, retained-record identity,
  and normalized reason digest.
- A bounded forward pass hashes every retained record's identity and selected
  content. Enrollment samples that exact identity before the cursor commit and
  again after cursor, high-water, and rollback-anchor persistence. If records
  below the bookmark change while final bounds/bookmark remain the same, the
  second sample differs, the gap is persisted, and restart replays from the new
  generation at health 45.
- Missing or unverifiable protected anchor authority explicitly prevents
  complete health/enrollment. No software-only claim is made against a
  whole-host rollback that also restores the protected store, signing
  authority, and Security-channel snapshot; that requires TPM or external
  monotonic witnessing.

### Fourth-pass gates

| Gate | Result |
|---|---|
| `py_compile` for A01, A16, and the dedicated test | `PASS` |
| Ruff for the same scope | `PASS` |
| A01 and A16 inert module self-tests | `PASS` |
| Dedicated High-A suite | `PASS` — `31 passed` |
| Dedicated + affected Adversary Combat/contract suites | `PASS` — `94 passed` |
| `git diff --check` for owned product/test files | `PASS` (line-ending notices only) |

## Second independent re-attack closure

The second re-attack independently closed `C27-R1-A10`; no further A10 product or test change was made in this pass. It reopened A01's in-flight disposition ordering and A16's approval/cursor rollback state. Both exact reproductions are now covered below.

### C27-R1-A01 — serialized irreversible-response state machine

- One re-entrant transition lock now spans the fsynced terminate intent, `kill()`, wait/postcondition, and exact commit/orphan outcome. Operator disposition uses the same lock and cannot inspect or close a bare in-flight intent.
- Every non-reversible action carries a random mutation generation. Recovery authorization is issued for an exact resource containing the action ID, mutation generation, and latest orphan record HMAC. Resolution additionally requires that exact mutation-started `ORPHAN`, its `operator_disposition_required` state, its sequence, and the same record currently held by the open mutation circuit.
- Production freshness uses the internal wall clock; caller-selected `now=` is no longer an authority input.
- Journal replay is ordered. A disposition not bound to the latest recovery orphan has no terminal effect, generic failure/commit records cannot close an existing non-reversible recovery orphan, and any later orphan reopens recovery.
- Exact inert evidence: while fake `kill()` was blocked, a concurrent bare-intent disposition remained blocked behind the transition lock. After the fake effect completed and its postcondition raised, the disposition was rejected, the journal remained `[intent, orphan]`, and restart stayed health 0. A historical signed `[intent, operator_disposition, orphan]` sequence likewise replays as recovery-required.

### C27-R1-A16 — single-use state approval and independent high-water

- Enrollment approval is single-use and bound to the exact host, generation, cursor sequence, record bookmark/anchor, observed oldest/high-water bounds, current gap digest, and operator-reason digest. Cursor schema v2 durably stores the consumed authorization request/digest and reason digest.
- Security reads and enrollment share one re-entrant state lock. Enrollment uses the internal clock and resamples the live channel bounds plus exact bookmark under that lock immediately before persistence; concurrent append, clear, or refill invalidates the approval window.
- A separate host-bound, HMAC-chained append-only high-water records monotonically increasing cursor sequence and same-generation record/high-water progress, the cursor HMAC, gap digest, and consumed approval. Cursor/high-water mismatch, sequence regression, missing anchor, or an interrupted two-file transaction remains incomplete.
- Exact inert evidence: replaying generation 1's signed approval after a detected generation 2 reset fails before and after restart; only a newly signed generation-2 state approval can enroll it. Restoring an older valid cursor plus its matching old fake Security-channel snapshot while leaving the independent high-water current is detected as rollback and remains health 45 through another restart.
- Boundary: software-only state cannot prove rollback when an attacker restores the cursor, the complete independent high-water history, the protected signing authority, and the host telemetry snapshot together. A TPM-backed monotonic counter or externally retained transparency witness is required for that stronger whole-host rollback claim.

### Second-pass gates

| Gate | Result |
|---|---|
| `py_compile` for A01, A16, and the dedicated test | `PASS` |
| Ruff for the same scope | `PASS` |
| A01 and A16 inert module self-tests | `PASS` |
| Dedicated High-A suite | `PASS` — `19 passed` |
| Dedicated + affected Adversary Combat + ETW suites | `PASS` — `64 passed` |

## C27-R1-A01 — Uncertain non-reversible mutation

- **Status:** `FIXED`
- **Change:** `src/angerona/modules/adversary_combat.py` establishes the uncertainty boundary after the durable intent and before invoking `kill()`. Any exception or non-definitive postcondition after that boundary appends a signed, non-terminal `orphan` with `mutation_started=true`, immediately opens the mutation circuit, sets health to `RECOVERY REQUIRED`, and remains pending across restart. It is never automatically terminalized or re-armed.
- **Operator closure:** only the existing fresh, exact, HMAC-valid human `response.execute` disposition can append the terminal `operator_disposition`; service, stale, altered, wrong-scope, and wrong-action receipts fail closed.
- **Independent replay:** an inert process set `killed=true` and then raised from `is_running()`. The result is now `journal=[intent, orphan]`, `mutation_blocked=true`, `health=0`; a new module instance reconstructs the same pending recovery state.
- **Gates:** compile `PASS`; Ruff `PASS`; inert self-test `PASS`; focused regressions `PASS`.

## C27-R1-A10 — Detector-producer authority for Chaos assurance

- **Status:** `FIXED`
- **Authority:** new `src/angerona/core/assurance_receipts.py` gives the manager a private broker. The manager enrolls only the exact registered built-in detector object/capability and hands that object a detector-specific issuer. Its per-enrollment MAC binds capability ID, detector code/name, lifecycle generation, random source epoch, one-time probe nonce, challenge, exact target/evidence digest, observation, and timestamp. The broker verifies registry object identity and consumes each challenge once.
- **Consumer:** `src/angerona/modules/chaos_harness.py` still requires the armed bus and rejects self/practice/stale/malformed records, but bus HMAC and display names are no longer treated as producer identity. A receipt must pass the independent manager broker.
- **Genuine producer paths:** APID issues only after every watched live prologue was compared; FIM hashes the exact watched marker path; native AMSI actually scans EICAR and requires `DETECTED`. NDRD currently sees caller-described DNS only through the shared bus, so it intentionally issues no receipt and exposes 75% source-assurance health. Default observation-only AMSI likewise remains unassured. Chaos therefore reports these legs failed instead of manufacturing green health.
- **Independent replay:** an unrelated publisher supplied every allowlisted public field through the shared EventBus and received a valid bus HMAC. Its fake producer MAC/source epoch is rejected. The dedicated tests also prove an impostor object cannot use a real detector's issuer, while one exact APID observation produces a valid one-time receipt.
- **Files:** `src/angerona/core/assurance_receipts.py`, `src/angerona/core/module_manager.py`, `src/angerona/modules/chaos_harness.py`, `src/angerona/modules/api_patch_detector.py`, `src/angerona/modules/network_protocol_decoder.py`, `src/angerona/modules/file_integrity.py`, `src/angerona/modules/amsi_bridge.py`, and `tests/test_cycle27_round1_high_a.py`.
- **Gates:** compile `PASS`; Ruff `PASS`; all affected module self-tests `PASS`; focused regressions `PASS`.

## C27-R1-A16 — Restart-safe Security-channel continuity

- **Status:** `FIXED`
- **Durable cursor:** `src/angerona/modules/etw_listener.py` now atomically persists a strict cursor document containing channel, host binding, sequence, generation, exact record bookmark/anchor, sampled oldest/high watermark, gap reason, enrollment time, and update time. The document uses an HMAC key derived from the installation EventBus authority plus a host/state-root binding. Unsafe file objects, malformed schemas, invalid values, MAC failure, and host mismatch are rejected.
- **Fail-incomplete semantics:** missing or unverifiable state never becomes green merely by replaying retained records. Clear/empty/refill, numeric reset, retention loss, record reuse, anchor mismatch, or an unread record persists a continuity gap across future process restarts. Cursor progress is persisted only after observed records and never advances past an unread record.
- **Safe enrollment:** clearing a gap requires a fresh, exact, HMAC-valid human `policy.approve` receipt for `telemetry/security-channel` and resource `Security`. Enrollment is accepted only when a successful bounds sample is at most 30 seconds old, the reader has no backlog, and its bookmark equals the sampled high watermark; the new clean baseline must then persist successfully.
- **Independent replay:** generation one records 50–55 were enrolled, the fake channel was cleared/refilled with generation two records 1–4, and a brand-new listener loaded the durable cursor. It replayed 1–4 but remained health 45 with a persisted reset gap; another restart remained degraded. Tampered and other-host cursor copies likewise remained incomplete.
- **Gates:** compile `PASS`; Ruff `PASS`; self-test `PASS`; focused regressions `PASS`.

## Gate evidence

| Gate | Result |
|---|---|
| `py_compile` for nine changed product files plus the dedicated test | `PASS` |
| Ruff for the same product/test scope | `PASS` |
| Seven affected module `self_test()` calls in inert state fixtures | `PASS` |
| Dedicated High-A suite | `PASS` — `15 passed` |
| Dedicated + Adversary Combat + ETW affected suites | `PASS` — `60 passed` |
| Module-manager/capability assurance and contract suites | `PASS` — `22 passed` |
| Total focused/regression tests | `PASS` — `82 passed` |
| `git diff --check` for owned files | `PASS` (line-ending notices only) |
