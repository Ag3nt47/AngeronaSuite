# Cycle 27, Round 1 — Second Remaining-A Remediation

This pass is limited to the five reopenings in
`independent_hostile_reattack_remaining_a02_a03_a07_a13_a14.{md,json}`. The ten
independent hostile assertions were retained unchanged. All tests use temporary
files, synthetic Defender records, fake event-log APIs, in-memory event buses,
inert canaries, and offline Ed25519 fixtures. No live containment, quarantine
target, Defender channel, driver, registry value, network target, or host policy
was changed. Author validation does not replace a fresh independent re-attack.

## C27-R1-A02 — cache authority is deep-isolated and interior-authenticated

Status: **REMEDIATED — PENDING INDEPENDENT RE-ATTACK**.

- `src/angerona/modules/adversary_combat.py:2716-2790` deep-copies the entire
  parsed authority graph on ingress and egress. Commit-index records are never
  returned by reference, including nested `details` dictionaries and lists.
- The retained cache now holds an HMAC state over every journal byte. Before
  cached authority is admitted, the exact pinned bounded object is reread and
  re-HMACed. A same-size interior edit is rejected even when file metadata and
  the terminal line are unchanged.
- `src/angerona/modules/adversary_combat.py:2973-3000` advances the private HMAC
  state only after the exact append and deep-retains the new signed record.

The independent shallow-mutation assertion passes. A separate regression
forces metadata fingerprints to remain constant, edits an interior signed
value without changing its length, and proves the fast path raises
`JournalIntegrityError` before using cached authority.

## C27-R1-A03 — terminal quarantine proof and retained recovery

Status: **REMEDIATED — PENDING INDEPENDENT RE-ATTACK**.

- Windows quarantine handles request no sharing, and same-volume destination
  identity is verified from the retained handle rather than reopening the path.
- `src/angerona/modules/adversary_combat.py:3062-3110` binds an exact-object
  validator inside the generic signed terminal writer. A hard link introduced
  at the former `_journal_commit` interception point prevents an `applied`
  receipt.
- `src/angerona/modules/adversary_combat.py:3354-3455` keeps every post-move
  topology/digest check and the commit attempt inside one orphan/rollback
  boundary. A fourth/final-check exception either restores the original bytes
  or retains a durable recovery record; it can no longer append an ordinary
  terminal failure for a moved object.

Both independent hard-link/final-check assertions pass unchanged.

## C27-R1-A07 — monotonic cursor, persisted gaps, and crash-honest outbox

Status: **REMEDIATED — PENDING INDEPENDENT RE-ATTACK**.

- `src/angerona/modules/av_telemetry_bridge.py:262-355` creates an independent
  HMAC-authenticated outbox enrollment. A previously enrolled missing database,
  malformed enrollment, or row-integrity failure degrades continuity instead
  of silently creating empty authority.
- Authenticated `coverage_complete=false` is honored at restart and remains
  fail-closed until explicit recovery. Gap creation durably writes incomplete
  coverage even when no later Defender record arrives.
- `src/angerona/modules/av_telemetry_bridge.py:730-765` rejects checkpoint
  regression, conflicting duplicate anchors, and unresolved non-contiguous
  records. One expected record number advances monotonically.
- `src/angerona/modules/av_telemetry_bridge.py:767-873` compares EventBus
  subscriber failure counters across publication, retains the outbox row when
  downstream acceptance fails, and permits health 100 only with complete
  authenticated coverage, no pending/leased/dead-letter row, and no delivery
  error.

The independent persisted-gap and cursor-regression assertions pass. Additional
regressions prove subscriber failure leaves cursor zero plus one pending durable
row across restart, and deletion of an enrolled outbox fails closed.

## C27-R1-A13 — exact canary identity/content and live health

Status: **REMEDIATED — PENDING INDEPENDENT RE-ATTACK**.

- `src/angerona/modules/deception.py:99-158` captures a bounded no-follow
  identity, byte length, nanosecond timestamp, and SHA-256 digest while proving
  the named object remains stable. The public float-mtime map is retained for
  compatibility but is no longer the detection authority.
- `src/angerona/modules/deception.py:231-274` detects same-timestamp replacement
  by identity/content and recalculates coverage after deletion or read failure.
  Zero remaining canaries report health 0 with visibility explicitly
  unavailable.

Both independent replacement and zero-canary health assertions pass unchanged.

## C27-R1-A14 — typed, enrolled, one-use kernel receipts

Status: **REMEDIATED — PENDING INDEPENDENT RE-ATTACK**.

- `src/angerona/modules/driver_provenance_guard.py:110-326` defines a bounded
  typed Ed25519 receipt and verifier. The signature is bound to enrolled
  authority, host, install, and boot identities; load generation; exact object
  identity/base/size/hash; load state; Code Integrity disposition; and a
  five-minute maximum freshness window.
- Receipt identity is consumed atomically once. A replay, wrong image/object,
  stale receipt, wrong enrollment, bad signature, arbitrary digest, or absent
  verifier cannot establish loaded-image binding.
- `src/angerona/modules/driver_provenance_guard.py:521-590` treats an unauthenticated
  binding claim as incomplete. The original digest-only API remains parseable
  for compatibility but has no authority.
- `src/angerona/modules/driver_provenance_guard.py:870-1025` validates provider
  count/completeness/truncation invariants. Empty or inconsistent complete
  collections emit incomplete coverage and remain below green; user-visible set
  wording no longer calls configured-path samples loaded drivers.

All three independent receipt/provider assertions pass. Additional regression
proves a correctly signed receipt verifies exactly once and fails for a
different image.

## Gates

| Gate | Result |
|---|---|
| Unchanged independent hostile contract | `PASS` — `10 passed in 3.08s` |
| New second-pass regressions | `PASS` — `4 passed in 2.87s` |
| Prior remediation + driver compatibility suites | `PASS` — `25 passed` |
| Broad focused affected suites | `PASS` — `165 passed, 1 skipped in 55.42s` |
| `py_compile` for four product modules and affected tests | `PASS` |
| Ruff for four product modules and affected tests | `PASS` |
| Combat armed-state, Deception, driver provenance, and AV telemetry `self_test()` | `PASS` — `4/4` |
| `git diff --check` for affected tracked files | `PASS` (line-ending notices only) |
| Fresh independent hostile re-attack | **PENDING — required before closure** |

## Honest residual boundary

Complete rollback of local journal/cursor/outbox state together with its signing
identity still requires TPM monotonic state or an independently administered
witness. POSIX descriptor custody cannot prohibit a privileged non-cooperating
hard-link operation; it detects topology changes at each signed terminal proof
and fails into recovery. EventBus subscriber counters prove synchronous local
acceptance, not remote storage durability; integrations requiring remote commit
must keep the row pending until their own explicit acknowledgement adapter is
enrolled. Loaded-image provenance remains incomplete unless an independently
enrolled kernel observer supplies a fresh signed receipt.
