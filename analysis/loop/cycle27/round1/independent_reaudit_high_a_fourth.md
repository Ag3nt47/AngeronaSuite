# Cycle 27, Round 1 — Fourth Independent High-A Re-audit

Scope was limited to the fourth remediations for `C27-R1-A01` and
`C27-R1-A16`. Validation was defensive, local, and inert. It used temporary
directories, an in-memory protected-anchor stand-in, fake process/journal
state, an in-memory EventBus, and a fake Windows Security channel. No live
process was terminated, no host event log or policy was changed, no network
target was contacted, and no product or test code was edited.

The fourth remediation closes the third audit's malformed-terminal,
outcome/reason, wall-clock, old-challenge, two-file deletion, current-anchor
rollback, and during-commit record-replacement paths. It does not yet close the
findings. A01 still forgets an uncertain mutation when its journal and protected
anchor are deleted or rolled back together. A16's retained-record identity is
not a full-record identity: content after character 4096 in an insertion string
and insertion strings after item 64 are omitted, allowing a replacement channel
to remain green indefinitely. Additional durability and multi-writer weaknesses
are recorded below.

| Original finding | Independent verdict | Residual severity | What held | Residual bypass |
|---|---|---:|---|---|
| `C27-R1-A01` | **REOPENED / PARTIAL** | MEDIUM | Complete terminal schema validation, selected disposition/reason binding, process-monotonic expiry, restart challenge invalidation, one-time concurrent consumption, and one-sided journal/anchor loss all fail closed. | Deleting both the journal and protected anchor, or restoring both to a pre-action snapshot, is treated as a fresh installation. Restart has no pending action, reports health 100, and re-arms while the journal signing key is unchanged. |
| `C27-R1-A16` | **REOPENED / PARTIAL** | HIGH | Old approval after all-state deletion, one-sided/adjacent-state rollback, malformed high-water, static hard-link objects, during-commit replacement, and next-poll replacement detection all fail incomplete. | Truncated/omitted event fields collide under the saved channel digest and survive restart at health 100 with zero replay. A protected-anchor/cursor/high-water/channel snapshot rollback is accepted, live cursor/high-water loss remains green until restart, and an uncoordinated second writer can return successful enrollment over a corrupt durable chain. |

## `C27-R1-A01` — Complete record semantics hold, but paired authority loss re-arms

### Controls independently verified

- `src/angerona/modules/adversary_combat.py:2259-2427` now validates the exact
  orphan, challenge, terminal field set, action/combat identity, status,
  allowlisted disposition, normalized reason and digest, complete signed
  authorization decision, resource, principal, permission, scope, and every
  challenge binding. Independently appended HMAC-authentic variants with a
  wrong reason, reason digest, resource, request ID, non-finite disposition
  time, or extra field all restarted with `blocked=true`, `health=0`, and the
  orphan still pending. The dedicated suite also covers wrong action, combat
  ID, status, and disposition.
- The approval resource binds the selected outcome and normalized reason. A
  different outcome or reason is rejected.
- Moving wall time backward after advancing the process-monotonic clock beyond
  the 300-second challenge deadline did not revive the decision.
- Restart issued a distinct nonce/counter resource and rejected the old exact
  decision. Two simultaneous consumers of one live challenge produced exactly
  one success and one rejection.
- Removing only the journal while retaining the anchor, or removing only the
  anchor while retaining the journal, made `_reconcile_state()` fail with the
  mutation circuit blocked.

### Residual: journal and protected anchor have no surviving installation witness

`_recovery_anchor()` at
`src/angerona/modules/adversary_combat.py:1550-1562` creates a new random anchor
whenever the anchor is absent and the journal currently has no records.
`_read_journal()` at lines 1684-1692 supplies that empty-record condition when
the journal path is absent. Startup reconciliation at lines 2607-2620 first
clears the in-memory circuit and has no remaining evidence from which to
reconstruct the uncertain mutation.

Two independent inert variants reproduced the same result:

```text
before rollback: journal=[intent, orphan], blocked=true, pending=true

delete journal + delete protected anchor:
  reconcile=true, blocked=false, pending=false, health=100
  journal signing key unchanged=true, new anchor created=true

restore pre-action empty journal + matching pre-action protected anchor:
  reconcile=true, blocked=false, pending=false, health=100
  journal signing key unchanged=true
```

The Windows production anchor is an authenticated value in Angerona's
current-user DPAPI-backed secret map, not an ordinary unprotected sidecar.
Consequently this is not an unprivileged file edit: it requires the ability to
delete or restore both the action journal and protected-store state. That is a
material mitigation and keeps the residual at **MEDIUM**. It nevertheless
matches the requested elevated local-state/snapshot adversary and needs no
journal HMAC forgery or operator decision. The current implementation also
cannot distinguish the pair deletion from first installation.

### Recommendation

Do not create a recovery anchor merely because both visible objects are empty.
Create it transactionally during installation and retain an independently
witnessed installation/key-birth marker; if an established installation
authority exists while the recovery anchor is missing, keep Combat disarmed.
For rollback resistance, bind the latest journal/anchor sequence to a TPM NV
counter or externally administered append-only witness. If neither exists,
keep the paired protected-state rollback boundary explicit and do not present
Combat as fully recovery-assured against an elevated snapshot adversary.

## `C27-R1-A16` — Full-record continuity is still bypassable

### Controls independently verified

- Cursor schema v3, high-water schema v2, and the protected rollback anchor
  reject one-sided cursor/high-water rollback, an absent or malformed half of a
  transaction, and an altered HMAC. A deliberately truncated high-water JSON
  restarted at health 45 and replayed records 1-4.
- Deleting cursor, high-water, and protected anchor together created a new
  random install epoch/challenge. The old approval resource changed, the old
  decision was rejected, and health remained 45 pending a fresh approval.
- `_safe_cursor_file()` accepts an ordinary single-link file and rejected an
  inert two-link hard-link object. The code also rejects symlink/reparse flags.
- A replacement made during the durable enrollment transaction is detected by
  the post-commit identity sample and remains health 45 across restart.
- A replacement made immediately after that final sample produced a temporary
  health-100 result, but the next Security poll detected it, replayed records
  1-4, and returned to health 45. This is a bounded observation-latency limit,
  not the permanent bypass below.

### Residual 1 (HIGH): the channel digest omits security-event content

`_record_anchor()` at `src/angerona/modules/etw_listener.py:1307-1329` hashes
only selected fields. It truncates generated/source/computer strings, retains
only the first 64 `StringInserts`, and retains only the first 4096 characters
of each insert. `_channel_identity()` at lines 1066-1101, bookmark validation
at lines 1355-1367, and saved-identity validation at lines 1418-1426 all depend
on that lossy anchor.

The independent fake channel preserved record number, event ID, time, source,
computer, category, and the first 4096 characters of a process-event insertion
but changed its tail. A second variant preserved the first 64 inserts but
changed insert 65. Both pairs had equal `_record_anchor()` values even though
their full event content differed:

```text
4096-character-tail replacement:
  anchor collision=true, changed full value=true
  restart health=100, gap="", emitted=[]

65th-insert replacement:
  anchor collision=true
  restart health=100, gap="", emitted=[]
```

This is not a SHA-256 collision. It is a deterministic collision in the data
fed to SHA-256. Under the same privileged channel-replacement threat used by
the original finding, changed content outside the selected window is never
replayed or disclosed, so A16 remains **HIGH**.

Hash a canonical, length-delimited representation of every complete event
field consumed or relied on downstream, including every full insertion string
and relevant native record metadata. Apply a total byte/record budget before
claiming completeness; an oversize or unrepresentable record must stop the
bookmark and remain below 100 rather than being silently truncated. Where the
API permits it, prefer hashing the complete native event bytes plus the parsed
representation.

### Residual 2 (MEDIUM): restoring the protected witness with local state is accepted

The anchor detects an old cursor/high-water pair only while a newer protected
anchor survives. Restoring the enrolled cursor, high-water, protected-anchor
value, and matching older channel snapshot—without changing the stable EventBus
or cursor HMAC key—produced:

```text
bookmark=5, emitted=[], gap="", health=100
```

The remediation correctly discloses that software-only state cannot prove a
whole protected-store/channel rollback. This is therefore an architectural
residual, not a failure of the stated HMAC. It remains relevant to the requested
elevated snapshot adversary. A TPM monotonic counter or independently
administered transparency/high-water service is required before claiming
rollback resistance across this boundary.

### Residual 3 (MEDIUM): live durable-state loss can remain health 100

The no-change fast path at
`src/angerona/modules/etw_listener.py:963-980` verifies only the cached cursor
HMAC against the protected anchor; it does not verify that the cursor and
high-water objects still exist and match. After deleting both files from a live
enrolled instance, an unchanged poll remained health 100. After appending one
new channel record, `_append_highwater()` at lines 698-765 created a new file
starting at the old in-memory entry sequence and previous HMAC, returned true,
and the module still reported health 100 even though that file could not be
verified from genesis:

```text
after cursor/high-water deletion, unchanged poll: health=100
after record 4 append: emitted=[4], health=100
restart: health=45, gap=true, replayed=[1,2,3,4]
```

Re-check the exact cursor and high-water file objects and authenticated tails
before taking the no-change fast path. If the high-water file is absent while
the in-memory entry sequence is nonzero, fail incomplete instead of creating a
non-genesis first entry. Hold and validate descriptor identities across every
append, then re-read the completed cursor/high-water/anchor transaction before
returning success or health 100.

### Residual 4 (LOW): no module-local multi-writer transaction lease

Two independently instantiated listeners sharing one state root and protected
anchor were synchronized at their high-water append. One enrollment returned
`ok=true` and health 100 while the other failed. A fresh instance then rejected
the resulting chain with `cursor high-water authentication failed`, replayed
records 1-4, and stayed health 45.

The authenticated OS-backed application singleton materially reduces ordinary
production reachability, and restart failed incomplete rather than losing the
records. This keeps the residual **LOW**. The module itself is still unsafe when
embedded, duplicated during an abnormal lifecycle transition, or invoked by a
second in-process owner. Add a state-root-scoped OS file lease around the whole
cursor/high-water/anchor transaction, and reject a writer generation that does
not own that lease.

## Gate evidence

- Focused dedicated and affected Adversary Combat suites: `85 passed in 26.89s`.
- `py_compile`: pass for both product modules and the dedicated High-A test.
- Ruff: pass for the same scope.
- Inert module self-tests: `2 passed` (Combat armed-state contract and ETW 4688
  decoder).
- `git diff --check`: pass for the affected source/test scope (line-ending
  notices only).
- Independent hostile matrices: A01 malformed/replay/race/clock/single-loss
  controls held, but paired journal/anchor loss re-armed; A16 all-state deletion
  and malformed state held, but lossy event identity, protected-state rollback,
  live durability loss, and multi-writer commit residuals reproduced.
- Final verdicts: **A01 REOPENED / PARTIAL (MEDIUM)**; **A16 REOPENED / PARTIAL
  (HIGH)**.
