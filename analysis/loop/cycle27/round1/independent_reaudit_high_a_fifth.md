# Cycle 27, Round 1 — Fifth Independent High-A Re-attack

Scope was limited to the fifth remediations for `C27-R1-A01` and
`C27-R1-A16`. All attacks were defensive, local, and inert. They used temporary
directories, in-memory protected-store stand-ins, fake process/action records,
an in-memory EventBus, and a fake Windows Security channel. No live process was
terminated, no host event log or policy was changed, no network target was
contacted, and no product or test code was edited.

The fifth pass closes the fourth audit's ordinary paired-loss, lossy-record,
live-file-loss, and duplicate-writer bypasses within its stated local-witness
boundary. It does **not** close either original finding. Both schema-2 anchors
still accept an authenticated schema-1 predecessor, then overwrite the newer
independent witness during migration. Restoring a copied legacy anchor and its
matching old journal/cursor state therefore erases a later high-water without
deleting, restoring, or forging the new witness. A01 also still has no
state-root writer lease and appends through an unpinned multi-link journal path.

| Original finding | Independent verdict | Residual severity | What held | Residual bypass |
|---|---|---:|---|---|
| `C27-R1-A01` | **REOPENED / PARTIAL** | MEDIUM | Paired journal/anchor deletion or rollback is rejected while the new witness survives; copied witness, signing-key substitution, valid-HMAC malformed witness, partial commits, malformed terminals, approval replay, and clock rollback fail closed. | Replaying a copied HMAC-valid schema-1 anchor plus its matching old journal causes migration to overwrite the newer schema-2 witness. Restart forgets the uncertain irreversible mutation and re-arms. Two uncoordinated module instances can also both report a successful append over a duplicate-sequence journal, and a planted hard link receives privileged journal appends. |
| `C27-R1-A16` | **REOPENED / PARTIAL** | HIGH | Complete field/insertion identity, explicit record/byte/time bounds, live authority verification, partial-commit detection, copied-witness/key substitution rejection, and the state-root OS writer lease all held. | Replaying a copied HMAC-valid schema-1 protected anchor with its matching old cursor/high-water/channel causes migration to overwrite the current authority witness. Restart emits no rolled-back events and reports health 100. |

## `C27-R1-A01` — Legacy migration can roll the new high-water backward

### Controls independently verified

- The fifth witness does stop the exact fourth bypass. With an authenticated
  `intent`/`orphan` pending, deleting the journal and protected anchor together,
  or restoring both to their pre-action values, left the newer witness in
  place. The dedicated regression restarted blocked at health 0 with a witness
  mismatch.
- Restoring an older witness alone failed with
  `combat journal/anchor rollback violates the signing-key witness`. Replacing
  the journal signing key while retaining current state failed journal
  authentication. A deliberately malformed witness with a correct HMAC but a
  negative journal sequence was rejected.
- Interrupting the journal/anchor/witness transaction immediately before the
  protected-anchor write left the journal ahead of the anchor and restarted at
  health 0. Interrupting it after the anchor write but before the witness write
  left an anchor/witness mismatch and also restarted at health 0.
- Complete terminal semantics, selected outcome/reason binding, process-
  monotonic expiry, restart challenge invalidation, one-time consumption, and
  wall-clock rollback regressions all remained green in the 41-test dedicated
  suite.

### Residual 1 (MEDIUM): schema-1 replay overwrites a newer witness

`_decode_recovery_anchor()` accepts both schema 1 and schema 2 at
`src/angerona/modules/adversary_combat.py:1513-1535`. After only comparing the
anchor tail to the restored journal, `_verify_recovery_anchor()` treats every
schema-1 value as migratable at lines 1789-1798. It writes a schema-2 anchor and
then unconditionally calls `_write_recovery_witness()`, replacing the
independent witness whose purpose is to prove that a later tail existed.

The independent reproduction created a valid legacy snapshot from the initial
empty tail, advanced the live schema-2 journal to an uncertain irreversible
`intent`/`orphan`, and then restored only the copied schema-1 anchor and its
matching empty journal. The newer witness was deliberately left untouched at
the start of the attack:

```text
before replay:
  journal=[intent, orphan]
  witness advanced=true
  blocked=true, health=0

restore copied schema-1 anchor + matching empty journal:
  reconcile=true
  blocked=false
  pending={}
  journal_error=""
  witness overwritten by migration=true
  migrated anchor schema=2
```

This requires a copied authentic pre-upgrade anchor/journal snapshot and the
ability to restore protected local state. It does not require the current
journal key, a forged HMAC, deletion/restoration of the new witness, or a human
recovery decision. DPAPI and the protected data-root ACL materially raise the
bar over an unprivileged file edit, so the residual remains **MEDIUM** under the
requested elevated local-state/snapshot adversary.

### Residual 2 (LOW): the action transaction has no cross-instance writer lease

The receipt lock created at
`src/angerona/modules/adversary_combat.py:826` is instance-local. Journal read,
append, protected-anchor advance, and witness advance at lines 1981-2003 are not
covered by a state-root-scoped OS lease. Two module instances were forced to
read the same empty tail before either appended. Both returned success for a
different sequence-1 intent; the file contained two lines with the same
sequence/previous HMAC, and a fresh instance rejected line 2 at health 0:

```text
writer successes=[1, 2]
journal lines=2
restart reconcile=false
restart blocked=true, health=0
error="journal integrity failure at line 2"
```

The corruption fails closed on restart and the normal suite singleton reduces
reachability, so this is **LOW** rather than an integrity bypass. It is still a
real false-success and availability weakness for duplicate/embedded owners or
an abnormal two-process lifecycle.

### Residual 3 (LOW): the journal append follows a planted hard link

Unlike the new witness reader, `_read_journal()` at lines 1909-1979 uses
path-based `is_file()`/`read_text()`, and `_append_journal()` opens the same path
with ordinary append mode at lines 1981-2003. It does not require a regular,
single-link, non-reparse, descriptor-pinned object.

An inert same-volume hard link from the predictable receipt path to an
unrelated temporary file had link count two. Reconciliation accepted it, and
`_journal_intent()` appended 620 bytes of signed JSON to the unrelated file.
The protected parent ACL limits this to an actor able to plant a link in the
state root, and the payload is constrained journal JSON, so the residual is
**LOW**. It nevertheless gives an elevated local attacker a privileged append/
corruption primitive and violates the custody standard used for the witness.

### A01 recommendation

- Never overwrite an existing schema-2 witness while migrating schema 1.
  Reject a schema-1 anchor whenever any newer witness/upgrade marker exists.
  If legacy compatibility is mandatory, perform migration through a one-time,
  non-replayable schema-floor transaction anchored outside the rollback set;
  otherwise require explicit recovery rather than auto-migration.
- Put journal read, append, anchor advance, witness advance, and final reread
  under one state-root-scoped OS writer lease. A caller must not receive success
  until the complete transaction rereads consistently.
- Open the journal with no-follow semantics, require a single-link regular file,
  pin and compare its identity before/after read and append, and reject unsafe
  parent/reparse topology before creating it.

## `C27-R1-A16` — Legacy migration erases current Security continuity

### Controls independently verified

- Full length-delimited identity now covers every tested native/consumed field:
  record number, event ID/type/category, reserved flags, closing record number,
  generated/written time, source, computer, SID, binary data, and every full
  insertion. Changing content after character 4096, insertion 65, insertion
  4096, or any listed scalar changed the record anchor.
- Exact boundaries were honest: 4096 insertion strings and a record identity of
  exactly 4,194,304 framed bytes were accepted; insertion 4097 and byte
  4,194,305 failed incomplete. A 4,096-record retained identity completed;
  record 4,097 returned incomplete. The exact 1.5-second boundary completed,
  while 1.500001 seconds returned incomplete.
- Losing the live cursor, high-water, protected anchor, or authority witness was
  visible on the same process poll at health 45. Restoring an old witness alone,
  substituting the EventBus/cursor signing key, and supplying a malformed but
  correctly HMACed witness all remained health 45 and replayed rather than
  claiming continuity.
- Commit interruption after high-water append, after cursor replacement, or
  after protected-anchor replacement restarted at health 45. Each variant
  replayed records 1-4 and named the exact cursor/high-water/anchor/witness
  mismatch.
- The in-process and OS writer lease serialized two module writers: the
  dedicated race produced exactly one success and one rejection, with a fresh
  instance at health 100. A separate process could not acquire the byte-range
  lock while the holder was alive. A forced child exit released the OS lock and
  allowed the next owner to acquire it. A two-link lease object was rejected as
  unsafe; the host did not permit creation of a test symlink, while the code's
  lstat/reparse checks remain present.
- Restoring cursor/high-water/protected anchor/channel without restoring the
  authority witness failed at health 45, closing the exact fourth paired-state
  rollback.

### Residual 1 (HIGH): schema-1 replay overwrites the current authority witness

`_decode_rollback_anchor()` accepts schema 1 or 2 at
`src/angerona/modules/etw_listener.py:642-694`. `_rollback_anchor()` at lines
729-753 treats every valid schema-1 value as a migration candidate. It calls
`_write_rollback_anchor()`, whose lines 755-763 force schema 2 and
unconditionally replace the authority witness. There is no durable schema
floor proving that this installation already completed that migration.

The independent reproduction enrolled records 1-3, saved a valid schema-1
anchor with the matching cursor/high-water/channel, advanced the live schema-2
state through records 4-6, and restored the old schema-1 anchor/cursor/
high-water/channel while deliberately leaving the advanced witness in place:

```text
before replay:
  bookmark=6, cursor sequence=2, witness advanced=true

restore copied schema-1 anchor + cursor/high-water + records 1-3:
  emitted=[]
  health=100
  gap=""
  cursor enrolled=true
  bookmark=3, cursor sequence=1
  current witness overwritten by migration=true
  migrated anchor schema=2
```

This is not the disclosed whole-local-snapshot limitation: the attacker did
not restore, delete, or forge the newer authority witness. The migration code
itself replaced the surviving high-water. The attack needs a copied authentic
legacy snapshot plus privileged Security-channel/protected-state rollback, but
no current signing key or new enrollment approval. It therefore preserves the
original **HIGH** severity for the requested elevated telemetry-erasure
adversary.

### Disclosed architectural boundary independently confirmed

Restoring the cursor, high-water, protected anchor, authority witness, and the
matching older channel snapshot together produced `emitted=[]`, `gap=""`, and
health 100. The journal equivalent likewise re-armed when journal, protected
anchor, and witness were all restored. The signing keys remained the same
because they are stable installation identities.

This is an inherent all-local-witness rollback boundary, not an undisclosed HMAC
failure. The implementation now labels health 100 as continuity only within
that local signing-identity witness boundary. TPM NV monotonic state or an
independently administered append-only witness is required to distinguish a
complete host snapshot rollback. This boundary does not excuse the schema-
migration bypass above, which overwrites a witness the attacker left current.

### A16 recommendation

- Make schema version monotonic. Never auto-migrate a schema-1 anchor over an
  existing authority witness. Bind a non-replayable minimum-schema/upgrade
  marker to TPM NV or an independent witness; absent that authority, reject
  legacy replay and require an explicit, audited recovery enrollment.
- Keep the complete record identity, no-change durable verification, commit
  ordering, final reread, and state-root OS lease unchanged; each resisted its
  targeted hostile variant.
- Continue describing whole-local-snapshot rollback as an explicit assurance
  ceiling unless an external monotonic witness is configured.

## Gate evidence

- Dedicated High-A suite: **41 passed in 11.57s**.
- Dedicated plus all directly affected Combat/ETW suites: **125 passed in
  43.19s**.
- `py_compile`: passed for both product modules and the dedicated test.
- Ruff: passed for both product modules and the dedicated test.
- Inert module self-tests: **2 passed** (Combat armed-state contract and ETW
  4688 decoder).
- Independent hostile matrices: A01 paired loss, copied witness, substituted
  key, valid-HMAC malformed witness, and partial commits held; schema-1 replay,
  duplicate writers, and hard-link journal append reproduced. A16 complete
  field/boundary identity, live loss, partial commits, witness/key rejection,
  and writer-lease contention/crash held; schema-1 replay and the explicitly
  disclosed whole-local-snapshot limit reproduced.
- Final verdicts: **A01 REOPENED / PARTIAL (MEDIUM)**; **A16 REOPENED / PARTIAL
  (HIGH)**.
