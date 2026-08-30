# Cycle 27, Round 1 — Sixth Independent High-A Re-attack

Scope was limited to the sixth remediations for `C27-R1-A01` and
`C27-R1-A16`. Every hostile check was defensive, local, and inert. It used
temporary directories, in-memory protected-store stand-ins, fake action
records, an in-memory EventBus, and a fake Windows Security channel. No live
process was terminated, no host event log or policy was changed, no network
target was contacted, and no product or test code was edited.

The sixth changes close the fifth audit's exact **surviving-witness** legacy
replay, ordinary cross-thread/cross-process duplicate-writer race, and static
hard-link journal append. They do not close either original finding. Both
legacy migrators still use *witness absence* as proof that an installation is
pre-upgrade. Deleting the current witness and replaying the same copied legacy
snapshot therefore recreates and lowers the witness without restoring or
forging it. Combat also releases journal-object custody after its final reread,
so a path removal can occur before `_journal_intent()` returns success and the
irreversible mutation boundary is crossed.

| Original finding | Independent verdict | Residual severity | What held | Residual bypass |
|---|---|---:|---|---|
| `C27-R1-A01` | **REOPENED / PARTIAL** | MEDIUM | A surviving witness blocks schema-1 replay; current-schema witness loss, old-witness/key substitution, partial commits, ordinary duplicate writers, static hard links, malformed terminals, approval replay, and wall-clock rollback fail closed. | Delete the current witness and replay a copied schema-1 anchor plus matching old journal: migration recreates a lower witness and re-arms at health 100. A post-final-read journal removal also returns durable-intent success with no canonical journal, and the journal reader has no byte/line/depth budget. |
| `C27-R1-A16` | **REOPENED / PARTIAL** | HIGH | A surviving witness blocks legacy replay; current-schema witness loss, old-witness/key substitution, all three partial-commit positions, record-identity budgets, and writer contention/crash recovery fail incomplete and replay telemetry. | Delete the current authority witness and replay a copied schema-1 anchor/cursor/high-water/channel snapshot: migration recreates a lower witness, emits no rolled-back records, and reports health 100. |

## `C27-R1-A01` — Witness loss still enables a legacy downgrade

### Controls independently verified

- With the newer recovery witness present, the copied schema-1 anchor/journal
  replay is rejected at health 0 and the witness remains byte-identical. The
  genuine pre-witness migration regression also remains green.
- The state-root process/OS lease rejects a live writer in another process,
  releases after forced process exit, and cannot be path-replaced while held on
  the Windows host. The two-instance thread regression leaves one successful
  sequence-1 record and one rejected writer.
- A two-link journal path is rejected before the unrelated file receives a
  byte. Older-witness substitution and journal-key substitution both restart
  at health 0.
- An interruption after journal append but before protected-anchor advance
  restarts at health 0 with an incomplete-anchor error. An interruption after
  anchor advance but before witness advance restarts at health 0 with a witness
  mismatch.
- Complete terminal semantics, outcome/reason binding, process-monotonic
  challenge expiry, restart invalidation, and one-time consumption remained
  green in the wider 94-test Combat/ETW gate.

### Residual 1 (MEDIUM): deleting the witness re-enables schema-1 migration

`_read_recovery_witness()` returns `None` for an absent file at
`src/angerona/modules/adversary_combat.py:1679-1688`. The schema-1 branch at
`src/angerona/modules/adversary_combat.py:1916-1954` treats only a *present*
witness as the upgrade floor. If the file is absent, it rewrites the legacy
anchor as schema 2 and creates a replacement witness at the legacy tail.

The independent reproduction saved an authenticated schema-1 empty anchor,
advanced the journal through an irreversible `intent`/`orphan`, then removed
the current witness and restored the copied legacy anchor and empty journal:

```text
reconcile=true
health=100
mutation_blocked=false
pending={}
journal_error=""
witness_recreated=true
witness_lowered=true
migrated_anchor_schema=2
```

This is narrower than the disclosed whole-local-snapshot boundary. The current
signing key was retained, and no old/current witness was restored or forged;
the migration path itself interpreted deletion as proof of a pre-witness
installation. Runtime migration can fail closed here without TPM support by
refusing schema 1 and routing legitimate upgrades through an explicit,
audited migration/recovery operation.

### Residual 2 (LOW): final reread does not retain journal custody through success

`_read_pinned_journal_bytes()` pins a file only for one read at
`src/angerona/modules/adversary_combat.py:2098-2153`. `_append_journal()` then
performs its final reread at lines 2317-2327, closes that descriptor, and
returns. The state-root writer lease locks a separate one-byte lease object; it
does not deny removal or replacement of the journal itself.

The inert path-swap reproduction removed the journal immediately after the
final strict reread returned its verified record list but before
`_append_journal()` evaluated that in-memory list:

```text
_journal_intent outcome=SUCCESS_RETURNED
signed record had been fsynced=true
canonical journal missing at success=true
protected anchor sequence=1
restart reconcile=false
restart health=0, mutation_blocked=true
```

The restart is correctly fail-closed, which limits severity. However,
`_terminate_process_transaction()` crosses the irreversible `kill()` boundary
immediately after `_journal_intent()` returns at
`src/angerona/modules/adversary_combat.py:2583-2608`. A privileged state-root
racer can therefore make an irreversible action proceed after the exact
durable intent has disappeared. A related between-read/append swap appended
552 bytes of signed journal data to a single-link inert sentinel file; final
verification rejected it and restart blocked, but the alternate file still
received the privileged append.

### Residual 3 (LOW): the journal parser is unbounded before authentication

`_read_pinned_journal_bytes()` reads the complete journal into a chunk list
without a maximum byte count, and `_read_journal()` decodes/splits the complete
value before parsing every line at
`src/angerona/modules/adversary_combat.py:2124-2143` and `:2234-2287`. Unsigned
prefix lines are accepted as legacy/display-only input before the signed chain.
An 8,002-byte, deeply nested unsigned JSON line raised an uncaught
`RecursionError` out of `_reconcile_state()` rather than producing the
documented health-0 integrity result. Arbitrarily large prefixes also cause
unbounded read/decode/split allocation before HMAC verification. The base
worker eventually records crashes and quarantines the module, so this is an
availability weakness rather than a mutation bypass.

### A01 recommendation

- Do not auto-migrate schema-1 state in the runtime. Use a separate, explicit
  upgrade/recovery transaction, rotate or purpose-separate the schema-2
  authority, and make every later schema-1 observation fail closed. Preserve
  the disclosed TPM/external-witness ceiling for rollback of *all* schema-2
  state.
- Keep a descriptor-pinned journal object and the installation writer lease
  alive through the host mutation and terminal record, or return a transaction
  guard whose custody cannot be released before the caller crosses that
  boundary. Bind the append object to the identity and exact size read at the
  start of the transaction.
- Add strict journal byte, record, line, nesting, and decode-time budgets;
  stream bounded lines; reject unsigned legacy prefixes after controlled
  migration; and convert parser/resource failures into an explicit health-0
  circuit state.

## `C27-R1-A16` — Missing-witness legacy replay erases Security continuity

### Controls independently verified

- A copied schema-1 protected anchor is rejected while the newer authority
  witness remains present; its bytes do not change. A current schema-2 anchor
  with a missing witness also fails incomplete at health 45 and replays records.
- Restoring an older witness alone or substituting the EventBus/cursor signing
  key fails authentication at health 45 and replays the retained channel.
- Forced interruption after high-water append, after cursor replacement, or
  after protected-anchor replacement produced health 45 on both the current
  instance and restart. Each restart replayed records 1-4 and named the exact
  cursor/high-water/anchor/witness mismatch.
- Complete length-delimited record identity and the exact insertion, byte,
  record, and elapsed-time boundaries remained green. No tested field/insertion
  collision or silent over-budget completion returned.
- The OS writer lease rejected a competing process, released after forced
  process exit, and rejected the existing multi-link/duplicate-writer cases.

### Residual 1 (HIGH): witness deletion is accepted as a pre-upgrade install

`_read_authority_witness()` returns `None` for an absent witness at
`src/angerona/modules/etw_listener.py:509-518`. `_rollback_anchor()` at lines
729-760 rejects schema 1 only when that read returns an object; otherwise it
automatically calls `_write_rollback_anchor()`, whose lines 763-770 replace the
anchor and create a new witness at the old authority revision.

The independent reproduction enrolled records 1-3, saved the matching
schema-1 anchor/cursor/high-water/channel, advanced live state through records
4-6, deleted only the current witness, and restored the copied legacy state:

```text
emitted=[]
health=100
gap=""
cursor_enrolled=true
bookmark=3
cursor_sequence=1
witness_recreated=true
witness_lowered=true
migrated_anchor_schema=2
```

The attack needs privileged Security-channel/protected-state rollback and an
authentic pre-upgrade snapshot, so the existing single-host mitigations still
matter. It does not need the current signing key, HMAC forgery, a restored old
witness, or a new enrollment approval. The module can distinguish this case by
never treating a legacy anchor as runtime enrollment authority; automatic
migration is what converts a detectable missing witness into health 100.

### A16 recommendation

- Reject schema 1 in the running sensor even when the witness is missing.
  Perform legitimate migration only in an explicit installer/operator flow
  that establishes a new schema-2 authority and forces a complete channel
  replay or audited enrollment before health can recover.
- Preserve the full event identity, honest limits, live durable-state checks,
  high-water/cursor/anchor/witness commit order, and OS writer lease; each
  resisted its targeted hostile variant.
- Continue declaring the whole-host snapshot ceiling unless TPM monotonic state
  or an independently administered append-only witness is configured.

## Disclosed architectural boundary

Restoring every schema-2 local object remains accepted: A01 re-armed when the
journal, protected anchor, and recovery witness were all restored together;
A16 emitted no records and reported health 100 when cursor, high-water,
protected anchor, authority witness, and matching channel were all restored.
The stable signing identities were also retained. This is the documented
same-host rollback boundary and is not counted as a new finding. TPM NV or an
external append-only authority is required to distinguish that complete
snapshot. It does not excuse the missing-witness legacy downgrade above,
because runtime refusal of schema 1 would fail closed in that narrower case.

## Gate evidence

- Sixth-remediation regressions: **6 passed**.
- Sixth regressions plus all directly affected Combat/ETW suites: **94 passed
  in 51.31s**.
- Independent hostile matrices: surviving/current/older witness, key
  substitution, schema-1-with-witness-deletion, three partial-commit positions,
  cross-process contention/crash release, final-read/path-swap, parser-depth,
  and full-local-snapshot cases completed using temporary fixtures.
- `py_compile`: passed for both product modules and the sixth-remediation test.
- Ruff: passed for both product modules and the sixth-remediation test.
- Inert module self-tests: **2 passed** (Combat armed-state contract and ETW
  4688 decoder).
- Final verdicts: **A01 REOPENED / PARTIAL (MEDIUM)**; **A16 REOPENED / PARTIAL
  (HIGH)**.
