# Cycle 27, Round 1 — Seventh Independent High-A Re-attack

Scope was limited to the seventh remediation of `C27-R1-A01` and
`C27-R1-A16`. Every reproduction was defensive and inert: temporary
directories, in-memory protected-store stand-ins, fake process/action objects,
a fake Security channel, an in-memory EventBus, and child processes created
only to hold test leases. No live process, host Security log, firewall, file,
policy, credential, or network target was attacked. Product code was not
edited.

The seventh patch closes its two exact legacy-downgrade bypasses. A valid
schema-1 Combat or Security anchor is rejected before it can become runtime
authority whether the current witness survives or is absent. The new journal
session also holds the canonical descriptor across all seven primary response
effects on Windows, detects hard links and alternate objects, and opens the
non-reversible circuit when custody changes at the fake kill boundary.

Neither original finding is fully closed. Combat's operator undo path is an
eighth host-mutation path outside the new continuous-custody context, and its
protected anchor/witness parsers do not share the bounded journal parser's
failure conversion. ETW durably commits the Security cursor inside
`_read_security_log()` and only publishes the returned events afterwards in
`run()`. A process loss at that exact boundary permanently suppresses the
already-retained events and restarts at health 100.

| Original finding | Independent verdict | Residual severity | What held | Residual bypass |
|---|---|---:|---|---|
| `C27-R1-A01` | **REOPENED / PARTIAL** | LOW | Schema 1 is rejected with and without a witness; strict journal byte/line/record/depth/schema limits held; pre-effect swaps, Windows delete denial, live hard-link detection, partial commits, and process/OS writer leases held. | `undo_action()` releases journal custody between its durable undo intent and `_undo_record()`. Removing the journal there lets the simulated reversal run, the terminal write fail, and health remain 100 with `_mutation_blocked=false`. Deep protected anchor or witness JSON also escapes as `RecursionError` instead of opening the journal circuit. |
| `C27-R1-A16` | **REOPENED / PARTIAL** | MEDIUM | Schema 1 is unconditionally rejected; subset schema-2/mixed rollback, full record identity, three partial-commit positions, and cross-process lease contention/crash release fail incomplete and replay. | Records 4-6 were durably bookmarked before EventBus publication. Simulated process loss before publication caused a fresh listener to emit nothing, retain bookmark 6, report no gap, and return health 100. |

## `C27-R1-A01` — Legacy downgrade is closed; two custody/parser edges remain

### Controls independently verified

- Independently generated authenticated schema-1 recovery anchors failed at
  health 0 with both a surviving witness and a deleted witness. The legacy
  value was not rewritten and no missing witness was recreated.
- Deep and oversized **journal** input, duplicate members, malformed/unsigned
  input, incomplete terminals, non-finite values, wrong record schemas, and
  record/line/byte ceilings remained fail closed in the strict reader. The
  author's deep-prefix and forced-byte-budget tests passed under independent
  execution.
- Read/append and final-read path swaps did not return false success. The
  Windows host denied canonical deletion during the fake irreversible
  `kill()` boundary. A hard link created while that effect was running was
  detected before terminal success and opened the health-0 non-reversible
  circuit.
- Journal-append-before-anchor and anchor-before-witness interruptions both
  restarted at health 0. A second process could not take either Combat or ETW
  writer lease while a live child held it; forced child termination released
  both kernel leases for the next owner.
- Static review confirmed the same `_journaled_mutation()` context encloses
  quarantine, suspend, terminate, remote-IP block, program isolation, host
  isolation, and deception activation. Windows keeps the live journal object
  delete-denying. POSIX retains and identity-checks the descriptor but cannot
  prevent a privileged unlink; the documented platform boundary remains
  accurate.

### Residual 1 (LOW): operator undo drops journal custody before the host effect

`undo_action()` appends `undo_intent` at
`src/angerona/modules/adversary_combat.py:4272-4277`, but that append closes its
descriptor, writer lease, and receipt lock before `_undo_record()` executes at
line 4278. The terminal phase obtains a new session only at lines 4279-4286.
Unlike the seven primary actions, the undo transaction is therefore not one
continuous object-bound mutation.

The inert reproduction committed a valid reversible remote-IP action and
replaced `_undo_record()` with a no-host-effect stand-in. At the exact simulated
effect boundary the stand-in removed the canonical journal; the unlink
succeeded on Windows because no journal descriptor was live. It then reported
that the simulated reversal had completed:

```text
effect_crossed=true
undo result ok=false
error="undo journal commit failed: JournalIntegrityError"
mutation_blocked=false
health=100
```

The protected anchor still prevents the next append from authorizing a new
effect, which limits severity. However, a firewall-rule removal, process
resume, quarantine restore, or deception stop can already have happened, and
`response_ready()`/health do not disclose the orphaned undo in the current
process. This is a safety and audit-integrity gap rather than a new remote
entry point.

Keep the receipt lock, installation writer lease, and one pinned journal
session across trusted-action selection, undo intent, `_undo_record()`,
postcondition, and terminal phase. If the effect may have started and any
terminal/custody check fails, open the in-memory circuit immediately and leave
a recoverable orphan-undo state.

### Residual 2 (LOW): protected authority JSON is not bounded like the journal

The new journal parser is bounded, but `_decode_recovery_anchor()` calls
unbounded `json.loads()` and catches only `TypeError`/`ValueError` at
`src/angerona/modules/adversary_combat.py:1677-1681`.
`_read_recovery_witness()` similarly omits `RecursionError`/`MemoryError` from
its parse conversion at lines 1802-1805 and performs numeric conversions
outside a defensive exception boundary at line 1814. `_reconcile_state()`
converts only `JournalIntegrityError` into the mutation circuit at lines
3548-3554.

Two separate 8,000-byte, 4,000-level inert values—one protected-anchor value
and one descriptor-pinned witness—raised `RecursionError` out of
`_reconcile_state()` while `_mutation_blocked` remained false. The base module
wrapper eventually restarts and quarantines the worker, so no host mutation is
authorized and severity is LOW. It still contradicts the remediation's stated
resource-failure contract and gives a protected-state writer a cheap Combat
availability failure.

Apply one small maximum byte count, duplicate-free JSON loader, maximum depth,
member/container budget, exact primitive schema, and catches for
`MemoryError`, `RecursionError`, decode errors, and numeric conversion errors
to the anchor and witness before authentication. Convert every failure to
`JournalIntegrityError` so reconciliation opens the visible health-0 circuit
without crashing.

### Schema-2 boundary retest (not counted as a new finding)

Deleting the journal, protected anchor, and recovery witness together while
retaining the stable explicit-root signing key still produced a new schema-2
genesis: `reconcile=true`, `blocked=false`, `health=100`, and no pending
records. Restoring every matching schema-2 authority object likewise remains
accepted. This is the previously disclosed all-local-witness boundary, not a
new regression in the seventh patch. A separately administered monotonic
witness/TPM NV counter is needed for complete snapshot resistance. A stricter
local mode could additionally require explicit first-install enrollment and
treat a pre-existing signing identity with no module authority as loss rather
than automatic genesis.

## `C27-R1-A16` — Cursor durability precedes event delivery

### Controls independently verified

- Independently generated authenticated schema-1 Security anchors were
  rejected before witness creation with the witness present and absent.
- Current schema-2 state with any non-matching subset of cursor, high-water,
  anchor, witness, or channel remained below 100 and replayed retained records.
  Whole matching local snapshot rollback remains the already disclosed
  external-witness ceiling.
- Forced interruption after high-water append, after cursor replacement, and
  after protected-anchor replacement all restarted at health 45 and replayed
  records 1-4. Full length-delimited record identity and the bounded Security
  read behavior stayed green in the wider compatibility gate.
- Live cross-process contention rejected the second cursor writer, and a
  deliberately terminated lease holder released the Windows kernel lock.

### Residual (MEDIUM): a crash after cursor commit permanently skips the batch

`_read_security_log_locked()` persists the enrolled cursor at
`src/angerona/modules/etw_listener.py:2132-2135` and then returns its in-memory
event list at line 2138. Only afterwards does `run()` describe and publish each
event at lines 2196-2206. There is no durable outbox, pending-delivery marker,
or acknowledgement binding the cursor advance to EventBus publication.

The independent fake channel enrolled records 1-3, appended records 4-6, and
called `_read_security_log()`. That call returned 4-6 **and had already
committed bookmark 6**. Simulating process loss by discarding that prepared but
unpublished list, then constructing a fresh listener over the same authenticated
state and unchanged retained channel, produced:

```text
prepared but unpublished=[4, 5, 6]
restart emitted=[]
restart bookmark=6
restart gap=""
restart health=100
```

The native Security log still contains the records, and exploitation requires
process disruption at a narrow but observable commit boundary; these are real
mitigations and keep residual severity at MEDIUM. An elevated adversary can
watch the cursor replacement and repeatedly terminate/restart the process to
turn the race into deterministic silent telemetry loss.

Prefer at-least-once delivery: persist a bounded authenticated pending batch
or outbox before moving the committed read cursor, publish stable
`generation + record + record-anchor` identities, and advance the cursor only
after durable delivery acknowledgement. On restart, replay every unacknowledged
record; duplicates are safer than omissions and can be deduplicated by the
stable identity. Health must remain below 100 while any prepared batch lacks a
delivery receipt.

## Gate evidence

- New independent hostile regressions: **17 passed**.
- New, seventh/sixth remediation, original High-A, and all directly affected
  Combat/ETW compatibility suites: **134 passed** (final rerun recorded after
  artifact creation).
- `py_compile`: passed for both product modules and the independent test.
- Ruff: passed for both product modules and the independent test.
- Inert self-tests: **2/2 passed** (Combat armed-state contract and ETW 4688
  decoder).
- Windows custody: canonical delete denied during the fake kill boundary;
  live hard-link change detected and circuit opened.
- Independent matrices completed: schema 1 present/absent witness; schema-2
  all/local-subset replay; protected parser depth; journal byte/depth/schema;
  read/append/final-read swap; hard link; all seven primary effects by source
  inspection; undo boundary; two A01 and three A16 partial commits;
  cross-process contention/crash release; ETW prepared-delivery crash.
- Final verdicts: **A01 REOPENED / PARTIAL (LOW)**; **A16 REOPENED / PARTIAL
  (MEDIUM)**.
