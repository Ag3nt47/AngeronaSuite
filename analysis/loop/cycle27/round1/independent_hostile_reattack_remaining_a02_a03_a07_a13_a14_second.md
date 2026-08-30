# Cycle 27, Round 1 — Second Independent Hostile Re-attack of A02/A03/A07/A13/A14

This is a fresh, independent re-attack of the second remediation recorded in
`remediation_remaining_a02_a03_a07_a13_a14_second.{md,json}`. The prior hostile
and author gates were read as attack hypotheses, not trusted as evidence. Product
code was not edited.

All runtime probes used temporary directories, inert file bytes, synthetic
Defender records, in-memory event buses, captured empty SQLite fixtures, and
offline Ed25519 keys. No live Defender channel, quarantine target, driver,
registry value, process, service, network target, firewall rule, or host policy
was accessed or changed.

## Verdict

**The second remediation does not close the independent gate. Four of the five
findings reopen.** The new contract collected 19 cases: **14 passed and 5
failed**. The five failures reproduce four distinct authority defects; A07 has
two independent failure modes.

| Finding | Verdict | Severity | Fresh hostile result |
|---|---|---:|---|
| `C27-R1-A02` | **REOPEN** | HIGH | Interior bytes are re-HMACed, but `_trusted_action()` still returns a shallow nested graph that can mutate the retained commit cache without changing journal bytes. |
| `C27-R1-A03` | **REOPEN** | MEDIUM | An NTFS hard link created after terminal proof but before journal append produced a two-link quarantine object and an `applied` receipt that still claimed one link. |
| `C27-R1-A07` | **REOPEN** | HIGH | A conflicting equal-cursor record reaches subscribers before its anchor is rejected; an older valid empty outbox snapshot also erases a pending record and restarts at health 100. |
| `C27-R1-A13` | **CLOSED for the requested boundary** | — | Equal-size/equal-mtime atomic replacement was detected, and deleting every canary reduced health to zero with honest visibility wording. |
| `C27-R1-A14` | **REOPEN** | HIGH | Forgery and same-verifier replay are rejected, but the same authentic receipt verifies again through a second provider/verifier instance. |

## 1. `C27-R1-A02` — nested authority still escapes the cache

### What remained closed

`src/angerona/modules/adversary_combat.py:2772-2790` deep-retains parsed records
and authenticates the complete journal bytes. The independent equal-length
interior edit at
`tests/test_cycle27_remaining_a_second_independent_reattack.py:160` kept the
cache fingerprint constant and restored mtime, but `_trusted_action()` raised
`JournalIntegrityError` and `response_ready()` remained false. The byte-integrity
portion of the second remediation is effective.

### Reopen evidence

`_trusted_action()` reads `_journal_cache_commits` at
`adversary_combat.py:4644-4654`, but returns `dict(record)` at `:4652`. That is
only an outer copy. Its `details`, nested dictionary, and nested list are shared
with the retained authority graph.

The inert probe at
`tests/test_cycle27_remaining_a_second_independent_reattack.py:136` mutated the
first returned record and then requested the same trusted action again. The
second call returned:

```text
details.nested.authority = 'forged'
details.nested.history[0].state = 'forged'
undone = false
journal bytes changed = false
```

The later undo path consumes this record at
`adversary_combat.py:4867-4901`. This does not create process isolation against
already-hostile native code, but it directly contradicts the remediation claim
that every cached authority graph is isolated across method boundaries.

### Required closure

- Deep-copy or deeply freeze the cached commit before every egress, including
  `_trusted_action()` and any recovery index accessor.
- Keep the cached object graph private and pass immutable typed projections into
  undo logic.
- Retain both the nested egress regression and the equal-metadata interior-HMAC
  regression.

## 2. `C27-R1-A03` — the signed terminal still has a hard-link race

### Reopen evidence

The exact-object validator runs at `adversary_combat.py:3126-3137`. The applied
record is appended later at `:3149-3153`. Quarantine supplies its validator at
`:3457-3481`. There is therefore a distinct interval after the validator returns
but before the commit append.

The Windows implementation says its no-sharing handle prevents hard-link
creation at `adversary_combat.py:713-720`. The fresh NTFS probe intercepted the
real `_append_journal()` call only for `record_type == "commit"`—after terminal
validation—and called `os.link()` on the retained destination. On this host the
link succeeded while the pinned handle was still open:

```text
alias exists = true
actual NTFS link count = 2
returned status = 'applied'
signed destination_link_count = 1
signed postcondition_verified = true
```

The failing contract is
`tests/test_cycle27_remaining_a_second_independent_reattack.py:189`. No external
file was used; both names and bytes were under the disposable test directory.

### What remained closed

The independent orphan test at
`tests/test_cycle27_remaining_a_second_independent_reattack.py:233` failed the
fifth/terminal topology proof, forced the first rollback to fail, and then
restarted the module. The durable pending phase survived, restart restored the
original bytes, and no recovery record remained. The orphan/restart repair is
effective.

### Required closure

- Do not make `applied` terminal on a proof obtained before the append. A link
  topology change at the commit boundary must produce rollback/recovery, never a
  one-link receipt.
- Replace the incorrect assumption that Windows share mode blocks
  `CreateHardLink`/`os.link`; prove the actual primitive on every supported file
  system.
- If alias creation cannot be prohibited, use an explicit provisional/final
  receipt protocol with a post-append retained-handle proof and honestly retain
  a residual race until an independently enforced topology boundary exists.

## 3. `C27-R1-A07` — pre-admission ordering and outbox generation remain unbound

### Reopen A — conflicting equal-cursor event is published first

`_drain_outbox()` publishes to the EventBus at
`src/angerona/modules/av_telemetry_bridge.py:850-851`. Only afterward does it
call `_save_checkpoint()` at `:861-869`. The equal-record check that compares the
stored anchor is at `:744-745`.

The probe at
`tests/test_cycle27_remaining_a_second_independent_reattack.py:297` first
accepted Defender record 1, then supplied record 1 again with a different
authenticated source digest. Observed state:

```text
record-1 subscriber deliveries before = 1
record-1 subscriber deliveries after  = 2
continuity gaps                       = 0
pending outbox rows                   = 1
cursor                                = 1
```

The cursor did not regress, but the conflicting event crossed the subscriber
boundary before its anchor was rejected. It can therefore reach correlation or
response consumers despite failing continuity admission.

### Reopen B — an older valid empty database erases pending delivery

The outbox enrollment binds only schema, random enrollment ID, database file
name, and creation time at `av_telemetry_bridge.py:263-276`. Verification at
`:304-345` proves the marker and checks whether a file exists, but does not bind
database identity, generation, authenticated high-water, or pending-row state.

The probe at
`tests/test_cycle27_remaining_a_second_independent_reattack.py:392` captured the
fresh empty SQLite database, created one pending Defender delivery through a
failing subscriber, closed it, and restored the captured database without
changing the enrollment marker or cursor. Restart reported:

```text
open_continuity_state = true
health                = 100
continuity gaps       = 0
cursor                = 0
pending rows          = 0
```

The captured snapshot contains neither the continuity key nor its derived
outbox key; replay after capture does not require key knowledge. This is not the
documented complete coordinated rollback of every witness: the authenticated
enrollment marker and cursor were left in place while only the enrolled database
was rolled back.

### What remained closed

- Subscriber exception: cursor stayed zero and the pending row survived restart
  (`tests/...second_independent_reattack.py:275`).
- Older retry: cursor remained at 2 and the old event was not republished (`:326`).
- Persisted gap: a quiet restart remained health 45 (`:352`).
- Plain deletion with the enrollment marker present failed closed (`:376`).

### Required closure

- Validate record number and anchor before `emit()`. Equal number/equal anchor is
  a deduplicated acknowledgement; equal number/different anchor is a durable gap
  and must never be published.
- Bind enrollment to a database generation/instance identifier plus an
  authenticated monotonic outbox high-water held outside the SQLite file.
- Transactionally advance that witness with enqueue/ack state so an older valid
  database cannot look empty and healthy. Continue to state honestly that a
  coordinated rollback of all local witnesses needs independent monotonic state.

## 4. `C27-R1-A13` — requested canary boundary closes

`src/angerona/modules/deception.py:99-149` now binds device/inode, size,
nanosecond mtime, and content digest. The equal-size, exact-mtime atomic
replacement at
`tests/test_cycle27_remaining_a_second_independent_reattack.py:444` emitted one
`Canary file TOUCHED` event. The zero-canary probe at `:469` removed all three
temporary traps; `_check_canaries()` at `deception.py:231-274` cleared both maps
and set health 0 with “zero canaries” in the note.

This closes the exact second-remediation claims. Poll-interval blind spots and
the explicitly unclaimed native read visibility remain honest residuals, not
reopened findings from this probe.

## 5. `C27-R1-A14` — replay state is verifier-local, not one-use authority

### What remained closed

- A forged Ed25519 signature and a receipt checked under the wrong public key
  both remained incomplete (`tests/...second_independent_reattack.py:482`).
- Reuse through the same verifier instance was rejected (`:504`).
- Complete-empty providers with `total_count` of null, 0, and 999 all remained
  health 20 or lower and never claimed verified coverage (`:545`).

### Reopen evidence

`DriverLoadReceiptVerifier` keeps consumed IDs only in its instance-local set at
`src/angerona/modules/driver_provenance_guard.py:272`. The atomic check at
`:310-314` has no durable or shared witness. Each
`DriverProvenanceGuard` may receive a separate verifier at `:859-871`.

The probe at
`tests/test_cycle27_remaining_a_second_independent_reattack.py:516` presented
the exact same authentic receipt through two provider/guard instances with
separately constructed verifiers for the same enrolled authority. Both results
were:

```text
state = 'provenance-verified'
evidence_complete = true
```

Thus the asserted one-use identity does not survive provider duplication,
verifier reconstruction, or restart.

### Required closure

- Put receipt consumption in one authenticated replay authority shared by all
  providers for the enrolled authority/host/install/boot tuple.
- Persist and bound consumed receipt IDs or a monotonic load-generation/object
  witness across verifier reconstruction and restart.
- Bind any provider namespace admitted by the product to that authority; a new
  wrapper object cannot mint a fresh replay domain.
- Retain forged, wrong-key, same-instance replay, cross-instance replay, and
  empty-provider negative gates.

## Gates and artifacts

| Gate | Result |
|---|---|
| Prior hostile + author contracts, unchanged | **PASS — 14 passed in 3.47s** |
| Fresh independent hostile contract | **FAIL — 5 failed, 14 passed in 4.52s** |
| `py_compile` for the new test | **PASS** |
| Ruff for the new test | **PASS** |
| Product files edited by this re-attack | **None** |

New independent contract:
`tests/test_cycle27_remaining_a_second_independent_reattack.py`.

SHA-256 at the final hostile run:

- `adversary_combat.py` — `b8c240ac7d413585d2122d506600a517ac6b485e0cb3388560e298a7277c62ab`
- `av_telemetry_bridge.py` — `4f55bd132996bcbadc3deb59c6e0bcbdb2630e1cb0fbc1d8b2db82b094977f3e`
- `deception.py` — `9dc9ba8403806605e5bfa224944be1b6de63ddc9ce6f2cbd0597f23728e93f00`
- `driver_provenance_guard.py` — `249ddc8214677138c205ae0dd676f92a7affd22fbbc7cb9ecee001895dcf270c`

Final count: **1 closed, 4 reopened; 3 HIGH and 1 MEDIUM**. The five red
assertions are release blockers and must not be weakened, xfailed, or rewritten
to assert the vulnerable behavior.
