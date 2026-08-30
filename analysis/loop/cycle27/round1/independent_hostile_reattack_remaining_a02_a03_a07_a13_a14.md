# Cycle 27, Round 1 — Independent Hostile Re-attack of A02/A03/A07/A13/A14

This is a fresh, independent re-attack of the completed remediation described
in `remediation_remaining_a02_a03_a07_a13_a14.{md,json}`. Product code was not
edited. Every runtime probe used only temporary files, synthetic Defender
records, fake event-log APIs, an in-memory EventBus, inert canary bytes, and
offline driver evidence. No live response, quarantine target, Defender channel,
driver, registry value, firewall rule, process, network target, or host policy
was changed.

## Verdict

**The independent closure gate fails: all five findings reopen.** The nominal
remediation file still passes (`13 passed`), while the new hostile contract file
fails all ten gates (`10 failed`).

| Finding | Verdict | Severity | Independent hostile result |
|---|---|---:|---|
| `C27-R1-A02` | **REOPEN** | HIGH | Retained journal authority is shallow-copy mutable; the Windows cache also accepts same-size interior tamper after attacker-restored metadata and remains armed long enough to append onto the invalid chain. |
| `C27-R1-A03` | **REOPEN** | MEDIUM | A hard link created after the final check but before commit produces an `applied` receipt with a two-link destination; a final-check exception instead terminalizes the already-moved object as `failed` and leaves no recovery record. |
| `C27-R1-A07` | **REOPEN** | HIGH | Cursor/outbox delivery is neither contiguous nor durably downstream-acknowledged; old retries can regress the cursor, persisted incomplete coverage restarts at health 100, and missing/tampered outbox state has no fail-closed enrollment boundary. |
| `C27-R1-A13` | **REOPEN** | MEDIUM | The read-visibility wording is corrected, but same-timestamp replacement bypasses the claimed mutation visibility and health remains 70 after every canary is gone. |
| `C27-R1-A14` | **REOPEN** | HIGH | Any 64-hex string is accepted as a trusted kernel receipt, the same value replays across different images, and a hostile complete-empty provider yields health 100 and “provenance verified.” |

## 1. `C27-R1-A02` — cached journal state is not immutable authority

### Reopen evidence

The retained cache is built with shallow `dict()` copies at
`src/angerona/modules/adversary_combat.py:2722-2740`. A strict cached read again
returns only shallow copies at `:2760-2769`, and `_trusted_action()` returns the
shallow cached commit at `:4521-4531`. Nested `details` dictionaries and lists
therefore remain shared across the returned diagnostic snapshot and the O(1)
authorization index. Mutating a returned strict snapshot changed the later
trusted action without changing any authenticated journal bytes:

```text
trusted_module='forged-in-memory'
nested_authority='forged'
undone=false
```

The Windows retained-tail optimization has a second integrity gap. Cache
freshness trusts a metadata tuple at `adversary_combat.py:2663-2672`, the final
line at `:2682-2710`, and an anchor bound only to journal length/final HMAC at
`:2081-2093`; it does not re-HMAC cached interior records at `:2743-2758` before
`response_ready()` or append. An inert Windows probe changed an interior line
without changing its byte length, restored mtime/change-time with
`FILE_BASIC_INFO`, and left the final line intact:

```text
metadata_restored=true
cache_accepted_forged_interior=true
response_ready_after_forgery=true
append_after_forgery=true
fresh_restart_reconcile=false
fresh_restart_error='journal integrity failure at line 1'
```

This is primarily a live integrity/availability failure—the cache continues to
use its old parsed record—but it authorizes additional response work and appends
new signed phases while the retained journal object is already invalid.

A complete replay of a captured journal + local witness + rollback-anchor value
also restarted successfully at the older two-record state after four records
had existed. That same-authority rollback limitation is honestly admitted at
`remediation_remaining_a02_a03_a07_a13_a14.md:119-125`; it remains an accepted
residual only if an independently administered monotonic witness is explicitly
outside scope.

### Required closure boundary

- Deep-freeze or deep-copy every cached record and nested value crossing a
  method boundary; never expose an object shared with `_journal_cache_commits`.
- Bind the retained fast path to an authenticated checkpoint over all cached
  state (for example a segment Merkle root) and revalidate that checkpoint
  before effect admission and append. Metadata and terminal bytes are not an
  interior authentication proof.
- Keep the complete-bundle rollback limitation explicit until TPM/remote
  monotonic state exists.

## 2. `C27-R1-A03` — the terminal custody window still commits an alias

### Reopen evidence

`_quarantine_file()` performs its last single-link and digest checks at
`src/angerona/modules/adversary_combat.py:3363-3371`, then calls
`_commit_after_mutation()` at `:3372-3375`. `_journal_commit()` at `:3031-3044`
does not revalidate object identity, digest, or topology. On this Windows host,
the retained share-read handle at `:705-719` did not prevent `os.link()` from
creating a hard link in that interval.

The inert boundary probe wrapped only `_journal_commit()`, created the link,
then called the original commit:

```text
alias_exists=true
destination_nlink=2
journal_last_type='commit'
journal_last_status='applied'
receipt_destination_link_count=1
returned_applied=true
```

There is a separate orphan-accounting boundary. The rollback-protected inner
`try` ends at `adversary_combat.py:3331-3353`; the final checks are outside it.
A deterministic failure on the fourth `require_single_link()` reached the outer
catch at `:3376-3379`, which appended `failure` after the move instead of
rolling back or retaining a pending recovery phase:

```text
check_count=4
result_is_none=true
source_exists=false
quarantine_exists=true
last_record_type='failure'
last_status='failed'
pending_after_failure=false
restart_reconcile=true
```

The existing regression at
`tests/test_cycle27_remaining_a_remediation.py:159-195` forces check three. It
does not exercise final check four or the commit-boundary alias.

### Required closure boundary

- Treat every exception after the object moves and before a verified terminal
  as an orphan requiring exact rollback or durable recovery, never ordinary
  `failure`.
- Prevent hard-link creation through a platform-enforced custody primitive, or
  make the terminal receipt depend on an atomic post-commit object/link proof
  that cannot race. A pre-commit check alone cannot prove terminal topology.
- On POSIX, explicitly account for the absence of deny-write/deny-link semantics
  on a retained fd; topology and digest checks alone leave the same window.

## 3. `C27-R1-A07` — delivery, ordering, persistence, and health can diverge

### Reopen evidence

The bridge treats return from `emit()` as delivery, then advances the cursor and
acknowledges the row at
`src/angerona/modules/av_telemetry_bridge.py:599-640`. `BaseModule.emit()` only
publishes to the bus at `src/angerona/core/module_base.py:732-734`. The bus
stores a bounded in-memory ring at `src/angerona/core/eventbus.py:307-317` and
swallows every subscriber exception at `:324-343`. A failed persistence
subscriber therefore cannot hold the outbox/cursor:

```text
checkpoint=21 subscriber_failures=1 delivered_tombstones=1 pending=0
restart_checkpoint=21 restart_events=0
```

Outbox readiness ordering at `src/angerona/core/durable_outbox.py:546-565`
allows a newer row to overtake an older row in retry backoff (`:640-671`).
`_save_checkpoint()` at `av_telemetry_bridge.py:585-597` has no monotonic or
contiguous compare, so the eventual old retry regresses the checkpoint:

```text
after_record_1_checkpoint=0 pending=1
after_record_2_checkpoint=2
after_retry_checkpoint=1
delivery_order=[2, 1] errors=1 gaps=0
```

The checkpoint loads authenticated `coverage_complete` at
`src/angerona/core/event_log_integrity.py:455-457,702-707`. The bridge writes it
at `av_telemetry_bridge.py:590-593` but never reads it. An independently proven
gap was saved with `coverage_complete=false`, then a restart with no new records
reported:

```text
first: checkpoint_status='authenticated' coverage_complete=false gaps=1 health=45
restart: checkpoint_status='authenticated' gaps=0 health=100
health_note='0 Defender record(s) delivered with authenticated continuity'
```

Health 100 at `av_telemetry_bridge.py:381-390` also ignores `_errors`, pending
or dead-letter rows. A fake native run delivered record 2 while record 1 stayed
pending, yet reported health 100. Cursor tamper is converted to a gap at
`:263-268`, but outbox construction at `:254-262` has no equivalent boundary.
Outbox tamper raised `OutboxIntegrityError` with health 100/gaps 0. Deleting the
SQLite database silently created an empty valid database at
`src/angerona/core/durable_outbox.py:156-189`.

### Required closure boundary

- Advance one contiguous high-water cursor only after a durable downstream
  acknowledgment; subscriber failure cannot count as durable acceptance.
- Prevent newer rows from overtaking an unresolved earlier record, reject
  checkpoint regression, and emit a durable gap for any non-contiguous source.
- Enroll/authenticate outbox existence and its high-water state independently;
  tamper or deletion must degrade without silently recreating empty authority.
- Persist and honor incomplete coverage, pending/dead-letter state, and delivery
  errors across restart before allowing health 100.

## 4. `C27-R1-A13` — read wording is fixed; the replacement claim is not honest

### What closed

`src/angerona/modules/deception.py:8-10`, `:71-74`, `:140-151`, and `:221-224`
now explicitly deny native file/registry read visibility. The former “Any
access is logged” lure text is gone.

### Reopen evidence

The module still says it alerts when “anything touches” a file at
`deception.py:3`, advertises file mutation/deletion visibility at `:140-151`,
but checks only float `st_mtime` at `:163-177`. An inert same-path replacement
with different bytes and the exact prior timestamp produced:

```text
identity_changed=true
mtime_equal=true
content_changed=true
touch_alerts=0
```

Health is set once at `deception.py:138-144`. Deleted canaries are removed at
`:167-171`, but coverage/health is not recomputed. Deleting all three produced
three events and then left:

```text
remaining_canaries=0
health=70
health_note='file mutation/deletion visibility active; audited file/registry read telemetry is unavailable in this module'
```

### Required closure boundary

Either describe this narrowly as best-effort sampled-mtime/deletion telemetry,
or bind each canary to stable file identity plus size/content digest and detect
replacement/timestamp restoration. Recompute health after every loss,
unreadable object, or reduced canary set; zero traps cannot remain healthy.

## 5. `C27-R1-A14` — the “kernel receipt” is an unauthenticated string

### Reopen evidence

The built-in PowerShell collector is honestly unbound at
`src/angerona/modules/driver_provenance_guard.py:512-529`. The future loaded
image contract is not cryptographic. `DriverProvenanceEvidence.__post_init__()`
at `:89-135` checks only enum combinations and whether
`binding_receipt_sha256` is 64 lowercase hex. `assess_driver_provenance()` at
`:237-304` treats `binding_state == 'loaded-image-bound'` as proof without
parsing/authenticating a receipt or binding it to host, boot/load generation,
object identity, image digest/size, Code Integrity, or observation freshness.

The same arbitrary digest produced `provenance-verified` for two different
image hashes. A plain synthetic value also produced:

```text
state='provenance-verified'
evidence_complete=true
binding_receipt_sha256='dddd...dddd'
```

This weakness is normalized by the product self-test at
`driver_provenance_guard.py:702-724` and by
`tests/test_driver_provenance_guard.py:18-44`.

Provider authority is also unchecked. `observe_once()` validates only collection
type/length and evidence record type at `driver_provenance_guard.py:569-602`.
A hostile `DriverCollection((), True, ..., total_count=999)` leaves
`worst=100` at `:596` and sets health to “driver provenance verified” at
`:687-689` with zero assessments. The set-change event at `:646-653` also calls
the unbound configured-path set “Loaded-driver evidence.”

### Required closure boundary

- Parse and authenticate a typed receipt from an enrolled kernel authority.
- Bind its signature to host/install identity, boot/session/load generation,
  exact loaded object identity/base/size, image digest, and Code Integrity
  disposition; reject stale and replayed receipts.
- Validate provider collection invariants independently. Empty or internally
  inconsistent “complete” collections remain incomplete and below green.
- Replace self-tests that mint authority from arbitrary hex with a verifier test
  using a separate test issuer and explicit negative replay/wrong-image cases.

## Adversarial regression artifact

New hostile gates live in
`tests/test_cycle27_remaining_a_independent_reattack.py`:

| Lines | Contract |
|---:|---|
| 54 | A02 returned strict snapshot cannot mutate cached authority |
| 78 | A03 terminal hard-link race cannot commit success |
| 121 | A03 final topology failure remains rolled back or recoverable |
| 160 | A07 persisted gap cannot restart at health 100 |
| 206 | A07 checkpoint cannot regress on an old retry |
| 219 | A13 same-timestamp replacement is detected or honestly narrowed |
| 243 | A13 health degrades when all canaries are gone |
| 259 | A14 receipt cannot replay across different images |
| 286 | A14 hostile empty provider cannot claim verified coverage |
| 300 | A14 synthetic receipt digest cannot produce verified provenance |

Validation:

```text
existing remediation regressions: 13 passed in 6.85s
independent hostile regressions:   10 failed in 4.98s
ruff (new regression file):        PASS
py_compile (new regression file):  PASS
```

The ten failures are intentional red gates proving the reopened boundaries;
they must not be waived, xfailed, or rewritten to assert vulnerable behavior.

## Audited snapshot

SHA-256 at re-attack time:

- `adversary_combat.py` — `4e65b2b5ef29dd0722b2689dbd16d1ec75223975b6a17d932f866e5ff0732c4b`
- `av_telemetry_bridge.py` — `1a8cf905b6a041202667c142dfd062190e76fffcb40c21df8946eb4a1b819df9`
- `deception.py` — `a990fb6bb11f43dd5db836ea28ee2dad68e62f48d8a519ffd78f69d832d979b6`
- `driver_provenance_guard.py` — `6f280719b3369780130dbcb83ae5831abcae94f1e379bc4affac377e83e1943b`

Final count: **0 closed, 5 reopened; 3 HIGH and 2 MEDIUM**. This is a release
blocker until the hostile contract file passes without weakening its assertions.
