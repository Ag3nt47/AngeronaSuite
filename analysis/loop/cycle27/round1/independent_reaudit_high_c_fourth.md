# Cycle 27 Round 1 — Fourth Independent High-C Re-attack

Date: 2026-08-28
Scope: the third remediation of `C27-R1-C03` and `C27-R1-C13` only
Method: manual source review plus inert, temporary-directory range-encryption,
timestamp-restoration, writable-mapping, hard-link race, restart, pending-crash,
retention-eviction, custody-bundle deletion/rollback, and ledger-capacity probes.
No service, driver, registry object, security control, user document, or
non-temporary host object was changed. This re-attack did not edit product code
or tests.

## Verdict summary

| Finding | Verdict | Residual severity | Independent result |
|---|---|---:|---|
| C27-R1-C03 | **REOPENED** | MEDIUM | Exact ancestry and the selected sample are now held and authenticated, but selection still trusts an attacker-restorable 120-second mtime and authenticates only the first 64 KiB. A same-inode, same-size, timestamp-restored 4 MiB file with its final 63 ranges encrypted had whole-file entropy 7.9770, produced no alert, and retained `complete=true`, health 100. A wholly encrypted file timestomped outside the window did the same. |
| C27-R1-C13 | **REOPENED** | MEDIUM | The authenticated ledger rejects ordinary isolated tampering, but custody-loss and alias state are memory-only and disappear on restart. A real source alias, pending-crash loss, and authenticated retention eviction each returned to health 100 after restart. A hard link created immediately after the evidence audit's final `fstat` was accepted, then changed the sealed evidence while health remained 100. Complete authority deletion or paired ledger/head rollback also enrolled a fresh/older healthy baseline, and a full ledger reported health 100 despite zero capacity for the next incident. |

Totals: **0 CLOSED, 2 REOPENED** (0 critical, 0 high, 2 medium).

## C27-R1-C03 — Authenticated prefix and mutable mtime leave deterministic ransomware blind spots

**Verdict: REOPENED (MEDIUM residual).**

### Exact source evidence

- `src/angerona/modules/ransomware_heuristics.py:69-72` limits entropy evidence
  to the first 65,536 bytes and admits only files whose mutable last-write time
  is within 120 seconds.
- `src/angerona/modules/ransomware_heuristics.py:1015-1030` applies those two
  conditions before constructing the otherwise exact sample receipt.
- `src/angerona/modules/ransomware_heuristics.py:1086-1095` applies the same
  timestamp gate again and creates no candidate for an older timestamp. This is
  treated as an ordinary covered file, not a skip or uncertainty.
- `src/angerona/modules/ransomware_heuristics.py:783-820` correctly rereads and
  authenticates the selected prefix from the exact held inode. It does not read
  or bind any later range, so modifying bytes at offsets 65,536 and above leaves
  every candidate receipt valid.
- `src/angerona/modules/ransomware_heuristics.py:1111-1124` consequently assigns
  health 100 whenever traversal counters are clean, even though no content
  evidence exists for an old-mtime file and only one public fixed range exists
  for a larger recent file.

### Independent inert reproductions

1. **Same inode, restored metadata, encryption outside the public range.** A
   4 MiB all-`A` file was enumerated. At the real `_scan_root()` →
   `_evaluate_entropy()` boundary, bytes 65,536 through EOF were replaced with
   random bytes on the same inode and the exact nanosecond mtime was restored.
   The current whole-file entropy exceeded the module threshold, but the fixed
   prefix and its SHA-256 remained unchanged:

   ```text
   C03_RANGE_REPRO {
     same_inode: True, size: 4194304,
     prefix_entropy: 0.0, tail_entropy: 8.0,
     whole_entropy: 7.9770, threshold: 7.9,
     entropy_alerts: 0, health: 100,
     complete: True, errors: 0, skipped: 0
   }
   ```

   This is a current-content false negative, not a stale-object race: the exact
   object, size, mtime, prefix length, and prefix digest all truthfully match at
   decision time. Partial/intermittent ransomware routinely preserves headers
   or encrypts ranges, so the first 64 KiB is attacker-predictable bypass
   surface.

2. **Whole-file encryption with timestamp restoration before discovery.** A
   64 KiB random file with entropy 7.9966 was assigned an mtime 3,720 seconds
   old, beyond the 120-second window. A full tick visited it but created no
   entropy candidate:

   ```text
   C03_TIMESTOMP_REPRO {
     entropy: 7.9966, threshold: 7.9,
     mtime_age_s: 3720.02, window_s: 120.0,
     events: 0, health: 100,
     coverage: {visited: 1, skipped: 0, errors: 0, complete: True}
   }
   ```

   Restoring a user-owned file's last-write time does not require changing its
   identity. An in-place encryptor that restores original timestamps and does
   not rename therefore avoids both entropy and rename-storm evidence.

### Controls that held

- The third remediation closes the previously demonstrated stale-prefix race:
  a change inside the sampled prefix, even with the inode, size, and timestamp
  restored, is rejected by the SHA-256 comparison.
- Watched-root replacement, nested junctions, changed final-file identity,
  sampled-length mismatch, and ordinary ancestry swaps remain fail-visible.
- A pre-existing writable memory map caused the reviewed Windows open to fail
  with sharing error 32; in the real `_tick()` path that error is counted and
  lowers coverage/health. The probe did not find a post-verification mapped
  writer bypass.
- File/directory/depth/time budgets, handles, and dedup remain bounded. The
  focused author regressions, including both same-inode prefix directions and
  the nested junction/hard-link cases, still pass.

### Required remediation

Do not use last-write time as the sole admission authority. Consume a durable
Windows change source (at minimum an identity-bound USN/change-time cursor with
explicit journal-loss and rollback states) and treat absent or discontinuous
change evidence below 100. For content, use a bounded multi-range contract over
start, middle, end, and identity-keyed unpredictable offsets; bind every range's
offset, length, and digest to the exact held generation, and bias toward full
reads for bounded small files. A fixed public prefix may remain one signal, but
must not be represented as complete entropy coverage. Add regressions for
header-preserving partial encryption, strided/range encryption, an old restored
mtime, and changes between every range acquisition and publication boundary.

## C27-R1-C13 — Custody loss is not durable and exact-object audits still have a hard-link publication race

**Verdict: REOPENED (MEDIUM residual).**

### Exact source evidence

- `src/angerona/modules/smart_deception.py:271-276` initializes alias residue,
  custody degradation, custody loss, sequence, and head only in memory.
- `src/angerona/modules/smart_deception.py:839-906` authenticates `commit` and
  `evict` rows and reconstructs only the currently active evidence map. It does
  not reconstruct a latched continuity-loss state from a prior eviction,
  pending cleanup, source-alias uncertainty, or any earlier degradation.
- `src/angerona/modules/smart_deception.py:1003-1030` deletes a recovered pending
  object and increments only the volatile degradation/loss counters. No durable
  loss event is appended.
- `src/angerona/modules/smart_deception.py:1171-1190` appends an authenticated
  eviction but again records its health consequence only in volatile counters.
- `src/angerona/modules/smart_deception.py:1374-1393` detects observed source
  aliases and conservatively degrades every source retirement, but neither the
  alias count nor the mandatory uncertainty is included in the custody ledger.
- `src/angerona/modules/smart_deception.py:1044-1075` checks evidence link count
  before and after its bounded read, then closes the handle. Windows permits
  `CreateHardLink`/`os.link` while this share-read-only handle is open. There is
  no indivisible link-topology seal after the final `fstat` and before the audit
  result is accepted at lines 1084-1118.
- `src/angerona/modules/smart_deception.py:686-745,896-905` locates the key,
  SQLite ledger, and JSON head by mutable path and creates a new authority when
  the entire bundle is absent. The HMAC head detects an isolated old ledger but
  supplies no independently monotonic freshness when the matching old head is
  restored with it.
- `src/angerona/modules/smart_deception.py:921-924` rejects only the *next*
  append after sequence 4,096. Neither `_refresh_quarantine_limits()` nor
  `_update_health()` at lines 1152-1210 and 1653-1686 exposes zero remaining
  ledger capacity before an incident is dropped.

### Independent inert reproductions

1. **Known source alias becomes healthy after restart.** A hard link was made
   to the attacked decoy before retirement. The sealed independent evidence
   copy remained intact and the first process correctly reported alias residue,
   degradation, and health 65. A new module instance authenticated the same
   ledger and evidence, but forgot the still-live source alias:

   ```text
   before_restart: alias_exists=True, alias_residue=1,
                   degraded=True, health=65, sequence=1
   after_restart:  refresh=True, alias_exists=True, alias_residue=0,
                   degraded=False, custody_loss=0, saturated=False,
                   health=100, sequence=1
   ```

2. **Evidence hard-link race after the final audit observation.** An actual
   `os.link()` to the evidence inode succeeded while its exact custody handle
   was open. In a boundary probe, the link was created immediately after the
   audit's final real `fstat` returned but before the descriptor closed. The
   returned stat receipt still carried link count one, so the audit returned
   true. After descriptor close, writing through the new alias changed the
   evidence digest while health stayed 100 until the next 300-second audit:

   ```text
   C13_RACE_MUTATION_WINDOW {
     audit_refresh: True, link_created_at_final_fstat: True,
     samefile: True, digest_changed: True,
     health_before_next_audit: 100, audit_period_s: 300.0
   }
   ```

   The following audit detects link count two and lowers health to 65. That
   delayed detection is useful, but it does not make the preceding health-100
   custody assertion current.

3. **Crash and retention loss are durable in rows but not in health.** Cleaning
   a bounded pending crash object produced `(degraded=True, loss=1, health=65,
   sequence=0)`. Restart against the now-clean directory returned
   `(degraded=False, loss=0, health=100, sequence=0)`. Separately, an aged
   evidence record produced an authenticated `commit` + `evict` chain at
   sequence two and health 65; restart loaded that same chain and returned
   health 100 because the active set was empty. This contradicts the remediation
   claim that interruption/intentional eviction remains permanently visible.

4. **Complete deletion and paired rollback create healthy older baselines.**
   After a real sequence-one archive, deleting the evidence, key, database, and
   head before restart caused a fresh key, empty ledger, and sequence-zero head
   to be created. Refresh returned true with no custody loss and health 100. In
   a second probe, sequence-one database/head copies were retained, a second
   incident advanced to sequence two, then the second evidence object was
   deleted and the old database/head pair restored. Restart accepted sequence
   one and the one surviving exact evidence inode with health 100:

   ```text
   total deletion: old_sequence=1 -> accepted_sequence=0,
                   refresh=True, custody_loss=0, health=100
   paired rollback: sequence_before=2 -> accepted_sequence=1,
                    physical_evidence=2 -> 1,
                    refresh=True, custody_loss=0, health=100
   ```

   This probe does not claim that a same-host HMAC can defeat an administrator
   who captured every authority; the remediation document already disclaims
   that. The residual is that this local-only freshness level is still promoted
   to health 100 and complete deletion silently re-enrolls instead of remaining
   fail-visible.

5. **Full authenticated ledger is green before the next incident is lost.** A
   valid bounded history of 2,048 commit/evict pairs was installed in one
   temporary ledger and authenticated by its matching head. It represented a
   normal exhausted lifetime with no active evidence. Refresh accepted sequence
   4,096 with `saturated=false` and health 100. The next real tampered decoy was
   retired, but its evidence could not be committed and was deleted:

   ```text
   before_incident: sequence=4096/4096, refresh=True,
                    saturated=False, health=100
   after_incident:  source_exists=False, evidence_count=0,
                    dropped=1, saturated=False, health=65
   ```

   The post-loss health downgrade is honest, but zero capture capacity existed
   before the incident and was falsely represented as 100.

### Controls that held

- Isolated ledger deletion/truncation, sequence gaps/reordering, row changes,
  HMAC changes, or a stale ledger against the current authenticated head fail
  closed. Missing or substituted expected evidence and foreign evidence also
  fail inventory reconciliation.
- The evidence copy is a distinct inode, bounded, fsynced, reread, and digest
  checked. A pre-existing source alias cannot mutate that copy.
- An evidence alias or digest change that persists into the next audit is
  detected, sets saturation, and lowers health. Root replacement/reparse and
  unsafe pending objects remain fail-visible.
- Quarantine item/count/byte/age/scan bounds and trip-alert state remain bounded;
  unresolved legitimate evidence is not selected merely to admit an incoming
  archive.

### Required remediation

Make continuity state part of authenticated durable state, not process memory.
Add closed-schema ledger events for pending recovery/loss, source-alias residue,
unprovable link topology, refused capture, and retention eviction; reconstruct a
latched degraded/lost state from the complete chain after every restart, and
clear it only through an authenticated operator disposition rather than an
empty active set.

Do not claim current single-link custody from a check-then-close `st_nlink`
receipt. Establish and continuously verify a quarantine namespace whose ACL
denies link creation to the attacker class, use a reviewed file-ID/hard-link
enumeration or filesystem enforcement boundary, and persist the conservative
degradation when race-free topology proof is unavailable. Reconcile again at
the publication boundary; a delayed next audit may improve detection but cannot
justify current health 100.

Treat local authenticity separately from anti-rollback freshness. Preserve a
non-reset enrollment marker outside the create-on-missing bundle, expose
`local-authenticity-only` below 100, and use an actual separately administered
monotonic/TPM-backed authority where rollback resistance is required. Bind and
no-follow the custody root, key, database, and head identities rather than
reopening mutable paths.

Finally, check and expose ledger remaining capacity before accepting health or
retiring a source. Reserve durable space for terminal/eviction events, never
delete evidence before its eviction event is durable, and use an authenticated
checkpoint/rollover protocol anchored to the high-water instead of a permanent
4,096-event dead end.

## Validation record

```text
python -m pytest -q tests/test_cycle27_round1_high_c.py \
  tests/test_cycle27_high_c_third_remediation.py
33 passed, 1 skipped in 5.36s

python -m py_compile \
  src/angerona/modules/ransomware_heuristics.py \
  src/angerona/modules/smart_deception.py
PASS

python -m ruff check \
  src/angerona/modules/ransomware_heuristics.py \
  src/angerona/modules/smart_deception.py \
  tests/test_cycle27_round1_high_c.py \
  tests/test_cycle27_high_c_third_remediation.py
PASS

RANS self_test: PASS
SDEC self_test: PASS
```

The one pytest skip is the pre-existing directory-symlink privilege fixture.
All fourth-attack reproductions used temporary filesystem objects, and every
temporary directory was removed after its probe. Green author tests support the
controls listed above but do not exercise fixed-range encryption, pre-discovery
timestomping, restart reconstruction of loss, the post-`fstat` link race,
complete authority deletion/paired rollback, or a fully exhausted ledger.
