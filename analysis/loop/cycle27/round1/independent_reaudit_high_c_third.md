# Cycle 27 Round 1 — Third Independent High-C Re-attack

Date: 2026-08-28
Scope: latest remediation of `C27-R1-C03`, `C27-R1-C04`, and
`C27-R1-C13` only
Method: manual source review plus inert, temporary-directory NTFS junction,
hard-link, same-inode mutation, evidence-substitution, retention-pressure,
crash-restart, and bounded-state probes. No service, driver, registry object,
security control, user document, or non-temporary host object was changed. This
audit did not edit product code or tests.

## Verdict summary

| Finding | Verdict | Residual severity | Independent result |
|---|---|---:|---|
| C27-R1-C03 | **REOPENED** | MEDIUM | Exact object identities are checked, but the sampled bytes are released before the decision and their SHA-256 is never revalidated. Same-inode content mutation with a restored timestamp produced a deterministic false negative with `complete=true` and health 100. An intermediate junction plus a hard link also preserved the accepted file ID while moving the pathname outside the watched tree. |
| C27-R1-C04 | **CLOSED** | — | The BYOVD action remains proposal-only, absent from the executable catalog, contains no service-control mutation sink, and cannot report success through direct, transactional, verification, or rollback methods. |
| C27-R1-C13 | **REOPENED** | MEDIUM | A filename-carried plain digest is not an authenticated custody receipt. Deleting all evidence or replacing it with a different, self-consistent inode was accepted with health 100; forged records could also evict the real record through normal retention. A hard link created after the source-copy check survived retirement without the alias counter or health changing. |

Totals: **1 CLOSED, 2 REOPENED** (0 critical, 0 high residual, 2 medium
residual).

## C27-R1-C03 — Sample freshness and watched ancestry are not held through decision

**Verdict: REOPENED (MEDIUM residual).**

### Exact source evidence

- `src/angerona/modules/ransomware_heuristics.py:623-689` opens and samples the
  enumerated file with exact identity, size, and modification-generation checks,
  but closes that handle before returning the sample.
- `src/angerona/modules/ransomware_heuristics.py:696-725` later opens the root and
  candidate again. It checks root/file identity, size, and modification time,
  but does not retain the enumerated parent chain, reject an intermediate
  reparse component, reread the current sample, or compare it with
  `candidate.sample_sha256`.
- `src/angerona/modules/ransomware_heuristics.py:1046-1081` validates only the
  syntax of the stored digest and entropy fields. It never proves that the
  digest describes the bytes visible at decision time, then assigns
  `ent = candidate.sample_entropy` directly.
- `src/angerona/modules/ransomware_heuristics.py:1014-1033` consequently grants
  health 100 whenever traversal counters are clean, even if the later decision
  consumed a stale but metadata-compatible sample.

### Independent inert reproductions

1. **Same inode, same size, restored timestamp, different bytes.** A recent
   64-KiB all-`A` file was scanned at entropy `0.0`. After `_scan_root()` returned,
   the exact same NTFS file was overwritten with random bytes and its original
   nanosecond timestamp was restored. The current entropy was `7.9973`, the
   stored digest no longer matched, and identity, size, and timestamp all still
   matched. `_evaluate_entropy()` returned zero errors and emitted zero alerts.
   Running this at the normal `_tick()` boundary produced:

   ```text
   sample_entropy=0.0
   decision_time_entropy=7.9971
   digest_changed=True
   alerts=0
   health=100
   complete=True
   errors=0
   skipped=0
   ```

   This is an in-place encryption-style false negative without a rename signal.

2. **Intermediate junction plus hard-link alias.** A nested high-entropy file
   was sampled, its directory was moved outside the watched root, and the old
   nested name was replaced with a temporary NTFS junction to another directory
   containing a hard link to that same file ID. The file was then overwritten
   with low-entropy bytes and its timestamp restored. The enrolled root identity
   still matched, the final file ID still matched through the hard link, and the
   ordinary absolute-path reopen followed the intermediate junction:

   ```text
   candidate_entropy=7.9970
   current_entropy=0.0
   same_inode=True
   evaluate_errors=0
   alerts=1
   root_identity_still_enrolled=True
   ```

   The alert named the former in-root pathname even though it now traversed a
   junction and the current object content contradicted the sample. Reversing
   the two samples yields the false-negative direction.

### Controls that held

- A watched root that is already a junction is rejected with nonzero
  error/skip counters and health below 100.
- Replacing an enrolled root, or replacing the whole root with a junction after
  enumeration, is rejected at decision time and lowers health.
- A normal file or nested-directory substitution with a different identity is
  rejected. Final-component reparses are opened no-follow.
- Traversal depth, file, directory, and wall-clock limits remain fail-visible.
- One hundred repeated exact scans showed no process-handle growth
  (`before=220`, `after=220`) and all scans remained within the declared bounds.

These controls bind stable object IDs, but object ID plus attacker-restorable
metadata is not a content-generation receipt, and holding only the watched root
does not bind every intermediate directory component.

### Required remediation

Keep the sampled file and its reviewed ancestor chain held from enumeration
through scoring and event publication, with write/delete sharing denied for the
entire interval. Open each component relative to the already-held parent (or use
an equivalent reviewed object-manager relative-open contract); never resolve the
decision pathname through mutable intermediate components. If an immutable
sample is handed to another worker, bind it to a duplicated exact handle and
recompute/compare its length and SHA-256 from that same held generation before
using its entropy. A digest that is merely well-formed must not count as proof.
Any ancestry, content, identity, size, timestamp, or read mismatch must discard
the candidate, increment explicit error/skip counters, and hold health below
100. Add regressions for same-inode timestamp restoration and the nested
junction/hard-link case in both false-negative and false-positive directions.

## C27-R1-C04 — Vulnerable-driver disablement remains inert

**Verdict: CLOSED.**

### Exact source evidence

- `src/angerona/modules/remediation_actions.py:616-682` contains no SCM,
  registry, command, or subprocess mutation. `begin_transaction()` raises;
  `apply()` and `apply_transactional()` force `ok=false`, `changed=false`, and
  `mutation_started=false`; verification and rollback cannot report success.
- `src/angerona/modules/remediation_actions.py:1526-1549` excludes the class
  from `ACTIONS` and includes it only in `PROPOSAL_ONLY_ACTIONS`.
- `src/angerona/modules/remediation_actions.py:1642-1681` returns an executable
  action only from `ACTIONS`; the typed BYOVD record can therefore produce only
  an operator-visible proposal.
- A repository-wide sink search found no `ChangeServiceConfig*`,
  `OpenSCManager*`, `OpenService*`, `ControlService`, `DeleteService`, or live
  `sc config/stop/delete` route. The two `sc stop/delete` strings in the kernel
  build helper are `echo`ed manual cleanup instructions, not execution paths.

### Independent result

The focused suite exercised plain records, exact authenticated approvals,
post-claim target substitution, stale/tampered approvals, direct application,
transactional application with pre-populated success fields, rollback, and both
verification methods. All service-disable paths remained non-executable and
could not retain a success receipt.

### Retention recommendation

Keep this class outside `ACTIONS` until one held SCM service handle and held
image-object identity span observation, operator approval, mutation,
postcondition, and rollback. The stale source comment describing this action as
“REAL” should be corrected for operator clarity, but it does not reopen the
removed execution route.

## C27-R1-C13 — Evidence receipts are forgeable and a concurrent alias escapes accounting

**Verdict: REOPENED (MEDIUM residual).**

### Exact source evidence

- `src/angerona/modules/smart_deception.py:695-753` accepts any single-link,
  bounded regular file whose attacker-chosen filename contains the SHA-256 of
  its own payload. There is no keyed MAC/signature, expected-record ledger,
  monotonic incident sequence, or retained prior file identity. An empty
  inventory is also a valid inventory.
- `src/angerona/modules/smart_deception.py:790-834` treats that self-consistent
  inventory as retention authority. It can prune the oldest real record in
  favor of injected, newer, syntactically valid records without setting
  saturation.
- `src/angerona/modules/smart_deception.py:884-953` captures `source_links` before
  copying and checks it once at the end of the copy. NTFS nevertheless permits
  a hard link to be created and removed while the source handle is held.
- `src/angerona/modules/smart_deception.py:974-1001` uses the earlier link count
  after evidence commit and original-link deletion. It does not make a final
  source-link/topology observation at that boundary, so an alias created after
  `_copy_and_verify_evidence()` returns is neither counted nor health-visible.
- `src/angerona/modules/smart_deception.py:65,695-708` recognizes pending crash
  files for creation but not inventory/recovery. A crash after exclusive pending
  creation leaves an “unrecognized object” that permanently saturates retention
  until manual cleanup. This failure is honestly visible, but automatic crash
  recovery is incomplete.
- `src/angerona/modules/smart_deception.py:1261-1291` can therefore return health
  100 after evidence deletion, replacement, or retention poisoning because none
  of those events advances a custody-loss counter.

The production data-root code materially limits this exploit on an elevated or
frozen Windows installation by requiring an Administrators/SYSTEM-only root.
That is credited: the evidence attacks require write authority to the protected
root in that deployment. Non-elevated source operation uses current-user
custody, and an attacker that has obtained administrator-equivalent host access
is still inside the stated hardening threat model. A plain digest does not add
independent authenticity once that directory authority is lost.

### Independent inert reproductions

1. **Deletion and self-consistent replacement accepted as healthy.** A real
   archived incident record was deleted. `_refresh_quarantine_limits()` returned
   true with count zero, no saturation, and health 100. A different inode with a
   different payload and a matching attacker-generated SHA-256 filename was then
   created; it was accepted as the sole record with health 100:

   ```text
   after_deletion: refresh=True, count=0, saturated=False, health=100
   after_forgery: refresh=True, count=1, different_inode=True,
                  payload="forged-not-the-original-incident", health=100
   ```

2. **Retention poisoning deletes genuine evidence.** Eight newer forged records
   were added beside one genuine record. Normal cap enforcement deleted the
   genuine oldest record, retained the eight forgeries, returned true, and left
   `saturated=false`, health 100.

3. **Concurrent hard-link alias escapes accounting.** A link to the source was
   created immediately after the real copy verifier returned but before source
   retirement. NTFS allowed the link creation while custody was held. The
   original decoy link was deleted, evidence remained a separate safe inode, and
   the active decoy was restaged; however, the attacked source survived through
   the alias while `alias_residue=0`, `custody_degraded=false`, and health 100.

4. **Crash after pending-file creation.** A child process exited with
   `os._exit(91)` immediately after exclusive pending creation. Restart found one
   pending file, returned `refresh=false`, set saturation, and reported health
   65. This is fail-visible, but retention remains unavailable until manual
   intervention.

### Controls that held

- A pre-existing source alias produces a separate sealed evidence inode,
  increments `alias_residue`, sets `custody_degraded`, and lowers health to 65.
- A pre-existing writable memory map caused exact source-custody acquisition to
  fail with sharing error 32; a new ordinary writer cannot mutate during copy.
- A hard link added to an archived evidence inode is detected by the next audit
  (`st_nlink=2`), sets saturation, and lowers health to 65. Persistent content or
  digest drift is likewise rejected.
- Replacing the enrolled quarantine root with another directory was rejected by
  identity, set saturation, and lowered health to 65. Reparse roots are also
  rejected.
- Quarantine count, byte, item-size, age, and scan limits remain explicit.
- After 5,000 ordinary epochs, dedup retained one entry with 4,999 normal
  evictions. Forced overflow retained exactly 256 entries, set
  `dedup_saturated=true`, and lowered health to 65. The dictionary never exceeded
  its 256-entry post-prune bound.

### Required remediation

Persist each committed evidence record in an authenticated, append-only custody
ledger with a monotonic incident/record sequence, exact file identity, size,
digest, link count, and quarantine-root identity. Reconcile every inventory
against that ledger: a missing expected record, an unexpected record, a changed
identity, or a rolled-back ledger must be a custody loss, never a new healthy
baseline. Store the authentication/high-water authority outside the mutable
evidence directory under the existing protected key boundary; a digest selected
by the same writer as the payload is only integrity metadata, not authenticity.

Immediately before retiring the source, revalidate its exact identity and link
topology after copy and again after setting delete disposition while its handle
is retained. Use reviewed Windows file-ID/hard-link enumeration to account for
every surviving name; if a race-free proof is unavailable, conservatively mark
alias residue/custody degraded. Add durable transaction stages for pending-file
creation, seal, commit, source retirement, and restage so restart can safely
clean or reconcile a bounded exact pending object without leaving retention
permanently saturated. Add the four reproductions above as regressions.

## Validation record

```text
python -m pytest -q tests/test_cycle27_round1_high_c.py
24 passed, 1 skipped in 4.44s

python -m py_compile \
  src/angerona/modules/ransomware_heuristics.py \
  src/angerona/modules/remediation_actions.py \
  src/angerona/modules/smart_deception.py
PASS

python -m ruff check \
  src/angerona/modules/ransomware_heuristics.py \
  src/angerona/modules/remediation_actions.py \
  src/angerona/modules/smart_deception.py \
  tests/test_cycle27_round1_high_c.py
PASS

RANS self_test: PASS
SDEC self_test: PASS
```

The one pytest skip was the directory-symlink test on a host where that specific
test privilege was unavailable. Both unprivileged NTFS-junction regressions
passed, including the whole-root post-enumeration swap. The independent nested
junction reproduction also completed. No operational intrusion was attempted.
