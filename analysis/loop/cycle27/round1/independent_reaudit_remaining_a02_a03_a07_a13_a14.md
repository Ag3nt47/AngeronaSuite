# Cycle 27, Round 1 — Independent Re-audit of Remaining A02/A03/A07/A13/A14

Scope was limited to the current implementations of `C27-R1-A02`,
`C27-R1-A03`, `C27-R1-A07`, `C27-R1-A13`, and `C27-R1-A14`. The review was
read-only with respect to product code and tests. Every runtime reproduction
used only temporary files, fake event-log objects, synthetic evidence, and
in-memory method substitutes. No live Defender/Security channel, driver,
process, firewall, registry value, credential, network target, or host posture
was changed.

Audited source snapshot (SHA-256):

- `adversary_combat.py`:
  `2ac3f3e9045d34211be729d19dd1c5dfeb18497138538e08e1bb972cc738fbb6`
- `av_telemetry_bridge.py`:
  `80dd87084f6388a18ee2cd12918535f49a7d69c08cfbbc65311797272b45d0c9`
- `deception.py`:
  `9469bf2919f6ab6fa3c36c965700da1201508eed43099b5087ae0a66b84abcc0`
- `driver_provenance_guard.py`:
  `378202d8d4f37716a688f0a780d670369afd484d8ead7c48bd56b3824df13a00`

## Verdict

No assigned finding is fully closed. Two have useful incidental partial
remediation: Combat now imposes strict resource ceilings, and Active Deception
now truthfully advertises reduced coverage and caps live health at 70. The
semantic live-action truncation, hard-link alias, retained Defender visibility,
read-observer, and loaded-driver object-binding gaps remain reproducible.

| Original finding | Verdict | Residual severity | Independent result |
|---|---|---:|---|
| `C27-R1-A02` | **PARTIALLY FIXED (incidental)** | MEDIUM | Journal reads are bounded, but append is still full-history quadratic, no transaction capacity is reserved, startup uses only 500 displayed actions, and `undo_all()` uses only 5,000. |
| `C27-R1-A03` | **OPEN** | MEDIUM | A two-link file was accepted and committed as quarantined while its alias survived; alias mutation after pin release produced an `applied` commit whose receipt hash no longer matched the quarantined object. |
| `C27-R1-A07` | **OPEN** | MEDIUM | Both fake restarts silently drained the same retained Defender detection, processed zero records, and reported health 100. No authenticated cursor, generation, gap, or delivery state exists. |
| `C27-R1-A13` | **PARTIALLY FIXED (incidental)** | MEDIUM | Health/description now disclose missing reads, but a generated lure still promises “Any access is logged & isolated”; an ordinary read produced no alert, and registry reads still have no observer. |
| `C27-R1-A14` | **OPEN** | MEDIUM | Service-config paths are sampled with separate path operations and no loaded-image/file-object binding. A schema-complete synthetic record with no binding field was classified `provenance-verified`. |

## `C27-R1-A02` — Bounds exist; efficient and complete live state does not

### What improved

`src/angerona/modules/adversary_combat.py:94-97` now caps the journal at 32 MiB,
64 KiB per line, 32,768 records, and JSON depth 16. Bounded descriptor reads and
strict resource/schema checks at lines 2244-2346 and 2509-2628 reject
oversized/deep input. The dedicated deep-input and byte-budget tests passed.
This closes the original **unbounded-memory** form of the finding.

### Residual evidence

`_append_journal()` at lines 2630-2678 still calls `_read_journal(strict=True)`
before every append and again after it. Both calls reread, split, decode,
schema-check, HMAC-check, and anchor-check all prior records. The total cost of
N appends therefore remains O(N^2), merely capped at a high ceiling. In a
temporary 100-record journal, consecutive 25-record append windows took
1.4735, 1.8975, 1.9896, and 2.2606 seconds; the last window was 1.53 times the
first even at this small scale.

There is no authenticated complete live-action index or compaction. Display
and control semantics share one truncated API:

- `_reconcile_state()` uses `list_actions(limit=500)` at lines 3541-3587.
- `undo_last()` considers at most 500 actions at lines 4231-4235.
- `undo_all()` considers at most 5,000 actions at lines 4237-4250.
- `list_actions()` constructs every commit and then slices only the requested
  suffix at lines 4015-4059.

An inert 5,001-commit fixture passed through the real `list_actions()` and
`undo_all()` selection logic:

```text
total_live=5001
visible_to_undo_all=5000
attempted=5000
oldest_attempted=false
```

The hard ceiling is also not a transaction reservation. `response_ready()` at
lines 1129-1135 does not check journal capacity, and `_journaled_mutation()` at
lines 2680-2689 reserves no terminal slots or bytes. With only one record slot
remaining, an intent may consume it before the host effect, after which commit,
orphan, undo, and failure phases cannot be appended. Existing recovery logic
usually remains fail-safe because the intent is durable, but the module can
cross an effect boundary into an avoidable accounting outage and may report
armed health until the next attempted append.

### Minimal remediation design

1. Separate the display tail from control state. Maintain an authenticated,
   host-bound live-action index containing every applied reversible action and
   every pending/recovery phase. Update it transactionally with the journal
   anchor/witness; never derive control state from a UI limit.
2. Segment the journal and authenticate each immutable segment plus a compact
   checkpoint/root. Verify only the current segment and checkpoint on append;
   compact terminal history atomically while retaining all live actions and
   recovery records.
3. Before writing an intent, reserve worst-case record and byte capacity for
   the intent, terminal/orphan, rollback intent/terminal, and circuit receipt.
   If the reservation cannot be proved, refuse before any host effect and set
   explicit saturation health.
4. Make `undo_all()` iterate the complete authenticated live index. Keep
   pagination/limits only in `list_actions()` for presentation.

Required gates: 501 active rules survive restart reconciliation; 5,001 active
reversible actions are all attempted by `undo_all()`; near-record and near-byte
ceilings refuse before the effect; crash-safe segment rotation/compaction
preserves anchor/witness continuity; and append latency does not scale with
total terminal history.

## `C27-R1-A03` — Quarantine still accepts and releases multi-link objects

### Residual evidence

`_PosixPinnedFileMove.__init__()` at lines 390-410 validates type and owner but
not `st_nlink`; its rename at lines 492-521 does not recheck it.
`_WindowsPinnedFileMove.__init__()` at lines 537-560 reads a structure that
contains `nNumberOfLinks` (declared at lines 701-719) but ignores the value.
Neither same-volume rename (lines 764-809) nor cross-volume copy/delete
(lines 824-906) requires a single-link source.

On Windows, a temporary two-link file was accepted by `_PinnedFileMove`:

```text
links_before=2
source_exists=false
destination_exists=true
alias_exists=true
alias_bytes="inert-defensive-fixture"
same_identity=true
```

The more important terminal-boundary reproduction used the real
`_quarantine_file()` transaction. The method hashes and moves under the pinned
handle, but explicitly closes that custody at line 2933 before
`_commit_after_mutation()` at line 2934. The inert fixture changed the surviving
alias at that exact boundary. Combat then appended an authenticated `commit`
with status `applied`, while the destination bytes no longer matched the
receipt's SHA-256:

```text
committed=true
alias_survived=true
journal_last_type=commit
journal_last_status=applied
receipt_hash_matches_destination=false
```

The existing no-follow traversal, exact file ID/inode, write/delete-sharing
denial while pinned, post-move hash, and journal custody are strong controls.
They prevent path substitution during most of the transaction. They do not
remove a pre-existing name for the same object or protect the object after the
file handle is closed and before the journal terminal is durable.

### Minimal remediation design

Require link count exactly one on the retained source handle at enrollment,
immediately before mutation, immediately after rename/copy, and immediately
before terminal commit. Record the observed source/destination link counts and
object identity in intent and commit. Treat an unavailable link-count proof as
“alias-safe quarantine unavailable,” not success.

Keep the current object and source/destination directory custody live through
the journal terminal. Extend the pinned mover so the same retained object can
roll back to the original directory entry without closing/reopening after a
commit failure. For cross-volume quarantine, reject a multi-link source before
copy/delete and require the new destination object to have one link. Enroll and
verify restrictive quarantine-root custody so a new alias cannot be introduced
between final validation and release.

Required gates: pre-existing Windows and POSIX hard links; an alias created at
each pre/post-move boundary; alias content mutation between postcondition and
commit; cross-volume alias behavior; restart/undo of an alias-rejected intent;
and proof that no success receipt is issued unless the committed destination
still matches its exact identity, digest, and single-link postcondition.

## `C27-R1-A07` — Defender history still has no restart/delivery continuity

### Residual evidence

`_try_evtlog_mode()` at lines 204-241 opens the legacy event-log handle and
silently drains all retained records at lines 218-225. It keeps only the handle's
in-memory sequential position. On a read error it opens a new handle and resets
health to 100 at lines 233-239 without a cursor, channel-generation check, gap
receipt, dedupe key, or retained replay decision. Old handles are not closed.
`_process_record()` at lines 243-276 also omits the channel record number from
published identity.

Two separate fake process starts each exposed one retained EID 1116 record.
Both starts drained it, processed zero records, and ended at health 100:

```text
restart 1: read_calls=3 retained_processed=0 health=100
restart 2: read_calls=3 retained_processed=0 health=100
```

The PowerShell path remains equally volatile. `_try_powershell_mode()` seeds
every current `DetectionID` into an in-memory set at lines 300-307, discards
those retained detections, and swallows later poll failures at lines 309-337
without lowering its health-80 state. There is no delivery acknowledgement in
either mode, so even a future bookmark must not be advanced before the emitted
event is durably accepted.

### Minimal remediation design

Use the modern Windows Event Log API with a bounded query and an authenticated
bookmark bound to channel, host, channel generation/oldest/high-water anchors,
record ID, and record digest. On first enrollment, process a bounded retained
window or emit an explicit retained-history omission; never silently drain it.
Persist an authenticated pending batch/outbox before cursor advancement and
advance only after delivery acknowledgement. Replay unacknowledged stable
`generation + record ID + record digest` identities after restart.

Represent clear/refill, record-number reuse, retention loss, unreadable record,
collector reopen, output truncation, and PowerShell fallback failure as durable
gaps that hold health below 100. Persist fallback `DetectionID` delivery state,
bound its size/age, and close every native handle deterministically. Reuse a
shared, independently tested continuity/outbox primitive rather than copying a
cursor-before-delivery implementation.

Required gates: retained detection before first start; restart after delivery;
crash before and after publish acknowledgement; clear/refill and record reuse;
cursor rollback/tamper; read error/reopen; duplicate replay; fallback restart;
and exact processed/skipped/error/gap counters.

## `C27-R1-A13` — Honest downgrade is useful, but read trapping remains absent

### What improved

The module-level contract at lines 1-10 and description at lines 71-74 now say
that the module proves only file mutation/deletion and needs an external OS
source for audited reads. `run()` at lines 138-152 sets health to 70 (45 for an
incomplete canary set), states the exact missing capability, and emits
`read_visibility=false`. An isolated live run independently produced:

```text
health=70
coverage=file-mutation-and-deletion
read_visibility=false
note="file mutation/deletion visibility active; audited file/registry read telemetry is unavailable in this module"
```

The registry-lure docstring also no longer claims that a read is observed.
These are material, truthful partial fixes and prevent a green 100% module from
representing read coverage.

### Residual evidence

`_check_canaries()` at lines 163-177 still polls only `st_mtime`. A normal file
read leaves that value unchanged and produces no event. `_plant_fake_registry_cred()`
at lines 232-242 still only writes a value; there is no registry read observer.
Most importantly, `_restage()` still writes this claim into every dynamic lure
at line 221: `Any access is logged & isolated.`

The inert dynamic-lure reproduction read the generated credential file and
then called the real canary checker:

```text
lure_claims_any_access=true
mtime_unchanged=true
alerts_after_read=0
baseline_unchanged=true
```

Default deployment outside personal folders and the explicit opt-in for
personal-folder/registry lures reduce exposure. Modification/deletion alerts
remain useful. A read-only credential-harvest path is still invisible.

### Minimal remediation design

Immediately change the remaining lure text and internal “any interaction”
wording to the exact mutation/deletion contract. Full read visibility should be
an explicit audited mode: enroll each decoy by volume/file ID and registry
key/value identity; verify the required File System/Registry audit policy and
per-object SACL; consume bounded, restart-safe 4663-equivalent or kernel-sensor
records; bind actor PID, process birth, executable identity, target object, and
access mask; deduplicate self-generated planting activity; and retain gap state.
Only advertise `read_visibility=true` or health 100 while that source, policy,
SACL, cursor, and delivery path are all verified.

Required gates: an ordinary file read and registry value query each produce one
object-bound event; a same-path replacement cannot inherit authority; wrong
object/actor/replayed records fail; missing audit policy/source/cursor remains
below 100; restart cannot skip retained reads; and module self-reads do not
create false trips.

## `C27-R1-A14` — Driver evidence is not bound to a loaded image or one file object

### Residual evidence

The collector's PowerShell at lines 273-328 asks `Win32_SystemDriver` for
services whose state is `Running`, takes each service's configured `PathName`,
and then performs separate path operations:

- `Get-Item` and length/mtime sample at lines 295-301;
- `Get-FileHash` at line 302;
- `Get-AuthenticodeSignature` at lines 303-306; and
- a second `Get-Item` length/mtime comparison at lines 307-310.

It retains no no-follow file handle, volume/file ID, link count, parent custody,
load base/size/generation, Code Integrity receipt, or kernel loaded-image
identity. Equal-size/equal-timestamp object swaps can compose hash and signature
evidence, and a benign disk replacement after a malicious image was loaded is
indistinguishable. Service `Running` state is not proof that the sampled disk
object is the image mapped in kernel memory.

The evidence schema at lines 35-50 and 65-79 has no binding field. The token at
lines 415-417 contains only service name and file basename, while line 460
unconditionally writes `load_state="running"`. The assessment at lines 195-247
can therefore issue `provenance-verified` from internally supplied values with
no loaded-object proof. An inert schema-complete fixture confirmed:

```text
state=provenance-verified
evidence_complete=true
binding_fields=[]
```

The guard is read-only, row/output/file-size bounded, uses a fixed trusted
PowerShell executable, exposes truncation, and treats the provider's ordinary
bundled blocklist non-match as unknown. HVCI/Secure Boot context and no automatic
driver response materially limit impact. They do not make the provenance join
object-bound.

### Minimal remediation design

First make the current PowerShell provider explicitly
`configured-path-sample/unbound`; add a mandatory `binding_state` and prevent
`provenance-verified`, trusted signer/catalog attribution, or exact `running`
claims unless a trusted loaded-image receipt is present.

For disk evidence, open the exact non-reparse image and its parent chain with
write/delete replacement denied; require a fixed local volume, regular file,
trusted custody, and link count one; record volume/file ID; hash through that
handle; calculate the catalog hash through the same handle; and keep custody
until signature/catalog verification and assessment publication complete.

For loaded-image binding, extend the trusted native/kernel collector to issue a
monotonic boot/session/load-generation receipt binding module base, image size,
normalized image identity, Code Integrity disposition, and the exact backing
file object/digest observed at image-section/load time. If only a pathname or
post-load disk object is available, report `unbound`/`unknown`. Do not equate a
SCM/CIM service state with an exact loaded module.

Required gates: benign disk replacement after an inert simulated load; same-size
same-timestamp swap between hash and signature; leaf/parent reparse and hard
link; service-running without a loaded-module receipt; path reuse across unload/
reload generations; catalog evidence bound to the handle digest; and a negative
test proving no unbound provider can produce `provenance-verified`.

## Validation

- Focused compatibility suites: **55 passed** across Combat journal/boundary,
  event XML, Deception data-boundary, Driver Provenance, and module self-test
  coverage.
- Existing strict Combat resource gates: **2 passed** for deep JSON and byte
  ceiling behavior.
- `py_compile`: passed for all four audited product modules.
- Ruff: passed for all four audited product modules.
- Inert reproductions: A02 tail completeness and append-cost trend; A03 alias
  survival and post-custody commit drift; A07 two-start retained suppression;
  A13 plain/dynamic-lure read invisibility and health downgrade; A14 missing
  binding-schema acceptance.
- New adversarial test file: not added. Permanent tests should assert the fixed
  contracts, not normalize the reproduced vulnerable behavior; exact proposed
  gates are listed above for the remediation agent.

Final count: **0 closed, 2 partially fixed incidentally, 3 open**. Residual
severity: **5 MEDIUM, 0 HIGH/CRITICAL**.
