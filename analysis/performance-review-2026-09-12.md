# Performance review after Ollama and Defender recovery

The Ollama/Defender repair was validated and published as
`dd57126ce0376c9064512b8160787b38b7ef62ec`. The approved recovery and preserved
history are documented in [the recovery record](ollama-defender-recovery-2026-09-12.md).
This follow-on review addresses the maintainer's report that module additions and
updates progressively slow Angerona.

## Scope and evidence

The review covered discovery of all 84 modules, their polling/startup patterns,
the signed event pipeline and recorder, Defender's durable delivery state, local
AI readiness, graph retention/replay, and the principal Qt refresh paths. Inert
fixtures exercised 21/84/168-module dashboards, 20,000 graph nodes, up to 5,000
authenticated outbox/audit rows, and a synthetic model inventory. No benchmark
changed model trust, protection settings, response authority, or live detections.

Local diagnostic artifacts are under `.tmp/performance-review-20260912/` and are
not published because they include machine-specific diagnostic data. Timings are
workload-specific measurements on a Windows laptop that remained in use; they
are not a claim of a uniform speedup throughout Angerona. Removed I/O, bounded
work, unchanged authentication counts, and regression tests are stronger evidence
than timing alone.

## Findings and fixes

| Path | Observed before | Change and measured result |
|---|---|---|
| Idle AI health after receipt expiry | 695 ms and 56 MiB of model reads with a 32 MiB fixture | Authenticate small approved configuration without granting a receipt; 3.84 ms and zero model-blob reads |
| Missing configured model tag | 1,079 ms and 32 MiB read before rejection | Reject the absent approved tag first; 3.76 ms and zero blob reads |
| Unchanged Defender witness, 5,000 retained rows | 3,108 ms per full witness rebuild | 1.42 ms median with the final file guard; reuse one authenticated digest only while connection, database changes, and backing-file evidence remain unchanged |
| Defender tombstone pruning, 5,000 rows | 719 ms and a temporary SQL sort | Add the `(state, created_at DESC)` index; 0.841 ms without the temporary sort |
| Ten Defender deliveries, 1,000 retained tombstones | 26.68 s | 14.43 s in the initial optimized run, with the same 30,195 row authentications, 30 durable enrollment writes, and 10 cursor writes |
| Graph eviction at 20,000 nodes | 23.24 ms median, 37.63 ms p95 per event | Index retained lifetimes by PID; 0.047 ms median, 0.079 ms p95 for the same synthetic churn |
| Graph ledger catch-up | A single pass drained every page to EOF, ignoring a stop until it finished | Retain a finite replay watermark; at most 1,000 rows/250 ms of per-record work per slice, generation-bound cancellation, and interruptible yields |
| Flow dashboard with 5,000 audit entries | Full audit verification alone blocked Qt for 1,115 ms, excluding paint | Verify the full chain and collect all tab evidence on bounded workers; refresh request 0.78 ms median, subsequent complete Qt paint 35.95 ms median |
| New sensor coverage notices | Some HIGH/CRITICAL coverage notices counted as active threats and automatically woke deep scanners from Chill Mode | Recognize exact producer coverage contracts; preserve severity/signatures and keep explicit attack evidence active |

The AI receipt lifetime, mandatory fresh pre-inference verification, explicit
self-test byte checks, approval requirement, and independent integrity-guard scan
schedule remain enforced. A known byte-verification failure remains degraded;
metadata readiness cannot clear it.

Defender still validates row payload/state signatures, authenticates its witness,
preserves delivery acknowledgements, and writes its durable enrollment/cursor at
the original transition boundaries. Changed or unstable state cannot reuse a
cached digest. No history or retention limits were reduced.

The witness guard binds the canonical main-file identity and main/WAL change
evidence as well as SQLite transaction counters. On Windows it reads NTFS
ChangeTime so restoring a file's size and modification time cannot conceal a raw
write. Physical changes without a matching observed transaction fail closed.

Graph catch-up reports incomplete coverage and cursor progress until complete.
Only a completed slice counts as liveness; a stopped generation cannot continue
using a replacement generation's stop token. PID reuse and timestamp/ID fallback
semantics are preserved. Per-record native/SQLite work can exceed the slice's
elapsed target; the row cap and cancellation checks bound work between such calls.

Flow's workers never manipulate Qt objects. Requests coalesce; closing invalidates
pending results, reopening reuses workers, and errors keep evidence unavailable
rather than asserting a verified view. Case selection/custody reads use a separate
bounded reader, with stale selection updates rejected. Presentation snapshots do
not authorize commands. Audit display rows can be reused, while audit verification
still runs in full.

Coverage classification is restricted to Process Egress Lease Guard status,
authenticated Temporal Tradecraft missing/overflow coverage, precise Audit Log
reader-access/missing-channel errors, AegisPath missing-snapshot or verified-scope
health, and Driver Provenance coverage schemas. Ambiguous Temporal blindness,
invalid graph/manifest receipts, malformed audit evidence, unknown schemas,
explicit attack/exploitation flags, and checkpoint integrity failures retain their
active classification. Warnings are not acknowledged, deleted, or suppressed.

## Broader checks and remaining costs

All 84 modules discovered without errors or started sensor threads: 6.29–6.45 s
cold and 0.48–1.24 s warm, with roughly 29 MiB added resident memory. Discovery
alone does not explain the roughly 200 s initial status readiness observed before
these changes. The existing first-cycle startup gate intentionally staggers
sensors; lowering it indiscriminately would produce a startup stampede.

The generic signed EventBus delivered about 5,600–6,300 events/s to 30 inert
subscribers. The asynchronous recorder committed 1,000 events in 0.28–0.40 s with
zero overflow/loss in those fixtures. The expensive work was in consumers, so the
generic bus and recorder were left intact.

Other measured costs remain: first population of Flow's 500-row audit view took
276 ms; SOAR's 500-row table refresh took about 114 ms median when one status
changed; full alert-table replacement was about 109 ms median. Replacing widgets
150 times showed no unbounded widget growth. Module assurance refresh still has
cost, but broad trust caching was not justified by these measurements.

Cold local inference still verifies the entire approved inventory and selected
model. The real recovered `llama3` smoke test took 261 s including cold verification
and completion and briefly pushed this 16 GiB laptop close to its memory limit.
The model was unloaded afterward. This review did not change the operator's
configured model, bypass verification, or run further live inference.

Source-mode warnings about unavailable Sysmon/kernel evidence, missing optional
roots, unsigned source trust boundaries, or separately unapproved baselines remain
visible. They require their own evidence/configuration decisions; this recovery
approved only the Ollama models and Defender state described in the recovery record.

## Validation and live verification

Relevant offline gates completed:

- Final AI/Defender/outbox/Ollama transport and boundary regression run: 150 passed.
- Flow, worker lifecycle, Fleet and DetectionForge refresh regression run: 47 passed.
- Provenance replay/identity/eviction/performance and watchdog regression runs: 44 passed.
- Threat coverage/observation/Chill tests: 61 passed. Broader existing practice,
  headless Chill, combat readiness and idle-I/O tests: 55 passed.
- Audit event-log integrity tests after adding the native reader error code:
  15 passed, one platform/fixture skip.
- Full package compilation and Ruff over the reviewed code passed.
- The supported direct `tools/selfcheck.py` run passed twice: 26 phases, with
  69 module/pipeline passes, zero failures, and 16 expected unstarted/optional
  skips across the 84 discovered modules. Sensors are not started by this harness.

The full harness initially exposed a native Qt access violation during the first
event-loop pump. Merely using production feature initialization did not resolve
it. Retaining the MainWindow and DashboardCards Python owners through explicit
teardown, as the application does, resolved both subsequent direct runs. The
harness now retains those owners and uses the production Qt initialization path;
no check was skipped to obtain a passing result.

An earlier combined boundary-test run observed a conflicting-anchor fixture's
gap count twice instead of once. It passed isolated and in the final combined
150-test run without changing the product or fixture. A retry becoming eligible
during slow durable I/O is a plausible timing explanation, not an instrumented
root-cause conclusion. The earlier run is not counted as clean.

The normal source application was stopped through its tray Quit action. Its
Defender state then reopened authenticated with health 100, without another
recovery or history replacement.

The first live restart of the performance changes produced a fresh status report
about 53 seconds after core creation, compared with roughly 200 seconds in the
earlier observation. It initially remained in Chill Mode, then began the normal
sequential wake after active-classified evidence. Provenance is tenth in that
queue, behind gates that can take 60–180 seconds; it subsequently ran and finished
catch-up, retaining 13,222 historical ledger gaps and zero new rejected records.
Defender stayed at health 100 with authenticated continuity. The final report
before tray shutdown recorded 46,226 event deliveries and zero delivery failures.

That first restart did **not** establish an overall resource improvement. Its
300-second capture peaked at 332 MiB combined core/wrapper RSS and averaged 109%
of one logical CPU. It recorded 43 confirmed 200 ms window-response timeouts.
The earlier 180-second capture averaged 69% of one logical CPU and peaked at
299 MiB; differing startup phases, workload and host contention prevent treating
those as a controlled comparison. These live observations prompted the additional
FIM and Shadow Shield liveness work below, rather than a claim that every latency
issue was resolved by the microbenchmarks.

## Additional live scan findings

The saved profile enables **Maximum Adversary Combat**, whose aggressive scan
cadences deliberately carry an availability cost. Its selection was preserved.
FIM's approved baseline is absent, and the missing `drill-sandbox` directory is
part of the bundled default watch policy, not a custom user-supplied root. The
first 10,000 Documents entries already accounted for 434 MB (partial metadata
inventory). Shadow Shield also watches Desktop, whose first 5,000 entries added
595 MB. The live process accumulated more than 6 GB of reads and 664 MB of writes
within five minutes while scanners woke.

Two actionable liveness problems were confirmed: FIM checked cancellation only
after a whole directory and could hash up to 8 GiB without reporting progress;
an incomplete root set prevented baseline adoption and repeated that work.
Shadow Shield performed its initial full walk/cache work and a VSS subprocess
with a 90-second timeout before its first cycle, against a 30-second watchdog
budget. It could proceed into VSS after noticing stop in the file loop. Its VSS
call eventually returned an unelevated initialization error while Watchdog had
already exhausted repeated recovery attempts. No watch root was removed or
silently recreated, and no baseline was approved to clear these warnings.

FIM now checks the immutable generation token at directory, file, hash-retry and
64 KiB read boundaries. Real work publishes progress at most once per second,
with pending coverage/content verification and health 35; it creates no complete
scan receipt or baseline authority. A cancelled initial scan cannot publish an
armed state or adopt its candidate. Incomplete full scans retry after
30/60/120/240/300 seconds, visibly capped at five minutes. Maximum-mode driver
and assurance checks continue at their existing cadence during that wait. A
complete scan resets the delay immediately. Its first content scan still costs
the same reads; no new metadata-only content cache was introduced. The FIM
liveness, baseline, proof-custody and drill-digest checks passed 23 tests.

The missing default practice folder remains an explicit provisioning issue:
practice workflows create/register targets when invoked, while the default FIM
policy requires the folder before any complete inventory. Treating that root as
optional or provisioning it safely needs its own reviewed coverage policy; this
performance repair does not manufacture a trusted baseline from incomplete data.

Shadow Shield now yields after completed cache slices (128 files, 16 MiB copied,
or 250 ms between files), retaining explicit partial coverage until traversal
finishes. Copies use cancellable 1 MiB chunks and an atomic temporary-to-backup
publication; cancelled or changed-source copies cannot become partial `.bak`
artifacts. Per-key retention enumeration is bounded and reports an overflow
instead of doing unlimited work. Exact-artifact restore authorization is unchanged.

Its VSS command remains fixed, hidden, and limited to 90 seconds. A stop cancels
only the child process owned by that request and rejects late results from the
stopped generation. Already-issued OS work cannot be retroactively withdrawn;
the gate prevents a new request after stop. The declared 120-second work/startup
budget covers that existing bounded VSS call, while actual cache slices report
their own progress. Unavailable VSS or incomplete cache coverage stays degraded.
The lifecycle, cancellation, Watchdog and restore-authority tests passed 29 tests.
The hourly VSS attempt limit also applies when PowerShell is unavailable. After
both scan fixes, the supported full selfcheck again passed all 26 phases with
69 module/pipeline passes, zero failures, and 16 expected skips.

The final Shadow Shield cancellation review also removed synchronous pipe closes
after a timed-out child cleanup. Python 3.12's `communicate` reader threads own
those streams until EOF; an explicit close can wait on their I/O lock. The owned
child still receives cancellation, and the caller performs only its bounded
0.25-second poll and one-second cleanup wait. A focused regression verifies that
this timeout path does not call a blocking stream close.

The next 180-second live capture reported fresh status after 53.7 seconds,
300 MiB peak combined core/wrapper RSS, and mean CPU of 98% of one logical CPU.
It recorded 38 confirmed 200 ms window-response timeouts. FIM and Shadow Shield
were running with explicit partial scan/cache coverage instead of their prior
restart failures; Defender remained authenticated at health 100. The capture
still showed material UI stalls and CPU cost, so it does not establish a whole-app
performance improvement. It also exposed model-integrity and memory-scanner
deadline problems addressed below.

After that capture, the process exited during external UIAutomation inspection
of its tray menu. The preserved crash log contains native COM and access-violation
exceptions, and the peer watchdog relaunched the core. The cause is unproven;
this is not counted as a clean shutdown or an established consequence of any
specific patch. An inert probe found that the installed PySide6 binding retains
the tray menu after Python garbage collection, so menu ownership alone does not
explain this event. Further live UIAutomation queries were avoided. The replacement
core was stopped through its visually verified normal tray Quit action, with a
temporary authenticated maintenance request preventing another automatic restart.

## Model and memory scan lifecycle follow-up

AI Model Integrity Guard is eligible for automatic Chill wake and maintenance;
it is not one of the three user-only modules in the existing policy. Its complete
approved inventory scan exceeded the generic 30-second first-cycle/work deadline.
Cancellation was checked only between whole files, and an interrupted pass was
then reported as an integrity failure. AI Triage had the same work allowance and
could perform several fresh verifications in one event batch before reporting
any completed work. These are lifecycle defects, not evidence that the approved
model bytes changed.

Both AI modules now declare a bounded 300-second startup/work allowance. A typed
cancellation propagates through inventory hashing, configured-model blob hashing,
and the shared attestation lock wait. Checks occur before and after each 4 MiB
read, and a cancelled scan cannot return a partial digest or grant a receipt.
Pending verification remains explicit; normal stop does not report model tampering
or a completed scan. Each completed triage request advances liveness, so multiple
slow requests in one batch do not inherit the first request's expired deadline.
An unfinished request cannot advance that deadline. The model approvals, complete
byte checks, receipt expiry, and configured model remain unchanged.

The focused AI lifecycle, readiness, model-attestation, Ollama transport and
watchdog checks passed 81 tests. They include two simulated 180-second requests
in one batch, cancellation while waiting for another attestation, cancellation
inside both byte-read paths, and late transport success/error after replacement
of the module's mutable stop field. Independent review found no blocking issue.
Cancellation remains cooperative around individual filesystem/network calls;
the patch cannot preempt an operating-system call already in progress.

Memory Injection Scanner previously walked an entire process sweep before its
first liveness boundary, performed unbounded native address-map traversal within
each PID, and hashed executable identity before discovering that its existing
300-second per-PID alert cooldown would suppress the alert. It also performed a
second, optional address-map enumeration for loaded-module enrichment.

Each PID traversal now has a two-second/32,768-query bound and generation-aware
cancellation. Completed PID attempts report actual progress while the sweep is
still explicitly incomplete. A limited traversal does not count as a fully
scanned process; any observed RWX evidence is retained with partial-coverage
details and its existing alert-only authority. The unchanged cooldown is checked
before duplicate hashing/enrichment, and the optional second map walk is reported
as unavailable. Exact executable trust checks and process-access restrictions
remain enforced.

There are practical limits: later sweeps restart at address zero, so a consistently
large or slow process may retain an unexamined tail and continue to report partial
coverage. First-alert executable hashing still uses the existing size-bounded
shared helper; cancellation rejects its late result but cannot interrupt its
individual call. Access-denied processes remain measured gaps. No new watchdog
allowance, process exemption, executable trust cache or protection-setting change
was introduced for this scanner.

The memory-scanner lifecycle, observation/response authority and watchdog suites
passed 72 tests, including 15 new inert lifecycle regressions. Compilation and
scoped lint checks cover the final reviewed files. Publication uses a clean
worktree that excludes unrelated local development; the exact checkout must pass
the supported full selfcheck before the guarded publisher can advance public
`main` and verify every README image.

## Final integration and remaining lifecycle findings

The reviewed performance update was published as
`b513698a1d5da52bc439797f234a8022794163cb`. The clean checkout imported its own
package and passed all 26 selfcheck phases, with 69 module/pipeline passes,
zero failures and 16 expected skips. Documentation validation passed; the guarded
publisher proved public `main` and its publishing branch matched the commit and
all five public README images matched the checked-out bytes.

The restarted core then attested all 18 approved model files clean at health 100;
Defender continuity also remained at health 100. Triage showed pending fresh
pre-inference verification, while memory, file and backup scans reported partial
coverage. The fresh status recorded 21,387 event deliveries and zero failures.
The final 180-second monitor included about 129 seconds with the core present:
316 MiB peak core/wrapper RSS, mean 94% of one logical CPU, and 37 confirmed
200 ms window timeouts. Its startup also overlapped the isolated selfcheck, so
these figures are observations, not a controlled speed comparison.

Two remaining watchdog warnings were traced before closing the review. Evolution
Engine completed one initial cycle and then parked indefinitely on its stop
event, which inevitably expired the generic 30-second deadline. It now declares
a sparse 60-second interruptible idle cadence, adding no scans or inference and
keeping both missed-progress and dead-thread supervision. The idle, watchdog and
Chill regression suite passed 19 tests; stopped generations cannot publish a new
cycle. This fixes a conflict between the earlier no-polling optimization and the
subsequently enforced liveness contract.

Ransomware Heuristics had a separate quadratic rename matcher: it sorted and
searched the available names again for each disappeared name. An indexed matcher
preserves the original lexical greedy pairing, including casefold, dotted-prefix
and equal-stem alternatives. Inert sets of 1,000 disjoint names on each side took
9.1217 seconds before and 0.0345 seconds afterward; 25,000 on each side took
1.0599 seconds afterward. Equivalence checks cover 150 varied fixtures, including
Unicode and ambiguous-name collisions. These filename-only fixtures confirm the
hotspot without reading user content; attributing the entire live 54-second
deadline miss to it would require additional phase instrumentation.

Ransomware sample reads and entropy-candidate evaluation now check the immutable
generation token at their work boundaries. Actual completed work reports pending
coverage without overriding existing custody or coverage faults. Cancelled work
cannot begin a new authenticated state transition or publish a late completed
scan. A durable transition already admitted finishes its state/witness update
coherently. Existing content receipts, fair-scan selection, exact identity checks,
practice gates and response authority remain enforced; watchdog deadlines were
not broadened for this module.

The relevant ransomware, authenticated-content, traversal, authority, response
and watchdog regression suites passed 188 tests with one expected skip. The
final 18 lifecycle tests also passed after adding cancellation-boundary coverage;
product code was unchanged after the broader run. Independent review verified
that a rejected post-stop alert cannot consume its entropy cooldown or pending
rename evidence. Evolution's final three lifecycle tests also confirmed that
already-stopped entry preserves prior health and evidence.
