# Cycle 40 — CI cleanup and incremental presentation

Date: 2026-10-02. Source version: 1.13.0.

## CI evidence and repairs

GitHub run [36896881189](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/36896881189)
failed on published commit ada57824918e52626f573ea5cca917801837bb2c.
Python 3.12 passed 4440 tests with ten skips, but fixture teardown failed with
WinError 145 in `failed-commit-runtime`. Python 3.13 passed 4439 tests with
ten skips, but the plain VMware custody fixture exceeded its 90-second bound.
All other jobs, including Python 3.10/3.11 and platform contracts, passed.

Red Team fixtures now capture their owned module threads before lease release
removes temporary producers, signal every captured module, and join them under
one ten-second deadline before closing the recorder. `BaseModule.stop()` stays
nonblocking. Teardown failure remains visible if a worker cannot finish;
cleanup errors are not ignored. A delayed final-write regression proves a
lease-removed producer finishes before its fixture can be removed.

The VMware PowerShell fixture now uses a private TEMP/TMP directory. It retains
the real Add-Type compilation, directory handles, rename challenge, reparse and
hidden-file cases, and host-service modification prohibitions. Phase markers
and bounded stderr survive a timeout without printing the encoded command.
The 90-second limit remains. The original remote timeout did not identify its
phase, so private temporary storage is a stabilization candidate, not proof of
the timeout's root cause. New remote CI results are required.

## Continued UI performance work

Module-row rendering avoids redundant flag, check-state, color, tooltip and
numeric sort-role mutations. A tooltip-only update now emits one underlying Qt
model change; the separately loaded published renderer emits two and fails the
new regression. This measures notification work, not whole-application latency.

Focused validation: 33 Red Team/VMware tests passed, followed by 18 module-table
and delayed teardown checks. Full exact-commit validation and guarded GitHub
publication are required before completion.

The first full gate on 10a3464 failed: 4425 passed, 23 skipped, four failures
in 1666 seconds. The native QEMU fixture compared the redirected C: interpreter
path with Windows' physical D: image. It now resolves the launch path before
the exact image/PID assertion. The assertion-only observer child exceeded 60
seconds; isolated observer probes now disable unrelated pytest plugin autoload
and use private TEMP/TMP, retaining the explicit observer and all assertions.
These four focused native/observer cases passed after correction.

Both live containment profiles also left queued responses beyond their original
deadlines in that full run. Both passed an isolated follow-up with unchanged
deadlines. A separate host migration was copying data; one disk sample showed
D: queue length eight and approximately 82 MB/s throughput. Contention is a
plausible contributor, not exclusive causal proof or a repaired performance
defect. No journal fsync, custody check or containment assertion was removed.
Failed evidence remains in `.tmp/cycle40_release_evidence.json` and its JSONL
journal. The corrected commit requires a fresh whole-suite gate.

## Native Qt lifecycle investigation

The corrected gate on a33e1fa aborted at approximately 37%, exit 0xC0000409.
Its journal captured `QThread: Destroyed while thread '' is still running`.
The active Fleet Fabric pruning test owns no Qt worker; its identity does not
identify the destroyed worker.

Deferred close relied on collectable callback cycles and retained Qt parent
ownership. Parent destruction could bypass closeEvent and destroy an active
worker. Deferred owners now have an external strong registry and detach from
their parent while hidden. The registry releases them after worker exit and
the close callback. Closing stays nonblocking; workers are not terminated.

SentinelLens allowed queued completion to schedule a fresh snapshot after
accepted close. Its terminal closing flag now rejects late snapshot/import/AI
callbacks and new refresh/import/AI work. A regression delivers completion
between accepted close and deferred deletion and verifies no refresh starts.

The native parent-destruction/GC child survives the repair; the published helper
aborts with 0xC0000409. Published snapshot callbacks fail the late-close test.
Combined QThread/SentinelLens/Fleet Fabric validation passed 41 tests with one
skip. These challenges prove the defects, not attribution of the earlier
destroyed worker. A fresh whole-suite run remains necessary.

## Published gate and rotation follow-up

The exact-commit local gate on 73b4f79 passed all five checks: 4431 tests
passed and 23 skipped in 1259.74 seconds. The guarded publisher verified
public main and all five README images. Hosted CI run 37066045684 passed
11 of 12 jobs, including Python 3.10, 3.11 and 3.13; Security assurance
run 37066045685 passed. Python 3.12 instead failed the oversized alert-log
rotation test (4443 passed, 10 skipped). CI was therefore still failing.

The local Python 3.12.10 retention suite passed 37 tests with two skips;
the hosted failure's precise cause remains unconfirmed. Its assertion now
checks the oversized fixture before writing and reports directory names/sizes
if no archive appears. The writer now uses the held descriptor's end offset
for its rotation size and append position, while retaining plain-file and
single-link validation. Previously it discarded that offset and relied on
metadata; after rotation it also wrote from offset zero if a replacement
file already existed. New tests preserve a real oversized archive under
injected stale size metadata and preserve replacement bytes created between
handles. Both reject the published writer. The repaired retention and
integration suites passed 46 tests with two skips. These challenges prove
the defects, not attribution of the hosted failure; fresh CI remains required.

The simultaneous-start mode witness on published 73b4f79 ran 66 selected real
workers from 84 discovered modules, with private data and inert watch files.
Its three 90-second phases measured maximum heartbeat gaps of 4262 ms in
initial Chill, 324 ms in Full and 855 ms after returning to Chill. An adjacent
separate Qt control peaked at 152 ms. All 744 accepted recorder events were
persisted, with no pending queue/spool and no captured module threads left
after bounded shutdown. Initial Chill still froze; no instrumented callback
explained its entire maximum gap. Excluded host-mutating modules, offscreen
rendering, short duration and host scheduling limit this witness. This is
not an all-module, all-day soak or a native simulation score. Evidence is
retained in `.tmp/cycle40_mode_soak_result.json` and
`.tmp/cycle40_qt_control_result.json`.

## Windows persistence follow-up

The full local gate on 3f191a5 completed with 4430 passes, 23 skips and three
failures in 1704.18 seconds. Bytecode, dependency audit, documentation and lint
passed. Alert rotation, the two-pass live GUI drill (187.75 seconds), both
containment profiles, worker teardown and VMware cases passed. Failures were
device-lab state replacement (WinError 5), temporal overflow becoming blind,
and concurrent CVE proposal ledger updates. Evidence remains in
`.tmp/cycle40_release_evidence_rotation_fix.json` and its journal.

All three writers used one atomic replacement attempt, unlike other state
writers that already tolerate short Windows sharing locks. They now use the
existing bounded `replace_with_retry` helper. Temporary-file fsync, authenticated
state, prior-file preservation, temporal blindness after permanent storage
failure and inert-only CVE proposals remain enforced. A native Windows reader
denying delete access forces the actual replacement error in each writer.
Releasing it after the first error permits save and reload; retaining it
exhausts seven attempts, preserves the old bytes and removes the temporary.
The temporal engine still locks persistence and reports blind/unavailable.
All six native cases passed; all three old writers reject the released-reader
challenge. Focused persistence/helper tests passed 44 with one skip.

These tests demonstrate the unhandled-lock defects. The device-lab traceback
identified access denial; the exact OS error behind the other full-run states
was not captured. Their existing assertions now report persistence status or
failed proposal results. This is not a claim that every storage error is
transient. Relevant adjacent UI tests and fresh whole-suite hosted CI are
required before reporting this follow-up complete. Adjacent proposal, temporal
health and device/UI validation subsequently passed 12 tests.

## Hosted CI confirmation and performance follow-up

Commit 80896ea passed all 12 hosted CI jobs, including Python 3.10 through
3.13, and all three security assurance jobs. Runs:
https://github.com/Ag3nt47/AngeronaSuite/actions/runs/37071908551 and
https://github.com/Ag3nt47/AngeronaSuite/actions/runs/37071908575.

A separate native-stack sampling technique identified ARP startup importing
the aggregate Scapy protocol suite, including unrelated Kerberos, DCERPC and
certificate decoding. The 60-second profile captured 1142 samples with two
errors; ARP startup accounted for 36.35 seconds of inclusive sample weight.
The profiler reported sampling lag, so these weights are diagnostic evidence,
not an uninstrumented latency measurement. ARP capture now imports only its
send/receive API and L2 decoding. Real encoded Ethernet/ARP packets still reach
candidate provenance without granting implicit baseline trust. Capture and
baseline tests passed 21 cases; the published startup fails the new cold-import
challenge.

Windows SSH discovery reuses the PID already present in its service status
snapshot, avoiding a redundant native query and incorrect association after
a restart. SSH and host-adaptation tests passed 64 cases with one skip; the old
collector fails the restart challenge.

A separate three-phase, 90-second-per-phase fixture without an attached
profiler exercised 66 selected workers. The repaired ARP/SSH working tree
produced initial Chill / Full / returned Chill p95 timer gaps of 74 / 43 / 43
milliseconds, with maxima of 3011 / 1527 / 2121 milliseconds. All 1050 accepted
events persisted, queues and spools drained, and captured workers stopped.
The separate Qt control's maximum gap was 74 milliseconds. The earlier profiled
boundary witness had initial Chill p95 2870 milliseconds and maximum 9605;
host conditions differ, and these short simultaneous-start fixture runs do
not establish all-day performance. Source hashes and raw evidence remain in
`.tmp/cycle40_arp_fix_source_snapshot.json` and related fixture artifacts.
Multi-second stalls remain open. Dashboard changes were applied after this run.

Dashboard health chips now update note-only tooltips. Health and resource
chips avoid resetting unchanged styles on numeric updates, while real color
transitions still restyle. Three visible-widget tests count native Qt style
events; all reject the published refresh methods. The repaired dashboard and
module-panel tests passed 20 cases, with 36 adjacent dashboard tests passing.
This follow-up was published as f2ca02e, with all five public images verified.
Its Python 3.10, 3.11 and 3.12 suites passed, but Python 3.13 failed after 4455
passes and 11 skips: the plain VMware custody fixture exceeded its unchanged
90-second PowerShell bound without a phase marker. Security assurance passed
all three jobs. The fixture now uses a private module-analysis cache, restricts
module discovery to the trusted inbox directory and explicitly imports the
required inbox modules before installing its host-mutation overrides. Native
cmdlets, the reviewed production body, foreign-directory rejection and ancestor
rename challenges remain intact. Earlier entry/module-loading markers improve
future attribution. This removes shared cache and module discovery inputs;
the blank failure log does not prove they caused the timeout. Fresh hosted
validation is required for this fixture follow-up. All 26 VMware setup tests
passed locally with these isolated module inputs.

## Repaired-startup native profile and ETW fallback

A second native-stack capture on 9347f84 collected 1110 samples with 11 errors
and reported sampling lag. ARP startup no longer appeared in that capture.
The ETW fallback accounted for 6.3 seconds of inclusive stack weight, with
5.65 seconds in Windows parent-ID queries. The fixture's instrumented maximum
timer gap was 12.652 seconds; its separate Qt control maximum was 26 ms.
This is diagnostic evidence of remaining stalls, not a clean latency benchmark.
All 381 accepted events persisted, queues drained and captured workers stopped.
Raw artifacts use the `.tmp/cycle40_repaired_native_*` prefix.

The ETW process fallback previously fetched PID, parent ID and name for every
process on every poll, although it publishes metadata only for newly observed
PIDs. Windows psutil's parent-ID accessor enumerates its native parent map.
The fallback now diffs PID-only observations and enriches new processes with
the same public metadata API. A process that exits during enrichment is removed
from the known-PID set so later reuse can be observed. Security-channel reads,
cursor custody and the polling interval remain unchanged.

A native test spies on the real psutil parent accessor and creates an owned
inert child. Baseline queries fell from 265 on the published method to zero;
the child still receives one creation event with its actual parent and name,
and steady polls do not re-enrich it. The old method fails this challenge.
A separate disappearing-birth case guards the baseline race. Relevant ETW,
cursor and event-log integrity validation passed 28 tests with one skip.
The earlier attempt to spy on the accessor omitted psutil's cache hooks and
failed in the test harness; preserving them with `functools.wraps` repaired
the observer before running either comparison.

## Remaining limits

Cycle 39's full local gate passed 4427 tests with 23 skips and publication
verified all five README images. That local pass did not prevent these remote
CI failures. Chill/Full stress pauses, variable native simulation scores and
the earlier unexplained Qt abort remain open. This cycle does not claim a
native coverage score or repair of all mode freezes.
