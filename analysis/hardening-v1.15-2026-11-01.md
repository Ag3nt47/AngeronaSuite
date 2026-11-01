# Angerona 1.15 November runtime and shutdown review

1 November 2026 · sanitized source-development follow-up

Application version remains 1.15.0; Windows package metadata remains 1.15.0.0.
This review supplements the [October WER/status record](hardening-v1.15-2026-10-30-wer-status-ci.md).
The prior published revision completed all 15 hosted checks. The changes here
require their own publication and exact-commit CI; they are not an accepted
signed production release or proof that all exploit paths are blocked.

## What the pasted history established

Black Box was reading mixed historical data as though it were one current test
run. One embedded historical run contained two failures alongside supervisor
event rows; 49 list containers were not 49 newly failed tests. The corrected
reader expands one embedded run level into 50 observations, preserves recorded
dates and distinguishes run results from event rows. It does not invent one
aggregate run. Malformed/deeper entries and traversal/output/read bounds remain
explicit; original bytes are preserved. Historical errors no longer create a
current exception overlay, while current-log classification is unchanged.

The older APPDATA errors belong to an earlier source revision whose call site
was already corrected. Explicit environment override rejection stays strict.
A later SAFE_MODE observation supports a startup-readiness question, not a
proved cause of the GUI stall. A stack ending in `qt.exec` does not identify
which work or callback delayed the UI. There is **no evidence that Optimus
deleted diagnostic data or caused these failures**; missing files and timing
alone do not identify an actor.

## Implemented controls and their limits

- **Normal logging:** the complete Python/Qt UTF-8 message limit defaults to
  64 KiB and is configurable from 4–256 KiB. The default 8 MiB admission limits
  cover the opened file and each
  process's role reservation. Existing bytes are preserved; uncertain writes
  stay held without refunds. Settings distinguishes saved limits from live
  application, with Block, Allow/change, one nonmodal notice per category and
  an explicit pending retry when busy. Optional logging holds do not block
  startup. This is not an OS quota, a file-identity/reparse lease, a shared
  cross-process cap, or a bound on native/external writes or earlier formatting
  allocations.
- **Logging provenance:** install-generation PID and raw native birth are
  captured once after hook installation and retained as exact decimal text
  in headers/status. Named bytes and arming reports remain distinct from
  writer attestation, native-hook health or complete fault capture.
- **AI admission:** an early read-only service check refuses an ineligible
  service before full model hashes. Host/model/generation and expected-model
  fences stay bound, while the final trust/transport gate, bytes, TTL and
  cadence remain unchanged. Cached request-stage timing includes inline
  callbacks and is not isolated AI-module CPU cost. Refusal is not a claim
  that a model was verified or a request completed.
- **Owned startup:** an exact successfully launched, retained process/Job
  receives one fixed 180-second monotonic starting window. The first valid
  authenticated heartbeat consumes it. The window grants no healthy state,
  deadline extension, expiry-triggered kill or duplicate spawn. Real exit
  remains actionable; waiter errors/invalid results are not exit proof, and
  completion rechecks the same owner under the lifecycle lock. Adopted PIDs
  and the separate five-second cross-peer claim remain outside this window.
  Expired-but-live startup remains explicitly held.
- **UI containment:** synchronous UGCAP refresh work now sits inside the
  refresh timing/exception boundary with bounded nonfatal reporting. This
  contains an exception; it does not prove the cause of a previous long stall.
- **Recovery confirmation:** the recovery-copy decision is explicitly
  nonmodal, so it can remain visible without disabling dashboard STOP.
  Only Yes queues deletion; No/default/Escape behavior is preserved. No
  recovery files were deleted when the observed blocking dialog was declined.
- **Final self-exit mitigation:** only the final Windows self-exit point,
  after durable operator STOP, existing bounded owned cleanup and a Qt-quit
  attempt, now uses a fixed current-process pseudo handle and exit code zero.
  It accepts no PID/handle/code parameter and adds no other-process access,
  privilege or I/O. Exception/unexpected-return paths retain the existing CRT
  fallback; other platforms are unchanged. This is a platform-semantic
  mitigation, not a substitute for cleanup, descendant-retirement evidence,
  guaranteed I/O completion or a proved repair of the native fault.

## Local validation

The focused AI cohort reported 327 passes/three skips; logging/UI reported
291 passes/one skip after a test-only oversized-ID correction. The private
observer models reported 53 passes in 43.47 seconds. An earlier owned-helper
timeout remains unexplained historical evidence, not a passed run.

The November runtime cohort passed 275 cases with one skip in 40.82 seconds.
The final exit/storage cohort passed 252 cases in 30.93 seconds, including
seven recovery-confirmation regressions. Completed JUnit independently
established 252 executed tests with no failures/errors/skips; an early process
exit alone would not prove completion. Native retirement, cleanup and unchanged
source/preferences were recorded for the owned gates. The final finite
startup preflight passed without launching a dashboard. Cohorts overlap and
must not be summed. Source tests do not establish native exploit prevention.

## Separate observations and shutdown evidence

The first November 120-second Full capture used the earlier 500-file source
candidate. Its automatic STOP verification was **not accepted** because a
window-modal recovery-copy confirmation disabled the main dashboard. No STOP
header or Yes action occurred in that held attempt; it is not a proved crash.
The dialog was later declined with No, the main dashboard re-enabled, and a
separate normal STOP plus retained native witness established Core exit zero
and retirement within that witness's scope. This addendum does not rewrite
the original observation's acceptance result.

An earlier manually quit instance had no retained native exit-code evidence
because its query handle had already closed. Subsequent discovery found no
related process, but that is not a native exit-zero receipt.

After the final nonmodal/self-exit changes, the 501-file candidate passed a
separate 60-second Full/STOP observation. Lifecycle acceptance was true: actual
Core native exit zero, all 39 observed unique generations (38 descendants plus
Core) retired and all 43 native wait rows signaled. There was one child admission
gap, no topology bound, no forced retirement and no harness application
termination. Source and selected saved/authority preferences stayed unchanged.
Polling remains incomplete for short-lived children.

The final capture had 2,287 records: 590 events, 1,468 diagnostics, 198 coverage
records, 29 heartbeats, a hello and a gap. Initial retention loss was 4,335.
Of 256 new events, 190 were informational, 38 medium, four low, 23 high and
one critical. Twenty-two high records were inference-socket role leads and
one was persistence-collection health. The critical SOAR severity aggregation
was not independent attack evidence. All diagnostics/coverage were retained
history, not new collection verification. The reader reported all 590 exports
verified in its HMAC-only scope; the analyst did not independently reverify
bytes, keys or native producer identity. No compromise or clean-host verdict
follows from these records or their retention gaps.

The 66 new non-informational records comprised 17 exposures, five unavailable
collection/assurance notices and 44 unresolved leads, with no supported active
attack established in those retained records. Ordinary record sequence was
continuous after the initial gap; this does not recover the missing history.

### Heartbeats and copied status

All 27 runtime samples wholly inside the reader window had four fresh
authenticated Core/Watch/Scan/BlackBox heartbeat views. Three unavailable counts
per role occurred only after STOP. The freshest end status was generated inside
the window but copied just after it: 75 running, 17 critical, 33 degraded,
one failed and 24 OK, with 69 unknown sensor-continuity states. The last copy
strictly inside the window instead had 23 OK/34 degraded. These as-of differences
are retained, not merged into one atomic live receipt. Native ETW/Sysmon remained
unavailable; heartbeats do not establish detector efficacy.

WER had 27 copied views: twelve admitted-at-last-check and fifteen stale with
expired leases, representing nineteen distinct status versions (eight admitted,
eleven stale). Retained last admission was admitted throughout; 26 owner views
contained four roles and one contained three. Copied queue/loss/skipped counters
were zero and upstream delivery was unverified. Copies could already be
3.161 seconds old, so neither prior admission nor zero copied counters proves
freshness at reading, continuous availability or loss-free upstream delivery.

AI attempt counters progressed from zero to 35 across fifteen unmeasured and
twelve circuit-open views. Observed attempts recorded one service check, zero
model checks and zero requests. This supports the observed early refusal path,
not completed model verification or a measured hashing speedup. Both normal-log
rows were held with `resume-check-required`, showing one 409-byte block per role
and no suppression. Their checked file sizes were stale pre-Full observations,
not current file accounting, native-write coverage or an OS quota receipt.

### CPU and interface scope

Over the 56.700798-second process-counter window, Core averaged **116.951618%
of one logical CPU**, inventory 8.487535%, ten stable endpoint generations
129.627806% combined and the diagnostic owner 5.979854%. Stable generations are
a lower bound excluding transients; diagnostic work was competing load. Different
host/event/timing contexts prevent a controlled speedup comparison. These are
not whole-machine percentages.

All 27 WM_NULL probes responded, with mean 28.33 ms and maximum 156 ms. Cached
GUI lag was 63–313 ms, callback duration 46.43–105.68 ms, metric age up to
10.144 seconds and RSS about 324–348 MiB. Full invoke returned in 168.77 ms;
status settled after 53.36 seconds, not a 53-second click delay. These measures
do not establish complete interactive responsiveness.

Native sampling had nine Full-window observations, seven observed and two
partial, including four thread retirements. Across the whole sampler there were
26 snapshots, ten retirements, no thread-open failures and cleanup of all
26 snapshot owners and 141 thread handles. Partial observations do not become
complete CPU accounting. The exact GUI thread used 9.328125 CPU seconds over
52.36 seconds, **17.815365% of one logical CPU**. The 126 exact thread-ID/birth
endpoint matches accounted for 60.9375 CPU seconds. Separately bracketed Core
CPU was 61.765625–62.046875 seconds over 52.203–52.485 seconds, or roughly
117.682433–118.856914% of one CPU. Advisory labels associated model integrity
with 23.604612%, memory injection 10.175945% and AI triage 1.492074%; missing
thread-birth bindings in the status schema and inline callbacks mean those are
not isolated module costs or grounds for an optimization claim.

## Native fault evidence and remaining P0

A newer dump was observed and hashed, but disappeared before admitted byte
parsing or preservation. No dump PID, native exception instruction, module or
unwind was verified. Its removal cause and actor remain unknown. Preserved
Python fault frames were mapped to the exact older source's final CRT exit
call; that mapping narrows a Python execution location, not a native crash
cause. The earlier independently reviewed PySide fault remains a separate
unresolved P0 availability finding.

The distinction is grounded in [CPython's exit implementation](https://raw.githubusercontent.com/python/cpython/v3.12.10/Modules/posixmodule.c)
and Microsoft's [ExitProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess)
and [TerminateProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess)
semantics. Avoiding one final teardown path is a mitigation with pending-I/O
and DLL-state limits; a later exit zero does not prove all native crashes fixed.
Both fault-copy phases captured the two known log files while Core was live.
The pre-STOP diagnostic delta added 77,324 bytes with a COM-exception label and
no access-violation marker in that delta. Historical access-violation text
preceded the newest STARTUP header. The live process continued; a faulthandler
fatal label does not establish that it exited. These copies do not cover final
STOP teardown, authenticate a writer or prove native-hook health. Native exit
zero and no harness force do not prove which finalizer API path ran or close
the P0 cause.

## Security acceptance remains separate

The Word report retains all five exploit classes, all 35 residual criteria
and the priority matrix. Kernel telemetry can be forged or suppressed; peers
can freeze together; same-user source/unsealed evidence remains writable;
open/inherited sockets, whole-root/authority rollback, storage exhaustion,
unavailable providers and false-positive leads remain material limits.
Signed service/PPL, actual WDAC enforcement, native ALE/flow teardown, physical
TPM and independently administered witness deployment need separate acceptance.
No new media or external LinkedIn post is part of this fix; existing demo media
remains synthetic and the LinkedIn text remains a draft.
