# Self-test budget accounting

The full drill and the selected-module check use the same bounded runner.
**Module checks** shows the diagnostic verdict, policy state, check evidence,
and the observed worker generation. Each bundled module has its own check
and recovery guidance. A detector fixture can pass while its live source is
off, degraded, or awaiting a dependency.

Open **Settings > Self-Test** to choose a module, run its installed diagnostic,
or inspect the bundled test method. Source experiments use editable sandbox
copies with syntax checking. Tests run the installed code. The time allowance
defaults to 30 seconds per module. Settings offers 15, 30 and 45 seconds.

A slow check can keep running while a spare slot within the hardware budget
starts the next check. A result arriving within its original deadline is
graded normally. A late result fails. If all slots remain occupied after a
bounded wait, unrun checks are **Deferred** and can be rerun individually.
The report lists each outcome and the event feed gets a bounded summary.

For a verified worker fault on an eligible module, **Recover selected worker**
requires approval. It rechecks the module's identity, generation and current
policy, then verifies that the replacement completes a work cycle and passes
a fresh diagnostic. Dependency, privilege and evidence failures have their
own review guidance. A worker restart does not recreate lost records or
install a driver or model.

Settings also lets the operator opt in to automatic recovery for each eligible
bundled module. Saved choices are off by default. Automatic recovery runs
after the dashboard or Settings diagnostic reports a confirmed worker fault,
using the same policy checks and replacement verification as manual recovery.

`_bounded_call` measures callback completion against one monotonic deadline
established before worker construction and startup. The coordinator waits only
for the remaining budget. A callback that finished on time can retain its result
when the coordinator resumes late; a callback that finished after the deadline
is reported as timed out. Completion is recorded before exception formatting,
so formatting cannot change when the callback actually failed.

This accounts for completion time. It does not provide hard native preemption:
a native call that holds the Python GIL can delay the coordinator beyond its
requested wait. Timed-out work keeps its existing process and hardware capacity
permits until the worker's cleanup finishes. Existing held-worker limits remain
in effect, and the coordinator does not terminate callback threads.

Failures while constructing the completion event or worker return the capacity
already acquired, including construction interrupted by a `BaseException`.
Ordinary `Thread.start()` failure retains the existing exception and capacity
policy. An interruption during `Thread.start()` can leave uncertainty about
whether a native thread launched; this checkpoint does not resolve that case.

A callback failure remains a failure even when its exception cannot be rendered.
The fallback is `callback failed; exception message unavailable`; printable
original error details remain available, including when completion was late.

Focused tests cover deadline boundaries, late coordinator resumption, remaining
wait budgets, prestart failures, unavailable capacity, held-worker retirement,
and unrenderable errors. A Windows-only inert control compares 500 ms
`Sleep` calls through `WinDLL` and `PyDLL`; neither receives credit for an
on-time result after a 100 ms completion deadline. The control joins each owned
worker and does not claim an overall performance improvement.
