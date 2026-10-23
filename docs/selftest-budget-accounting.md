# Self-test budget accounting

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
