# Timeout investigation and verification

Date: 2026-10-21. Maintenance version remains 1.13.0. Baseline:
`a3188df2841608bc7b58690d3808c70bc9b538e7`.

This follow-up investigates the two deadline failures retained in the
[October 18 record](../chill-efficiency-2026-10-18/README.md). It preserves the
10-second sandbox output deadline, three-second descendant retirement check,
100-second comprehensive containment verification window and existing
containment durability barriers. Focused reruns alone do not establish a
passing full suite.

## Sandbox scheduling

The sandbox explicitly launched its disposable child at below-normal Windows
priority. A runnable normal-priority peer can prevent such a child from even
reaching Python bootstrap before its wall-clock deadline. Omitting the
priority flag is insufficient because a below-normal parent can pass its
priority class to the child. The correction explicitly requests normal
priority while retaining suspended creation, Job Object assignment before
resume, token admission, source custody, bounded output and process-tree
cleanup. [Microsoft's scheduling documentation](https://learn.microsoft.com/en-us/windows/win32/procthread/scheduling-priorities)
describes the priority and inheritance behavior.

Two controlled sequential pairs pinned only disposable coordinator, peer and
target processes to one allowed CPU. A finite normal-priority compute peer
remained active at the result in every trial. Both below-normal children
timed out with no output, no bootstrap marker and zero sampled user CPU;
sampled kernel CPU ranged from zero to 0.015625 seconds. Explicit normal
priority completed in 4.61 and 4.36 seconds with the same ten-second deadline.
The second pair also proved descendant retirement within the original three
seconds. [Structured proof](sandbox-proof.json) includes source hashes,
original resource caps, observations and focused regression results.

The new regression creates the child while its disposable coordinator has
below-normal priority, restores the coordinator, then proves the child
receives normal priority, gets CPU while its peer is busy and retires its
disposable descendant. It never changes the priority or affinity of the
test runner or unrelated host processes. The existing 32-process, 512 MiB
per-process, 1 GiB job and 90 CPU-second limits remain intact.

## Containment checkpoint latency

The earlier comprehensive case completed its inert engine steps, then reached
its verification deadline with response work still queued. A pass-through
wall-clock profile on the unchanged implementation attributed 20.14 seconds
to 78 journal appends, 33.94 seconds to 79 protected-anchor writes and 33.23
seconds to 79 independent key-bound witness writes. Included in the anchor
time were 158 calls to the permission helper, totaling 11.31 seconds and
launching an external `icacls` process at both the temporary and renamed-file
boundaries. Recorder deliveries totaled 1.23 seconds; the measurements did
not support treating the recorder lock as the dominant delay.

An experiment overlapped the independent anchor and witness writes while
joining both before granting response credit. On this volume, alternating
native samples showed no benefit: serial append median 0.991 seconds versus
1.099 seconds overlapped. That experiment was removed. Journal flushes,
protected-anchor flushes, witness flushes and independent verification are
retained.

The native permission helper uses the actual process-token user SID with
SYSTEM and Administrators, preserves an existing owner within that trust
boundary, and sets a protected DACL containing only the exact explicit
full-access grants. Fresh verification permits an already-private inode to
avoid a repeated ACL mutation after rename; no prior authority decision is
cached. Unsafe leaves, multiple links, untrusted owners and failed native
readback do not select a path-based subprocess retry. Only absence of the
optional Windows API dependency selects the legacy best-effort helper.
DPAPI protection and both permission-hardening calls remain mandatory parts
of the existing write path; the permission helper retains its best-effort API.

The native operation and readback use a retained leaf handle, followed by a
fresh pathname identity check. Ancestor checks remain snapshots: this is not
atomic custody of the whole ancestor tree and does not prevent every
ancestor-redirection side effect. No stronger race-resistance claim is made.
The handle-based operations follow the
[Windows security API contract](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo).

The focused ACL gate passed 29 new security/native cases and nine unchanged
privacy-storage cases. The real Windows DPAPI fixture independently inspects
exact permissions at both original boundaries, verifies encrypted roundtrip
and flush use, and rejects subprocess launches. Fault cases exercise invalid
masks, inherited/deny/unknown ACEs, null DACL, unsafe leaves and owners,
identity changes, failed updates/readback, handle cleanup and fallback scope.

In six matched samples per mode, run as baseline/native three-sample blocks
repeated twice, the original two-boundary helper launched
12 utility children; the native helper launched zero. Median time across
both calls fell from 92.43 ms to 3.94 ms. Every final ACL and the file's
identity after replacement were independently verified. All samples are
retained, including the native first-call cost of 85.35 ms.

The instrumented comprehensive integration case passed: all 39 responses
executed, queue depth/pending/drops ended at zero, and its AAR verified 37/37
simulation validations and response steps. The original 100-second
verification window remained. Call duration was 86.05 seconds; the final
handler completed 81.38 seconds after case entry. The window begins after
engine completion, so whole-case duration is not the deadline measurement.
The same 158 permission calls took 2.03 seconds instead of 11.31 seconds.
Other I/O stages also varied; the whole-case difference is not attributed to
the ACL change. [Containment proof](containment-proof.json) retains the stage
tables, matched measurements, unchanged Actor/Guard/test hashes and limits.

## Complete regression

The new one-process full suite completed with **5,107 passed, 25 skipped,
zero failures and zero errors** across 5,132 cases. JUnit duration was
2,639.339 seconds; the external wrapper took 2,663.015 seconds including
observation and final source verification. No competing maintainer build or
test job ran during this gate. There were no retries, deadline changes or
post-run Python source corrections.

| Case | Full-run call result | Call duration |
| --- | --- | --- |
| Comprehensive verified containment | PASS | 36.57 s |
| Successful sandbox descendant retirement | PASS | 0.54 s |
| New one-core scheduling/low-parent regression | PASS | 3.90 s |

These are whole-call durations, not changes to the requested inner deadlines.
The two-drill GUI arm/launch/signed-AAR case also passed. The outcome trace
contains 5,132 test starts, no failed phase reports, no recorded Qt
critical/fatal messages and a closing session record.

All **994 Python files under `src`, `tests` and `tools`** matched the frozen
normalized fingerprint before and after the run:
`e52dd07018eef0a8ae4f55c859859d23c185328baca8cc59b557608b7288de15`.
[Per-file hashes](sources.json) describe the exact tested tree;
[validation.json](validation.json) reconciles JUnit, the execution journal,
source custody and local artifact hashes. Focused gates overlap this suite
and must not be added to its count.

A separate read-only observer retained 511 five-second samples of the actual
CPython pytest runtime, with no observer errors. Sampled peak RSS was about
631 MiB and peak thread count was 20; descendant resources are excluded and
sampling can miss peaks. Host available RAM fell as low as about 391 MiB.
These are observations from this run, without a matched host baseline or
whole-application performance claim. Initial launcher-only samples were
identified and excluded from pytest resource totals.

## Fresh offline self-check

The fresh harness passed all 28 phases. Its 84 module rows reconcile to
66 PASS and 18 explicit prerequisite/platform SKIP results. The separate
event-pipeline check also passed; it is not an 85th catalog module. The
559 module subchecks reconcile to 530 PASS and 29 SKIP results. All nine
verifier checks passed: eight controlled canaries and report reconciliation.
The constrained-worker fixture completed 32 inert modules at a measured peak
of two workers against its two-worker budget, with no unfinished calls.

[Sanitized self-check evidence](selfcheck.json) retains names, statuses,
timings, accounting and input hashes. Saved all-module report equality was
asserted in its verification phase; a later reliability fixture intentionally
overwrites the auxiliary failure report with its own focused result. The
final phase report remains separately retained. These checks do not establish
live sensor or model readiness. All 994 Python files compiled, and Ruff,
final documentation drift, whitespace and six strict-JSON evidence checks
passed.

## Native watchdog tests

After the Python gate finished, both native Go test groups passed offline:
five top-level tests and 17 subtests, including three harmless test-child
launches. All eight source/test/module files matched before and after, and
their raw hashes match the previously published native proof. The existing
Go 1.27.2 SDK and dependency cache were used with downloads disabled.
[Native evidence](native-tests.json) records the commands and outcomes,
including an initial incorrect SDK-root setting that prevented test execution
and was corrected before the passing runs. No native source, architecture
build or installed supervisor changed.

## Evidence limits

The historical failed run did not retain child bootstrap stages, CPU samples
or checkpoint phase measurements. Some staged builds and tests overlapped
that run, but temporal overlap does not prove its exact physical trigger.
Controlled reproductions establish specific code mechanisms; they cannot
reconstruct missing historical host telemetry. These are local component and
inert simulation checks, not evidence of real-attack detection coverage,
whole-host CPU savings, every older computer's performance or long-duration
all-sensor stability. Chill and its manual local-AI lock remain governed by
the [operator guide](../../docs/hardware-and-selfcheck.md#chill-mode).
