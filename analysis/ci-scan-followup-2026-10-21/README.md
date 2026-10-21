# Hosted CI and secret-scan follow-up

Date: 2026-10-21. Maintenance version remains 1.13.0. Investigated commits:
`306911a931dab28d3ba0234711676f8653cf242f` and
`faadba63a3d6046aeec79233b020a908793e67bd`, followed by
`0934ec07eb392a1af2de6c150f7aa83444d56cc9`.

The [local complete-suite record](../timeout-rootcause-2026-10-21/README.md)
passed 5,107 tests with 25 skips. The subsequent hosted runs exposed two
fixture/scanner issues and a later native shutdown fault. Local validation
does not substitute for hosted acceptance.

## Hosted failures

The [job snapshot](hosted-failures.json) preserves the reported job outcomes
and failing assertion separately from the corrected commit's acceptance.

The [CI run](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/39659889736)
failed on Python 3.10, 3.11, 3.12 and 3.13. Each completed its full suite with
5,119 passes, 12 skips and the same one failure: the new sandbox scheduling
fixture's `peer_active_at_result` assertion. Child output success, explicit
normal child/target priority, below-normal parent creation and shared CPU
affinity assertions had already passed. The failure was not the child-output
deadline or descendant-retirement assertion.

That assertion observed the finite CPU peer after the sandbox call completed
its custody and temporary-state cleanup. The scheduling claim concerns CPU
availability during bounded output. The logs did not retain phase timings or
the peer's exit code, so they cannot establish its exact exit timing or cause.
The correction must observe the relevant phase while retaining separate
cleanup and process-ownership checks; it must not increase the child deadline
or turn the check into a skip.

The [Security assurance run](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/39659889812)
reported 21 `generic-api-key` findings, all in the historical `sources.json`
manifest. Each value was independently verified as the normalized SHA-256 of
its referenced public source file. Filenames containing credential-related
words triggered the heuristic beside their digests; no credential was found
in these 21 findings.

Exact commit/path/rule/line fingerprints retain full-history scanning and
ordinary API-key detection. A broad path or digest-pattern allowlist would
suppress unrelated future findings and is not used. The historical manifest
and its source-freeze evidence remain unchanged.

CodeQL, Scorecard, dependency audit, public README integrity, all three
platform-contract jobs and all three native installer jobs passed in those
same runs. Their success does not erase the five failed jobs.

## First correction and independent challenges

The first correction records the owned peer's process-handle status
immediately after the original bounded-output helper returns complete. It
also captures resume/output/return timing for diagnosis. After the sandbox
returns, the peer must still be running or have exited naturally with code
zero; sandbox cleanup must not terminate its sibling. The original child
success, priority, affinity and three-second descendant-retirement assertions
remain, as do the ten-second output deadline and finite 16-second peer.
No production Python or native code changes.

A controlled probe kept the original output and custody helpers intact and
delayed only post-output cleanup. The old fixture's final peer-alive assertion
failed after successful output, with the peer's natural exit code zero. The
corrected fixture passed its actual assertions in that same situation.
This demonstrates the observation mismatch; it does not reconstruct the
unrecorded hosted phase timings.

The corrected fixture's nine actual assertions passed with output returned
at 4.032 seconds and deliberately delayed return at 16.329 seconds, after
the peer exited naturally. The 51-case resource/custody/security gate passed
with zero skips, failures or errors. [Fixture evidence](sandbox-fixture.json)
records both observations, original limits, the actual test-file hash, the
focused JUnit hash and unchanged production helper hashes.
Compilation of the changed fixture, repository Ruff, documentation drift
and whitespace checks also passed. The prior all-module self-check and
complete local suite remain the dated `306911a` record; no new local
full-suite total is inferred from this focused selection.

## Second hosted attempt and coordinator priority

The first correction's [Security assurance run](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/39668432650)
passed secret scanning, CodeQL and Scorecard. Its [CI run](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/39668432468)
passed all eight non-Python jobs, but all four Python jobs failed. The
[second snapshot](hosted-second-attempt.json) retains the outcomes rather than
treating the passing local selection as hosted acceptance.

Python 3.11 recorded the finite peer's natural exit before native child resume
at 16.078 seconds. Python 3.12 and 3.13 completed child output but observed that
the peer had already exited. These logs locate the starvation earlier than
post-output cleanup. They did not record the coordinator's initial priority.

A paired experiment ran the exact test function under a disposable
below-normal driver. With inherited coordinator priority, the coordinator's
initial, saved and restored classes were all BELOW_NORMAL. Native resume
returned at 17.172 seconds and output at 17.922 seconds, after the peer's
natural exit. The actual test failed despite successful child output and
descendant retirement. With explicit NORMAL on outer coordinator creation,
those three readbacks were NORMAL, output completed at 5.063 seconds while
the peer remained active, and the actual test passed. The deliberate
BELOW_NORMAL parent around sandbox child creation remained verified.

This proves an inherited-priority defect in the fixture: the normal CPU peer
can delay the coordinator's native-resume and output phases. The paired probe
does not timestamp the inner ResumeThread call. Its mechanism is consistent
with the hosted phases, but does not reconstruct their unrecorded starting
process classes. [Paired evidence](coordinator-priority.json)
retains both observations and the unchanged 10-second output, 3-second
retirement, 16-second peer and 30-second coordinator budgets.

The correction requests NORMAL for the disposable coordinator and verifies
its initial and restored classes, including immediately before child resume.
The real sandbox child still starts from the temporarily below-normal parent;
child priority, shared CPU affinity, peer activity during output and sibling
ownership checks remain mandatory. No production scheduler or deadline changes.

The final fixture also passed under an actual below-normal driver with output
at 5.313 seconds and the peer active. Its 51-case focused gate passed in
33.13 seconds with zero skips, failures or errors. The proof records the final
test-file and JUnit hashes and confirms that all 414 product Python sources
match the earlier complete local regression's source map.

## Exit diagnostics after a passing summary

In the second attempt, Python 3.10 printed **5,120 passed / 12 skipped** and
then exited with code 1 about 0.402 seconds after its summary, without a
traceback or a reported failed test. This job failed; the passing test count
does not establish successful process shutdown. Its cause is not proved by
that log. The PowerShell step launched only one native command, so an exit
status from the separate custody step cannot explain it.

CI now keeps an independent journal of pytest's session result, unconfigure
boundaries, the actual pytest entry point's SystemExit or exception, and an
interpreter atexit observation. PowerShell records the native exit status
immediately after Python and returns that same status. The observer retains
the real pytest command-line arguments and verdict, with no skip, retry,
timeout increase or conversion of nonzero status into success. Future logs
can distinguish a test verdict from a later entry-point or shutdown failure.

The observer's **15-case gate passed in 35.75 seconds**. It challenges real
test and collection failures, unconfigure exceptions, closed stdout, failed
journal I/O, and a passing pytest exit followed by native shutdown exit 7.
That last challenge retains process exit 7 rather than reporting success.
The exact CI launcher then passed the **51-case resource gate in 22.08
seconds**, with pytest, session and native process exit codes all zero.
Both atexit markers and completed unconfigure were observed. These markers
do not cover every native cleanup operation; the external exit code covers
the process result. [Diagnostic evidence](ci-diagnostics.json) retains the
commands, hashes, limits and the earlier local collection-probe failure
whose original cause could not be recovered. CI diagnostic tails print
curated status fields and omit raw failure/Qt text and parameter values.

## Third hosted attempt: native shutdown

The coordinator correction and exit observer exposed a separate failure in
the [third CI run](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/39672005464).
All four Python versions completed **5,132 passed / 12 skipped**, including
the scheduling check. Python 3.12 and 3.13 also completed process shutdown
with native exit zero and both atexit markers. Python 3.10 and 3.11 completed
pytest with SystemExit zero and successful unconfigure, but then crashed
with native status **0xC0000005** between the atexit markers. Their GitHub
steps failed. The full matrix was not accepted.

The [shutdown snapshot](hosted-shutdown-failures.json) preserves these per-job
results and distinguishes the native access-violation code from PowerShell's
step exit 1. Faulthandler reported no Python frame for the crashing current
thread. The other frames identify blocked surviving workers, not a causal
fault in those workers. These logs do not identify a native DLL/function or
prove the cause of the older uninstrumented `faadba6` exit 1.

All eight non-Python CI jobs passed. The same commit's
[Security assurance run](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/39672005598)
passed secret scan, CodeQL and Scorecard. Those successes do not erase the
two failed interpreter shutdowns.

The pinned PySide 6.11.1 source registers
[`QtCore.__moduleShutdown` with Python atexit](https://github.com/qtproject/pyside-pyside-setup/blob/v6.11.1/sources/pyside6/PySide6/glue/qtcore.cpp#L1219-L1240).
Its [`shutdown` implementation](https://github.com/qtproject/pyside-pyside-setup/blob/v6.11.1/sources/pyside6/PySide6/glue/qtcore.cpp#L338-L340)
drains the same cleanup path explicitly. This establishes the relationship
between the cleanup boundaries; it does not identify the hosted faulting
destructor.

The old session fixture kept its application alive through the tests but left
native cleanup to interpreter shutdown. A candidate tracks whether the
fixture created that application, drains requested DeferredDelete events and
explicitly shuts down its owned application in a finally block. A borrowed
application remains with its creator. It avoids dispatching unrelated timers
from completed tests during final cleanup.

Three disposable-process challenges verify owned application/widget/timer
destruction before SystemExit, borrowed ownership and propagation of an
original test exception through cleanup. All three passed with native exit
zero. A 52-case GUI lifecycle selection also passed through the exact CI
launcher on Python 3.12 with completed unconfigure, SystemExit zero, both
atexit markers and native exit zero. These checks establish the intended
cleanup boundary on Python 3.12. They do not establish a fix for the access
violation: the matching Python 3.10.11 runtime reproduced the original crash,
and explicit application shutdown moved the same crash into fixture teardown.
A retained-wrapper baseline on Python 3.12 exited normally and does not
reproduce the native access violation.

The Python 3.10 reproduction also crashes with the execution-trace plugin
absent. Passive sentinels around the unchanged registered callback locate
the failure inside `PySide6.QtCore.__moduleShutdown`. The single MainWindow
integration case is sufficient to reproduce it. Creating the loading signal
bus lazily under application ownership still produced the native access
violation after that case passed its assertions. Neither candidate is
accepted as a shutdown fix. Constructor-only, settings-only and inert local
history-dialog probes exited normally; those reduced probes do not replace
the original integration assertions or the hosted full suite.

## Confirmed dialog teardown fault

A native dump of the unchanged Python 3.10 case recovered a saved Python
traceback: `PresentationTimer.eventFilter` → `refresh` → `_sync` →
`_watch_window`, at baseline line 107. The timer called `removeEventFilter`
on its cached `RedTeamConsole` after Qt had already invalidated that native
dialog. The child timer and widget could still receive destruction-related
events. The resulting `RuntimeError` entered Shiboken's override-error path
during Qt application cleanup.

The pinned binding's [older Python error-fetch path](https://github.com/qtproject/pyside-pyside-setup/blob/v6.11.1/sources/shiboken6/libshiboken/sbkerrors.cpp#L108-L139)
retained an unnormalized string value. Its
[context-prefix path](https://github.com/qtproject/pyside-pyside-setup/blob/v6.11.1/sources/shiboken6/libshiboken/sbkerrors.cpp#L183-L201)
passed that value to the
[compatibility exception-argument accessor](https://github.com/qtproject/pyside-pyside-setup/blob/v6.11.1/sources/shiboken6/libshiboken/pep384impl.cpp#L367-L391).
The dump identifies the invalid access there. This explains the captured
Python 3.10 native crash; the hosted matrix separately verifies supported
interpreter versions. The original application lifetime error is corrected
at the timer rather than hiding the callback failure or changing dependencies.

An inert dialog/child/timer probe reproduces the same path without simulation
actions. With Python 3.10.11 and PySide 6.11.1 held constant, the original timer
crashed with **0xC0000005**. Changing only the timer source made that unchanged
probe exit **0**, invalidate all three retained wrappers, finish shutdown,
produce both atexit markers and leave stderr empty. On Python 3.12, the
baseline exposed the exact callback traceback and the correction exited
cleanly. Cold probe timings are not performance benchmarks.

The fix validates the owner, current window and cached window before native
queries; Hide directly stops wakeups while preserving start intent. Owner
destruction retires the timer. Chill interval calculation shares the guarded
lookup. Four disposable-process regressions cover Full/Chill parent destruction
and reparenting after a cached window is destroyed. They reject printed Qt
override errors even when a process returns zero. All four passed on Python
3.12; the existing 79-case presentation/Chill/AI-lock/history/observer gate also
passed with native exit zero. The
[sanitized root-cause record](qt-shutdown-rootcause.json) includes the inert
probe source, hashes, recovered call chain and separate validation scopes.
Raw memory dumps remain private.

The same actual-source launcher on Python 3.10.11 then passed all **16 new
lifecycle cases**, with session/SystemExit/native status zero, completed
unconfigure, both atexit markers, no Qt callback errors and empty stderr.
Source hashes remained identical before and after. This focused gate ran
alongside the complete Python 3.12 regression and is not a timing comparison.

That first complete-regression attempt exposed a further omission in the
candidate guard: Qt can reenter a timer filter after Python clears the
wrapper's attributes. Reading `_retired` before checking the native object
then raised `AttributeError`, with a call failure and a teardown error in
the minimum-window footer test. The run had observed 3,282 passing calls,
11 skipped calls and one failed call when it was stopped; it is incomplete
and unaccepted. Its supervisor termination status 15 is not a pytest verdict.
The original MainWindow integration case had passed in 127.52 seconds.

The corrected entry guard checks native validity first and treats absent
Python state as retired before reading the event or owner. Two further
Full/Chill canaries clear wrapper state deliberately and dispatch real Qt
events through the installed filter. They distinguish this controlled
fault injection from an assertion that cyclic GC always runs in that order.

The final focused Python 3.12 gate passed **46 cases**, including the complete
affected GUI polish suite, all six timer lifecycle cases and the existing
timer-efficiency/Chill checks. A fresh actual-source Python 3.10 gate passed
all **18 lifecycle cases** with native/session/SystemExit zero, completed
unconfigure, both atexit markers and empty stderr. These gates validate the
completed guard; the earlier 16-case record validates only the first candidate.

A separate history-worker defect released GUI-affinity signal carriers on pool
threads. Application ownership and GUI deferred deletion now cover completion
and refused starts; nine inert tests verify delivery, errors and destruction
thread. This is not attributed as the captured crash's cause. The live GUI
integration setup also waits for a completed process-monitor poll within its
original ten-second bound; launch still requires its own later fresh,
loss-free cycle. No authority threshold or deadline was relaxed.

## Completed local regression

The fresh complete Python 3.12 run passed **5,138 tests / 24 skipped / zero
failures or errors** in 800.25 console seconds (804.875 seconds including
the launcher and source checks). Pytest session, SystemExit and native
process status were all zero; unconfigure completed, both interpreter atexit
markers were present and stderr was empty. All **999 Python source files**
were identical before and after. The full 5,162-case inventory includes the
original MainWindow case, the affected footer case and all 18 new lifecycle
cases. The 30 Chill/Ollama-lock and nine Chill presentation-budget checks
passed. Local skips reflect available capabilities and remain distinct from
the hosted matrix's dependency and platform coverage.

The subsequent isolated offline self-check passed **28/28 phases** and
reconciled all **84 modules**: 66 passed, 18 expected capability skips, plus
a passing event-pipeline result. It recorded **559 module subchecks**
(530 passed, 29 skipped) and **9/9 verification checks**, including controlled
failure, exception, malformed-result, timeout, skip and corrupt-accounting
canaries. Saved-report readback and constrained-hardware worker-budget checks
passed. The harness took 35.734 seconds. Its established direct-exit policy
reports the harness result; normal interpreter shutdown is established by
the independent lifecycle gates and full regression above.

## Hosted acceptance at `5919c67`

The [completed CI run](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/39681727025)
and [Security assurance run](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/39681727269)
both passed for the exact code commit
`5919c670922016985dc69fd6de0b4259d0fe75b7`.

| Python | Passed | Skipped | Native exit | Pytest seconds |
| --- | ---: | ---: | ---: | ---: |
| 3.10 | 5,150 | 12 | 0 | 589.43 |
| 3.11 | 5,150 | 12 | 0 | 627.27 |
| 3.12 | 5,150 | 12 | 0 | 410.01 |
| 3.13 | 5,150 | 12 | 0 | 525.16 |

Each interpreter collected all **5,162 cases**, reported no test failures,
completed unconfigure, raised the real pytest SystemExit zero and emitted
both Python atexit markers before native exit zero. The two formerly crashing
interpreters, Python 3.10 and 3.11, received an independent completed-log check.
All eight remaining CI jobs passed: dependency audit, three platform contracts,
three native installer checks and public README integrity. Secret scan,
CodeQL and Scorecard also passed. The
[acceptance snapshot](hosted-acceptance.json) preserves per-job links and
structured exit evidence for this immutable code commit.

Python 3.13 emitted 29 existing `PureWindowsPath.is_reserved` deprecation
warnings. These were path-API notices; no native shutdown failure occurred.
Runner timings describe these tests and are not comparative performance
benchmarks. The documentation follow-up preserves the tested product, test
and tool sources; later workflow outcomes are checked separately.

## Secret-scanner validation

The same Gitleaks 8.24.3 version used by GitHub reproduced all 21 findings
before the correction and zero afterward. An all-ref historical scan found
one additional older public-source-hash false positive in `a3188df`; it was
independently verified and received its own exact fingerprint. There are
22 new fingerprint exceptions, with no wildcard or rule changes.

The pre-follow-up historical snapshot then passed with zero findings across
200 commits and 24.71 MB. Two isolated positive canaries remained detectable:
a generic API key at the same manifest path and line in a different commit,
and a GitHub token. Both were still detected in history after removal from
the latest fixture tree. No canary credential values are republished here.
[Scanner evidence](gitleaks.json) retains tool provenance, commands, report
hashes, narrow exception scope and the historical snapshot boundary.

The accepted code run and its exit diagnostics are linked above. Subsequent
commits receive their own checks in
[GitHub Actions](https://github.com/Ag3nt47/AngeronaSuite/actions).
