# Self-Test and Red Team button review

Reviewed 2026-10-21 for the SpywareGuard preview update.

## Button paths and resulting behavior

The dashboard Self-Test button follows `MainWindow._run_self_test()` → one
background `_self_test_worker()` → `SelfTestRunner.run()` → nonmodal results.
The button now respects the configured AI/Chill state without an unconditional
30-second Ollama preparation step. A regression fixture invokes the actual
worker method with a forbidden service launcher and confirms that an AI check
in Chill is an explicit skip while progress and the final report still arrive.

The runner retains its process-wide six-call ceiling, hardware/pacing worker
budget, per-module lock, timeout permits, independent defect canaries, exact
inventory reconciliation, bounded event reporting, atomic JSON write and
readback. Expected skips remain distinct from failures and successful checks.
Timed-out calls retain capacity until they really exit.

The ordinary event-pipeline probe now installs one short-lived diagnostic
subscriber, verifies received events through the bus authentication contract,
and detaches in `finally`. A UUID correlates the receipt. This detects a broken
subscriber path even when a ring entry exists, and remains reliable when a busy
producer evicts the diagnostic from recent history. It removes repeated
`recent(50)` allocations and 100-ms polling from the normal bus path. Minimal
external bus adapters without subscription lifecycle methods retain a bounded
history-based compatibility check.

Each module record now includes `stage_ms` for contract validation, the active
self-test, and available health consistency validation. The human report lists
the five slowest modules. Durations use `perf_counter()`; coordinator deadlines
retain the existing monotonic deadline logic. On the tested Windows/Python 3.12
runtime, `monotonic()` used a 15.625-ms `GetTickCount64` clock and could report a
10-ms operation as 0 ms; `perf_counter()` used `QueryPerformanceCounter` with a
reported 100-ns resolution. These are elapsed timings, not CPU utilization or
real-time guarantees.

Red Team follows `_open_simulation()` → `RedTeamConsole` → the parent launch
coordinator → `RedTeamEngine.start()` → its safety preflight and live validation
lease → the background playbook → authenticated history and verified AAR.
The authority, evidence custody, cancellation, cleanup, report authentication
and containment verification gates remain part of that path.

The Red Team Discovery stage now takes a PID snapshot to count processes.
Previously it constructed process objects and fetched every process name,
although the names were unused. Enumeration errors now produce a failed probe
with an explicit error instead of claiming a successful enumeration of zero.
Each playbook stage records a high-resolution `duration_ms` in its history and
stage details; this measurement includes configured jitter and validation.
History readers use `QThreadPool.tryStart()` so repeated consoles cannot queue
unbounded work behind stalled filesystem operations. Saturation produces a
visible retry message. Narration and status strings display as literal text,
including user-supplied technique names containing HTML-like characters.

## Measured performance

Seven read-only measurements on the development Windows host with 345
processes produced:

| Discovery implementation | Median | First sample |
| --- | ---: | ---: |
| Count `process_iter(["pid", "name"])` | 2.526 ms | 30.413 ms |
| Count `psutil.pids()` | 0.074 ms | 0.158 ms |

This is approximately 34× faster for the count operation on that host. It is
not a claim that the complete adversary drill is 34× faster; intentional jitter,
filesystem custody, response verification and report generation dominate it.

## Offline validation

- Focused button, deadline, verifier, results, authenticated history, editor,
  stage clickthrough and bounded-reader tests: **91 passed**, 15.33 seconds.
- Red Team runtime-target, lease, launch/readiness and actual owned-fixture
  containment/AAR regression checks: **45 passed**, 83.39 seconds. This includes
  both base and comprehensive campaigns, verifying their expected 13/13 and
  37/37 simulation contracts and corresponding owned-target response receipts.
- Full `tools/selfcheck.py`: **28 phases passed, 0 failed**. The inventory
  contained **85 modules: 67 passed, 18 expected skips, 0 failed**. There were
  **565 module subchecks**, one pipeline subcheck, and **9 verifier/accounting
  checks**. Checks and verification took 6689.4 ms with three workers; this
  excludes report I/O and notification delivery.
- SpywareGuard appeared in the default inventory and passed its offline policy,
  inert sandbox and ingestion-gate check in 3.2877 ms. A separate fixture forbids
  its live collectors and confirms the self-test does not add containment
  records or mutate the live instance's sandbox history.

The selfcheck used disposable `.tmp/selfcheck/12084` state, Chill/AI lock, the
harness's forbidden native Ollama launcher, and disabled BlackBox startup. Full
console output is in ignored `.tmp/spyware-selfcheck.log`; structured evidence
is in that disposable run's `diagnostics/selfcheck_report.json`. Pytest fixtures
used isolated state and owned benign markers/processes. These results verify
the tested application contracts and simulation workflow, not detection of
unknown spyware, universal API interception, or real incident containment.

## Research and coverage decisions

[Python's Event documentation](https://docs.python.org/3.12/library/threading.html#event-objects)
supports receipt-based waiting, and its thread lifecycle explains why a timed
out Python call must retain its capacity until it exits.
[Python's performance-clock documentation](https://docs.python.org/3.12/library/time.html#time.perf_counter)
supports the high-resolution elapsed measurements.
[Qt's QThreadPool documentation](https://doc.qt.io/qtforpython-6.11/PySide6/QtCore/QThreadPool.html#PySide6.QtCore.QThreadPool.tryStart)
provides explicit admission without an expanding work queue, while
[Qt's threading guidance](https://doc.qt.io/qtforpython-6.8/overviews/qtdoc-thread-basics.html)
keeps widgets on the GUI thread. The
[psutil API reference](https://psutil.io/api/#psutil.pids)
distinguishes a PID snapshot from richer per-process queries. A count has no
authority to select a process for response.

MITRE's current [Screen Capture T1113](https://attack.mitre.org/techniques/T1113/),
[Input Capture T1056](https://attack.mitre.org/techniques/T1056/) and
[Process Injection T1055](https://attack.mitre.org/techniques/T1055/) descriptions
support scenario coverage for sensitive API access, credential targeting and
unbacked executable memory. Their references to legitimate system APIs also
reinforce that a named API alone cannot establish a malicious actor. The new
SpywareGuard scenarios therefore remain explicit telemetry/policy rehearsals;
real API, memory and browser evidence requires the applicable local collector.
No exploit payload, real credential read, API hook or remote attack was added
to either button program during this review.
