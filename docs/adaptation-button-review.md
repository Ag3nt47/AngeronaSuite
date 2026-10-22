# Adaptation button review — 2026-10-21

The review follows the dashboard button through its dialog, background context
monitor, audit collectors, immutable profile preview, no-write sandbox, explicit
apply, transaction journal, recovery enrollment, rollback, and feedback views.
It adds measured scheduling improvements and removes recovery-artifact hashing
from the GUI thread. These results cover adaptation; the separate Self-Test,
Red Team, and SpywareGuard reviews have their own evidence.

## Traced control path

- `main_window.py`: the `ADAPTATION` header action calls `_open_adaptation`,
  reuses one `HostAdaptationService` and one `AdaptationWorkbench`, and raises
  that dialog. The 15-second timer starts a background context cycle; unchanged
  results do not rebuild the visible workbench.
- `adaptation_workbench.py`: Audit and Safe Checkup use `_run_task`; Guided Auto
  Adapt performs one audit, builds an exact plan, and simulates that plan before
  the separate exact-plan confirmation. Profile changes, rollback, and recovery
  work remain worker operations. Closing during host-change/recovery work is
  refused. Automation, exceptions, exports, activity, and all seven tabs were
  traced to their service calls.
- `host_adaptation.py`: snapshots collect services, listeners, network context,
  active firewall policy/rule scopes, and hardware. Baselines and exceptions are
  authenticated local stores. Profile apply verifies the closed command catalog,
  plan identity/expiry, host identity, enrolled recovery artifact, breaker,
  current firewall digest, durable transaction, and fresh postconditions.
  Failed mutations invoke rollback; ambiguous recovery locks the breaker.
  Context rules remain proposal-only.

## Findings and implemented changes

1. Independent service, listener, context, firewall, and hardware probes used to
   run serially. Snapshot collection now overlaps them with five workers. A
   per-service lock prevents simultaneous snapshot callers from multiplying the
   probe pool. Every capture is fresh; no stale observation cache can authorize
   a mutation. Existing subprocess timeouts and collector row limits remain.
2. A hardware-probe exception could abort a complete audit. It now becomes an
   explicit unavailable hardware collector while the other evidence remains
   visible. Failed hardware collection is excluded from comparison and cannot
   become a golden baseline, avoiding invented hardware-removal drift.
   Inaccessible disk queries and disk truncation also report partial coverage;
   unavailable disks no longer appear as successful zero-capacity observations.
3. Initial status and repeated preview/apply/recovery UI paths synchronously
   authenticated a recovery artifact of up to 256 MiB. A coalesced background
   status worker now performs baseline, recovery-integrity, and breaker reads.
   Cached recovery status is a presentation hint; the mutation broker still
   authenticates current bytes before apply or restore.
4. The audit summary now includes total capture time. Its tooltip shows each
   collector's elapsed time, completeness, and error. Partial audit activity
   reports unavailable risk instead of recording a successful healthy score.
5. A cleared circuit breaker retained red locked styling. Successful background
   refresh now restores the ready styling. Missing golden baselines display
   “baseline required” instead of a seemingly healthy zero drift score.
6. Automation help incorrectly said exact SSID rules always took priority. It
   now describes the existing strongest-profile selection and Public-context
   tie break. The overview also explains when to consult the dedicated
   SpywareGuard evidence and coverage dashboard.

## Offline evidence

`venv/Scripts/python.exe -m pytest tests/test_host_adaptation.py tests/test_adaptation_performance.py -q`

The focused suite passed **34 tests** after the implementation. Regression
fixtures prove overlapping probes, the shared five-probe ceiling, explicit
partial hardware evidence, no invented hardware drift, baseline refusal, and
background recovery checks that cannot block GUI event handling. Existing
tests exercise tampered stores, exact approvals, rollback failures, transaction
reconciliation, incomplete collectors, feedback, Public/VPN/SSID priority, and
remote-session restrictions. No real firewall changes, model calls, or network
requests are used by the added fixtures.

`venv/Scripts/python.exe tools/benchmark_adaptation_snapshot.py --delay-ms 20 --repeats 7`

This benchmark injects five fixed 20 ms waits and fixed probe output. Seven
samples measured median serial collection **101.768 ms** and median parallel
capture **23.554 ms**, a **4.321×** median scheduling ratio. The first parallel
sample was **122.767 ms**, so cold scheduling overhead can exceed the serial
case. This is evidence of I/O overlap under a synthetic workload, not a claim
about physical-host scan speed or spyware detection effectiveness. The script
prints every sample so cold overhead is visible.

The correctness-focused Ruff check passes for the changed adaptation sources,
tests, and benchmark. The offline suite does not establish timing guarantees
for blocked OS APIs, atomic cross-collector host state, or live Windows Firewall
behavior. Active mutation still requires its existing authenticated recovery
and fresh firewall checks.

## Research used

- [Python concurrent futures](https://docs.python.org/3/library/concurrent.futures.html):
  fixed worker limits and independent tasks support I/O overlap. No collector
  waits on another submitted collector; nested-future deadlock patterns are
  avoided. Pools are scoped to short snapshot work rather than permanent loops.
- [Qt threads and QObjects](https://doc.qt.io/qt-6/threads-qobject.html): expensive
  work belongs in workers and widget updates belong on the GUI thread. The
  status worker emits plain values; the receiving slot updates Qt widgets.
- [psutil API documentation](https://psutil.readthedocs.io/stable/index.html):
  bounded process attribute reads and permission-aware telemetry are useful;
  process identity must not be inferred from cached PID data. Existing listener
  enumeration already caches process names only within a single capture and
  excludes PID churn from drift equality, so that behavior was retained.

## Extending adaptation locally

Users may edit the source to add features for their own security needs. Add
read-only sensing in `host_adaptation.py`, publish explicit collector quality,
and add a failure fixture before trusting the data for baseline comparison.
Keep mutation profiles in the closed `PROFILES` catalog and preserve exact-plan
approval, expiry, journal, recovery, and postcondition checks. GUI additions go
in `adaptation_workbench.py`; additional defensive modules should follow the
module discovery and capability contract rather than silently broadening an
adaptation profile's commands. Review local changes and run the offline checks
before enabling them on a protected host.
