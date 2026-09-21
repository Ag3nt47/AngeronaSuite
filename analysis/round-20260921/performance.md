# Performance review — 2026-09-21

This bounded review starts from `b9c1733` and complements the earlier
`analysis/session-efficiency-2026-09-20.md` update. The historical loop state
still records completed cycle 34; these findings belong to the new maintainer
review and do not reopen that completed cycle. Only inert fixtures were used.

## Applied changes

### Process Monitor: avoid repeated transformations

Each polling cycle normalized every process identity twice and reconstructed
every process command string, including unchanged processes that emitted no
event. Long command lists amplified that CPU and allocation cost on every tick.

The monitor now retains the normalized identity for the second pass through the
same snapshot. The first pass still builds the complete parent-name map before
any lineage rule runs. Command formatting happens when a new process or a
validation receipt requires a creation event. The validation capability still
receives the complete raw process dictionary on every eligible observation;
identity deduplication, PID reuse, parent lineage, event content, health counts,
and source polling cadence are preserved. The per-poll observations list is
proportional to the current process snapshot and is replaced on the next poll.

`tools/benchmark_module_poll_efficiency.py --baseline-ref b9c1733` loaded the
baseline source from Git and compared it with the changed source in the same
Python 3.12.10 process. Each fixture uses 600 stable process rows, 100 polls per
repeat, five repeats, and a median. The existing processes are in the initial
PID baseline, so no creation event is expected. Sensor enumeration, sleeping,
UI rendering and event publication are replaced with inert fixtures.

| Arguments per process | Before, ms/poll | After, ms/poll | Bookkeeping reduction |
| --- | ---: | ---: | ---: |
| 16 | 5.729103 | 2.069335 | 64% |
| 128 | 19.903719 | 2.198564 | 89% |

These are loop bookkeeping measurements, not whole-application CPU savings.
OS process enumeration and detection frequency are unchanged.

Status: **APPLIED**. Compile, scoped Ruff, offline module self-test, and
creation/lineage/PID-reuse/validation-receipt regressions passed.

### Shared sensors: cache age independent of wall-clock corrections

Process and connection caches used wall-clock time for their TTL. A backwards
clock correction could make a stale snapshot appear young until the clock
caught up; a forwards correction caused needless fresh enumeration. Both
lifetimes now use monotonic time, while connection evidence receipts keep their
wall-clock collection timestamp. Existing TTL values, serialization of cache
misses, completeness/error receipts, and `max_age=0` bypass are preserved.

Fixtures move the wall clock forward and backward by one day while advancing
monotonic time normally. Both cache types share the snapshot inside 1.5 seconds
and refresh at expiry. Thirty-two concurrent fixture callers still perform one
enumeration, including a successful empty connection table. A failed connection
receipt remains incomplete and is retried after the TTL despite clock rollback.

Status: **APPLIED**. Compile, scoped Ruff, clock, concurrency, forced-fresh and
connection-coverage regressions passed. This fixes cache correctness under clock
changes; there is no claim of faster ordinary steady-state enumeration.

### Entropy self-test: release temporary files

The bug hunter reproduced a surviving directory and 24,576 fixture bytes after
each successful entropy self-test. `self_test()` now owns its files through
`TemporaryDirectory`, including exception paths. It still exercises the same
entropy primitives and inline scoring path; no process pool is started.

Repeated success and injected-failure fixtures each run three invocations and
leave zero files/directories in the assigned temporary parent. Existing leaked
files outside these fixtures were not deleted.

Status: **APPLIED**. Compile, scoped Ruff, entropy self-test and cleanup
regressions passed. Prevents 24 KiB plus filesystem metadata accumulating per
self-test invocation; it is not a runtime sensor memory-leak fix.

## Validation

- All five changed/new Python files passed `python -m py_compile` and scoped
  Ruff. `git diff --check` found no whitespace errors.
- **28 tests passed** across `test_module_poll_efficiency.py` (13 new cases),
  `test_cycle30_process_generation_identity.py`,
  `test_cycle29_connection_coverage_and_identity.py`, and
  `test_adversary_combat.py`.
- Module self-tests are exercised within those tests. `telemetry/sensors.py`
  has no standalone self-test.
- No GUI, live sensor, inference request, host response action, full regression
  suite, or multi-hour soak was launched by this performance review. Final
  package validation and guarded publication belong to the coordinating agent.

## Proposed follow-up

Broader sharing of LSASS/recovery process enumeration remains **PROPOSED**.
Those guards currently consume fresh scans and explicitly account for missing
command and generation identity fields. Moving them onto an older shared
snapshot requires a separate completeness/freshness contract and evidence that
detection and response behavior remain unchanged. No such cadence or collection
change was applied here. The visionary report describes that larger design.

| Optimization | Component | Status | Expected/measured win |
| --- | --- | --- | --- |
| Reuse per-poll identity; format emitted commands only | Process Monitor | APPLIED | 64–89% less fixture loop bookkeeping |
| Monotonic cache lifetimes | Shared process/connection telemetry | APPLIED | Prevent stale reuse and extra scans after clock corrections |
| Scoped temporary fixture cleanup | Entropy self-test | APPLIED | Eliminate 24 KiB plus one directory retained per invocation |
| Broader process snapshot reuse | LSASS/recovery guards | PROPOSED | Potentially fewer expensive OS enumerations; not yet measured |
