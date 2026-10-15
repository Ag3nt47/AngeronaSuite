# Hardware responsiveness and unnecessary background work

Date: 2026-10-14. Version: 1.13.0. Baseline: `fea868c`.

The operator reported a footer speed percentage near 12% on an older computer
and requested improvements across Black Box, scanners and modules. They clarified
that lower pace should slow processing so the dashboard remains functional. The footer
has two distinct readings: a tiny 30-Hz Qt paint heartbeat and **Angerona pace**.
Pace is `100 / routine interval multiplier`: an 8x interval displays 12% after
rounding. It is not measured processing speed, CPU usage or detection coverage.
Healthy feedback takes at least 24 seconds to restore 8x through 4x and 2x to
1x. Low FPS, delayed paint delivery or host CPU pressure can keep it reduced.
No feedback thresholds or display measurements were changed to raise this value.

## Changes

- Routine processing previously paused only at fixed item-count boundaries:
  eight files, 256 discovery entries or 256 native memory queries. Slow hardware
  could spend seconds processing those items before a 50-ms pause. A shared
  per-worker pacer now checks elapsed work at every available boundary as well.
  At 8x it targets approximately 7 ms of work before a pause of up to 50 ms;
  4x and 2x permit larger work slices. Existing count-based pauses remain.
  Nested counters do not reset elapsed work; ordinary cadence sleeps do.
  Actual cooperative wait time extends module watchdog deadlines without
  advancing readiness. Scan Center uses one local work budget per scan and
  retains its wall deadline, while memory traversal retains the original
  2-second native-work budget and one cumulative 6.4-second rest allowance.
  Archive members now have checkpoints between inspections. This affects
  routine work at explicit checkpoints, not event delivery, response actions,
  watchdogs or the separate real-time telemetry scanner. Individual native
  calls cannot be interrupted by this policy; pace is still not a CPU quota.
- Black Box previously inspected threads, memory mappings, sockets and file
  handles even when minimized or displaying another tab. These three detail
  workers now sleep on events until their own tab is visible, wake immediately
  when selected, and pause again on hide/minimize/tab change. Existing logging,
  host telemetry and process-bound suite health continue independently. An
  in-flight native inspection finishes normally; hiding never waits for it.
  Detail exports identify the last captured snapshot; unopened details report
  that no data was captured. This deliberately trades continuous detail snapshots
  for lower unattended overhead, without changing security sensors.
- Periodic dashboard reconciliation previously acquired the manager lifecycle
  lock on Qt. That lock also covers module starts, which can wait for a retiring
  worker. Reconciliation now uses one reused background reader with one coalesced
  follow-up. Manager locking, shutdown checks, policy transitions and synchronous
  explicit reconciliation are retained. Queued work captures the manager rather
  than widgets and retires when its dashboard owner is destroyed.
- Eco wake-up cancellation now publishes its stop request before waiting for
  an admitted module start to finish. Previously the worker could reacquire a
  non-fair lock and start another module before the waiting cancellation could
  publish its request. The existing start barrier remains: cancellation returns
  only after an admitted start finishes. A deterministic queued-cancel challenge
  covers both direct starts and manager-delegated starts.
- YARA traversal still discovers and sorts its bounded inventory. It locates the
  fair cursor with binary search and allocates only the selected batch, replacing
  two complete filter passes and concatenation. Binary response classification
  lowercases the payload once instead of up to three times. File-handle freshness,
  cancellation checkpoints, traversal bounds, cursor ordering, signature
  requirements, response authority and polling intervals remain enforced.
- Memory Time-Machine avoids Windows UDP table reads because Windows psutil does
  not expose UDP remote endpoints. Other platforms retain `inet`: connected UDP
  peers can be evidence on Linux. Unattributed listeners do not contribute remote
  strings and no longer trigger a full connection-table read per process. Missing
  remote ownership and failed bulk reads retain the original fallback. Unknown
  ownership still reports incomplete collector coverage.

## Component measurements

These are local, controlled fixtures. They do not measure whole-application
speed, native detection effectiveness, every hardware configuration, or the
operator's reported footer value. No production Angerona core was running when
the initial process inventory was inspected.

| Workload | Before | After |
| --- | --- | --- |
| Hidden Black Box inspectors, six seconds, own benchmark PID | 2 thread / 1 memory / 2 resource collections | 0 / 0 / 0 |
| Same fixture process CPU time | 0.4375 seconds | Below the process CPU timer's resolution |
| Visible memory tab, six seconds | Not separately measured | 2 memory collections; no thread/resource collections |
| GUI call with controlled 250-ms lifecycle lock contention | 250.307 ms | 0.784 ms; 50 Qt timer deliveries during wait |
| Isolated cursor selection, 200,000 sorted candidates | 130.977 ms; 3,281,856 peak traced bytes | 0.062 ms; 80,060 bytes |
| Binary classification, positive 16-MiB fixture | 84.535 ms | 53.155 ms |
| Binary classification, partial-signature 16-MiB fixture | 94.812 ms | 46.250 ms |
| 512 processes, attributed remote peers plus unattributed listener | 1 bulk + 512 per-process queries | 1 bulk; all 512 remote strings delivered |

Scanner timings are medians after warmup, with neither profiler nor allocation
tracing active. Peak allocations use a separate traced run. Cursor selection
measures the post-sort algorithm only; filesystem discovery and YARA matching
remain outside that measurement. Classification verdicts and selected batches
were checked for equivalence. Full synthetic traversal timings were noisy on
the shared host and are not used as a whole-scanner speed claim.

Reproduce the read-only fixtures with the repository virtual environment:

```text
python tools/benchmark_blackbox_idle.py --baseline-ref fea868c --seconds 6
python tools/benchmark_yara_scan_efficiency.py --baseline-ref fea868c
python tools/benchmark_routine_work_pacing.py --item-ms 20
```

Black Box native queries target only the benchmark's own inert process; runtime
files use a private temporary directory. YARA inputs are synthetic and do not
start sensors, native scans, response actions or model inference.

The routine-work fixture uses virtual time rather than measuring a machine.
For 32 indivisible 20-ms items at 12.5% pace, it preserves all 32 items while
changing the longest work burst from 160 ms to 20 ms and increasing total
requested rest from 200 ms to 1,600 ms. This deliberately slows completion to
give the UI more opportunities to run. Larger indivisible native calls still
set a lower bound on the work burst; no scheduling policy can split them here.

## Validation

Focused regressions cover elapsed-time yields before fixed batch boundaries,
nested counter resets, normal/disabled policy, ordinary sleep exclusion,
actual-wait watchdog accounting, bounded memory traversal and cancellation;
hidden/selected/minimized inspector behavior, stop
wakeups, visibility changes during blocked native reads, last-capture labels,
blocked lifecycle operations, coalescing and destruction, cursor ties and wraps,
all binary signature requirements, collector fallback, connected POSIX UDP peers
and large process-table delivery. The isolated self-check passed all 26 phases,
including its disposable 30-step drill and cleanup.

An initial integration run passed 4,905 tests with 23 skips and failed the Eco
wake-up cancellation challenge. Its failure led to the cancellation repair
above. That run preceded the final elapsed-pacing integration and is not evidence
of a passing final tree. Its log remains in
`.tmp/performance-2026-10-14-pytest.txt` locally.

The final run uses the existing opt-in `tools.pytest_execution_trace` observer
to retain outcomes and native Qt diagnostics. Tests run serially without a
selection filter; their assertions and normal isolation remain intact.

The final ordinary Windows run passed **4,923 tests with 23 explicit skips** in
884.54 seconds (exit 0). The final isolated self-check passed **26/26 phases**.
Compilation of source, tests, tools and Black Box; fatal Ruff checks;
documentation drift; and Git whitespace checks passed. Logs remain locally in
`.tmp/performance-2026-10-14-pytest-final.txt`,
`.tmp/performance-2026-10-14-final.pytest.jsonl`, and
`.tmp/performance-2026-10-14-selfcheck-final.txt`.

Publication uses the guarded publisher to verify canonical public main and all
README image bytes before completion is reported. Local tests do not establish
the status of hosted CI on the resulting commit.
