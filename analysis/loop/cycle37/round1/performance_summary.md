# Cycle 37 Round 1 — performance analysis and gated optimization

Date: 2026-09-30. Scope: sustained Chill and Full worker load, with read-only
inspection of the GUI refresh and Settings paths. The six-minute Cycle 36
offscreen witness used only Process Monitor, FIM, and YARA; it did not reproduce
the operator's all-worker freeze. This round does not treat that limited result
as a passing full-host performance test.

## Applied: bound flight-cache event insertion cost

The In-Memory Flight Cache remains enabled in both Chill and Full. Its EventBus
subscriber writes each event synchronously to a bounded SQLite memory table.
After reaching the 5,000-row cap, every `put()` ran a `DELETE` with an ordered
subquery to rediscover the oldest row, despite being the only writer and
already assigning monotonically increasing IDs. That extra query added latency
to every event publisher under sustained or bursty telemetry.

`FlightCache` now remembers only successfully inserted row IDs in a bounded
`deque` and deletes the oldest by SQLite primary key. Failed inserts can leave
ID gaps without selecting or evicting the wrong row. The same newest rows,
read visibility, count, and commit batching remain. No detection cadence,
EventBus delivery policy, response control, or durable recorder changed.

Measurements on the Windows host, using in-memory SQLite and 10,000 further
inserts after filling a 5,000-row cache:

| Measurement | Old ordered-subquery eviction | Direct-ID eviction |
| --- | ---: | ---: |
| Paired five-run module-level median | 61.5 µs/event | 28.0 µs/event |
| Isolated SQLite statement comparison | 31.5 µs/event | 8.1 µs/event |

The paired module-level median is a **2.2×** improvement. Individual samples
varied with other host activity, so this is a local microbenchmark, not a
whole-app CPU or freeze result. The cache holds at most 5,000 small Python
integers in addition to its prior table. Improvement matters most when the
cache is full and EventBus volume is high; quiet idle CPU is not the claim.

Gate: `py_compile` passed; `FlightCacheModule.self_test()` passed through the
focused test; 32 targeted tests passed across the new exact-eviction regression,
existing cache batching, and module review tests; Ruff and `git diff --check`
passed. **Status: APPLIED.**

## Applied: reuse one live policy decision per module table row

The 66-worker offscreen witness measured `ModulesPanel.refresh()` at 7.859 s
total over 33 Full-mode calls (maximum 1.047 s). The table was asking
`ModuleManager.module_usage()` three times per row: once through assurance,
once through `is_enabled()`, and once for the policy tooltip. It now reads one
fresh policy result for each row and passes its enabled state to the assurance
projection, checkbox, and tooltip. It still samples every module on every
scheduled panel refresh; discovery, selection, sorting, and live policy
transitions remain observable.

An isolated 84-row pure-Python policy projection measured 3.372 ms/frame for
three decisions per row and 1.085 ms/frame for one, a 3.11× reduction in that
projection. This does **not** establish a 3.11× GUI or whole-app improvement;
Qt work and worker contention dominate the measured stalls. The offscreen
panel regression now asserts one read per row plus a fresh transition from
disabled to enabled. `py_compile`, Ruff, and diff checks passed; the GUI test
remains in the integrated release gate. **Status: APPLIED, UI gate pending.**

## Applied: reuse ransomware content histogram for complete windows

The host lacks NumPy, so `_byte_histogram()` counts bytes in Python. The
ransomware content proof counted each full 64 KiB read once for the aggregate
and range receipts and again for window entropy. `_read_content_sample()` now
calculates that window's entropy from the existing exact histogram when the
window is one complete read. Fragmented OS reads continue through the original
accumulation path. It still opens, reads, hashes, and verifies the same bytes,
with unchanged range selection, deadlines, coverage receipts, and alert
decisions. No sensor cadence or security threshold changed.

A paired baseline/current 1 MiB full-file proof on the same Windows host
matched every `_ContentSample` field and reduced median main-thread CPU from
0.359 s to 0.172 s (2.09×) across five alternating pairs. The microbenchmark
isolates this content hot path; no post-change all-worker soak has yet proved
the operator's freeze resolved. New complete/strided proof tests also compare
full and fragmented reads. Gate: `py_compile`, Ruff, and diff checks passed;
`RansomwareHeuristicsModule.self_test()` passed; 20 new/lifecycle tests and 18
adjacent content/remediation tests passed. **Status: APPLIED.**

## Investigated without product change

- `SettingsDialog._tab_system()` still calls Windows `autostart.is_enabled()`
  synchronously during construction. A read-only host sample took 194.4 ms;
  the Scheduled Task query has a ten-second timeout. Making this asynchronous
  must preserve the current OS-truth checkbox and changed-autostart rollback
  semantics, especially if Save is pressed before the probe completes. It is
  a startup/dialog latency issue, not evidence for a running-mode freeze.
  **Status: PROPOSED.**
- Shared process and connection snapshots already serialize cache misses and
  use a short age bound; Process Monitor and Network Monitor use their declared
  polling intervals. The Detection Runtime's empty-lane process and snapshot
  calls measured 18.5 and 29.3 µs respectively in a 5,000-call local sample.
  Reducing those cycles or deep-scan cadence without coverage proof would risk
  a security regression. **Status: INVESTIGATED; NO CHANGE.**
- `EventBus.publish()` signs and then invokes every subscriber inline on the
  producer thread. Its existing `subscriber_metrics()` reports per-callback
  latency and budget violations, so a real soak can attribute producer stalls
  without changing delivery order. A synthetic signed 15-subscriber bus took
  roughly 173 µs/publish for 10,000 no-op events on this busy host; adding a
  full Flight Cache callback yielded about 181 µs/publish in that run, with
  39 µs/call attributed to the cache callback. This synthetic result does not
  establish real steady-state event volume. **Status: INVESTIGATED; NO CHANGE.**
- An initial 66-worker offscreen soak subscribed `FlightRecorder.record_bus`
  directly. That callback commits SQLite inline; its 16,408 ms maximum over
  215 Chill deliveries coincided with a 5,573 ms Qt heartbeat slip. Production
  `app.py` instead starts `AsyncFlightRecorder` and subscribes its bounded
  `submit` queue handoff, so the initial soak did not reproduce the production
  recorder graph. An isolated 500-event EventBus/SQLite fixture measured
  direct publication at 0.158 ms median, 1.062 ms p99, and 21.998 ms maximum;
  production async wiring measured 0.024 ms median, 0.096 ms p99, and 1.290 ms
  maximum, with all 500 signed events persisted in four batches and no DLQ
  failures. This supports rerunning the all-worker soak with production wiring,
  not changing authoritative storage semantics based on a harness artifact.
  The existing async-recorder, recovery, and headless-delivery gates passed
  (14 tests). **Status: INVESTIGATED; NO CHANGE.**
- The corrected 66-worker run used `AsyncFlightRecorder.submit` and drained all
  680 accepted events into the ledger without overflow or DLQ failure. It still
  reproduced Qt heartbeat slips: 3,480 ms with three >1-second gaps in initial
  Chill; 1,590 ms with three gaps in Full; and 3,496 ms with ten gaps after
  returning to Chill. Initial Chill consumed roughly 96% of one CPU core and
  added 106 MiB RSS. Thus the synchronous recorder was a harness confounder,
  not the whole freeze explanation. **Status: MEASURED; UNRESOLVED.**
- A second instrumented 66-worker, production-recorder witness ran Chill →
  Full → Chill for 90 seconds each and drained its queue. Full still had a
  7,761 ms maximum Qt heartbeat slip and 18 gaps above one second. The timed
  `MainWindow._refresh_body()` reached 1,188 ms and `ModulesPanel.refresh()`
  accounted for 7,859 of its 9,809 total milliseconds. The 7,761 ms gap did
  not overlap any timed refresh callback, so panel work alone is insufficient
  to explain it. Full-mode native CPU leaders were Ransomware Heuristics
  (26.1 s/90 s), Qt MainThread (12.0 s), Storage Hygiene (9.8 s), Memory
  Injection Scanner (6.5 s), and Process Monitor (6.3 s). Initial Chill had
  unrelated pytest contention for its first 31 seconds and should not be used
  as a clean maximum; returned Chill had a 1,339 ms maximum and two >1-second
  gaps. The new module and GUI optimizations are grounded in these hotspots,
  but this witness predates both patches. **Status: MEASURED; POST-FIX SOAK
  REQUIRED.**
- The main Qt timer's heavier path invokes `ModulesPanel._build()` on each
  panel refresh. It assesses every visible module and constructs its tooltip
  before comparing the rendered row snapshot; immutable source anchors are
  cached and unchanged rows avoid Qt writes. Dashboard counts, alerts, threat
  posture, and SOAR queue reads already use background `AsyncSnapshot` workers.
  Instrumented timings identified the module panel as the largest measured
  Qt refresh component, leading to the single-policy-snapshot change above.
  Further caching of assurance scores requires a precise invalidation proof
  because health, worker liveness, and policy can change during a run.
  **Status: INVESTIGATED; BOUNDED CHANGE APPLIED.**
- A controlled selected-worker result cannot certify all-worker,
  physical-display, or all-day behavior. The 66-worker offscreen run above is
  materially stronger but still lacks a native-thread CPU breakdown and Qt
  callback attribution. A disposable-data-dir soak must still explicitly exclude
  the USB monitor, which enforces Windows AutoRun/AutoPlay registry policy on
  start. Active and Smart Deception write canaries under `data_dir()` by
  default, so a disposable data root contains them when the personal-folder
  opt-in is off. Canary Drills spawn benign subprocesses after five seconds;
  Smart Deception targets personal folders if that opt-in is set. These are
  test isolation constraints, not recommendations to disable production protection.
  **Status: PROPOSED.**

| Optimization | Component | Status | Expected or measured win |
| --- | --- | --- | --- |
| Delete the known oldest successful row by primary key | In-Memory Flight Cache | **APPLIED** | 61.5 → 28.0 µs/event paired median at full cache; preserves exact newest-row set |
| Reuse one fresh policy result per visible row | ModulesPanel | **APPLIED; history/panel checks 19/19** | 3.372 → 1.085 ms/84-row policy projection; all live rows still assessed |
| Reuse content histogram for exact 64 KiB window | Ransomware Heuristics | **APPLIED** | 0.359 → 0.172 s/1 MiB proof thread CPU; exact proof and strided decisions preserved |
| Resolve startup task state without blocking dialog construction | Settings System tab | **PROPOSED** | Avoid up to ten seconds of Qt blockage on a slow Windows task query; transactional semantics require a separate review |
| Attribute sustained mode load with default-enabled real workers | GUI and worker runtime | **PROPOSED** | Identify actual CPU, memory, or Qt-stall source before changing detection cadence |

## Completed-code repeat with independent Qt control

The 66-worker repeat ran each phase for 90 seconds without concurrent pytest.
The separate-process 20 ms Qt heartbeat ran for 283.344 seconds, with a maximum
slip of 43 ms and no recorded large gaps. Angerona's results were:

| Phase | Maximum slip | Gaps >1 second | CPU, percent of one core | Panel total / maximum |
| --- | --- | --- | --- | --- |
| Initial Chill | 1480 ms | 1 | 120.45% | 2688 / 156 ms |
| Full | 527 ms | 0 | 118.62% | 2878 / 187 ms |
| Returned Chill | 1074 ms | 2 | 118.91% | 3266 / 234 ms |

All 1079 accepted recorder events persisted, the queue drained, and neither
storage nor overflow DLQ recorded failures. Full's maximum fell from 7761 to
527 ms and panel total from 7859 to 2878 ms in these runs. Workload and host
conditions differ: this is a repeat witness, not a controlled efficacy claim.
Ransomware Heuristics still consumed 31.047 CPU seconds in Full and Storage
Hygiene 23.438. The simultaneous minimal Qt control stayed responsive while
Angerona paused, supporting application-process contention rather than a
host-wide Qt scheduling stall. Chill freezes remain **MEASURED; UNRESOLVED**.
The component speedups do not prove reduced whole-application CPU usage.

Raw local records: `.tmp/cycle37_instrumented_mode_soak_result.json` and
`.tmp/cycle37_qt_control_result.json`; the fixture uses production async
recorder wiring and disposable data, with the exclusions stated above.
