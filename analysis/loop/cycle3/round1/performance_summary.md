# Cycle 3 / Round 1 — Performance Summary

Date: 2026-07-19

Scope: long-running slowdown/freezing, Eco-off wake-up, GUI-thread stalls,
event/alert growth, module polling, lifecycle cleanup, watchdog/crash evidence,
and Ollama shutdown. All applied changes preserve detections and response; no
security poll interval or alert admission rule was relaxed.

## Runtime evidence reviewed

- `diagnostics/not_responding.log` captured the Qt thread stalled for more than
  five seconds inside `FlightRecorder.try_count_since()` during a dashboard
  refresh. The Python writer lock was non-blocking, but the shared SQLite
  connection still carried a 3000 ms busy handler and could wait on external
  database/schema activity.
- The same log captured the Stop path stalled for 5.8 seconds while
  `psutil.process_iter()` requested `cmdline` for every Windows process.
- Later samples found the GUI in alert-row insertion or a trivial paint call
  while 70–80 module/helper threads were live. This is consistent with system/
  GIL pressure rather than an unbounded dashboard table: the alert view is
  already capped at 120 rows, incrementally updated, and uses item actions rather
  than leaking per-row button widgets.
- Runtime crash logs contain old Settings exceptions and historical fault dumps,
  but no newer Python exception explaining the progressive slowdown. Current
  self-test failure status reports 63 passed / 0 failed.

## Optimizations

### P-C3-R1-01 — EventBus restart fan-out and bounded recent copy

- **Component:** `core/eventbus.py`
- **Problem:** modules that subscribe from `run()` could register the same bound
  callback again after stop/start or Eco resume. Every future event was then
  processed multiple times. Also, `recent(20)` copied the full 500-entry ring on
  every call before slicing.
- **Change:** subscriber registration is idempotent; positive-limit reads copy
  only the requested newest items with `islice(reversed(...), limit)`. Historical
  zero/negative-limit semantics are preserved.
- **Measured:** 200,000 `recent(20)` calls over a full ring: 1.0606 s → 0.2627 s,
  **4.04x faster**. Re-registering one bound callback 20 times still delivers
  exactly one callback per event.
- **Gate:** compile PASS; focused behavior regression PASS.
- **Status:** **APPLIED**

### P-C3-R1-02 — Truly non-blocking dashboard SQLite reads

- **Component:** `core/storage.py`
- **Problem:** `try_recent()` and `try_count_since()` used the writer connection.
  Even after a non-blocking Python-lock check, SQLite could invoke its 3000 ms
  busy handler; a real watchdog trace captured a >5 s Qt stall in COUNT.
- **Change:** interactive reads use a separate read-only WAL connection with
  `timeout=0` / `busy_timeout=0`, plus their own non-blocking lock. The existing
  `writer busy -> return None` contract is retained. Busy/schema-lock errors now
  skip one repaint tick instead of propagating or sleeping.
- **Expected improvement:** dashboard database wait is bounded to an immediate
  success/skip rather than seconds. Returned rows are the same authenticated,
  last-committed records.
- **Gate:** compile PASS; committed-row/count equality, writer-busy compatibility,
  zero-wait pragma, and UI-lock contention regressions PASS; prior Round-3 test
  remains PASS.
- **Status:** **APPLIED**

### P-C3-R1-03 — One connection snapshot per Memory Time-Machine sweep

- **Component:** `modules/memory_timemachine.py`
- **Problem:** every six-second sweep called per-process connection enumeration
  for every PID. On Windows this repeated an OS connection-table query hundreds
  of times and competed with the GUI when Eco mode was turned off.
- **Change:** take one `psutil.net_connections(kind="inet")` snapshot and
  partition it by PID before carving the same `laddr->raddr` strings. If any row
  is unattributed or the bulk call fails, fall back to the original per-process
  path so telemetry coverage is not weakened.
- **Measured:** 238 processes / 169 attributed connections: 0.1834 s → 0.0030 s,
  **60.97x faster for connection collection** (one OS enumeration instead of
  238). Output/fallback regressions preserve the carved connection data.
- **Gate:** compile PASS; module `self_test()` PASS; focused bulk/fallback snapshot
  regressions PASS.
- **Status:** **APPLIED**

### P-C3-R1-04 — Expire inert speculative-triage PID cooldowns

- **Component:** `modules/speculative_triage.py`
- **Problem:** `_last_prewarm` retained every historical PID forever even though
  an entry cannot affect a decision after the eight-second cooldown.
- **Change:** periodically discard only entries whose cooldown has expired. Live
  cooldown decisions and the bounded prewarm queue/cache are unchanged.
- **Expected improvement:** memory tracks risky PIDs in the active eight-second
  window rather than all risky PIDs seen over a multi-day session.
- **Gate:** compile PASS; module `self_test()` PASS; expired/live cooldown focused
  regression PASS.
- **Status:** **APPLIED**

### P-C3-R1-05 — Race-free sequential Eco cancellation

- **Component:** `core/eco_wakeup.py`, `gui/main_window.py`
- **Problem:** pressing Eco ON while a sequential Eco-OFF wake was still running
  could stop current scanners while the worker concurrently started the next one.
  The UI could say Eco ON while a late heavy scanner came online.
- **Change:** cancel an active wake before pausing modules and serialize the
  worker's cancel vs check/start section. After `cancel()` returns no later module
  can start; a start that already won finishes before the caller performs stops.
- **Expected improvement:** no competing wake/pause churn and no background
  scanner stampede after a rapid Eco toggle.
- **Gate:** compile PASS; existing sequential-cycle tests PASS; deterministic
  cancel/start race regression PASS.
- **Status:** **APPLIED**

### P-C3-R1-06 — Filter before expensive shutdown command-line reads

- **Component:** `gui/main_window.py`
- **Problem:** Stop requested PID/name/cmdline for every process. Windows may retry
  protected-process command-line reads; the watchdog captured this exact stack.
- **Change:** enumerate PID/name first and request a command line only for Python
  candidates. The same Angerona ownership command-line predicate and kill action
  are preserved.
- **Measured:** current 238-process host: 0.0567 s → 0.0181 s, **3.13x faster**;
  only two Python candidates required command-line reads.
- **Gate:** compile PASS; focused lifecycle regressions PASS.
- **Status:** **APPLIED**

### P-C3-R1-07 — Virtualized alert model under extreme bursts

- **Component:** `gui/pages.py` AlertsPanel
- **Problem:** a remaining watchdog sample landed inside item creation during a
  burst. The existing 120-row cap and incremental update prevent growth, but
  `QTableWidget` still creates up to 840 items on a gap rebuild.
- **Proposed change:** migrate the visible alert feed to a bounded
  `QAbstractTableModel` with stable action delegates and chunked gap replacement.
- **Reason not applied:** widget/model replacement needs offscreen Qt equivalence
  tests for sorting, row actions, selection, and newest-event reconciliation.
- **Status:** **PROPOSED**

### P-C3-R1-08 — Consume the existing cosmetic performance governor

- **Component:** `core/perf_governor.py`, dashboard refresh wiring
- **Problem:** the governor is constructed but not sampled or consumed by the
  dashboard, so its cosmetic-only profiles currently recover no UI headroom.
- **Proposed change:** sample GUI latency/RSS on a slow cadence and apply only the
  documented refresh/visible-row/coalescing knobs.
- **Reason not applied:** wiring changes visible refresh cadence and needs Qt load
  tests plus a settings restart/live-update contract. No detection path should
  ever consume these knobs.
- **Status:** **PROPOSED**

## Gates and changed files

- `py_compile`: **205/205 Python files PASS** in the latest combined concurrent tree.
- Performance/lifecycle/prior-performance regression set: **11/11 PASS**.
- A full-suite rerun during concurrent remediation work reached **30 passed / 1
  unrelated failure**: the changing Posture Hardening drill-resolution result no
  longer exposed the legacy `resolved` key expected by
  `test_policy_and_drill_resolution.py`. This is owned by the remediation pass,
  not a performance file; the parent loop was notified.
- Module gates: Memory Time-Machine, Speculative Triage, and ARIA Overdrive
  `self_test()` all PASS.
- Changed source: `core/eventbus.py`, `core/storage.py`, `core/eco_wakeup.py`,
  `modules/memory_timemachine.py`, `modules/speculative_triage.py`, and
  performance-only sections of `gui/main_window.py` (Eco lines ~594 and Stop
  lines ~2364; ARIA/microphone lines were not touched).
- Added focused tests: `tests/test_cycle3_round1_performance.py`.
