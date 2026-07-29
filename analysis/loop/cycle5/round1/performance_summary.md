# Cycle 5 / Round 1 — Performance Summary

Method: inspected runtime scheduling, EventBus reads, telemetry polling, GUI
refresh timers, watchdog cadence, logging, and SQLite access. Applied only the
clearly behavior-preserving telemetry hot-path change below. The real-time
detection and protection paths were not throttled.

## APPLIED

### P1 — Telemetry SQLite polling: persistent reader with rowid cursor

- **Component:** `src/angerona/gui/telemetry_worker.py`
- **Problem:** `TelemetryWorker` polled every 50 ms and, on every poll, opened a
  new read-only SQLite connection, parsed the schema, selected/sorted the newest
  200 rows, closed the connection, and deduplicated them through a growing set.
- **Change:** Keep one thread-owned read-only connection for the worker lifetime.
  Preserve the initial newest-200 snapshot in oldest-first delivery order, then
  seek `WHERE rowid > ? ORDER BY rowid ASC LIMIT 200`. Bursts larger than 200
  drain over successive polls without omissions. Close the connection in the
  worker's `finally` block and reconnect after transient SQLite failures.
- **Correctness adjunct:** Removed the invalid `QThread.setDaemon(True)` call,
  which prevented `TelemetryWorker` construction under PySide6. Qt owns thread
  lifecycle; explicit `stop()` and the application shutdown path are unchanged.
- **Measured improvement:** isolated 5,000-row SQLite database, 1,000 idle polls:
  old path **2,338.7 ms**; persistent cursor path **156.6 ms**;
  **14.9x faster / 93.3% less elapsed CPU work**.
- **Gate result:** changed-source `py_compile` PASS. Focused PySide6/SQLite test
  PASS: initial 200 rows retained; a later 250-row burst drained as 200 + 50;
  oldest-first ordering preserved; next poll returned zero duplicates.
- **Status:** **APPLIED**

## PROPOSED

### P2 — EventBus push subscription for GUI telemetry

- **Component:** `gui/telemetry_worker.py`, `core/eventbus.py`
- **Problem:** With no database event, the worker still polls
  `EventBus.recent(200)` at 20 Hz and deduplicates object identities.
- **Proposal:** Replace GUI EventBus polling with a bounded subscriber queue,
  preserving the current batch size and maximum flush latency.
- **Reason not applied:** subscription lifetime/unsubscription semantics require
  a broader lifecycle change and concurrency tests.
- **Expected improvement:** eliminate up to 20 ring snapshots/s while idle.
- **Status:** **PROPOSED**

### P3 — Consolidate overlapping GUI recent-event snapshots

- **Component:** `gui/main_window.py`, dashboard/posture panels
- **Problem:** independent refresh consumers request overlapping EventBus
  snapshots on the same timer cycle.
- **Proposal:** construct one immutable refresh snapshot and pass it to pure
  panel calculations that accept pre-fetched events.
- **Reason not applied:** panel API changes require GUI integration coverage and
  risk conflicts with concurrent Loop 1 work.
- **Expected improvement:** fewer lock acquisitions and ring copies per refresh.
- **Status:** **PROPOSED**
