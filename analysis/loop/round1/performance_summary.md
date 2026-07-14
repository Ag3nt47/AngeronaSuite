# Round 1 — Performance Summary

Method: static analysis of module `run()` loops, the GUI refresh path, SQLite
access, and the EventBus/tracker polling, plus micro-benchmarks of the pure logic
where a change could be quantified. No GUI was launched (PySide6 absent); Qt paths
were reasoned statically and, where possible, verified with isolated harnesses.
Every applied change is gated: `py_compile` + behaviour proof, and nothing on the
real-time detection path was throttled or weakened.

Note on gating: the sandbox mount intermittently served **truncated** reads of the
large `gui/main_window.py` (1262 of 1276 lines, cut mid-function), producing a
FALSE `SyntaxError`/`IndentationError` in the tail — a known artifact per the
RUNBOOK. The real file (verified via the host filesystem) is intact and closes the
offending `try` block correctly; the edited method was compile- and behaviour-
verified in isolation.

---

## APPLIED

### P1 — In-Memory Flight Cache: drop the per-insert `COUNT(*)` scan
- **Component:** `modules/flight_cache.py` — `FlightCache.put()` / `count()`
- **Problem:** `put()` ran `SELECT COUNT(*) FROM events` on **every** insert to
  compute the eviction overflow. `put()` is a hot path — `FlightCacheModule`
  subscribes to the EventBus and calls `put()` for *every published event* (the
  bus can sustain ~140 events/s). `COUNT(*)` is an O(n) index/table walk that
  grows with the 5000-row cap, so the cost rises as the cache fills.
- **Change:** Maintain an authoritative in-process row counter (`self._nrows`),
  incremented on insert and decremented by the exact number evicted. `put()` is
  the *sole* mutator of the table, so the counter is provably exact. `count()`
  returns it directly instead of querying. `_count_locked()` (real `COUNT(*)`)
  is retained but no longer on the hot path.
- **Improvement (measured, micro-bench 20 000 inserts at cap=5000):**
  46.2 µs/insert → 29.5 µs/insert on `put()` — **1.57× faster**, ~16.7 µs saved
  per event (~2.3 ms/s at 140 ev/s, and it removes an O(n) term that would keep
  growing). 
- **Gate:** `py_compile` PASS. Behaviour: isolated harness confirms the module's
  own `self_test` assertions still hold (cap-held=10, newest=msg24, ro-guard),
  and a 500-insert eviction stress test confirms `count()` == real
  `SELECT COUNT(*)` at every step. Same rows, same eviction, same reads.
- **Status:** APPLIED.

### P2 — Dashboard: stop re-applying an unchanged button stylesheet every tick
- **Component:** `gui/main_window.py` — `MainWindow._update_threat_intel_pulse()`
- **Problem:** Called on the 1 s UI tick, it unconditionally called
  `threat_intel_btn.setStyleSheet(style)`. In the common (no INTL/KEV alert) case
  `style` is the constant `""` every tick, yet `setStyleSheet()` forces a full Qt
  style **re-polish/repaint** of the widget on every call — a redundant repaint
  once per second for the whole session.
- **Change:** Cache the last-applied string (`self._intl_btn_style`) and only call
  `setStyleSheet()` when it actually changes.
- **Improvement:** In the steady idle case, style re-polishes drop from 1/s to 0
  after the first (measured 10 ticks → **1** call instead of 10, a 90% cut). When
  an alert is pulsing, the string alternates every tick and is always applied, so
  **10 ticks → 10 calls — the pulse animation is byte-for-byte preserved.**
- **Gate:** `py_compile` PASS (isolated method; full-file compile blocked only by
  the mount-truncation false error described above). Behaviour: fake-button
  harness confirms 1 call when idle, 10 when pulsing — visible appearance
  identical (setting the same QSS twice is idempotent).
- **Status:** APPLIED.

---

## PROPOSED (not applied — GUI/detection-path; behaviour equivalence not provable
without the Qt runtime / would touch a detection module)

### P3 — Heatmap: build the static Coverage table once instead of every 5 s
- **Component:** `gui/attack_heatmap.py` — `AttackHeatmapWindow._refresh_coverage()`
- **Problem:** The 5 s `_refresh()` timer rebuilds the entire Coverage table
  (~N techniques × 6 cells → hundreds of `QTableWidgetItem` allocations) on every
  tick while the dialog is open. But the data is **static**: `attack_coverage.COVERAGE`
  is a module-level constant and `_valid_action_keys()` derives from the fixed
  `remediation_actions.ACTIONS` allow-list — neither changes during a session.
- **Proposed change:** Populate `_cov_tbl` once (first refresh / tab shown), or
  cache the `summary()` string and skip the rebuild when unchanged. The live
  Heat matrix and Top tab (which *do* change) keep their 5 s cadence.
- **Expected win:** Eliminates hundreds of widget allocations + a full table
  repaint every 5 s while the heatmap is open. No behaviour change (identical
  static content).
- **Why proposed, not applied:** GUI render path; can't execute Qt here to prove
  the rendered table is identical. Low risk, recommended for a human-verified apply.

### P4 — Coalesce duplicate `net_connections()` scans through the shared cache
- **Component:** `modules/beacon_detector.py` (`_poll_once`, 5 s) and
  `modules/counter_agentic.py` (`_watch_ollama_port`, `_POLL`)
- **Problem:** Both call `psutil.net_connections(kind="inet")` **directly** — the
  single most expensive sensor call on Windows (tens–hundreds of ms) — bypassing
  the existing time-boxed shared cache in `telemetry/sensors.list_connections()`
  (1.5 s TTL) that was built precisely to collapse these duplicate full scans.
  Two independent full connection-table enumerations per cycle instead of one.
- **Proposed change:** Route both through `sensors.list_connections()` (and
  `list_processes()` for the pid→name lookups), so overlapping polls reuse one
  enumeration. TTL (1.5 s) is far shorter than either module's poll interval, so
  detection fidelity is unchanged.
- **Expected win:** Up to one fewer full `net_connections()` scan per overlapping
  window; removes per-pid `psutil.Process(pid).name()` calls (each its own syscall)
  in favour of the batched, cached process table.
- **Why proposed, not applied:** These are live **detection** modules and the
  cached helper returns dicts (`raddr` as `"ip:port"` string, no psutil object,
  no `SYN_SENT`/`ESTABLISHED` object semantics). Rewiring changes the data shape
  and status-filtering; behaviour equivalence (identical detections) can't be
  proven statically. Per the RUNBOOK, when in doubt on a security control →
  PROPOSE. Recommended as a carefully-tested change in a later round.

---

## Not changed (already optimal — verified)
- `core/storage.py` FlightRecorder: already uses a write-counter + `MAX(id)`
  amortised prune and a `max_ts()` zero-cost pre-check; no per-tick `COUNT`.
- `core/alert_ack.py`: already mtime-cached (the reference pattern).
- `gui/main_window.py` `_refresh_body`: already change-detected and tick-modulo
  staggered (1 s / 2 s / 4 s tiers); heavy panels don't run every tick.
- `gui/telemetry_worker.py`: already batches off the Qt main thread with
  backpressure; EventBus already drops INFO under ring pressure.
- `telemetry/sensors.py`: shared 1.5 s process/connection snapshot cache already
  exists (P4 is just about *using* it from two stragglers).
