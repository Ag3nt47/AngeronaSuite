# Cycle 2 / Round 1 — Performance Summary

Date: 2026-07-14. Scope: the current combined tree after Round 1 remediation
and QA, with emphasis on the long-run dashboard path, non-Eco awakened modules,
EventBus/storage, watchdog evidence, process/network/memory/YARA scans, and the
headless self-check. No detector cadence, threshold, response action, event
durability, rule, or `rules/_active_combined.yar` content was changed.

## Applied

### C2-P1 — Cache an unchanged SOAR queue parse

- **Component:** `src/angerona/gui/pages.py` — `_read_soar_queue()`.
- **Problem:** `SoarPanel.refresh()` runs on the dashboard's two-second full
  refresh. Even when the append-only queue had not changed, it reread the whole
  JSON-lines file and parsed up to 500 records. The panel's later row-count
  check avoided a table rebuild, but only after paying the file and JSON cost.
- **Change:** Cache the parsed bounded result by canonical path, nanosecond
  mtime, byte size, and requested limit under a small lock. A caller still gets
  a fresh list. Append and clear operations change size/mtime and therefore
  invalidate the cache without changing queue semantics.
- **Measured win:** 400 reads of an unchanged 500-row representative queue fell
  from **434.287 ms to 32.436 ms**, a **92.5% reduction** (about **13.4x
  faster**). An appended 501st record invalidated the cache and the bounded
  500-row result exposed the new final record.
- **Status:** APPLIED.

### C2-P2 — Suppress identical dashboard card renders

- **Component:** `src/angerona/gui/pages.py` — `StatCard.__init__()` and
  `StatCard.set()`.
- **Problem:** The four summary cards called both `QLabel.setText()` and
  `setStyleSheet()` every full refresh even when their displayed value and
  colour were unchanged. Reapplying a stylesheet can trigger Qt style and
  repaint work; this was constant UI churn during long sessions.
- **Change:** Remember the last `(text, color)` pair and return early only when
  both are identical. A changed text or colour still updates immediately.
- **Measured win:** 400 identical updates fell from **400 text + 400 stylesheet
  calls to 1 + 1** (**99.75% fewer Qt mutation calls**). Offscreen Python/Qt
  time fell from **1.895 ms to 0.695 ms** before accounting for the avoided
  style/repaint work. A subsequent changed value performed the expected second
  update and preserved the displayed text and style.
- **Status:** APPLIED.

### C2-P3 — Keep direct self-check temporary artifacts on D:

- **Component:** `tools/selfcheck.py` — startup environment setup.
- **Problem:** Production startup already pins `ANGERONA_DATA`, `TEMP`, and
  `TMP` to the D-resident runtime tree, but executing `tools/selfcheck.py`
  directly bypassed that entry point. Its drill and diagnostic temporary files
  could therefore churn the user's C-profile temp directory.
- **Change:** Call the same canonical `configure_runtime_environment()` helper
  before Qt or any self-check phase imports `tempfile`.
- **Status:** APPLIED in the shared tree. The combined command that would have
  recompiled this runner and asserted `tempfile.gettempdir()` was interrupted;
  the coordinator's next full self-check gate should reconfirm it. Production
  startup was already D-pinned and is unaffected.

## Reviewed / not changed

- **Awakened modules:** `EcoWakeupWorker` starts paused modules sequentially and
  waits for a real first-cycle boundary; `BaseModule.sleep()` keeps subsequent
  cycles interruptible and resource-governor aware. The staged start also
  naturally offsets later scan cadences. No safe reason was found to slow a
  detector or change its security sampling interval.
- **Process, memory, YARA, and network sensors:** shared process/connection
  snapshots, serialized cache misses, empty-snapshot caching, first-poll
  staggering, and per-batch policy snapshots remain present. Beacon Detector
  and Counter-Agentic Detection still use direct connection enumeration, but a
  shared-cache conversion remains proposed only because its address/status
  shape and freshness contract differ on a live detection path.
- **EventBus/storage:** subscribers still run synchronously after the ring lock
  is released. Making durable recorder/cache delivery asynchronous could reduce
  publisher latency, but it would change ordering, visibility, and crash
  durability; no speculative queue was added. SQLite remains WAL/NORMAL,
  hard-bounded, amortized-pruned, and severity-aware.
- **UI/watchdog evidence:** the actionable historical stalls were alert/Resolve
  Center widget storms, repeated policy/config reads, and headless self-check
  artifacts. Those paths are now bounded/cached or test-isolated. No new
  production crash was established by Round 1 QA.
- **ARIA Overdrive:** the new governor remains opt-in/unwired and cosmetic-only.
  It was not enabled implicitly or used to throttle detection.

## Gates and convergence

- `src/angerona/gui/pages.py` direct `py_compile`: **PASS**.
- SOAR cache: fresh-list equivalence, 500-row bound, unchanged-file cache hit,
  and append invalidation: **PASS**.
- Stat card: identical-call suppression plus changed-text/style equivalence:
  **PASS** under offscreen PySide6.
- `git diff --check` for `pages.py`: **PASS** (line-ending notice only).
- `tools/selfcheck.py`: minimal startup-only edit; its final compile/path/full
  self-check gate remains for the coordinator because the validation command
  was interrupted.

Performance convergence for this phase: **YES for safe steady-state UI work**.
The remaining high-cost candidates would change live detection freshness,
event-delivery durability, or protocol overload behavior and remain proposals
until equivalence/load tests exist.
