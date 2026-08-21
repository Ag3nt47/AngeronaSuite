# Cycle 7 / Round 2 - Performance Summary

## Scope and invariants

This pass inspected the current post-`478e65e` tree for long-runtime UI churn,
polling, repeated filesystem/database/network work, unbounded state, worker
leaks, Eco wake sequencing, live-alert rendering, scanner/watchdog churn, and
the new deferred-QThread-close guard. Applied changes are limited to passive
display work and Purple Guard policy loading. Detection cadence, signatures,
events, containment, authorization, and evidence verification are unchanged.

## Applied optimizations

### APPLIED - Purple Guard policy identity cache

- **Component:** `angerona.modules.purple_guard.PurpleGuard`.
- **Problem:** with remediation signatures installed, the one-second detector
  cycle reparsed the unchanged `purple_guard_policy.json` every time. That is up
  to **86,400 identical file opens and JSON parses per active day**.
- **Change:** cache the parsed techniques behind a file identity containing
  device/inode, nanosecond mtime/ctime, and size. Atomic replacement, in-place
  rewrite, deletion, and creation invalidate the cache immediately. Direct
  helper callers retain their original uncached semantics.
- **Measured improvement:** 5,000 unchanged reads took **1.325681 s** through
  the legacy parser and **0.585787 s** through the identity check: **2.26x
  faster**, with 4,999/5,000 file opens/parses eliminated. A regression proves
  an atomic policy update is visible on the next cycle.
- **Security/behavior proof:** the policy content and one-second detection
  cadence are unchanged. The cache key is not an authorization primitive and
  does not bypass parsing after any observable file identity change.
- **Gate:** compile PASS; Ruff PASS; Purple Guard self-test PASS; focused tests
  PASS.
- **Status:** **APPLIED**.

### APPLIED - revision-gated expanded console mirroring

- **Component:** `angerona.gui.dashboard_details.ConsoleDetailDialog`.
- **Problem:** an open detail dialog copied the dashboard's complete console,
  copied its own 80,000-character transcript, and recounted lines every 650 ms
  even when no output changed.
- **Change:** consult Qt's document revision first. Full text extraction,
  bounding, transcript replacement, scroll movement, and line counting now run
  only after the source document changes. The independent busy indicator still
  refreshes on every tick.
- **Measured improvement:** 500 unchanged refreshes over a representative
  804-KiB/4,000-line console took **3.708455 s** in the legacy probe and
  **0.002480 s** with the gate: **1,495x faster** in the isolated benchmark.
  The regression proves 20 unchanged ticks perform zero full transcript reads
  and the next append is rendered immediately.
- **Security/behavior proof:** the displayed transcript remains the same newest
  80,000 characters and uses the same guarded command path.
- **Gate:** compile PASS; Ruff PASS; dashboard and focused tests PASS.
- **Status:** **APPLIED**.

### APPLIED - sample-gated System Pulse detail rendering

- **Components:** `SystemPulseCard`, `SystemPulseDetailDialog`, `MetricTile`.
- **Problem:** the 900 ms detail timer copied the complete 90-sample history,
  rebuilt eight table items, regenerated graph samples, and reapplied unchanged
  metric/state text between the card's two-second samples.
- **Change:** expose cheap sample revision/busy tokens, create the four telemetry
  rows once, and update history/graph/metrics only for a new sample. Sampling
  state remains independently live. Card and metric controls now skip identical
  property/text/style writes.
- **Measured improvement:** the focused regression observes **0 snapshot copies
  and 0 table rebuilds across 20 unchanged refreshes**, followed by exactly one
  copy/update for the next sample. Under the normal 900 ms detail / 2,000 ms
  sample cadence this removes more than half of steady unchanged render work.
- **Security/behavior proof:** host sampling cadence, fields, bounded history,
  off-thread `psutil`/`netsh` execution, error state, and late-result shutdown
  guard are unchanged.
- **Gate:** compile PASS; Ruff PASS; System Pulse lifecycle and UI tests PASS.
- **Status:** **APPLIED**.

### APPLIED - unchanged table rebuild coalescing

- **Components:** `ModuleResourceDialog`, `TopTalkersDialog`.
- **Problem:** open views discarded and recreated unchanged Qt table items every
  1.3 seconds (module activity) or four seconds (network talkers). Repeated item
  allocation and table sorting increases GUI-thread work with window count and
  uptime.
- **Change:** compare bounded immutable render fingerprints and rebuild only
  after visible row content changes. Module health/intensity and Top Talkers
  summary text still update independently.
- **Measured improvement:** focused tests observe **0 rebuilds across 20
  unchanged refreshes** for each view and one immediate module-table rebuild
  when an event is added. At the 25-event module cap this avoids recreating up
  to 75 `QTableWidgetItem` objects every 1.3 seconds per unchanged open view.
- **Security/behavior proof:** OS connection collection still runs off the GUI
  thread at the same cadence; every changed process, destination, count,
  interface, severity, timestamp, or message invalidates the corresponding
  render key.
- **Gate:** compile PASS; Ruff PASS; dashboard and focused tests PASS.
- **Status:** **APPLIED**.

## Inspected and intentionally unchanged

- **Eco wake sequencing:** already starts heavy scanners one at a time, waits
  for a real first-cycle boundary, coalesces cancellation, and bounds per-module
  waits. No parallel wake stampede or GUI-thread blocking was found.
- **Live Alerts:** already uses an in-memory storage revision, a zero-wait
  read-only SQLite connection, one coalesced reader, a 120-row cap, lightweight
  action items, and incremental prepend/trim rendering. Shared in-progress
  alert changes were not touched.
- **Deferred QThread close:** the new helper is signal-driven rather than
  polled, stores a bounded list of only currently running workers, and clears it
  before the final close. No performance correction was required.
- **Watchdog/scanner churn:** watchdog cadence is eight seconds and restart
  attempts are capped; shared process/connection snapshots already collapse
  common duplicate OS enumerations. No security scan was delayed.

## Proposed follow-ups

### PROPOSED - define the TelemetryWorker production latency contract

`TelemetryWorker` performs an indexed SQLite/EventBus poll every 50 ms, but no
production owner currently constructs it. Adaptive idle backoff could reduce
up to 20 no-op queries per second if it is integrated later, but it would alter
UI delivery latency. Define and test that contract before applying.

### PROPOSED - attack-matrix snapshot/render revisioning

The open ATT&CK heatmap serializes the full technique matrix and visits every
cell every five seconds. Heat decays with wall time, so a simple event revision
cache would change visible decay semantics. A time-bucketed cache needs explicit
heat/selection/filter tests first.

### PROPOSED - generation-aware Purple Guard event deduplication

The process-marker deduplication set still clears wholesale after 4,096 keys.
A bus-generation-aware bounded cache could avoid a rare duplicate burst, but
retention changes need drill/AAR proof and were not made in this
behavior-preserving pass.

## Verification

- Changed-source `py_compile`: **PASS**.
- Ruff over all owned changed Python files: **PASS**.
- Purple Guard module `self_test()`: **PASS** - exact file/process markers
  detected; benign noise ignored.
- Focused performance/UI/lifecycle gate: **34 passed**.
- Wider owned/relevant performance and lifecycle gate: **70 passed**.
- `git diff --check` for owned files: **PASS** (line-ending conversion warnings
  only).
- A broader shared-tree run recorded 72 passes and one timing failure in the
  independently edited QThread result-order test; the test waits on a queued Qt
  signal without pumping the application event loop. It is outside this pass's
  ownership and was reported to the coordinating agent.

No protection path was throttled and no security control was weakened.
