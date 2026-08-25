# Round 8 — Host Adaption Performance

Scope: one behavior-preserving responsiveness pass over the new host-adaptation
workbench and dashboard context monitor. Security collection, command semantics,
approval, rollback, and circuit-breaker behavior were not changed.

## Results

### APPLIED — Remove dashboard-thread signed-state I/O

- **Component:** `gui/main_window.py` context monitor
- **Problem:** every 15-second Qt timer callback parsed and verified the signed
  adaptation state on the GUI thread, then an enabled cycle immediately parsed
  the same store again in `run_automatic_cycle()`.
- **Change:** the timer now performs only an in-memory single-flight check and
  starts the bounded worker. The worker's existing automatic-cycle entry point
  performs the one required state check, including the disabled case.
- **Expected/measured improvement:** zero adaptation filesystem reads on the Qt
  timer callback; enabled monitor ticks reduce state-store reads from two to one
  (50%). Disabled ticks retain one read, moved off the GUI thread. The existing
  active-event gate prevents overlapping monitor workers.
- **Gate:** focused test proves `state()` is not called by the timer thread;
  compile and adaptation suites pass.
- **Status:** **APPLIED**

### APPLIED — Coalesce workbench state reads

- **Component:** `gui/adaptation_workbench.py` persisted views
- **Problem:** a complete persisted-view refresh parsed the same signed state
  separately for adaptive weights, trigger rules, and breaker status.
- **Change:** one verified state value is shared by the exception and trigger
  views. Breaker status retains its own service call so time-window expiry
  semantics remain unchanged.
- **Expected/measured improvement:** state-store reads per complete refresh fall
  from three to two (33%) with identical validation and presentation.
- **Gate:** focused call-count test passes; breaker-status expiry remains routed
  through the original core method.
- **Status:** **APPLIED**

### APPLIED — Skip unchanged Qt table reconstruction

- **Component:** `gui/adaptation_workbench.py` activity, exceptions, trigger, and
  rollback-snapshot views
- **Problem:** context completion and manual refresh discarded and reallocated
  every `QTableWidgetItem`, causing avoidable layout and repaint work (up to 500
  activity records) even when data was identical.
- **Change:** retain bounded immutable row signatures, rebuild only changed
  views, suspend widget updates during real replacements, and preserve the
  selected rollback snapshot. Automatic monitor outcomes now refresh only views
  they can mutate; `stable`, `disabled`, `no-match`, and `already-applied` do no
  table work.
- **Expected/measured improvement:** isolated 500-row activity benchmark averaged
  **0.869 ms** for an unchanged refresh versus **12.671 ms** for a forced rebuild,
  a **14.6x** speedup. Signatures are bounded by the stores' existing retention
  limits and do not cache host snapshots or security observations.
- **Gate:** focused identity test confirms unchanged Qt items are retained;
  state-changing automatic outcomes still route snapshot/activity/status updates.
- **Status:** **APPLIED**

### PROPOSED — Event-driven network context wakeup

- **Component:** host context monitor
- **Problem:** while automation is armed, polling can invoke `netsh` and
  PowerShell every 15 seconds even when network topology has not changed.
- **Proposal:** use Windows network-profile/interface change notifications to
  wake the existing worker, retaining a slow reconciliation poll as a safety net.
- **Expected improvement:** remove nearly all steady-state subprocess launches
  on stable hosts.
- **Why not applied:** notification completeness, service-session behavior, and
  missed-event recovery require Windows integration testing. Changing cadence
  without that proof could delay a defensive adaptation.
- **Status:** **PROPOSED**

### PROPOSED — Background initial persisted-view load

- **Component:** adaptation workbench open path
- **Problem:** opening the workbench still verifies several bounded local stores
  before its initial tables are populated.
- **Proposal:** capture a read-only persisted-view bundle on a worker and install
  it atomically on the GUI thread.
- **Expected improvement:** faster first paint when activity and snapshot stores
  are at retention limits or storage is temporarily slow.
- **Why not applied:** the current bounded reads are small, while lifecycle and
  stale-result ordering need a dedicated Qt close/reopen gate.
- **Status:** **PROPOSED**

## Gates

- `python -m py_compile` for both changed GUI modules and the focused test:
  **PASS**.
- Final focused host-adaptation/UI/performance set after security convergence:
  **20 passed**.
- Final full repository suite: **1077 passed / 3 intentional platform skips /
  0 failed**.
- `angerona.core.host_adaptation.self_test()`: **PASS** — integrity stores,
  exceptions, and context matching healthy.
- `git diff --check`: **PASS** (only the repository's existing line-ending
  conversion warning for `main_window.py`).
