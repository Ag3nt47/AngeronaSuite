# Cycle 6 / Round 3 — Performance Regression

Scope: post-change regression of the GUI telemetry worker and Resolve Center,
plus static blocking/hot-loop review of the new kernel-posture ledger and WFP
transactional containment work. No protection cadence was changed.

## Regression evidence

### Telemetry SQLite cursor

- **Component:** `src/angerona/gui/telemetry_worker.py`
- **Result:** persistent read-only connection and indexed rowid cursor remain
  intact. Initial newest-200 delivery and subsequent no-duplicate cursor reads
  passed.
- **Measurement:** 1,000 idle cursor polls over a 5,000-row SQLite database:
  **216.4 ms total / 216.4 µs per poll**.
- **Gate:** `py_compile` PASS.
- **Status:** **APPLIED (REGRESSION PASS)**

### Resolve Center pagination and change detection

- **Component:** `src/angerona/gui/resolve_center.py`
- **Result:** a 5,000-event active set creates only 25 table rows per page.
  Unchanged refreshes return before event filtering/table reconstruction.
- **Measurements:** unchanged fast path: **115.7 ms / 1,000 calls
  (115.7 µs/call)**. Forced refresh with 5,000 supplied events and a 25-row
  render: **338.3 ms / 100 calls (3.38 ms/call)**.
- **Gate:** pagination/action tests PASS.
- **Status:** **APPLIED (REGRESSION PASS)**

## New-path review

### Kernel-boundary posture ledger

- **Component:** `src/angerona/modules/kernel_posture_ledger.py`
- **Finding:** observation runs in the module worker, not the Qt thread, at a
  **300-second interval**. External checks have explicit 6–8 second timeouts;
  driver registry enumeration is bounded at 2,048 keys; ledger retention is
  bounded at 256 records. No tight polling or unbounded collection found.
- **Gate:** ledger tests PASS.
- **Status:** **REVIEWED — NO CHANGE**

### WFP controller and containment planning

- **Component:** `src/angerona/modules/wfp_controller.py`
- **Finding:** suspicious-connection scanning runs in the module worker at a
  **30-second interval**. Port/PID snapshots are cached for five seconds, PID
  names are cached within each scan, and containment planning/receipt checks do
  not perform implicit host commands. No GUI-thread blocking or hot loop found.
- **Gate:** containment transaction tests PASS.
- **Status:** **REVIEWED — NO CHANGE**

## Gates

- Focused pytest:
  `tests/test_resolve_center_pagination.py`,
  `tests/test_kernel_posture_ledger.py`,
  `tests/test_wfp_containment_transactions.py`:
  **15 passed in 1.29 s**.
- Changed-module `py_compile`: **PASS**.
- Full `src` compile scan: **PASS**.
- Product-code changes in this regression pass: **none**.

