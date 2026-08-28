# Cycle 25 / Round 2 — Bug Test Results

Date: 2026-08-27
Scope: current shared v1.12 worktree, with focused coverage of Auto Adapt,
host-baseline recovery, durable SIEM/remote delivery, IPC admission control,
module lifecycle truth, sortable/clickable GUI evidence, and persistence drift.

## Result

- Product compile: **346/346 Python files valid** under `src/angerona/`.
  Nine first-pass failures were Windows `__pycache__` write
  `PermissionError`s while other loop workers shared the checkout. Recompiling
  those exact sources to fresh temporary output paths passed **9/9**; these
  were output-lock artifacts, not syntax defects.
- Discovery: **80 modules**, **0 discovery/import errors**, **0 duplicate
  module names**, **0 duplicate capability IDs**, and **61/61 declared module
  `CODE`s unique**. The manager's documented class discovery found every
  module. Compatibility `register()` hooks exist for 64 discovered instances;
  the remaining class-only modules are valid under the repository's explicit
  no-registration-required contract.
- Standalone core self-tests: **24 passed / 0 failed**.
- Module harness: **64 passed / 0 failed / 17 expected skips**, including the
  EventBus pipeline (63 active module self-tests plus the pipeline). Skips were
  limited to disabled, unstarted optional, or other-platform capabilities.
- Project selfcheck: **26 passed / 0 failed**, both by direct invocation and by
  the exact `run-selfcheck.bat` launcher; batch exit code **0**.
- Focused Round 2 tests: **56 passed** across adaptation, durable outbox, IPC,
  remote bridge, mitigation proposal, cursors/contracts, and GUI surfaces.
- Lifecycle/persistence follow-up: **38 passed**.
- Final complete `test_v12_*` gate: **46 passed / 1 expected skip / 0 failed**.
  The skip is an environment-dependent optional capability. Command groups
  overlap and are intentionally not summed into a misleading aggregate.

## Bugs

### C25-R2-BT-01 — IPC self-test could erase a concurrent authorization count

- Component: `src/angerona/modules/ipc_guard.py`
- Symptom: the supposedly isolated loopback self-test incremented the module's
  live `accepted` counter and restored a pre-test snapshot afterward. A real
  production authorization completing during that window could be overwritten
  by the older snapshot.
- Root cause: `_serve_conn()` had no isolated accounting mode, so the test used
  production counters and compensated with snapshot/restore.
- Status: **FIXED**.
- Fix: added an explicit `count_result=False` test path and removed counter
  snapshot restoration. Authentication behavior is unchanged for production
  callers.
- Gate: source compile passed; `tests/test_v12_ipc_guard.py` and
  `tests/test_shared_ipc_contract.py` passed **4/4**. A new regression simulates
  two independently completed production counts during the self-test and
  proves both survive.

## Non-defect observations

### First selfcheck YARA timeout

The first highly concurrent selfcheck reported one YARA self-test timeout at
12 seconds. The same test passed directly in approximately 47 ms, the complete
selfcheck rerun passed, and the batch launcher rerun passed. No source,
assertion, timeout, or security gate was weakened. This was classified as host
scheduling/load contention rather than a reproducible product defect.

### First-pass compile permission errors

Nine source files could be read and compiled but their normal package
`__pycache__` targets were temporarily locked. Fresh-path `py_compile`
reverification passed every affected source. They are recorded as shared-mount
artifacts and not syntax failures.

## Files changed by bug testing

- `src/angerona/modules/ipc_guard.py`
- `tests/test_v12_ipc_guard.py`
- `analysis/loop/cycle25/round2/bugtest_results.md`
- `analysis/loop/LOOP_LOG.md`

No commit or publication was performed by this QA agent.
