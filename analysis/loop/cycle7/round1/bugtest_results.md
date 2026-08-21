# Cycle 7, Round 1 — Bug-test results

Date: 2026-08-20  
Branch: `codex/enterprise-cycle7`  
Scope: independent crash, lifecycle, startup, recovery, data-root, and release
challenge against the live shared tree.

## Outcome

- **FIXED C7-BT-01:** `AnalysisWorker` replaced Qt's native
  `QThread.finished()` with `finished(dict)` and emitted it from inside
  `run()`. Result consumers could call `deleteLater()` before the native thread
  had returned, producing the observed process-wide Qt abort. Results now use
  `result_ready(dict)`; native `finished()` exclusively controls cleanup.
- **REPORTED C7-BT-02:** Fleet loopback shutdown remains intermittently unable
  to interrupt a handler stopped in a partial HTTP request on Windows. The
  failure is reproducible and can retain the replay-ledger SQLite handle.
- **REPORTED C7-BT-03:** suspend/resume has no explicit power-resume grace.
  Process and UI heartbeat gaps can therefore be classified as suspension or a
  UI stall immediately after a host sleep. This requires a physical-host power
  lifecycle design/gate, not a speculative unit-only patch.
- **REPORTED C7-BT-04:** three manually runnable legacy engine paths still
  default mutable files to the source/current directory rather than the
  canonical data root. They are not imported by the production suite, but do
  not satisfy a literal "every Angerona entry point writes to D:" contract.

## Crash evidence and lifecycle challenge

- A fresh `%LOCALAPPDATA%\CrashDumps\python.exe.20648.dmp` was generated during
  the first aggregate run at **2026-08-20 21:25:20 MDT**.
- Windows Application Error recorded `Qt6Core.dll 6.11.1.0`, exception
  `0xc0000409`, parameter `7`, at 21:25:17. This matches the earlier 18:09
  failure signature rather than a Python exception.
- The code audit found the concrete early-destruction path in
  `angerona.core.analysis_worker.AnalysisWorker`: a result-bearing signal
  shadowed the native completion signal, while consumers connected that signal
  to `deleteLater()` or reaped the worker from the result callback.
- The fix separates result delivery from thread completion and keeps the live
  Alerts worker in its retention list until native `QThread.finished()`.
- Regression coverage asserts that `result_ready` is delivered while the
  worker is still running and native `finished` remains false until `run()`
  returns. The existing deferred-close and standalone Alert Detail integration
  gates remain intact.
- **30/30** fresh-process Qt lifecycle repetitions passed after the fix, with
  no new Python crash dump or Application Error after 21:25.
- Final focused result/result-order gate: **5 passed / 0 failed**.

## Compile, discovery, and self-tests

- Final package compile: **279 Python files / 0 failures**.
- Built-in module import inventory: **67/67 imported**, no import failures.
- Registration inventory: **53/53 callable `register()` functions
  constructed**.
- `ModuleManager.discover()`: **65 modules / 0 discovery errors**.
- Module codes: **48 coded classes / 0 duplicate codes**.
- Fourteen module files intentionally lack `register()`: twelve use
  `BaseModule` class discovery and two are utility-only workers; none is a
  missing-registration regression.
- Module stress drill: **51 passed / 15 expected stopped, idle, optional-service,
  or platform skips**.
- Runnable zero-argument core self-tests: **18 passed / 0 failed**.
- `python tools/selfcheck.py`: **26/26 passed**.
- `run-selfcheck.bat`: exit 0 and **26/26 passed** in the generated report.

## Regression and static gates

- Pre-fix clean shared-tree aggregate: **716 passed / 2 intentional platform
  skips / 0 failed**.
- Post-fix aggregate: **731 passed / 2 skips / 1 Fleet shutdown failure**; the
  run completed without a native Qt abort. Root will run the authoritative
  combined-tree suite after remediation agents finish.
- Focused startup, app shutdown, watchdog, recovery, lifecycle, data-path,
  release, and workflow tests: **93 passed / 1 platform skip**.
- Release hash/setup/workflow static tests: **8/8 passed**.
- Ruff over the full `src`, `tests`, and `tools` trees: PASS at the tested
  snapshot; changed-file Ruff gate after the fix: PASS.
- Release workflow YAML parse: PASS. Source trust preflight: PASS.
- Documentation drift checker: PASS at the tested snapshot.
- `git diff --check`: PASS (line-ending notices only).
- Inno Setup is not installed locally, so the real installer executable could
  not be compiled here. The checked workflow remains the required build gate.
- Ten-second smoke runner: PASS with 11 samples, zero RSS/handle/thread growth
  and zero dropped events. It explicitly lacks live queue/UI metrics and is
  plumbing evidence only, not long-runtime proof.

## C7-BT-01 — FIXED: result signal could destroy a running QThread

- **Component:** `core/analysis_worker.py`, alert result consumers.
- **Symptom:** intermittent process-wide `Qt6Core.dll` abort while asynchronous
  alert analysis or its owner was closing.
- **Root cause:** `AnalysisWorker.finished = Signal(dict)` shadowed
  `QThread.finished()`. It was emitted inside `run()` and consumers performed
  cleanup immediately, before the native worker had necessarily unwound.
- **Fix:** renamed the payload signal to `result_ready`; all exact product and
  test consumers were updated; worker deletion/reaping is connected only to
  native `finished()`.
- **Gate:** result/native-finished ordering regression passes standalone;
  focused tests **5/5**; fresh-process lifecycle stress **30/30**; compile and
  Ruff PASS; no subsequent WER crash event.

## C7-BT-02 — REPORTED: Fleet handler shutdown race

- **Component:** `core/fleet_service.py` / `BoundedThreadingHTTPServer`.
- **Symptom:** an aggregate test first received WinError 10053 rather than the
  promised saturation HTTP 503. The saturation case then passed 10/10 alone.
  More importantly, the stalled-handler stop gate failed **2/20** isolated
  repetitions.
- **Evidence:** failed stops left `_active_handlers == 1` and the accept thread
  stopped, while the replay SQLite file remained locked. Instrumented runs also
  observed WinError 10038 when shutdown closed a socket before handler setup,
  and WinError 10053 while the buffered request reader was unwinding.
- **Disposition:** no change in this QA pass. Fixing cross-thread Windows socket
  cancellation and accounting needs a dedicated remediation with repeated
  partial-request, setup-race, and ledger-close gates.

## C7-BT-03 — REPORTED: sleep/wake ambiguity

- The resilience supervisor classifies a live PID with a stale heartbeat as
  suspended, and the UI watchdog treats an old GUI heartbeat as a stall.
- Neither path currently consumes an explicit Windows power-resume signal or
  applies a resume epoch/grace period. A healthy-but-slow resume can therefore
  create misleading stall evidence or race recovery.
- Physical sleep/wake, watchdog recovery, and post-resume sensor freshness must
  be tested on the host; an offscreen test cannot certify this behavior.

## C7-BT-04 — REPORTED: legacy manual write paths

- `engines/unified_defense_engine.py` and `engines/unified_edr.py` use a
  current-directory `edr_status.json`.
- `engines/persistence.py` defaults `ude_telemetry.db` beside its source file.
- `engines/defense_monitor.py` stages `incident_payload.json` beside source.
- No production import/reference was found for these legacy engines, so the
  normal suite and launchers remain on the canonical data root. The paths still
  need retirement or canonical-root routing before claiming every manually
  runnable entry point writes only to D:.

## Files changed by this QA fix

- `src/angerona/core/analysis_worker.py`
- `src/angerona/gui/pages.py` (exact AnalysisWorker consumers only; preserved
  concurrent Alert Detail lifecycle work)
- `tests/test_qthread_close_lifecycle.py`
- `tests/test_cycle4_round2_cloud_privacy.py`
- this report and the Cycle 7 Round 1 loop-log summary

