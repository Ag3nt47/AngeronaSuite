# Bug hunt — round 20260921

Status: baseline review and reproductions completed; production remediation belongs to the patch applier. This report does not claim post-patch gates or live-sensor assurance.

## Scope and gates

- Checkout: `AngeronaSuite-module-review-20260921`; the original checkout was not edited.
- Interpreter: existing `AngeronaSuite/venv/Scripts/python.exe`, with `PYTHONPATH` explicitly set to this checkout's `src`.
- Runtime state was isolated under this checkout's `.tmp/bug-hunt-*` directories; `QT_QPA_PLATFORM=offscreen` and the supported selfcheck mode were used. Inventory/reproductions did not start real sensors, inference or response actions. The existing selfcheck's benign disposable drill remains part of the supported harness.
- Whole-package `py_compile`: **377 passed, 0 failed**. No syntax errors or sandbox stale/truncated-read artifacts occurred; fresh-copy revalidation was therefore unnecessary.
- Discovery: **84 capabilities**, **0 import/construction errors**, **0 duplicate declared CODEs**. All 87 Python files in the module package were inventoried: 84 capabilities plus package initializer, capture worker and remediation helper.
- Module SelfTestRunner: **68 module passes, 0 failures, 16 expected skips**. The independent EventBus pipeline check adds one pass, producing the harness's **69 passed, 0 failed, 16 skipped** result. Skips include unsupported OS, intentional opt-out and stopped/optional prerequisites; these are not reported as passing sensor tests.
- Core self-tests: **24 passed, 0 failed**, discovered from every top-level `core/*.py` self_test definition. Core red-team/coverage behavior without a top-level self_test is exercised by the project's harness.
- `tools/selfcheck.py`: **26 phases passed, 0 failed**. `run-selfcheck.bat` uses the same entry point with the virtualenv interpreter and UTF-8; its exit propagation was reviewed. The review worktree has no private venv, so the explicit existing interpreter was used instead of running the wrapper's missing-venv guard.
- No full pytest run was performed by this agent; the parent schedules final suite validation after edits.

Machine-readable evidence: `compile-before.json`, `core-selftests-before.json`, `bug-reproductions-before.json`, `module-audit.json`. Full baseline harness output: `selfcheck-before.txt`. Human-readable exhaustive inventory: `module-audit.md`.

## Findings

### BH-01 — AMSI native context closes during an active scan — REPORTED

Component: `src/angerona/modules/amsi_bridge.py`, `_AMSI.scan/close`, `AMSIBridgeModule.stop`.

`BaseModule.stop()` intentionally signals and returns without joining its worker. The AMSI override immediately closed its context/session, while a worker or concurrent self-test could remain inside the native scan. A benign blocked fake-native scan demonstrated that the context closed before the scan returned. This is a native lifetime race, independent of the passing stopped readiness test.

Required change: serialize context destruction against active scans and let worker-generation cleanup own the native handle, without blocking the GUI stop path. Gate with blocked-scan shutdown and restart tests plus AMSI self-test and package compile.

### BH-02 — Successful AMSI restart retains observation-only fallback — REPORTED

Component: `src/angerona/modules/amsi_bridge.py`, `AMSIBridgeModule.run`.

An unsuccessful initialization sets `_fallback=True`; a later successful initialization did not reset it. The fixture began in fallback, supplied a successful benign initialization and observed `_fallback` still true. Script events consequently continued down the observation-only path after recovery.

Required change: derive fallback from the current generation's initialization result. Gate failed-then-successful restart behavior.

### BH-03 — API-hook alert dedupe never retires — REPORTED

Component: `src/angerona/modules/api_patch_detector.py`, `_raise_alert`, `_flagged`.

The set retains `pid/export` keys forever, without expiry, capacity control or process-generation identity. A hook, then a complete clean scan returning health 100, then the same hook produced only **one alert for two incidents**. A 1,001-distinct-key fixture retained every key; source inspection finds no eviction. PID reuse can also inherit old suppression.

Required change: bound and expire suppression while retaining active repeated-alert control and allowing independent incidents to alert again. Process identity and clean-scan semantics should remain explicit. Gate high-cardinality state, expiry, repeated unchanged hooks and recurrence.

### BH-04 — Disabled module callbacks continue work — REPORTED

Components: `network_protocol_decoder.py`, `provenance_graph.py`, `canary_drill.py`; companion adversary review also covers `flight_cache.py` and `speculative_triage.py`.

EventBus retains subscriptions for the process lifetime. NDRD and PROV callbacks had no stopped-state guard; after `stop()`, a benign published event incremented NDRD DNS count from 0 to 1 and PROV node count from 0 to 1. Canary's stopped callback likewise parsed a trusted process event and advanced `_last_trusted_event`. MEMC still reaches its closed-cache path on each event; SPEC admission is recorded by the companion adversary review.

Required change: stop admission/processing when a module is disabled and preserve meaningful running/resume behavior. Tests must distinguish explicit offline helper evaluation from a retained live subscription. The shared availability/count policy belongs to the parent and must retain broken expected protection as degraded.

### BH-05 — Entropy self-test leaks temporary directories — REPORTED

Component: `src/angerona/core/entropy_pool.py`, `self_test`.

The test uses `tempfile.mkdtemp()` and never removes its three fixture files. An isolated passing invocation left **one directory and 24,576 bytes** after return. Repeated self-tests accumulate diagnostics artifacts.

Required change: scope fixtures with `TemporaryDirectory`, covering both success and error paths. Gate its self-test and verify fixture removal.

### BH-06 — AMSI native scan failures are reported as clean success — REPORTED

Component: `src/angerona/modules/amsi_bridge.py`, native scan result handling and self-test.

A failing mocked `AmsiScanBuffer` HRESULT of -1 returned `AMSI_RESULT_CLEAN` (0). The running self-test then returned `True` with `AmsiScanBuffer functional — probe result=CLEAN`. Closed/uninitialized contexts similarly returned CLEAN. This can hide unavailable scan coverage.

Required change: fail the operation on native error/closed context and preserve degraded health/failed self-test instead of interpreting failure as a clean verdict. Gate failure, closed-context and successful clean-result cases separately.

## Ruled-out candidates and limits

- Repeated bound-method subscriptions are already deduplicated by `EventBus.subscribe`; no duplicate-subscription leak is alleged for Identity Session, DNS or Purple Guard.
- Audit Log Integrity Guard retains source objects across generations, but its native `WindowsEventLogSource.close()` is a no-op and reads acquire/close per-query handles. The proposed closed-source restart issue was ruled out.
- `register()` is optional under class-based discovery. Sixteen modules omit it and eighteen omit explicit class CODE metadata; all 84 still discover correctly. These are compatibility metadata gaps, not failed registration.
- One local ad-hoc reporting script initially hit Windows CP1252 encoding while printing Unicode. It was rerun with `-X utf8`; this was a diagnostic-script issue, not an Angerona failure. The supported harness already configures UTF-8.
- A temporary mock used during concurrent patching lacked the newly introduced AMSI lock; that fixture error was corrected before reproducing BH-06. It is not a production defect.
- Baseline counts above precede concurrent remediations. Final post-patch regression and publication gates are owned by the parent; append their results instead of relabeling these baseline observations.

Total: **377 files compiled; 92 self-tests passed (68 modules + 24 core), 0 failed, 16 module skips; selfcheck 26/26 passed; 0 bugs fixed by this agent, 6 finding groups reported.**
