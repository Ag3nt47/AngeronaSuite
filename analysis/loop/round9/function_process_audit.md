# Round 9 — Functional and Process Regression Audit

Date: 2026-08-25
Scope: Python compilation, complete regression suite, built-in module discovery,
module and standalone self-tests, application/batch harnesses, launcher bootstrap,
and launch/shutdown/background-worker/process-ownership paths.

## Outcome

- **Genuine defects found:** 1
- **Fixed behind gates:** 1
- **Reported product defects remaining:** 0
- **Environmental/capability limitations observed:** optional Ollama/model,
  optional native/kernel/watchdog artifacts, disabled modules, and non-Windows
  modules described below. These were not counted as product regressions.

## Commands and exact results

| Gate | Command / method | Result |
|---|---|---|
| Package compile | `python -m py_compile` over every `src/angerona/**/*.py` and `run-compile-check.bat` | Initial tree **308 compiled, 0 failed**; final concurrent tree **310 compiled, 0 failed**; batch exit 0 |
| Baseline complete pytest | `venv\Scripts\python.exe -m pytest -q` | **1,258 passed, 3 skipped** |
| Final complete pytest after the fix/current concurrent tree | same | **1,268 passed, 3 skipped** in 115.35 s |
| Built-in discovery | `ModuleManager.discover()` in isolated data root | **67 modules, 0 discovery/import errors** |
| Module CODE audit | discovered module instances | **48 declared CODEs, 48 unique, 0 duplicates** |
| Module source/import audit | imported every `angerona.modules.*` file | **69 files imported**; 67 contained module classes |
| Module self-tests | `SelfTestRunner`, headless modules deliberately not started | **48 passed, 0 failed, 21 skipped** |
| Standalone self-tests | isolated subprocess for each top-level `self_test()` in core/resilience/Shark/GUI, 45 s deadline each | **31 discovered, 31 passed, 0 failed, 0 timed out** |
| Project selfcheck | `venv\Scripts\python.exe -u -X utf8 tools\selfcheck.py` | **26 phases passed, 0 failed**, exit 0 |
| Batch selfcheck | `run-selfcheck.bat` | **26 phases passed, 0 failed**, exit 0 |
| Focused lifecycle/process regression set | 14 lifecycle, drain, shutdown, process-baseline, worker, and headless test files | **81 passed** in 12.49 s |
| Launcher boundary | canonical and guarded `--bootstrap-selftest` | **2/2 passed**, both exit 0 |
| Bounded process smoke | `tools/run_soak.py --profile smoke --duration-seconds 2` | **PASS**, 3 samples; zero handle growth, thread growth, and dropped-event delta |
| Lint for changed audit files | `ruff check` on self-test runner/policy/harness/tests | **PASS** |
| Final repository lint | `venv\Scripts\ruff.exe check src tests tools` | **PASS** |
| Patch hygiene | `git diff --check` | **PASS** (line-ending notices only) |

## Self-test classification

The final module report contains no raw failures.

- **13 harness-specific skips:** AI Triage/Ollama unavailable; AMSI Bridge,
  Active Deception, Active Response SOAR, Adversary Combat, Dynamic Resource
  Governor, Memory Injection Scanner, Network Monitor, Process Monitor, SOAR
  Automation, Sysmon Event Bridge, TUNE, and WFP Controller were deliberately
  not started by this non-elevated diagnostic or require explicit arming.
- **5 operator-disabled skips:** Cloud CTI Escalation, Forensics Capture, Packet
  Sniffer, Remote Bridge, and SIEM Forwarder.
- **3 platform skips:** Linux Observe, Linux eBPF, and macOS Observe are not
  available on the Windows audit host.
- The optional kernel driver and indirect-syscall bridge were absent, and the
  source Python execution was not a signed hermetic build. Their self-tests
  truthfully reported supported fallback/degraded posture; none caused an
  import, crash, or false pass.

## Defect fixed

### FIXED — headless selfcheck could waive a hung module self-test

**Component:** `tools/selfcheck.py` / `angerona.core.selftest.SelfTestRunner`

**Symptom:** the harness parsed rendered text and included the broad substring
`"timed out"` in its expected-failure allowlist. A new or regressed module whose
`self_test()` hung beyond 12 seconds could therefore produce a `[FAIL]` row but
still let the authoritative project selfcheck exit 0. The same text report also
showed 13 alarming raw FAIL rows that the outer harness subsequently waived.

**Root cause:** expected unstarted/optional states and genuine execution defects
were classified after rendering by broad text matching rather than as structured
results.

**Correction:**

- Added a pure, narrowly scoped `is_expected_unstarted_failure()` policy.
- Added an optional `expected_failure_cb` to `SelfTestRunner.run()`. Controlled
  harnesses may convert only an explicitly recognized unstarted prerequisite to
  a structured skip; normal application self-tests remain strict by default.
- Timeouts, exceptions, unrelated idle text, and unrelated Ollama failures are
  explicitly ineligible for conversion.
- The headless report, persisted result, severity decision, and process exit now
  agree: **47 PASS / 0 FAIL / 21 SKIP**, rather than printing 13 FAIL rows and
  later silently waiving them.

**Regression gate:** `tests/test_selfcheck_policy.py` — **3 passed**. It proves
the narrow stopped/optional cases become skips and timeout/exception/unrelated
failures remain actionable failures. Focused Ruff, direct selfcheck, batch
selfcheck, compile, and the final full suite all passed afterward.

## Discovery and registration findings

Twelve class-bearing module files do not expose the older optional `register()`
convenience function: `ai_triage`, `cloud_escalation`, `deception`,
`file_integrity`, `forensics`, `macos_observe`, `network_monitor`,
`persistence_sweep`, `process_monitor`, `soar`, `soar_engine`, and
`yara_scanner`. This is **not a defect** in the current architecture:
`ModuleManager` discovers `BaseModule` subclasses directly, and all twelve were
imported and included among the 67 discovered modules without error. Adding
unused wrappers would not improve runtime coverage.

## Launch, shutdown, worker, and child-process review

The static inventory covered **87 `threading.Thread` construction sites, 9
`QThread` subclasses, 2 `QThreadPool` construction sites, and 16 direct
`subprocess.Popen` sites**. Focused runtime gates exercised generation-safe
module restart, close deferral for active QThreads, UI worker completion order,
backpressure bounds, evidence/storage drain, fleet-handler drain races, process
baseline shutdown, packet-worker termination, Ollama ownership/attestation,
headless Chill shutdown, and exact Angerona child-process ownership.

The ownership tests reject substring/name-only matches and accept only the suite
interpreter or canonical Angerona entry point. Launcher bootstrap tests also
confirmed both supported launch paths preserve their environment scrub and
trust-root boundary without actually launching or elevating the application.

No escaped owned child, hung worker, leaked handle/thread growth, import failure,
state leak, or shutdown test failure was reproduced. The batch harness emits one
Qt `QThreadStorage` teardown advisory after all 26 phases and explicit cleanup;
it is not the fatal `QThread: Destroyed while thread is still running` condition,
does not change exit 0, and no live-worker/process leak was observed. It is
recorded as a runtime advisory rather than a product defect.

## Evidence limitations

The two-second smoke profile proves sampling plumbing and bounded process
counters only; it is not long-duration soak proof and did not receive live GUI
tick/queue metrics. Elevated production ETW/WFP/AMSI behavior and optional
native-driver artifacts require a separately installed/elevated acceptance
environment. They were not falsely claimed as covered by this non-elevated
functional audit.
