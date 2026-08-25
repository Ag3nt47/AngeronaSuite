# Round 8 — Bug Test Results

Date: 2026-08-24. Runner: Angerona bug-testing / QA agent. Environment:
Windows, `venv\Scripts\python.exe` (CPython 3.12), `PYTHONPATH=src`, Qt
offscreen. The shared dirty tree was treated as authoritative; unrelated and
concurrent edits were preserved.

## Gates executed

- Per-file `py_compile` into an isolated temporary output directory:
  **304/304 package files passed**, zero syntax errors. No stale/truncated
  sandbox-mount false positive was observed.
- Adaptation/dashboard focus:
  `pytest -q tests/test_host_adaptation.py tests/test_startup_dashboard_ready.py
  tests/test_loading_activity.py tests/test_context_info_tabs.py` passed
  **16/16** before the two new bug regressions; the final dedicated adaptation
  file passed **9/9** after the concurrent context-binding hardening converged.
- Qt/application lifecycle focus:
  `test_async_widget_close_lifecycle.py`, `test_qthread_close_lifecycle.py`,
  `test_performance_lifecycle.py`, `test_app_shutdown_drain.py`, and
  `test_app_startup_health.py` passed **23/23**.
- Core import/self-test sweep: **129/129 imports**, **19/19 callable core
  self-tests**, zero failures. This includes `host_adaptation.self_test()`.
- `ModuleManager.discover()`: **66 modules**, zero discovery errors, **48**
  non-empty codes, and zero duplicate codes. There are 54 top-level
  `register()` factories across 69 package files; `register()` is optional in
  this class-based discovery design, and all intended runtime modules were
  discovered, so no missing-registration defect was found.
- Built-in module runner: **47 passed / 12 expected stopped, idle, or
  unavailable-Ollama results / 8 structured platform/configuration skips / 0
  unexpected failures**. The runner's count includes its synthetic event
  pipeline gate in addition to the 66 discovered modules.
- `python tools/selfcheck.py`: **26 passed / 0 failed**.
- `run-selfcheck.bat`: **26 passed / 0 failed**, and the wrapper returned exit
  code zero after its exit-code propagation fix.
- Final aggregate after the adversary/remediation convergence and final
  ActiveStore hardening: `pytest -q` passed **1077 tests / 3 intentional
  platform skips / 0 failures** in 75.71 seconds. The final focused
  host-adaptation/UI/performance set passed **20/20**.
- Ruff on the adaptation service/workbench, dashboard/header integration, and
  focused tests: pass. `git diff --check`: pass.

One ad-hoc module report initially hit a Windows CP1252 `UnicodeEncodeError`
while printing an arrow glyph after discovery had already completed. This was
a runner-console encoding artifact, not a product import or module failure;
the UTF-8-configured project harness subsequently completed cleanly.

## Bugs found and fixed

### R8-BT-01 — context re-entry was incorrectly de-duplicated

**Component:** `angerona.core.host_adaptation.HostAdaptationService`.

**Symptom:** a proposal-only SSID rule produced the sequence `proposed`,
`no-match`, `stable` when the host moved from the matched SSID to an unmatched
SSID and then returned. The return is a real context transition and should
produce a new proposal.

**Root cause:** the no-match path retained `last_trigger_signature`, so the
later matching context was mistaken for an unchanged continuous context.

**FIXED:** clear only the proposal de-duplication signature on a no-match
transition. The separate last-applied signature remains intact, preventing
automation from repeatedly fighting operator changes by reapplying an already
applied posture. Regression:
`test_context_transition_can_propose_again_after_no_match`.

Gate: dedicated adaptation tests **9/9**, full aggregate **1066 passed / 3
skipped**, compile **304/304**.

### R8-BT-02 — simultaneous Public network could be hidden

**Component:** Windows context collection in `host_adaptation.capture_context`.

**Symptom:** the PowerShell collector selected the first active connection
profile. With simultaneous Private/VPN and Public attachments, enumeration
order could classify the whole context as Private and suppress a configured
Public-network trigger.

**Root cause:** `Select-Object -First 1` discarded the remaining active network
categories.

**FIXED:** collect every active category and choose the conservative precedence
`Public`, then `Private`, then `DomainAuthenticated`. Regression:
`test_context_marks_any_active_public_network_as_public`.

Gate: dedicated adaptation tests **9/9**, full aggregate **1066 passed / 3
skipped**, Ruff and compile pass.

### R8-BT-03 — batch self-check hid Python failures from callers

**Component:** `run-selfcheck.bat`.

**Symptom:** the wrapper wrote Python's status into its report and then ended on
a successful `echo`, so automation invoking the batch file could receive exit
code zero even when `tools/selfcheck.py` failed.

**Root cause:** `%errorlevel%` was not captured and returned immediately after
the Python process.

**FIXED:** capture the Python result in `ANGERONA_SELFCHECK_EXIT`, write that
exact result to the report, and `exit /b` with it.

Gate: the real batch wrapper completed **26/26** and returned exit code zero;
its report records the same zero result.

## Reported / external gates

- **REPORTED — live privileged mutation acceptance:** QA exercised immutable
  plans, command preview, no-write sandbox behavior, approval/plan binding,
  stale-state checks, injected executor/snapshot paths, circuit breaking, and
  UI lifecycle. It deliberately did not apply or import a real Windows Firewall
  policy. Elevated physical-host apply, connectivity validation, automatic
  failure rollback, and one-click restore remain a controlled operator
  acceptance test.
- **REPORTED — physical context acceptance:** mixed active Windows Public and
  Private categories are regression-tested with bounded collector output.
  Reproducing the topology with real Wi-Fi/VPN adapters remains an external
  hardware/network gate.
- The 12 stopped/idle/Ollama module runner results and 8 structured skips are
  expected for the non-elevated headless configuration; the official harness
  classified them without masking any unexpected failure.

## Final summary

- Files compiled: **304**.
- Core self-tests: **19 passed / 0 failed**.
- Module runner: **47 passed / 0 unexpected failed / 20 expected non-pass**
  (**12** expected state failures + **8** skips).
- Selfcheck: **26 passed / 0 failed** (direct and batch wrapper).
- Full pytest: **1077 passed / 3 skipped / 0 failed**.
- Bugs fixed: **3**. Reported external acceptance gates: **2**.
