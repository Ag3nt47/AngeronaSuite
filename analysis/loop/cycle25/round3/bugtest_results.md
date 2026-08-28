# Cycle 25 / Round 3 — Final Bug Test Results

Date: 2026-08-28
Scope: independent final v1.12 QA gate over the shared worktree. The gate
covered package syntax, every built-in capability self-test, standalone core
self-tests, import/discovery/registration identity, the project headless
selfcheck, its supported batch launcher, and the complete serial pytest suite.

## Result

- Product compile: **346/346 Python files valid** under `src/angerona/`, with
  no stale-read or output-lock artifact in either complete compile pass.
- Structural module gate: **82/82** `angerona.modules.*` files imported;
  **64/64** zero-argument compatibility `register()` hooks constructed a
  `BaseModule`; discovery produced **80 modules** with **0 import/discovery
  errors**, duplicate names, or duplicate capability IDs. All **61 declared
  module `CODE`s were unique**.
- Registration compatibility: 16 class-discovered capability files do not
  expose the optional legacy `register()` hook. This is valid under the
  manager's documented subclass-discovery contract, and all 16 were imported,
  instantiated, contracted, and self-tested successfully or explicitly
  classified by the harness.
- Exhaustive targeted module harness: **69 passed / 0 failed / 12 expected
  skips**, including the EventBus pipeline. Excluding the pipeline, 68 module
  self-tests passed. The skips were nine deliberately unstarted/optional
  states and three unavailable platform states (Linux or macOS); no timeout or
  exception was accepted as a skip.
- Standalone core self-tests: **24 passed / 0 failed** in isolated processes
  with a 30-second per-test timeout.
- Project selfcheck after the safe harness correction: **26 passed / 0
  failed**. Its internal module phase passed **64 / 0** with **17 expected
  inactive/platform skips**. The exact `run-selfcheck.bat` entry path also
  returned exit code **0** and reported **26 / 0**.
- Complete serial pytest gate: **1,808 passed / 6 expected skips / 0 failed**
  in 585.40 seconds. The six skips were explicit host-capability boundaries:
  five unavailable symlink/directory-link operations for the current account
  and the Windows exclusion of a POSIX permission-bit assertion.
- Final Ruff gate passed for `src`, `tools`, and `tests`; `git diff --check`
  found no whitespace errors.

## Bugs

### C25-R3-BT-01 — Selfcheck required an intentionally removed automatic ACL action

- Component: `tools/selfcheck.py`
- Symptom: the `Vetted active remediation` selfcheck crashed with
  `AttributeError: 'NoneType' object has no attribute 'key'` while asserting
  that an ambiguous directory finding selected `lockdown_acl`. Initial
  selfcheck result: **25 passed / 1 failed**.
- Root cause: v1.12 deliberately removed `LockdownAclAction` from the
  production `ACTIONS` registry until exact, locale-independent verification
  and rollback of DACL, owner, and inheritance are available. The harness
  retained the obsolete pre-remediation expectation.
- Status: **FIXED**.
- Fix: the selfcheck now requires `select_action(dirw) is None`, explicitly
  proving that ambiguous directory ACL changes remain proposal-only/manual
  review. Production selection and enforcement code was not changed.
- Gate: `tests/test_v12_remediation_safety.py` passed **5/5**; the modified
  harness compiled and passed Ruff; direct selfcheck passed **26/26**; the
  exact batch launcher passed **26/26** with exit code 0; the complete serial
  suite passed **1,808 tests** with no failures.

## Non-defect observations

### One transient concurrent YARA timeout

The first exhaustive targeted module run reported one YARA timeout after 20
seconds while multiple test processes were sharing the host. The exact YARA
self-test then passed five isolated runs effectively immediately, and the full
80-module targeted rerun passed it within a **69/0/12** result. Both direct and
batch selfcheck runs also passed YARA. This matches the already-recorded Round
2 host-contention observation and is not reproducible as a product defect. No
timeout, assertion, scanner bound, or test was weakened.

### Explicit environment limits

This was an offline, non-elevated QA run. It does not prove live Ollama model
availability, Linux/macOS sensors on their native hosts, optional kernel/ETW
driver deployment, signed watchdog/native syscall binaries, or real privileged
host remediation. Those capabilities reported their existing truthful
unavailable/fallback/idle states. The five link-backed pytest cases also remain
skipped because this Windows account cannot create the required links; they
were not converted to passes.

## Commands

- `$env:PYTHONPATH='src'; venv\Scripts\python.exe -u -X utf8 tools\compile_check.py`
- Isolated structural Python gate importing all `angerona.modules.*`, invoking
  every zero-argument `register()`, and validating discovery names, capability
  IDs, and declared `CODE`s.
- Targeted `SelfTestRunner.run(names=list(manager.modules), timeout=20.0, ...)`
  with the narrow `tools/selfcheck_policy.py` inactive-prerequisite policy.
- Isolated 30-second subprocess execution of every module-level
  `angerona.core.*.self_test()` discovered by AST.
- `venv\Scripts\python.exe -u -X utf8 tools\selfcheck.py`
- `.\run-selfcheck.bat`
- `venv\Scripts\python.exe -m pytest -q tests\test_v12_remediation_safety.py`
- `venv\Scripts\python.exe -u -X utf8 -m pytest -q`
- `venv\Scripts\python.exe -m ruff check src tools tests`
- `git diff --check`

## Files changed by final bug testing

- `tools/selfcheck.py`
- `analysis/loop/cycle25/round3/bugtest_results.md`
- `analysis/loop/LOOP_LOG.md`

No commit or publication was performed by this QA agent.
