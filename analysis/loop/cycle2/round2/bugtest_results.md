# Cycle 2 / Round 2 — Bug Test / QA Results

Date: 2026-07-14. Environment: supported Windows virtual environment with
`PYTHONPATH=src`; Qt ran offscreen. Scope: independent verification of the
current combined tree after the Cycle 2 Round 2 remediations. Concurrent edits
were preserved. No visible GUI was launched, no host process was stopped, and
`rules/_active_combined.yar` was not modified.

## Compile and tree-integrity gates

- Full `src`, `tools`, `tests`, and root-runner compile: **201/201 Python files
  passed**, 0 failed.
- Conflict-marker scan across source, tools, and tests: **0 found**.
- `git diff --check`: PASS; output contained only Windows line-ending notices.

## Module imports, construction, and discovery

- `angerona.modules.*`: **62/62 module files imported**, 0 failures.
- `BaseModule` classes: **61/61 instantiated**, 0 constructor failures.
- `ModuleManager.discover()`: **61 modules discovered**, 0 discovery errors.
- Duplicate non-empty module `CODE` values: **0**.
- Duplicate module names: **0**.

## Focused Cycle 2 regressions

`pytest` is not installed in the supported environment, so the repository's
direct unittest/routine entry points were used; no dependency was installed.
Final result: **15/15 passed**, 0 failed.

- Round 1 AAR correlation and severity-aware retention: **3/3**.
- Trusted-process, run-scoped drill resolution, runtime FIM target, and token-
  bound process correlation: **4/4**.
- Round 2 drill cancellation, ARIA action binding, confirmed research egress,
  and shutdown ownership predicate: **4/4**.
- First-cycle lifecycle, sequential Eco wake-up, D-drive runtime default, and
  model-specific Ollama unload: **4/4**.

The drill-cancellation regression stopped both engines during their five-second
jitter in under one second, observed no later completion callback or artifact,
and confirmed that the worker threads exited.

## ARIA and research self-tests

`run_aria_selftests.py`: **12/12 passed**, 0 failed. This includes the
versioned/immutable confirmation gate and the revised research contract:
`research` stays local, while opening vetted browser sources is a separate
confirmed action.

## Full application self-check

`tools/selfcheck.py`: **26 phases passed, 0 failed**, exit code 0.

- Discovered all 61 modules and constructed the complete dashboard/dialog
  surface offscreen.
- Raw module drill: **47 pass, 15 expected skips, 0 genuine failures**. The
  skips are documented stopped/idle/optional-Ollama harness states.
- The benign live Red Team drill completed **30 steps over 2 phases** and
  cleaned its inert custom marker.
- Judgment/tamper, vetted remediation, persistence, coverage, incident,
  world-view, YARA/EICAR, WAL/retention, and audit-cache gates passed.

## D-drive storage verification

The final run asserted the canonical paths after the production environment
setup:

- Project: `<install-folder>`
- Persistent data: `<install-folder>\runtime-data`
- `TEMP`/`TMP` and `tempfile.gettempdir()`:
  `<install-folder>\runtime-data\tmp`

The self-check's current tamper-test artifacts in
`diagnostics/remediation_attempts.log` are consequently D-resident. Older
C-profile entries predate the current path gate or came from isolated temporary
test fixtures; they are historical log records, not current production paths.

## Crash and watchdog review

- `diagnostics/selftest_failures.json`: generated at 20:43:57 with **0
  failures**.
- `diagnostics/crash.log`: unchanged since 15:58:55; no new unhandled crash was
  produced by these gates. Its tail contains historical startup/thread
  snapshots, including optional Ollama, AMSI, and Scapy waits.
- `diagnostics/not_responding.log`: unchanged since 19:36:56. The current full
  self-check produced no false watchdog record.
- The new `blocked_tamper` remediation entries are intentional Judgment Gate
  probes proving that altered scripts are refused, not failures.

## Result and convergence

No new production defect was found and this phase made **no code changes**.
All four Round 2 remediations passed independent focused, module, ARIA, shutdown,
research, and full-application gates. Round 2 QA is converged; the overall
three-round loop still requires its planned Round 2 performance/visionary and
Round 3 gates.
