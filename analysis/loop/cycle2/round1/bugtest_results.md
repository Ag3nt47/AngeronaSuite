# Cycle 2 / Round 1 — Bug Test / QA Results

Date: 2026-07-14. Environment: supported Windows virtual environment with
`PYTHONPATH=src`; Qt ran offscreen. Scope: independent verification of the
current shared tree after the C2-R1-01 through C2-R1-05 remediations. Concurrent
Claude/agent work was preserved. `rules/_active_combined.yar`, secrets, host
state, and unrelated files were not changed.

## 1. Compile and tree-integrity gates

- Final `tools/compile_check.py`: **194/194 Python files passed**, 0 failed.
- The two QA-runner edits also passed direct `py_compile` before their affected
  suites were rerun.
- `git diff --check`: PASS; output contained only existing Windows line-ending
  notices.
- Conflict-marker scan across source, tools, and tests: PASS.

## 2. Import, discovery, and module identity

- `angerona.modules.*`: **62/62 module files imported**, 0 import failures.
- `BaseModule` classes instantiated: **61/61**, 0 constructor failures.
- `ModuleManager.discover()`: **61 modules discovered**, 0 discovery errors.
- Duplicate non-empty module `CODE` values: **none**.
- Duplicate module names: **none**.

## 3. Focused Cycle 2 regressions

Focused result: **7 passed, 0 failed**.

- `tests/test_cycle2_round1_remediation.py`: **3/3 passed**. It rejected fuzzy
  basename/bare-PID AAR evidence, enforced bounded step/trigger correlation,
  and proved an INFO flood cannot evict protected critical evidence while the
  ledger remains hard-bounded.
- `tests/test_policy_and_drill_resolution.py`: **4/4 passed**. It proved exact
  path trust, path-rich name-collision rejection, historical/run-scoped drill
  resolution, deterministic posture remediation, runtime FIM targets, and
  token-bound process correlation.
- Static shutdown review: PASS. `kill-all-angerona.bat` filters Python
  processes to the canonical Angerona root, requests graceful llama3 unload,
  and contains no image-wide Python or Ollama runner kill.
- ARIA disabled-state enforcement is present at invocation, confirmation, and
  proactive-trigger boundaries; its standalone assistant self-test passed.

## 4. ARIA self-tests

Final `run_aria_selftests.py` result: **12 passed, 0 failed**.

The first run completed three passing checks, then the runner—not an ARIA
module—raised `UnicodeEncodeError` while printing a Unicode trend arrow through
a legacy Windows CP1252 console. The standalone runner now configures UTF-8
stdout/stderr, matching the main self-check. Its full rerun passed Perf
Governor, Assistant, Runbook RAG, Posture History, Routines, Dispatch, HUD,
Voice, Channel Push, Inbox Triage, Research, and Research Fetchers.

## 5. Full project self-check

`tools/selfcheck.py` was run twice and passed both times. Final result:
**26 phases passed, 0 failed**, exit code 0.

- Discovered and constructed all 61 modules and the complete dashboard/dialog
  surface.
- Raw module drill: **47 PASS, 15 expected skips, 0 genuine failures**.
- The 15 raw failures are documented safe harness states: optional Ollama
  timed out; live sensors intentionally left stopped reported `status=stopped`;
  Active Response SOAR was safely unarmed/idle.
- The live benign Red Team drill completed **30 steps over 2 phases** and
  cleaned its inert custom marker.
- Judgment/tamper gates, vetted remediation, persistence classification,
  incident correlation, world view, YARA/EICAR, WAL retention, and audit-cache
  speed checks passed.

The headless harness deliberately does not enter Qt's event loop. Its first run
therefore caused the production UI watchdog to append a false freeze record
during a slow PySide import. The harness now stops that watchdog immediately
after constructing `MainWindow`; production watchdog behavior is unchanged.
The second full run passed and left `diagnostics/not_responding.log` unchanged
at its earlier 19:36:56 timestamp.

## 6. Crash and diagnostic classification

- `diagnostics/selftest_failures.json`: **0 failed**, empty failure list.
- `diagnostics/crash.log`: no unhandled exception has been recorded since
  2026-07-12. Later entries are startup/writeability markers and historical
  thread snapshots, not a new crash from this validation.
- Judgment Gate `blocked_tamper` remediation records are intentional self-check
  probes proving altered scripts are refused.
- The latest prior UI-watchdog record was the headless-harness artifact
  described above; the fixed rerun generated no new record.

## Bugs

### Fixed — QA harness only

1. **ARIA runner CP1252 crash:** configured UTF-8 output so valid Unicode test
   details cannot abort an otherwise passing Windows run.
2. **False self-check freeze report:** stopped the real UI watchdog after the
   headless harness constructs `MainWindow`, preventing test-only diagnostic
   noise and log growth.

### Production result / remaining issues

- **No new production defect was found.** All five Round 1 remediations passed
  independent focused, static, ARIA, and full-application gates.
- The 15 raw module skips remain expected in a safe headless run and are not
  product failures. Previously documented deferred architecture hardening is
  unchanged.

## Final gate summary

- Compile: **194/194**.
- Imports/discovery: **62/62 imports; 61/61 modules; 0 errors; 0 duplicates**.
- Focused remediation/policy/drill tests: **7/7**.
- ARIA self-tests: **12/12**.
- Project self-check: **26/26**; module drill **47 pass, 15 expected skips,
  0 genuine failures**.
- Bugs fixed: **2 QA-harness issues**. New production bugs: **0**.

