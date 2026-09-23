# Bug hunter — deep review pass 3, 2026-09-23

Status: COMPLETE. The final collection contains 3,991 tests. Across the original
full run and subsequent correction/integration gates, the latest result for
every collected case is **3,972 passed, 19 skipped, 0 unresolved failures**.
No test added during concurrent edits is left uncovered. This reconciled result
is not represented as a second all-green full-suite run. No production defect
was established by the full run; three stale test assumptions were corrected.

## Scope and isolation

Commands use `<review-worktree>` and the original checkout's existing venv,
with `PYTHONPATH` explicitly set to this worktree's `src`. Qt is offscreen;
runtime and fixture paths stay beneath `.tmp`. The ordinary pytest fixture and
offline harness prohibit native Ollama launch. The dedicated startup tests own
their inert process, listener and custody mocks. No production file is edited
by QA in this pass. No publication was attempted.

## Completed gates

- Final package compile: 388 files pass, no syntax errors and no mount artifacts
  (`compile-round3.json`), including the Windows token helper and setup helpers.
- Final supported `tools/selfcheck.py`: 26 phases pass, 0 fail. Module discovery finds
  all 84 capabilities. Module self-tests: 66 pass, 0 fail, 18 explicit skips;
  the separate pipeline test passes (harness summary: 67 pass/18 skip).
- Direct core `self_test()` batch: 24 pass, 0 fail
  (`core-selftests-round3.json`). Final AST inventory finds the same 24 direct
  core tests, with no newly added direct core self-test omitted.
- Refreshed exhaustive inventory has no broken discovery imports or duplicate
  declared CODEs. The existing 16 missing optional `register()` declarations
  and 18 absent explicit CODE declarations remain supported discovery cases.
  See `module-inventory-round3.json` and its readable Markdown companion. Module
  source hashes and details were refreshed against the final selfcheck; the
  later AI triage change is included in that final snapshot.
- Corrected publication-boundary test group: 58 pass in 37.75 seconds;
  targeted Ruff and whitespace checks pass.
- Full aggregate before fixture corrections: **3,884 passed, 19 skipped,
  3 failed in 1,205.62 seconds**. All three failures are detailed below. The
  preserved result and slowest test phases are in `pytest-full-round3.json`.
- Subsequent corrected deployment, Lab readiness retirement, Ollama startup,
  optional VMware setup/full setup and native installer gate: **96 passed,
  1 skipped in 16.97 seconds**.
- Corrected release/setup documentation group: **22 passed in 18.30 seconds**.
- Final combined startup/token custody, registered installation, transport,
  process attestation, VMware setup, Lab retirement, full setup, release docs,
  native installers, status UI and autonomous-response gate: **206 passed,
  1 skipped in 67.47 seconds**.
- Independent adversary's new Windows token boundary cases: **11 passed in
  5.22 seconds**. These simulate native APIs; no elevated native process launch
  is claimed as accepted by this test gate.
- Final collection reconciliation: **3,972 passed, 19 skipped**, zero uncovered
  cases and zero unresolved failures (`pytest-reconciled-round3.json`). Results
  use each run's start timestamp so a long original run cannot overwrite a
  corrected case merely because its JUnit file was written later.

## R3-QA-01 — workspace-contained fixture PATH assertion

Status: FIXED in test only. The full run exposed
`test_git_boundary_uses_absolute_git_literal_argv_and_fresh_environment`.
Its assertion rejected the workspace root as a substring anywhere in PATH.
The required disposable fixture directory is under the workspace's `.tmp`, so
the fully pinned runtime directories correctly contain that root as a parent.
The actual workspace root was not a PATH search entry.

The assertion now compares complete normalized PATH entries and still rejects
the workspace directory itself. All other custody, argv, environment and
credential-helper assertions remain intact. The entire 58-case publication
snapshot group passes with the correction. No production boundary was relaxed.

## R3-QA-02 — unowned-destination fixture reached the wrong guard

Status: FIXED in test only. `test_deploy_refuses_existing_unowned_destination`
passed the actual repository as its staging source, but its isolated destination
was inside the repository's `.tmp`. The deployment script correctly refused
overlapping paths before reaching the ownership-marker guard under test.

The case now creates inert sibling source/destination directories. It still
requires the exact ownership refusal, a failing process exit and untouched
sentinel content. All three deployment safety tests pass in the 96-case gate.
The separate overlap test remains unchanged.

## R3-QA-03 — README installation heading changed

Status: FIXED and gated. The README rewrite moved
installation guidance into `Choose your installation`; the old test split on
the removed `One-click Windows install` heading. The updated test targets the
new section and requires the specific versioned Windows MSIX, SHA-256 guidance,
publisher information and the no-Python/no-terminal packaged-install statement.
The documentation owner retained that statement with its trusted signed
release qualification. All 22 release/setup tests pass separately and again
inside the final combined integration batch. No installer behavior changed for
this test correction.

## Slow tests

The longest measured call phases were the 129th-binding refusal (37.19 seconds),
settings-tab sandbox opening (25.51 seconds), exporter backpressure drain
(16.75 seconds), partial-request/replay-ledger cleanup (12.57 seconds), and
publication snapshot revalidation (12.30 seconds). All five passed. The JSON
records the top 25 call phases. This is regression-test wall time with native
fixtures and concurrent review activity; it is not a measurement of the
installed application's idle overhead, nor enough evidence by itself for a
behavior-changing optimization.

## Aggregate closure and limits

The full suite retains its original captured outcome. Corrected failures and
subsequent narrow gates are reported separately rather than rewriting a failed
run as an all-green run. Every final collected test has a recorded passing or
skipped result. Parent-approved narrow reruns cover subsequent product edits.
The parent confirmed the independent adversary found no new issue before this
report was closed. QA made only the three test corrections described above;
all production edits and native acceptance decisions remain owner-controlled.

The tests establish inert policy, custody, lifecycle and integration behavior.
They do not establish native elevated Ollama creation, successful VMware guest
startup under the retained VMX seal, or native macOS/Linux GUI acceptance. Those
limits remain explicitly documented by the responsible agents and maintainer.
No commit or publication was made by QA.

Machine-specific paths are removed from the public inventory/report artifacts.
Private `.tmp` logs remain local evidence. Test durations describe QA
workloads, not the installed application's idle CPU or response latency.
