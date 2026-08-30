# Cycle 26 round 3 terminal bug-test results

Date: 2026-08-28
Scope: cumulative post-remediation QA; inert fixtures only; no publication,
network write, privileged host mutation, or live security-control change

## Verdict

The terminal snapshot compiles and imports, discovers all **81** Windows
capabilities, has unique capability identities and module codes, and passes the
focused response, authentication, source-authority, Scan Center, module-health,
and release regressions except for one newly isolated publication-runtime
boundary defect. Three clearly safe integration/self-test bugs were fixed
behind direct gates.

Cycle 26 is **not yet terminal green**. The focused suite reports three failed
test nodes with one common cause: the pinned publisher runtime rejects the
standard reviewed Git-for-Windows hard-link topology that its own profile
describes. This is tracked separately as **C26-R3-C13** and is owned by release
remediation. The full suite was not started on this snapshot: the focused run
alone required 601 seconds under host antivirus I/O pressure, the publisher
boundary was already known red, and repeating a non-authoritative full run
would not close C13.

## Gates run

- Whole product compile: **350/350** Python files under `src/angerona/` passed.
  The first AV-backed bytecode-write pass returned transient `PermissionError`
  for `privilege.py`, `sgx_guard.py`, and `source_sandbox.py`; fresh byte reads
  compiled all three with Python's built-in compiler, then individual
  `python -m py_compile` retries passed. These were host filter artifacts, not
  syntax defects.
- Module import/discovery: **83/83** `angerona.modules` files imported;
  **65/65** zero-argument compatibility `register()` hooks constructed; the
  established **18** class-discovery/helper files without a hook remained
  valid. Static discovery produced **81/81** `BaseModule` capabilities,
  **81/81** unique capability IDs, zero discovery errors, and zero duplicates
  among **62** declared `CODE` values.
- Isolated package-level self-tests: after the fixes and bounded retries,
  **37/37 passed**, zero functional failures. This includes every module-level
  zero-argument `self_test()` discovered under the package, including the five
  child-isolated resilience targets.
- Exact headless capability/selfcheck run before the YARA fix: discovery
  **81**, runner **64 passed, 1 timed out, 17 expected skips** (the count
  includes the event-pipeline pass), then **25/26** integration phases passed.
  The sole failed phase was the runner's YARA timeout; all GUI construction,
  module inspector, click/detail, remediation, red-team, and performance smoke
  phases passed.
- Exact warmed selfcheck capability rerun after the YARA fix: discovery **81**,
  runner **63 passed, 2 timed out, 17 expected skips**. The timeouts were YARA
  and Posture Hardening while six module workers competed through the same host
  AV filter. Posture Hardening had passed the first exact run, and the corrected
  YARA test passed directly in **4.1 seconds**. The redundant rerun was stopped
  after the authoritative capability phase because the first exact run already
  proved the remaining 25 phases. No timeout or exception was converted to an
  expected skip.
- Focused cumulative Cycle 26 gate: **249 passed, 5 expected platform/link
  capability skips, 3 failed** in **601.41 seconds** across response custody and
  receipt authority, typed remediation, authentication extension enrollment,
  runtime isolation, release signing/profile/snapshot, source authority,
  module-health evidence, Scan Center, and the v12 capability contracts. All
  three failures have the single C13 cause described below.
- Quality/hygiene: Ruff passed all **52** changed/untracked Python files; **44**
  repository JSON documents parsed; `git diff --check` exited 0 (only
  informational LF/CRLF notices); the final helper-process inventory found
  **0** selfcheck/scanner/resilience/watchdog survivors.
- `run-selfcheck.bat` logic was inspected: it selects the repository venv,
  forces offscreen Qt, uses UTF-8/unbuffered Python, captures the report, and
  propagates the exact exit code. The direct invocation exercised the same
  Python entry point without rewriting the shared wrapper report.

## Bugs

### QA-C26-R3-03 — stale 80-capability integration contract

- **Severity/status:** LOW — **FIXED**.
- **Component:** `tests/test_v12_capability_contracts.py`; current capability
  inventory/status text in `README.md`.
- **Symptom/root cause:** Authentication Extension Integrity Guard added the
  81st capability, while one exact-count assertion and the current README
  markers still required 80. Historical Cycle 25/loop evidence was preserved.
- **Fix/gate:** current assertions and status markers now require/report 81.
  Isolated discovery proved 81 unique capabilities with zero errors, and the
  updated contract test passed inside the focused gate.

### QA-C26-R3-04 — manager self-test manufactured SAFE_MODE

- **Severity/status:** LOW — **FIXED** behind the self-test gate.
- **Component:** `src/angerona/resilience/manager.py::_isolated_self_test`.
- **Symptom:** repeated inert runs reported a live, ingesting scanner with no
  duplicate, but failed respawn; added bounded diagnostics showed
  `restarts=1`, `state=dead`, and `safe_mode=True`.
- **Root cause:** the self-test called `ProcessSupervisor.tick()` from its own
  thread while the real supervisor thread was already ticking. During the
  intentionally bounded cross-process spawn claim/backoff window, the duplicate
  ticks spent the failure budget twice as fast and manufactured SAFE_MODE.
- **Fix:** the test now observes the actual supervisor lifecycle without
  injecting extra ticks, uses bounded 15-second readiness and 12-second respawn
  observation windows, and retains a 45-second child-custody deadline. Product
  supervisor behavior is unchanged.
- **Closure gate:** affected compile passed; direct isolated self-test passed in
  **15.98 seconds** with three frames, no duplicate adoption, and exactly one
  respawn. Final package-level accounting is 37/37 passed.

### QA-C26-R3-05 — disk EICAR fixture caused false YARA timeout

- **Severity/status:** LOW — **FIXED** behind direct compile/self-test gates.
- **Component:** `src/angerona/modules/yara_scanner.py::self_test`.
- **Symptom/root cause:** the benign readiness probe wrote an EICAR-named marker
  into a temporary file. The host AV intercepted that fixture, making a correct
  in-process yara-x result intermittently exceed the 12-second concurrent
  harness deadline.
- **Fix:** the same inert marker is compiled and scanned as in-memory bytes.
  Production file scanning is unchanged and remains covered by Scan Center
  regressions.
- **Closure gate:** affected compile passed; direct YARA self-test passed in
  **4.1 seconds**. In-memory compile/scan itself measured about 0.011 seconds and
  bundled-rule compilation about 0.025 seconds. The exact six-worker selfcheck
  remains subject to the separately recorded host-contention limitation and was
  not represented as a clean run.

### QA-C26-R3-06 / C26-R3-C13 — pinned Git runtime rejects reviewed hard links

- **Severity/status:** publication blocker — **REPORTED / ASSIGNED TO RELEASE
  REMEDIATION**; not fixed by bug testing.
- **Component:** `tools/windows_publication_runtime.py::stage_pinned_runtime`,
  `tools/publication_git_runtime_profile.json`.
- **Exact failed nodes:**
  1. `tests/test_cycle26_publication_snapshot.py::test_asset_verifier_uses_captured_commit_not_mutable_worktree`
  2. `tests/test_cycle26_publication_snapshot.py::test_git_boundary_uses_absolute_git_literal_argv_and_fresh_environment`
  3. `tests/test_cycle26_publication_snapshot.py::test_local_url_rewrite_is_rejected_even_when_origin_remains_canonical`
- **Evidence:** profile and live `D:\Git\cmd\git-lfs.exe` both have size
  **46,920** and SHA-256
  `c470d205517c7a53ceca321df16a6e4549fcd52b576ab4d09536d36f26fda5a9`.
  `fsutil hardlink list` proves it aliases `\Git\cmd\git.exe`. The staging
  boundary nevertheless rejects any source with `links != 1`, so it cannot
  stage the exact standard tree represented by its own reviewed profile. All
  three tests fail before their intended assertions with `publication runtime
  source identity changed: cmd/git-lfs.exe`.
- **Why reported:** safe treatment of a reviewed hard-link topology changes the
  publisher trust boundary. Refreshing or weakening that anchor is not an
  obvious bug-test fix and requires the assigned release-authority design and
  regression review.

## Accounting and handoff

- Clearly safe bug groups fixed by terminal bug testing: **3**.
- Design/security defects reported for remediation: **1** (C13).
- Product failures silently converted to skips: **0**.
- Files compiled: **350**.
- Package-level self-tests: **37 passed, 0 failed** after fixes/retries.
- Exact selfcheck result retained: **25 passed, 1 failed phase** on the first
  complete run; its only module result was a timeout. Distinct pass evidence
  exists for every testable capability across the exact/direct runs, but no
  single all-green capability run is claimed.
- Full-suite status: **not run on this known-red, AV-constrained snapshot**;
  required after C13 remediation (and again at Cycle 30 final closure).
