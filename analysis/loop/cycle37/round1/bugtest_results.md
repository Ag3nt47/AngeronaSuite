# Cycle 37 / Round 1 — Bug Test Results

Date: 2026-09-30. Scope: package syntax and import/discovery checks, all
built-in module and standalone core self-tests, the project headless selfcheck,
focused Combat/GUI Red Team tests, and adversarial Shark artifact tests. This
is offline evidence over the shared worktree; it is not a release gate or a
public-main verification.

## Results

- Full package compile: **404/404** Python files parsed after the current
  shared-worktree additions; no syntax error or stale/truncated read was found.
- Structural module check: **86/86** `angerona.modules.*` files imported;
  **68/68** zero-argument `register()` hooks constructed `BaseModule` objects.
  The other 18 files have no legacy hook; discovery uses `BaseModule` subclasses
  and helper files directly. **66/66** declared `CODE` values were unique.
  `ModuleManager.discover()` produced **84** capabilities with **zero**
  discovery errors or duplicate capability IDs.
- Standalone top-level core self-tests: **24 passed / 0 failed**, each in a
  separate process with a 30-second cap. This includes CVE ignore/advice,
  alert acknowledgement, incident timeline, purple loop, report attestation,
  and trusted time.
- The first direct project selfcheck, before the Shark fix and before the
  deliberate 66-worker load, passed **26/26** phases. Its module phase passed
  **67 / 0**, with **18** explicit inactive/platform skips. `run-selfcheck.bat`
  invokes this same Python harness, sets offscreen Qt, and records its exit in
  `selfcheck_report.txt`; the batch wrapper itself was inspected, not executed.
  After the 66-worker soak ended, a fresh isolated selfcheck again passed
  **26/26** phases with **67 / 0 / 18** module pass/fail/skip counts.
- The focused Combat/readiness UI and journal set passed **85/85**. The actual
  two-launch offscreen MainWindow Arm/Launch test passed **2/2** in 164.30 s:
  both 38-step runs produced 37/37 signed verified containment responses, and
  the separate-process OS witness and negative control passed. Native analytic
  detections were **0/37** in this specific fixture because it does not enable
  FIM. The final response in the two runs took about **47 s** and **54 s**;
  that long tail remains a latency concern even though containment verified.
- Shark artifact regressions initially failed **5/5**, demonstrating actual
  overwrite, hardlink overwrite, replacement-path deletion, unowned stale-file
  deletion, and unbounded marker read behavior. After the fix, the Shark safety
  module passed **12/12**, with two POSIX-only regressions skipped on Windows,
  including the bounded-survey and moved-marker provenance assertions. The
  broader Shark/native-AAR/cancel/import set passed **39/39** before the final
  portability/provenance hardening edit. Ruff and `git diff --check` passed
  after the final source edit.

## Bugs fixed

### C37-R1-BT-01 — Fixed-name BYOVD marker overwrote an operator file

- Component: `src/angerona/shark/shark_attack.py`.
- Reproduction: place an ordinary file or a hardlink at
  `angerona_byovd_drill.sys`, then call `_step_simulated_byovd()`. The old
  `Path.write_text()` truncated the preexisting object, including its other
  hardlink name. **FIXED**: all Shark marker/ZIP writes now use exclusive
  no-follow creation, require a regular single-link file, write through the
  held descriptor, and record that exact identity only after successful
  creation. A name collision becomes a failed drill step; the existing file
  stays intact. The established BYOVD filename and benign marker text remain
  recognizable by `intel_sync`.
- Gate: ordinary-file and hardlink adversarial cases passed; successful BYOVD,
  Initial Access text/ZIP, and double-persistence creation/cleanup passed.

### C37-R1-BT-02 — Stop cleanup deleted a replacement at an old artifact name

- Component: `SharkAttackEngine.stop_and_clean()`.
- Reproduction: create a Shark marker, rename it away, put unrelated bytes at
  the recorded pathname, and stop the engine. The old cleanup deleted the
  replacement. **FIXED**: cleanup accepts only identities captured by this
  run's exclusive creation. Windows opens a no-follow DELETE-capable handle,
  rechecks the file ID and single-link state, and sets disposition on that
  held object. A failed identity check has no pathname-unlink fallback. POSIX
  leaves an artifact for operator review because its portable rename/unlink
  operations cannot atomically bind the pathname to the checked file ID.
- Gate: replacement-path preservation and normal exact-owned cleanup passed.

### C37-R1-BT-03 — Old-marker sweep was unbounded and deletion was heuristic

- Component: `_file_has_marker()` / `_cleanup_stale_artifacts()`.
- Reproduction: an old file with the BYOVD marker substring and matching
  filename was deleted without run ownership; a marker beyond 1 MiB was read
  in full. The previous two-file deletion cap did not bound glob enumeration
  or content reads. **FIXED**: survey visits at most 64 directory entries per
  selected directory, checks at most two matches, bounds plain reads to 4 KiB
  and ZIP/input sizes to 1 MiB, and leaves old-run files for operator review.
  Name/content matches no longer authorize automatic deletion after a restart.
- Gate: old lookalike preservation, oversize refusal, and the explicit
  entry-count cap passed.

### C37-R1-BT-04 — Noise scratch could overwrite and delete a prior directory

- Component: `many_small_files` Shark Noise Injection variant.
- Reproduction: a preexisting random-name scratch directory containing
  `chunk_0.tmp` would be reused with `exist_ok=True`; the step wrote over that
  file and later glob-deleted all matching files. **FIXED**: the scratch name
  uses a full UUID, directory creation is exclusive, each chunk is created
  with the same exact-file helper, and immediate cleanup visits only identities
  created by this run. A foreign or replaced file is retained.
- Gate: adversarial preexisting-scratch preservation and normal 200-chunk
  cleanup both passed on Windows. POSIX switches this variant to the CPU-only
  noise test because exact-object deletion of 200 scratch files is unavailable.

### C37-R1-BT-05 — A moved drill marker left stale trusted provenance

- Component: `SharkAttackEngine._create_artifact()` and the memory-only
  practice-scope registry.
- Reproduction: move a newly created marker out of its pathname while Shark
  still holds its write descriptor, then create unrelated bytes at that old
  pathname. The prior successful-write branch returned without cleanup custody
  but left the old path registered as a practice artifact. **FIXED**: this
  branch revokes that path's run-bound registration before returning.
- Gate: the moved-marker/reused-name regression passed and showed no practice
  provenance for the unrelated replacement.

## Reported load-dependent failures

The headless selfcheck was not reliably green under concurrent load. During the
66-worker mode soak, one rerun reported **25 passed / 1 failed** because its
two-phase Red Team drill exceeded the existing 30-second deadline. A captured
repeat reported **23 passed / 3 failed**: Posture Hardening self-test exceeded
12 seconds, the Alerts dialog did not render its seeded history rows, and the
live drill again exceeded 30 seconds. A subsequent run after the soak ended
overlapped a separate GUI history test; it ended **25 passed / 1 failed**:
AI Triage and YARA each exceeded the module runner's 12-second limit, while
the live Red Team phase passed. These are real failed checks, not skips or
syntax/mount artifacts. The concurrent-load failures show user-visible drill
latency; the specific cause of each timeout is not yet isolated. The clean
post-soak selfcheck passed. No deadline,
assertion, security check, or module self-test was relaxed.

The timing probe was stopped at the release coordinator's request to keep the
remaining 66-worker soak attributable. Its partial trace had phase 1 starting
at 4.42 s and phase 2 at 19.44 s, with repeated marker stages around
0.4–1.2 s, tagged-process work around 3.4 s, and one 5.4-second gap. It did
not prove a single deadlock. A clean exclusive timing run remains needed before
changing Red Team security-sensitive custody checks.

## Commands and limits

### Coordinator follow-up after the interrupted provenance edit

The partially completed provenance edit initially failed marker creation on
Windows and left old path-only fixture assumptions incompatible with the new
observed-object contract. The coordinator finished the hash-through-held-handle
path, detector-observed file ID/content digest propagation, and temporal
replacement regressions. The focused provenance/Shark/producer/YARA set passed
57 tests / 3 platform skips. FIM read-sharing, bounded churn retry, cancellation,
baseline, and exact native-receipt gates passed 22/22. Its receipt schema and
complete-coverage requirement were retained.

The completed-patch FIM-enabled GUI probe passed two tests in 124.69 seconds:
two launches each completed 38/38 steps and 37/37 signed verified containment,
with native observations of 34/37 and 11/37. The separate OS witness verified
all 36 source removals and quarantine hashes plus three birth-bound process
exits in each run. Run durations were 59.547 and 57.906 seconds. Earlier
FIM-enabled attempts failed with zero native observations, and the trace found
incomplete metadata reads during concurrent response/file churn. Those failed
attempts remain failures; the targeted read-sharing/retry change does not
guarantee complete native coverage or resolve response latency under load.

- `venv\Scripts\python.exe -u tools\compile_check.py`
- Isolated Python AST/import/registration/discovery checks and 24 core
  self-tests (30-second per-test cap).
- `PYTHONPATH=src; venv\Scripts\python.exe -u -X utf8 tools\selfcheck.py`
- `PYTHONPATH=src; QT_QPA_PLATFORM=offscreen; venv\Scripts\python.exe
  -u -X utf8 -m pytest -q -s tests\test_cycle35_redteam_gui_live.py`
- Focused Combat/readiness test set, Shark enterprise/native-AAR/cancellation
  and safety test set, Ruff, and `git diff --check`.

This run did not test live privileged remediation, a production FIM-enabled
native detection rate, or long-duration physical-display responsiveness. No
commit or GitHub publication was made by the bug-test agent.
