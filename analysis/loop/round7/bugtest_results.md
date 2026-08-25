# Round 7 — Bug Test / Release QA Results

> **Final status (2026-08-25):** the frozen v1.10.2 revalidation appended below
> is authoritative: 1,255 passed, 3 intentional skips, 0 failed. Earlier totals
> in this file are preserved as interim evidence only.

Date: 2026-08-22. Runner: Angerona bug-testing / QA agent. Environment:
Windows, `venv\Scripts\python.exe`, `PYTHONPATH=src`, Qt offscreen. The shared
dirty tree was treated as authoritative and concurrent work was not reverted.

## Gates executed

- Per-file `py_compile`: **297/297 package files passed**, zero syntax errors.
- Core import sweep: **125/125 core modules imported**, zero import errors.
- Callable module-level core self-tests: **18 passed / 0 failed**.
- `ModuleManager.discover()`: **66 modules**, zero discovery errors, **48**
  non-empty module codes, zero duplicate codes. Registration factories remain
  optional because discovery is class-based; every intended built-in was found.
- Module runner: **51 passed / 16 expected stopped, idle, optional-Ollama, or
  foreign-platform skips / 0 unexpected failures**.
- `tools/selfcheck.py`: **26 passed / 0 failed**.
- Authoritative aggregate after fixes: **997 passed / 3 intentional platform
  skips / 0 failed** in 107.06 seconds.
- Async Qt/Scan Center lifecycle focus: **28/28 passed**; an additional isolated
  close/delete stress ran **8/8 iterations** without a Python/Qt fault.
- Chill/performance focus: **45/45 passed**.
- Installer/startup/JARVIS/release focus: **53/53 passed** before the final
  launcher additions; final launcher/hash-lock focus: **18/18 passed**.
- Ruff: pass. Bandit Medium/High: zero findings (existing reviewed `nosec`
  warnings only). `pip-audit`: zero known dependency vulnerabilities.
- Tracked-tree privacy scan found no user profile, private key, GitHub token,
  AWS key, or tracked runtime database/log/key artifact. Two `sk-...` hits were
  substrings in the public NIST AI Risk Management Framework URL, not secrets.
- `start-angerona.bat --bootstrap-selftest`: pass. All **17** previously tracked
  PowerShell scripts plus the new repair script parsed with zero AST errors.

## Bugs fixed

### R7-BT-01 — HIGH — unsupported existing venv bypassed the Windows release gate

The source launcher previously treated existence of `venv\Scripts\python.exe`
as sufficient and jumped directly to launch. The current environment is
CPython **3.14.2** with PySide6 **6.11.1**, while the reviewed Windows dependency
lock and installer require CPython **3.12 x64**. Windows Error Reporting records
the real 16:45 dashboard failure in this 3.14 `pythonw.exe`, faulting in
`Qt6Core.dll` with `0xc0000409`.

**FIXED:** `start-angerona.bat` now verifies exact CPython 3.12/win-amd64 before
dependency preflight or launch and fails visibly without deleting the existing
environment. `Repair-Angerona-Python.bat` / `.ps1` provide an explicit one-click
repair: user types `REPAIR`; the script validates a fixed, non-reparse checkout
and exact repo-root venv; locates or installs Authenticode-valid PSF Python 3.12
through a Microsoft-signed winget; preserves the old venv; installs only the
SHA-256-locked wheel set; and rolls back on failure. It never changes checkout
ACLs, runtime data, or configuration. The cancellation path was executed and
left the existing venv untouched.

Gate: repair PowerShell parse pass; launcher/hash-lock tests **18/18 pass**;
hostile-environment bootstrap self-test pass.

### R7-BT-02 — setup omitted a supported privacy boundary

`Config.deception_user_folders` was operator-configurable in Settings but absent
from the Full Setup inventory, breaking the promise that setup maps every
supported end-user option.

**FIXED:** added an advanced opt-in checkbox with explicit data-boundary copy.
Gate: setup/transport/SOAR/atomic focused tests **22/22 pass**.

### R7-BT-03 — transport source gate mistook dictionary lookup for HTTP

The SOAR approval hardening used `_approved_requests.get(...)`; the deliberately
simple guard against unreviewed `requests.get(` calls matched that substring and
failed even though no network call existed.

**FIXED:** equivalent membership/index access avoids the ambiguous source token.
Gate: focused test above and final aggregate pass.

### R7-BT-04 — push helper could push an old commit after commit failure

The helper did not inspect `git add`/`git commit` status and interpolated the
operator's commit message into `cmd.exe` syntax.

**FIXED:** staging and commit failures now abort before push; empty staged sets
exit cleanly; commit text moves through an environment-backed UTF-8 file and
`git commit -F`, never command syntax. Gate: static release regression pass.

## Crash/log assessment

- The protected live `<repo-parent>\AngeronaData` store correctly denied this
  non-elevated QA process, so no claim is made about unreadable protected logs.
- Repository `shared_logs` entries are stale (newest 2026-07-19); repository
  diagnostics are UI/document artifacts, not current crash evidence.
- Windows Application log distinguishes the **production** 16:45 `pythonw.exe`
  Qt6Core fast-fail from later `python.exe` offscreen test-process faults at
  16:55–17:03. The new close/delete lifecycle stress produced no later fault.

## Reported / external gates

- The installed `AngeronaAutostart` task still points to the current repo venv as
  `pythonw.exe -m angerona`. This process lacks authority to rewrite the
  protected task. The environment must be repaired to reviewed 3.12 before the
  next autostart; elevated Angerona can then reconcile the task to `--chill`.
- `backup_to_F.bat` defaults to the intended F-drive folder and checks drive
  presence/health, but its maintenance-only arbitrary destination parameter is
  still a `/MIR` sharp edge. Final release automation should use only the
  validated default F destination and reject reparse/root targets.
- Physical sleep/resume, long elevated interactive soak, clean-machine Setup,
  native Linux/macOS artifact execution, publisher signing/notarization, and
  actual Defender/ETW/AMSI/WFP integration remain external acceptance gates.
- One initial aggregate recorded a transient atomic-I/O retry count mismatch.
  The test passed alone and the unchanged code passed the complete final
  aggregate; it is classified as non-reproduced suite interference, not a fixed
  product defect.

## Final summary

- Files compiled: **297**.
- Core self-tests: **18 passed / 0 failed**.
- Module self-tests: **51 passed / 0 unexpected failed / 16 expected skips**.
- Selfcheck: **26 passed / 0 failed**.
- Full pytest: **997 passed / 3 skipped / 0 failed**.
- Bugs fixed: **5**. Reported operational/external gates: **4**.

## Python 3.12 integration follow-up

The reviewed CPython 3.12 rerun exposed an overflow-lane lock convoy that the
earlier Python 3.14 run did not reproduce: the 40,000-event publisher phase took
7.44 seconds on an otherwise idle run. `queue.Queue`'s Python Condition and the
per-submit lifecycle mutex serialized eight otherwise-independent publishers.

**R7-BT-05 FIXED:** the overflow lane now combines a C-backed `SimpleQueue` with
an exact bounded semaphore, preserving the same capacity and `queue.Full`
synchronous-durability fallback. A saturation hint avoids repeated primary
`queue.Full` exceptions, and submit reads lifecycle references without holding
the global lifecycle mutex; stop still sets its event before joining and any
stop race fails into the durable synchronous lane.

The first post-fix wall-clock runs passed, but the same fixed five-second cutoff
later failed at 5.64 seconds while the live Chill stack had the eight-core host
at 93% CPU. Instrumentation showed the bounded worker still handled over 98% of
events in batches; CPU scheduling, not a return to publisher I/O, caused the
wall-clock failure. The gate now proves the intended property directly: exact
losslessness, authenticated evidence, bounded queue depth, at least 95% of
events avoiding synchronous publisher I/O, aggregate batch accounting, and
fewer than one batch write per eight queued events. A 30-second thread-join
deadline remains only as a deadlock/liveness bound, not a speed score.

Post-fix gates under the live 93%-CPU load: the structural 40,000-event test
passed **3/3**; the complete async-recorder/priority suite passed **10/10** in
7.32 seconds; Ruff and compilation passed. The aggregate fix count is **5**.

---

# Frozen v1.10.2 final release-candidate revalidation

Date: 2026-08-25. This is the authoritative final-tree revalidation and
supersedes the interim totals above. It ran on Windows with CPython 3.12.10,
`PYTHONPATH=src`, Qt offscreen, and the shared v1.10.2 source tree frozen.

## Outcome

**PASS — no reproducible release-blocking defect remains.** Every collected
pytest case resolved successfully or as an intentional skip; the package
compiled and imported cleanly; Ruff, both selfcheck entry points, all callable
core/Shark self-tests, the ARIA self-test runner, and the dependency audit
passed.

## Compile, lint, imports, and discovery

- `tools/compile_check.py`: **308/308** files parsed; **0 failed**. The complete
  `src/angerona` `py_compile` gate found no syntax error or mount-read artifact.
- `python -m ruff check src tests tools`: **PASS**.
- `git diff --check`: **PASS**. Git emitted only line-ending conversion notices,
  not whitespace errors.
- Recursive package import inventory: **69/69 module files imported**, **0
  failures**.
- `ModuleManager` discovery: **67 modules**, **0 discovery errors**, **0
  duplicate names**, and **0 duplicate non-empty codes**.
- Twelve class-bearing module files intentionally have no optional module-level
  `register()` factory (`ai_triage`, `cloud_escalation`, `deception`,
  `file_integrity`, `forensics`, `macos_observe`, `network_monitor`,
  `persistence_sweep`, `process_monitor`, `soar`, `soar_engine`, and
  `yara_scanner`). All twelve were found through the documented `BaseModule`
  subclass discovery path, so none is a missing-module defect.

## Complete pytest gate

- Collection: **1,258 tests in 197 files**.
- Authoritative run: the 197 files were executed in 14 sequential shards to
  avoid known aggregate Windows I/O/plugin contention.
- Result: **1,255 passed, 3 intentionally skipped, 0 failed**. Every shard
  exited zero.
- Current response-surface spot gates also passed: SOAR queue reconciliation
  **12/12**; Posture/Red Team/Top Talkers/Combat Undo **19/19**; current Combat,
  lifecycle, finalize/deploy, and shutdown boundary set **18/18**. The complete
  aggregate independently included all Combat, Ollama, ARIA, SOAR, GUI/menu,
  and host-action tests.

An earlier non-authoritative sweep set `--basetemp` to
`.tmp/final-pytest/shard-N` inside the checkout. That created exactly two
expected boundary refusals: Source Sandbox rejected a workspace-contained
parent identity, and deploy safety rejected a destination nested inside its
stage tree before reaching the marker assertion. Those were test-environment
configuration artifacts, not product failures. Repeating the complete sweep
with pytest's normal external Windows temp location produced the authoritative
zero-failure result above.

## Self-tests and harnesses

- Module `SelfTestRunner`: **46 genuine module passes**, **0 genuine failures**.
  It additionally reported **13 expected inactive-environment results** (for
  stopped sensors, idle/unarmed SOAR, stopped Combat, and unavailable optional
  Ollama) plus **8 disabled/platform skips**. Its displayed `47 passed` includes
  the separate Event Pipeline row.
- Callable core and Shark module-level self-tests: **20/20 passed**.
- `run_aria_selftests.py`: **15/15 passed** (`ALL PASS`).
- `python tools/selfcheck.py`: **26/26 application/GUI phases passed**, exit 0.
- `cmd.exe /d /c run-selfcheck.bat`: **26/26 application/GUI phases passed**,
  exit 0, with its report written successfully.

## Dependency gate

`python -m pip_audit --local` returned **no known vulnerabilities**. It skipped
only the two local, non-PyPI distributions (`angerona` and the local
`srt 0.0.0+angerona.1`). Source metadata and runtime import both report
**1.10.2**. The current editable environment's installed distribution metadata
still says 1.10.0; that is stale local venv metadata, not a source or runtime
version defect.

## Defects found and disposition

### R7-FINAL-BT-01 — stale exact-contract regression fixture — FIXED

`tests/test_cycle4_round1_regressions.py` still treated a filename/command token
as response authority without the required signed v1 Combat contract. The
fixture now supplies the exact contract and includes a negative uncontracted
case. Gate: focused Combat/ARIA/Ollama/SOAR set **110/110**, then the complete
pytest gate passed.

### R7-FINAL-BT-02 — Combat Undo empty-state controls — FIXED

The Combat history refresh returned early for a missing module or empty action
set without disabling `Undo selected` and `Undo all`. The handlers were safe,
but the visible state was wrong. Both early-return paths now disable the
selector and buttons; a regression covers a history containing only unverified
reversible-looking records. Gate: focused GUI/settings set **9/9**, then the
complete pytest gate passed.

### R7-FINAL-BT-03 — generated Posture advisory path not persisted — FIXED

The new inert Posture advisory could return `no staged remediation` before its
advisory-only fields because generation did not persist the generated path in
the weakness record. The remediation stores that path while retaining the
unconditional non-executable policy. Gate: Posture/Red Team/Top Talkers/Undo
set **19/19**, then the complete pytest gate passed.

### R7-FINAL-BT-04 — Red Team rapid-rerun cleanup ordering — FIXED

`start()` reset `self.steps` before taking the prior-artifact snapshot, so an
exact run-owned marker could survive a rapid rerun. The immutable prior-artifact
snapshot is now captured before reset. Gate: the focused **19/19** set and the
complete pytest gate passed.

### R7-FINAL-BT-05 — stale SOAR direct-suspend tests and missing receipt reconciliation coverage — FIXED

The SOAR queue tests still expected a direct `psutil` suspend after product code
moved manual action behind Combat's signed response contract. They now assert
zero direct suspend calls, the exact `suspend_process` PID/birth-time contract,
the exact queue request ID, terminal/non-resubmittable `SUBMITTED` state, and
verified signed success/failure/timeout reconciliation. An unsigned lookalike
cannot close the queue. Gate: `tests/test_soar_queue_controls.py` **12/12**,
then the complete pytest gate passed.

### R7-FINAL-BT-06 — selfcheck expected execution of inert model advice — FIXED

Two selfcheck phases retained the old expectation that tampered AI-authored
Posture output would enter the execution path. The harness now proves the hash
tamper independently, then asserts the stronger current contract:
`ok=False`, `advisory_only=True`, and `executable=False`. No product policy or
test guarantee was weakened. Gate: direct and batch selfcheck **26/26**; Ruff
and compilation passed.

### R7-FINAL-QA-ENV-01 — workspace-local pytest temp root — ENVIRONMENT ARTIFACT

The two initial failures caused by the deliberately workspace-contained
`--basetemp` were not reproducible with the standard external pytest temp root.
They demonstrate that the source/deployment guards correctly reject unsafe
containment relationships. No product change was warranted.

## Final frozen-tree summary

- Files compiled: **308/308**.
- Self-tests: **81 passed / 0 genuine failed** (46 module, 20 core/Shark, 15
  ARIA), with 13 expected inactive and 8 platform/operator skips.
- Selfcheck: **26/26 direct and 26/26 batch**, both exit 0.
- Full pytest: **1,255 passed / 3 skipped / 0 failed**.
- Bugs fixed: **6**. Release-blocking bugs reported: **0**.
