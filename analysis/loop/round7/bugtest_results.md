# Round 7 — Bug Test / Release QA Results

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
