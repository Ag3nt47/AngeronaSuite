# Cycle 7, Round 3 — Full validation

Date: 2026-08-20  
Validation start: 2026-08-20 21:58:07 MDT  
Scope: final integrated compile, discovery, self-test, crash/lifecycle,
remediation, security, performance, release, and regression validation on the
shared Cycle 7 tree.

## Final outcome

- **PASS:** final current-tree aggregate completed with **744 passed / 2
  intentional platform skips / 0 failed** in **98.56 seconds**.
- **PASS:** `py_compile` checked **279/279** Python files under
  `src/angerona`; no syntax failures.
- **PASS:** all **67/67** `angerona.modules.*` files imported. All **53**
  exposed `register()` factories constructed, **65** modules discovered with
  **0** discovery errors, and **48** declared module codes contained **0**
  duplicates. Fourteen files intentionally use class discovery or are support
  workers rather than registration factories.
- **PASS:** final module stress drill recorded **51 passes / 15 expected
  stopped, idle, optional-service, timeout, or platform skips / 0 unexpected
  failures**.
- **PASS:** all **18/18** runnable zero-argument core self-tests passed.
- **PASS:** final direct `tools/selfcheck.py` run completed **26/26** phases.
  The `run-selfcheck.bat` wrapper also exited 0 and wrote a **26/26** report
  during this round; its only behavior is to invoke the same harness in the
  checked virtual environment and redirect the report.
- **PASS:** final focused Cycle 7 crash/lifecycle, drill-remediation,
  performance, Fleet shutdown, Remote Bridge authority, release hash/setup,
  and Upgrade Console close set completed **34/34**.
- **PASS:** Ruff, documentation drift, source-trust preflight, workflow policy,
  and `git diff --check` completed cleanly. The only Git output was the
  repository's existing LF-to-CRLF checkout notice.

## Defects challenged during the round

### Fleet partial-request shutdown — fixed and verified

The first integrated snapshot reproduced the already reported Windows Fleet
shutdown race:

- **732 passed / 2 skipped / 1 failed**;
- `test_supervised_stop_interrupts_stalled_handler_and_closes_replay` observed
  `FleetLoopbackService.stop(timeout=0.2)` return `False` with a handler blocked
  on an incomplete HTTP request.

The Cycle 7 remediation then added a service-owned shutdown event and
short-polling socket reader, an atomic stop/setup handshake, exactly-once
handler accounting, bounded saturation draining, serialized lifecycle changes,
and canonical cleanup before the replay ledger closes. The new regression set
includes **15** consecutive partial-request drains and **10** forced handler
setup races. The final aggregate and the final **34/34** focused set both pass.
No replay-ledger handle remained locked.

### AnalysisWorker native Qt completion — remains closed

The payload-bearing signal remains separate from native `QThread.finished()`;
result consumers no longer reap a running worker. The final Qt lifecycle tests
pass in both the aggregate and focused set. The earlier round's **30/30**
fresh-process lifecycle stress remains the direct repeated native-crash gate.

### Remote telemetry authority — remains observe-only

Authenticated Remote Bridge events retain source evidence but cannot provide a
receiver-local PID/path, invoke local SOAR containment, or mutate local
Evolution Engine policy through peer-controlled verification fields. All four
remote-authority regressions pass in the final tree.

### Red-team remediation truth and isolation — remain closed

The final suite reconfirms that Threat Intel labels generated fixes as staged,
not executed; AI/no-fix outcomes cannot bulk-suppress applicable KEVs; sandbox
self-tests execute in disposable integration-disabled children with a hard
deadline; and installer downgrade/version gates remain enforced.

### Performance regressions — remain closed

The final focused and aggregate suites reconfirm unchanged-refresh coalescing
for expanded Console, System Pulse, resource details, and Top Talkers, plus
Purple Guard policy/revision caching. No performance gate regressed.

## Transient and concurrent-edit observations

- Before the final tree settled, a 35-file relevant subset recorded **170
  passed / 1 skipped / 3 failed**. One failure imported a newly added legacy
  engine test before its optional dependency stub was present; one asserted the
  old Inno compiler lookup while the verified-compiler workflow was being
  edited; and one Upgrade Console close took 0.411 seconds against a 0.2-second
  timing threshold under concurrent load.
- The missing stub and release assertion were completed by their owning
  remediation changes. The Upgrade Console close gate then passed **10/10** in
  fresh serial processes and passed again in both final test sets. It is
  classified as a non-reproducing load-sensitive test observation, not a
  confirmed product defect.
- No test was weakened or removed to obtain the final pass.

## Crash and diagnostic audit

- Windows CrashDumps contained **0 new dumps** after the 21:58:07 validation
  start.
- Windows Application log contained **0 new Application Error, Windows Error
  Reporting, or Application Hang events** after that start.
- The newest Python dump remains
  `%LOCALAPPDATA%\\CrashDumps\\python.exe.20648.dmp` from **21:25:20**, before
  the AnalysisWorker native-completion fix.
- No new crash/error/not-responding report was found under the canonical
  `D:\\local-security-ai\\AngeronaData` tree or the legacy LocalAppData
  Angerona tree during the bounded post-run audit.

This is strong automated and fresh-process evidence, but it is not a substitute
for a physical sleep/resume exercise or an 8–24 hour interactive production
soak with all live sensors and Ollama enabled.

## Coordinating security/release addendum

- The project venv did not include Bandit, but the repository's isolated,
  hash-pinned developer audit environment did. The coordinating pass scanned
  all **77,866 source lines** at medium/high severity and returned **0 findings**
  (0 medium, 0 high).
- The exact Inno Setup 6.7.1 upstream artifact was checked against its committed
  SHA-256, installed noninteractively, and successfully compiled the complete
  Setup script with placeholder release payloads. Real release artifacts still
  require clean-VM install, upgrade, downgrade rejection, uninstall, and
  attestation verification in release CI.

## QA disposition

- Bugs fixed directly by the Round 3 validation agent: **0**.
- Bugs reproduced and handed to remediation during validation: **1** (Fleet
  partial-request shutdown), **fixed and closed in the same loop**.
- New unresolved reproducible product bugs after the final gates: **0**.
- Reported external/acceptance limits: **2** — physical sleep/resume was not
  exercised, and long live-runtime/clean-release-VM acceptance is still required.
