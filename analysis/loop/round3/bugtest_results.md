# Round 3 — Bug Test / QA Results

Date: 2026-07-14. Runner: Angerona bug-testing / QA agent. Environment:
supported Windows virtual environment (`venv\Scripts\python.exe`) with
`PYTHONPATH=src`; Qt ran offscreen. The runtime-generated
`rules/_active_combined.yar` file was not modified.

Scope: audit the current shared tree after Round 3 remediation, detect partial
edits from the interrupted remediation turn, verify R3-03/R3-04 and the Round 2
security/performance changes, exercise Evidence Lattice Fusion (ELAT), and run
the repository's complete compile/import/self-test harness.

## 1. Tree-integrity and compile gates

- `git diff --check`: no malformed patch fragments or whitespace errors; only
  expected line-ending notices were emitted.
- Merge-conflict scan: no conflict markers were found in source, tools,
  `mitigation_gate.ps1`, or the Round 3 artifacts.
- No partial/orphaned remediation edit was found. R3-03 and R3-04 are present in
  all intended enforcement points; R3-01 and R3-02 remain explicitly deferred.
- `tools/compile_check.py`: **169/169 Python files passed**, zero syntax errors,
  exit code 0.
- `mitigation_gate.ps1`: PowerShell AST parse passed with zero parse errors.

## 2. Imports, discovery, and module identity

- `angerona.modules.*`: **62/62 module files imported**, zero broken imports.
- `ModuleManager.discover()`: **61 modules discovered**, zero discovery errors.
- Duplicate non-empty module `CODE` values: **none**.
- Duplicate discovered module names: **none**.
- Thirteen files still have no optional module-level `register()`:
  `ai_triage`, `cloud_escalation`, `deception`, `file_integrity`, `forensics`,
  `network_monitor`, `packet_sniffer`, `persistence_sweep`, `process_monitor`,
  `remediation_actions`, `soar`, `soar_engine`, and `yara_scanner`. This remains
  a non-functional consistency item because discovery uses `BaseModule`
  subclasses and all 61 modules were discovered.

## 3. Self-tests

### Core and Shark

All callable core/Shark self-tests passed: **6 passed, 0 failed**.

| Component | Result |
|---|---|
| `core.cve_ignore` | PASS |
| `core.cve_fix_advisor` | PASS |
| `core.alert_ack` | PASS |
| `core.incident_timeline` | PASS |
| `core.ir_bundle` | PASS |
| `shark.red_team` | PASS |

### All discovered modules

The built-in `SelfTestRunner` exercised the event pipeline and all 61 modules:

- Event pipeline: **PASS**.
- Module self-tests: **46 PASS, 15 expected environment/state skips, 0 genuine
  failures**.
- The 15 raw failures are the expected stopped/idle/Ollama cases recognized by
  `tools/selfcheck.py`: AI Triage timed out without optional Ollama; live sensors
  intentionally not started by the headless runner reported `status=stopped`;
  Active Response SOAR reported safe unarmed/idle state.
- ELAT passed entity fusion, deduplication, time-window expiry, and
  false-positive controls.
- The actual bundled YARA engine detected the EICAR self-test sample.

## 4. Round 3 targeted regressions

Focused result: **12 passed, 0 failed**.

### R3-02 partial key hardening — PASS

An isolated first run created one stable 32-byte signing key; reload retained
the same signing authority; replacing the file with malformed data caused
`BusAuthority.load()` to fail closed instead of rotating the key. This validates
the applied partial hardening only. The same-user key-custody boundary remains
deferred as documented by remediation.

### R3-03 PowerShell containment gate — PASS

- The shared CVE advisor self-test passed.
- The Python scanner/strict containment allow-list rejected WMI/CIM process
  termination and all **5/5** historical generated playbooks.
- The deterministic network-only `New-NetFirewallRule` fallback passed.
- `mitigation_gate.ps1` parsed successfully; its AST validation remains present
  immediately before any playbook execution.

### R3-04 YARA compile/activation gate — PASS

Using the actual bundled `yara64.exe` in an isolated rules directory:

- the shipped base `rules.yar` compiled;
- a valid generated rule was compiled and atomically activated;
- an invalid generated rule was rejected;
- both active and persisted last-known-good bytes remained unchanged after
  rejection; and
- the resulting live ruleset passed the YARA/EICAR module self-test.

The pre-remediation `rules/auto_generated.yar` remains syntax-invalid, as already
documented by the Round 3 finding, but is not active and is rejected by the new
compile gate. It was not rewritten during QA. `rules/_active_combined.yar` was
not read as an activation source and was not modified.

### EventBus long-run behavior — PASS

A ten-entry ring received 30 INFO events: all 30 reached subscribers while only
the newest 10 remained in bounded history. This verifies the long-run telemetry
delivery fix without unbounded memory growth.

## 5. Round 2 security and performance regressions

- **R2-01 PASS:** a hostile Authenticode path containing quotes, semicolons,
  spaces, and Unicode remained child-process environment data and never entered
  PowerShell source; the constant script retained `-LiteralPath`.
- **R2-03 + P5 PASS:** the recorder reused the armed bus HMAC, persisted nested
  details, and surfaced a details-only SQLite modification as a CRITICAL ledger
  integrity failure.
- **R2-04 PASS:** with a live SSE connection held open, a concurrent initialize
  POST returned 202; a body over 256 KiB returned 413.
- **P3 PASS:** once the static ATT&CK coverage table was marked populated, a
  second refresh returned without touching/rebuilding the table.
- **P6 edge REPORTED:** the cache-miss locks serialize callers, but the cache-hit
  condition tests the truthiness of the cached list. A valid empty process or
  connection snapshot is therefore treated as uncached; in an eight-caller
  empty-snapshot probe, all eight callers repeated the OS enumeration. This is a
  low-severity performance edge, not a correctness or detection failure. It was
  reported rather than patched during the final QA stop; the safe follow-up is
  to key cache validity on its timestamp, including empty snapshots, then rerun
  the existing concurrent miss gate for both process and connection caches.

## 6. Full project self-check

`tools/selfcheck.py` completed with **26 phases passed, 0 failed**, exit code 0.
It constructed the complete 61-module application and dashboard/dialog set,
ran the live benign Red Team drill, verified tamper/TOCTOU and remediation
gates, exercised persistence and incident correlation, and passed the WAL,
bounded-ledger, and audit-cache speed phase. Interactive alert views remained
bounded (362 LOW+ rows and 16 CRITICAL rows in this run).

## Bugs

### FIXED

- **None.** No obvious functional production defect or partial Round 3 edit was
  found, so the QA pass made no production-code change.

### REPORTED

- **R3-QA-01 (LOW, performance): empty sensor snapshots are not cached.** See P6
  above. Normal non-empty snapshots retain the Round 2 serialization benefit;
  the edge can cause redundant scans when a valid result is empty.
- R3-01, R3-02, and R2-02 remain deliberately deferred design/security-boundary
  work, not regressions introduced by this round.

## Final gate summary

- Files compiled: **169/169**.
- Imports/discovery: **62/62 imports; 61 modules; 0 errors; 0 duplicate codes**.
- Core/Shark self-tests: **6 passed, 0 failed**.
- Module self-tests: **46 passed, 0 genuine failed, 15 expected skips**; event
  pipeline passed.
- Focused Round 3 regressions: **12 passed, 0 failed**.
- Full project self-check: **26 passed, 0 failed**, exit 0.
- Bugs fixed: **0**. New bugs reported: **1 low-severity performance edge**.
