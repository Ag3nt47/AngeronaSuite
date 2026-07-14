# Round 2 — Bug Test / QA Results

Date: 2026-07-14. Runner: Angerona bug-testing / QA agent. Environment:
supported Windows virtual environment (`venv\Scripts\python.exe`) with
`PYTHONPATH=src`; Qt ran offscreen. The runtime-generated
`rules/_active_combined.yar` file was not touched.

Scope: validate the current shared worktree after Round 2 remediation, run the
full compile/import/self-test gates, and specifically regression-test R2-01,
R2-03, and R2-04. R2-02 remains the deliberately deferred protocol redesign
described in `remediation_summary.md`.

## 1. Compile gate

- Direct `py_compile` walk: **168/168 Python files passed**.
- Repository `tools/compile_check.py`: **168 scanned, 0 failed**, exit code 0.
- No stale/truncated-read or mount artifacts occurred on this Windows run.

## 2. Import, discovery, and module identity checks

- `angerona.modules.*`: **61/61 files imported**, 0 broken imports.
- `ModuleManager.discover()`: **60 modules discovered**, 0 discovery errors.
- Duplicate non-empty module `CODE` values: **none**.
- Duplicate discovered module names: **none** (the manager's keyed collection
  contains all 60 unique names).
- Thirteen module files have no module-level `register()`:
  `ai_triage`, `cloud_escalation`, `deception`, `file_integrity`, `forensics`,
  `network_monitor`, `packet_sniffer`, `persistence_sweep`, `process_monitor`,
  `remediation_actions`, `soar`, `soar_engine`, and `yara_scanner`.
  This is the previously documented consistency gap, not a runtime defect:
  discovery uses `BaseModule` subclasses and all 60 modules were discovered.

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

An initial ad-hoc console wrapper encountered a Windows CP1252
`UnicodeEncodeError` while printing the incident-timeline arrow. This was an
output-encoding artifact, not a product/test failure. Re-running with UTF-8
produced the 6/6 result above; the project harness already configures UTF-8.

### All discovered modules

The built-in `SelfTestRunner` exercised the event pipeline and all 60 discovered
modules:

- Event pipeline: **PASS**.
- Module self-tests: **45 PASS, 15 expected environment/state skips, 0 genuine
  failures**.
- The raw runner labels the 15 skips as failures because live sensors are
  intentionally not started by the headless harness: 13 report
  `status=stopped`, Active Response SOAR reports safe unarmed/idle state, and AI
  Triage times out waiting for optional Ollama. `tools/selfcheck.py` explicitly
  recognizes these strings as expected skips. No unexpected failure remained.
- Windows-specific checks that were available passed, including Defender/AV,
  ETW process decoding, YARA/EICAR, persistence classification, packet and C2
  classifiers, and the kernel-driver-absent safe path.

## 4. Project self-check

Executed the same offscreen venv/Python path used by `run-selfcheck.bat`:

- `tools/selfcheck.py`: **26 phases passed, 0 failed**, exit code 0.
- Application and all dashboard/dialog construction passed with 60 modules.
- Live benign Red Team drill completed 30 steps over two phases and cleaned its
  inert custom marker.
- Judgment Gate tamper/TOCTOU blocks, vetted-remediation gates, persistence,
  incident correlation, world view, and WAL/retention performance gates passed.

## 5. Round 2 targeted regression tests

### R2-01 — Authenticode command injection: PASS

A hostile telemetry path containing a quote, semicolons, spaces, a destructive
PowerShell-looking fragment, and Unicode was passed to `_authenticode_status()`
under a mocked child process. The path was absent from argv and PowerShell source,
arrived unchanged only through `ANGERONA_AUTHENTICODE_PATH`, and the constant
script used `-LiteralPath`. It could not become executable PowerShell syntax.

### R2-03 — event-ledger integrity: PASS

A temporary pre-remediation SQLite schema was migrated in place. The test then
proved that:

- the `hmac_sig` column was added and new signatures were persisted;
- nested `details` survived a signed round trip;
- changing only stored `details` produced a CRITICAL integrity-failure event;
- a migrated unsigned row was visibly marked `[UNSIGNED LEGACY]`; and
- a live armed EventBus accepted its signed event but rejected an otherwise
  identical event whose `details` decision was changed.

### R2-04 — MCP concurrency/resource caps: PASS

A live loopback MCP server was started on an ephemeral port. With an SSE stream
held open, an `initialize` POST completed with HTTP 202 and its JSON-RPC response
arrived on that stream, proving the stream did not monopolize the server. A body
over the 256 KiB cap returned HTTP 413. The server and stream shut down cleanly.

Targeted result: **3 passed, 0 failed**.

## Bugs

### FIXED

- **None.** No obvious production defect was found, so no bug-test code patch was
  warranted. All Round 2 remediation changes passed their gates.

### REPORTED / carried forward

- **No new production defect.** The 13 missing `register()` functions remain a
  non-functional consistency item; discovery and imports are complete.
- **R2-02 remains deferred by design**, not regressed: Remote Bridge mutual
  authentication and AEAD/mTLS need a versioned protocol migration and were not
  changed by the Round 2 remediation.

## Final gate summary

- Files compiled: **168/168**.
- Core self-tests: **6 passed, 0 failed**.
- Module self-tests: **45 passed, 0 genuine failed, 15 expected skips**; event
  pipeline passed.
- Round 2 targeted regressions: **3 passed, 0 failed**.
- Project self-check: **26 passed, 0 failed**, exit 0.
- Bugs fixed: **0**. New production bugs reported: **0**.
