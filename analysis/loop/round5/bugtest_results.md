# Round 5 — Final Bug Test / QA Results

Date: 2026-08-25. Runner: Angerona bug-testing / QA agent. Environment:
supported Windows virtual environment (CPython 3.12.10), `PYTHONPATH=src`,
`CI=true`, UTF-8 output, and Qt offscreen. This audit ran after the final Combat,
SourceSandbox, ARIA/model-pack, Sysmon, producer-contract, and performance edits
had converged in the shared tree. The live host-isolation campaign was excluded
by assignment and retained for the root agent's single-owner acceptance run.

## 1. Compile, lint, and patch-integrity gates

- `tools/compile_check.py` invoked `py_compile` on every Python file under
  `src/angerona`: **307/307 passed**, zero syntax errors or stale-mount
  artifacts.
- Ruff correctness gate over `src`, `tests`, and `tools`: **PASS**.
- `git diff --check`: **PASS**. Output contained only expected LF-to-CRLF
  checkout notices, not malformed patches or whitespace errors.

## 2. Imports, discovery, registration, and module identity

- Imported **69/69** `angerona.modules.*` files with zero broken imports.
- `ModuleManager.discover()` constructed **67 modules** with zero discovery
  errors.
- Duplicate discovered module names: **none**.
- Duplicate non-empty module `CODE` values: **none**.
- Optional compatibility hooks constructed **55/55**. Twelve class-bearing
  modules intentionally use subclass discovery without the optional hook:
  `ai_triage`, `cloud_escalation`, `deception`, `file_integrity`, `forensics`,
  `macos_observe`, `network_monitor`, `persistence_sweep`, `process_monitor`,
  `soar`, `soar_engine`, and `yara_scanner`. All twelve were discovered, so this
  is not a functional omission.

## 3. Self-tests and complete behavioral suites

- Core and Shark module-level `self_test()` functions: **20 passed / 0
  failed**. This includes action policy, alert acknowledgement, score, Cortex,
  CVE controls, host adaptation, OCSF, report attestation, installer guidance,
  Sigma/telemetry contracts, and the Shark engine.
- `SelfTestRunner` event pipeline: **PASS**. The 67 discovered module results
  were **46 genuine passes / 13 expected inactive-environment results / 8
  platform or operator-disabled skips / 0 genuine failures**. Expected inactive
  results were stopped live sensors, idle/unarmed SOAR, and unavailable optional
  Ollama.
- `tools/selfcheck.py`: **26/26 phases passed**, exit 0.
- `run-selfcheck.bat`: **26/26 phases passed**, exit 0, including whole-GUI
  construction and its batch report path.
- ARIA standalone self-test harness: **15/15 capability groups passed**,
  including the exact-token write gate, voice channel boundary, RAG, scheduled
  routines, six-agent dispatch, local research, and inbox triage.
- Final focused Combat/Sandbox/ARIA/model/Sysmon/producer/performance set:
  **96/96 passed**.
- Final complete suite after all Round 5 performance changes: **1181 passed / 3
  intentional platform skips / 0 failed** in 84.52 seconds.

## 4. Bugs

### FIXED — R5-BUG-01: stale Purple Guard contract assertion

- **Component:** `tests/test_redteam_runtime_targets.py`.
- **Symptom:** the first complete suite stopped at one failure although Purple
  Guard emitted a valid event.
- **Root cause:** the producer was correctly hardened to include
  `response_authorized=true` and a versioned, exact-path quarantine contract,
  but an older exact-dictionary assertion still expected the pre-contract
  payload.
- **Fix:** updated the regression to require the full authorization contract;
  no product behavior or gate was weakened.
- **Gate:** producer/runtime-target subset **13/13 passed**; focused set **96/96
  passed**; complete suite **1181 passed / 3 skipped**.

### FIXED — R5-BUG-02: FIM benign-drill provenance block was unreachable

- **Component:** `src/angerona/modules/file_integrity.py` and
  `tests/test_adversary_response_producers.py`.
- **Symptom:** `_registered_benign_noise()` returned `None` for a name-matching
  file and could no longer recognize an exact, live, in-memory registered Red
  Team noise artifact. This caused a drill false-positive regression.
- **Root cause:** insertion of the new `_combat_file_contract()` function split
  `_registered_benign_noise()` before its provenance lookup, leaving that lookup
  stranded after an unconditional return in the new function.
- **Fix:** restored the exact-path, TTL-bounded `practice_scope` provenance check
  inside `_registered_benign_noise()`. Added a regression proving that an exact
  registered `kind=red-team` artifact is ignored while an unregistered filename
  lookalike remains hostile evidence.
- **Gate:** focused producer tests passed; File Integrity Monitor self-test
  passed; compile, Ruff, focused, selfcheck, and complete-suite gates all passed.

### REPORTED — R5-QA-01: Maximum Combat polls can reuse a longer-lived cache

- **Components:** `telemetry/sensors.py`, `modules/network_monitor.py`, and
  `modules/process_monitor.py`.
- **Evidence:** the shared process/connection snapshot cache defaults to 1.5
  seconds, while Maximum Combat polls connections every 0.75 seconds and
  processes every 1.0 second. An alternating fast-mode tick can therefore
  receive the previous snapshot rather than a new OS enumeration.
- **Disposition:** **REPORTED**, not changed in the bug-test lane. Selecting a
  mode-specific `max_age` is an explicit detection-latency versus enumeration-
  cost policy decision. A bounded follow-up is to pass half-cadence cache ages
  in Combat mode and add call-contract/performance tests.

## Final gate summary

- Files compiled: **307/307**.
- Imports/discovery: **69/69 imports; 67 modules; 0 errors; 0 duplicate names or
  codes**.
- Module self-tests: **46 passed / 13 expected inactive / 8 skipped / 0 genuine
  failed**.
- Core/Shark self-tests: **20 passed / 0 failed**.
- Selfcheck: **26 passed / 0 failed**, direct and batch exit 0.
- ARIA self-tests: **15 passed / 0 failed**.
- Focused security regressions: **96 passed / 0 failed**.
- Complete pytest: **1181 passed / 3 intentional skips / 0 failed**.
- Bugs: **2 fixed / 1 design-level issue reported**.
