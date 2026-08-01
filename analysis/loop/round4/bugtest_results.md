# Round 4 — Bug-test results

Date: 2026-08-01  
Branch: `codex/enterprise-cycle7`  
Scope: live shared Cycle 15 tree; no commit made by the bug-test agent.

## Outcome

- **FIXED:** one safe diagnostic-launch regression in `tools/selfcheck.py`.
- **REPORTED:** no product crash, import, Settings, fleet-lifecycle, provider-
  credential, Help-parity, or immediate-window-close defect reproduced.
- **LONG-RUNTIME LIMIT:** a two-second smoke sample passed, but it is runner
  plumbing evidence only. It is not an 8-hour/24-hour production soak and must
  not be cited as proof that long-runtime growth is solved.

## Gates run

### Package compile and import inventory

- `tools/compile_check.py`: **277 files compiled / 0 failures** before testing,
  then **277 / 0** again after the fix and concurrent performance changes.
- Imported all **67** `angerona.modules.*` files: **67 passed / 0 failed**.
- `ModuleManager.discover()`: **65 modules / 0 discovery errors**.
- Called all **53** module-level `register()` functions: **53 constructed / 0
  failures**. Twelve other capability files deliberately use the manager's
  `BaseModule` subclass discovery contract rather than `register()`; two files
  are utility workers. No new missing-registration regression was found.
- Module `CODE` inventory: **48 coded modules, 0 duplicate codes**. Seventeen
  class-discovered modules have no legacy `CODE`; names remain unique and all
  were discovered, so this is not a runtime defect.

### Self-tests and selfcheck

- Module stress drill: **51 passed / 15 expected stopped, optional-service, or
  platform skips**. The expected set includes an unavailable macOS sensor on
  Windows, inactive live sensors, an optional Ollama timeout, and idle SOAR.
- Callable zero-argument `angerona.core.*.self_test()` functions: **18 passed /
  0 failed**.
- Final `run-selfcheck.bat`: **26 phases passed / 0 failed**, exit code 0.

### Focused and full regression tests

- Settings construction, provider credential consolidation, capability Help
  parity, Upgrade Console immediate close, app startup/shutdown, fleet
  lifecycle, tenant authentication, Fleet API HTTP hardening, and soak-runner
  unit tests: **133 passed / 0 failed** in 75.65 seconds.
- Complete serial repository regression: **705 passed / 2 intentional platform
  skips / 0 failed** in 194.65 seconds.
- Post-performance-agent regression for EventBus revision gating, Purple Guard,
  System Pulse worker reuse, remediation, and lifecycle: **34 passed / 0
  failed** in 13.30 seconds.
- `ruff check tools/selfcheck.py`: PASS.
- `git diff --check`: PASS (line-ending conversion notices only).

### Bounded runtime smoke

`tools/run_soak.py --profile smoke --duration-seconds 2` completed with a PASS:

- 3 samples over 1.965 seconds;
- RSS growth 0.352 MiB;
- handle growth 0;
- thread growth 0;
- dropped-event delta 0;
- no queue/UI metrics file supplied.

The evidence itself correctly labels this as plumbing-only and privacy-
minimized. A real Angerona process plus runtime metrics is still required for
the 8-hour and 24-hour profiles.

## Bug found and fixed

### BT-15-01 — Non-admin selfcheck could not open protected production data

- **Component:** `tools/selfcheck.py` / `run-selfcheck.bat`
- **Symptom:** the stock harness exited before module discovery with
  `sqlite3.OperationalError: unable to open database file`.
- **Root cause:** `configure_runtime_environment()` resolved the live
  `runtime-data/flight-recorder.db`, whose Administrators/SYSTEM-only ACL is
  correct for production but incompatible with the batch file's documented
  non-admin diagnostic mode.
- **Fix:** when the operator has not supplied `ANGERONA_DATA`, selfcheck now
  selects a per-process sandbox below `.tmp/selfcheck/<pid>` on the D: workspace.
  This avoids both production-state mutation and concurrent selfcheck database
  collisions while preserving explicit operator overrides.
- **Gate:** changed file compiled and linted; the unmodified
  `run-selfcheck.bat` then exited 0 with **26/26** phases passing.

## Reported / deferred evidence

No design-level code change was made for long-runtime behavior. The smoke gate
does not exercise a running dashboard, live queue metrics, eight hours of
resource growth, suspend/resume, or 24-hour retention. Those remain operational
validation work, not a defect inferred from a two-second sample.

