# Bug hunter — deep review pass 2, 2026-09-23

The bounded integration review passes. No new production defect was established
in this pass. The two pass-1 QA regressions are fixed by the patch applier and
pass again against the combined worktree. No production module was edited by
this bug hunter; changes are regression tests and offline-harness isolation.

## Scope and isolation

All commands used `<review-worktree>`, the
existing original-checkout venv interpreter, and this worktree's explicit
`PYTHONPATH=src`. Qt was offscreen. Runtime, quarantine, rollback, logs and
diagnostic fixtures stayed under disposable `.tmp` roots. No live sensor,
VMware guest, native Ollama launch or model inference was initiated by QA.

The new automatic-start integration required an explicit offline boundary:
`tests/conftest.py` and `tools/selfcheck.py` now replace the two high-level
Ollama preparation helpers with an honest unavailable result, and forbid the
native spawn helper. Existing inventory/readiness checks and skip policy stay
intact. The dedicated `test_ollama_startup.py` is exempt by agreement with its
owner; it exercises the real helper with its own inert listener, process and
custody mocks. Its gate is reported by that agent rather than included here.

## Results

| Gate | Result | Evidence |
|---|---|---|
| Whole package compile | 385 passed, 0 errors, 0 mount artifacts | `compile-round2.json` |
| Autonomous response, status UI, Chill compatibility | 19 passed | `.tmp/qa-autonomy-round2.xml` |
| App startup/shutdown, dashboard readiness, headless, AI readiness, self-test deadlines/results, module contracts, safe startup | 161 passed, 1 skipped | `.tmp/qa-startup-round2.xml` |
| GUI result fixture plus pass-1 Lab and MTM regressions | 16 passed | `.tmp/qa-fixtures-round2.xml` |
| Distinct pytest cases across those three batches | 186 passed, 1 skipped, 0 failed | XML classname/name deduplication; no full suite run |
| Supported `tools/selfcheck.py` | 26 phases passed, 0 failed | `.tmp/qa-selfcheck-round2.txt` |
| SelfTestRunner inventory within selfcheck | 84 modules; 66 module passes, 18 expected skips, 0 failures; separate event pipeline passes | Harness summary is 67 passed including pipeline |
| Changed QA/harness files Ruff and tracked whitespace | Passed | Targeted `ruff check` and `git diff --check` |

The 24 core `self_test()` checks and exhaustive 84-module discovery/identity
audit passed in pass 1; they were not independently rerun as a separate core
batch here. See `core-selftests-round1.json` and
`module-inventory-round1.json`. Current module discovery also passed in the
supported selfcheck. Platform, optional configuration, unstarted-worker and
approved-model prerequisites remain visible skips, not invented sensor passes.

## New deterministic proofs

`tests/test_deep_review_autonomous_response.py` adds:

- `test_authenticated_response_worker_verifies_quarantine_receipt_without_ollama`:
  AI readiness explicitly fails and inference entry points reject calls. The
  real Combat worker consumes an authenticated typed request for an inert
  exact-path/exact-hash artifact, quarantines it, verifies the postcondition,
  records a verified journal action, emits an authenticated receipt with the
  same target/hash/run ID, and restores the exact bytes through production undo.
- `test_forged_ai_instruction_text_cannot_authorize_response`: four variants
  cover an unsigned typed claim, signed AI narrative with forged action flags,
  a signed remote-observe claim, and signed prose without a typed contract.
  Hostile command-like JSON/HTML text produces no action, mutation or receipt.

`tests/test_ollama_status_ui.py` adds:

- `test_status_refresh_reads_only_cached_state_and_preserves_failed_percentage`:
  refresh cannot invoke API/process/start helpers; a failed 25% stage remains
  25%, and unchanged snapshots do not reset the label.
- `test_invalid_host_and_hostile_startup_detail_are_literal`: an invalid host
  produces a generic 0% failure, while injected detail stays literal plain
  text with its real 45% stage.
- `test_hidden_status_panel_stops_timer_and_resume_refreshes`: hiding stops
  background UI refresh, and showing resumes it.
- `test_retry_schedules_start_and_keeps_qt_responsive`: retry uses the async
  helper, disallows synchronous preparation, and allows a queued Qt tick.

These tests establish that an authorized local response does not need model
availability. They do not establish that the user's current daemon, approved
model, response configuration or running GUI is healthy.

## Findings and fixture updates

| Item | Status and gate |
|---|---|
| R1-QA-01: Lab completion could disappear during a full-queue/concurrent-drain race | FIXED by patch applier; deterministic regression passes here. |
| R1-QA-02: MTM late collection could admit payloads and use a retired ring after stop | FIXED by patch applier; late-work, ring lifetime and restart regressions pass here. |
| Legacy self-test GUI harness lacked the new `config.ollama_host` dependency | FIXED in test fixture; previously masked the intentionally injected runner error with AttributeError. Added the minimal config and reran the complete focused startup selection: 161 pass/1 skip. |
| Legacy Chill test expected no daemon preparation and family-tag matching | UPDATED for the requested behavior: explicit self-test prepares the daemon with `for_selftest=True`, inference stays forbidden in Chill, and an omitted model tag matches only `:latest`. |
| Automatic native service startup could escape legacy tests/offline harness | PREVENTED by explicit inert helpers plus a forbidden-spawn guard; the supported harness remains 26/26. |

Initial new-test failures from assigning to frozen events and checking a
pre-publication unsigned event were fixture errors, corrected with immutable
replacement and the signed bus copy. No product behavior or security assertion
was weakened. No new production finding is left open by this bounded pass.

The parent owns the final combined suite, native acceptance checks, current
installed-machine diagnosis, documentation and guarded publication. No commit
or publication was made by this agent.
