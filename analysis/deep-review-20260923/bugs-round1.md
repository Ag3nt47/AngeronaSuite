# Deep review 2026-09-23 — bugs, round 1

**Bounded baseline QA complete. Two concrete defects reproduced and handed to the patch applier. No production code was changed by the bug hunter.** These are before-fix results; final integrated regression belongs to the next scheduled round.

## Scope and isolation

Worktree: `<review-worktree>`, based on `7b7b264` plus the pending Analysis Lab/source-review implementation. Interpreter: the original checkout's existing virtualenv Python, with `PYTHONPATH` explicitly pointing to this worktree's `src`. App/runtime fixtures and logs were isolated under `.tmp`; pytest's existing per-test runtime isolation was retained. Later test batches also use an explicit `.tmp` basetemp. No live sensors, inference, real VM, or host containment were launched. A supported test exercises OS job limits against its own short-lived sleeping child, and response tests use only disposable inert files and mocked action backends.

## Baseline validation

| Gate | Result |
| --- | --- |
| Full `src/angerona/**/*.py` compile | **384 passed; 0 failed; 0 mount artifacts** |
| Analysis Lab core/UI + GitHub source-review/UI tests | **87 passed, 1 skipped** |
| Ollama transport/readiness + response contract/readiness tests | **104 passed** |
| Module usage/lifecycle patches + Chill idle + source authority tests | **74 passed** |
| Newly added deterministic regressions | **1 passed, 2 failed as expected for real defects** |
| Core top-level `self_test()` inventory | **24 passed, 0 failed** |
| Module discovery | **84 capabilities, 0 discovery errors, 0 duplicate declared CODEs** |
| Module self-tests | **66 passed, 0 failed, 18 expected skips** |
| Event-pipeline test | **1 passed** |
| Supported `tools/selfcheck.py` | **26 phases passed, 0 failed** |

The existing focused pytest batches total **265 passed, 1 skipped**; including the new literal-text control gives **266 passed, 2 reported failing regressions, 1 skipped** across these disjoint batches. No full pytest run was started.

All 84 capabilities are accounted for in `module-inventory-round1.json`, with source hashes, methods, registration declarations and individual baseline self-test results. This is an exhaustive inventory and test-result accounting, plus targeted manual lifecycle review; it does not claim every line of every module was manually re-reviewed. Sixteen modules lack `register()` and eighteen lack explicit class CODE metadata; class-based discovery supports these and all 84 import/construct correctly. The dashboard selfcheck shows `0/73` relevant capabilities while the inventory window retains all 84 rows.

Machine-readable evidence: `compile-round1.json`, `core-selftests-round1.json`, `module-inventory-round1.json`. Raw local logs/JUnit: `.tmp/qa-lab-round1.*`, `.tmp/qa-ai-response-round1.*`, `.tmp/qa-module-chill-round1.*`, `.tmp/qa-lab-regressions-round1.*`, `.tmp/qa-mtm-round1.*`, `.tmp/qa-selfcheck-round1.txt`. Logs are diagnostics, not host trust or protection attestations.

## R1-QA-01 — Lab completion can disappear during progress-queue race — REPORTED

Component: `src/angerona/gui/analysis_lab.py`, `AnalysisLabPanel._start` worker final-outcome delivery.

The worker catches `queue.Full`, then unconditionally calls `pending.get_nowait()` before retrying its completion message. The GUI can drain progress after the producer observes Full and before that removal. The removal then raises `queue.Empty` outside the worker's exception handling. The final result is never delivered, `_busy` stays true and controls remain disabled. This is a real concurrent schedule, independently reproducible without starting a thread, VM or network request.

Pending gate:

`tests/test_deep_review_round1_lab_regressions.py::test_final_outcome_survives_progress_drained_after_full`

Baseline failure: `_queue.Empty` at the final-result eviction path. The test supplies a deterministic queue that models the GUI's legal concurrent drain, then requires final result delivery and restored controls.

Recommended remediation: tolerate concurrent emptiness during best-effort progress eviction and retry final-result insertion; retain bounded queue behavior. Root/patch applier owns production edits.

## R1-QA-02 — Retired Memory Time-Machine sweep writes closed ring — REPORTED

Component: `src/angerona/modules/memory_timemachine.py`, `MemoryTimeMachineModule._sweep`, `stop`, `_SpscRing.close`, `stats`.

`stop()` signals the generation and immediately closes its mmap ring. `_sweep()` checks stopping before each process, but not after potentially blocking `_process_strings()` returns. If Stop happens during that call, the sweep can still admit a new triage payload, commit dedupe state, increment forwarded counters and push to the already-closed ring. With the real ring, write failures are caught as collection failures; the later `stats()` ring-depth access is outside that catch and can raise on the closed mmap. A routine Stop/Chill transition can therefore leave late activity and a retiring-worker crash.

Pending gate:

`tests/test_deep_review_round1_module_lifecycle.py::test_memory_sweep_does_not_admit_late_work_or_write_retired_ring`

Baseline failure: the fixture recorded a push with `closed=True` after cancellation. It uses fake psutil, an inert metadata string and a fake ring; no native process memory was read. It additionally requires no queued late payload and no late emitted activity once remediation reaches those assertions.

Recommended remediation: generation-owned ring cleanup in the worker, cancellation checks after collection and before admission/publication, and safe closed/unavailable-ring observations. The patch applier owns implementation; the performance bot owns broader collection costs.

## Adversarial AI and response checks

The passing new control `tests/test_deep_review_round1_lab_regressions.py::test_hostile_ai_or_tool_error_is_literal_text` feeds HTML and an instruction to execute a command through a tool-error outcome. The status remains explicit Qt PlainText, the message stays literal, readiness is false and Run remains disabled. No text is executed.

Focused passing files:

- `test_ai_triage_readiness.py`
- `test_ollama_transport.py`, `test_ollama_process_attestation.py`, `test_ollama_registered_install.py`, `test_ollama_transport_inventory.py`
- `test_combat_response_readiness.py`, `test_semantic_response_contracts.py`, `test_adversary_combat_boundaries.py`
- `test_cycle26_source_authority.py`
- `test_module_review_patches.py`, `test_machine_module_usage.py`, `test_module_poll_efficiency.py`
- `test_chill_ui_idle.py`, `test_chill_live_idle_io.py`, `test_headless_chill_runtime.py`

These cover forged/unsigned request identities, worker-time policy rechecks, semantic response eligibility, observer/remote evidence boundaries, missing or untrusted Ollama listener diagnosis, missing model versus transport error distinctions, and attestation requirements. They do not establish that the operator's current listener, model baseline, approved source evidence or action journal is ready. This bug hunter performed no actual-host inference or mutation and found no failing Ollama/automatic-response regression in this first pass; the parent is separately inspecting sanitized current runtime evidence.

## Limits and follow-up

- Existing self-tests that report an optional/stopped or unsupported state remain SKIP, not live-sensor passes. The SelfTestRunner's displayed total is 67 passes because it includes the separate EventBus check.
- No syntax errors occurred, so no fresh-path revalidation was needed; no mount artifact is alleged.
- The initial MTM fake-ring fixture lacked `depth`; that fixture omission was corrected before recording the real stopped-write assertion failure. It is not an Angerona defect.
- Existing Lab tests cover schema/size bounds, cancellation, inert source copying, job transaction exclusion and native job limits. They do not exercise a real VMware run; that remains a separately authorized integration step.
- Do not weaken either regression to make a baseline pass. Run these tests, relevant existing lifecycle/UI tests and compile after the corresponding fixes; run the full suite only after combined edits stabilize.

**Totals: 384 files compiled; self-tests 90 passed (66 modules + 24 core), 0 failed, 18 expected module skips; selfcheck 26/26 passed; 0 production bugs fixed by this agent, 2 reproduced defects reported.**
