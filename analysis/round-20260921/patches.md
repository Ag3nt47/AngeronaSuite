# Reported module fixes — 2026-09-21

The patch applier changed only the seven assigned modules and added
`tests/test_module_review_patches.py`. Changes address the adversary and bug-hunt
findings recorded in this session. Historical `analysis/loop/state.json` names
the already completed cycle34; its historical findings were not relabeled.
The parent owns the current consolidated log, full-suite validation and publication.

| Finding | Change | Compile | Self-test / regression gate | Status |
|---|---|---|---|---|
| R20260921-01 | `network_protocol_decoder.py`, `provenance_graph.py`, `flight_cache.py`, `speculative_triage.py`: retained callbacks reject stopped admission; closed MEMC rejects before serialization; SPEC binds callback admission to the original stop token and clears pending/cached work at explicit stop and generation cleanup. | PASS | Module self-tests PASS; disabled callbacks, restart subscription deduplication, zero closed-cache serialization, callback/stop race, in-flight prewarm retirement and watchdog replacement regressions PASS. | FIXED |
| BH-01 | `amsi_bridge.py`: serialize native scan/close with one context lock; worker `finally` owns cleanup, keeping GUI stop nonblocking and the context alive until scans return. | PASS | Blocked native scan vs stop and concurrent self-test scan vs close fixtures PASS. AMSI self-test with inert native success fixture PASS. | FIXED |
| BH-02 | `amsi_bridge.py`: derive fallback from each initialization result, including successful recovery; stop interrupts the polling body before another bus drain. | PASS | Successful reinitialization from fallback and cleanup regression PASS; inert AMSI self-test PASS. | FIXED |
| BH-03 | `api_patch_detector.py`: cap suppression at 1,024 entries with 300-second monotonic expiry; bind remote keys to creation time from the same process handle used for memory reads; rearm an export only after an actual clean comparison. Unknown remote birth identity cannot suppress an alert. | PASS | Real read-only ntdll parser self-test PASS; clean/reintroduced hook, repeated active hook, PID reuse, expiry, capacity, unknown identity, incomplete scan and process-handle identity regressions PASS. | FIXED |
| BH-04 | `canary_drill.py` plus the callback modules above: stop callbacks before event parsing; Canary no longer advances telemetry liveness while disabled. Pure offline analysis helpers remain usable. | PASS | Stopped event-access rejection PASS for all five consumers; Canary strict ETWG echo/telemetry contract self-test PASS in an inert readiness fixture. | FIXED |
| BH-06 | `amsi_bridge.py`: native failed HRESULT and closed context raise errors instead of returning CLEAN; running self-test reports failure and script scan errors degrade health. | PASS | Negative HRESULT, closed context and successful CLEAN fixtures PASS. | FIXED |

R20260921-02 (staged-start authority) is assigned to the parent, and BH-05
(entropy self-test temporary-directory cleanup) to the performance agent.
They are not included in this patch applier's closure count.

## Validation

- `py_compile` succeeded for all seven changed modules and the new test file.
  No stale/truncated-read workaround was needed.
- **87 tests passed**, no skips/failures, in **12.15 seconds** across the new
  20-case regression file and eight adjacent test files:
  `test_cycle28_api_patch_coverage`, `test_cycle29_canary_durable_pipeline`,
  `test_detector_observations`, `test_session_efficiency`,
  `test_cycle3_round1_performance`, `test_cycle30_speculative_triage_contract`,
  `test_cycle4_round3_lifecycle`, and `test_lifecycle_backpressure`.
- NDRD, PROV, SPEC and MEMC self-tests passed their synthetic logic/SQLite
  checks. APID parsed all seven required ntdll export prologues from disk.
- AMSI's success self-test used an inert native-return fixture; blocked-scan,
  HRESULT failure and closed-session regressions used fake native functions.
  Canary's strict echo contract ran with an inert readiness fixture. These
  checks are not claims of live antivirus or Windows process-event coverage.
- `git diff --check` passed. No tests disabled a production security control,
  started native AMSI scanning, called a model, or mutated host defenses.
  The existing explicit opt-in gate for in-process AMSI remains unchanged.

Interpreter: `D:/local-security-ai/AngeronaSuite/venv/Scripts/python.exe`, with
`PYTHONPATH=D:/local-security-ai/AngeronaSuite-module-review-20260921/src`.

Lifecycle boundary: entry guards stop further retained-callback work after
disablement. A short synchronous callback already admitted before stop may
finish. SPEC additionally rejects a callback that finishes parsing after its
generation retires and drops any model result returning after retirement.
An already dispatched model request may finish its existing bounded timeout;
it cannot populate the replacement generation's cache.
