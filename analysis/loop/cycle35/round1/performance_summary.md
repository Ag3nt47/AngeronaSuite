# Cycle 35, Round 1 — Performance

## Applied: deny ordinary process receipt requests before full lease validation

**Component:** `src/angerona/modules/purple_guard.py`, `_ProducerReceiptCapability.issue_process_observation`.

**Problem:** During a live Red Team drill, Process Monitor offers every observed host process to its bound validation receipt capability. Before this change, a process with no enrolled challenge still reached `RedTeamValidationLease._state_matches()` before the final `not identity` denial. That lease check reopens and validates every retained `_redteam_*.txt` marker, plus policy and recorder state. The September 23 failed campaign left 68 markers in the local drill target. Thus an ordinary process inventory could cause hundreds of unnecessary full target scans per cycle. The captured live run reported a Process Monitor watchdog restart at run+43.24 s, with its last cycle 36.3 s old; this mechanism is consistent with that delay, although the captured record does not isolate every contributing host cost.

**Change:** Return `{}` immediately when the process command has no Red Team challenge token. If a token is present but the exact enrolled PID/birth challenge validator returns no identity, return `{}` before `_state_matches()`. A challenge that can receive a receipt still passes the same producer, lifecycle, EventBus, policy, target, recorder, and lease checks before signing. Process Monitor still observes and publishes its ordinary process telemetry; its detection cadence and rules are unchanged.

**Measured improvement:** A five-repeat, inert 100-process fixture with 68 temporary 600-byte marker files measured a median **1,832.75 ms before** and **0.49 ms after** for the denied receipt path. The fixture's full-target callback ran **100 times before and 0 times after**. It simulates marker file open/hash work and isolates this call path; it does not measure whole-app CPU, actual lease verification, or native disk behavior. A separate post-fix, read-only Windows Process Monitor Combat-mode cycle with 238 tracked processes and the same 68-marker callback completed in **3.09 s**, with zero full-target checks, against its **30 s** watchdog work budget. Its cadence sleep was mocked out. Direct rich process enumeration on this host took 2.90 s cold and 0.10/0.095 s warm across 247 processes; no detector or full GUI was launched for these measurements.

**Gate:** `py_compile` passed for the changed module and focused test. Purple Guard and Process Monitor `self_test()` both passed. `tests/test_module_poll_efficiency.py` passed **14/14**, including a new regression proving no-token and unenrolled nonce-shaped rows never call the full lease check while an enrolled challenge does and produces a verifiable signed receipt. `tests/test_cycle27_redteam_simulation_fifth_independent_reattack.py` passed **12/12**. An adjacent suite passed **16 tests** and failed one newly added live scoring regression: it recorded 13 validated detections but only one verified Combat response within its 20 s wait. That response/custody failure remains under separate remediation and is not represented as fixed by this performance change.

**Status:** **APPLIED**.

## Proposed: bound Purple Guard's repeated orphan-marker validation

**Component:** `src/angerona/modules/purple_guard.py`, `scan_once()` and `_validation_target_markers_safe()`.

**Problem:** A marker that cannot be attributed to the active lease is deliberately left retryable. With 68 orphan markers, each one can invoke a full scan/hash of all 68 markers on every Purple Guard cycle, approximately 4,624 marker visits before other lease checks. The captured run later restarted Purple Guard after a 34.4 s missed cycle. The exact process-to-cycle attribution has not been timed on the physical host.

**Proposed change and expected win:** Design a bounded, coherent custody validation pass that can avoid repeated whole-directory reads while still checking every current marker identity/content at the point a receipt is granted. A simple mtime cache or skipping unrelated marker validation could accept an alias or same-stat content replacement, so neither is applied. The expected win is to reduce redundant marker opens from quadratic toward linear in the number of retained markers, subject to adversarial race tests and the module self-test.

**Gate/status:** No code changed for this proposal; security-equivalence gate remains open. **PROPOSED**.

## Dashboard and remaining measurement boundary

The two-second SOAR panel refresh requests an `AsyncSnapshot`; queue parsing, copying and hashing occur on its worker, so this path is CPU work but does not itself block Qt for that parse. The dashboard's module assurance pass runs on Qt; an isolated 84-module pure-function fixture measured a median **3.96 ms** per pass. Neither result justifies a speculative cache that could stale live health, source provenance, or response presentation. No GUI or shared sensor code was changed in this round.

The reported Chill/Full physical-host slowdown and freeze remain to be measured with the application's runtime tick/stack diagnostics under both modes after this fix. The process receipt optimization specifically removes redundant work during a validation lease; it does not establish an all-day idle-load improvement. No detection path was throttled and no watchdog deadline was relaxed.

| Optimization | Component | Status | Expected or measured win |
| --- | --- | --- | --- |
| Early deny for unenrolled process receipts | Purple Guard validation capability | APPLIED | 100-process, 68-marker fixture: 1,832.75 ms to 0.49 ms; full-target checks 100 to 0 |
| Coherent bounded marker custody validation | Purple Guard marker scan | PROPOSED | Reduce approximately quadratic repeated marker reads without losing current alias/content checks |
