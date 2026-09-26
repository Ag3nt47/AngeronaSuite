# Cycle 35, Round 2 — Performance

## Reproduced: process snapshot contention when enumeration exceeds its TTL

**Component:** `src/angerona/telemetry/sensors.py`, `process_snapshot()`; affects concurrent consumers including Process Monitor in Full mode and live sentinels in Chill mode.

**Problem:** The process cache deliberately dates evidence from the **start** of enumeration. The first caller holds `_proc_cache_lock` until the OS scan finishes. If that scan takes longer than the caller's maximum age, every waiting caller sees the just-completed result as expired and performs another full scan while holding the same lock. A deterministic eight-thread fixture with a 50 ms inert `process_iter` and a 10 ms maximum age performed **eight serialized scans in 0.409 s**. This reproduces the contention mechanism, not the user's physical-host idle load. The normal cache default is 1.5 s; Process Monitor asks for 0.5 s during Combat, so ordinary warm Windows enumerations measured previously at about 0.1 s will not hit this edge, while a slow cold or pressured enumeration can.

**Proposed change and expected win:** A completed in-flight scan could be shared among callers that were already waiting for it; the fixture would then use one scan. However, a process created after that scan passed its PID may be visible to a later queued caller only if that caller performs its own fresh enumeration. Coalescing such calls can delay a detection until the next poll. The existing start-time age is an explicit security guard, so no cache-freshness or polling change was applied. A future design needs a bounded scan scheduler and a security-equivalence test for process births during a slow scan before this optimization can be accepted.

**Gate/status:** Deterministic read-only reproduction; **PROPOSED**, no production code change.

## GUI event-loop investigation

Current dashboard timer work is partitioned by presentation cadence: active Full mode requests cosmetic panels every 2 s, quiet Chill every 10 s; the incident wake remains event-driven. The SOAR queue parse/copy/hash, alert ledger reads, security policy snapshot, posture calculation, and flow-metrics write already use background workers. The July `diagnostics/not_responding.log` shows synchronous table and SQLite stacks, but the corresponding current readers are asynchronous, so those historical stacks cannot establish a current freeze.

An isolated offscreen Qt fixture with 84 inert modules measured unchanged `ModulesPanel.refresh()` at **5.06 ms median** and one changed health row at **12.04 ms median** (20 trials; changed maximum 20.71 ms). An isolated 500-record SOAR panel measured first population at about **226 ms**, an unchanged fingerprint at **0.006 ms median**, and one changed status record at **24.77 ms median** (10 trials; maximum 28.71 ms). The 500-row initial population can miss several frames, but neither steady-state fixture reproduced a multi-second stall. Queue presentation is bounded to 500 records. These fixtures do not include the full application, physical display driver, SQLite contention, or a real Chill/Full transition. No Angerona process was running during this audit, so sustained CPU and actual event-loop latency in both modes remain unmeasured.

`MainWindow._enter_eco()` calls `stop()` on its Chill-paused modules on Qt, while the ordinary `BaseModule.stop()` only signals the worker and returns; Full-mode wake runs in `EcoWakeupWorker`. Some modules override `stop()`, and those were not individually timed under a live transition. The visible steady-state refresh path did not support a safe speculative GUI rewrite. The UI files were transferred to the separate UI worker for a confirmed settings/readiness fix.

**Gate/status:** Read-only fixtures and static review; no production code changed, so no compile or module self-test gate was needed. **INVESTIGATED**.

| Optimization | Component | Status | Expected or measured win |
| --- | --- | --- | --- |
| Security-equivalent scheduling of concurrent slow process scans | Shared process evidence cache | PROPOSED | Inert 8-caller edge: potential 8 scans to 1; detection-latency proof required |
| Incremental SOAR row updates if live profiling identifies frame loss | SOAR panel | PROPOSED | Isolated one-row-change redraw currently ~25 ms for 500 records; no current multi-second stall reproduced |
