# Cycle 35, Round 3 — Performance

## Applied: keep Packet Sniffer child teardown off the Qt thread

**Component:** `src/angerona/modules/packet_sniffer.py`, `PacketSnifferModule.stop()` and `_terminate_worker()`.

**Problem:** `MainWindow._enter_eco()` calls `stop()` for all 19 Chill-paused modules on the Qt thread. Packet Sniffer is an optional member of that set. Its override used to call `Popen.terminate()` then `wait(timeout=1.5)` and, on timeout, `kill()` then another `wait(timeout=1.5)` synchronously. An isolated offscreen Qt fixture with a bounded, unresponsive capture-child stand-in reproduced a **3,000.8 ms** `stop()` call and a 10 ms Qt timer firing **2,990.9 ms late**. This proves an event-loop freeze is possible when the optional sniffer is enabled and its child does not stop promptly. It does not establish that this module caused the user's all-mode freeze on their physical host.

**Change:** `stop()` now signals the existing module generation immediately and hands that **exact** child to a non-daemon reaper for the same bounded terminate → wait → kill → wait cleanup. The capture thread still cleans up the child in its `finally` block before its generation can exit and a restart can launch a replacement. A termination lock serializes these two cleanup paths; the worker pointer is cleared only if it still refers to the retired child. The reaper attempts force-kill even if graceful termination raises. The non-daemon reaper keeps shutdown cleanup alive after the Qt event loop exits.

**Measured improvement:** Repeating the same full-timeout offscreen fixture after the change measured **1.0 ms** for `stop()` and a 10 ms Qt timer running on time (approximately **−0.2 ms** scheduling error). The reaper still spent the configured time completing child cleanup in the background. A separate real, hidden Python child fixture was terminated and its pointer eventually cleared after `stop()` returned in **2.03 ms**. These are isolated fixtures, not whole-app frame or CPU measurements.

**Gate:** `py_compile` passed for the changed module and focused test. `PacketSnifferModule.self_test()` passed. Packet Sniffer isolation and delivery suites passed **10/10**, including an offscreen timer regression, a rapid stop→start generation race test, and a termination-failure force-kill test. No capture detection cadence, event type, or worker output protocol changed.

**Status:** **APPLIED**.

## Investigated: Smart Deception's synchronous decoy cleanup

**Component:** `src/angerona/modules/smart_deception.py`, `SmartDeception.stop()`.

This default-enabled Chill-paused module cleans its exact-custody decoys before signaling its worker to stop. An isolated Windows fixture pointed its manifest and decoys exclusively at a temporary directory and exercised the real exact-object deletion path. Three decoys took **13.4 ms**; six took **12.2 ms**; all were removed. Storage pressure or antivirus could make this synchronous path slower on another host, but this fixture did not reproduce a multi-second stall. Moving custody cleanup to another thread without a complete stop/restart identity protocol could race decoy deployment and weaken cleanup guarantees, so no change was applied.

The July `diagnostics/not_responding.log` stacks are historical; those synchronous table and SQLite paths are now asynchronous in current source. Full-mode wake-up already uses `EcoWakeupWorker`; its `cancel()` can briefly wait on a start critical section, whose base lifecycle join is bounded to 0.25 s. A physical-host Chill/Full trace is still needed to attribute any remaining sustained slowdown or freeze.

**Status:** **INVESTIGATED**, no Smart Deception change.

| Optimization | Component | Status | Expected or measured win |
| --- | --- | --- | --- |
| Asynchronous bounded child reaper | Packet Sniffer stop | APPLIED | Worst-case fixture: Qt stop 3,000.8 ms → 1.0 ms; timer delay 2,990.9 ms → ~0 ms |
| Preserve exact-custody cleanup pending physical-host profiling | Smart Deception stop | INVESTIGATED | Temporary 3/6-decoy cleanup ~12–13 ms; no safe change justified |
