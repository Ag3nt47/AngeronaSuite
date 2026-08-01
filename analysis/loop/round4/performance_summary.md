# Round 4 - Performance Summary

## Scope and invariants

This bounded pass targeted long-runtime slowdown in hot polling paths without
changing detection cadence, event content, security verification, or operator
behavior. The historic three-round loop in `analysis/loop/state.json` remains
complete; this report records the next performance continuation as Round 4.

## Applied optimizations

### APPLIED - Purple Guard policy snapshot coalescing

- **Component:** `angerona.modules.purple_guard.PurpleGuard`
- **Problem:** once a drill remediation policy existed, each one-second work
  cycle parsed `purple_guard_policy.json` three times: for health, file-marker
  detection, and process-marker detection.
- **Change:** `work_cycle()` reads one coherent policy snapshot and passes it to
  both detector scans. Direct `scan_once()` and `scan_process_once()` callers
  keep their prior behavior by reading the policy when no snapshot is supplied.
- **Measured improvement:** 2,000 policy reads took 0.656579 seconds. At the
  same measured cost, the hot loop falls from about 984.9 microseconds to 328.3
  microseconds of policy I/O/parsing per active cycle: **66.7% fewer reads**.
- **Security/behavior proof:** all file and process signatures in a cycle see
  one policy version; no signature, cadence, or emitted event was removed.
- **Gate:** focused regressions PASS; Purple Guard `self_test()` PASS.
- **Status:** **APPLIED**.

### APPLIED - EventBus revision gate for unchanged Purple Guard scans

- **Components:** `angerona.core.eventbus.EventBus`, Purple Guard process scan.
- **Problem:** Purple Guard copied and classified the newest 500 events every
  second even when no event had been published since its previous pass.
- **Change:** EventBus now exposes a lock-protected, process-local monotonic
  revision incremented under the existing publish lock. Purple Guard skips only
  when both the revision and enabled technique set are unchanged. A new publish
  always invalidates the gate; buses/test doubles without `revision()` retain
  the legacy full scan.
- **Measured improvement:** 20,000 unchanged scans over a 500-event ring took
  0.062800 seconds with the gate versus 10.587952 seconds for the legacy
  classify walk: **168.6x faster** in this isolated hot-path benchmark.
- **Security/behavior proof:** the token is not trusted as event evidence and
  has no signing/authorization role. Authoritative content still comes from
  `recent()`. Tests prove revision changes only on publish, a newly published
  tagged process is detected, and enabling the process policy rechecks an
  unchanged bus.
- **Gate:** focused regressions PASS; EventBus/Purple Guard compile PASS.
- **Status:** **APPLIED**.

### APPLIED - resident System Pulse sampler worker

- **Component:** `angerona.gui.system_pulse.SystemPulseCard`
- **Problem:** the visible dashboard card created and destroyed one native
  Python thread every two seconds, or **1,800 thread creations per hour**.
- **Change:** one daemon sampler waits on a coalescing event. Existing closed,
  busy, and visibility guards are unchanged; sampling remains off the Qt main
  thread, and shutdown wakes and terminates the resident worker.
- **Measured improvement:** dispatching 1,000 no-op samples through one worker
  took 0.077072 seconds versus 0.529496 seconds with 1,000 fresh threads:
  **6.9x lower dispatch overhead** in the isolated benchmark. Real sampling
  time remains governed by the same `psutil` and bounded `netsh` calls.
- **Security/behavior proof:** sample fields, two-second scheduling, Wi-Fi
  caching, timeout, late-result discard, and Qt signal handoff are unchanged.
  A lifecycle test proves three samples use the same worker and shutdown wakes
  it to a completed exit.
- **Gate:** GUI lifecycle/UI regressions PASS; compile PASS.
- **Status:** **APPLIED**.

## Proposed follow-ups

### PROPOSED - extend revision-aware polling only to proven immutable consumers

Other EventBus snapshot consumers may benefit from the same change token, but
each needs consumer-specific lifecycle and burst tests first. No protection
loop was throttled in this round.

### PROPOSED - bound Purple Guard historical deduplication by event generation

The process deduplication set clears wholesale after 4,096 entries. A bounded
ordered generation-aware cache could avoid a rare duplicate burst after that
clear, but changing retention semantics requires drill/AAR evidence tests and
was therefore not applied in this behavior-preserving pass.

### PROPOSED - separate static status payload work from heartbeat publication

The status reporter regenerates serialized output on its heartbeat cadence.
Caching static sections could reduce long-uptime filesystem work, but the
generated timestamp is an external liveness contract. Apply only after an
explicit compatibility test defines which fields may be reused.

## Verification

- `py_compile`: PASS for all three changed product modules and both new tests.
- Ruff: PASS for all owned changed Python files.
- `git diff --check`: PASS (line-ending conversion warnings only).
- Focused pytest gate: **53 passed in 4.14 seconds** across the new performance
  tests, lifecycle/backpressure, dashboard UI, Purple Guard, and drill
  remediation regression suites.
- Purple Guard module self-test: **PASS** - exact file/process markers detected;
  benign noise ignored.

No detection interval, security control, signature, event, or containment path
was weakened for performance.
