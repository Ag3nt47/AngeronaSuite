# Sustained responsiveness follow-up — 2026-10-04

## Evidence and scope

The operator reported that both the dashboard and the host could become slow
after running for a while. No live Angerona process was available for profiling
during this investigation. Existing local watchdog diagnostics nevertheless
recorded approximately six-second GUI stalls while constructing System Pulse
details and while reading the simulation console's sandbox editor.

The System Pulse detail table has four rows. Repeated isolated open/close checks
did not show growing widget counts. Its construction slowed under synthetic
Python-thread contention, so a sampled table-insertion frame alone does not
establish a table-size or layout defect. No cosmetic redesign was made.

An isolated Memory Time-Machine workload reproduced a concrete cache cliff:
256 PIDs with three unchanged strings forwarded nothing on repeat sweeps;
257 PIDs forwarded all 771 strings again on every sweep. Sequential enumeration
continually evicted the next PID from the 256-entry cache. The same defect
produced 960 redundant forwarded strings per sweep for 320 PIDs.

## Changes

- Adaptive routine scan pacing defaults to enabled, including for legacy config
  files. A bounded 30-Hz Qt paint heartbeat and existing System Pulse CPU samples
  drive hysteresis at interval multipliers 1, 2, 4 and 8. Missing visible feedback
  is detected even before the first measured frame. Hidden/minimized/destructed
  dashboards clear the UI lease; recent CPU pressure can still pace background
  work. Prolonged missing UI feedback falls back to conservative 2x.
- FPS and its percentage of the 30-Hz target appear in the footer beside an
  Angerona pace bar. The bar is 100 divided by the requested multiplier; it does
  not claim a CPU quota, measured throughput or security coverage percentage.
  CPU remains an independent host metric. Settings > Appearance offers opt-out.
- Opted-in process/network inventories, YARA, Memory Time-Machine and memory
  injection scans receive interruptible waits. FIM full-file and Sysmon fallback
  intervals use specific pacing points without changing their fast event paths.
  File hashing and memory-region walks yield within long passes. Added interval
  delay is capped at 30 seconds; batch waits at 50 ms. Independent governors use
  the greater delay rather than multiplying their factors. Healthy feedback
  restores one level every eight seconds.
- Memory Time-Machine retains a wider, bounded PID index without increasing its
  aggregate fingerprint limit. Repeated observations stay deduplicated on
  ordinary hosts with more than 256 processes. Long-string fingerprints stay
  associated with their original observation even when the queued payload is
  truncated. Failed queue admission remains retryable. Completed inventories
  retire absent OS PIDs; failed inventories and overlapping synthetic self-tests
  preserve their cache state.
- Opening the simulation console no longer initializes an unvisited Sandbox
  Editor. Selecting that tab initializes and reads its protected working copy
  on a background worker. Reload, save, and confirmed rollback use the same
  serialized worker; overlapping requests are rejected while busy.
- Editor buffers and Qt controls remain on the GUI thread. Errors retain the
  existing buffer, show a failure status, and keep the original source-sandbox
  checks. Saves still syntax-check and write only the isolated working copy.
  Closing the cached dialog allows an authorized operation to finish; destroying
  its owner stops result delivery and releases the worker when its task returns.
- Full-suite validation exposed a native Qt lifetime bug in floating-orb
  minimization. An isolated GUI-only reproducer minimized/restored/deleted a
  window before its queued callback ran, then triggered a pure-virtual paint
  error and access violation during later garbage collection. The callback is
  now bound to its target's Qt lifetime, holds weak references and rechecks
  native validity and minimized state. Ten repeated deletion/paint/GC cycles
  run in a subprocess regression; GC and assertions remain enabled.

## Validation

Initial cache/editor regression selection passed all 58 tests and the offline
self-check passed 26 phases. Expanded pacing, UI, inner-loop, configuration and
module-audit regressions are recorded in the [complete review](module-review-2026-10-04/README.md).
Synthetic screenshots were inspected in Standard and Orbital display, and the
footer was checked at 480 pixels and desktop width. Tests use inert inventories,
isolated working copies and mocked host mutations. Exact-commit CI results are
recorded by GitHub Actions.

## Limits

The cache reproduction proves avoidable repeated work, not an overall CPU or
frame-rate percentage. The recorded watchdog stalls and synthetic contention
measurements do not identify every source of host load. Live sustained-session
responsiveness after restarting the updated application still needs observation.
Routine intervals deliberately increase under pressure, so discovery latency
may increase. Event delivery, streaming telemetry, signature verification,
response authority gates and watchdog cadence are excluded from this controller.
Cooperative pacing cannot preempt a blocked native call or guarantee that other
applications leave enough CPU available. No all-sensor elevated soak was run.

Private runtime logs were read locally; none are included in this update.
