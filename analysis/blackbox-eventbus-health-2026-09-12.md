# Black Box event-bus health correction

Black Box previously treated writes to status, flow, memory-map, or database
files as proof that the event bus was moving. A fixed 20-second timeout also
classified a running process as frozen, even though the status reporter can
intentionally wait 30 seconds between unchanged reports, or 60 seconds in Chill
mode. Standalone Black Box still defaulted to the obsolete checkout runtime
folder, and process discovery matched unrelated helpers whose paths contained
"Angerona".

The recorder now resolves the same runtime path as the application without
creating or hardening application state. Process discovery recognizes the core
entry point. Health assessment uses a complete status snapshot tied to the
observed PID and process start time, with freshness derived from the advertised
report interval. Missing, old, or malformed diagnostics do not establish a
deadlock. File modification times from other components cannot establish bus
activity.

The event bus delivers callbacks inline; it has no dispatcher heartbeat.
StatusReporter now exports the bus revision and cumulative subscriber delivery,
failure, and callback-budget counters. Black Box distinguishes observed,
advancing, and quiet counters and retains recorded callback issues as advisory
history. These diagnostics do not confer response authority or prove sensor
coverage. Unchanged reports retain their bounded quiet-mode write cadence.
Atomic replacement keeps the previous complete status file readable until its
replacement is ready; concurrent final/periodic writes are serialized.
Archive & Clear now copies diagnostic snapshots (at most the last 4 MiB per
file) into the recorder archive and leaves live status/log files in place.

On inspection, the core was not running. The last saved application self-test
(September 10) reported unavailable Ollama/model and Defender telemetry
dependencies. Those historical dependency failures are separate from the
recorder's bus-health classification and are not repaired or cleared by this
change.

Validation covers runtime-path resolution, core/helper process identification,
process-bound freshness, normal/Chill quiet periods, malformed diagnostics,
callback-failure evidence, atomic replacement, and preservation/retry after a
failed write. Existing event-bus and telemetry-status tests are included.

Verified results:

- 79 focused tests passed in a separate checkout containing only this fix.
- Ruff and Git whitespace checks passed for the changed Python files.
- Package compile check: 382 files, zero failures (includes pre-existing local
  analysis-lab additions, which are excluded from this publication).
- Isolated application selfcheck: 26 phases passed, zero failures. Module
  self-tests: 68 passes, 16 expected skips, zero failures, plus event pipeline
  PASS. Optional/offline/platform skips do not establish live dependency health.
