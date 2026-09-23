# Security GUI wake admission — performance round 2

Date: 2026-09-23. Scope: MainWindow's security wake gate and existing
`AsyncSnapshot` initialization/completion plumbing only. Ollama, ordinary GUI
panels, source authentication, sensors, defense authority and module cadences
were not changed by this review. The all-84-module cadence inventory remains
in `module-cadence-round1.json`; it was not repeated.

## Finding

The prior gate cleared `_security_wake_pending` as soon as a queued Qt wake
handler began, before its asynchronous classifier completed. A stream of HIGH
events interleaved with Qt dispatch could therefore enqueue another wake for
every event while the same reader was blocked. `AsyncSnapshot` bounded reader
work, but the earlier bridge still multiplied Qt callbacks and the handler's
USB/presentation reconciliation work. An adversarial event flood could exploit
that unnecessary GUI work without producing additional useful classifications.

## Applied change

One lock now protects the gate across the initial queued callback and the full
read. Arrivals during a pending read set one dirty-follow-up flag. Completion
starts one follow-up read immediately through the existing reusable worker.
Requests from the existing presentation timer use the same admission gate.
Concurrent publishers cannot both pass an unlocked check/set pair.

The follow-up reads the existing authoritative EventBus revision delta. The gate
stores no event payload or unbounded backlog. Every retained event still reaches
the same classification, USB and Chill-policy code; priority-ring overflow stays
explicit. The first serious event still requests immediate Qt wake. Events that
arrive while classification is blocked are read as soon as that worker completes.
Deterministic detection and response operate independently of this GUI path.

Failed reads preserve the existing cursor. When new demand arrived during a
failed read, a single queued retry avoids synchronous recursive retry on repeated
prepare/start failures. Without fresh demand, the next event or existing
presentation refresh retries, as before. Fresh preparation also clears demand
covered by an AsyncSnapshot generation retry, preventing an extra third read.

Destruction/application quit closes the gate and reader without waiting for I/O.
Late bus callbacks cannot emit into a deleted Qt owner, and a blocked old worker
cannot apply its result after destruction. Cleanup disconnects its application
quit callback so destroyed owners do not leave that registration behind. No new
worker, polling timer or periodic wake was added.

Status: **APPLIED**.

## Reproduction and validation

`tests/test_security_wake_backpressure.py` contains an executable reference of
the prior clear-before-request gate beside the changed gate. Both use the same
inert blocked reader and offscreen Qt dispatch. The comparison publishes an
initial HIGH and then 1,000 more HIGH events, processing Qt events after each.

| Identical blocked-reader workload | Prior gate | Changed gate |
| --- | ---: | ---: |
| Dispatched Qt wake callbacks | 1,001 | 1 |

The changed-gate preservation fixture additionally interleaves 1,000 INFO events
with 1,000 new serious events. A 64-entry general ring and 2,048-entry priority
ring exercise general-history overflow and retained security-event recovery.
All **1,001 serious events** are classified in exactly **two reads**, the same
worker is reused, the cursor reaches the current bus revision, and the reader
timer stops when work completes. INFO-only traffic creates neither a security
wake nor a reader thread. Eight concurrent publisher threads still produce one
initial queued wake.

Other regressions cover a failed blocked read followed by exactly one retry,
prepare failure, thread-start failure, generation invalidation without stale
application or an extra follow-up, and destroying the owner while its reader is
blocked. After destruction, another 1,000 CRITICAL publications produce no GUI
dispatch or result application, and the old worker exits when its inert fixture
is released.

Final focused validation: **21 tests passed** across the new regression file,
`test_chill_ui_idle.py`, and `test_dashboard_snapshot_refresh.py` in 5.87 seconds.
The two existing fixtures now initialize the shared gate/status plumbing;
their original behavior assertions remain. All four Python files passed
`py_compile`, scoped Ruff and whitespace checks. No full application, live sensor, model, native defense
or physical-host soak was launched. Tests used the worktree `.tmp` runtime root
and offscreen widgets; this is a deterministic dispatch-work reduction, not a
whole-PC CPU or multi-hour memory measurement.

| Optimization | Component | Status | Expected/measured win |
| --- | --- | --- | --- |
| Hold admission gate through async completion | Security event-to-Qt bridge | APPLIED | 1,001 queued callbacks reduced to 1 in the blocked-flood fixture |
| One dirty follow-up using the existing worker | Security classifier | APPLIED | Two reads cover all 1,001 retained serious events; no extra thread/timer |
| Close retained callback gate and quit registration | Security reader lifecycle | APPLIED | No late dispatch/result after owner destruction |
