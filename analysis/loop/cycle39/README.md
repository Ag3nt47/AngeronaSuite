# Cycle 39 — Scan Center and flight-cache bounded work

Date: 2026-10-01. Baseline: `e4f0ad1a8b22cc7dc4838db4529d2f659205b3bf`.

This maintenance pass extends the previous security/performance repairs with
six reproduced Scan Center failures and a fresh staged-start mode witness.
It does not establish universal stability or complete Red Team detection.

## Reviewed repairs

- Local file-read and YARA scan errors now produce `limited` coverage rather
  than `completed`. Findings remain available; coverage errors remain bounded.
  Denied directory/entry inspection also marks traversal incomplete, with a
  bounded error summary and an unreadable-entry metric.
- A per-file signature cap reports incomplete coverage. Iteration consumes at
  most 32 matches rather than materializing an arbitrary iterable before slicing.
- Passive listener, interface and interface-address loops also slice before
  materialization. The operating system's own inventory call can still allocate
  or block; these changes bound Angerona's subsequent iteration/copies.
- Scan workers detach scanners and native match/result aliases in `finally`.
  Interrupted scanner configuration also detaches its scanner before propagation.
  A retained traceback therefore does not keep these thread-bound objects alive
  after their worker exits. This extends the prior background YARA lifecycle fix
  to the independent on-demand Scan Center service.
- Scan Center displays “Coverage incomplete” and bounded coverage errors.
  Cancellation no longer claims a Defender child was stopped for every operation.
- The optional flight cache serializes event details before taking its database
  lock, retaining closed-cache admission checks. Queries reject work beyond
  50,000 SQLite VM operations or results beyond the configured cache row cap.
  The query progress handler is cleared in `finally`; rejected queries leave
  subsequent writes and normal queries working. These are operation/row bounds,
  not wall-clock or individual SQL-function allocation guarantees. Durable
  recording and response evidence do not use this ephemeral query contract.
- Periodic module-panel projection now coalesces requests and yields Qt after
  at most eight rows or a cooperative four-millisecond batch budget. Complete
  row projections render together. Explicit filters/refreshes cancel pending
  batches; toggles and close cancel them too. Discovery/replacement changes
  restart the projection before publishing stale rows. One provider can still
  overrun the budget, and final Qt rendering remains synchronous.

## Verification

Six failure-injection challenges were executed against the published baseline
module loaded separately from the working source. All six baseline assertions
failed as expected; the candidate passes all six. Cases cover unreadable files,
signature engine exceptions, retained result-provider tracebacks, bounded match
enumeration, interrupted native scanner setup and unreadable directory traversal.
Ownership stand-ins model Rust
methods without Python `self` frames; they are not real attack efficacy tests.
Scratch evidence: `.tmp/cycle39_baseline_challenge.json`.

Expanded service, UI, FIM liveness and YARA lifecycle validation: **43 passed,
2 skipped**. The match iterator deliberately raises if the consumer advances
beyond 32 entries. The UI check asserts visible incomplete coverage and error
details. This is a bounded-work improvement, not a measured whole-app speedup.

Flight-cache regression/performance checks: **35 passed**. Three additional
challenges fail against the published baseline: a recursive aggregate, an
expanding cross join and an intentionally blocked serializer that prevents an
unrelated reader from acquiring the old cache lock. All pass after the repair.
Scratch evidence: `.tmp/cycle39_cache_baseline_challenge.json`.

Module-panel, runtime-reader and dashboard checks: **29 passed**. An injected
slow row provider confirms heartbeat callbacks execute while a coalesced
projection is still pending; ten requests produce one row pass. Discovery
changes restart projection and explicit refresh prevents stale later writes.

## Running-mode witness

The 66-selected-worker staged-start witness completed approximately 90 seconds
each in initial Chill / Full / returned Chill. Maximum heartbeat slips were
**683 / 793 / 2152 ms**, p99 **214 / 183 / 309 ms**, with **0 / 0 / 4** gaps
over one second. The async recorder drained **1482/1482** accepted events;
shutdown was clean. Returned Chill remains demonstrably slow. Module-panel
refresh reached 1266 ms and the flight-cache event subscriber accumulated
76 delivery-budget violations in that phase. Elapsed callback timing includes
scheduler/GIL delay and does not prove exclusive CPU attribution.

This witness preceded the final cache changes; it has no simultaneous separate
Qt control. Earlier control measurements are not reused as this run's control.
Brief focused tests overlapped parts of the witness, so it is not an unloaded
production comparison. Source mode startup used staged first cycles, before
starting the heartbeat; it does not measure production boot-worker responsiveness.
Evidence: `.tmp/cycle39_production_start_soak_result.json`.

The final combined cache/panel/Scan Center source then completed a separate
90-second-per-phase simultaneous-start stress run without heavy concurrent
tests. Maximum slips were **5809 / 1495 / 605 ms**, p99 **746 / 214 / 167 ms**,
and **9 / 1 / 0** gaps over one second. The simultaneous separate Qt process
peaked at **58 ms** with no long gaps. This confirms application-specific
pauses remain in initial Chill and Full; returned Chill's short result does
not prove sustained stability. Startup staging differs from the earlier run,
so no direct whole-application speedup is claimed.

The recorder persisted **1051/1051 primary accepted events** and its workers
stopped. Four late shutdown events took the durable synchronous spool lane;
three replayed and one 1119-byte spool segment remained. Therefore “workers
drained” is not evidence that all late events reached the primary ledger.
The fixture closes additional GUI workers after stopping the recorder; this
ordering limits conclusions about production shutdown. No YARA ownership error
appeared in this run. Evidence: `.tmp/cycle39_final_mode_soak_result.json`,
`.tmp/cycle39_final_qt_control_result.json`, `.tmp/cycle39_final_soak.log`.

The fixed exact-commit gate includes bytecode compilation, dependency audit,
documentation drift, lint and the full test suite. Completion additionally
requires guarded GitHub publication and byte-identical public README assets.

## Remaining limits

Earlier native Red Team coverage varied despite successful signed containment;
this pass does not change credit rules or claim a new simulation score.
The staged-start mode fixture waits for startup before beginning its heartbeat,
whereas production uses a boot worker. It measures running-mode behavior only.
Its selected modules and disposable roots retain the earlier fixture exclusions;
it cannot certify physical-host, all-module or all-day responsiveness.
