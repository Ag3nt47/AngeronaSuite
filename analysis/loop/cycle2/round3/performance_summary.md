# Cycle 2 / Round 3 - Final Performance Summary

Date: 2026-07-15. Scope: bounded final regression audit of the combined tree
after Round 3 remediation and QA, including non-Eco UI/storage refreshes,
Round 1 SOAR/card caches, Round 2 pending-action TTL retirement, Round 3 token
locking, the shadow preview, drill cancellation, and diagnostic/storage bounds.
No detector cadence, rule, response action, visible GUI structure, runtime
configuration, or host process was changed.

## Applied: make interactive storage refreshes non-blocking

### Production evidence

`diagnostics/not_responding.log` recorded a legitimate 5.4-second production GUI
stall at 21:39:50 with the sampled Python stack waiting in
`DashboardCards.refresh -> FlightRecorder.max_ts -> storage._lock` while 59
production threads were active. The operator clarified that the computer was
put to sleep/woken and Angerona was turned off **after** this entry; those later
host-state changes do not explain or invalidate the 21:39:50 stall.

The stack identified the cause: dashboard timer callbacks used the same lock as
SQLite commits, retention pruning, incremental vacuum, and WAL checkpoints. An
independently controlled contention probe then reproduced the mechanism by
showing that the old GUI query waited for the full duration of a deliberately
held writer lock.

### Change and thread-safety boundary

- `FlightRecorder.revision()` returns the latest committed event id through a
  separate, tiny lock and performs no SQLite work. It is initialized from the
  ledger's maximum id and advances only after the insert commit and any scheduled
  retention work finish. Failed/DLQ-routed writes do not advance it.
- `try_recent()` and `try_count_since()` acquire the existing database lock only
  when immediately available. A busy result is explicit (`None`); no partial
  data is returned.
- `DashboardCards` and `AlertsPanel` use the committed revision as their change
  detector. If the writer is busy they retain the last complete view and retry
  on the next two-second refresh. The durable writer, ordinary blocking query
  APIs, event order, retention, signatures, and detector paths are unchanged.
- Lock order is one-way: a committed writer may briefly take the revision lock
  while already holding the database lock; revision readers never take the
  database lock. User callbacks and detector code do not participate.

### Controlled measurements

A temporary D-drive ledger with 500 representative events was measured under a
synthetic 250 ms writer-lock hold:

- the former GUI-style `max_ts()` query waited **250.407 ms**;
- **10,000** combined `revision + try_recent + try_count_since` busy-path probes
  completed in **10.966 ms** total (about **1.10 microseconds per triplet**) and
  every query correctly returned busy rather than waiting;
- uncontended `revision()` cost **306.4 ns/call** over 100,000 calls;
- a tuned retention probe (`MAX_ROWS=200`, `PRUNE_EVERY=50`) retained **249**
  rows, within the expected hard bound of 250, and the committed revision
  matched SQLite's maximum id (**1000**).

The permanent regression `tests/test_cycle2_round3_performance.py` also holds
the writer lock in another thread and requires the revision and both interactive
queries to return within 50 ms while preserving committed data afterward.

## Final regression audit

### ARIA token lock, pending TTL, and shadow preview

- A representative 5,000-action stage/cancel probe with nested immutable
  arguments and memory tracing averaged **663.63 microseconds/action**, ended
  with **0 pending actions**, and retained **0.037 MiB** current / **0.047 MiB**
  peak traced memory. This includes tracing overhead and ran while another local
  application test was active; it remains below one millisecond and is an
  operator-only path.
- The pure shadow evaluator averaged **63.46 microseconds/evaluation** over
  20,000 nested previews. It remains outside confirmation and host-action
  branches and stores only bounded digest/diagnostic metadata.
- The Round 3 re-entrant lock covers only tool/pending-map mutation. Full UUID
  allocation, TTL retirement, token consumption, and registry invalidation are
  atomic; user callbacks and shadow evaluation remain outside the lock.
- Existing combined gates again passed the Round 2 binding/TTL suite, Round 3
  forced-collision test, seven shadow-policy tests, and all twelve ARIA/research
  self-tests. No deadlock, pending leak, duplicate execution, or material
  regression was found.

### Drills, caches, modules, and bounds

- Both drill cancellation paths retain interruptible waits, bounded joins,
  boundary checks, and final cleanup. The focused cancellation regression passed;
  the unchanged Round 2 100-cycle evidence remains valid (zero surviving Red
  Team or Shark workers).
- The Round 1 SOAR parse cache remains a single 500-row tuple keyed by one file
  identity, and each stat card retains one `(text, color)` tuple. Neither grows
  with uptime; no invalidation or display regression was found.
- Sequential non-Eco wake-up still waits for a real first-cycle boundary and
  offsets later sensor cadences. The lifecycle regression passed. Slowing live
  detectors further was not justified.
- SQLite remains WAL/NORMAL, severity-aware, incrementally vacuumed, and bounded
  near 40,000 rows; watchdog rotation remains one active plus one approximately
  4 MiB archive. No new crash was established. The 21:39:50 storage-lock stall
  is treated as valid production evidence; later sleep/wake, shutdown, and test
  launches are not conflated with it.

## Verification and convergence

- Changed-file warning-as-error compile: **3/3 PASS**.
- New nonblocking storage regression: **1/1 PASS**.
- Round 1 storage/AAR regressions: **3/3 PASS**.
- Round 2 remediation regressions: **5/5 PASS**.
- Round 2 shadow-policy regressions: **7/7 PASS**.
- Round 3 collision regression: **1/1 PASS**.
- Production-package compile helper: **195/195 PASS**.
- ARIA/research self-tests: **12/12 PASS**.
- Lifecycle/performance regression runner: PASS.
- Scoped diff-integrity check: PASS; line-ending notices only.

Final performance convergence: **YES**. The only code change closes the valid
production GUI/storage lock stall and is independently proven by controlled
contention. The new path is bounded, nonblocking, eventually consistent on the
next refresh, and leaves detection, durability, response, and rule semantics
intact.
