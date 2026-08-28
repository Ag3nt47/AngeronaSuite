# Cycle 25 Round 3 — Performance and reliability gate

Date: 2026-08-28

Scope: final v1.12 audit of EventBus/subscriber recording, durable exporters,
host-adaptation probes, capability inventory and clickable UI refresh paths,
bounded alert analysis, standards validators, and worker lifecycles. Changes in
this pass are behavior-preserving and do not lengthen a detection interval or
weaken an integrity, freshness, or response gate.

## Applied optimizations

### P3-01 — C-backed exact-capacity primary recorder lane — APPLIED

- **Component:** `src/angerona/core/storage.py`, `AsyncFlightRecorder`.
- **Problem:** the normal EventBus subscriber handoff still used
  `queue.Queue`, taking its Python `Condition` path for every producer even
  though this worker never uses `Queue.join()`. The authenticated overflow lane
  already used the repository's exact-capacity `SimpleQueue` plus bounded
  semaphore adapter.
- **Change:** use that same `_BoundedSimpleQueue` adapter for the primary lane.
  Ordered Event objects, capacity, nonblocking `queue.Full` behavior, overflow
  routing, durable persistence, and shutdown drain semantics are unchanged.
  A failed underlying handoff now also releases its reserved capacity slot.
- **Measured:** alternating 8-producer/1-consumer runs, 80,000 events per sample
  (7 samples): median **22.306 us/event -> 15.925 us/event**, a **28.6%**
  reduction. Single-thread round-trip medians were 5.143 us -> 4.850 us.
- **Gate:** final focused suite 106/106; recorder-specific 19/19; Ruff,
  `py_compile`, and diff check passed.

### P3-02 — Revision-gated capability/detail refresh — APPLIED

- **Component:** `src/angerona/gui/pages.py`, Capability Center, module list,
  and `ModuleInspector`.
- **Problem:** each Capability Center tick recursively copied every frozen v12
  contract. An open Module Inspector independently copied the EventBus twice
  and rebuilt both event tables every two seconds even when no event changed.
- **Change:** live tables read a small immutable contract projection; full
  recursive dictionaries remain reserved for the JSON export/inspection path.
  Module Inspector now samples one coherent 1,000-event snapshot per EventBus
  revision and uses displayed-row fingerprints to avoid unchanged feed/history
  rebuilds. Health, age-window counters, sorting, selection data, and click
  detail objects remain live and unchanged.
- **Measured:** contract projection median **43.324 us -> 1.508 us** per call
  (**96.5%** less). With a 300-event ring and 100 module events, an unchanged
  inspector tick measured **13.458 ms -> 0.474 ms** (**96.5%** less), with
  structurally zero ring copies and zero table rebuilds until a revision changes.
- **Gate:** new regression proves one snapshot, no unchanged or unrelated-event
  table rebuild, and one exact rebuild for a relevant event. Final focused suite
  106/106; UI subset 43/43; Ruff, `py_compile`, and diff check passed.

## Audited, retained, or proposed

### EventBus delivery metrics — RETAINED

No-op publication medians were 0.955 us (no subscribers), 4.857 us (one), and
17.260 us (eight). Subscriber callbacks remain inline and ordered; per-callback
latency/failure metrics remain immediately observable. Coalescing metric updates
under one post-delivery lock benchmarked faster, but it changes what a subscriber
can observe during nested publication, so it was not applied in this
behavior-preserving gate.

### Durable exporters/outbox — RETAINED / PROPOSED

SIEM and Remote Bridge retain drain -> durable stage -> drain ordering, cursor
commit only after every selected row is durable, authenticated mutable-state
checks, bounded leases, and explicit capacity-gap receipts. `PRAGMA data_version`
and `total_changes` keep normal operations on the trusted fast path while forcing
a full row-authentication sweep after unobserved mutation. Batch enqueue/ACK could
reduce `synchronous=FULL` commits, but would alter crash-time duplicate/replay
boundaries; it remains **PROPOSED**, not applied.

### Host adaptation probes — RETAINED

Remote-session authorization remains fresh and host-wide: SSH/session hints,
WTS enumeration bounded to 256 sessions, and remote-control process enumeration
bounded to 4,096 entries. Firewall collection remains a complete bounded policy
snapshot and runs off the Qt thread. These probes deliberately were not cached:
a stale negative could authorize a mutation after a remote operator connects or
could make a baseline restore compare incomplete state.

### Alert analysis and worker lifecycles — RETAINED / PROPOSED

Live Alert analysis remains bounded to two active workers plus six queued exact
event identities, with deduplication and finished-signal retirement. Auto Adapt
uses one in-flight background operation, the dashboard poll has a single-flight
event, and CVE batch analysis is owned/interruption-aware. A dashboard can still
start one CVE detail worker per distinct CVE; a global detail-analysis cap is
**PROPOSED** because imposing it would change current click behavior and needs a
product-level queue/refusal UX decision.

### OCSF/Sigma/ATT&CK validators — RETAINED / PROPOSED

OCSF paths, observables, and unmapped details are bounded; Sigma YAML has byte,
document, node, depth, string, selector, value, and regex bounds plus atomic
admission. Sigma revalidates directly mutable rule dictionaries on every match.
Compiling immutable admitted plans could improve high-rule-count evaluation, but
skipping revalidation would change the public mutable-list behavior and trust
boundary, so it remains **PROPOSED**.

### Shared-log mtime caching — NOT APPLIED

Threat-intelligence refresh is already 60 seconds and stops while hidden.
Caching solely by mtime/size could miss a same-size replacement with preserved
timestamps. No new cache was added without a content-generation or authenticated
revision token.

## Validation evidence

- Final focused v1.12 performance/reliability suite: **106 passed in 29.65 s**.
- Additional lifecycle/performance sweep: **100 passed, 1 scheduling-sensitive
  assertion failed once**. The exact Eco wakeup cancellation test then passed
  **10/10 isolated**. The failure occurred when the test's newly spawned cancel
  thread was not scheduled within its 20 ms assumption; no product exception,
  leaked worker, or repeatable lifecycle fault was observed, and no timeout or
  protection was weakened.
- Ruff: clean for all three changed files.
- `py_compile`: passed for all three changed files.
- `git diff --check`: passed (Git emitted only the repository's normal future
  LF-to-CRLF checkout warning).

## Final optimization table

| Optimization | Component | Status | Expected/measured win |
|---|---|---|---|
| C-backed exact-capacity primary handoff | AsyncFlightRecorder | APPLIED | 28.6% median multi-producer handoff reduction |
| Immutable live contract projection | Capability Center/module list | APPLIED | 96.5% lower contract-read cost |
| One revision-gated event snapshot and row fingerprints | Module Inspector | APPLIED | 96.5% lower unchanged tick; zero unchanged row rebuilds |
| Atomic batch enqueue/acknowledge | Durable exporters | PROPOSED | Fewer FULL SQLite commits; crash semantics need design proof |
| Immutable compiled Sigma plans | Sigma evaluator | PROPOSED | Lower per-event high-rule-count validation cost |
| Global per-CVE detail-worker backpressure | Threat Intel UI | PROPOSED | Bounds distinct-CVE click bursts; needs explicit UX behavior |
