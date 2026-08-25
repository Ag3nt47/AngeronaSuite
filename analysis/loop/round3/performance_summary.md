# Round 3 — Performance Summary

Date: 2026-07-14. Scope: the QA-reported P6 empty-snapshot cache edge, repeated
process-policy/drill-resolution reads in hot batches, and a final review of the
current Round 3 loop changes. Changes were limited to measurable,
behavior-preserving cache work. `rules/_active_combined.yar` was not touched.

## APPLIED

### P9 — Cache valid empty sensor snapshots

- **Component:** `telemetry/sensors.py` — `list_processes()` and
  `list_connections()`.
- **Problem:** Round 2 serialized shared cache misses, but a cache hit still
  required `if cached`. A successful empty list was therefore treated as a
  miss. Concurrent callers were serialized, yet each caller repeated the full
  OS enumeration after the previous empty result.
- **Change:** Cache validity now uses the initialized timestamp and TTL. Empty
  and non-empty snapshots follow the same cache contract. `max_age=0` still
  forces a fresh scan, the default 1.5-second freshness window is unchanged,
  and returned data is unchanged.
- **Measured win:** In deterministic eight-thread gates, valid empty process and
  connection snapshots each fell from **8 OS enumerations to 1**, removing
  **7/8 (87.5%)** of the expensive scans in that overlap. Non-empty snapshots
  also remained at one enumeration.
- **Gate:** `py_compile` PASS. Focused concurrency regression PASS for all four
  combinations (process/connection × empty/non-empty): eight callers received
  identical results, the sequential cache hit did not enumerate again, and
  `max_age=0` performed exactly one forced refresh.
- **Status:** APPLIED.

### P11 — Reuse process-policy and drill-resolution snapshots per batch

- **Components:** `core/process_allowlist.py`, `core/drill_resolution.py`,
  `core/threat.py`, `gui/resolve_center.py`, `modules/mem_inject_scanner.py`,
  `modules/soar.py`, `modules/soar_engine.py`,
  `modules/posture_hardening.py`, and `shark/aar_report.py`.
- **Problem:** The JSON content caches already avoided repeated file reads when
  mtimes were unchanged, but each process/event match still resolved the
  default data directory through `Config.load()`, statted the policy file,
  cloned cached rows, and—for drill state—deep-copied the complete JSON object.
  Threat, process-scan, SOAR, Resolve Center, and AAR loops repeated that work
  for every item in a batch.
- **Change:** Both policy modules now cache their process-lifetime default data
  directory. `policy_snapshot()` returns immutable normalized allowlist rows;
  `resolution_snapshot()` returns an immutable resolution mapping. Existing
  match APIs accept an optional snapshot and retain direct-call compatibility.
  Each identified hot caller now loads once at batch start and reuses that exact
  snapshot for all items. Atomic writes still invalidate the underlying mtime
  cache, so the next batch observes operator changes.
- **Measured win:** A 50-event threat evaluation fell from up to **50 policy +
  50 resolution load/stat/clone paths to 1 + 1**. A three-PID memory batch and
  both eight-event SOAR batches each used **one** policy snapshot. Reused
  snapshot checks were instrumented to prove **zero hidden per-item reloads**.
  Four implicit path lookups across the two policy modules caused two total
  `Config.load()` calls (one per module), rather than four.
- **Gate:** Nine touched files `py_compile` PASS. Exact name/path allowlist
  behavior, old/new drill timestamp behavior, run-scoped resolution matching,
  snapshot immutability, policy-write invalidation, threat output, and forced
  no-reload checks PASS. Memory and both SOAR response actions were stubbed;
  their batch read-count gates PASS without host changes.
- **Status:** APPLIED.

## REVIEWED / NOT APPLIED

### P4 — Route remaining direct connection scans through the shared cache

- **Components:** `modules/beacon_detector.py`, `modules/counter_agentic.py`.
- **Finding:** The consumers still require different connection fields and
  potentially fresher observations than the shared dictionary snapshot.
- **Decision:** PROPOSED only. Reuse could remove a full connection-table scan,
  but equivalence on a live detection path remains unproven.

### P8 — Bound all MCP request-worker threads

- **Component:** `engines/mcp_server.py`.
- **Finding:** Session queues, bodies, backlog, and socket reads are bounded,
  while the underlying threaded HTTP server can still create many short-lived
  request workers during a local connection flood.
- **Decision:** PROPOSED only. A process-wide semaphore and rejection response
  require protocol/load testing because they alter overload behavior.

### P10 — Avoid whole-file Evolution footprint reads

- **Component:** `modules/evolution_engine.py` — `_latest_footprint()`.
- **Finding:** An evolution trigger reads and splits the complete
  `attack_feed.log` before searching backward. Cost grows with the feed, but the
  path runs only after a verified bypass and is not a steady-state loop.
- **Decision:** PROPOSED only. A bounded reverse reader or indexed/rotated feed
  would need tests for UTF-8 line boundaries and the guarantee that the newest
  matching technique is still found. No speculative complexity was added to a
  rare security workflow.

### Evidence Lattice and YARA activation review

- Evidence Lattice work is event-driven; per-entity signal and dedup state are
  bounded, and its 15-second health loop only reads two in-memory counts.
- Generated YARA compilation runs only on a bypass-driven activation, while the
  normal scanner retains its five-minute cadence. No safe steady-state win was
  identified in either Round 3 path.

## Gate summary

- Changed Python files compiled: **10/10 PASS** (P9 + P11).
- Sensor concurrency/equivalence combinations: **4/4 PASS**.
- Policy/resolution equivalence, invalidation, immutability, default-path, and
  batch read-count gates: **PASS**.
- No detector cadence, security threshold, snapshot TTL, output shape, or
  forced-refresh behavior changed.
- Temporary test scaffolding was removed after the gate.

| Optimization | Component | Status | Measured / expected win |
|---|---|---|---|
| Cache valid empty snapshots | Shared process/connection sensors | APPLIED | 8 concurrent empty-result scans → 1; 87.5% removed |
| Reuse policy/resolution snapshots | Threat, Resolve Center, MINJ, SOAR, AAR | APPLIED | 50-event threat batch: 50+50 load paths → 1+1 |
| Reuse shared connection cache in detectors | BEAC/CAGT | PROPOSED | Up to one full scan per overlapping tick |
| Bound MCP request workers | MCP server | PROPOSED | Bounded thread resources under local floods |
| Reverse/index Evolution feed lookup | Evolution Engine | PROPOSED | Avoid O(file size) rare-trigger reads |

## 2026-08-22 addendum — network-first Chill live-path audit

This bounded second pass audited the modules that deliberately remain online in
Chill. Network Monitor, C2 Beacon Detector, WFP, ETW/Sysmon, Defender/AMSI, USB,
watchdog/resilience, SIEM/mobile bridges, and both SOAR tiers remain started and
unthrottled. Existing ARP/WLAN/deep-decoder fallback floors were not increased.

### P12 — Park Evolution's event-driven idle thread

- **Component:** `modules/evolution_engine.py`.
- **Problem:** every activation already arrives through the EventBus callback,
  but the module's otherwise empty `run()` loop still woke every five seconds.
- **Change:** publish the normal first-cycle readiness boundary once, then wait
  interruptibly on the lifecycle stop token. EventBus activation and stop/start
  behavior are unchanged.
- **Expected/measured improvement:** deterministic cadence inspection changed
  the idle wait sequence from repeated five-second waits to one interruptible
  indefinite wait: **17,280 no-op wakeups/day removed**.
- **Gate:** module `self_test()` PASS; lifecycle/cycle gate PASS; focused
  Evolution/remote-evidence regressions PASS.
- **Status:** APPLIED.

### P13 — Avoid reopening an unchanged deception feed

- **Component:** `modules/deception.py`.
- **Problem:** Active Deception opened and read `attack_feed.log` every five
  seconds even when no writer had changed it.
- **Change:** cache a bounded file identity (device/inode/size/mtime/ctime) and
  reopen only after change, truncation, or replacement. Canary stat checks keep
  their original five-second detection cadence. Failed reads are not cached,
  and a concurrent append is caught on the next pass from the exact stream
  cursor.
- **Expected/measured improvement:** the regression gate proves two unchanged
  polls perform one open and an append performs the next open with no missed
  marker. For a continuously present, idle feed this reduces up to **17,280
  opens/day to the initial open plus actual changes**.
- **Gate:** `py_compile`, Ruff, focused regression, and a sandboxed running
  module `self_test()` PASS.
- **Status:** APPLIED.

### P14 — Slow auxiliary bookkeeping only while Chill is quiet

- **Component:** `core/chill_mode.py`.
- **Problem:** several non-detection helpers retained full periodic cadence even
  though their security work is event-driven or operator/drill initiated.
- **Change:** add reversible Chill floors for Posture Hardening (2s to 16s),
  HEAL crash-patch staging (10s to 60s), Flight Cache health accounting (10s
  to 80s), Evidence Lattice health accounting (15s to 120s), and Storage
  Hygiene (15m to 2h). Flight Cache ingestion and Evidence Lattice fusion remain
  immediate callbacks. Watchdog restart remains immediate; HEAL only stages an
  optional patch afterward. Explicit drills and active hostile evidence remove
  every floor before full coverage resumes.
- **Expected improvement:** about **57,684 auxiliary cycle wakeups/day removed**
  during a continuously quiet Chill session. Combined with P12, that is about
  **74,964 idle wakeups/day removed**, without changing the live network,
  telemetry, USB, or response cadence.
- **Gate:** exact-name protection invariant, throttle-floor lifecycle, policy
  transitions, compile, Ruff, and focused regressions PASS.
- **Status:** APPLIED.

### Reviewed but not applied

- **Behavioral Tuner transaction coalescing — PROPOSED.** It commits each learned
  behavior separately and can create avoidable WAL traffic during a process
  burst. Batching changes crash-durability and learning semantics; it needs a
  journaled, replay-safe design before application.
- **Longer shared connection-cache TTL — PROPOSED.** It would reduce the remaining
  `net_connections()` calls, but could miss short connections or delay a live
  network detector. Freshness was left unchanged.
- **Authenticode-result metadata caching — REJECTED.** It would save PowerShell
  signature checks but could trust bytes changed with preserved metadata. The
  integrity assessment remains cryptographic and unchanged.

### Addendum gates

- Changed Python files `py_compile`: PASS.
- Ruff on changed Python/tests: PASS.
- Focused Chill/idle-I/O tests: **10/10 PASS**.
- Wider lifecycle, Evolution, remote-evidence, and performance set:
  **47/47 PASS**.
- Edited module self-tests: Evolution PASS; Active Deception PASS in an isolated
  temporary profile; no real user canaries or host state were touched.

---

# 2026-08-25 Expansion Loop — Round 3 Performance Regression

This pass re-audited the new governed model-pack lifecycle, Upgrade Console,
Sysmon continuity/full event coverage, Community-ID, OCSF 1.8 mapping, and the
round-1 ARIA RAG/ETW optimizations. Detection cadence, response thresholds,
event shapes, and security controls were not changed.

## APPLIED

### XP3.1 — Move periodic resilience/scanner file reads off the Qt thread

- **Component:** `gui/upgrade_console.py`.
- **Problem:** the new model-pack state/admission and mutation paths correctly
  used `QRunnable`, but the same console's 3-second watchdog timer still read
  two diagnostic JSON files plus heartbeat state on the Qt thread, and its
  1.5-second telemetry timer read scanner JSON there. Slow storage or endpoint
  scanning could therefore stall painting and input.
- **Change:** timer callbacks now submit background snapshots through the
  console's stable worker bridge. Result rendering stays on the owning Qt
  thread. Separate single-flight flags coalesce repeated timer ticks, stale
  tokens are ignored, the zero-delay initial timer is stopped on close, and
  late results retain the existing safe shutdown behavior.
- **Measured improvement:** with a deterministic 50 ms diagnostic read, the Qt
  callback returned in **0.036 ms** while the 51.492 ms I/O completed on a
  worker. Eleven refresh requests while that read was pending retained exactly
  **one queued job** (90.9% request coalescing in the stress sample; no backlog).
- **Behavior proof:** runtime tests verify that both watchdog and scanner reads
  run off the Qt thread, completed values render on Qt, and duplicate ticks are
  single-flight. Existing model-pack async, stale-result, mutation, provider,
  and close-during-worker tests remain green.
- **Gate:** `py_compile` PASS; Ruff PASS; focused cross-feature regression
  **45/45 passed**.
- **Status:** APPLIED.

## VERIFIED / NO CHANGE NEEDED

- **Governed model packs:** install/activate/rollback/remove network and disk
  work is already off-thread in the Upgrade Console. Catalog input is capped at
  2 MiB/128 packs, runbooks at 256 per pack/16,000 characters each, receipts at
  256, and activation history at 64. Lifecycle state is HMAC-attested and model
  operations are process-wide single-flight.
- **Community-ID and OCSF:** both paths are stateless, bounded pure mappings.
  Native Community-ID is calculated only for newly observed external sockets,
  not every active socket on every poll. OCSF validation allocates only a small
  error list and is not a polling path.
- **Sysmon:** steady-state polling remains at two seconds, cursor persistence is
  once per consumed batch rather than once per record, and fallback PID state is
  replaced by the current process snapshot. Full event-range parsing is bounded
  to 1 MiB XML per record and bounded copied fields.
- **Round-1 RAG/ETW changes:** the pre-indexed BM25 term-frequency/normalizer
  cache and 4,096-entry ETW PID LRU remain behavior-equivalent; their focused
  performance regressions passed in the 45-test gate.

## PROPOSED / NOT APPLIED

### XP3.2 — Constant-time first-run Sysmon tail positioning

- **Problem:** a brand-new cursor still drains the retained Sysmon channel to
  establish its initial tail. A large channel can make first startup O(records).
- **Proposal:** use `EVENTLOG_SEEK_READ` at the range-reported newest record,
  with an explicit concurrent-arrival boundary and sequential fallback.
- **Expected win:** replace an unbounded initial discard loop with one seek plus
  normal incremental reads.
- **Why proposed:** pywin32 seek-buffer advancement and records arriving between
  the range query and seek need a Windows-native integration gate. Applying this
  from static reasoning could skip a first live record and weaken detection.
- **Status:** PROPOSED.

### XP3.3 — Asynchronous ARIA startup index/manager construction

- **Problem:** production model operations and periodic status reads are
  off-thread, but ARIA's one-time startup still constructs the pack manager and
  builds the initial local runbook index during main-window initialization. The
  Upgrade Console's standalone/fallback constructor likewise reads the bundled
  catalog and install key synchronously.
- **Proposal:** prepare an immutable manager/index bundle on a startup worker and
  atomically attach it before exposing model-pack tools.
- **Expected win:** remove one-time catalog/key/directory and documentation-tree
  I/O from GUI startup.
- **Why proposed:** this crosses ARIA tool-registration/readiness sequencing and
  needs startup-close, disabled-ARIA, corrupt-state, and retry lifecycle tests.
- **Status:** PROPOSED.

| Optimization | Component | Status | Expected/measured win |
|---|---|---|---|
| Async coalesced diagnostic snapshots | Upgrade Console | APPLIED | 50 ms I/O becomes 0.036 ms Qt submission; 11 ticks → 1 job |
| Constant-time first-run cursor seek | Sysmon Listener | PROPOSED | O(retained records) → O(1) initial positioning |
| Async initial manager/RAG bundle | ARIA startup | PROPOSED | Remove one-time local disk scan from GUI initialization |
