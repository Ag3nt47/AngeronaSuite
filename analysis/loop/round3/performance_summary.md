# Round 3 — Performance Summary

Date: 2026-07-14. Scope: the QA-reported P6 empty-snapshot cache edge and a
final review of the current Round 3 loop changes. Changes were limited to one
measurable, behavior-preserving cache correction. `rules/_active_combined.yar`
was not touched.

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

- Changed Python file compiled: **1/1 PASS**.
- Sensor concurrency/equivalence combinations: **4/4 PASS**.
- No detector cadence, security threshold, snapshot TTL, output shape, or
  forced-refresh behavior changed.
- Temporary test scaffolding was removed after the gate.

| Optimization | Component | Status | Measured / expected win |
|---|---|---|---|
| Cache valid empty snapshots | Shared process/connection sensors | APPLIED | 8 concurrent empty-result scans → 1; 87.5% removed |
| Reuse shared connection cache in detectors | BEAC/CAGT | PROPOSED | Up to one full scan per overlapping tick |
| Bound MCP request workers | MCP server | PROPOSED | Bounded thread resources under local floods |
| Reverse/index Evolution feed lookup | Evolution Engine | PROPOSED | Avoid O(file size) rare-trigger reads |
