# Round 2 — Performance Summary

Date: 2026-07-14. Scope: prior P3/P4 proposals plus the Round 2 event-HMAC,
FlightRecorder, and threaded MCP changes. Changes were limited to measurable,
behavior-preserving work. `rules/_active_combined.yar` was not touched.

## APPLIED

### P3 — Build the static ATT&CK Coverage table once

- **Component:** `gui/attack_heatmap.py` — `_refresh_coverage()`
- **Problem:** Every five-second live-heat refresh replaced all 108 items in the
  18x6 Coverage table, even though `COVERAGE` and the vetted remediation action
  allow-list are process-lifetime constants.
- **Change:** Populate the table once after the first successful coverage import.
  Live Heat and Top Techniques retain their five-second refresh behavior.
- **Measured win:** 50 redundant refreshes fell from **38.175 ms** to
  **0.0425 ms** total (about **99.9% less work**), eliminating 108 Qt item
  allocations per timer tick (1,296 allocations/minute while open).
- **Gate:** `py_compile` PASS. Offscreen PySide6 equivalence PASS: 18 rows, 108
  cell texts unchanged, and all underlying item identities unchanged across 50
  cached calls.
- **Status:** APPLIED.

### P5 — Reuse the EventBus HMAC on the recorder hot path

- **Components:** `core/storage.py`, `app.py`, `core/headless.py`
- **Problem:** Round 2 integrity hardening signed every normal event on the armed
  EventBus, then FlightRecorder repeated canonical JSON serialization and HMAC
  immediately in its subscriber.
- **Change:** Added the explicit `record_bus()` subscription path, which reuses
  the bus-authoritative signature. Public `record()` retains its independent
  signing contract for direct/import callers; unsigned input is still signed.
- **Measured win:** Representative event preparation fell from **18.92 us** to
  **5.31 us/event**, saving **13.61 us/event** (about 72% of this preparation
  cost; roughly 1.9 ms CPU/s at 140 events/s). SQLite durability is unchanged.
- **Gate:** `py_compile` PASS. Targeted compatibility/integrity PASS: normal bus
  signature persisted unchanged and verified; direct `record()` re-signed an
  unrelated supplied signature exactly as before; invalid input on the bus-only
  path surfaced as an explicit `[INTEGRITY FAILURE]` on read.
- **Status:** APPLIED.

### P6 — Serialize shared sensor-cache misses

- **Component:** `telemetry/sensors.py`
- **Problem:** The documented shared process/connection cache checked outside
  its lock and locked only assignment. Simultaneous module ticks on an empty or
  expired cache therefore all ran the same expensive OS enumeration.
- **Change:** Separate process and connection miss locks now cover check, scan,
  and publish. The two sensor types do not block each other, and TTL/data shape
  are unchanged.
- **Measured win:** With 12 simultaneous callers and a deterministic 50 ms OS
  scan, both process and connection paths fell from **12 enumerations to 1**.
- **Gate:** `py_compile` PASS. Concurrency regression PASS: all 12 callers
  received identical snapshots and each sensor executed exactly once.
- **Status:** APPLIED.

## PROPOSED / NOT APPLIED

### P4 — Route remaining direct connection scans through the shared cache

- **Components:** `modules/beacon_detector.py`, `modules/counter_agentic.py`
- **Finding:** Both still call `psutil.net_connections()` directly. Reuse could
  remove overlapping scans, but the shared helper has a different address data
  shape and a 1.5-second freshness window. A short-lived beacon or Ollama-port
  connection could be observed differently.
- **Decision:** PROPOSED only. This is a live detection path; equivalence was not
  proven, so no security fidelity was traded for speed.

### P7 — Batch FlightRecorder commits

- **Component:** `core/storage.py`
- **Finding:** Per-event SQLite commit remains the dominant recorder cost.
  Batching would improve throughput, but changes crash durability and how soon
  events become query-visible.
- **Decision:** NOT APPLIED. Current WAL/NORMAL, bounded retention, and bounded
  interactive reads are retained.

### P8 — Bound all MCP request-worker threads

- **Component:** `engines/mcp_server.py`
- **Finding:** Round 2 correctly bounded SSE sessions, queues, body size, socket
  reads, and backlog. `ThreadingHTTPServer` can still create more concurrent
  short-lived request workers than the 16-session cap under local connection
  flooding.
- **Decision:** PROPOSED only. A semaphore/rejection policy changes overload
  behavior and needs a protocol-level load test. Normal MCP overhead from the
  new session lock is constant-time and not a useful optimization target.

## Gate summary

- Changed files compile: **5/5 PASS**.
- Storage integrity/compatibility regression: **PASS**.
- Offscreen Qt content/item-identity regression: **PASS**.
- Sensor concurrency regression: **PASS**.
- No detector cadence, security threshold, event retention, SQLite durability,
  or MCP protocol behavior was weakened.

| Optimization | Component | Status | Measured / expected win |
|---|---|---|---|
| Static Coverage build-once | Attack heatmap GUI | APPLIED | 99.9% less work on redundant calls; 1,296 allocations/min removed |
| Reuse bus HMAC | Event storage | APPLIED | 13.61 us/event saved in preparation |
| Serialize cache misses | Shared sensors | APPLIED | 12 concurrent OS scans -> 1 |
| Reuse connection cache in detectors | BEAC/CAGT | PROPOSED | Up to one full connection scan per overlap |
| Batch SQLite commits | FlightRecorder | NOT APPLIED | Faster writes but unacceptable durability/visibility change |
| Bound MCP request workers | MCP server | PROPOSED | Bounded resources under local floods |
