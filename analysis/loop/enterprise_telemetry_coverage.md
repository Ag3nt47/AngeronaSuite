# Enterprise telemetry coverage accounting

Implemented a bounded per-sensor continuity accountant for ENT-ING-004,
ENT-PERF-003, ENT-PERF-009, and DEF-003.

The primitive consumes optional `sensor_id` and `sensor_sequence` event details.
It reports gaps, duplicates, regressions, missing sequence metadata, staleness,
and sensor-cardinality evictions. A sensor without sequence metadata is
`unknown`; a stale sensor or one with discontinuities is `degraded`. “Healthy”
means only that no discontinuity was observed in the retained process lifetime,
not that collection is complete.

Performance is bounded to O(1) work per observation and at most 256 sensors by
default. The least recently observed sensor is evicted on overflow, with a
visible eviction counter. There is no disk or network I/O on the event path.

Current limitation: state is process-local, so restart continuity requires
future crash-safe checkpointing or a durable ingestion ledger. Sensors must
emit monotonic sequence numbers for gap detection; legacy events remain
explicitly unknown.

The application creates one accountant at startup, subscribes it to the live
EventBus, and passes it to the existing StatusReporter. Both `status.json` and
`status.txt` now expose the bounded sensor snapshot and its explicit limitation.
