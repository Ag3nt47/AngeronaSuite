# Cycle 4 / Round 1 — Performance Summary

Method: inspected `analysis/loop/state.json`, both diagnostics trees, current
status snapshots, module polling loops, GUI timer paths, EventBus consumers, and
long-lived collections. No GUI was launched. Changes below are outside the
root-agent-owned files and preserve event ordering, retention limits, generated
records, detections, and response controls.

## Runtime evidence

- `diagnostics/not_responding.log` contains 101 GUI stalls (average 6.72 s,
  maximum 54.9 s); `runtime-data/diagnostics/not_responding.log` adds 24
  incidents (average 9.58 s, maximum 41.3 s). Repeated captured stacks include
  table rebuilds, SQLite dashboard reads, posture history, allow-list reads,
  threat-intel rendering, and attack-heatmap rendering.
- The current `runtime-data/diagnostics/status_core.json` reports 340.8 MiB RSS
  and 38 core-process threads. Older captured sessions listed 80–87 live threads
  during stalls, with most module threads sleeping or queue-blocked.
- `runtime-data/diagnostics/crash.log` has 25 startups, one native access
  violation, and no Python unhandled exception. The older root diagnostics log
  has 43 access violations and 56 unhandled-exception records, but the native
  dumps do not identify a reliable faulting Python component; no speculative
  crash fix was applied.

## APPLIED

### P1 — ATT&CK tracker O(1) event-ID retention

- **Component:** `src/angerona/core/attack_tracker.py`
- **Problem:** once a technique reached 100 recorded event IDs, every additional
  hit appended and then copied a 100-element list (`ids[-100:]`) on the EventBus
  subscriber path.
- **Change:** use `deque(maxlen=100)` and serialize the same final ten IDs in the
  same oldest-to-newest order.
- **Improvement:** a 200,000-hit isolated benchmark improved 0.664 µs/hit to
  0.047 µs/hit (**14.17× faster; 92.9% less time**) after saturation, while
  eliminating recurring list allocations.
- **Gate:** `py_compile` PASS; focused test proves the exact retained IDs
  `150..249` and snapshot IDs `240..249`. Performance regression set PASS.
- **Status:** **APPLIED**

### P2 — Compliance history O(1) bounded retention

- **Component:** `src/angerona/modules/compliance_mapper.py`
- **Problem:** after reaching 2,000 incidents, every drain copied all 2,000
  retained references through a list slice.
- **Change:** use `deque(maxlen=2000)`, preserving the exact newest-2,000
  retention and iteration order consumed by the JSON artifact.
- **Improvement:** 1,000 saturated 100-record drains improved 10.161 ms to
  2.605 ms (**3.90× faster; 74.4% less time**).
- **Gate:** `py_compile` PASS; exact oldest/newest retention test PASS; module
  `self_test()` PASS; performance regression set PASS.
- **Status:** **APPLIED**

### P3 — HEAL crash-directory metadata cache

- **Component:** `src/angerona/modules/self_healer.py`
- **Problem:** HEAL globbed and sorted every crash-snapshot filename every ten
  seconds even when the directory had not changed. Cost grew with lifetime
  snapshot count.
- **Change:** compare the directory's nanosecond mtime/ctime and only glob when
  directory metadata changes. The stamp is captured before enumeration so a
  concurrent create is either seen immediately or forces the next scan.
  Pre-launch ignore semantics and at-most-once handling remain unchanged.
- **Improvement:** unchanged-directory polling with 2,000 filenames improved
  15.763 ms to 0.019 ms (**816× faster; 99.88% less time**).
- **Gate:** `py_compile` PASS; focused create/invalidate/at-most-once test PASS;
  module `self_test()` PASS; performance regression set PASS.
- **Status:** **APPLIED**

### P4 — StatusReporter reuses one EventBus snapshot

- **Component:** `src/angerona/core/status_report.py`
- **Problem:** each three-second report copied recent EventBus state twice
  (`recent(200)` and `recent(60)`).
- **Change:** render the recent-event section from `events[:60]` of the already
  captured 200-event snapshot. The output ordering and 60-event limit are
  identical and the report is now internally consistent under concurrent
  publication.
- **Improvement:** 500-entry ring benchmark improved 7.395 µs/report snapshot to
  5.993 µs (**19.0% less time**) and removes one lock acquisition/copy.
- **Gate:** `py_compile` PASS; focused test proves one `recent(200)` call and the
  same 60 newest events; performance regression set PASS.
- **Status:** **APPLIED**

## PROPOSED

### P5 — Move Top Talkers enumeration and PTR lookups off Qt

- **Component:** `src/angerona/gui/top_talkers.py`
- **Problem:** the four-second GUI timer directly calls
  `psutil.net_connections(kind="inet")`, performs per-PID process lookups, and,
  when enabled, runs blocking reverse DNS on the Qt main thread.
- **Proposed change:** collect an immutable snapshot on one bounded worker and
  render the latest completed result; coalesce ticks while a collection is
  active and cache PTR answers with a TTL.
- **Expected win:** removes an unbounded OS connection-table call and network
  name-resolution latency from Qt; avoids overlapping refresh work.
- **Status:** **PROPOSED** — not applied without Qt runtime/render verification.

### P6 — Bound lifetime connection/forensics identity sets

- **Component:** `modules/network_monitor.py`, `modules/forensics.py`
- **Problem:** `_seen`, `_known_pid_hosts`, and `_captured` retain connection/PID
  identities for the process lifetime. This grows memory and PID reuse can
  suppress a legitimate later detection/capture.
- **Proposed change:** expire connection identities in lockstep with the existing
  novelty window and discard captured PIDs only after verified process exit plus
  a reuse-safe creation-time check.
- **Expected win:** bounded long-run memory and no stale-PID blindness.
- **Status:** **PROPOSED** — alters detection/capture decisions and needs explicit
  adversarial equivalence tests before applying.

### P7 — Make optional Scapy sniffer lifecycle explicit

- **Component:** `src/angerona/modules/arp_watchdog.py`
- **Problem:** `scapy.sniff()` checks `stop_filter` only when a packet arrives.
  During an idle network, stop/Eco pause can leave the helper thread blocked;
  a later restart can create another sniffer. Thread inventories contain an
  `arp-watchdog-scapy` helper, though the native crash logs do not prove it
  caused an access violation.
- **Proposed change:** retain an `AsyncSniffer` handle and stop/join it during
  module shutdown, with a single-active-sniffer invariant.
- **Expected win:** prevents leaked/duplicate capture helpers across lifecycle
  transitions.
- **Status:** **PROPOSED** — live sensor lifecycle; requires packet-capture gates.

### P8 — Fix newest-first cursor consumers in a behavior-authorized bug round

- **Component:** multiple `bus.recent()` consumers, including Compliance Mapper,
  Forensics, Mobile Bridge, and AI Triage.
- **Problem:** `EventBus.recent()` returns newest first; several loops update
  `_last_ts` while walking that order, causing older unseen events in the same
  batch to be skipped after the first newest item.
- **Proposed change:** process each fetched batch oldest-to-newest and advance the
  cursor after the batch, with same-timestamp identity deduplication.
- **Expected win:** avoids wasted scanning of entries that are immediately
  cursor-rejected and, more importantly, restores complete consumer coverage.
- **Status:** **PROPOSED** — deliberately not applied here because it changes
  observable event processing and belongs in a detection/bug remediation gate.

## Verification

- `python -m py_compile` (four changed source files plus focused test): **PASS**
- `tests/test_cycle4_round1_performance.py`: **4 passed**
- Combined performance regression set: **26 passed**
- `ComplianceMapperModule.self_test()`: **PASS**
- `SelfHealer.self_test()`: **PASS**

