# Cycle 19 Performance and Stability — Passes 16–21

Date: 2026-08-21  
Scope: GUI/telemetry refresh, module scheduling, recorder/database growth,
bounded caches, resource governance, and watchdog/resilience cadence.

## Outcome

Two concrete hot paths were fixed without reducing detection cadence or response
authority:

1. The authoritative flight recorder no longer makes every EventBus publisher
   perform a locked file append when its SQLite queue is saturated. A second
   bounded worker lane preserves signed overflow in multi-event writes.
2. Core and peer-watchdog supervisors no longer enumerate every process command
   line every second to rediscover the same heartbeat-less Black Box process.
   They retain psutil's PID-reuse-safe `Process` identity and immediately rescan
   when that exact process exits or becomes a zombie.

The previously unbounded `dlq_events.json` path is now a bounded authenticated
spool with automatic, idempotent replay:

- 2 MiB active segments;
- 32-segment and 64 MiB hard pending-spool limits;
- per-line HMAC verification before re-ingestion;
- segment-scoped SQLite replay receipts that close the commit/delete crash
  window;
- fixed-size 512-event replay transactions with batch membership queries;
- raw quarantine for malformed/forged lines, which are never rendered or
  executed;
- no deletion of a valid source segment until every line is committed, already
  present, or durably quarantined;
- explicit queue, replay, quarantine, byte/count, capacity-wait, and failure
  metrics in `ingest-status`;
- bounded shutdown: in-memory lanes drain first, one maintenance segment is
  attempted, and any remaining signed segments stay durable for the next
  background/startup pass instead of making application exit hang.

At the catastrophic boundary where both bounded memory lanes and the complete
64 MiB disk budget are exhausted, the writer deliberately backpressures until a
verified replay frees committed space. Unlimited lossless input, a hard disk
bound, and permanently non-blocking producers cannot all be guaranteed at once;
this fail-closed behavior makes the exceptional state observable and preserves
evidence rather than silently dropping or overwriting it.

## Before/after measurements

The Cycle 19 adversarial baseline used eight publishers and 40,000 signed events:

| Measurement | Before | After | Result |
|---|---:|---:|---:|
| 40,000-event publish completion | 33.855 s | 2.080 s | 16.3x faster |
| Publish throughput | 1,182 events/s | 19,228 events/s | 16.3x higher |
| Evidence preservation | 40,000 | 40,000 | unchanged |
| Recorder/DLQ failures | 0 | 0 | unchanged |

An additional same-host pre-change micro-benchmark needed 5.380 seconds for only
8,000 events (1,487/s). The final path handled five times that input in less
than half the time. In the final run, 39,872 events used the asynchronous spill
lane and only 128 reached the synchronous last-resort during momentary queue
saturation. A bounded shutdown pass replayed 17,103 rows in 1.763 seconds; the
remaining 5.30 MiB stayed authenticated on disk for later background replay.

The heartbeat-less liveness regression performs 101 healthy checks:

| Probe behavior | Before | After |
|---|---:|---:|
| Whole-host `process_iter(cmdline)` scans | 101 | 1 |
| Exit detection | next tick | next tick + immediate rescan |

This removes about 99% of steady-state full process-table scans for each
heartbeat-less component in each supervisor, while retaining PID-reuse identity
and zombie rejection.

## Pass evidence

### Pass 16 — GUI refresh and telemetry rendering

Status: **VERIFIED — no new change required**

The current tree already uses a 1/2/4-second tiered dashboard cadence, committed
in-memory storage revisions, zero-wait UI reads, incremental 120-row alert
updates, cached SOAR file parses, a persistent System Pulse sampler, bounded UI
queues, and 250-row render batches. The targeted GUI/lifecycle regressions pass.
Increasing visual refresh frequency or moving protection sampling onto the GUI
thread was rejected.

### Pass 17 — flight-recorder publisher backpressure

Status: **APPLIED**

`AsyncFlightRecorder` now has a primary SQLite queue and an 8,192-event overflow
queue serviced by an independent batch DLQ worker. Both are count-bounded.
Publisher work remains signing plus `put_nowait` in the normal and flood paths.
The old synchronous append is retained only as the evidence-preserving last
resort when both queues are full or a worker is unavailable.

### Pass 18 — scheduling and resource governor

Status: **VERIFIED / PROPOSED**

Safety-critical IPC, watchdog, and response modules still start immediately;
other modules wait for a genuine first-cycle boundary before the next cold scan.
The resource governor continues to exempt the named response path and changes
only cooperative sleep multipliers. No detection loop was newly throttled.

A shared immutable psutil host-snapshot broker could remove duplicate process
and connection enumeration across legacy modules, but it remains **PROPOSED**:
shipping it requires per-sensor freshness SLOs and stale-snapshot fail-closed
tests to prove that consolidation cannot create a correlated telemetry blind
spot.

### Pass 19 — database growth and durable overflow

Status: **APPLIED**

The signed spool segmentation/replay/quarantine design above closes the
unbounded transient-flood file. Replay uses an indexed HMAC column, a fixed
number of SQL statements per batch, and segment-scoped receipts. Database
failure leaves the source segment untouched; a regression injects an
`OperationalError`, proves the bytes remain, restores SQLite, and proves the
same record replays exactly once.

### Pass 20 — caches and memory

Status: **VERIFIED — no new change required**

EventBus history, flight cache, telemetry worker pending/seen sets, UI render
queue, process baseline work, status histories, and alert tables all retain
explicit count bounds. The new recorder adds only 8,192 overflow references and
fixed 1,024-event write batches; it never creates an unbounded in-memory retry
list. Replay streams one bounded segment and 512-event batches.

### Pass 21 — watchdog and resilience

Status: **APPLIED**

`cached_cmdline_probe` removes repeated whole-host command-line scans after a
sidecar is adopted. It reuses psutil's process identity, rejects zombies, and
does a full rescan immediately after exit. Heartbeat-backed Core/Scanner paths
and their suspension thresholds are unchanged.

## Gates

- Changed-source `py_compile`: **PASS**.
- Focused recorder/spool/probe tests: **12 passed / 0 failed**.
- Performance, GUI backpressure, lifecycle, shutdown, and resilience regression
  set: **76 passed / 0 failed**.
- Full project suite: **792 passed / 2 intentional platform skips / 0 failed**.
- Ruff on changed source/tests: **PASS**.
- `git diff --check` on owned files: **PASS** (line-ending notices only).
- Bandit was not installed in this virtual environment; no result is claimed.

## Remaining native/soak gates

- Elevated Windows soak with real ETW/scanner traffic, Eco transitions,
  sleep/resume, deliberate SQLite lock, and deliberate full-volume conditions.
- Native Linux/macOS artifact soak and suspend/resume validation.
- Operator workflow for inspecting/exporting/acknowledging quarantine segments.
- Freshness-SLO design before any shared host-snapshot broker is allowed to
  replace independent real-time detector sampling.
