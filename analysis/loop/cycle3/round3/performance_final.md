# Cycle 3, Round 3 — Posture-history performance gate

Date: 2026-07-19  
Scope: `src/angerona/core/posture_history.py` only

## APPLIED — non-blocking ARIA posture-history reads

### Evidence and root cause

`diagnostics/not_responding.log` repeatedly captured the Qt main thread in:

`AriaHud.refresh -> PostureHistory.sparkline -> downsample -> series -> writer lock / SQLite fetchall`

The captures include 5–8 second UI stalls, including a fresh 5.7 second stall at
2026-07-19 10:23:55. Although posture writes had already moved to a daemon
thread, HUD reads still shared the writer connection and its blocking Python
lock. A slow commit or WAL/checkpoint therefore blocked the GUI.

### Change

- Enabled WAL/NORMAL settings for the standalone posture database.
- Added a dedicated `query_only`, `timeout=0` SQLite connection for HUD reads.
- Added a 150 ms SQLite progress budget; a busy or over-budget refresh keeps the
  last valid HUD value and retries on the next timer tick.
- Added small, lock-protected, 16-key LRU caches for sparkline and trend results.
- Kept `series()` as the exact blocking API for reports and offline callers.
- Replaced sparkline's 100,000 full `PosturePoint`/note/band materialization with
  a covering `(ts, score)` index and a score-only query.
- Replaced trend's 100,000-object materialization with bounded indexed COUNT and
  OFFSET queries in one read snapshot.
- Closed the read connection explicitly during shutdown.

No security control, event, score, trend formula, point ordering, or intended
chart output was changed. Under transient contention, the visible chart remains
at the last committed value for one refresh instead of freezing the application.

### Measurements

Synthetic file-backed database, 100,000 posture points, Windows host:

| Path | Before | After | Improvement |
|---|---:|---:|---:|
| 32-column sparkline | 393.088 ms | 82.785 ms | 4.75× faster |
| Full-window trend | 713.001 ms | 47.795 ms | 14.92× faster |
| Forced busy HUD snapshot | up to the writer wait (5–8 s observed in watchdog) | 0.031 ms cached return | non-blocking |

Times are isolated micro-benchmarks and will vary with host load; the contention
gate is the important invariant.

### Gates

- `py_compile` for implementation and targeted tests: PASS
- `PostureHistory.self_test()`: PASS
- Targeted unit tests: 5/5 PASS
  - output equivalence with original downsampling contract
  - cached return under forced UI-read contention (<25 ms)
  - writer-lock isolation (<200 ms)
  - bounded cache and width edges
  - six parallel readers plus 400 asynchronous records
- `git diff --check`: PASS (line-ending notice only)

Status: **APPLIED**

## PROPOSED — retention policy for posture history

The table is append-only and the interactive query is capped at 100,000 points,
so read cost is bounded, but the database itself can continue growing. A future
schema/versioned retention policy could compact old points into hourly/daily
aggregates. It is not applied here because it changes stored-history semantics
and requires an explicit product retention decision.

Status: **PROPOSED**
