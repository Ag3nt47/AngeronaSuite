# Long-session responsiveness — 2026-09-07

## Investigation

The operator reports freezing/slowing after Angerona has been running for a
while. Local diagnostics contain older history-query stalls addressed by the
September 5 maintenance. More recent entries show 5.6–5.9-second UI heartbeat
gaps, including one while Qt updates a System Pulse progress bar and others
inside the native event loop. Those stacks alone do not identify one root cause.
No running dashboard workload was available for a fresh live profile during
this investigation; no application restart was forced.

Code review found three remaining sources of recurring presentation overhead:

- `AsyncSnapshot` created a new daemon thread for every completed refresh,
  including the main dashboard's frequent security and threat reads.
- ARIA's compact HUD still called SQLite trend/sparkline functions on Qt after
  the asynchronous posture result arrived. Sparkline reads can materialize up
  to 100,000 scores. A zero-wait database lock and SQLite progress budget do not
  eliminate Python decoding or all filesystem latency on the caller.
- Event drill-down construction and Refresh still queried/decode history and
  optionally classified active threats on Qt.

## Changes

`AsyncSnapshot` now creates its worker lazily, reuses it, and sleeps on a bounded
request queue between reads. There is at most one outstanding read, one result
and one coalesced follow-up per owner. The worker releases its last callable and
payload before waiting. Closing wakes idle workers, cancels queued reads, and
rejects results from reads already in progress without joining on the UI thread.
Existing generation invalidation, retry and last-good-display behavior remain.

ARIA keeps the trend and sparkline in a completed memory snapshot. A separate
reader updates it without delaying the current posture score or the independent
security-event wake path. Event history windows load and filter at most 500 rows
on a worker. Busy/error preserves their existing rows and shows retry status;
it no longer silently replaces the history view with a smaller live-ring sample.
History snapshots remain presentation data; action authorization is unchanged.

## Validation

- Initial focused suite: 27 passed, including existing dashboard, lifecycle,
  stale-generation, retry, busy-history and posture-history checks.
- New regression checks process 250 refreshes with one worker and assert that
  all completed payloads become collectable. They verify immediate closure of
  a blocked read, worker exit, continued Qt heartbeats during blocked ARIA and
  event reads, off-thread active classification, event time/severity filtering,
  coalesced refreshes and retention of displayed rows after busy/error results.
- A separate 1,000-refresh no-op benchmark compared the original and updated
  helper in separate processes: 1,000 worker starts versus 1; process CPU time
  was 0.4844 seconds versus 0.2500 seconds in this single local run. Both applied
  all 1,000 results and had no live worker after close. This is a helper benchmark,
  not a measurement or promised percentage reduction for the whole application.
- Whole-package compilation: 376 files, zero failures. Ruff correctness and
  whitespace checks passed. All source, tools and tests also byte-compile.
- Headless self-check: 26 phases passed, zero failed. Its module/pipeline runner
  reported 69 passed, zero failed and 16 expected prerequisite/platform skips.
  The asynchronous event-history phases explicitly wait for completion and
  assert that seeded alerts rendered (three alert rows and one critical row).
- The first full run passed 3,255 tests with 17 skips and one lexical transport
  guard failure: the queue parameter `requests` resembled an unguarded HTTP call.
  Renaming it to `jobs` preserves behavior; all 17 focused transport/refresh
  checks passed afterward. Validation used CPython 3.12.10 / PySide6 6.11.1.

- Full rerun on the final product code: 3,255 passed, 17 skipped, one failure in
  475.02 seconds. The unchanged v2 history-migration test encountered Windows
  `PermissionError` / WinError 5 replacing its temporary registry manifest.
  It passed individually (1 passed), and its entire test file passed afterward
  (10 passed, 1 expected skip). It also passed in the first full run. This
  intermittent filesystem failure is retained in the validation record; the
  full rerun is not described as entirely green. No assertion, permission check
  or detection-history migration behavior was relaxed.
- Documentation drift validation passed. Publication uses the guarded canonical
  publisher; a separate F: backup receives an independent Git repository and
  SHA-256 readback verification, with unfinished local work saved separately.

## Deployment and limits

Maintenance remains on v1.13.0 and the 84-capability inventory. The changes were
prepared in an isolated worktree; the operator's unfinished VMware Analysis Lab
files were excluded from publication. No live settings, evidence, journal state,
detector policy or security response authority was changed.

Restart a source-launched Angerona to load the update; running processes and
previously built executables do not hot-reload it. The regression checks establish
bounded work and UI responsiveness under controlled blocked reads. They do not
prove every cause of multi-hour Windows slowdown has been eliminated. An OS call
already running in a worker can still take time to return, but closing its view
does not wait for it.
