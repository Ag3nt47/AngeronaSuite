# Cycle 2 / Round 2 - Performance Summary

Date: 2026-07-14. Scope: the combined tree after Round 2 remediation and QA,
with focused measurement of the new drill-cancellation, ARIA action-binding,
research-egress split, emergency-shutdown predicate, and Round 1 GUI caches.
Tests used the supported virtual environment, `PYTHONPATH=src`, D-resident temp
storage, and no visible GUI. Detection cadence/thresholds, response durability,
rules, and host process state were not changed.

## Applied: expire abandoned ARIA confirmation snapshots

### Evidence before the change

ARIA's five-minute confirmation TTL was enforced only when the operator later
submitted that exact token. An abandoned token was never retired. Since the
Round 2 safety binding intentionally retains an immutable argument snapshot,
preview, callback, version, and digest, a long stream of unconfirmed actions
could retain substantial memory for the life of the process.

A synthetic long-session probe staged 20,000 representative nested WRITE
actions, aged them past the existing TTL, and staged one more action:

- pending actions after expiry and the next stage: **20,001**;
- current traced memory: **30.129 MiB** (peak **34.866 MiB**);
- no expired record was released.

### Change

`src/angerona/core/assistant.py` now retires expired confirmation snapshots
before staging another WRITE. The normal hot path examines only the oldest
insertion-ordered edge and removes entries until it reaches a still-valid
action, avoiding an O(n) scan for every normal stage. Registry changes and the
operator-facing `pending()` view perform a full expiry scan. Every still-valid
token, immutable snapshot, confirmation digest, callback/version check, expiry,
and single-use rule remains unchanged.

### Evidence after the change

The identical 20,000-action probe produced:

- pending actions after expiry and the next stage: **1** (the new valid action);
- traced memory before retirement: **30.134 MiB**;
- traced memory after retirement and collection: **0.403 MiB**, a **98.7%**
  reduction in retained benchmark memory;
- one-time retirement of the extreme backlog: **209.239 ms**;
- normal 20,000-action staging: **6.436 s** versus **6.322 s** before;
- 10,000 representative stage-plus-cancel operations: **259.6 us/action**
  versus **254.6 us/action** before (about 2%, within run-to-run noise).

The change is therefore material for abandoned long-session state while adding
no meaningful cost to normal operator actions.

## Measured and left unchanged

### Drill cancellation

One hundred actual start-during-30-second-jitter/cancel cycles were run for each
engine with history I/O disabled so the probe measured cancellation itself:

- Red Team: mean **0.465 ms**, p95 **0.650 ms**;
- Shark: mean **0.201 ms**, p95 **0.302 ms**;
- live `RedTeamEngine`/`SharkAttackEngine` worker threads afterward: **0/0**;
- later stages, artifacts, and completion callbacks: absent under the focused
  regression.

The per-engine Event and one retained reference to the latest terminated thread
are constant-size. The 250 ms join remains only an upper bound; the measured
interruptible waits exited far below it. No cancellation code change was
warranted.

### ARIA binding and research split

Immutable binding remains operator-action-only rather than a periodic task.
Five thousand local research READs completed in **522.566 ms** and 5,000
confirmed-action previews followed by cancellation completed in **1004.195
ms**. The sequence ended with **0 pending actions**, **0.009 MiB** current traced
memory, and **0.018 MiB** peak. The READ path performed no browser/network call.
No research change was warranted.

### Emergency-shutdown predicate

`tools/angerona_process_owner.ps1` is sourced only by the operator-triggered
`kill-all-angerona.bat`; it is not imported, polled, or resident while Angerona
runs. Its six-case ownership regression passed. It therefore contributes no
non-Eco steady-state CPU, thread, or memory cost, and no change was warranted.

### Round 1 caches and diagnostics

- The SOAR cache has one key and one tuple value (bounded to the requested 500
  rows), not a per-path dictionary; append/clear invalidates it by file
  metadata. The stat-card cache retains one `(text, color)` tuple per card.
  Neither can grow with uptime.
- The persisted SOAR file is still read in full when it changes. The cache has
  removed that cost from unchanged two-second refreshes; changing persistent
  response-history retention was excluded by this phase's durability guard.
- `diagnostics/crash.log` has no application start/crash evidence newer than
  15:58:55. `not_responding.log` has no entry newer than the 19:36:56 headless
  self-check import stall already isolated by QA. Its rotated predecessor is
  bounded at approximately 4 MiB. No new live-production stall signature was
  established.

## Gates and convergence

- Full repository compile helper: **194 files scanned, 0 failed**.
- Warning-as-error compile of the affected Assistant, both drill engines,
  research bridge, and Round 2 regression file: **5/5 passed**.
- Direct Round 2 regression runner: **5/5 passed**, including the new
  abandoned-confirmation TTL case.
- ARIA standalone self-tests: **12/12 passed**.
- `git diff --check` for the changed source/test: PASS; line-ending notice only.
- No probe artifacts were left behind.

Performance convergence for Round 2: **YES**. The one proven unbounded
long-session state path is now TTL-bounded on continued use. The other new
Round 2 paths are short-lived or operator-only and showed no worker, pending
action, or memory accumulation. No detector sampling, response ordering,
durable record, rule, or UI behavior was weakened.
