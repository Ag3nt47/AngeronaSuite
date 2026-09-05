# Defensive response readiness and USB responsiveness

Date: 2026-09-05. Maintenance on v1.13.0; no version or capability-count change.

## Findings and repairs

1. **Response worker liveness.** Combat only reported its startup cycle. An idle
   or busy event consumer could subsequently miss the watchdog deadline despite
   working normally. Completed queue waits and handled events now renew the
   bounded deadline. An exception does not publish a successful work cycle.
2. **Publisher delays.** Admission shared the journal's lock and resolved file
   targets on the detector's publishing thread. Admission now uses an independent
   memory-only lock; filesystem-dependent contract checks run on the response
   worker. Authentication precedes deduplication and is repeated before action.
3. **Execution-time policy.** Queued work now rechecks current severity, enabled
   policy, evidence disposition and exact target contract. Boolean contract
   versions and process identifiers are rejected. These changes narrow authority.
4. **Misleading active-threat state.** Combat's own recovery events are suite
   health. Immutable Recovery Assurance reports backup posture as exposure,
   retaining its severity, finding details and observation-only behavior.
5. **Response visibility.** Settings → Adversary Combat now shows STARTING,
   ARMED, DISABLED, recovery, journal capacity and queue states with the exact
   bounded recovery reason and session decision counters. The panel reads only
   memory, grants no authority, renders text literally and stops polling while
   hidden. A running worker alone no longer passes the Combat self-test. A failed
   startup-deception checkpoint immediately holds response instead of announcing
   ARMED, and disabled response no longer starts deception.
6. **USB UI stalls.** Reviewed existing USB changes move protected-storage and
   approval operations to bounded background workers. One prompt is displayed at
   a time, security prompts skip cosmetic reveals, and redundant application of
   the dashboard stylesheet is removed. The global event filter ignores unrelated
   event types early. Cancellation, parent destruction, delayed results, PIN reset
   and volume-identity rechecks preserve the exact insertion's untrusted state.

## Narrow startup checkpoint recovery

The inspected failure was an authenticated journal with one additional startup
honeypot intent beyond matching protected anchor and witness checkpoints. This
is consistent with an interrupted append/checkpoint sequence; the error alone
does not establish malicious activity.

`tools/recover_combat_startup.py` provides inspection by default. Its explicit
apply mode requires an exact review token, a stopped application and matching
authenticated authority. It accepts only paired startup-deception history ending
in one additional intent. It refuses containment history, altered inputs,
unmatched witnesses, incomplete records and invalid signatures. Before advancing
the existing checkpoint it preserves and verifies copies of the unchanged
journal, encrypted protected store and witness. It never truncates history,
creates a key, changes containment policy, replays a host action or starts Combat.
The normal startup recovery path then handles the remaining internal intent.

This is an operator-invoked maintenance path, not automatic acceptance of
ambiguous recovery state. General journal corruption, missing authority, legacy
anchors and histories containing containment actions still require separate
verified recovery. Complete privileged rollback of all local authority remains
outside a purely local software witness's guarantees.

## Performance evidence

- Idle queue wait changed from 0.25 s to 1 s: four scheduled empty wakeups per
  second become one. Queue arrival still wakes the worker immediately.
- A 500-event authenticated admission sample on the development host measured
  median **0.218 ms** and p95 **0.704 ms**, while all 500 events stayed queued and
  no host action ran. This is a local handoff measurement, not end-to-end threat
  containment latency or a cross-machine performance guarantee.
- A deterministic regression holds the journal lock on another thread and proves
  admission can still complete without filesystem target resolution.

## Validation

Final full offline suite in the original checkout: **3046 passed, 16 expected
platform skips** in 248.90 s. This includes USB cancellation, response readiness,
startup hold, recovery-command rejection and checkpoint revalidation regressions.

Headless selfcheck: **26 passed, 0 failed**. Module self-tests:
**69 passed, 0 failed, 16 expected platform/optional/unstarted skips**.
ARIA standalone checks: **15 passed**. Compilation of **372 source files**,
correctness lint and documentation drift checks passed. The response status panel
and USB approval prompt were rendered and visually inspected with synthetic data.

Tests use isolated runtime roots, inert files and mocked host-action boundaries.
The quarantine integration proves a verified receipt and byte-identical restore
of harmless test data. No external penetration test or exploit deployment was run.
