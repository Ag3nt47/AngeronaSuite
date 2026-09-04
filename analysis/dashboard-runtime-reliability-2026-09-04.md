# Dashboard and module reliability — September 4, 2026

The reported freezes matched repeated capability source-path verification on the
GUI thread and complete alert-table rebuilds. Runtime diagnostics also identified
Defender outbox payload conflicts, Sysmon retained-history startup timeouts, and a
response module repeatedly exiting when journal prerequisites were unavailable.

## Changes

- Capability source evidence is verified by one bounded background worker.
  Display snapshots expire after 30 seconds; pending, expired, and failed checks
  report unavailable source evidence until verification completes. Existing
  descriptor, path, digest, and provenance checks remain in use. Source-edit and
  response authorization do not use this presentation cache.
- Alert refreshes retain unchanged rows by complete event identity. Rendering is
  capped before insertion, sorting and painting are restored even after an
  exception, and equal-timestamp records remain distinct. The ten-minute detail
  window now reports minutes instead of displaying “0h”.
- Defender continuity-report IDs include the complete payload, including changing
  counters. Repeated reports and restarts no longer collide with a different
  payload under the same ID. Durable outbox authentication and conflict rejection
  are preserved; existing evidence is not deleted or reset.
- Sysmon replays at most 256 records per poll with a one-second cooperative work
  budget and stop checks. Each consumed contiguous prefix is checkpointed before
  yielding; the next poll rechecks generation and exact cursor identity. Native
  I/O and a single record's processing are not forcibly interrupted by this budget.
- A response module with an unavailable journal stays blocked and waits
  interruptibly. It retains the actual error, does not subscribe for response
  execution, and does not automatically rearm or trigger a restart storm.
- Storage Hygiene recognizes the intentional per-user `Angerona/SourceData`
  profile. Generic overlap/reparse rejection and retired migration/purge
  boundaries remain intact.

## Validation

Nine new offline regressions cover blocked source reads, snapshot expiration,
incremental alert rendering, render-error cleanup, Defender repeated/restarted
reports, bounded Sysmon replay and stop behavior, blocked response lifecycle, and
source-profile storage handling. All nine pass.

An isolated offscreen dashboard benchmark used 84 discovered modules, 120 alert
rows, and 30 refreshes without starting live sensors. Module refresh measured
39.39 ms median / 55.05 ms maximum; alert updates measured 11.21 ms median /
18.12 ms maximum. The maximum UI heartbeat gap was 133.85 ms. These are local
measurements, not a guarantee under full sensor load.

The supported `run-selfcheck.bat` completed all 26 phases with no failures;
its module SelfTestRunner recorded 69 passes, no failures, and 16 expected
platform/unstarted/optional-prerequisite skips. Package/tool compilation, Ruff,
and documentation-drift checks passed. The full serial regression suite passed
**2,891 tests with 15 expected skips and no failures in 580.41 seconds**.

## Remaining host prerequisites

Unelevated source launches cannot provide administrator-only event sessions,
protected response authority, or native driver coverage. Missing recovery-copy
and restore-test attestations continue to report missing evidence. This update
does not fabricate those prerequisites, discard journals, change recovery policy,
or disable integrity checks. Historical diagnostics remain available for review.
