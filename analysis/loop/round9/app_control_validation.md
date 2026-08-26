# Round 9 Loop 2 — App Control Decision Evidence Validation

Date: 2026-08-25
Scope: `core/app_control_evidence.py`, `modules/app_control_monitor.py`, their
focused tests, ModuleManager discovery, targeted self-test, authenticated cursor,
Code Integrity Event Log API usage, lifecycle ownership, and live-host schema.

## Result

- **Focused regression tests:** 16 passed
- **Focused Ruff:** passed
- **Discovery:** 68 modules, 0 errors; App Control Decision Evidence present
- **Targeted self-test:** event pipeline + App Control module, 2 passed / 0 failed
- **Live modern Event Log API:** channel high watermark 1741; bounded query and
  handle cleanup completed without error
- **Live schema/correlation gate:** 256/256 events parsed, 107/107 decisions
  correlated complete, 0 missing decision paths, 0 parser errors
- **Repository compile/Ruff:** 310/310 compiled; full Ruff passed
- **Full pytest:** 1,285 passed, 3 skipped, 1 documentation-drift failure
  (`README.md` still says 67 modules while static discovery is now 68). This is
  the expected documentation-owner follow-up for the newly added module, not a
  functional App Control defect.
- **Defects fixed:** 5 related defects in five root-cause families

## Microsoft contract cross-check

Microsoft documents that CodeIntegrity/Operational carries the 3004, 3033,
3034, 3076, and 3077 decision events; 3089 carries one row per signature and is
joined by `System/Correlation/@ActivityID`. Unsigned files produce one 3089 row
with `TotalSignatureCount=0`. It also explicitly notes that 3004/3033 can occur
without an App Control policy. The implemented source uses the supported modern
EvtQuery/EvtNext/EvtRender handle flow and closes both event and query handles.

References:

- https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations
- https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/operations/appcontrol-debugging-and-troubleshooting
- https://learn.microsoft.com/windows/win32/api/winevt/nf-winevt-evtquery
- https://learn.microsoft.com/windows/win32/api/winevt/nf-winevt-evtnext

## Fixed defects

### FIXED — cursor authority failure became falsely healthy

When the cursor signing key was unavailable, the first poll correctly set health
55, but a second idle poll set health 100 even though no authenticated restart
checkpoint existed. An untrusted cursor with no selected events also remained
unrepaired. The sensor now tracks cursor authentication explicitly, retries an
idle repair, and cannot report healthy without a trusted checkpoint.

Gate: `test_cursor_authority_failure_never_becomes_false_healthy` and
`test_untrusted_cursor_is_repaired_but_gap_stays_visible_for_poll`.

### FIXED — degraded evidence was overwritten in the same poll

Partial joins, channel record-number regression, cursor authentication failure,
and parse degradation could be immediately overwritten by the generic idle
health branch. Per-poll degradation is now explicit; a clean later poll may
recover health, while the poll that observed the gap remains degraded and emits
the evidence.

### FIXED — ActivityID groups were not individually bounded

The number of correlation groups and dedup records was bounded, but a hostile or
malformed stream could keep one ActivityID alive forever while growing its
decision list or signature dictionary without limit. Per-group records are now
strictly capped; excess decisions produce `bounded-eviction` evidence and
signature overflow is retained only within the cap and marked untrusted.

Gate: `test_correlation_group_state_is_bounded_under_one_activity`.

### FIXED — closed owned source remained attached across restart

The run-finalizer closed an internally owned event source but retained it in
`self._source`. Current `WindowsCodeIntegritySource.close()` is a no-op, which
masked the lifecycle error; any future source session/handle would be reused
after close on restart. The finalizer now detaches exactly the source it closed,
so the next generation constructs a fresh adapter.

Gate: `test_owned_source_is_detached_after_close_for_clean_restart`.

### FIXED — live 3033 schema lost file/process/signing evidence

The fixtures used `FileName`/`ProcessName`, while live Windows 3033 records on
the audit host used `FileNameBuffer`, `ProcessNameBuffer`, and `ValidatedPolicy`.
The parser accepted the records but discarded the canonical path fields, so real
alerts rendered as generic `code`. Canonical aliases now preserve those values.
The message also no longer invents an App Control policy attribution for
3004/3033/3034 records that contain no policy metadata; those are correctly
described as Code Integrity decisions.

Gate: live 256-event sample after the fix had 0 missing decision paths and all
107 decisions correlated complete; the real-schema fixture is permanent.

## Self-test correction

The module self-test previously claimed the ActivityID join was ready after only
parsing one 3077 fixture. It now actually feeds a decision and unsigned 3089 row
through `DecisionCorrelator` and requires one `complete` result.

## Reported scope gaps (not changed in this correctness review)

- The selected sensor set covers the main Code Integrity/App Control decision,
  3089 signature, and policy-activation events. Microsoft also documents other
  relevant Code Integrity decisions such as 3064/3065, 3079/3080/3081/3082,
  3104, and 3114, plus the separate AppLocker MSI/Script channel. Adding those is
  a capability-design expansion rather than an obvious regression fix.
- The initial `T1553.006` tag was removed from generic decisions: a blocked code
  load is control evidence, not proof an adversary modified code-signing policy.
- A permanently inaccessible channel currently emits a recurring health event
  each poll. Alert coalescing/backoff would be a useful operational enhancement,
  but changing global alert cadence was outside this low-risk validation.

## Final integrated closure

The later design/adversarial loops expanded this implementation beyond the
initial validation above. Final focused App Control coverage is **35 passed**.
The sensor now has strict 3089 cardinality, authenticated restart-safe pending
groups, per-group hard bounds, default path-redacted details, exact oldest-
retained gap intervals, dedupe reset on channel generation changes, and an
HMAC-authenticated schema-v2 cursor bound to the SHA-256 of its exact WEVT
record.

Three deterministic clear/refill races are permanently covered: replacement
before a poll, replacement after initial anchor admission but before the staged
query, and replacement between terminal admission and cursor write. Raw rows
are staged before parsing/emission, the prior record anchor is revalidated, and
the terminal anchor is compared both before and after pending-state persistence.
The admitted anchor—not a fresh unbound replacement—is stored. Mismatch emits a
gap, resets correlation/dedupe, and replays from the oldest retained record.

Final independent late-flip probe: gap detected, six replacement rows replayed,
replacement decision emitted exactly once, authenticated cursor at record 6.
The full-tree final gate is recorded in `summary.md`. Physical WEVT clear,
rollover, restart, and suspend/resume soak remains an external acceptance gate.
