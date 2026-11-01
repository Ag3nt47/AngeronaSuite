# Angerona 1.15 recorder commit boundary

1 November 2026 · sanitized source-development follow-up

Application version remains 1.15.0; Windows metadata remains 1.15.0.0.
This follows the [remediation custody review](hardening-v1.15-2026-11-01-remediation-custody.md).
Signed deployment, independent enrollment and native protection acceptance
remain separate. The native shutdown P0 remains unresolved.

## Confirmed source defect

The batch telemetry writer previously included both its successful SQLite
commit and a later revision query inside the same retry/fallback handler.
If that later `SELECT MAX(id)` raised an OperationalError, rollback could not
undo the already successful commit. The retry inserted the same signed batch
again. The nonunique signature index permits these rows, while the returned
count described only one batch. A generic exception could instead spill
already committed input to the authenticated dead-letter queue.

Replay had a related accounting defect. Committed replay receipts prevented
another SQL insertion, but retry could describe the first attempt's newly
inserted rows as duplicates; a generic failure could retain an already
committed source segment. Single writes also placed postcommit bookkeeping
inside insertion error handling, although the existing pruning method caught
its own ordinary SQL errors. An ordinary prune SQL error alone does not prove
that single-write duplication path.

These are source-level counterexamples, reproduced with fixture faults.
They do not establish the cause or size of earlier host drive growth.

## Patch behavior

Single, batch and replay paths now capture their revision candidate before
commit. A failed precommit statement rolls back under the recorder's existing
writer lock before the established retry, fallback or source-retention path.
The returned-success commit branch is structurally outside those handlers.

After a successful commit, the recorder publishes its memory-only revision
before optional pruning. This is a monotonic committed-identifier high-water
mark, including when retention subsequently removes that event. Optional
maintenance has its own contained error handling and rolls back its separate
pending transaction. It cannot undo the earlier successful event/receipt
commit or change its original persisted/inserted/duplicate counts.

Signing, original event bytes, public result types and authenticated fallback
are preserved. This is not global signature deduplication, a migration or a
cleanup of historical copies. No existing evidence was rewritten for this
fix and no new startup capacity gate was added.

## Focused validation

The seven-file gate passed **64 tests in 26.89 seconds**, including **32 new
fault-injection cases**, with zero failures, errors or skips. Completed JUnit
independently reconciled all cases. The owned test child exited zero, native
wait and Job active count were zero, no force was used, native handle cleanup
was proved, and all 501 runtime source files plus selected saved preferences
remained unchanged. Whole-package Ruff and independent source/fixture review
passed. Prior gates remain separate cohorts.

Fixtures used temporary SQLite/files and a literal temporary key, with real
SQLite commits and deterministic connection proxies. They covered the former
postcommit revision-query failure, precommit query failures, transient and
exhausted partial-insert failures, escaping maintenance errors after a real
DELETE, rollback of an internally caught retention error, replay counts and
segment retirement, original signatures, revision-publication failure and
later catch-up, and high-water preservation when retention removes the newest
event. No host scanner, service, response action or network operation was
started by these tests.

## Fresh ordinary runtime observation

The frozen 501-file source manifest is
`d2a7e07ed6a977592689306bf82287cc5afdb0a2651c09a3d3b4aed0ca814e32`,
based on published 3489e05. Inventory count alone is not a revision identity.
A separate finite startup preflight passed before launch.

Ordinary Full60 and normal STOP met bounded lifecycle acceptance. Core native
exit was zero; all 45 unique observed generations, including Core, retired.
All 49 retained wait rows signaled and exact identity sets reconciled. Outer
diagnostic exit and Job active count were zero, native cleanup was proved,
and no forced retirement or application termination call occurred. Independent
after-STOP checks matched all 501 source files and selected preferences. A
later bounded process query found no matching application or recorder process;
polling is not complete historical process coverage or an indefinite guarantee
against reopening.

No storage fault or drive-full scenario was deliberately injected live. The
new error branches were exercised offline. Ordinary launch and shutdown do
not establish deployed prevention, complete persistence or full-storage
startup behavior.

The reader followed 170 event frames after hello cursor 6356, alongside 330
retained event frames. New severities were 97 informational, 47 medium, 24 high
and two low. Among the 73 non-informational frames, the available evidence and
reported classifications identify 22 declared exposures, five unavailable
notices and 46 unresolved observations/leads. No supported active detection
was established within that evidence; this is not a clean-host verdict.
Omitted details prevent wholesale independent reconstruction.

The initial 4,356-record retention gap remains explicit. All 1,472 diagnostics
and 198 coverage frames are retained history, not new probes. The exporter
reported 500 verified originals under HMAC-only scope; this analysis did not
independently recompute MACs or attest native producers.

The requested reader duration is 60 monotonic seconds, without exact recorded
wall-clock endpoints. The separate generated-status proxy spans 65.519 seconds
and includes 30 copies. Both recorder workers reported healthy/alive in every
copy, with zero admission-rejection counters, no admission-gap latch and zero
DLQ/replay failure or quarantine counters. All 70 copied runtime metrics
reported zero delivery drops. These cached process-lifetime values do not
establish durable or between-sample continuity.

End status retained 75 enabled workers running: 17 critical, 33 degraded,
one failed and 24 OK, with 69 unknown sensor sequence states. Four fresh
authenticated roles appeared in all 30 proxy samples. Core's two stale samples
and each other role's three stale samples occurred only after STOP confirmation.
Role liveness does not establish sensor or prevention coverage.

WM_NULL succeeded on all 30 probes, with a maximum of 219 ms. Cached GUI lag
ranged from 46 to 422 ms; copied metric age reached 9.642 seconds. One signed
age was negative by 36 ms, reflecting timestamp/read ordering rather than an
atomic clock observation. Core averaged 109.461%, inventory 9.338% and the
diagnostic process 6.391% of one logical CPU over a separate 63.079-second
sampled window. These are uncontrolled observations, not whole-machine
percentages, a causal speedup or click-latency measurements.

Fault copies preserved their prefixes. The diagnostic copy added 78,034 bytes
between Core binding and the pre-STOP read, with label `0x8001010d` and no
appended access-violation marker; its mtime precedes Full invocation. A later
named-file read after proved STOP/native retirement found both logs byte-identical
to their pre-STOP copies, with zero net append. This adds an after-STOP
observation to the earlier Core-live copies. It is not continuous logging,
writer attribution, hook-health verification or native P0 cause proof.

## Subsequent hosted validation

The published commit-boundary revision
**40124c7c6d3a32ada576c3fe66080daea4425c6d** subsequently passed all fifteen
hosted jobs, verified at 21:17:44 UTC on 1 November: twelve
[CI jobs](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/41348493869)
and three [security jobs](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/41348493832).
Both runs match that exact commit, main and the push event. These results
remain separate from the later
[optional-audit admission update](hardening-v1.15-2026-11-01-optional-audit-admission.md),
which requires its own publication and exact-commit hosted checks.

## Remaining limits

An exception raised by `commit()` can have an ambiguous outcome. This change
separates commits that returned successfully; it does not provide exactly-once
delivery for ambiguous commits or a failed rollback. Those existing policies
require a separate transaction-identity design. If revision-cache publication
itself fails, the cache can lag until a later successful write.

Row retention is not a physical byte/page quota. The telemetry database shares
its file with a separate remediation writer; WAL, schema/index allocation,
legacy entry sizes, raw/native output and constructor failures remain distinct
storage and startup concerns. No guaranteed response reserve, cross-process
budget or one-time history deletion is implied. A proposed reserve is not an
enforced allocation.

The Ring 3 and same-user boundaries, unavailable privileged providers,
independent-witness deployment and native P0 remain documented in the
[Word patch report](../docs/releases/Angerona_1.15_Security_Patch_Summary.docx)
and [readable Master Manual](../docs/master-manual.md).
