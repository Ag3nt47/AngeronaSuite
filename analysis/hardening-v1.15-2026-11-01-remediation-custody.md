# Angerona 1.15 remediation custody and receipt retention

1 November 2026 · sanitized source-development follow-up

Application version remains 1.15.0; Windows metadata remains 1.15.0.0.
This follows the [recorder admission review](hardening-v1.15-2026-11-01-recorder-admission.md).
Native signing, installed service acceptance and hardware protection remain
separate from a source version label. The native shutdown P0 is still unresolved.

## False closure after terminal journal failure

The vetted remediation framework records an owned intent before dispatch and
requires a terminal journal transaction afterward. A native postcondition can
pass while that final transaction fails. The framework correctly retains the
native `verified=True` observation, reports recovery required and preserves the
unresolved transaction. Posture Hardening previously used truthy `verified` and
a technique identifier to mark the weakness PATCHED anyway.

That was a false-closure path: PATCHED could be reported without successful
terminal custody. This framework's current executable catalog contains Registry
Hardening; its process/network action proposals remain separate. The finding
does not establish that the earlier startup or storage symptoms used this path.

Posture now requires all of the following before both PATCHED state and a
verification-proof event:

- An actual boolean native verification result, applied state, no recovery or
  journal-error indication, and membership in the requested finding cohort.
- Well-formed transaction, receipt and action identities.
- A successful read of authenticated, committed application evidence bound to
  the exact transaction, action and MITRE identifier.

The native observation is preserved when durable closure is held. A missing,
malformed, unsigned, pruned, unavailable or inconsistent receipt cannot close
the finding. Signature-field presence alone supplies no authentication.

## What the committed-evidence reader checks

The reader uses one indexed joined query under the existing custody lock. It
binds the current unowned/unclaimed APPLIED transaction to the retained audit
receipt and its signed body: action, technique, host scope, outcome, passed
verification, time, trigger rules and canonical transaction-record identity.
Receipt-body verification alone does not authenticate separate SQL columns;
their agreement is checked explicitly. Reconciliation uses its explicit trigger
and must also have passed verification.

A connection with an existing SQLite transaction is refused without commit,
rollback or other repair. The verifier must not treat that connection's own
authentic but uncommitted rows as committed evidence or take over another
transaction owner's work.

SQL bounds constrain physical projections before Python materializes JSON;
logical UTF-8 format limits are checked before parsing. UTF-16 database storage
and Unicode serialization overhead are covered. The accepted strict signed
metadata limits are 32 characters for MITRE and 128 for action identifiers;
the actual executable catalog fits. Longer generic transaction metadata is
held rather than accepted through a truncated signed prefix.

This proves retained local committed evidence. It is not a fresh host recheck,
independent witness, kernel attestation or protection against a compromised
signing context. Earlier matching-state rollback boundaries remain.

## Durable-only audit growth

Legacy `log()` counted successful audit inserts toward the existing
10,000-row/every-500-write prefix-retention policy. Ordinary terminal completion
and reconciliation also inserted receipts but did not advance that counter.
Durable-only workloads could therefore grow the audit table indefinitely.

All three successful receipt writers now participate in the same postcommit
accounting. Retention removes only the eligible oldest contiguous audit prefix;
retained records, signatures and links remain unchanged. Unresolved transaction
and reconciliation-claim custody are preserved under their separate rules.
The retained-chain verifier already accepts the first retained receipt's
previous hash as its checkpoint; interior deletion is not substituted for that
policy.

Owner/proof capabilities retire only after successful terminal commit, before
optional maintenance. Retention runs in a separate best-effort transaction;
its failure cannot report an already committed terminal operation as failed or
delay capability retirement. Failed terminal commit still preserves ownership
and unresolved state.

This is amortized row retention, not a physical-byte quota, complete-history
guarantee or reliable cross-restart hard ceiling. Existing database allocation
need not shrink when rows are retired.

## Focused validation

The eight-file gate passed **93 cases in 139.43 seconds**, with zero failures,
errors or skips. Completed JUnit independently reconciled all 93 cases. The
owned child exited zero, native wait and Job active count were zero, no force
was used, native handle cleanup was proved, and source plus selected preferences
remained unchanged. Whole-package Ruff and independent source/fixture review
passed. These results are separate from the earlier recorder cohort.

Fixtures used temporary SQLite stores, literal temporary signing keys and inert
actions. Native command dispatch was denied; no host registry or network change
was performed for these tests. Coverage included genuine signed closure,
terminal journal failure with the native fact preserved, unsigned/presence-only
proofs, wrong identities, signed-body/SQL disagreement, uncommitted authentic
rows, unavailable custody, full-size Unicode records in UTF-8 and UTF-16 stores,
genuine reconciliation, prefix retention and maintenance-failure lifetimes.

## Fresh ordinary runtime observation

The changed source used a frozen 501-file inventory identified by manifest
`79bae93dac85933b7ba2f027a8b93608df70c3c7faf92835b0253782d1c4d0eb`,
based on published 9e2ccb9. Inventory count alone is not a unique revision.
A separate finite startup preflight passed before launch.

The ordinary Full60/normal-STOP run met bounded lifecycle acceptance: Core
native exit zero, 48 unique observed generations including Core, all 52 retained
wait rows signaled, exact identity sets reconciled and native cleanup proved.
Outer diagnostic exit/Job active count were zero; no application termination
or forced retirement occurred. Independent after-STOP checks matched all 501
source files and selected preferences. Polling is not complete short-lived
process history.

The live run did not deliberately invoke vetted host remediation or fill the
drive. The new closure and retention failure branches were exercised offline;
ordinary launch and shutdown do not establish deployed enforcement efficacy.

The reader followed 345 event frames after hello cursor 6420, alongside 409
retained event frames. New severities were 294 informational, 32 medium, 17 high
and two low. The available evidence and reported classifications identify
15 declared exposures, five unavailable-coverage notices and 31 unresolved
observations/leads among the 51 non-informational frames. No supported active
detection was established within that evidence; this is not a clean-host
verdict. Omitted details prevent wholesale independent reconstruction.

The initial 4,420-record retention gap remains explicit; subsequent record
sequence 4421–6765 is contiguous. All 1,402 diagnostics and 189 coverage frames
are retained history, not new probes. The exporter reported 754 verified
originals under HMAC-only scope; this analysis did not independently recompute
MACs or attest native producers.

The requested reader duration is 60 monotonic seconds, without exact recorded
wall-clock endpoints. Its separate cached-status proxy spans 64.170 seconds
and includes 29 sample copies. All reported both recorder workers healthy/alive,
zero admission counters, no admission gap, and zero DLQ/replay failure or
quarantine counters. All 70 copied runtime metrics reported zero delivery
drops. These cached process-lifetime values do not establish between-sample
or durable continuity.

End status retained 75 enabled workers running: 17 critical, 34 degraded,
one failed and 23 OK, with 69 unknown sensor sequence states. Four fresh
authenticated roles appeared in every proxy sample; each role's three
unavailable samples occurred only after STOP confirmation. Role liveness does
not establish sensor or prevention coverage.

WM_NULL succeeded on 28 of 29 probes; one exceeded 500 ms and the next sample
responded. Cached GUI lag reached 1,250 ms. Core averaged 118.280% and inventory
9.620% of one logical CPU over a separate 62.207-second sampled window. These
are uncontrolled observations, not whole-machine percentages, a causal speedup
or a click-latency measurement. The UI pause remains unresolved.

Fault copies preserved their prefixes. The diagnostic copy added 77,088 bytes
with native label `0x8001010d` and no appended access-violation marker; its mtime
precedes Full invocation. Copies exclude final STOP teardown. Native exit zero
and selected fault bytes do not resolve the P0 cause.

## Distinct hosted validation

The preceding published recorder commit
**9e2ccb92dd9732427554366f43fef5f4ecd027ff** passed all fifteen hosted jobs,
verified at 20:05:46 UTC on 1 November: twelve
[CI jobs](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/41342027496) and
three [security jobs](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/41342027479).
Both runs match that commit, main and the push event. These successes do not
validate this later custody revision, which requires its own publication and
checks.

## Remaining storage and startup limits

Runtime database byte/free-space admission remains design work. The telemetry
ledger shares its database with the durable remediation journal; a recorder-only
target cannot be called an aggregate quota or a guaranteed response reserve.
The proposed 64 MiB reserve is unproved and has not been enforced.

Legacy optional audit entries still lack a whole-record byte limit. Terminal
transaction retention has a separate count limit; WAL, schema/index allocation,
raw dashboard output and native/external writers require their own accounting.
Existing constructor/schema failures under actual full storage or bad custody
remain separate startup risks. This fix adds no new capacity refusal, page cap,
startup veto, automatic database replacement or blanket evidence deletion.

Source development retains its Ring 3, same-user trust and native-provider gaps.
The [Word security report](../docs/releases/Angerona_1.15_Security_Patch_Summary.docx)
keeps the broader exploit classes, required deployments and residual criteria.
