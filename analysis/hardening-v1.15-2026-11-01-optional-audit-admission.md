# Angerona 1.15 optional remediation audit admission

1 November 2026 · sanitized source-development follow-up

Application version remains 1.15.0; Windows metadata remains 1.15.0.0.
This follows the [recorder commit-boundary review](hardening-v1.15-2026-11-01-recorder-commit-boundary.md).
Native signing, installed protection acceptance and independent enrollment
remain separate. The native shutdown P0 is unresolved.

## Storage gap and separation from security journals

The optional legacy `RemediationLog.log()` writer previously had no complete
entry-size limit. Its raw metadata, serialized record and actual signed receipt
could therefore create a large row despite row retention. Its sole product
caller, the nested `_audit` in `apply_remediation`, ignored optional-write
results and swallowed exceptions. Adding only a size rejection would leave
omitted optional history invisible to that caller.

Seven optional branches cover proposals, skipped and dry-run decisions,
host-policy refusal, recovery-circuit hold, preparation failure and a failed
MUTATING transition. Native terminal completion and reconciliation instead use
their existing owned transaction writers. The new admission bound applies to
legacy `log()` only; it does not change `_insert_receipt_locked`, prepare,
terminal completion, reconciliation or the committed-evidence closure gate.

## Complete entry accounting and binding checks

Optional rows now have a 64 KiB logical UTF-8 entry limit. Accounting includes
every stored text field: raw trigger, MITRE identifier, action key/title,
outcome, `record_json`, actual `receipt_json` and receipt hash, plus a fixed
32-byte scalar allowance for identifier, timestamp, verification and host flag.
It is not an estimate of SQLite pages, WAL allocation or serializer peak memory.

Oversized or invalid entries receive a typed, bounded reason/size/limit refusal
before INSERT. They are not truncated, rewritten, re-signed as replacement
evidence, spilled or queued for automatic retry. A rejected optional entry
does not advance the receipt head or retention cadence, delete old history,
roll back someone else's transaction, or retire transaction/recovery ownership.
Accepted ordinary inputs preserve their existing JSON encoding, signatures
and receipt-metadata return shape.

Raw SQL text fields require plain strings. A string subclass can supply a
different value through DB-API adaptation; measuring its underlying text alone
would not constrain the bound value. Known custom adapters for the actual
builtin binding types—string, integer, float and NULL—also cause the optional
entry to be rejected. The guard neither invokes nor changes the registry;
unrelated adapters remain allowed. This assumes trusted SQLite binding and
does not resist a compromised process or concurrent global-registry changes.

## Visible omissions without response authority

Per-invocation results retain native applied/skipped/record fields and add
separate optional-audit attempted, recorded, rejected, unavailable and
persistence-unknown counts. Complete syntactic writer acknowledgments mean
only that an acknowledgment was returned; they are not independent
authentication or permission to mark a finding PATCHED. Missing/partial legacy
acknowledgments and generic database exceptions remain uncertain, not proven
lost writes. An exception raised by commit may follow an actual commit.

The current log instance exposes copied memory counters under a separate
short lock, including pending calls and a latched optional-history gap. The
getter takes no SQLite lock and performs no SQL, path, clock or native query.
Counters reset when that instance is replaced or the process restarts; they
are nondurable and do not attest writer health or complete history.

Status JSON/TXT uses a bounded whitelist. `remlog status` reads the projection
before history queries; an empty retained history still displays a gap.
Both remediation summaries display per-invocation optional counts separately
from native outcomes. Missing or malformed observations show unavailable with
unknown counts. No Healer restart, enterprise proof score, response authority,
new setting or startup scan/capacity gate was added. Other existing reporter
and console operations retain their own work and I/O.

## Focused validation

The thirteen-file gate passed **301 tests in 222.11 seconds**, with zero
failures/errors and one skip because directory symlinks were unavailable.
It included 95 new writer-admission cases and separate visibility regressions.
Completed JUnit independently reconciled all 302 outcomes. The owned child
exited zero, native wait and Job active count were zero, no force was used,
native handle cleanup was proved, and all 501 runtime source files plus
selected preferences remained unchanged. Whole-package Ruff and independent
source/fixture reviews passed. Historical cohorts are separate results.

Fixtures used temporary SQLite and HMAC keys with inert actions and denied
native command dispatch. They covered exact/one-over limits, UTF-8 and escaped
JSON, real receipt overhead, each raw metadata field, custom text/builtin
adapters, unchanged oversized history, signatures and chain continuation,
commit uncertainty, maintenance failure after successful commit, pending/reset
counter behavior, all seven caller branches and unavailable acknowledgments.
A tiny optional limit did not block genuine intent, terminal or reconciliation
receipts; rejected optional history could not close a Posture finding. Status
tests trapped SQL/path/clock work, checked privacy and empty-history output,
and destroyed their own inert offscreen dialogs without shutting down the
session-owned Qt application.

## Fresh ordinary runtime observation

The frozen 501-file manifest is
`9c854a3cdbf439baab7b623f6703b69bd7be8745dfcd590d72609c548050bb34`,
based on published 40124c7. Inventory count alone is not a revision identity.
A separate finite startup preflight passed before launch.

Ordinary Full60 and normal STOP met bounded lifecycle acceptance: Core native
exit zero, all 55 unique observed process generations including Core retired,
all 59 retained wait rows signaled, and exact identity sets reconciled. Outer
diagnostic exit/Job active count were zero, native cleanup was proved and no
application termination or forced retirement occurred. Independent after-STOP
checks matched all 501 source files and selected preferences; a later bounded
query found no matching app/recorder process. Polling does not reconstruct
complete historical process activity or guarantee indefinite non-reopening.

Oversized entries and custom adapters were not deliberately injected live.
Ordinary runtime and shutdown do not prove live refusal efficacy, complete
telemetry or deployed protection.

The reader followed 164 new event frames after hello cursor 6334, alongside
310 retained event frames. New severities were 87 informational, 46 medium,
29 high and two low. The 77 non-informational frames comprise 23 exported
exposures, 49 exported observations/leads and five health/coverage notices.
Two of those health classifications are candidates based on AI module/message
matching, rather than an exported disposition. No supported active detection
was established within the examined evidence; this is not a clean-host verdict.
A critical frame was retained history, not a new detection in this window.

Details were omitted from 159 new events, including 76 non-informational
frames, preventing wholesale independent reconstruction. The initial
4,334-record retention gap remains explicit; record sequence 4335–6498 is
unique and contiguous. All 1,489 diagnostics and 201 coverage frames are
retained history, not fresh probes. The exporter reported 474 HMAC-only
verified originals. This analysis did not independently recompute MACs or
attest native producers.

The requested reader duration is 60 monotonic seconds, without exact recorded
wall-clock endpoints. A separate cached-status proxy spans 65.565509 seconds
and contains 30 copies. The new optional-audit projection is observed in all
30: all eight counters, including attempted, rejected, unknown and pending,
are zero; the gap latch is false and scope is nondurable/current-instance with
false response authority. All 69 copied projections agree. These observations
do not exercise admission or certify complete history.

Both recorder workers reported healthy/alive in all 30 proxy samples, with
zero admission, DLQ failure, replay failure and quarantine counters. All
69 copied runtime metrics reported zero delivery drops. Cached values are
not durable or between-sample continuity evidence. Four fresh authenticated,
tree-bound heartbeat roles appeared in all 30 proxy samples; each role's
three unavailable samples occurred only after STOP confirmation. Liveness
does not attest kernel telemetry or prevention.

End status retained 75 enabled workers running: 16 critical, 35 degraded,
one failed and 23 OK, with 69 unknown sensor sequence states. Native ETW/Sysmon
coverage remained unavailable in the canary reports. WER had 18 admitted and
12 stale cached copies, maximum age 2.953 seconds and unverified upstream
delivery; AI had 14 unmeasured and 16 circuit-open copies, with no model/request
attempts. These are scoped copied states, not continuous provider guarantees.

WM_NULL succeeded on all 30 probes, maximum 78 ms; cached GUI lag ranged from
47 to 234 ms. Core averaged 119.463%, inventory 8.949% and the diagnostic
process 6.074% of one logical CPU over a separate 62.506-second sampled window.
These uncontrolled observations are not whole-machine percentages, a causal
performance comparison or click-latency measurements.

Fault copies preserved their prefixes. The diagnostic log added 77,391 bytes
between Core binding and pre-STOP read, including label `0x8001010d` without
an appended access-violation marker; its mtime precedes Full invocation. Both
named logs read after proved STOP/native retirement were byte-identical to
their pre-STOP copies, with zero net append. These bounded copies do not prove
continuous logging, hook health, writer attribution or the native P0 cause.

## Remaining exposure

Existing oversized rows are preserved. This is no physical database/page/WAL
quota, cross-process storage reserve or bound on temporary serialization.
Shared writers, cross-restart row ceilings, raw/native output, cache policy
and constructor/schema failure under actual full storage require separate
accounting. This patch adds no automatic history deletion or replacement.

A concurrent adapter-registry change or compromised Python process can bypass
in-process assumptions. Same-user writable state, kernel control, unavailable
privileged providers, independent-witness deployment and the native P0 retain
their documented limits. The [Word patch report](../docs/releases/Angerona_1.15_Security_Patch_Summary.docx)
and [Master Manual](../docs/master-manual.md) retain the broader exploit classes,
deployment requirements and residual exposure criteria.
