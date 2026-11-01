# Telemetry storage and dialog recovery review

1 November 2026 · Angerona 1.15.0 source development

The change adds observed storage admission for the telemetry writer and repairs
a reproducible interrupted reveal path. It preserves recorded history and
reports unavailable facts, volatile pending work and rejected deliveries.
It does not establish an OS quota, a completed native P0 diagnosis, an Optimus
actor or an accepted signed production deployment.

## Telemetry writer scope

Production GUI and headless startup apply the policy after recorder construction
and before asynchronous workers start. A bare recorder remains explicitly
unconfigured for legacy callers. Defaults are database 256 MiB, WAL 64 MiB and
a 2048 MiB free-space floor. Accepted settings ranges are database 16–16384 MiB,
WAL 4–1024 MiB and free space 512–65536 MiB, with a separate strict Block flag.
The complete logical write unit is fixed at 1 MiB, counting stored SQL text and
escaped dead-letter representation. Upstream serialization still allocates
before this admission boundary; it is not a memory-byte quota.

Workers sample exactly the database, WAL, SHM and their volume. Cached getters,
policy changes and UI refreshes perform no storage probe or SQL work. Generation
checks reject mismatched observations and short memory locks are released before
native I/O. Sampled sizes are advisory observations, not an atomic aggregate or
filesystem-enforced quota. The remediation journal shares this database.
Constructor/schema work, other/native writers and namespace attacks remain
outside this telemetry policy. No guaranteed response reserve is claimed.

## Holds and operator decisions

An immutable acknowledged prefix prevents a storage hold from replaying already
committed rows or acknowledged spool data. Held work is distinct from a generic
write/replay/dead-letter failure or a runtime-healer restart signal. Already
admitted finite work may finish after a newer Block; instant cancellation is not
promised. Commit-raised uncertainty remains a separate result.

Bounded per-lane pending slots preserve admitted work in memory. New deliveries
in definitive hold reject with explicit subgroup counts and a latched,
nondurable coverage gap. Workers remain alive and parked, probe within their
bound, and wake for STOP. A false drain is reported while volatile pending work
remains; retirement of a worker thread is separate from native process
retirement. Exiting the process can lose unpersisted work.

Settings > System and Full Setup expose the same four fields. Block, Allow and
Apply change this run; Save separately persists the choice. Allow acknowledges
policy acceptance while fresh worker facts may still be pending. Close, Escape
and Keep do not alter policy. Warnings are nonmodal and deduplicated. No
database-delete button, automatic history cleanup, checkpoint or vacuum was
added under hold.

A single oversized volatile pending event can be discarded only after a
nonmodal confirmation defaulting to No. The exact parked token and matching
policy, worker and pending generations must still be current and not in flight.
Stale requests are refused. User-discard counts and the coverage gap remain
latched; recorded history, replay originals and recovery copies are preserved.
Oversized durable replay remains preserved and defers separately, allowing
otherwise valid new telemetry.

## Cached status and counters

Status JSON/TXT and the runtime-healer evidence whitelist expose only fixed,
bounded copied fields. Malformed or absent observations are unavailable with
unknown counts. Ready requires coherent generations, required facts, no stale
or pending probe, an unblocked configured policy and a valid fixed reason.
Availability remains separate from continuity.

Pending, rejected, user-discarded and write-failure counters are nondurable and
reset with the instance. Runtime metrics count user discards once alongside
parent admission rejection; the storage-hold subgroup is not added twice.
Hold, replay-deferral and maintenance-deferral values count cumulative attempts,
not distinct events or a present replay/maintenance backlog. Write failures
include unconfirmed outcomes. Zero gaps do not establish complete history.

## Dialog recovery

Destroying a reveal animation's current target could leave a queued window
with its narrow transition mask and no progressing coordinator. The repaired
source path restores queued windows and releases masks through target loss,
close and shutdown handling. Regression tests exercise this counterexample.
The historical outline-only incident was not captured in this run, so this
does not attribute its cause, establish Optimus interference or close native P0.

## Offline validation

The fixture-corrected focused gate passed 447 tests in 89.48 seconds with no failures, errors or skips. A later disclosure-label source edit separately passed 447 tests in 70.12 seconds with no failures, errors or skips. Whole-source Ruff and the finite startup preflight also passed; their receipts remain separately scoped.

The initial focused run's five failures and 442 passes in 132.11 seconds remain
preserved. The fixture-only correction aligned inert capacity fixtures, waited
for the timer's actual start, supplied an explicit cached fake and expected the
exact expanded DTO. That separate run passed 447 tests in 89.48 seconds;
production source was unchanged only between those initial and fixture-corrected
attempts, and boundary assertions were retained and reviewed. The later
disclosure-label source edit passed its own 447-test gate in 70.12 seconds.
These are fixture and failure-path tests, not deliberate drive exhaustion on
the user's live data.

## Fresh ordinary operation and shutdown

The final disclosure-label epoch's ordinary Full60 and normal STOP met bounded lifecycle acceptance: native Core exit zero, 51 unique observed process generations and all 55 retained wait rows signaled. The 503-file source snapshot and selected saved preferences were unchanged. Child exit codes and complete process history were not established; no drive-full or storage-hold fault was injected live.

The final epoch's 51 observed identities comprise Core and 50 descendant
generation rows; 55 wait rows include repeated waits. This is not a complete census of every
short-lived child. The owned diagnostic job ended empty with normal cleanup
and no forced retirement. Its total process accounting is a separate scope,
not additional Angerona detector coverage or verified child exit codes.

The source inventory SHA-256 was `19b05c8c7c053ddf58d4e3d801f012f3cf1ce552a85a11724aca8469c2ef4116`. Independent retained-handle
review accepted lifecycle retirement, source identity and the selected saved
preference bridge. Neither this ordinary Full60 run nor source preservation
proves storage-hold efficacy, every detector's availability or durable event
continuity.

Before the disclosure-label edit, a separate ordinary Full60/STOP observation
accepted 44 observed identities (Core plus 43 descendant rows) and 48 signaled
wait rows against source inventory `ad5d02c07a204a0f045205ace1618e3d0e7bf5ed05af271c0ae9aad6c6c3b8e2`. That earlier
epoch and its 89.48-second fixture-corrected gate remain preserved historical
evidence; they do not substitute for the final source's 70.12-second gate and
51-identity observation above. The same child-exit, process-history and live
storage-hold limitations apply to both epochs.

### Alert and counter review

The final disclosure-label epoch contained 156 new events after hello cursor 6401 and 353 disjoint retained events. New severities were 21 HIGH, 37 MEDIUM, 3 LOW and 95 INFO; retained included one CRITICAL exposure from Immutable Recovery Assurance Guard. Explicit medium-or-higher dispositions were new: 17 exposure, 38 observation, one health and two missing; retained: 10 exposure, nine observation, two health and 34 missing. Details were omitted from 151 new and 309 retained events (1,379 and 2,007 fields). The 509 events carried exporter-reported HMAC-only verification flags; analyst MAC and native producer verification were not performed. The initial retention gap was 4,401; 2,156 data frames were contiguous, with zero hello-reported reader queue drops. Omissions prevent complete classification. The first-epoch retained Persistence Sweep HIGH/active candidate remains unresolved; approximate message/time linkage and a generic HIGH fallback do not prove hostile execution or harmlessness. No alert, baseline, allowlist or trust enrollment was cleared.

The requested 60-second reader and 62.324-second cached-status proxy are distinct. In 29 copied statuses (20 unique generated statuses), storage was configured and unblocked: eight ready and 21 unmeasured (19 stale facts, two pending probes). Database/WAL/SHM observations were 42,250,240 / 16,777,216 / 32,768 bytes, with approximately 12.95 GB free. Pending count ranged zero to four and ended zero; three primary parked observations held one event. Rejections, discards, write failures, overflow and the reported storage gap were zero/false. Replay deferrals and hold attempts rose from 19 to 35 as cumulative attempts, not backlog. Both recorder workers were healthy/alive throughout these copies. RuntimeMetrics reported zero drops in 28 available copies; one observation was unavailable. Optional audit counts were zero and gap false, but are instance-lifetime/nondurable and do not prove historical continuity.

All four heartbeat roles were fresh in all 29 copies; unavailable samples occurred after STOP. All 29 WM_NULL probes responded, maximum 156 ms. Of 75 enabled running modules, health was 23 ok, 34 degraded, 17 critical and one failed; 69 sensor coverage states were unknown. AI request state was 19 unmeasured and 10 circuit-open, without model/request stage entries. This is bounded ordinary observation, not a clean-host, complete coverage or kernel-health verdict. No live drive-full fault was injected; fake-full tests are separate. Selected fault prefixes were preserved; diagnostic growth of 78,755 bytes had no appended AV/fatal-Python marker and source mtimes preceded Full. Both post-STOP copies matched pre-STOP. This does not establish continuous logging or resolve native P0. The offline parser exited normally, with signaled native wait, an empty owned Job and proven cleanup.

### Named fault-log comparison

After native retirement, both selected fault logs were byte-identical to their
pre-STOP copies with zero appended bytes. This named comparison does not prove
continuous logging, writer/hook health, every teardown path or native cause.
The earlier 77,656-byte COM-labeled diagnostic delta predates the Full invocation
and remains unattributed. Raw originals and prior failures remain private and
preserved; a later exit-zero receipt does not establish a repaired native fault.

## Hosted checks

Published base e0bdebb completed 15 hosted jobs: 11 passed and four Python jobs failed the same six stale optional-audit dictionary-shape assertions. Each failing Python job also reported 12,280 passes and 37 skips. Those expectations were updated while retaining their boundary assertions. Local focused success does not establish hosted success for the changed revision; the new published commit requires its own check results.

## Remaining work

These are sampled telemetry-writer admission targets, not an OS filesystem quota, atomic aggregate or guaranteed response reserve. The remediation journal shares the database; constructor/schema work, other/native writers, upstream serialization allocations and namespace attacks remain outside this policy. Native P0, same-user/kernel trust boundaries and independent deployment requirements remain unresolved.

Longer realistic workloads, deliberate hold/resume and crash recovery in
controlled disposable environments, independent native diagnosis and the
separately accepted signed/service/hardware deployment remain required. No
alerts, evidence baselines or trust enrollment were cleared to produce these
results. AI text, external tools and a green heartbeat confer no response
authority. Raw host evidence remains private; this record is a sanitized review.
