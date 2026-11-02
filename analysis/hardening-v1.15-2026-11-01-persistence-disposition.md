# Persistence baseline classification review

1 November 2026 · Angerona 1.15.0 source development

Pre-existing startup configuration remains urgent review evidence without
claiming observed hostile execution from enrollment alone. The change adds
explicit observation metadata to new baseline emissions and a narrow legacy
projection. Original severity, evidence, signatures and unreviewed baseline
state are preserved. No response authority is introduced.

## New and retained evidence

The producer adds exactly four fields to baseline-enrollment events:
`disposition="observation"`, `finding_kind="observation"`,
`active_attack=False` and `response_authority="observe-only"`.
It retains HIGH/CRITICAL risk severity, the existing bounded value, surface,
entry and MITRE evidence, `baseline_trust="unreviewed"` and
`response_authorized=False`. Inventory is not enrollment as trusted software.

For retained events, the classifier recognizes only the normalized Persistence
Sweep producer at HIGH/CRITICAL severity with an exact plain dictionary of
seven keys: `change`, `surface`, `entry`, `value`, `mitre`, `baseline_trust` and
`response_authorized`. The six text values must be plain strings, the change
must equal `baseline_enrollment`, trust must equal `unreviewed` and response
authorization must be literal `False`, not zero or a text representation.

Any missing or extra field refuses the legacy projection, including active
signals, response contracts, corroboration or unknown future metadata. Existing
explicit classification and active-signal branches keep their precedence.
Other producers, lower severities, dictionary/string subclasses and near-match
values do not enter this special case. Added, modified and removed persistence
changes retain their prior path. Signed retained bytes are not rewritten.
The observation remains visible in review and priority retention; it does not
become an active-attack count solely because of its HIGH/CRITICAL severity.

## Validation

The 14-file focused cohort passed 390 cases with two filesystem-availability skips in 45.44 seconds, including 48 new classification cases. Whole-source Ruff and finite startup preflight passed. These are bounded local checks, not hosted acceptance.

The 48 new classification cases are included in that cohort, not 48 additional
cases to add to its 390 passes. Tests cover real baseline production, signed
retention and original-byte preservation, strict metadata/type boundaries,
active and explicit precedence, added/modified changes and cached visibility.
The two skips remain explicit coverage gaps. Gate and preflight recorded the
same 503-file runtime map and unchanged selected preferences; their diagnostic
processes retired normally with empty owned jobs and proven handle cleanup.
No additional test run is performed by the documentation builder.

## Fresh ordinary operation

A separate ordinary Full60 and normal STOP met bounded lifecycle acceptance: native Core exit zero, 45 unique observed identities and 49 signaled retained waits; the 503-file source snapshot and selected preferences were unchanged. Child exit codes and complete process history remain unverified. This was not a malware scan, canary or native kernel-enforcement test.

The 45 identities include Core plus 44 descendant generation rows; 49 wait rows
include repeated waits. The owned diagnostic job ended empty and exited zero
without forced retirement. Its total process accounting is a separate scope,
not additional sensor coverage or proof of child exit-code success. Source
manifest SHA-256: `974be90cff3d2253c1780e5ea732126b9cb2f981f455686dfddd747513cea1cc`. Initial module warmup and final reviewed
coverage have separate observation windows; neither provides whole-host
cleanliness or every-detector availability.

### Root-reviewed alert and coverage classification

The persistence-disposition epoch contained 156 new events after hello cursor 6330 and 292 disjoint retained events. New severities: 15 HIGH, 44 MEDIUM, two LOW and 95 INFO. Retained events included one CRITICAL exposure from Immutable Recovery Assurance Guard. Explicit medium-or-higher dispositions were new: 21 exposure, 35 observation, one health and two missing; retained: 14 exposure, 22 observation, two health and 33 missing. A retained Persistence Sweep HIGH event explicitly displayed observation, with five omitted details. Matching presentation text supports correspondence only, not original identity, trust or harmlessness; the earlier host candidate remains unresolved and the exact legacy envelope cannot be reconstructed from this export. No alerts, baselines, allowlists or trust enrollment were cleared. Omissions affected 151 new and 249 retained events (1,416 and 1,838 fields). All 448 events carried exporter-reported HMAC-only verification flags, without analyst MAC or native-producer verification. The initial retention gap was 4,330; 2,156 data frames were contiguous, and hello-reported queue drops were zero.

The requested 60-second reader differs from the 62.716-second cached-status proxy: 29 copies and 20 unique generated statuses. Storage was configured and unblocked, with four ready and 25 unmeasured copies (20 stale facts, five pending probes). Database size was 42,651,648 to 42,860,544 bytes; WAL 16,777,216 and SHM 32,768 bytes, with about 12.92 GB free. Storage pending ranged zero to two and ended zero; an independently cached recorder value reached three. These are not an atomic queue snapshot. Both recorder workers were healthy/alive in all 29 copies. Admission rejections, storage rejections, discards, write failures, DLQ/replay-failure and quarantine counters were zero; storage gap was false and all 29 metrics copies reported zero drops. Replay deferrals/hold attempts rose from 19 to 35 as cumulative attempts, not backlog; maintenance deferrals were zero. Optional audit counters/pending were zero with gap false, but are nondurable instance-lifetime observations, not proof of historical continuity.

All four heartbeat roles were fresh with reported authentication/tree binding in all 29 copies; each role had three unavailable samples after STOP. WM_NULL responded 29/29, maximum 47 ms; cached GUI lag was 47 to 109 ms. All 75 enabled modules were running at the final snapshot: 24 ok, 33 degraded, 17 critical and one failed; 69 sensor coverage states were unknown. Initial Full confirmation still showed 72 of 75 running during warmup. AI state was 13 unmeasured and 16 circuit-open, with no model/request stage entries. This ordinary Full/STOP observation does not establish a clean host, kernel integrity, native producer attestation or malware/TOCTOU canary efficacy. It is separate from the 390-pass/two-filesystem-skip offline gate, whose 48 new cases all passed. The offline parser exited normally with a signaled native wait, empty owned Job and proven cleanup.

### Named post-STOP fault comparison

Both selected post-STOP fault copies were byte-identical to their pre-STOP copies, preserving their prefixes with zero appended bytes and no appended access-violation marker. During the broader captured interval, the diagnostic log grew by 77,298 bytes without an appended AV/fatal-Python marker; source mtimes preceded Full invocation. Named byte comparisons do not establish continuous logging, writer identity, hook/finalizer health or the cause of native P0. The native shutdown investigation remains open.

The named comparison does not prove continuous logging, writer/hook health,
all finalizer paths or native P0 cause. Raw host originals remain private.

## Original candidate and remaining limits

The earlier host candidate remains unresolved: its approximate link omitted five details and does not conclusively bind the original alert to this exact legacy envelope. No alert, baseline, allowlist or trust enrollment was cleared. Native P0 and same-user/kernel trust boundaries remain open.

The code counterexample and synthetic regression results do not conclusively
identify the earlier host startup entry. Missing evidence remains missing;
urgent review priority is separate from proof of execution. No automatic
response or investigator verdict follows from the new projection. This review
does not establish a native shutdown fix, independent kernel enforcement,
accepted signed/service/hardware deployment or an Optimus attribution.

## Hosted results

At the 23:21:54 UTC snapshot, published base a71c613 had 11 successful jobs and four Python Test steps still in progress. The earlier e0bdebb runs completed their suites in about 31 to 36 minutes, so elapsed time alone does not establish a hang. The corrected six optional-audit expectations and the storage update belong to a71c613's own hosted runs. This persistence classification increment has separate local test and runtime evidence; its eventual published commit requires its own hosted results. No pending run is counted as successful, and no new publication is selected while the previous exact-commit runs remain unfinished.

Hosted checks attach only to their exact published commit. The focused local
cohort and fresh source observation do not establish hosted success for the
next published revision. Prior terminal results and the changed revision's
checks must be reviewed separately before publication is called complete.

## Subsequent GUI recorder validation

Base `a71c613` finished at 23:39:23 UTC on 1 November with 11 successful jobs
and four failed Python jobs. Each Python 3.10–3.13 suite reported 12,450 passes,
37 skips and the same single GUI red-team recorder-acknowledgment failure.
The six earlier optional-audit dictionary assertions did not fail again.
See the [completed CI run](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/41360350601).

The fixture subscribed a synchronous recorder. Settings Save installed the
worker-probed storage policy, but that fixture had no worker to refresh its
facts. This provides a deterministic path to refused writes and a missing
authenticated recorder echo. The fixture now matches the production graph:
an owned asynchronous adapter supplies the bounded subscriber while the raw
recorder remains the exact query and signature-validation identity. Cleanup
proves retirement of the fixture's producer, GUI and report users, then the
same recorder generation's full drain before SQLite closes. Unknown owners
retain the recorder. The eight-second marker deadline, report signatures,
37-contract assertions and both GUI launches remain unchanged.

Two earlier local runs reached the simulation but correctly withheld campaign
credit after recording only two of three tagged process attempts. Bounded,
test-only diagnostics then captured a third-attempt `CreateProcess` quota
refusal (`WinError 1816`). These diagnostics preserve original arguments,
returns and exceptions and leave native receipt issuers unchanged. They write
only a private, exclusive file capped at 64 rows and 64 KiB.

The private diagnostic owner had an eight-process ceiling. A separately
reviewed GUI-only owner used a 32-process ceiling with the same 512 MiB memory
limit. The four-file cohort then passed **79 cases with one open-file-rename
availability skip in 143.53 seconds**. Both complete GUI launches, signed
after-action reports, independent OS witness checks and cleanup assertions
passed. Its exact native pytest generation exited zero, the owned Job was
empty, handles were closed without forced retirement, and the 503 runtime
source files, selected test inputs and saved preference hashes were unchanged.

Native accounting returned the configured limits before launch and collected
1,319 Basic/Extended samples. The maximum sampled membership was 15 and the
kernel-reported peak job memory was 202,829,824 bytes; the largest sampling
gap was 0.125 seconds. Sampled membership is not a complete process history,
and per-member identities and ancestor limits were not collected. This proves
that the old ceiling cannot accommodate that successful execution; it cannot
retroactively establish which quota triggered the earlier failure.
[Windows job limits](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information)
and [kernel peak-memory accounting](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information)
have separate meanings. The tracked GitHub pytest wrapper does not install
this private Job limit. No application validation, retry, deadline or coverage
rule was relaxed, and no production process limit was changed.

These local results are separate from the new commit's hosted checks. The
earlier incomplete reports retain their withheld scores and private evidence.
