# Angerona 1.15 cached WER status and CI review

30 October 2026 · sanitized third follow-up

Application and Windows package versions remain 1.15.0 and 1.15.0.0. This
review follows the [inventory/WER update](hardening-v1.15-2026-10-30-inventory-wer.md)
and preserves its dated evidence, including the capture that did not measure
typed WER availability. The newer observations below measure a limited cached
status projection; they do not establish continuous upstream delivery or native
attack prevention. No raw host identifiers, paths, keys, process/thread rows or
fault-log contents are published here.

## Cached admission publication and status

The WER observer publishes immutable cached admission summaries with minimum
expiry, lifecycle generation, fixed reasons, role counts and independent loss
accounting. A pure memory getter distinguishes `unmeasured`, `stopped`, `stale`,
`unavailable` and `admitted-at-last-check`. The JSON/TXT status reporter
whitelists that projection as `wer_observation`. Reading this WER projection
performs no native, file or supplier query, renews no lease and does not alter
the Live Debug schema/tail.

The getter samples its clock after acquiring cached publication/counter fields.
Queue size is read separately, and lifecycle is rechecked afterward. Its output
therefore describes getter-time diagnostic evaluation, **not one atomic kernel,
queue and process receipt**, continuous freshness, or state at status-file write
or reader time. A last successful admission remains history even when its
lease has subsequently expired. Independent loss accounting cannot become
upstream delivery verification.

Review fixed late policy replacement and added rejection of oversized diagnostic
state or reason strings before enum lookup. Existing
source leases remain two seconds, the diagnostic DTO maximum remains five
seconds, and queue 64/drain 16, deduplication, alert behavior, cadence and
response authority are unchanged. The final source-focused gate reported
**244 passes and one skip in 11.68 seconds**, separately from earlier cohorts.
These are functional/export/model tests, not a real WER attack, PPL acceptance
or simultaneous-peer-freeze experiment.

ETW guidance was corrected without changing logic or health policy. A mutable
source checkout stays unelevated; privileged-provider coverage requires its
accepted deployment and rights. Polling is a separate partial observation path,
not a promise to preserve missing ETW coverage.

## Latest Full observation and retained evidence

The 120-second Full/STOP observation met bounded lifecycle acceptance. Actual
Core native exit was zero, all 53 observed unique generations (Core plus
52 descendants) retired, and all 57 native wait rows were signaled. There was
no topology bound, forced retirement or application termination call. The
498-file source manifest and saved preferences remained unchanged, with no
related Core found by independent post-STOP discovery. Five child admission
gaps remain explicit; polling can miss short-lived children.

The 2,299-record reader capture contained 700 events, 1,355 diagnostics,
183 coverage records, 59 heartbeats, a hello and a gap. Initial retained-history
loss was **2,919 records**. All diagnostics/coverage were retained history; none
was newly delivered in this reader window. The reader **reported** all 700
original exports verified in its HMAC-only-observed scope. This analysis did
not independently reverify original bytes or keys; the report is not native
producer attestation or complete-window coverage.

Of 238 new events, 150 were informational, 78 medium, four low, five high and
one critical. The 88 non-informational records were classified as 39 declared
SpywareGuard exposures, six unavailable collection/assurance notices and
43 unresolved leads (39 RWX observations and four inference-listener leads).
No supported active detection was established within those retained records;
this is neither a clean-host nor compromise verdict. Native-provider gaps,
the CHAOS assurance gap and incomplete persistence collection remain visible.

Final status showed 75 enabled workers running: 23 OK, 34 degraded, 17 critical
and one failed. Sixty-nine sensor states remained unknown, with native
ETW/Sysmon unavailable. All 56 Full samples had fresh authenticated heartbeat
views for Core/Watch/Scan/BlackBox. Unavailable counts for those four roles
occurred only after STOP. Their liveness does not attest detector coverage.

## WER copied status observations

The capture contained 56 copied WER status views: 23 `admitted-at-last-check`
and 33 `stale` with expired leases. They represented 38 unique copies, of which
15 were admitted and 23 stale. Every copy retained an admitted last-check result
with no ownership-rejection code; that does not supersede the
copy's separately evaluated present state. Fifty-five copies listed four owned
roles; one stale copy listed Core only.

Copied queued, skipped and loss counters were zero, and upstream delivery
verification was false throughout. Copies could be up to 3.325 seconds old at
reading. Even an admitted getter result can expire before the reader sees it;
these snapshots do not prove zero continuous failures, no loss between samples,
current cache custody, upstream ETW/Sysmon delivery, absence of a dump/freeze,
or historical warning causes. Earlier unmeasured captures remain unmeasured.

## CPU and interface measurements

Over a common 118.764644-second aggregate interval, Core used 134.15625 CPU
seconds (**112.959755% of one logical CPU**) and inventory used 11.65625 seconds
(**9.814579%**). Ten stable process generations used 151.75 seconds
(**127.773717%**), a lower bound excluding transients. The diagnostic owner used
7.09375 seconds (**5.972948%**) as competing load. Different host/event/windows
prevent a controlled comparison with earlier captures; these are not
whole-machine percentages or an optimization result.

All 56 WM_NULL probes responded, with mean 9.79 ms and maximum 94 ms. Cached
GUI lag ranged 94–422 ms, callback duration 13.20–85.24 ms and metric age up to
10.125 seconds; Core RSS was approximately 289–352 MiB. Full invoke returned
in 171.8 ms and fresh status settled after 58.45 seconds. Settling is not a
58-second click latency; none of these measurements proves complete UI response.

The native thread sampler made 34 snapshots, including 19 within Full:
13 accepted and six partial, with seven retirements in that Full subset.
Overall it recorded 143 retirements and one open failure, with cleanup proved
and no halt. All 34 snapshot owners and 144 thread owners closed once. Working
native APIs and explicit partial results do not establish complete CPU coverage.

The exact GUI thread birth stayed stable across 19 Full samples and accounted
for 19.90625 CPU seconds over 116.891 seconds (**17.029754% of one logical
CPU**). There were 126 exact thread-ID/birth endpoint matches totaling
129.953125 CPU seconds over approximately 116.875–116.891 seconds. Separately
bracketed Core CPU was 131.921875–132.21875 seconds over inner/outer intervals
of 116.687/117.000 seconds, or roughly 112.753739–113.310609% of one logical CPU.
Endpoint widths were 93–219 ms and enumeration walks 93–203 ms; unmatched and
short-lived work remain missing, so these are not one atomic full-CPU partition.

Advisory worker labels associated AI triage with about 14.96%, model integrity
12.49%, memory injection 12.15% and SpywareGuard 2.67% of one logical CPU. The
status schema has no thread birth, and inline EventBus callbacks charge their
publisher's thread. Labels therefore do not isolate module execution cost;
unlabeled/unmatched work remains. No module optimization is claimed or justified
solely by these labels.

## Fault logging and remaining availability risk

The pre-STOP fault-log copy was missed for this run. A bounded post-STOP check
found both known crash-log files absent. There are no fresh captured fault-log
bytes from which to claim complete native-fault coverage or absence of faults.
The cause of absence is unproved; it is not attributed to an attacker, cleaner
or source code. Earlier private diagnostic bytes and the saved native dump
remain preserved. The earlier P0 native access violation remains unresolved;
normal later exits do not establish a repaired callback/ownership cause.

## Hosted CI and test-only remediation

The preceding public revision completed 15 terminal checks: eleven passed and
four failed across [CI](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/41004070042)
and [Security](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/41004070060).
Every Python benchmark failure involved a denial-regex expectation for the
public Process layer while the guarded backend reported the psutil platform
layer. Python 3.12 additionally exposed a real-clock 10 ms fixture-deadline
failure; its precise timing-boundary cause was not proved. These were normal
pytest exit-one results, not native crashes or command timeouts.

Two test-only corrections now admit exactly the two expected denial layers,
add a direct backend guard case and use a shared inert clock across the job
and witness modules for one parameterized unknown-count test's four outcomes,
with sleep forbidden. Forbidden-host-access
latching, cache identity/cohort checks, unknown ownership, one-shot termination
and close, and separate real-deadline cases remain. Production timeouts and
authority are unchanged. The focused six-file cohort passed **121 cases in
21.06 seconds**, including its real-deadline cases. It covered poll-benchmark
isolation and UGCAP job outcome, job witness, process retirement, ownership and
startup protocol. Native exit and Job-zero cleanup were proved without forced
retirement; source/preferences were unchanged. Independent test-delta review
and whole-tree Ruff passed. These local checks are not new hosted acceptance.
New publication and exact-new-commit hosted CI remain required and separate
from the older revision's results.

The Word report retains the five exploit classes and their detailed residual
criteria. Signed service/PPL, physical TPM, WDAC enforcement, native ALE/flow
teardown and independent witness deployment remain separate acceptance tasks.
No complete-coverage, all-holes-repaired or kernel-compromise-resistance claim
follows from cached diagnostics, source tests or ordinary-user lifecycle checks.
