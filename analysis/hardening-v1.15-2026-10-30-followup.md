# Angerona 1.15 follow-up review

30 October 2026 · sanitized source, local validation and observation record

This follow-up covers Windows recorder metadata custody, setup discovery,
release-test fixtures, stopped canaries and alert wording. It supplements the
[original hardening review](hardening-v1.15-2026-10-30.md); earlier observations
and their failures retain their original scope. No raw host capture, process
identity, credential, startup command or private path is published here.

## Windows recorder metadata custody

New recorder pending, write-scratch and writer-lock files receive an explicit
current-token-user owner and a protected DACL for that user, SYSTEM and
Administrators before data is written. The implementation checks the actual
opened object's security descriptor, file identity and single-link state.
Existing inherited files that already meet private custody are accepted.
Existing nonprivate, aliased or multilink objects are held; the repair does
not rewrite their ACLs, delete them or overwrite their contents.

Native file-handle transfer to the CRT has one owner. Uncertain native creation,
transfer or auxiliary/file/descriptor close retains tracked custody and fences
replacement of the optional recorder worker. It does not turn an uncertain
close into permission to retry a numeric handle. The SQLite protection writer
remains usable. Other default file-lease callers and POSIX mode 0600 are
unchanged. Parent-directory checks remain path checks, **not retained directory
leases**. These controls do not isolate the source application from the same
user, an administrator or a hostile kernel.

An ordinary-user probe found the native token owner equal to the token user and
accepted inherited private fixtures. It did not reproduce the hypothesized
elevated-CI Administrators-owner default. Report the observed custody behavior,
not that unproved explanation for the earlier hosted failure.

The focused runs covered **82 distinct cases across two runs**: the first had
79 passes and three fixture failures; after correcting only those fixtures,
their three-case rerun passed with unchanged product bytes. This is not a
single 82-pass run. Both runs established native retirement and unchanged
reviewed source; neither proves independent authority or signed deployment.

## Configuration and release checks

Full Setup now exposes the eleven optional recorder-witness settings and points
to the existing running-dashboard enrollment controls. Setup stores public
enrollment values and local TLS file paths. It does not display, provision or
serialize the request private key. The host request identity stays in the OS
credential store; the archive signing key stays with the independent authority.
Witnessing remains off by default. Missing enrollment, network or storage holds
optional witnessing while local protection continues.

Release tests now supply a stable installed-version baseline through the
existing comparison seam. Equal-version and downgrade rejection remain product
requirements, including before download/installer actions. This corrects
fixtures that unintentionally compared their candidate with the new product
version; it does not relax release admission or move all fixtures to an invented
future product version. The focused setup/updater gate reported **167 passes**.

Stopped-canary, source-authority, headless-delivery and red-team fixture checks
reported 134 passes and two further fixture failures. The two affected files
then passed all 18 tests in a 20.65-second recheck after test-only corrections:
the canonical EventBus signs a copy, and a tracked-collector fixture had omitted
required state. That recheck established native retirement and unchanged source;
it overlaps the earlier cohort and does not erase its first result.
Alert-wording/adjacent checks reported 383 passes and one skip;
STOP-overlay/adjacent checks reported 67 passes. These cohorts overlap other
scopes and must not be added into an overall total.

The earlier public revision had 15 terminal GitHub checks: eleven passed and
four Python jobs failed. Local remediation and focused gates are not fresh
hosted-CI acceptance. Publication and exact-revision hosted results require
their own completed receipts.

## Runtime and collector measurements

A separate 120-second Full observation ended with actual native Core exit zero,
all retained generations retired and unchanged reviewed source/preferences.
Overall observation acceptance remained false: three inventory-monitor samples
reached its **time deadline**, at 92, 225 and 363 observations after about
2.016 seconds. None reached the count cap. This identifies these three holds;
it does not retroactively identify the cause of earlier count-or-time holds,
or repair the earlier unresolved native shutdown access violation.

After retirement, three authenticated native inventory requests completed in
1.547, 1.500 and 1.406 seconds. Over their matched 4.453-second window, the
actual collector used 4.265625 CPU seconds, or **95.792% of one logical CPU**,
mostly kernel time. Each returned 373 rows with 144 unreadable command lines
and three incomplete identities. Enumeration completed; ordinary-user coverage
remained partial. These three requests establish their cost, not production
consumer cadence, whole-host utilization or the cause of earlier GUI delays.

A subsequent direct-collector profile kept one original baseline and then
temporarily timed strictly forwarding getter/stage wrappers. Timings are
inclusive, nested and not additive. Two instrumented passes attributed roughly
1.25/1.53 seconds to the creation-time getter; a process disappeared during the
third overall pass and the profile was held. Instrumentation, changing live
input and cache warming prevent a controlled speedup comparison. No performance
improvement or all-pass profile is claimed, and evidence freshness was not
relabeled or extended.

## Alert review and precise claims

The retained snapshot began with a 3,342-record gap and contained 847 exported
events. All 31 high and two critical records were reviewed: eleven reported
unavailable collection/assurance, three posture exposures and nineteen
unresolved detection/correlation leads. Verified exported originals and receipts
authenticate the observed records, not kernel truth or complete time coverage.
The redacted evidence does not establish either compromise or a clean host.

The critical recovery event was an explicit offline-copy exposure. The critical
CHAOS event recorded missing assurance echoes; intentionally unassured DNS and
observation-only AMSI were distinct from the unresolved FIM marker failure.
An unreviewed startup command referenced a temporary-path executable that was
absent at the later read-only check. No hash or signer could be inspected, no
execution was proved and no startup entry was approved, changed or removed.
Its location remains a reviewable risk, including possible later recreation.

Current messages describe CHAOS results as an **assurance gap**, KEV matches as
review-required candidates rather than proven host applicability, and a startup
command as a configured reference whose execution is unverified. The changes
preserve severity, counts, evidence, approval/exclusion decisions and existing
legacy-reason compatibility. They do not manufacture successful receipts,
enable risky native AMSI, approve the inference listener or reset a baseline.

## Final changed-source observation

The final changed-source Full-mode observation and STOP **met lifecycle
acceptance**. The Core exited natively with zero and all 52 observed unique
process generations retired. No topology gap or forced retirement was reported;
the 497-file source manifest and saved preferences remained unchanged. This is
bounded lifecycle evidence, not proof of complete process discovery, working
detectors, successful containment or a repair of the earlier P0 native crash.
Polling cannot prove that every short-lived child was observed; other transient
role/admission gaps remain in their original evidence.

The 2,497-record capture contained 920 events, 1,337 diagnostics, 179 coverage
records, 59 heartbeats, one gap and one hello. Its initial retained-history loss
was **2,941 records**. Of 436 new events, 393 were informational, 29 medium,
five low, eight high and one critical. The critical event reported the CHAOS
assurance gap for NDRD/FIM/AMSI, not a confirmed hostile blinding event. All
diagnostic and coverage records were retained history; none was newly delivered
in this reader window, so their count is not new collector acceptance.

Final worker status was 75 running/75 enabled, with 23 OK, 34 degraded,
17 critical and one failed; 69 sensor coverage states remained unknown. Full
mode was invoked once. Fresh status and paint verification arrived about
60 seconds later, after explicit startup-readiness retries. That settling delay
is not a measured button-click latency. Of 55 WM_NULL probes, 54 responded and
one exceeded the deadline at roughly 516 ms; window-message response does not
measure complete interactive responsiveness.

Over a common 118.284491-second aggregate interval, Core CPU was 144.046875
CPU seconds (**121.780% of one logical CPU**) and inventory CPU was 88.625
seconds (**74.925%**). Ten stable process generations used 240.8125 CPU seconds
combined (**203.588%**), a lower bound excluding transients. The diagnostic owner
used 5.453125 CPU seconds (**4.610%**) and was competing load. These are not
whole-host percentages or a controlled before/after comparison.

The private diagnostic monitor now takes one fresh Toolhelp map per batch,
reducing its own repeated enumeration. This changed the observer, not the
product's inventory collector, and demonstrates no product speedup. An observed
COM exception preceded continued event delivery and normal exit; it was not the
earlier native access-violation failure. Neither normal shutdown nor better
observation identifies that earlier callback/ownership cause.

## Remaining acceptance

The prior native shutdown crash remains an unresolved P0 availability finding.
Normal later exits and better logging do not prove its cause repaired. Final
post-remediation lifecycle observation is accepted within the scope above;
exact-revision hosted checks remain a separate acceptance step. Signed service
deployment, physical TPM enrollment, native
driver-policy enforcement and PID-bound ALE/established-flow teardown remain
outside the demonstrated scope. Source user-mode controls retain their stated
same-user, administrator and kernel trust limits.
