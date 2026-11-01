# Angerona 1.15 advisory bursts and setup review

1 November 2026 · sanitized source-development follow-up

Application version remains 1.15.0; Windows package metadata remains 1.15.0.0.
This record supplements the [runtime and shutdown review](hardening-v1.15-2026-11-01.md).
Source-file counts describe an inventory, not a unique revision. The earlier
Full120 capture and the later combined Full60 capture therefore retain their
separate source manifests, observation windows and acceptance scopes.

## Implemented changes

- **Counter-Agentic port leads:** port-only records explicitly carry an
  observation disposition. HIGH severity, messages, evidence, deduplication and
  false response authorization remain. A socket role or familiar port is not
  proof of hijacking, malicious intent or a verified breach.
- **SOAR burst aggregation:** aggregate text presents an advisory summary of
  classified-active high-severity event counts. Port-only observation records
  are excluded from those counts. The output retains health disposition with
  false response authorization.
  The 20-second/four-event/two-process threshold and 60-second latch are
  unchanged. Genuine active-detection contracts are unchanged; accumulating
  advisory leads does not create their missing evidence or grant action rights.
  The internal latch can affect later legacy-CRITICAL eligibility only when
  opt-in active defense is enabled; checks of original integrity, exact
  contracts, protected processes, corroboration by two modules and Adversary
  Combat guards remain required. The aggregate alone cannot verify a breach,
  trigger lockdown or authorize an action.
- **Setup discoverability:** Full Setup now maps the three existing normal-log
  controls with their existing types, ranges, defaults and help. It does not
  change logging admission or weaken configuration validation. Whole Python/Qt
  messages default to 64 KiB, configurable from 4–256 KiB; the default 8 MiB
  per-file/process-role budgets remain application limits, not OS quotas.

## Focused checks and hosted CI

The advisory cohort passed 317 cases in 206.10 seconds. The setup/logging cohort
passed 94 cases in 43.03 seconds. Independent source review approved both
changes. These cohorts are separate and may overlap; they are not summed or
presented as native exploit-prevention acceptance.

The preceding published revision (9675347)'s fifteen hosted jobs are terminal: eleven
passed and four Python jobs failed. Each Python version had the same two
Full Setup schema assertions, 12,040 passes and 37 skips, followed by ordinary
pytest exit one and orderly teardown. The three missing logging mappings are
now covered by the focused setup check. That local result does not rewrite
the published failures or establish new-commit hosted success; publication
and checks for the changed revision remain required.

## Earlier advisory-rule Full120 observation

The earlier 120-second Full/STOP observation included the advisory changes
before the setup mapping correction. Bounded lifecycle acceptance was true:
Core native exit zero, 55 observed unique generations retired and all 59
retained wait rows signaled. Source and selected preferences were independently
verified unchanged. Polling remains incomplete for short-lived children.

Nineteen new Full-window HIGH Counter-Agentic records carried observation
disposition and false response authorization. No SOAR aggregate appeared
anywhere in this capture, so the new aggregate wording has offline coverage
only. The sole initially retained critical record was Immutable Recovery
Assurance Guard exposure with false response authorization, not a SOAR burst.

There were 502 new events: 422 informational, 53 medium, 22 high, five low and
none critical, after an initial 4,657-record retention gap. The 80 new
non-informational records comprised 26 exposures, seven unavailable notices
and 47 unresolved leads, with no supported active attack established within
those records. That classification is not a clean-host verdict.

All 75 enabled workers were running, while 17 states were critical, 34
degraded, one failed and 23 OK; 70 sensor-continuity states were unknown.
All 55 Full runtime samples had four fresh authenticated role heartbeats.
Heartbeat liveness does not attest native sensor coverage. Of 55 WM_NULL
probes, 54 responded and one exceeded the 500 ms deadline. Core averaged
114.291048% of one logical CPU in its measured window; this is not a
whole-machine percentage or controlled performance comparison.

The live fault-log delta contained a COM-exception label and no new
access-violation marker in those 77,910 bytes. Its scope excluded final STOP
teardown. A normal exit and an absence of a marker in selected bytes do not
close the earlier native P0 availability finding.

## Combined post-setup Full60 observation

The final combined candidate differs from the preceding advisory-rule candidate
only in the setup-wizard mappings; CAGT and SOAR bytes are identical. Its
501-file source-manifest SHA-256 is
`5715f56f11633b1778e54e1b4eec0fcadfcb637316daab7ddbc9d610a27455ae`.
The reader window was 18:25:28.139486–18:26:28.139486 UTC on 1 November.

Bounded lifecycle acceptance was true: Core native exit zero, all 40 observed
unique generations (39 descendants plus Core) retired and all 44 retained
native wait rows zero, with an exact observed identity-set match. The owned
outer process also exited zero, its Job emptied and cleanup completed without
forced retirement. Independent checks verified the source inventory and
selected saved preferences after STOP. This is lifecycle acceptance, not full
short-lived-child coverage, detector efficacy or proof of the finalizer API used.

### Events and classification

The capture contained 2,208 rows: 803 events, 1,210 diagnostics, 164 coverage
records, 29 heartbeats, a hello and a gap. Initial retention loss was 4,624;
ordinary sequences 4,625–6,801 were continuous and unique afterward. Of the
803 events, 626 were retained history and 177 were new: 124 informational,
34 medium, 17 high, two low and none critical. All diagnostics and coverage
records were retained history, not new collector verification.

Sixteen fresh HIGH CAGT records and five retained HIGH CAGT records all carried
typed observation disposition, complete identity and false response
authorization. This proves the observed presentation/contract path, not that
the leads were malicious incidents. SOAR had thirteen retained informational
records and no fresh records; no non-informational aggregate appeared anywhere.
The changed SOAR aggregation wording remains offline-gated only in both captures.

The 53 fresh non-informational records comprised sixteen declared SpywareGuard
exposures, five unavailable notices and 32 unresolved leads (sixteen RWX memory
observations and sixteen CAGT leads). The unavailable group included two native
canary notices, two AI notices and one HIGH persistence-collector health record;
that record retained false response authorization, nine complete collection
surfaces and a partial service surface. No supported active attack was established
within those records. This is not a clean-host verdict or recovery of lost data.
The reader reported all 803 exports verified in its HMAC-only original/live scope;
the analyst did not recompute signatures or attest native producer identity.

### Status and copied availability

All 28 Full runtime samples showed four fresh authenticated role heartbeats.
Three unavailable counts per role occurred only after STOP. There were 27 copied
status views and one unavailable status sample. Final status reported 75 running,
17 critical, 33 degraded, one failed and 24 OK, with 69 unknown sensor-continuity
states. This differs from the preceding capture's 70 unknown states; the two
observations are not merged. Native ETW remained unavailable and polling partial.

WER had 27 copies: ten admitted-at-last-check and seventeen stale, representing
nineteen unique versions (seven admitted/twelve stale). Retained last admission
remained admitted; copied loss counters were zero while upstream delivery was
unverified. Copied age reached 3.486 seconds, so none of these facts establishes
continuous availability or current upstream telemetry. AI had thirteen unmeasured
and fourteen circuit-open views, twelve attempts and observed service/model/request
counts of one/zero/zero. No completed model check, request or hashing speedup follows.
Normal-log status was externally available in 27 copies, while its role rows
remained held with `resume-check-required`; normal-only budgets do not attest
native/external writes or OS quotas.

### Resource and fault scope

Over 58.203 seconds, Core averaged 108.994% of one logical CPU, inventory 8.537%,
the ten stable endpoint generations 121.987% combined and the diagnostic owner
5.423%. Stable generations exclude transients; diagnostic work competed for CPU.
Different windows and host/event contexts prohibit a controlled speedup claim.
Host CPU samples ranged from 34.3–92.3%, averaging 51.029%; these use a different
denominator from the per-process figures.

All 28 WM_NULL probes responded in 0–94 ms, mean 15.679 ms. Cached GUI lag was
78–234 ms, callback duration 21.929–113.013 ms and metric age up to 10.038 seconds.
Full invocation returned in 234.081 ms; fresh status settled after 60.745 seconds,
which is not a 60-second click latency. These observations do not erase the
preceding capture's one 500 ms WM_NULL timeout or establish all UI paths responsive.

Native sampling had nine Full observations: five observed and four partial,
including one unavailable cached status and six thread-retirement observations.
Across the sampler, all 24 snapshot owners and 139 thread handles closed, with
eight retirements, two thread-open failures and no halt. GUI-thread CPU was
18.245% of one logical CPU. Labels lack thread-birth binding and may charge
inline callbacks to publishers; neither partial native sampling nor labels
provide isolated module cost or complete CPU attribution.

The 77,088-byte diagnostic delta contained a COM-exception label and no
access-violation label. Its last modification preceded Full invocation, so it
is not evidence of a fault generated during the Full window. Both log-copy
phases occurred while Core was alive and excluded final STOP teardown. They do
not prove writer/hook health, a native exception instruction, P0 repair or an
Optimus cause. The native shutdown P0 remains unresolved.

## Remaining exposure and evidence limits

The [security patch report](../docs/releases/Angerona_1.15_Security_Patch_Summary.docx)
retains all five exploit classes, 35 residual criteria and the priority matrix.
Same-user source and unsealed history, forged/suppressed kernel telemetry,
simultaneous user-mode peer suspension, unsigned/removable driver policy,
open/inherited sockets, whole-authority rollback, provider gaps and heuristic
false positives remain material limits. Signed service/PPL deployment,
accepted WDAC enforcement, native ALE/flow teardown, physical TPM enrollment
and an independently administered witness require separate acceptance.

Normal-log limits do not cover native/external writers, earlier allocations,
cross-process storage totals or filesystem identity. No evidence attributes
missing diagnostics or the native fault to Optimus. Raw host captures,
identifiers, paths and diagnostic bytes remain private. Existing synthetic
demo media is unchanged; the LinkedIn text remains an unposted draft.
