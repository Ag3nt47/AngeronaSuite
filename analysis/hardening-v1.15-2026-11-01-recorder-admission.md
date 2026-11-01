# Angerona 1.15 recorder admission and shutdown review

1 November 2026 · sanitized source-development follow-up

Application version remains 1.15.0; Windows metadata remains 1.15.0.0.
This supplements the [advisory/setup review](hardening-v1.15-2026-11-01-advisory-bursts.md).
The native shutdown P0 remains unresolved. No evidence attributes the earlier
missing dump or startup failures to Optimus.

## Failure path and correction

EventBus delivers subscriber callbacks inline. The recorder previously used
bounded primary and overflow queues, then performed synchronous disk spill on
the publisher when both lanes filled. Its spool capacity loop can wait
indefinitely while replay cannot progress. A GUI publisher could therefore
wait on storage despite ordinary SQLite work having dedicated workers. This
source-grounded path does not establish the cause of the earlier outlined
window or native crash.

`AsyncFlightRecorder.submit` now signs when needed, then performs bounded memory
admission without disk writes, capacity waits or scheduling sleeps. Exhausted,
stopping or unavailable lanes raise `RecorderAdmissionRejected` with a fixed
reason; successful calls retain their `None` return. EventBus counts the
subscriber failure and continues other subscribers. Rejected recorder delivery
does not necessarily mean every security consumer lost the event.

Admitted Event objects and signatures, order within each memory lane, and
existing spool originals remain preserved. Actual DLQ write failures have a
separate counter. Admission
rejections and saturated/stopping/unavailable counts are process-lifetime
memory diagnostics, latched across restarts of the same recorder object but
**not a durable loss journal across process exit**. No synthetic coverage event
or persistence acknowledgment is fabricated. A false admission-gap flag does
not certify continuity; unexpected worker failure can leave in-flight custody
unresolved.

Runtime delivery-failure totals include rejected admissions exactly once.
Cached recovery JSON, text status and `ingest-status` expose count and scope.
Worker availability stays separate from historical gaps, avoiding pointless
restarts of available workers. Detector thresholds, response contracts, trust
enrollment and action authority are unchanged.

## Stop and restart ownership

Admission and STOP closure share a short memory lock. Signing, storage, thread
creation and joins remain outside it. Startup admission and lifecycle-generation
fences prevent an old stop from certifying replacement workers using SQLite.

Only the last concurrent stop caller can finalize retirement; earlier callers
return false while another owns finalization. With captured/current workers
retired, bounded cleanup removes only identity-matching wake tokens and
preserves real Event references and order. Queued real records with dead
workers make the drain result false and remain available to explicit restart.
This does not attest in-flight batch durability after unexpected worker failure.
Native or disk stalls can still cause an explicit stop timeout.

## Validation and hosted scope

The sixteen-file focused gate completed with **144 passes and one skip in
57.86 seconds**. The directory-symlink test reported symlinks unavailable on
this Windows host. Completed JUnit independently reconciled 145 cases, zero
failures and zero errors. The owned child exited zero; native wait and Job
active count were zero, without force. Handle cleanup was proved; source and
selected preferences remained unchanged. Whole-package Ruff and independent
source/test review passed.

Deterministic worker barriers held both full memory lanes while the publisher
completed before storage was released. An 8,000-attempt flood reconciled every
attempt as admitted or rejected, retained every admitted signed record and
performed no publisher disk I/O. Separate tests covered before-start/after-stop
refusal, other-subscriber delivery, concurrent stops, late wake insertion,
preserved queued records, restart fencing, status visibility and benchmark
dependency loading. These are offline correctness checks, not live disk-full
or deployed exploit-prevention acceptance.

Preceding published commit **7ebb387470234ad77824d36864c50899d53f6f5d** has
fifteen terminal hosted successes, verified 1 November at 19:15:53 UTC: all twelve
[CI jobs](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/41337890072) and all
three [security jobs](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/41337890145).
That completes follow-up of earlier setup-schema failures; it does not validate
this later recorder revision. Changed-commit publication and checks retain
their separate scope.

## Fresh ordinary Full-mode observation

A new 60-second Full/normal-STOP capture used the frozen 501-file source
inventory identified by manifest
`0aaf66457a37a589443980349b9e2b657dbeae7509fce06e5cb407b6c4a795b5`,
based on published 7ebb387. Inventory count alone is not a unique revision.
Bounded lifecycle acceptance was true: Core native exit zero, 48 unique
observed generations including Core, all 52 retained wait rows signaled,
and exact identity sets reconciled. Outer diagnostic exit/Job active count
were zero; no application termination or forced retirement occurred.
Independent after-STOP checks matched all 501 source files and selected
preferences. Polling does not establish complete short-lived process history.

This ordinary Full run did not deliberately fill the drive or live-exercise
the offline saturation scenario. The reader requests a monotonic 60-second
follow but does not record exact wall-clock endpoints. Its hello cursor gives
the stronger feed boundary: 300 event frames were retained at hello; 155
followed cursor 6306. A separate cached-status timestamp proxy spans 59.048
seconds and contains 27 collected samples and 158 events, three already retained
at hello. These windows are not interchangeable.

The 155 post-cursor events were 83 informational, 44 medium, 25 high and three
low. Review of their available evidence and reported classifications found
22 declared exposures, five unavailable-coverage notices and 45 unresolved
observations/leads among the 72 non-informational records. No supported active
detection was established within that evidence; this is not a clean-host
verdict. Omitted details prevent wholesale independent reconstruction, and a
cached module/message match is not identity or authentication proof.

The initial 4,306-record retention gap remains explicit; subsequent event,
diagnostic and coverage sequence 4307–6461 is contiguous. All 1,500 diagnostics
and 200 coverage records are retained history, not newly performed probes.
The exporter reported all 455 originals verified under HMAC-only scope. This
review did not independently recompute MACs or attest native producers.

All 27 strict Full-proxy status copies reported healthy recorder availability
and live primary/DLQ workers. The audit reported zero rejected admissions,
DLQ/replay failures or quarantines, and no admission gap. There were 43 available
recorder projections; all 71 copied runtime metrics reported zero delivery
drops. These are cached process-lifetime samples, not durable or between-sample
continuity proof.

At the retained end status, 75 enabled workers were running while 17 module
states were critical, 33 degraded, one failed and 24 OK; 69 sensor sequence
coverage states were unknown. Native ETW/Sysmon remained unavailable. Every
Full-proxy sample had four fresh authenticated role heartbeats. Each role's
three unavailable samples occurred only after STOP confirmation; liveness does
not establish detector coverage.

Across the separate 56.650-second sampled-cost window, Core averaged 96.838%
and the inventory child 8.274% of one logical CPU; the diagnostic owner averaged
5.461%. All 27 WM_NULL probes responded, with maximum 313 ms. These are not
whole-machine CPU percentages, a controlled performance comparison or a
click-latency measurement.

The diagnostic fault copy preserved its prefix and added 77,324 bytes with
native label `0x8001010d` and no appended access-violation marker. Its mtime
precedes Full invocation. The copies exclude final STOP teardown, so neither
those selected bytes nor native exit zero resolve the P0 crash cause.

## Remaining storage boundaries

- Primary SQLite retention limits rows, not physical bytes. Its database also
  contains a separately written durable remediation journal. A telemetry budget
  must preserve response/recovery custody and account for both writers; a
  recorder-only limit cannot be described as a shared-database quota.
- WAL checkpoint and journal-size settings do not establish an aggregate
  physical maximum. Existing large databases and authenticated records have
  not been deleted or replaced by this fix.
- Normal Python/Qt message budgets do not cover raw dashboard stdout/stderr
  descriptors or native/external crash writers. Those need separate limits.
- Direct startup's temporary fallback does not yet share the critical
  launcher's bounded workspace-history policy. This differs from the launcher's
  warning-only storage admission behavior.
- Nondurable rejection counters do not close unexpected in-flight batch loss,
  upstream collection gaps or same-user tampering boundaries.

Byte/free-space admission, coordinated remediation reserves and bounded raw
output are follow-up designs, not implemented quotas. Existing scan, recovery,
witness and launcher limits retain their individual scopes.
