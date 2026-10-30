# Angerona 1.15 hardening review

30 October 2026 UTC. This sanitized record describes implemented source changes,
focused offline checks and separate ordinary-user Full observations. Raw host
captures, identifiers, addresses and payload paths remain private. No signed
installation, WDAC/SCM/ACL change, TPM enrollment/write or hostile exploit was
performed. The [release notes](../docs/releases/v1.15.0.md) map the controls and
deployment limits.

**P0 availability finding remains open:** an earlier 120-second session ended
with a confirmed native PySide access violation after STOP. A later session
exited normally, but does not establish that the earlier fault is fixed. The
logging change below improves observability; it is not a native crash repair.

## Implemented and reviewed

- Provider-specific kernel/Sysmon canary contracts and bounded WER precursor
  correlation preserve native generation, provenance and missing coverage.
- Program-firewall transactions retain process, executable and ancestor
  identity custody through intent, outcome, durable completion and compensation.
- Independent freshness is bound before persisted-state admission. Optional
  recorder epochs commit exact stored row bytes with remote append admission,
  separate authority signing, bounded archives and exact pending reconciliation.
- Installed engine admission checks the actual service account, token, package
  and protected roots before configuration, keys or sensors. Its desktop console
  is status-only. Managed v2 driver policy requires separate enrollment, pinned
  materials, two independent OS-bound approvals and verified native readback.
- Servicing review follows bounded recognized local queue operations. TPM code
  verifies pinned fresh certifications and builds policy plans; no hardware
  writer or automatic deployment is supplied.
- Native cleanup keeps owners on uncertainty. Recorder verification uses
  bounded indexed reads; legacy retrieval import no longer creates files.
- Crash logging now reports per-target opening/STARTUP writes, installed
  Python/thread/Qt hooks and the single selected native-fault output. Partial
  or unavailable arming remains visible without blocking dashboard startup.
  An arming receipt is not a promise to capture every interpreter-teardown fault.

## Validation scope

These cohorts overlap and must not be added into an aggregate test total.

| Final focused scope | Result |
| --- | --- |
| Native service, driver-policy composition, pipe/broker custody and status console | 183 passed |
| Independent recorder worker and bounded historical SQL | 64 passed |
| Credential/runtime/settings composition | 71 passed, one expected POSIX fork skip |
| TPM certification and policy-plan adapter | 83 passed; no physical TPM calls |
| Legacy retrieval import and bounded output | 11 passed |
| Watchdog lifecycle wording and existing liveness cases | Nine passed |
| Inference-socket presentation and adjacent boundaries | 39 passed |
| Crash logging arming and adjacent observability | 55 passed |

The unchanged broad selfcheck compiled **487 package files** and reported
**28 phase passes / one failure**. Its native defensive drill passed all 30
steps; module/pipeline results were **69 passes / one failure / 17 expected
skips**. The remaining failure is the existing host Ollama wildcard-listener
attestation. It was preserved as a failure, not converted to a skip; no owned
authority to change or stop that listener was established. A prior run with a
smaller diagnostic-process cap had an incomplete drill; its swallowed spawn
error prevents assigning a cause from the later successful run.

Focused source checks are separate from hosted CI, signed deployment and
physical-hardware acceptance. Publication and exact-commit CI have their own
receipts.

## Earlier 180 second Full observation

The read-only reader ran for 180 seconds. All 59 distinct status publications
reported version 1.15.0, Full mode and **75 running / 75 enabled / 86 discovered**
(11 off). This proves lifecycle in the observed scope, not detector efficacy.

The capture explicitly begins after **4,446 unavailable retained records**.
Only 361 exported events were new after attachment: 271 informational, 17 low,
66 medium, seven high and zero critical. The high records were six unresolved
inference-process leads and one HVCI exposure. RWX/JIT observations and their
SpywareGuard interpretations remained unconfirmed. No confirmed breach,
spyware compromise, WER attack or downgrade was established.

Three userspace canary cycles completed their sensor/recorder pipeline. Kernel
ETW and native Sysmon were separately unavailable on all three checks. Six WER
owned-cache coverage warnings were intermittent; their precise cause remains
unresolved. No kernel-loopback or pre-dump-prevention success is inferred.
Response authority stayed held in Source Observe. Queue-drop counters in the
observed Live Debug scope stayed zero; historical subsystem debt remains
separate from this capture's delivery counters.

Matched native CPU intervals show substantial cost: Core averaged **99.31% of
one logical CPU** over 209.733 seconds; inventory averaged **79.37% of one
logical CPU** over its own 196.263-second interval. These are not whole-host
percentages. Core RSS ranged 297.78–303.62 MiB. Five of 90 window-message probes
missed a 500 ms deadline while heartbeats remained fresh. Across 21 distinct
rolling metric publications, excess heartbeat lag had median 532 ms and maximum
1,078 ms. Competing host and diagnostic load was present. No captured CPU profile
localizes a root cause, and no measured performance improvement is claimed.

The observation found Watchdog Monitor's healthy label overstated its worker
lifecycle checks as overall detector health. A focused wording correction now
states that sibling workers have no observed lifecycle/deadline faults and that
detector coverage is separate. Recovery behavior, scores and deadlines are
unchanged. Its nine-case gate passed after shutdown; this capture predates that
wording change and is not a live observation of those changed bytes.

A separately reviewed Counter-Agentic presentation correction now includes
bounded socket state, endpoints and role. It labels a listener only for explicit
LISTEN with the matching local port, and no longer implies hijack, initiation
or locality from a port observation alone. Detection criteria, HIGH severity,
exact-path/digest approval and deduplication remain unchanged. Its 39-case gate
passed after the capture; the capture is not a new live validation of this fix.

## Earlier shutdown verification

The first mode/STOP verifier encountered timing and UI enumeration failures.
These are retained harness failures, not a proved application crash or restart.
A separate confirmation-only operation invoked Yes once, made no additional
STOP-header invocation and launched nothing. All 17 native wait observations
were signaled; those observations are not 17 distinct processes. Nine prior
live generations were rechecked, no replacement Core was found, and independent
enumeration found zero Core candidates. Saved preferences stayed unchanged.

## Later 120 second observations

These sessions are separate from the earlier 180-second capture. They are not
combined into one measurement window or an all-pass result.

The first later session completed its Full capture and STOP but ended with a
confirmed **0xC0000005 native access violation**. Static saved-dump unwinding
included QObject destruction, widget destruction and event dispatch; the exact
callback or ownership cause remains unknown. An inert GUI-thread confirmation
reproduction passed without reproducing the fault. That negative reproduction
does not resolve the finding or identify the security impact of its root cause.

After the logging observability patch, a second 120-second session recorded
119.793 seconds of reader output. Its initial **2,898-record retention gap**
is separate from the earlier 4,446-record gap. There were 439 retained and
268 new events: 202 informational, 54 medium, seven low, five high and zero new
critical. Four high records were inference-port listener leads using the new
bounded socket wording; the other was a persistence collector-incomplete
condition. Medium records were 27 memory-permission observations and 27
uncorroborated SpywareGuard exposures. Six low records were unavailable native
canary checks and one was a novel destination. No confirmed breach was found.

All 707 exported events reported verified original/export receipts with
HMAC-only observed provenance, not independent kernel truth. No later payload
sequence gaps or duplicates were reported; 2,213 new detail fields were omitted
from the advisory redacted view. The source reported 75/75 enabled workers
running while detector states remained 23 OK, 33 degraded, 18 critical and one
failed; 69 collector statuses were unknown. Lifecycle counts cannot override
those coverage states. Watchdog remained in its degraded/stability path, so this
session does not demonstrate its revised green-path wording.

Three userspace canary echoes completed in 2.084, 2.118 and 1.004 seconds.
Native ETW and Sysmon were separately unavailable on three checks each. No new
WER cache warning appeared; silence does not prove complete WER coverage.
Matched native CPU over a 118.346-second window averaged **119.155% of one
logical CPU** for Core and **79.072% of one logical CPU** for inventory. A
multithreaded process can exceed one logical CPU. These are not whole-machine
percentages or a controlled before/after benchmark. Three of 94 window-message
probes missed the 500 ms deadline; rolling GUI lag peaked at 328 ms and measured
tick duration at 139 ms. CPU cost and responsiveness remain unresolved.

This final session recorded one STOP-header invocation and one Yes confirmation.
All retained native wait observations were signaled, cleanup was proven and the
actual Core exit code was zero. Independent checks found no Core candidate and
unchanged source/preferences. Nevertheless, the observation was **not accepted**:
its monitor reported `process_inventory_bound` twice. That guard bounds either
4,096 observations or a two-second deadline; the saved evidence does not identify
which bound was reached. No count-overflow cause is inferred. Exit zero in one
session does not prove the earlier native crash was repaired.

The logging-enabled launch recorded both STARTUP writes, Python/thread/Qt hook
arming and one native-fault output. A logged **0x8001010D COM exception** occurred
while Core continued delivering events; it was not the process exit failure.
Both named crash-log files were later absent after STOP. The reason is unproved;
the private capture preserves the diagnostic text. No attacker, source cleanup
or external cleaner is blamed, and no complete crash-capture guarantee is made.

## Remaining work

P0 is the unresolved native shutdown access violation and its reproducible
ownership/callback diagnosis. Diagnostic log disappearance also needs bounded
attribution and durable capture review. Other follow-ups are bounded CPU
profiling, typed WER-cache failure/age diagnostics and current native
collector/baseline gaps. These findings do not justify weakening identity,
listener attestation or response policy.
Certified ELAM/PPL, PID-bound native ALE/socket teardown, signed service/policy
acceptance, physical TPM enrollment/protected writes and independent authority
deployment remain explicit external acceptance requirements.
