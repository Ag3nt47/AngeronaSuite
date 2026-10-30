# Angerona 1.15 process inventory and WER follow-up

30 October 2026 · second follow-up, sanitized evidence

This update retains application version 1.15.0 and Windows package version
1.15.0.0. It follows the [earlier custody and runtime review](hardening-v1.15-2026-10-30-followup.md).
The changes below improve bounded advisory observations and a correlation
clock race. They do not supply kernel attestation, privileged response,
pre-dump interception or a remedy for every exploit class.

## WER ownership cache timing

The WER path now acquires its cached native-owned process snapshot before
sampling the admission clock. Admission and correlation use that same
post-acquisition time. A fresh publication that arrives during acquisition
therefore cannot be rejected merely because it follows an earlier caller
clock sample. Future evidence, exact expiry, TTL, source identity/authentication,
the 64-entry queue, 16-item drain and deduplication checks remain enforced.

The legacy exception string remains compatible while a fixed typed reason
uses the existing exported `coverage_reason` field. Malformed exact-class
snapshots hold the whole cache; private exception text is not exported. This
does not authorize fallback process discovery or relax response identity.
The four-file cohort covering [WER](../tests/test_werfault_guard.py),
[owned context](../tests/test_owned_process_context.py),
[service context](../tests/test_service_process_context.py) and
[fast-path observation](../tests/test_fast_path_vpn_observation.py) passed
120 cases in 11.29 seconds. These are functional/source/export tests, not a real attack or
simultaneous-peer-freeze experiment.

The selected live capture contains no WER `coverage_snapshot`, typed cache
event or source-cache-failure receipt. Its typed cache availability was
**not measured**; absence of a retained warning cannot become zero failures.
The correction does not identify the cause of historical cache warnings.
Post-event correlation can still arrive late; certified PPL/ELAM and guaranteed
freeze or dump prevention remain unavailable.

## Compatibility-gated Windows birth observations

The [advisory adapter](../src/angerona/telemetry/windows_process_births.py)
supports native AMD64 Windows with the reviewed psutil 7.2.2 layout only.
Unsupported configurations preselect the legacy collector. Imports perform no
host query. An admitted scan takes a fresh bulk birth map before rich metadata
and another after all second-image observations, retaining the existing
scan-local parent map and two fresh `Process` objects per row.

Both maps must contain the reader's own exact raw FILETIME witness. Raw birth
comparisons reject inconsistent identity even where distinct FILETIME values
project to the same floating-point timestamp. The admitted fast cache is read,
never populated. Each native query has a 16 MiB buffer ceiling, four attempts
and at most 65,536 rows; the parser dereferences no returned pointers. Failure
during an admitted scan remains explicit loss, without an in-flight legacy
retry. Observations are not reused across requests. Only two system-DLL
bindings are cached, not process facts or self witnesses.

Empty/non-list PID tables are explicit loss. A bounded list that omits the
witnessed self retains visible rows as partial. An oversized list skips the
self-membership prewalk, then the existing bounded row loop retains rows and
reports row-limit loss. Unsupported legacy empty-table behavior is unchanged. These
are best-effort user-mode process observations, not executable custody or a
source of response authority, kernel truth or elevation.

The adapter credits the BSD-licensed psutil layout and authors in its source.
Its compatibility model uses the pinned
[psutil 7.2.2 Windows layout](https://github.com/giampaolo/psutil/blob/release-7.2.2/psutil/arch/windows/ntextapi.h);
Microsoft's [public API declaration](https://learn.microsoft.com/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation)
does not establish a portable public CreateTime layout. Independent review
found an incorrect builtin-module pin; the corrected genuine psutil Windows
module is covered by a real metadata-only test. Other reviews tightened bounds
and retained explicit loss handling.

The final inventory gate passed **385 cases in 15.15 seconds**. Earlier 378/379
case runs remain separate and are not added. Posture/AI advisory regression
checks passed two cases in 2.39 seconds. Separately, posture score math, bands
and policy remain unchanged while interface copy no longer presents a 100%
score as a full-security guarantee.
Whole-tree Ruff and whitespace checks passed. None is native attack efficacy.

## Native measurements and their limits

The intended paired comparison was **held after its first legacy leg**:
1.4382656 seconds wall time, 1.359375 CPU seconds, 355 enumerated rows,
353 retained and two skips whose exact cause is unconfirmed. No candidate
bulk read occurred in that comparison. There was no paired redo, so it cannot
establish a controlled speedup.

A separate candidate-only authenticated protocol run completed three requests
in about 0.235, 0.234 and 0.281 seconds. Each returned 356 rows with zero skips,
145 unreadable command lines and three incomplete identities. Enumeration
completed, but overall coverage was partial. Over its matched 0.75-second
window the worker used 0.609375 CPU seconds, **81.25% of one logical CPU**;
the parent used 0.046875 seconds, **6.25%**. Exact native retirement was proved
and source/preferences were unchanged. An intentional owned-job stop exit of
one was distinct from outer forced retirement. This finite run does not measure
production request frequency, detection efficacy or a baseline comparison.

## Final changed-source Full observation

The changed-source 120-second Full/STOP observation met **bounded lifecycle
acceptance**. Actual Core native exit was zero, all 48 observed unique process
generations retired, and no application TerminateProcess calls or forced
retirement occurred. The 498-file source manifest and saved preferences were
unchanged; independent post-STOP discovery found no Core. Four transient child
admission gaps remain explicit, although no topology bound was reached.
Polling cannot prove complete short-lived-child coverage.

The 2,313-record capture contained 659 events, 1,403 diagnostics, 190 coverage
records, 59 heartbeats, one gap and one hello, with initial retained-history
loss of **2,860 records**. Of 252 new events, 164 were informational, 78 medium,
four low, five high and one critical. The high records were four unresolved
inference-listener leads and one persistence-coverage gap; the critical record
was a CHAOS assurance gap. No breach or clean-host verdict follows. All 659
exported originals verified in the observed HMAC-only scope, not native producer
attestation. Every diagnostic/coverage record was retained history, not new
collector verification in the reader window.

Final status showed 75/75 enabled workers running: 23 OK, 35 degraded,
16 critical and one failed; 69 sensor states were unknown. Native ETW/Sysmon
remained unavailable. All 56 Full samples had fresh authenticated
Core/Watch/Scan/BlackBox role heartbeats. Unavailable counts for those four
roles occurred only after STOP, not during the Full samples. Liveness is not
coverage or prevention proof.

Over the common 117.527861-second aggregate interval, Core used 134.3125 CPU
seconds (**114.281% of one logical CPU**) and inventory used 12.765625 seconds
(**10.862%**). Ten stable generations used 152.828125 seconds (**130.036%**),
a lower bound excluding transients. The diagnostic owner used 4.8125 seconds
(**4.095%**) as competing load. The earlier session's Core/inventory/diagnostic
values were 121.780%/74.925%/4.610% over a different interval and host/event
context. Neither comparison is a controlled causal speedup measurement or a
whole-machine utilization figure.

All 56 WM_NULL probes responded, with mean 25.39 ms and maximum 422 ms.
Cached GUI lag was 109–265 ms, with metric age up to 9.75 seconds. Full invoke
returned in about 125 ms, the button changed after 1.70 seconds, and fresh
status verification took 56.66 seconds. That settling interval is not a
56-second click delay; none of these measures proves complete UI responsiveness.
Preserved logs contain STARTUP and one COM exception before continued events
and normal exit, with no access violation in those bytes. The earlier P0 native
shutdown access violation remains unresolved; absence in this capture is not
proof of repair or complete fault capture.

## Publication and remaining boundaries

The prior published revision completed all 15 hosted checks: twelve
[CI jobs](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/40998480400)
and three [Security jobs](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/40998480356).
Those results do not accept the new unpublished changes. Exact-new-commit hosted
checks and publication remain separate gates.

Same-user source trust, kernel telemetry forgery/suppression, simultaneous peer
freeze, inherited/open sockets, independent-authority compromise/whole-root
rollback and incomplete or unsealed history remain material limits. Signed
service/PPL deployment, physical TPM enrollment and native ALE/flow teardown
are not supplied by this follow-up. The detailed five-class residual analysis
in the Word report remains applicable. No raw host identifiers, private paths,
startup values or process-row contents are published here.
