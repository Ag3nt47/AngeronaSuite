# Live runtime and containment review — 24 October 2026

This is a sanitized review of an authorized local application session. Raw
process rows, commands, network identifiers, original events, signing material
and private backups remain local. Product version remains 1.14.0; this review
does not close the broader 1.15 work or rewrite the October 22 issue register.

## Actual runtime evidence

The core was identified by its command, parent relationship, process creation
identity and matching diagnostic status, separately from the launcher, scanner,
watchdog and Black Box. The checkout initially had a clean worktree at
`9f0fe74a550e56a3d27e6d0f05e785046f96be01`. This does not attest every byte
already loaded by the running process.

The original session had no enabled Live Debug pipe. Review therefore used
bounded, read-only SQLite queries, existing status/watchdog files and an
independent process sampler. Existing original event HMACs were verified with
the existing installation authority, without creating or rotating keys. Archive
integrity does not establish maliciousness or a live producer receipt.

The initial selected original capture contained 78 records. A subsequent
254.438-second durable-log observation recorded 883 events, all with matching
archive HMACs. It ended with an explicit core-generation change when the
operator terminated the application. These selected inputs do not establish
complete session continuity; the observer did not substitute its own records
for authenticated source evidence.

### Spyware Guard

* A repeated startup finding referenced a missing executable in a temporary
  directory. Both observed registry views retained the entry. Its MEDIUM
  persistence heuristic became CRITICAL through the configured single-rule
  host-isolation fallback. No execution or spyware identity was established.
  The entry was not deleted, approved or exempted.
* Nine memory-observation pairs retained exact same-handle receipts. Originals
  described RWX executable-memory metadata, with `active_attack=false` and
  an alert-only producer policy. Spyware Guard requested process containment
  under its standing single-rule policy, including a Black Box process.
  Receipt identity is not proof of injected code; requests are not verified
  completed containment. No binary-name or publisher allowlist was added.
* The captured beacon original described four regularly spaced connections by
  the Windows Defender Core service, without threat-intelligence corroboration.
  Timing alone did not establish C2. Microsoft's [service description](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-core-service-overview)
  and [network requirements](https://learn.microsoft.com/en-us/defender-endpoint/configure-network-connections-microsoft-defender-antivirus)
  provide context, not an exemption or verification of the observed peer.
* Unquoted service-path findings remained configuration exposures with no
  automatic response authority. Familiar names were not treated as trust.

The operator explicitly prioritized automatic containment before human review.
These changes preserve the existing single-rule response requests and exact
process-generation binding. No live payload, arbitrary PID kill or fabricated
successful response was used to validate them.

Follow-up descriptions now state that a temporary startup entry does not prove
execution or maliciousness, and identify the exact alert-only RWX source as an
uncorroborated memory-permission indicator. Original reasons, evidence and
source-event signatures remain intact. Two regressions verify unchanged
single-rule automatic host/process requests; the focused module suite passed
119 tests after these wording changes.

### Other serious alerts

Canary misses and CHAOS failures established assurance gaps, not proven API
hooking. Gateway drift remained unresolved alongside missing route evidence;
the retained baseline was preserved. HVCI, DMA, release, recovery, audit and
driver findings represented exposures or unavailable evidence rather than
confirmed malware. Registered Purple Guard markers remained drill evidence.
Watchdog restart requests were not treated as completed repairs; provenance
and compliance workers also reached bounded restart exhaustion during review.

Recovery-tamper substring alerts included diagnostic source searches containing
the searched-for command text. Their originals already specified observation
and no response authority. This remains a detector/presentation limitation;
no PowerShell-wide or search-tool exemption was introduced.

### Runtime-tamper report

Three authenticated alerts followed the authorized edit of `core/threat.py`.
Each reported the containing source file changed. The check's source-drift
branch is reached after the live callable fingerprint still matches, whereas
the old universal message incorrectly claimed an in-memory modification.
The timestamps and reviewed diff support authorized source maintenance as the
explanation for these particular records. They do not exonerate unrelated
future drift. Original alerts and armed baselines were retained.

## Performance

The 300-second sampler collected 101 consecutive samples against retained
native handles for the four confirmed process generations. No target-generation
change or status identity mismatch occurred within that interval.

| Measurement | Observed result |
| --- | --- |
| Core mean CPU | 89.33% of one logical CPU; 11.17% of the eight-CPU machine |
| Black Box mean / peak CPU | 0.776% / 2.604% of one logical CPU |
| Host mean / peak CPU | 60.31% / 92.9% |
| Core RSS | 210.0–223.8 MiB |
| Black Box RSS | 27.6–34.8 MiB |
| Minimum available host memory | 5.15 GiB |
| Inline EventBus changes | 16,549 deliveries, 784 budget violations, zero delivery failures |
| Maximum status generated-data age | 87.43 seconds |
| Sampler CPU cost | 34.08 CPU-seconds; about 1.42% machine CPU |

Six same-day core watchdog samples showed 5.2–5.9-second GUI beat delays.
Sampled stacks included dialog construction, a System Pulse bar update and
the native Qt event loop. The log lacks PID/birth binding; timing and stack
correlation do not identify a cause. Black Box's retained watchdog tail had no
same-day stall. Its low CPU does not prove GUI responsiveness.

The per-core runtime-metrics file was absent. `flow_metrics.json` contains
calculated display estimates and was not used as measured queue latency or
loss. Competing host work and the observer's own cost remain relevant. No
performance improvement or complete helper attribution is claimed.

## Applied source changes

1. Status, dashboard, threat window and posture now include retained
   HIGH/CRITICAL EventBus evidence through the existing atomic revision view.
   INFO bursts cannot evict a still-retained critical alert from these
   calculations. Existing acknowledgment, allowlist, resolution and response
   policies remain. Retention overflow and restarts can still lose evidence.
2. Self-integrity distinguishes `source-file-drift`, `runtime-callable-drift`
   and `coverage-unavailable`, with corresponding explanations. CRITICAL
   severity, tamper flags, checks, approval requirements and alert latching
   remain. Live Debug exports only these three exact `tamper_kind` values.
3. A separate rollback-checkpoint maintenance tool admits only the exact
   authenticated completed-undo/failure pattern described below. It does not
   broaden the existing inert-drill recovery or run automatically at startup.

## Containment checkpoint repair

The actual journal held 361 authenticated, newline-complete records. Its
schema-2 protected anchor and witness agreed at record 360, a completed undo.
One trailing authenticated failure record completed the same program-firewall
rollback. This historical terminal-checkpoint gap explained the current
`RECOVERY REQUIRED` state. It was not evidence of a newly observed attacker.

The existing startup and inert-drill tools correctly refused this different
history. The new `tools/recover_combat_rollback.py` inspects read-only by default.
It authenticates the whole bounded history, exact five-record terminal
relationship, existing anchor/witness and an exact native firewall-rule absence
observation. Only the documented missing-rule HRESULT proves absence;
unavailable dependencies, access denial and ambiguous results remain holds.

After the operator terminated the application and the suite processes were
observed absent, explicit apply advanced the existing checkpoint from 360 to
361. Private byte-verified backups preserved the prior journal, encrypted store
and witness. The journal and signing key were unchanged. The command returned
`recovered=true`, `host_actions_executed=0`, `rearmed=false`; restart readiness
and actual containment require their own observations.

Apply uses the reviewed input token, writer lease, pinned journal, credential
transaction, stopped-app checks and fresh rule absence. These are point-in-time
observations, not an atomic OS firewall/process-start interlock. A failure
between anchor and witness writes stays an explicit integrity hold with private
backups; no automatic reset or history deletion is attempted. The old process
generations were absent after operator termination, but their native exit codes
were not retained across that termination.

## Validation and deployment

* Priority visibility: 91 passed, one explicit skip across seven focused suites.
* Recovery and journal: 111 distinct tests passed, zero skips across the staged
  focused runs; repeated cases are not additional coverage. This includes a
  failure after the anchor write, preserving the resulting witness hold.
* Self-integrity: 31 focused/selected tests and its module self-test passed.
* Live Debug enum export: 25 focused tests passed; other cases were deselected.
* The first default offline selfcheck retained 28 passed/one failed phases:
  inherited `OLLAMA_HOST` lacked a URL scheme. Strict URL validation correctly
  refused it. The separate disposable rerun uses a child-process-only validated
  loopback URL, preserving host settings, environment and the failed evidence.
  That rerun passed all 29 phases, with 68 module PASS and 18 explicit module
  SKIP rows. It does not repair the host's separate Ollama configuration.
* Final combined priority/self-integrity/Live Debug gate: 100 passed, zero
  failures/skips, native exit 0. Whole `src`, `tests` and `tools` compilation,
  documentation drift and whitespace checks passed.

Independent post-apply inspection verified matching journal/anchor/witness at
361, all signed records, no pending phases and native exact-rule absence. Key
and journal matched the pre-inspection hashes; verified backups matched the
originals, and this read-only inspection changed no authority bytes. Prior
inspection hashes originally existed in tool output; their later private
transcription is explicitly advisory, separately from the original backups.

The guarded publisher verified the foundation commit
`8a604d4e211995f1e3075e75d23888bf694232f7` at both the current branch and public
default `main`, with all seven repository-relative README images matching.
This precedes the follow-up features below and does not certify their source.

## First restarted observation and follow-up requests

The restarted source process exposed the verified same-user Live Debug pipe.
Its observed standing authority was ARMED in maximum mode with LOW minimum
severity. Ten signed response receipts reported verified quarantines of
registered inert Purple Guard files. These demonstrate that scoped automatic
response worked; they are not ten real malware detections or proof of PID
termination or host isolation. The repeated temporary startup record yielded
`no eligible target`, rather than a successful containment receipt.

The first 240-second reader retained 2,811 views, including 912 event records.
It explicitly reported 1,948 startup records outside retention. The complete
offline map hit its 512-case bound with 731 overflow records; that failed map
is retained. A separate, provenance-recorded selection of 48 unchanged serious
alert/identity/gap views processed without case overflow. Neither result repairs
the retention gap or establishes session-wide continuity.

A separate 180-second observation collected 37 samples of the exact core and
Black Box generations, which remained active. All 37 real runtime-metrics
reads validated, representing 17 distinct publications. Measured core GUI beat
lag reached 2.203 seconds, with three publications above one second. Maximum
measured tick body was 100.72 ms; nine publications lacked a recent tick-body
sample, which is not zero. Observed queues stayed small and reported zero drops.
Core mean CPU was 94.02% of one CPU and Black Box 0.859%; observer cost was
about 0.143% machine CPU. Actual mode was Chill with a 60-second status period,
different from the earlier active-mode session. Publisher and live-reader work
also competed. No causal performance improvement follows from these numbers.

Self-integrity armed 31/31 mandatory targets without a new callable-drift
finding. Health remained capped at 60 because its baseline was TOFU-unapproved;
no independently approved manifest was fabricated or enrolled. Native exit
and handle-retirement evidence exists for the new diagnostic observers; the
application was left running.

### Dashboard paint separation

A later watchdog sample during the restarted session caught
`AlertsPanel._apply_loaded_events → _rebuild_event_rows → EventBus.verify`
during a 5.5-second GUI stall. The source confirmed bulk canonical JSON/HMAC
verification still ran on Qt when applying up to 120 alert rows, although SQL
retrieval was already on a worker. This callback was outside the main tick-body
measurement, explaining why those timings alone could miss the work. A sampled
stack does not assign the complete stall duration to that single operation.

The existing `DashboardAlertReader` now prepares authenticated identities and
artifact text on its worker. Qt receives frozen display projections and applies
at most eight row operations per turn under a cooperative four-millisecond
budget, yielding for painting and input. A slow individual Qt operation is not
preemptible. New snapshots supersede partial old jobs; close/destruction retire
pending paint work. Original events remain available for unchanged action-time
verification; cached display strings grant no response authority.

### Internally updatable definitions

The requested Definitions tab imports a bounded local literal-IOC pack, shows a
version/digest/date/count and bounded literal preview, and queues exact-bundle
activation or retained-version rollback. Persistent local authorization is
separate from research candidate approval and external publisher identity.
Active SHA-256/IP/domain matches use the existing automatic response path.
No real spyware feed or external publisher is silently trusted. See
[the definition format and workflow](../docs/spyware-guard.md#updating-local-spyware-definitions).

The first combined follow-up gate passed 351 cases with zero failures/errors/skips
and native exit 0. The definition suites separately passed 215 cases; GUI projection gates
passed 91, and the SpywareGuard page/window gate passed 31. These overlapping
runs are not additive coverage totals. Whole-source compilation and the fresh
child-loopback selfcheck passed again: 29 phases, 68 module PASS/18 module SKIP.
An independent static review found and the author fixed one post-replacement
disk/memory divergence case, retaining an explicit definitions hold on uncertain
publication. Local authenticated state is not an independent replay witness.

The source restart first used the operator-requested Kill All utility. A
read-only check recognized all eight exact known core, watchdog, scanner and
Black Box generations. The utility's initial wrapper exit did not establish
termination: self-elevation dispatches another process without waiting, and
completion text does not verify native process retirement. The captured retry
reported cancellation of its UAC request. No elevation success is inferred.

Under the operator's existing authorization to terminate all Angerona processes,
the four actual suite processes were then terminated through native handles at
current privilege, with raw creation-time checks immediately before each call.
The four launcher wrappers retired naturally. Independent retained handles
verified all eight matching creation/exit times and native exit code 1; all
observer/action handles closed, and the observers exited normally. A second
watcher overlapped the first before its bounded deadline. No unrelated process
was terminated. Subsequent bounded discovery found no remaining suite roles or
pending UAC prompt.

### Containment failure in the restarted run

The continued 900-second capture retained 3,907 events in 4,480 decoded records,
with an explicit initial retention gap of 4,642 records. Its 21 critical events
included a real current-run Combat disarm at 18:03:44 UTC, before this reader
attached. Later requests were held for the same checkpoint mismatch. Exported
integrity booleans report the producer's verification; they are not a new
offline cryptographic verification. Diagnostic lines mentioning an unresponsive
window are not counts of distinct GUI stalls.

The final current status confirmed `RECOVERY REQUIRED`. Read-only inspection
found 391 complete, authenticated journal records; the protected anchor and
witness agreed at 390. The trailing record is an unfinished host-isolation undo
intent, unlike the historical completed program rollback. The earlier repair
must refuse this different evidence. No host-clean conclusion or automatic
authority reset is justified.

### Write ordering and explicit host-undo closure

An offline regression reproduced a concrete admission window: a journal phase
could become durable before the existing credential transaction was acquired.
Refused admission then left its checkpoint behind. The corrected implementation
reserves that same bounded transaction before appending and retains it through
anchor/witness publication. Initial host-intent contention leaves all authority
bytes unchanged, performs no modeled firewall action and permits a later normal
request. Post-append storage faults still hold response. This is a reproduced
defect; the exact historical exception remains unavailable because the old
undo-intent catch discarded it. Original future criticals now retain up to four
exception class names, with no messages, locals, paths or credentials.

The new stopped-only host-undo tool authenticated the whole actual history and
verified both exact managed rules were absent. Independent review rejected an
early write order that could expose a valid pending journal to startup recovery.
The final implementation pre-authenticates and durably appends both truthful
closure records before advancing any checkpoint. Every partial append and
intermediate anchor/witness state stays held before host reconciliation on a
fresh object. It performs no firewall or process action and does not rearm.

After focused validation and a fresh inspection token, explicit apply appended
991 bytes: an undo terminal and original-action failure recording that the rules
were already absent. Journal, protected anchor and witness now agree at 393,
with no pending action or undo. The original 391 records remain byte-identical
as a prefix, the installation key is unchanged, and verified private backups
match the independently preserved originals. Eleven independent read-only
postflight checks passed, including fresh native rule absence and unchanged
authority bytes during inspection. The first private postflight attempt used
the wrong physical journal path and failed before verification; its script was
retained and corrected. No product authority was changed by either postflight.

Final combined GUI/definition/visibility/integrity/transaction gate: 361 passed,
zero failures/errors/skips, native exit 0. Journal compatibility separately
passed 167; the final typed-diagnostic/uncertain-mutation gate passed 23. The
host-undo and prior recovery gates covered 133 distinct cases (56 new, 77 existing),
including eight fresh-start interruption cases; overlapping reruns are not
additional coverage. Whole-source compilation, documentation drift and whitespace
checks passed. The fresh child-loopback selfcheck passed all 29 phases, with 68
module PASS, 18 explicit module SKIP and pipeline PASS.

The final reviewed source was restarted with the same installation and opt-in
Live Debug/runtime metrics. A private 17-path source manifest records scoped
working-file hashes, not complete dependency or loaded-byte attestation. A
600-second observation described below is separate from final-source deployment
and guarded publication.

### Further observation: recurrence and additional false positives

The next exact-generation observation completed 600 seconds, with all 17 scoped
source paths unchanged before and after. Its first 180 seconds had 37 valid
metrics samples and 16 distinct publications. The full window had 51 samples
and 30 distinct publications; maximum GUI beat lag reached 4.406 seconds, with
maximum measured tick body 140.53 ms. Only 21 publications had recent tick-body
measurements; nine missing samples are not zero. A startup watchdog entry at
about 14 seconds showed a 5.1-second delay in ResourceStrip widget insertion.
The observer attached about 79 seconds after core creation; that startup
interval is a coverage gap, and the watchdog format lacks PID/birth binding.

Full-window core CPU averaged 103.44% of one CPU, or 12.93% of the machine;
Black Box averaged 0.844% of one CPU. About 81% of dense core CPU time was
kernel time. Three retained native thread IDs accounted for most dense CPU,
but available artifacts could not honestly assign them to modules. The new
opt-in status diagnostics expose advisory live worker IDs and lifecycle
generations for subsequent correlation, with no host queries or response
authority. Helpers and stale/unavailable worker identities remain gaps.

Observed flight/overflow/alert-diagnostic queues stayed at zero; evidence queue
peaked at 5/2,048, and every observed queue drop counter was zero. Mode changed
from Chill to active during the window. Combat briefly restarted and later
returned ARMED, so this is not continuous readiness. Its final sample still
had a pending request. No causal speedup follows from this comparison.

The first reader exited 2 before reaching its initial cursor. Its error was
printed only to suppressed stdout, leaving an explicit reason gap. The capture
remains preserved as incomplete. A separate bounded retry retained error
receipts and progressed; its initial retention loss of 2,280 records remains.
Seven critical and 26 high events in the reviewed interval were individually
classified. Known startup exposures, unresolved gateway drift, recovery
requirements and registered CHAOS/canary coverage exercises were not treated
as malware. Original archive events used for investigation were HMAC-verified.

Three signed, native-postcondition-verified termination receipts concerned a
VPN client, a JavaScript runtime and a code-execution helper. The inspected
trigger chain contained uncorroborated executable-memory metadata. The VPN case
contained one 8 KiB anonymous RWX region in a partial scan, with the producer
explicitly declaring observation/alert-only and no active attack. Receipt
identity and successful containment did not establish spyware. These actual
effects motivated an intentional correction: exact alert-only RWX findings and
direct private-executable-memory leads now remain exposures, retaining source
signatures and process identity without typed action or host fallback. Strong
fresh active evidence, behavioral rules and activated definitions retain their
automatic response path. No executable-name or publisher exemption was added.

A new Sysmon ProcessAccess critical was confirmed to be false attribution.
Native exact-channel lookup reported the Sysmon channel absent; the legacy
open returned the same records as Application. The corresponding older native
record belonged to another Windows provider and contained no XML or process
access evidence. This matches Microsoft's documented
[Application-log fallback](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-openeventlogw).
The adapter now verifies exact channel availability and provider before event-ID
meaning, including reopen. Missing/foreign sources use the existing weaker
fallback; malformed genuine Sysmon payloads report MEDIUM unavailable coverage,
observed severity and fixed error types without response authority. Valid
parsed observations retain their existing behavior. Sysmon coverage is not
claimed on this host. The actual-source focused gate passed 28 cases.

ResourceStrip now retains same-name widgets and style caches, coalesces newer
name sets, and reconciles at most eight chip operations per cooperative 4 ms
turn. Widgets stay on Qt. The original regression had five failures/one pass;
the candidate passed all six, and combined GUI gates passed 54. Initial bulk
StatusStrip construction remains synchronous; the sampled stack does not prove
all 5.1 seconds belonged to insertion. Fresh measurement is still required.

Maximum/terminate response now dispatches the retained-handle kill before
network work. Verified exit ends that PID-bound response, without a persistent
program firewall rule for the exited target. A safe pre-effect failure may use
the existing network fallback only after fresh exact-live-identity checks;
uncertain effects remain held. Contain/suspend behavior is preserved. Actual
completed bounded firewall steps renew only their current initialized worker's
progress; there is no timer, timeout extension or synthetic heartbeat. The
expanded gate passed 78 cases, including all 29 new ordering/progress cases.

### Protected-store replacement and the later program undo

The same run subsequently produced a 452-record authenticated journal with
matching anchor/witness at 451. Its trailing program-firewall undo intent had
not completed. The new original diagnostic retained
`JournalIntegrityError → PermissionError`; the old event lacks a native code or
exact boundary. The earlier credential-admission defect does not explain this
permission failure. Read-only quiescent shutdown first refused the mismatch;
authorized native shutdown then preserved the exact before/after authority
hashes while retiring all eight suite generations. No checkpoint was reset.

An inert native Windows reproduction held an ordinary reader on the protected
store. Its actual rename failed with native error 5/errno 13, producing the same
three-record/two-checkpoint rollback pattern. Transient-reader retries completed
all five phases; a persistent reader remained held. This proves a matching
mechanism, not the unrecorded native code of the historical incident. Windows
[delete-sharing semantics](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
explain why a reader can block replacement.

The protected-store fix admits only seven attempts for native errors 5/32, with
at most 0.7 seconds of aggregate sleeps. This is not a hard total I/O deadline.
Retry requires unchanged content, identity, ordinary writable single-link
leaves, full ancestor identity/no-reparse checks, fresh protected private native
owner/DACL proofs and the existing transaction. It never repairs ACLs during a
retry or retries uncertain publication. No private proof grants no additional
retry authority. Independent review found and the author tightened the custody
requirements before final validation.

A separate program-undo workflow now admits only the exact one-rule pending
program rollback, including strictly validated completed native-termination
history. The host-only workflow still refuses it. Both truthful closure records
precede checkpoint advancement, with the same interruption holds, native
absence, token, backup, stopped and full-history requirements. Its final gate
passed 215 cases: 48 new and 167 existing, with no failures/errors/skips.
The final native protected-store gate passed 99 cases with one existing
POSIX-fork-on-Windows skip and native exit 0. The inherited directory route is
bounded to 32 entries and binds each native identity and exact security
descriptor to the first protected boundary. A read-only check of this actual
installation admitted its existing two-directory route and strictly protected
credential leaf. The old unprotected evidence copy correctly remained
ineligible. No host ACL was changed. Independent static review found no blocker
in the frozen helper and tests.

An additional definition-publication regression exposed a wrapper that could
complete a rename and then raise, before the caller recorded success. The
corrected path retains matching after an attempted-publication exception only
when it positively proves the prior private state and original authority
unchanged. Changed, missing, unreadable or unknown state holds matching, hash
scans and further updates until restart revalidation. A known successful rename
followed by any later failure always holds. The new tests perform a real inert
rename followed by an exception and verify that restart authenticates the new
pack without rewriting its key or rolling back disk state.

### Actual program-undo closure

After fresh stopped/native-absence inspection, the explicit program tool closed
the authenticated 452-record history at **454**, with matching anchor and witness.
It appended only the truthful undo completion and failed-action accounting;
the original 452-record prefix and installation key stayed byte-identical.
Eleven independent read-only postflight checks passed: full chain, terminal
bindings, both checkpoints, no pending actions/undos, original key/prefix,
private backup bytes, the exact managed rule still absent, zero host actions,
no rearm and unchanged authority during verification. The private verifier's
first invocation failed to import the repository tools before performing any
check; that attempt was preserved and the import path corrected. Native rule
absence and stopped-process checks remain point-in-time evidence.

The final offline selfcheck passed all 29 phases, including owned Qt/reader
retirement, with native exit 0. Its scheme-bearing loopback Ollama URL was set
only in the disposable child; host settings were unchanged. Final fresh
observation and guarded publication still require their following receipts.
These source tests do not establish a clean host, continuously ready response,
detection efficacy or CI.

### Final startup classification and offline gates

The repeated temporary Windows Run payload alert had registry configuration,
not a collector observation of execution, existence or malicious content. A
text-only correction still allowed standing host isolation. The final tuning
therefore treats that exact source/kind as an exposure in both direct response
and publication paths, preserving evidence, targets and observed severity.
Injected active/fallback hints cannot promote it; independent behavior evidence
for the same process and activated definitions retain automatic response. This
adds no executable or publisher allowlist and deletes no registry entry.

The final six-suite SpywareGuard/definition/intelligence/page/window/sensor gate
passed **371 cases**, with no failures/errors/skips and native exit 0. The first
launcher used an interpreter lacking psutil and collected no tests; its failure
is preserved and has no validation credit. The corrected gate used the actual
repository virtual environment. A further final-source offline selfcheck passed
all **29 phases**, including owned reader/Qt retirement, with native exit 0.

The broader 28-suite gate passed **778 cases/one existing skip**, native exit 0,
in 520.87 seconds. It imported SpywareGuard before the last startup-classification
change; the subsequent 371-case gate covers that correction. The prior unused
20-path pre-observation manifest remains separate. The final live run uses a
new 20-path manifest including the last correction. These overlapping results
must not be added together as a unique test count.

### Fresh ten-minute observation of the repaired source

The actual module child was identified separately from its virtual-environment
launcher and canonical Black Box child. Native process-generation handles pinned
the core and recorder. The observer began 52.22 seconds after core creation;
startup GUI timing remains outside its measurement. All 20 scoped working-source
hashes matched before and after 600 seconds. This is scoped source stability,
not a loaded-byte, dependency or independently trusted build attestation.

The 180-second dense phase had 37 samples and 18 distinct valid metrics
publications. GUI heartbeat lag peaked at **813 ms**; tick duration peaked at
**107.774 ms**, with 11 recent tick-body publications available and seven missing.
Core CPU averaged **80.477% of one CPU / 10.060% of the eight-CPU machine**;
Black Box averaged 0.903% of one CPU. Observer cost was 0.128% machine CPU.
Host mean CPU was 47.60%. Different host/diagnostic load prevents a causal
before/after speedup claim.

The full 600-second window had 51 valid metrics samples/32 distinct
publications. GUI heartbeat lag peaked at **1,156 ms**, with the same measured
107.774 ms tick maximum (19 recent tick bodies available, 13 missing).
Time-weighted CPU was 82.951% of one CPU / 10.369%
machine for the core and 0.901% of one CPU / 0.1126% machine for Black Box.
The full-window observer cost was 0.0397% machine CPU. No new watchdog entry was
observed. These timer measurements do not establish interactive input latency
or preempt the possibility of a later native Qt/GIL delay.

Fresh worker-ID endpoint associations identified Process Monitor, the
Shadow-Copy / Recovery Tamper Guard and LSASS Credential-Access Guard among
the hot native threads. Three fresh endpoint intervals per worker qualified;
other intervals had stale status. Later read-only native thread creation
timestamps placed the same still-live threads before the observer, closing the
observed TID-reuse concern for this window. Worker names remain advisory; no
stack or per-thread I/O cause was captured. All three source paths use the
shared rich process inventory. Its cache deliberately measures age from
collection start; no evidence-age or identity check was relaxed to lower CPU.

All 49 matching-generation automatic-response samples were ARMED, with zero
queued/pending actions and zero queue drops. The first two status reads still
belonged to a retired core and were excluded. The ten current publications had
ages 1.68–61.68 seconds; the latest was 37.10 seconds old under the 60-second
heartbeat. Samples cannot prove continuous readiness. Full-window queue peaks
were flight-recorder 2/4,096 and evidence-read-model 3/2,048, with overflow and
diagnostic queues at zero. There
was no live executed-action receipt, rollback or retry exercise in this window.
The actual mode was **Chill**, ordinary user privilege, with the memory scanner
enabled but paused. Thus tests prove weak-RWX classification and kill-first
behavior, while this quiet live run does not exercise them or full normal-mode
coverage. No interactive user feedback was received during this measurement.

The finite reader exited 0 after retaining 900 event views: 852 INFO, 17 MEDIUM,
13 LOW, 16 HIGH and two CRITICAL. It reported 1,698 initial records lost during
historical-diagnostic replay. A separate bounded protected-original selection
verified 122/122 HMACs, remained below its 400-record cap, and matched all 18
serious event HMACs in the completed capture. No serious discrepancy was found
in that query; the general live-delivery gap remains. The alert observer's first
unquoted floating birth argument was rounded by PowerShell, causing status
identity refusal. Its corrected observer reread the intact event capture; the
brief status-poll gap and original failure remain recorded.

Two authenticated startup findings were MEDIUM exposures with no response
contract, eligibility or host fallback. Sysmon truthfully reported channel
unavailability and process-diff fallback. Other serious findings were evidence
or coverage gaps: access-denied audit collection, absent Sysmon channel,
unconnected egress audit, missing graph/release/temporal evidence, disabled HVCI
posture and absent qualifying recovery copies. The driver summary does not
establish hundreds of malicious drivers. Neither recovery exposure nor these
coverage findings establishes an active attack or a clean host.

Both native observation targets remained alive through the window. The
performance observer and its independent exit witness exited 0 with all owned
handles closed. Retained native handles separately proved the finite reader
and wrapper signaled/exit 0. The alert observer and launchers were also verified
retired. Bounded native gateway-cache queries and protected-ledger reads were
recorded as competing diagnostic load, including one failed native query.

### Gateway collection failure found during that observation

The remaining gateway CRITICAL had only tokenized identity drift in its
authenticated original. Same-tick originals also reported both route sources
missing. The current same-interface gateway IP/MAC token matched the
authenticated historical baseline; no changed current MAC or poisoning was
corroborated. A pure offline reproduction with missing routes reproduced both
route drift and a critical identity-change claim. The producer discarded the
compared raw identities, so a transient historical change cannot be excluded.

The baseline and enrollment were HMAC-valid, revision 2, approximately 46 days
old, and unchanged by review. A narrow follow-up evidence gate and fresh
observation remain required; the baseline must not be replaced to make the
dashboard green.

The subsequent shutdown preflight authenticated a fully closed startup
`activate_honeypots` intent/commit at journal records 455–456, targeting the
registered Smart Deception module. Applied/committed timestamps were
19:52:57.255/19:52:59.069 UTC, before the performance observer began. The commit
verified module activation; it is not a process-termination or malware receipt.
No corresponding action receipt had appeared in the selected live events.
This corrects any inference of zero actual actions from a quiet event capture.

The first shutdown attempt refused its stale expected count of 454 before
terminating any process. After reviewing the authenticated closed pair, the
updated quiescent check required exact 456-record authority hashes, full chain,
matching anchor/witness and empty pending sets under the existing writer,
pinned-journal and credential transaction. All eight exact suite generations
then retired: four actual roles were terminated and four wrappers exited
naturally, each with retained-handle signaled/native exit 1 proof. All owned
handles closed. Journal, protected authority, witness and key stayed
byte-identical before/after shutdown. The gateway correction proceeds only
after this retirement, followed by a fresh observation.

### Gateway evidence correction and validation

The correction requires complete route/interface/neighbor evidence in both
samples, with resolved usable unicast identities and matching interface/gateway
binding. The neighbor collector now retains native interface context, refuses
cross-interface borrowing and invalidates ambiguous or failed/incomplete cache
rows. Global collection loss removes provenance before a proposed baseline can
be built. Purpose-separated private binding tokens retain interface context
without persisting raw identifiers in the baseline.

Legacy schema-v2 baselines remain parseable but cannot acquire missing binding
provenance from their opaque hashes. Unknown, legacy or changed topology remains
HIGH coverage, untrusted, with no baseline advancement. Two complete consistently
bound samples still produce CRITICAL for a genuine MAC change. No key/schema
reset, baseline replacement or automatic enrollment was added.

The regression first failed against the unchanged imported production evaluator,
reproducing its false critical. The first revised gate passed 97 and failed four
contradictory inert fixtures: no-route fixtures inherited a gateway identity, and
the old selftest omitted interface indices while changing the gateway address.
Those fixtures were corrected to represent the intended evidence without
weakening runtime checks. The final focused gateway/network/approved-ARP gate
passed **101 cases**, with no failures/skips, native exit 0 and retained-handle
proof of owned child retirement. Compile/diff checks passed; independent final
static audit found no blocker. Read-only postchecks confirmed actual network
baseline/enrollment bytes unchanged and no ARP baseline fabricated. A fresh
22-path source observation follows this correction.

### Final gateway-corrected restart

The final-source offline selfcheck passed all 29 phases and normal native exit 0,
including owned Qt/reader teardown. An attempted independent native attachment
arrived after that fast selfcheck had already ended; it opened no handles. Its
missed generation proof remains distinct from the normal completion receipt.

The new actual core and canonical Black Box generation were independently
pinned. The 300-second observer began 49.18 seconds after core creation. All
**22 scoped source hashes** matched before and after the window. The first two
status files belonged to the retired prior core and were excluded. All 39
current-generation status samples, spanning five publications aged 2.44–59.45
seconds, reported ARMED, pending zero, Chill enabled, ordinary privilege and
no active critical. Self-Integrity remained health 60/TOFU-unapproved.

All 41 runtime-metrics samples were valid, representing 21 publications. GUI
heartbeat lag peaked at **1,532 ms**; recent tick-body measurements were available
for 13 publications and unavailable for eight, with maximum **64.7295 ms**.
Time-weighted core CPU was **84.6979% of one CPU / 10.5872% machine**; Black Box
was **0.89583% of one CPU / 0.11198% machine**. The dense 180-second phase had
host mean CPU 47.50% and observer cost 0.127% machine CPU. The full observer
used 1.828 CPU seconds in its measured window. Queue peaks were flight recorder
1/4,096 and evidence read model 2/2,048; overflow and alert diagnostics stayed
zero, with no observed drops. All 11 watchdog file observations were unchanged.

The core's resident footprint was higher than the preceding run and decreased
from roughly 729 to 681 MB, while private commit changed from roughly 198 to
201 MB. The cause of that resident-footprint difference was not established;
these samples do not prove an expanding private heap or exclude later growth.
The same three process-inspection workers remained the largest sampled native
thread consumers. Native creation/ownership observations, timing limitations
and advisory module association are retained separately from stack attribution.

The optional Live Debug reader failed during its initial snapshot with
`Diagnostic pipe read failed`, leaving the last sequence below the announced
cursor. Its wrapper retained the error and reader exit 2. A later same-generation
retry failed with the same reason after approximately 1.57 seconds. The cause is
unresolved; these are diagnostic-delivery gaps, not proof of no alerts or of a
GUI/core failure. No exact retained native-generation attachment was available
for those already-exited readers. Independent status/metrics and bounded,
authenticated protected-original review supply the final evidence below.

The corrected gateway appeared as HIGH incomplete-telemetry coverage with
untrusted status and baseline-not-advanced, rather than a false identity-change
critical. A post-window exact read-only check proved network baseline and
enrollment bytes, timestamps and revision 2 unchanged from prepatch, with no ARP
baseline fabricated. The new memory-scanner classification still lacks live
exercise while Chill pauses that producer. Neither quiet observations nor
definition tests establish host cleanliness or full sensor coverage.

The performance observer exited 0, independently witnessed through its retained
native handle; observer/witness handles closed. The witness completed normally
and its exact command generation was absent, without a third retained process
pin. The alert observer also completed naturally. Angerona and Black Box remain
running; no runtime source changed during this final observation.

Final protected-original review selected 76 records from core creation through
20:22:08 UTC, below its 500-record cap; all 76 HMACs verified with unchanged
existing key identity/bytes. All 17 serious originals were covered: 16 HIGH and
one CRITICAL. The sole critical was the known recovery-assurance exposure,
observation-only with no response authority. Gateway findings stayed HIGH
coverage/drift, untrusted, without a false MAC-change critical. Startup metadata
remained MEDIUM exposure without response; Sysmon reported unavailable collector
coverage. Self-Integrity reported 31/31 watched INFO and unapproved-baseline
MEDIUM, with no new high/critical callable alert. Other serious findings were
audit, platform, driver, release or source-coverage exposures. No new active
threat was corroborated in this selection.

The first reader lost 1,733 initial records and stopped at sequence 2,215 below
the announced cursor 3,733, leaving another 1,518 initial retained records
undelivered. The retry produced an error receipt without a usable capture. The
named-module archive selection was corrected before this final review; its
separate severity query already covered all serious originals. Archive evidence
does not turn failed live delivery into continuous coverage. No new core's
startup journal action was independently read, so absence of selected Bus
action receipts remains distinct from proof of zero startup module actions.
Post-window exact-generation status at 20:23:17 UTC still reported ARMED/ready,
queue/pending/drops zero. Owned alert-observer generations were retired and the
application stayed running.

This maintenance update's offline validation and observations are distinct from
publication. Completion additionally requires the guarded publisher's exact
canonical-origin, branch/main/HEAD, fast-forward, clean-tree and seven README
asset checks. Its final receipt identifies the published commit.

### Follow-up GitHub CI review

The CI run for `3af99e55` failed on the same two assertions in all four Windows
Python jobs (3.10–3.13); each job otherwise passed 9,035 cases with 22 skips.
The separate Security assurance run and the eight other CI jobs succeeded.
The Sysmon fixtures omitted the provider identity required by the corrected
collector and expected legacy message/field values. They consequently tested
provider rejection instead of reaching the intended XML checks.

The corrected fixtures supply the verified Sysmon provider. The unsafe-entity
case proves the hardened parser was called and checks typed unavailable,
observation-only coverage without path leakage or response authority. The
oversized case installs a parser that fails if either collector calls it.
The focused XML, Sysmon adapter and coverage gate passed 25 cases with native
exit 0; compilation and whitespace checks passed. No product, workflow,
timeout, exclusion or parser security policy changed. Local validation used
Python 3.12; corrected cross-version results require the new public-head run.
Historical failed runs remain historical and were not rerun on their old SHA.
