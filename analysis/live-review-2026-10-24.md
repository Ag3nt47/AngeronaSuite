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

### VPN and diagnostic-throughput follow-up

The mixed-interface Fast Path rule treated a process with established VPN and
public physical-address sockets as critical split-tunnel abuse. The sampler
does not establish actual routing, the operator's split-tunnel policy, malicious
content or an exact process generation. An isolated authenticated EventBus
fixture reproduced the critical from that topology alone. This check now emits
MEDIUM exposure with no response authority. Bounded socket context and dedup
remain; independent credential-theft IOC matching still emits CRITICAL in the
same event. No vendor or executable-name exemption was added.

The operator authorized allowing the installed VPN. Four exact ordinary
installed executables were independently reviewed with valid publisher
signatures and current SHA-256 values, then approved through the existing manual
path-and-digest policy while Angerona was stopped. The previous policy was
absent; no existing entries were discarded. Stronger behavior and activated
SpywareGuard definition matching retain their response policy. Reviewed files,
digests and private receipts stay outside the public repository. A separate
Windows PowerShell signature adapter returned unavailable because its security
module failed to load duplicate extended type data; that failure does not prove
invalid signatures, an execution-policy denial or spyware. No host module,
execution-policy or environment repair was attempted.

The unchanged Live Debug transport could quickly deliver an inert snapshot
without contention, but an actual-core memory-first reader remained incomplete
after 30 seconds. Removing per-record output I/O therefore did not resolve the
observed delivery limit. In a controlled admitted-client native contention
fixture, individual writes delivered only 370 of 2,001 sequences in 12.22 seconds
before the snapshot deadline; coalesced writes delivered all 2,001 in 3.27
seconds, reducing writes from 374 to 22. These are fixture results, not measured
host CPU savings or proof of the old unrecorded disconnect's cause. A client
starved before reading still fails the unchanged native I/O deadline.

The server now batches its existing pages of at most 100 records and their
preceding retention notice into writes of at most 64 KiB. Per-frame 32 KiB bounds,
newline framing, ordering, gap notices, cursor advancement after complete page
writes, process identity, same-user ACL, cancellation and I/O deadlines remain.
Tests cover near-limit split/coalesced frames, native synchronous and pending
completion, retained-buffer drain, independent slow/fast clients and explicit
disconnect failure. Independent static review found no blocker.

### Warm observation and graph rebuild correction

A further 300-second window on the unchanged preceding generation used a frozen
scope of **22 source files**, unchanged before and after the observation.
All 41 qualified status samples were ARMED with pending zero, Chill enabled,
ordinary privilege and no active critical. Whole-window core CPU was 92.609% of
one logical CPU (11.576% of the eight-CPU machine); Black Box was 0.823% of one
CPU. GUI heartbeat lag peaked at 2,187 ms; recent tick-body measurements peaked
at 52.0966 ms, with 12 available and eight missing publications. No new watchdog
entry or queue drop was observed. The guarded publisher overlapped part of this
window and consumed substantial CPU; these observations do not isolate causes.

The hottest previously unmapped native thread remains unattributed. Source
review independently found that the app-owned Sentinel Lens worker rebuilt its
complete retained graph whenever a consumed batch emptied its queue, bypassing
the declared 200 ms interval. A deterministic inert fixture reproduced three
builds for three arrivals at 0, 62.5 and 125 ms. Removing that early condition
coalesces dirty input at the nominal cadence; idle polling can add up to 50 ms,
followed by scheduling and build time. Every accepted record, bounded retention,
drop accounting and final dirty shutdown publication remain. This is an
advisory snapshot freshness change, with no threat-response or collector TTL
change. It does not identify the retired hot thread or establish a live speedup.

Protected-original review from the preceding cutoff through exact core exit
covered all serious findings in the interval: **zero HIGH and zero CRITICAL**.
All 70 selected originals verified with unchanged existing signing-key identity
and bytes. Thirty SpywareGuard rows were configuration-only exposures without
response authority; the newest 40 of 426 Sysmon rows explicitly reported the
process-diff fallback. The other 386 older INFO Sysmon rows were outside this
selection. This bounded archive review is distinct from continuous live
delivery and does not establish host cleanliness.

Before runtime edits, all eight exact suite generations retired under the
reviewed, fully authenticated 458-record journal with matching checkpoint and
witness, no pending phases and byte-identical authority before and after. Its
two new records were paired startup Smart Deception activation, not a
threat-triggered PID action. The four substantive processes had retained native
termination receipts; their wrappers exited naturally. Every held handle closed.
The stopped validation interval is a runtime coverage gap.

### Follow-up offline validation

The actual-source VPN gate passed 127 cases with two existing platform skips;
the Live Debug gate passed 154 with one existing platform skip; Sentinel Lens
passed 26 with one existing skip. All returned native exit 0, with owned process
retirement evidence. Five deterministic cadence regressions cover spaced-input
coalescing, dirty idle publication, due backlog, quiet idle and final stop flush.

The first broader smoke check passed 28 phases and failed AI Triage readiness
because a user environment bind address was not a valid client URL. The offline
checker now uses its fixed loopback HTTP fixture and continues to forbid native
Ollama startup. It changes no persistent environment, production URL validation
or expected-skip rules. The final fresh disposable-profile run passed all 29
phases; its runner reported 69 passes and 18 optional/unstarted skips. Both
native selfcheck generations retired with exit 0 and every held handle closed;
Qt verification retired 13 widget owners, 13 readers and eight Python workers.
Compilation, documentation drift and whitespace checks passed.

### Continuing freezes and verified response promotion

The next frozen 25-source generation disproved a complete responsiveness fix.
Its first 300-second observation remained in Chill with 39 current ARMED status
samples and no pending actions, but the tail recorded a 9,156 ms GUI heartbeat
delay and a new watchdog entry. The sampled Python main-thread stack ended in
`qt.exec()` and did not identify a callback or lock cycle. A later 90-second
window included 12 failed native window-pump probes and status as old as 103
seconds. A stale ARMED sample does not establish current protection readiness.
The operator subsequently disabled Chill; those workloads must be distinguished.

Batching improved the controlled transport fixture, but actual finite delivery
remains intermittent: one finite reader exited 2 with incomplete coverage,
whereas a subsequent 90-second follow completed and a separate memory-first
reader reached diagnostics in 3.19 seconds. Different time and load prevent
attributing those differences to output persistence alone. Retention gaps and
client failures remain explicit. No continuous or lossless coverage is claimed.

A bounded external, non-suspending 60-second profiler collected 1,070 Python
execution-lock-owner samples, with 71 sampling errors retained. Of those, 558
followed the shared rich process collector into protected-process creation-time
fallback and psutil's native whole-system process query. The profiler consumed
about 2% of one logical CPU. This establishes an actual lock-holding hotspot;
its compressed per-thread timelines cannot identify the duration or cause of a
particular earlier GUI pause. Moving this collector across a process boundary
addresses that mechanism without weakening process-generation or freshness
checks. The existing detached console omits parts of the full dashboard and was
not substituted for it.

Authenticated originals also proved a distinct false-positive chain. The beacon
producer marked a process's connection timing as observation-only, without
corroborated threat intelligence or a response contract. SpywareGuard preserved
the source digest but promoted that finding into an active response contract.
The fully authenticated action journal proved a real exact-generation process
termination. Neither a publisher signature nor endpoint ownership proves host
cleanliness, but the original producer evidence did not authorize that response.
No vendor or executable allowlist was added to solve this promotion bug.

Later critical watchdog exhaustion and missing probe echoes are genuine
protection-availability failures. They do not independently prove malware or
API hooking. Subsequent fresh status showed containment recovery; stale status
was not counted as proof of availability. Production AI readiness also retained
its environment URL-policy failure; the offline fixture correction did not
repair that production configuration. One intended 600-second observer stopped
after 90 seconds near the process termination; its incomplete interval and
missing native exit receipt remain a coverage gap.

The published fixture-only commit `d7123b05` completed all 12 CI jobs and all
three Security jobs. Each Windows Python 3.10–3.13 job passed 9,037 tests with
22 skips. Those results validate that exact published revision, not subsequent
runtime candidates; historical failures were neither deleted nor rerun.

### Collector isolation and response-boundary correction

The embedded dashboard and direct headless entry now register one retained
inventory owner before constructing consumers. Native rich process collection
runs in its child; the original collector body and independent birth/image
checks remain intact. Qt admission is refused before acquiring the shared cache
lock. Existing collection-start TTL is unchanged, and failed or timed-out
collection stays unavailable instead of falling back to native work in Qt.
The private inherited-stdio protocol uses bounded strict JSON, an ephemeral
direction-separated MAC, exact parent/wrapper/worker generation bindings, and
request sequence/nonces. It carries observations, not response commands or an
installation credential. No external endpoint or new installed service exists.

Startup and retirement remain off Qt, with one owner retained through uncertain
cleanup. Native regression fixtures hold the child's Python execution lock
while a parent Qt timer and GUI admission continue. Tests also exercise malformed
and replayed receipts, deadlines, startup failures, cancellation during spawn,
and forced parent exit after worker admission. Windows creates its new owned
wrapper suspended, assigns its private job, then resumes its independently
verified sole initial thread; this closes the pre-hello redirector inheritance
gap identified during review. No running target is suspended. An abrupt parent
exit within native creation before job assignment remains an unproved creation
boundary; post-admission job closure tests do not prove atomic creation.
See Microsoft's [job inheritance rules](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

SpywareGuard now carries the beacon producer's policy and corroboration evidence
through its signed wrapper. Missing, unknown and alert-only cadence policies
remain exposure without process, peer or host fallback authority, even when
conflicting response hints are supplied. The explicitly corroborated producer
policy retains automatic response, including existing upstream-owner dedup.
The original source failed eight of ten focused cases; both corroborated
positive cases already passed. The applied six-suite gate passed 202 cases.

Maximum/terminate dispatch now attempts the authorized exact process transaction
before remote-IP firewall work as well as program isolation. A held firewall
provider no longer delays that attempt. Existing authenticity, typed action
capabilities, native generation custody, journal and uncertain-effect holds
remain. Other modes and contracts preserve their previous behavior. The
original dispatch failed three of 13 new inert scheduling cases; the applied
70-case process/contract/checkpoint gate passed without skips.

Canary misses retain their original HIGH/CRITICAL availability priority and
counters but explicitly report coverage failure with unconfirmed cause. Other
trusted process activity, especially polling fallback, cannot establish ETW
hooking or deliberate suppression. The signed record carries no active-attack
or response authority; the existing synthetic-producer practice classification
still applies. Two new authenticated polling/missing-probe cases and four
durable-pipeline cases passed on the applied source. Existing generic miss
health calculation can overwrite the critical branch's health-10 call with 40
after two misses; that separate health-policy limitation remains unchanged.

### Fresh isolated-collector observations

The first restarted generation kept all 30 scoped source hashes unchanged over
300 seconds. After excluding startup publications, 51 current status samples
were ARMED in Chill, with no pending response. Core CPU was 35.766% of one
logical CPU (4.471% of this eight-CPU host), while the separate inventory worker
used 56.912% (7.114% of the host). Black Box used 1.563% of one CPU. Collection
cost moved across the process boundary; it was not eliminated. Of 121 bounded
core window-pump probes, 119 responded and two early probes timed out. GUI
heartbeat lag peaked at 2,172 ms, and a startup tick at 1,303 ms. No new hang
watchdog entry appeared. These workloads differ from the preceding run and do
not establish an isolated causal speedup.

A second 300-second window on the same generation was actually in Full mode:
61 qualified samples showed Chill off, ARMED and no pending work. Its mode-change
origin was not exported and was not inferred as a manual unlock. Core CPU was
94.458% of one CPU (11.807% of the host), inventory worker 55.849% (6.981%), and
Black Box 0.927%. The core answered 114 window-pump probes and timed out eight;
heartbeat lag peaked at 875 ms and recent tick duration at 243 ms. The watchdog
file again remained unchanged. This demonstrates remaining intermittent window
pump delays, not a guarantee that every click is responsive. Observer CPU and
the competing validation load remain in the private receipts.

Authenticated archive review verified all 184 selected originals, including all
42 serious findings across that generation's reviewed interval. Thirty-three
serious rows preceded the second window. Its nine new serious findings were
failed probe/coverage checks and platform hardening exposure. Missing recovery
copies, missing audit/Sysmon access, unavailable graph evidence, aggregate
unverified driver inventory, and claimed vulnerability candidates did not prove
malicious drivers or exploited vulnerabilities. These coverage failures remain
open; no alert or baseline was cleared.

### Unleased marker false positives and supported practice authority

The same review uncovered a second actual false-positive response chain. A
separate disposable-profile checker launched three owned, fixed sleep probes.
The live Purple Guard recognized their marker text but had no issuer lease for
them. It nevertheless produced process response contracts. Signed originals,
the checker's authenticated history and independent native producer receipts
bound all three controls to that isolated test. The live action journal proved
two exact-generation native terminations. A third attempt failed before a
verified effect when the native image query failed; it was not counted as a
successful kill. The controls' inert ownership is established by that combined
evidence, not by accepting a marker label or executable signature as trust.

Purple Guard now treats unleased lexical process and file markers as HIGH
observations: no active-attack flag, response authority, response contract or
copied practice lineage. Independent bounded observation dedup does not consume
a future issuer-attested hit. Valid issuer-backed controls retain their normal
contracts, and independent malicious indicators retain their response policy.
This also prevents an ordinary marker observation from entering SOAR's active
attack count or waking modes as an asserted attack.

The next diagnostic generation launched with 33 scoped runtime source hashes.
A native accessibility invocation switched Chill off in about 209 ms; a fresh
generation-bound status confirmed Full mode. Later archive review authenticated
170 selected originals, including all 28 HIGH/CRITICAL rows and both unleased
Purple process observations. Both observations explicitly refused response
authority, and the journal remained at 477 fully authenticated records with a
matching checkpoint/witness and no pending action. The only records added after
the previous generation's 475 were startup Smart Deception activation. There
was no new PID/IP containment in that reviewed interval. The three critical
findings concerned recovery exposure and failed sensor probes. This is bounded
evidence for the calibrated marker path, not a complete host-security verdict.

Automated attempts to open an alert detail initially failed in the diagnostic
selector: Qt exposes the checkable Details control as a checkbox, and accessible
row selection did not establish the table's current row. Subsequent attempts
also did not establish a newly opened owned detail dialog. Every helper had a
native terminal/closed-handle receipt; no successful alert-detail latency is
claimed from those attempts. The successful Full-mode invocation is distinct
from validation of the alert-detail path.

Before each runtime source change, the reviewed suite generations retired under
fresh full-history authentication, matching witness/checkpoint, no pending
phases, and byte-identical journal authority before and after. The last completed
retirement covered ten exact native generations; five substantive processes
were terminated through retained handles and their five wrappers exited
naturally. Diagnostic handles closed. The following restart left an 11 minute
13 second protection gap while stopped validation ran. The VPN GUI remained
alive, and its four exact approved executable digests still matched; unavailable
SYSTEM process queries were retained as coverage gaps. No encrypted-traffic
efficacy claim follows from service/adapter liveness.

### Full-mode Black Box follow-up

A further 300-second observation kept all 33 scoped runtime source hashes
unchanged. Whole-window native CPU counters measured the core at 98.266% of one
logical CPU, the separate inventory worker at 57.724%, and Black Box at 0.984%.
These correspond to 12.283%, 7.215% and 0.123% of the eight-CPU host. The core
answered 109 native window-pump probes and timed out 13; Black Box answered all
61 of its probes. Heartbeat lag peaked at 1,141 ms and recent GUI tick duration
at 352 ms. No new hang-watchdog entry appeared. All 61 distinct, generation-bound
status samples confirmed Full and ARMED; their maximum age was 3.941 seconds.
The latest sample had no pending response. Window-pump replies do not measure
click, tab, alert-detail or paint latency, and the timeouts remain open
responsiveness evidence.

All 206 selected archived originals verified, including the complete set of 48
serious findings across the reviewed generation interval: 37 HIGH and 11
CRITICAL. The 300-second window itself added six HIGH and four CRITICAL rows.
Four repeated canary misses and their four critical coverage-failure reports
retained an unconfirmed cause; the remaining HIGH rows were an unleased marker
observation and a platform-hardening exposure. These findings supplied no
response authority or proof of active compromise. Selected lower-priority
module tails were capped, so complete serious-event selection does not imply a
continuous or complete event stream.

The authenticated action journal remained at 477 records with matching
checkpoint and witness, no pending phases, and unchanged bytes across all four
authority objects. No new journaled containment action was established in this
window. No alerts, baselines or authority were cleared to obtain that result.
The observer's native generations retired and its query handles closed while
the application continued running.

A private 24-case integration gate and an inert SOAR baseline overlapped this
window. Their wall-time boundaries are preserved, but exact native CPU for
those helpers was not collected. Earlier integration and accessibility helpers
were confirmed to precede the window. These competing workloads and differing
runtime phases prevent attributing timing differences to a single change.

### Remaining execution-lock hotspot

A fresh bounded, non-suspending profile yielded 800 weighted Python
execution-lock-owner samples and retained 75 sampling read-race errors. Sentinel
Lens accounted for 421 of those samples (52.625%); its analysis function for 415
(51.875%). These are sampled stack proportions, not CPU-time measurements or
the duration of a particular GUI pause. They identify remaining advisory
analysis work for investigation without proving the cause of an earlier freeze.
The applied Sentinel Lens change now pauses one second after a completed
advisory rebuild by default. Explicit intervals, retained evidence, queue/loss
accounting and final stop flush remain. This changes no response policy or
collector TTL and supplies no hard freshness or click-latency guarantee. Its
actual Sentinel/causal gate passed 33 cases with one existing platform skip;
the subsequent frozen-source observation is recorded below.

### Issuer-backed practice verification and original response receipts

The marker-authority correction exposed a compatibility gap in the supported
practice verifier: its advisory file/process registrations did not supply a
live issuer lease. The applied integration now acquires the existing lease
through the exact manager, EventBus and bound flight recorder before creating
controls. It enrolls the created file identity or a native process challenge,
then requires the real Process Monitor observation and issuer-attested Purple
receipt. A synthetic practice event, tag, run label or registration string
cannot substitute for that proof.

The applied SOAR bridge preserves the original authenticated Purple event when
delegating to the exact registered, running Combat owner. Combat's existing
original-event admission and HMAC dedup remain responsible for one-shot
response. There is no copied publisher identity or fallback response actor.
If Combat already completed that original action, SOAR can adopt only its
signed matching receipt and verified, committed, applied, non-undone journal
entry. File adoption additionally binds the original target and content digest;
process adoption binds the original permitted action, native PID and birth,
image, retained-handle custody, signaled wait and terminal exit. A completed
old-generation receipt cannot authorize another action against a reused PID.
Without a completed proof, new process work still requires the existing exact
live-process identity check.

An exclusive file handoff can briefly make the issuer's historical file proof
unavailable. The applied code permits bounded observation only of that same
registered pending handoff, with its descriptor released for Combat custody.
Released or failed custody, changed bindings, and absent or completed handoffs
do not grant a retry window. Full issuer proof is still mandatory before SOAR
submission or success credit; pending state supplies neither authority nor a
successful receipt.

Practice closure still requires the positive control, a quiet negative control,
both exact signed events durably recorded, verified response, and the action's
postcondition before verifier cleanup. Marker cleanup is restricted to the
issuer's retained identity; a replaced file is not removed by pathname fallback.
An uncertain probe retirement retains the existing owner until terminal proof,
without respawning or repeating host actions. Frozen packaged runtimes
explicitly refuse the Python process probe because the application executable
is not an admitted Python interpreter; file-marker practice remains supported.

The unchanged legacy file-practice baseline failed. On frozen private candidate
bytes, the integration gate then passed 25 cases, including real file, native
process and readiness positives; the independent SOAR security gate passed 42.
Both returned native exit 0 with owned diagnostic retirement and closed-handle
proofs. General inventory was supplied by controlled offline fixtures only;
the exact native child proof remained real, and incomplete production readiness
was not relaxed. These private candidate results are distinct from the applied
validation attempts and fresh 34-source observation below.

The first maintenance validation of the applied runtime code passed 139 cases
and failed four during general process-inventory readiness setup. The proper
practice file, process and readiness integrations passed. A separate offline
checker passed 28 of 29 phases and failed its drill at the same strict lease
boundary. The host inventory reported incomplete enumeration and many unreadable
processes; production readiness correctly refused to treat it as complete. These
failed attempts remain recorded and do not establish either malware or a
successful host-coverage check.

The applied harness-only correction now labels that phase as an offline general
inventory fixture with native owned controls. A temporary standard-library
patch supplies fresh immutable empty general snapshots only while that
disposable-profile phase owns its controls; the existing issuer, real native
child/artifact proof, response, history and cleanup remain. The fixture refuses
a non-disposable profile or a preexisting running/alive Process Monitor, and
restores the exact original supplier on success or error. Five focused fixture
cases and the five existing drill-cleanup cases passed privately with native
exit 0 and no diagnostic child processes. This is not a repaired host inventory,
an additional production trust source, or a completed 29-phase host assessment.
The applied harness tests subsequently passed all ten on normal repository
paths, with native exit 0 and both diagnostic generations retired. Initial
fixture-location failures remain recorded; test input now uses its explicit
disposable data root instead of assuming the ambient pytest temporary directory
falls within that boundary. The profile guard was unchanged.

The four affected lease-setup tests and an incomplete-enumeration negative
subsequently passed a five-case actual-source follow-up. Controlled general
inventory was supplied only to those offline contract setups; exact owned
native target proofs and the negative coverage hold remained. This focused
follow-up does not relabel the earlier 139-pass/four-failure run as a passing
full-suite rerun.

The final disposable-profile offline checker passed all 29 phases with native
exit 0. The module runner reported 69 passes, zero failures and 18 optional or
unstarted skips. The explicitly labelled owned-controls phase completed its
real issuer/native controls and cleanup using the scoped general-inventory
fixture. Teardown retired 13 widget owners, 13 readers and eight Python workers;
both native checker generations had terminal, closed-handle receipts. These
results validate the offline harness, not whole-host inventory availability.
The preceding 28-pass/one-failure attempt remains part of the record.

### Fresh 34-source Full-mode observation

The exact maintenance stop and restart left a 6 minute 44.096 second protection
gap. After a fresh Full-mode confirmation, the final 300-second window ran from
23:46:02.456 to 23:51:02 UTC on 24 October. All 34 scoped runtime source hashes
matched before and after. All 61 distinct generation-bound status samples were
fresh, Full and ARMED, with maximum age 3.702 seconds and no response pending,
queue backlog or drops. The application remained running after observation.

Whole-window native counters measured core CPU at 91.0729% of one logical CPU
(11.3841% of the eight-CPU machine), the inventory worker at 56.8906%, and Black
Box at 1.0%. The core answered 116 window-pump probes and timed out six in six
turns. Black Box answered all 61 probes, with a maximum measured response of
1.552 ms. GUI heartbeat lag peaked at 625 ms and tick duration at 114.868 ms;
all 30 retained metric samples supplied tick data. The flight-recorder queue
peaked at four, other sampled queue depths at zero, and all sampled drop counts
were zero. There were no new watchdog-log changes. A corrected derived report
excludes unsampled rows from its watchdog-change count; the earlier report was
preserved.

These measurements are not instrumented click, navigation or paint latency.
Workload, startup phase and module timing differ from previous windows, so no
isolated CPU reduction or causal before/after ratio is claimed. The operator
subsequently answered both the earlier collector-fix question and the latest
Full-mode question with “Responsive” for tabs and alert details. That is useful
operator-reported corroboration, separate from measured interaction latency.
The operator then qualified it as “still a little laggy but a lot better” and
requested responsiveness while using other programs. Remaining contention and
interaction latency are unresolved; the six probe timeouts still preclude a
universal no-freeze claim. All four native observer/witness/wrapper generations
retired with exit 0 and closed
handles; the applications were intentionally left running.

All 186 selected archive originals verified. The complete serious selection
contained 47 findings: 45 HIGH and two CRITICAL across startup, pre-Full and
observation time. The critical rows concerned recovery-evidence exposure and
missing CHAOS collector echoes; neither established active malware. The only
serious finding timestamped within the 300-second performance window was a HIGH
HVCI-not-running exposure. All 24 Purple marker observations lacked active or
response authority. The newest 40 of 69 SpywareGuard rows were inactive,
response-ineligible exposures; 29 older lower-priority rows were outside that
selection. Unavailable audit/graph evidence, production AI URL configuration,
posture and other collector gaps remain open. Archive completeness applies to
the committed serious selection, not uncommitted or never-collected events,
and does not supply missing per-row core-generation provenance.

The full authenticated journal reached 479 records with matching checkpoint and
witness and no pending phase. Its only additions after the preserved 477-record
prefix were the paired startup Smart Deception activation; that prefix and the
existing signing authority were unchanged. No new PID/IP containment was
established from the selected observations. Four exact VPN executable approvals
still matched their digests, with the expected processes, two running services,
adapter and GUI present. Liveness does not prove encrypted-traffic efficacy.

A bounded committed-archive continuation through 00:02:10 UTC on 25 October
found exactly three additional HIGH HVCI exposures, all authenticated, and no
new CRITICAL. The independent authority check at 00:02:24 UTC authenticated all
479 records again, with matching checkpoint/witness, no pending phase and all
four authority objects byte-identical to postflight. It found no new tail or
actions. This is a named archive/journal cutoff, not a continuous live-feed or
host-cleanliness claim.

### Live Debug CLI continuity checks

Two fresh post-window clients failed before reaching their initial cursor: the
finite reader after about 8.4 seconds and the intended 90-second follow after
about 8.3 seconds. They retained about 409/410 records and 130.8 KiB before a
generic read error. Their captures and errors remain preserved; neither run
establishes current alert-feed continuity.

The CLI output-batching correction is now applied outside the unchanged
34-source runtime scope. A broader 121-case gate passed its preceding revision;
after a minimal interrupt/BrokenPipe correction, the 31 affected actual-source
tests passed with normal repository imports and native exit 0. All four retained
diagnostic generations had terminal/closed-handle evidence, and the outer helper
and wrapper were independently absent. These gates are not interchangeable
revision claims. Transport custody/protocol checks are separate from original
event-HMAC verification.

The fresh standard finite client then succeeded with native exit 0. Its phase
wall time was 3.695 seconds and client interval 3.100649 seconds, reaching its
full initial cursor with 2,000 event frames and no client/reader errors. Its
explicit initial retention gap of 7,959 records and zero reported queue drops
were preserved. The fresh follow also completed with native exit 0 over
90.942388 seconds, reaching its initial cursor and retaining 2,280 event frames
and 43 heartbeats without client/reader errors. Its initial retention gap was
also retained. Neither successful mode restores evicted history or establishes
lossless session coverage; the earlier failed readers remain failed.

All 34 runtime hashes matched before and after these client checks. Retained
diagnostic children and reader threads retired, with no reported native custody
gap, and the core query handle closed while the application remained running.
The transport results do not replace original-event authentication or expand
the named committed-archive cutoff above. Further current-build profiling and
responsiveness under competing applications remain separate ongoing work.

### Subsequent storage exhaustion and publication gaps

Post-client review selected 18 new serious committed originals, all HMAC
verified: 12 CRITICAL and six HIGH. Two live-module self-test summaries each
reported 71 passes, six failures and 11 skips. Failures included no-space errors
in Compliance Mapper and Kernel-Boundary Posture Ledger, a database-open failure
in Posture Hardening, ETW lifecycle/health unavailability and the existing AI
provider URL refusal. Their caller was not established from the original
events. These are availability and coverage failures, not proof of malware.

An independent volume query confirmed zero available bytes on the configured
source-data volume, while the workspace volume retained capacity. The three
failing file/database fixtures use Python temporary storage under the expected
canonical source-data root. This routing is intentional source policy, not an
established regression. A missing cleanup in the Posture self-test was found,
but no large disposable artifact with proved ownership was established; it
does not explain the exhausted volume. No files or evidence were deleted.

The post-client authority check at 00:14:36 UTC still authenticated all 479
journal records with matching checkpoint/witness, unchanged authority bytes
and no pending phase. VPN processes and services remained present. However,
the selected status file was already 55.57 seconds old. At 00:17:47 UTC, the
same core generation remained alive while status and runtime-metric evidence
were about 248 and 252 seconds old. These stale files cannot establish current
Full/ARMED state or current GUI timing. Committed archive selection also cannot
recover events that could not be persisted during storage exhaustion.

Source review found a startup capacity check but no periodic production check
of the configured data volume. Storage Hygiene checks spill locations and
intentionally accepts the source profile; it is not a capacity monitor. Status
Reporter retains write-failure evidence in memory, which cannot update files
on a full destination. A private, observation-only capacity/publication-health
candidate is being prepared. Free capacity alone will not prove successful
journal or recorder writes. No deletion, data-root migration, baseline reset,
fallback signing authority or response bypass is authorized by such a warning.

The operator requested cleanup candidates for review. Discovery is limited to
bounded metadata checks of known cache/dump locations and top-level downloads;
contents, active security evidence and unknown trees are excluded. Any selected
cleanup or move remains a separate reviewed action. A new non-suspending
profile of the unchanged runtime is also in progress, with storage pressure
and competing diagnostic work retained as timing context.
