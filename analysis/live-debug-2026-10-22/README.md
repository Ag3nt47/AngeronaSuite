# Live debugging and screenshot issue review

This review follows the reported runtime-tamper alerts, persistence findings,
Black Box diagnostics and five-second GUI heartbeat delays. The scope includes
the new opt-in [live debug harness](../../docs/live-debug-harness.md), its
read-only Black Box client, and independent security/performance review.

Evidence comes from the screenshots, source inspection, isolated reproductions,
native Windows transport checks and regression tests. Protected production logs
were not readable from the development session. A reproduced false-positive
mechanism does not conclusively identify the cause of a retained live incident.
Original authenticated alerts, baselines and response records are preserved.
A fixed source defect can have a passing isolated regression while wider
deployment or incident cause remains unproven; the row result and its stated
limits define that scope.

The [component interaction map](interaction-map.md) records dependencies,
cross-component failure paths, safeguards and the staged observation matrix.
The [additional sensor review](additional-sensor-review.md) records six held
providers' active-path, cancellation, executable, storage and offline limits.

## Current source and hosted CI evidence (2026-10-23)

The current source checkpoint covers shared-HKCU collection (SCN-04),
record-bound CVE freshness and worker lifetime (GUI-18), source-conflict
interruption recovery (UPD-04), and lossless diagnostic receipt review (TST-39).
The initial **214-test cohort** and final **54-test follow-up** each passed with
zero failures, errors or skips; the cohorts overlap. Final source also passed
**1,152 Python 3.10 AST checks** and a **29-phase default selfcheck**. Its 86 module
rows reconcile as 68 PASS/18 explicit SKIP, with a separate passing pipeline and
nine verifiers. Both supervised interpreter generations retired with native exit
0, all four handles closed; MainThread only, no QApplication and zero top-level
widgets.
The fresh Recovery/SpywareGuard pair observation completed for **90.140 seconds**
with **352 status/heartbeat samples** and a maximum heartbeat gap of about
0.797 seconds. Its state is **OBSERVED_WITH_GAPS**: the isolated recovery profile
remained unprovisioned (health 15) and SpywareGuard remained preview (health 85).
Neither module crashed or reported overflow; no capture/export/console drops,
errors or pending threads were recorded. The admitted core query handle and both
outer generations proved retirement with native exit 0 and closed handles.
Shutdown recorded MainThread only, no QApplication and zero top-level widgets.
The next guarded publication will carry the short [changelog](../../CHANGELOG.md).

The pair exported four events: one critical recovery exposure, one medium
Run-persistence observation and two low service-path exposures. Every exported
event had response_authorized=false; the three Spyware events separately had
active_attack=false and spyware_confirmed=false. No threat/false-positive
adjudication, suppression or remediation followed. Each module had 18 scheduled
cycles, not 18 proven scans: the capture lacks per-source scan-completion counters
or timestamps. Active findings imply that the persistence collector returned,
without establishing completed-scan counts or full surface coverage. The single
current Run observation versus two R7 records is current source behavior only;
it does not prove historical physical-key or account identity. This two-module,
ordinary-user observation does not measure GUI responsiveness or all sensors.

The 214-case gate covered the first updater revision. Later source review found
a POSIX candidate-open availability gap; no host hang or activation bypass was
demonstrated. The final 54-case gate covers the hardened updater and an immediate-
close neighbor. POSIX retry opens require nonblocking/no-follow flags and check
the acquired descriptor before stream construction. Three inert flag/ordering/
ownership controls do not establish physical FIFO/device efficacy, universal
I/O deadlines or protection against privileged namespace races. Recovery remains
limited to process interruption, with no source activation or power-loss claim.

Published [6ead285](https://github.com/Ag3nt47/AngeronaSuite/commit/6ead285f3e4658674600f15fb9f1f4f1f64ac9d3)
completed [CI](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/39979165038)
with 11 of 12 jobs passing and [Security](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/39979165167)
with 3 of 3 passing. Python 3.10/3.12/3.13 each recorded 7706 PASS/19 SKIP;
Python 3.11 recorded 7679 PASS/19 SKIP/27 setup errors from one 45-second
confinement preflight timeout. Exact retirement was retained; the cause remains
UNKNOWN. The last advisory stage cannot identify a specific blocked operation,
and clock stability remains unproven. New fixed-label operation tracing is
bounded to 64 operation markers plus one explicit limit marker; fixed coarse
stages are separate. Checks/order and 45-second/10-second deadlines remain,
and tracing may itself affect timing.

The preceding source gate passed 255 tests/one POSIX-fork skip and default 29;
a later one-workflow gate passed 8 local checks. Their exact source snapshots,
native retirement, 68 PASS/18 SKIP module accounting, separate pipeline and 9 verifiers
remain recorded below. PER-13's synthetic Sigma benchmark and PER-14's atomic
COMMIT-count contract are scoped evidence, not dashboard, whole-product or
power-loss results. Earlier 28f4 CI 11/12 and all original failed histories remain
in the validation record; a newer source change does not rewrite their causes.

R7 observed the earlier 1854/fabb source for 90.204 seconds: 347 repeated
status/heartbeat views and 18 scheduled cycles per module, not 18 full persistence
scans. Core and both outer generations retired/exit 0; original launcher Popen
closure is not claimed. Its five response-ineligible findings remain:
a fresh unprovisioned recovery profile, two Run records, and two distinct lexical
service exposures. No confirmed spyware or supported false positive was
adjudicated. The original physical Run-key identity, historic user SID equality
and benignity remain unproved. The independently source-confirmed repeated
shared-key collection policy is a separate follow-up, not incident adjudication.
The original triage cutoff had unexecuted exact queries; top-level omission
counts do not establish nested export completeness. A later four-target read
matched both Run command records and both distinct service command records;
the two current service configurations were disabled. It did not establish
physical aliasing, historical account identity, benignity or threat. The query
child exited 0 and its admitted handle signaled retirement, but the supervisor
failed a post-exit image query with WinError 31 before recording terminal native
exit/birth proof. That owner gate remains failed. A future observer correction
passed six inert FakeAPI controls only. Separate precision corrections retain
exact generation strings from the immutable original; they supply no new
observation or retroactive native proof. R7 does not validate this later source
revision or establish the cause of the earlier R5 observer failure.

The register has 151 unique IDs, preserving all prior 148 IDs/order and the
original SCN-04/TST-38 evidence as history. Independent
witness/backup administration, signed deployment and trusted activation remain
separate evidence boundaries.

## Issue map

| ID | Evidence and cause | Result |
| --- | --- | --- |
| INT-01 | `marshal` code fingerprints change when execution holds an extra constant reference; reproduced on the exact `executable_sha256` callable | Canonical v2 fingerprints preserve constants, nested code, exception tables, defaults and closures. Old independent manifests require explicit review. |
| INT-02 | Repeated ACL helper collection can time out; localized principal names are incomplete evidence | Native Windows SID/access-mask audit; denied, unsupported and incomplete fallback evidence remains unknown. The screenshot's exact helper failure is unconfirmed. |
| SEC-01 | A swap/read/restore race returned approved bytes for a different named executable | Initial, opened-descriptor and final named identity checks, single-link enforcement and retained no-follow file/parent custody. Inert re-attack denied. |
| SEC-02 | A same-size edit with restored mtime preserved Windows metadata and reused an approved cached digest | Removed executable digest-result reuse. Every authorization hashes fresh bounded content; policy snapshot caching remains. |
| SEC-03 | Patching the separate stricter digest predicate escaped its sibling's runtime monitoring | Monitor the strict predicate and new custody helpers explicitly; missing mandatory coverage fails closed. |
| PER-01 | An unquoted service configuration alone requested critical host isolation | Configuration exposure remains reviewable and cannot request containment. Eligible execution detections keep the single-rule policy. |
| PER-02 | Whole-command path matching treated log/output arguments as executable payloads | Parse executable/script targets and retain real transient execution findings. |
| PER-03 | Task names/descriptions and ordinary interpreter use were treated as critical execution | Inspect task execution fields; generic administration/profile locations remain review exposures. No trust-by-name exception. |
| PER-04 | Initial parser narrowing missed valid nested/quoted interpreter execution | Independent review added cmd switches/double quoting, PowerShell prefixes/direct scripts, Python option arguments, shell commands and quoted regsvr32 targets. Unsupported syntax is partial analysis. |
| CLS-01 | Exact ACL/persistence collection failures and Sysmon replay notices entered the active-threat list | Producer-specific health contracts retain signed severity. Explicit attack, integrity and delivery-failure evidence still scores. |
| GUI-01 | Reveal filter resolved PySide enum attributes for every widget event | Cached membership; measured rejection-path component speedup 3.71 times in the isolated review. This is not a whole-application speedup. |
| GUI-02 | Deleted destinations and stale opening callbacks could wedge reveal coordination | Owned/coalesced timers, deleted-target recovery and preserved security-window opt-outs. |
| GUI-03 | Recovered heartbeat could be blamed for an earlier delay; a sampled Qt stack was called a deadlock | Stable heartbeat sampling and accurate uncertainty in watchdog/Black Box wording. |
| GUI-04 | Runtime-code source location existed but alert detail showed unavailable | Display source provenance without converting the source file into a quarantine target. |
| GUI-05 | Exact native Qt five-second delay in screenshots | Unresolved cause; a Python stack sample alone cannot prove a lock cycle. Collect live evidence and repeated samples. |
| GUI-06 | Legacy threat dialog could perform current executable-authorization hashing on Qt | Coalesced background threat snapshots, responsive pending state, retained evidence on read failure and safe close. |
| GUI-07 | An isolated real source launch measured an 8.94-second startup Qt timer gap while offline regression was running | Captured through the live feed with no reported queue loss. A sampled responsiveness-publication frame is not causal proof: 2,000 isolated real-footer publications peaked at 7.6 ms. Bounded next-run instrumentation is prepared; cause remains open. |
| DBG-01 | A normal-user reviewer cannot read elevated private recorder storage | Opt-in outward-only Windows pipe shares bounded redacted views; protected storage ACLs stay intact. |
| DBG-02 | History paging copied all retained records while holding the publisher lock | Select only the requested page under the lock, then copy outside it; serialization also stays outside the handoff lock. |
| DBG-03 | Log path checks could race a reparse/parent replacement | Retained native parent/file custody and canonical handle-path checks; no arbitrary-file export API. |
| DBG-04 | Malformed records, slow readers, disconnects and cancellation can lose or misattribute evidence | Bounded frames/queues/clients, OS PID and held process-birth binding, explicit gaps, cancellation completion ownership and regression coverage. |
| DBG-05 | CLI writer failure could re-enter the failed writer; unbound verdicts could label unseen sequences | Independent review requires isolated output errors and reasoned, record-bound caller-only annotations. |
| DBG-06 | A 64 KiB short-line log generated over 65,000 views and delayed EventBus export | Bounded, resumable source turns and fair log scheduling; blank runs become counted notices. Mixed-line replay and simultaneous log/event pressure checks passed; no lossless-capture claim. |
| DBG-07 | Native overlapped cancellation could release buffers early or wait for unissued I/O | Track operation issuance, cancel and drain before releasing ownership; real-pipe and interruption regressions. |
| DBG-08 | Scanner/watchdog/Black Box startup exceptions were outside the original stream's log allowlist | Explicit fixed crash/stall sources in both the diagnostic feed and independent recorder. |
| DBG-09 | The installed pywin32 returns integer 535 for an already-connected pipe without issuing overlapped I/O; treating it as pending hung live shutdown | Corrected returned and raised status handling, bounded stop waits, retained pending-I/O ownership and partial-start cleanup. All 17 native lifecycle regressions passed. The failed observation and its exact owned-process cleanup remain recorded. |
| DBG-10 | A fast reader replayed over 1,100 views without error, while the same live feed disconnected when its consumer persisted each record to disk | One-second per-client write deadline was too short for a disk-persistence pause. Three-second bounded waits preserve cancellation and client independence; a native retained-history pause replay and existing stalled-reader regressions passed. Restart is required for a running producer to load this change. |
| SCN-01 | A one-second PID difference scan allocated per-process metadata for unchanged processes | Read PID sets with `psutil.pids`; enrich additions only. Measured idle component median 4.98 to 0.34 ms, 14.6 times faster. |
| SIDE-01 | Substring process matching could adopt an unrelated process mentioning a helper | Shared exact executable/script/module/role identity, refreshed candidate argv, PID-generation cache and denied-candidate isolation. |
| SIDE-02 | Peer watchdog ignored the Black Box disable setting | Both supervisors now honor the configured disable boundary. |
| SIDE-03 | Aliased snapshot/status paths caused repeated identical disk work | Deduplicated paths and removed redundant exists/stat calls; independent recorder remains a separate failure domain. |
| SIDE-04 | Legacy Black Box process inspection chose the largest matching core when multiple data profiles coexisted | Ambiguous independent cores now yield unknown process identity instead of RSS-based selection; launcher/child collapse remains. 64 affected regressions passed. Discovery of a single core is still advisory, not proof of its data-profile ownership; Live AI Review uses explicit PID/birth binding. |
| SIDE-05 | Closing the actual Black Box left six QThreads running and reproduced native exit 0xC0000409 | Normal close waits asynchronously for owned readers; direct quit and partial startup also retire owners before Qt deletion. 76 affected tests passed; independent optional-thread/snapshot replay remained responsive and exited normally. The actual live recorder also closed with exit 0. |
| HOST-01 | Short live sample showed substantial system CPU contention from multiple programs | Scheduling pressure is a plausible contributor, not a malware verdict. No unrelated process was terminated or allowlisted. |
| TST-01 | Direct-file pytest wrapper invocation omitted the repository import root | Direct-file mode now anchors the selected script's checkout. Passing/failing child runs preserve pytest's verdict and exit journal; 15 wrapper regressions passed. |
| TST-02 | Selfcheck completed its GUI phases but crashed during native Qt teardown | Retain owners, stop timers/readers, join bounded workers and dispatch only DeferredDelete before QApplication shutdown. Two complete runs exited normally; the forced-exit workaround was removed. A printed report alone is not a successful process exit. |
| TST-03 | A race regression's one-second startup assertion failed while its worker reached the intended barrier immediately afterward | Event-confirmed bounded synchronization, direct lock-ownership proof, worker diagnostics and unconditional release/join preserve the causal security checks. All 41 tests in its file and a final exact-race rerun passed; product gates are unchanged. |
| TST-04 | The full regression found the new live-debug setting missing from guided setup and an outdated CLI flag assertion | Guided setup now exposes the Windows read-only sharing opt-in and restart requirement. All 40 affected setup/settings/CLI tests passed. |
| GUI-08 | The source editor searched each line separately for 35 identically formatted keywords | One equivalent keyword alternation reduces rule scans from 41 to 7. Exact native formatting equivalence and 12 affected regressions passed; measured full source-dialog construction was 2.10 to 2.30 seconds before and 0.50 to 0.78 seconds after. |
| GUI-09 | New bulk module startup can contend with synchronous lifecycle controls; Chill may change during settings persistence | Background governed startup, held competing controls and first-cycle pacing. A post-save veto-only admission check closes the reproduced race; nine late policy/lifecycle transitions held startup and the control started once. Independent final native test file: 25 passed. |
| GUI-10 | SpywareGuard occupied a tab and fixed header buttons did not use wide screens well | One reusable dedicated window opens from the wider top-right black-spy button. Native width/scale, lifecycle and UGCAP checks passed across 480 to 3,840 pixels. |
| GUI-11 | The collapsed globe had one anonymous orbit dot; the expanded Scanner label could clip | Four colour-coded named-function moons reuse the existing cached status cadence and routes. Native geometry checks cover small, edge and negative-origin displays; no per-moon collector/timer. |
| NEWS-01 | Generic Citizen Lab RSS omitted recent research, news queued behind scans, and summaries were discarded | Bounded official research cards, earlier background scheduling, cached details, per-source failure state and dated offline references. 146 affected regressions passed; unavailable CISA retrieval remains visible. |
| SCN-02 | Eight shared sensor reads plus eight Scan Center audits made nine connection enumerations; cached row dictionaries could be changed by a consumer | Scan Center reuses the existing typed receipt and shared rows are immutable. Inert concurrent replay made one query, preserving age/partial/error/cancellation limits; 141 compatibility regressions passed. |
| SCN-03 | YARA and API Patch Detector request their full 64 MiB/128 MiB caps for smaller regular files | Applied four-file change uses opened size plus one and rejects size changes; YARA refuses a mismatch before scanning. Five new real-file/receipt/cache/retry controls and 84 focused tests passed/native 0 with stable files and clean retirement. This bounds requested bytes, not allocator behavior or product throughput; a tiny 20-read comparison is diagnostic only. Other read candidates remain deferred. |
| TST-05 | One native repair fault-injection fixture encountered a Windows atomic-replace failure before reaching the intended crash point | Recovery failed closed and preserved the original environment. The exact fixture passed in an independent rerun; the transient OS/storage cause remains unconfirmed. No trust gate was relaxed or broad retry added. |
| TST-06 | A threat-dialog test's first native Qt dispatch outlasted its entire 200-ms observation interval | Event-confirmed repeated heartbeats are required while the worker remains blocked, within a bounded two-second interval. 79 affected regressions passed; this is not a fix or causal explanation for the historical startup stall. |
| SEC-04 | The installed certifi bundle retained a compromised CA root; the bootstrap pip also vendored an affected bundle | Reviewed certifi 2026.10.19 and pip 26.2.2 wheels, matched official metadata hashes and updated release locks. The fresh installed-environment audit reports no known vulnerabilities. |
| AUTH-01 | One policy signing key under multiple approval labels could count as multiple operators | Enrolled issuer/subject/key proofs, distinct-key/subject matching, exact-operation signatures and durable revocation/attempt records. Registered high-impact actions require independent outcome verification; global critical-change integration is still in scope. |
| READY-01 | ATT&CK declarations contributed to apparent protection without proving collection or recent detection | Separate declared, collecting, scoped detection-tested and response-verified stages; stop, replacement, loss, expiry and clock discontinuity withdraw proof. Practice controls do not become real exploit coverage. |
| WIT-01 | Losing witness state before restarting could silently re-enroll an old host head | Explicit create-only initialization and a signed durable enrollment marker make partial loss fail closed across restart. Restoring all witness storage still requires an independent freshness floor. |
| WIT-02 | Closing a witness authority could release its lease while a checkpoint was still committing | Close and checkpoint/save use the same authority lock, and save rechecks lease ownership. A bounded concurrency regression verifies retained ownership. |
| ID-01 | Identity Session Guard lacked dependable local event and browser inventory producers | Opt-in native fixed-provider Windows session events and bounded Chromium manifest metadata. Actual Security-channel reads were denied here and remain a gap; browser inventory returned unverified manifest declarations only. |
| HOST-02 | Ollama listened on every interface and was correctly rejected; local restart stalled during GPU discovery | With explicit computer-only authorization, persisted loopback binding and a strict boolean Vulkan compatibility override. Normal trusted startup and local APIs are ready; actual listener inspection shows only IPv4 loopback. CUDA discovery remains available. |
| SIDE-06 | Reverse-close hid Black Box before closing it, so Qt did not necessarily emit lastWindowClosed after its readers drained | The standalone entry exits on an accepted, fully drained close signal. Hidden-close/native-entry regressions and compatibility tests: 87 passed. The actual updated recorder closed with native exit 0. |
| TST-07 | The observation deadline used QApplication.quit, which the intentional dashboard close-to-tray handler cancels | An inert native Qt reproduction confirms close negotiation, not a module deadlock. The owned test uses Qt.exit on its GUI thread and still runs production cleanup. The repeated two-minute desktop run exited normally, with a 1.27-second maximum measured Qt gap. |
| TST-08 | New collector/witness settings were absent from Full Setup; the new coverage wording broke a stale selfcheck assertion | Complete settings mapping, bounded multiline public-key editing, witness enrollment validation and semantic declaration/proof checks. Fresh selfcheck: 29 phases passed with normal exit; 176 cross-feature and 83 setup/matrix checks passed in their respective groups. |
| EVAL-01 | Labelled replay could be described as held out without checking declared training or fixture overlap | Optional training-cohort comparison rejects exact payload reuse despite renamed IDs/labels, duplicate denominators, incomplete sources and changed package seals. 48 replay/evaluation regressions passed. Independent curation and semantic disjointness remain unproven. |
| WIT-03 | Disabling or changing witness enrollment could resurrect a cached matched receipt as fresh assurance | Shared invalidation covers settings and explicit host-key provisioning, including provider failure before IO. Fresh current witness/UI/guard gate: 75 passed; independent key/enrollment regression: 5 passed. Disabled status cannot inherit old assurance. |
| WIT-04 | A 256-entry witness nonce FIFO evicted still-fresh requests, allowing exact signed replay after capacity pressure | Freshness-bound retention refuses requests at bounded live capacity rather than evicting valid nonces. Capacity/restart/expiry regression and independent signed replay retest passed; head rollback was never observed in the original reproduction. |
| RCV-01 | External recovery verified a logical sparse payload before applying its smaller per-file drill bound | Strict limits precede payload verification in restore and recheck, sparse encodings are rejected, and logical chunks check cancellation. Independent replay reduced pre-rejection hashing from 32 MiB to the 10,405-byte encrypted input only. No live files were restored. |
| RCV-02 | Recovery observation used the global data directory while its workflow used the manager's configured private profile | One configured-profile resolver now serves both paths. Regression finds an imported signed backup without consulting the ambient profile; affected recovery, archive and witness integration gate: 175 passed. |
| PREV-01 | Guidance could imply that requested Windows settings prove runtime enforcement | Exact native Logon audit staging, signed authority and prior-state recovery contracts; HVCI, blocklist, LSA, App Control and Secure Boot remain guided and held. 39 focused checks passed; the real native query was denied and no policy writes occurred. |
| SVC-01 | A protected-directory ACL mask rejected safe read/execute rights while inspecting installed service custody | The reviewed mask now separates mutation from read/execute rights. Native access-mask regressions preserve rejection of generic service execute rights; production service deployment remains unconfigured. |
| PREV-02 | Cancelling a restore before dispatch permanently consumed its original recovery opportunity | Durable cancellation releases only the exact undispatched original link, preserving the cancelled child ID and uncertain dispatched attempts. Independent configure, cancel, newly signed restore replay succeeded with exactly two consumed capabilities. |
| DBG-11 | Stop during native exporter startup could return clean and later leave a dead exporter reporting running; another start could replace its owner | Separate lifecycle ownership, immediate stop signalling, bounded pending status and pre-activation cancellation checks. New barrier regression and 79 affected checks passed; independent held-start replay confirmed no late activation or replaced owner. |
| DBG-12 | A CLI duration limit could end a non-follow snapshot before its declared retained cursor and return success | Duration now applies to follow mode as documented; finite snapshots must reach their declared cursor or report their independent incomplete-snapshot deadline. Controlled-clock regression preserves every retained sequence. |
| TST-09 | Runtime plan source checks omitted transitive custody and cancellation helpers | A bounded manifest now includes the complete first-party Python tree and harness. Changed helpers, added and removed Python files invalidate the plan; 30 harness regressions passed. This remains source-drift evidence, not independent build or dependency attestation. |
| DBG-13 | A deeply nested existing JSONL header could escape CLI error handling with RecursionError | Existing-output inspection now uses the stream's bounded strict decoder for depth, nodes, finite numbers and duplicate keys. Seven new cases passed; malformed local files yield a bounded advisory error. |
| READY-02 | A monotonic clock rollback followed by recovery could resurrect an older detection proof | The invalidation floor retains the previous maximum; new proof is required after a discontinuity. Independent replay now stays at collecting after clock recovery instead of restoring the old verified-response stage. |
| READY-03 | Process Monitor discarded incomplete sensor receipts and reported healthy collection after native enumeration denial | The worker retains typed collection coverage and degrades health for denied, partial and error receipts. Independent real-worker fixtures for denial, failure, partial iteration and unreadable command lines all withhold collecting; the complete control earns collecting. |
| AUTH-02 | Closing the broker released its durable state lease while an admitted handler was still running | Bounded pending-close retains ownership through the handler and receipt write, rejects queued work and retires the lease once. Independent two-phase restart-exclusion replay passed; 146 related tests passed. |
| AUTH-03 | Approval expiry or revocation during durable attempt persistence was not rechecked before dispatch | Final current admission checks run after durable burn. Independent genuine-proof expiry and revocation cases made zero handler calls, retained the spent attempt and rejected retry after restart. Clock regression and closing during burn also block dispatch. |
| AUTH-04 | Trusted principal construction accepted truthy non-boolean enabled values and untyped kind values | Strict ID, PrincipalKind and boolean validation now rejects malformed configuration. 61 authorization/identity/policy checks passed; this is configuration hardening, with no demonstrated remote input path. |
| CLS-02 | Fleet Health Monitor's high-severity unbound-store coverage event lacked an exact health-disposition contract and could score as an active threat | Exact typed unbound coverage now remains HIGH health evidence; genuine custody failures and contradictory attack evidence remain active. 220 Fleet/threat regressions and independent signed-event replay passed. Retained pre-contract records still require review. |
| TST-10 | A legacy recovery-readiness fixture patched `sleep` but ran a worker that now waits on `_wake.wait`, so the full-suite fixture did not terminate | The single-cycle assertion now calls the production observation method directly. All 16 tests in its file passed. The interrupted broad run remains incomplete; a new source-frozen full run with per-test tracing is running. |
| TST-11 | Two fixtures depended on ambient hostname and resilience settings removed by the sealed test harness | Explicit inert hostname and explicit enabled-policy input under a mocked backend preserve each assertion. The two failures were identified in a 177-pass diagnostic run; all 29 affected-file tests passed after correction. Product policy is unchanged. |
| DBG-14 | The independent pytest exit journal retained its file until interpreter finalization and emitted ResourceWarning | The last exit callback writes its final marker then closes its captured stream. Strict warning/order and invalid-descriptor checks preserve native verdicts; all 18 launcher tests passed. |
| CI-01 | Public main's secret-scan flagged a public TPM key-container name as a generic API key | Reviewed checkpoint 787fb43 passes the exact committed CI push-scope scan and real-secret negative controls with default rules retained. Guarded publication passed, including all seven public README images; the actual GitHub secret-scan now passes. The later full ancestry audit completed with three deliberate synthetic-fixture findings, unchanged policy and native exit1; no live credential was identified. Initial partial scans remain preserved. |
| CI-02 | A Windows pipe can close just before its terminating parent reports gone, mislabelling engine exit as heartbeat loss | Published checkpoint 787fb43 reprobes the same authenticated PID/birth for a bounded 250 ms and preserves unknown/reused identity refusal. Its 34 beacon and 103 related checks passed. The actual main-push CI passed all12 jobs (each Python 3.10 to 3.13 matrix run:5795 passed,13 skipped); security passed all3 jobs. Both published checkpoints were fast-forwarded into the broader working tree before the current source freeze. |
| CI-03 | Published cd8e22a failed one existing capacity-boundary test on GitHub Python3.12 | Original CI:11 successful jobs,1 failed; security:3 successful jobs. Test-only repair e1c056c is published with29 focused passes,1 skip and additional budget/tamper controls; production policy is unchanged. Its exact main-push CI passed12/12 jobs and security3/3; each Python3.10-3.13 job passed5890 tests with14 skips. Historical cause is not uniquely proven and the failed run is retained. |
| CI-04 | Published b79209c2 failed the Python 3.10 process-baseline state-integrity test while stopping its worker | The54c8732 test-only repair kept persistence/stop/tamper budgets and passed exact CI 12/Security 3; Python 3.10 through3.13 each 5979/18/native 0. Original b792 cause uncertainty remains. Checkpoint 13 a74’s GUI/Forge failures remain historical despite later focused controls. CI 14’s four Python failures were stale lexical queue-audit matches (TST-30); checkpoint 15 published the25-control test-only correction and passed exact CI 12/Security 3, each Python 6131/18/native 0. Separate frozen root full R10 accepted 7554/0/49. These results do not publish broader1.14 or identify original CI causes. |
| TST-12 | The private full-test driver reused the runtime-only sealed PATH, hiding Git from four inert publication fixtures and skipping developer-tool checks | Correct the private test-toolchain handoff with the machine-installed absolute Git directory while retaining runtime isolation overrides. No product change is needed. Eleven selected Git/Git Bash tests and both exact documentation-checker failures passed in focused native reruns. The frozen broad run retains its original failures and continues. |
| OBS-01 | The observer records a long final persistence stage but updates its loop-gap maximum only at the next iteration, which may never occur after the deadline | A raw-scanner case exited normally but overran the requested interval during observer I/O. Its OBSERVED label is incomplete and must be interpreted with gaps. Terminal work/deadline accounting and the sole advisory heartbeat durability change are applied with 49 passing matrix tests; new runtime observation remains in progress; this does not establish a scanner deadlock or the cause of historical Qt stalls. |
| CLS-03 | App Control collector denial was scored as an active threat | Applied an exact typed unavailable-collector contract; genuine decisions, cursor authentication failures and unexpected errors remain active. Included in 251 passing affected checks; the native provider remains held for bounded-wait review. |
| CLS-04 | Peripheral/DMA observer denial was scored as an active threat | Applied exact typed collection health while preserving device risks and unknown errors as active. Error dedup now distinguishes changed native failure codes. Included in 251 passing affected checks; runtime provider drain remains held. |
| CLS-05 | Authentication-extension collection denial was scored as an active threat | Applied exact typed unavailable-collector health; baseline tampering, contradictory fields and unexpected exceptions remain active. Included in 251 passing affected checks; fixed-local path and cancellation review remain open. |
| GUI-12 | Independent label-based preferences did not guarantee the wider SpywareGuard button after font/style changes | Applied shared-budget width priority. Native 16 window/scale points and 3 immediate font/style transitions passed with containment, non-overlap, reopen/settings and UGCAP gates; host operations were forbidden. |
| SVC-02 | A successful pipe write followed by immediate disconnect can discard an unread response | Deterministic native reproduction confirmed one authenticated callback then lost response. Applied bounded exact-byte nonce/digest receipt, never dispatched or retried;81 affected tests passed with native shutdown. Privileged service remains diagnostic only. |
| PRIV-01 | Username discovery failed in a sealed Windows environment and broke sessions and privacy exports | Published ffb41c4 adds bounded native username fallback for display/redaction, never identity authority. Session collection is independent; IR export refuses before collection/destination creation if no real redaction seed exists. Checkpoint 330 passed,2 platform skips. |
| TST-13 | A connection-snapshot fixture hardcoded11434 while isolated configuration deliberately selected65534 | The product correctly followed its configured port. The fixture now explicitly supplies its inert11434 endpoint; original failure retained and full affected rerun recorded separately. |
| TST-14 | A private focused runner omitted its temporary directory, causing four hardlink fixtures to fall back to another volume | Corrected private directory preparation without weakening runtime hardlink enumeration. Original163-case attempt retained:4 failed,1 skipped; corrected rerun passed 162 tests with 1 skip and native exit0. The full-suite driver already prepared its private temporary path. |
| TST-15 | Refreshed selfchecks exceeded module deadlines or refused an unproved fresh Process observation | Latest actual module selfcheck at a74/1852 passed29 phases/native0 in31.485s, reconciling86 module rows (68PASS18SKIP), separate pipeline and9 verifiers. Both native generations retired/four handles closed/MainThread/no QApplication. Earlier failures and29.265s remain historical; this is not fullR8, a benchmark or R7 cause proof. |
| TST-16 | A startup-response fixture assumed the expiration counter guaranteed completed diagnostic publication | A controlled barrier reproduced the legitimate intermediate state, then verified one response-inert diagnostic after publication. Corrected fixture and barrier are applied and included in366 passing focused checks. Production response code is unchanged. |
| TST-17 | The repeated GUI campaign could not prove a later Process Monitor cycle before launch admission closed | Latest full R7 failed only the second GUI launch: fresh Process Monitor proof refused after 6.579 seconds, stage retry/waiting true, no red-team report run. First launch passed 37/37 signed simulated-response contracts plus OS witness; case-process evidence was time-correlated, not independently attested. Cause unknown. Earlier GUI r6 and R6c passes remain historical. Test-only capture is applied; one focused test/two actual GUI launches passed with exact retirement as a nonreproduction, but the failure-only branch was not exercised and cause/capture gap remain open; no health/readiness/pacing/deadline override or causal repair is claimed. Later frozen full R10 passed the same two-launch GUI call (122.2837177 seconds) and all 7603 cases had zero failures. Historical R7 pacing/last refusal/cause and the unexercised failure-capture branch remain unresolved; elapsed time is not a benchmark. |
| TST-18 | UGCAP's slow-operation worker fixture failed during protected-channel startup | Startup preparation and bounded diagnostics are applied; strict authentication, expiry and deadlines remain. Private R7's 135 passes and two unexplained failures remain recorded. Private R8 and the subsequent main-tree gate each passed all 137 selected tests with native exit 0; the latter retained 1,190 unchanged inputs and actual kernel retirement. The earlier failures were not reproduced or causally explained. |
| TST-19 | Fresh GUI acceptance could not complete its first rich Process Monitor collection within readiness admission | Cold diagnosis demonstrated repeated whole-system parent maps. Applied one-map/fresh-identity collection passed419 focused tests, then the actual two-launch GUI check passed with native exit0 and1180 unchanged inputs. Original initial-readiness native1 is retained. Protected identity fields remain unknown; timings are not a controlled throughput benchmark. |
| TST-20 | UGCAP cleanup credited job-zero and launcher exit before the actual child process handle became signaled | The original native probe confirmed premature retirement credit. Applied bounded member witnesses now require signaled kernel handles plus job, process and I/O completion. Root acceptance passed 137 tests, no skips, normal native exit 0 and 1,190 unchanged inputs. Private R7's two functional failures remain historical; no lasting orphan or continued application-code execution was established by the original probe. |
| TST-21 | Private native gate crashed after writing passing JUnit records | The original 0xC0000005 remains open. Both A/B arms exited 0, but the timer never fired. Auth custody passed separate native/main-tree gates. Official matching Python PDB metadata was validated; offline DbgHelp stopped before parsing because its no-network option could not round-trip. One approved offline pure-Python decoder also stopped before procedure parsing on an unsupported debug header. No symbol function or initiating cause is claimed. R6c retired normally with assertion exit1 and did not repeat C0; the original cause stays open. R7 also retired normally without this error recurring; historical cause remains open. |
| TST-22 | An accepted fresh Process observation request was cleared before collection and lost when the result was refused | Source-confirmed repair retains the latest refused request for a fresh read at the next normal poll; newer requests and stop/restart revoke older credit. Reviewed patch `aa432db7eb4bb6593d9c13ee71550a5f7e5f568153d16df4078f2f1e0ef15a12` passed 42 private supplied-inventory tests and 163 main-tree tests, with normal native retirement. Subsequent uninstrumented root selfcheck r4 passed 29/29 with 1,192 unchanged inputs and MainThread-only atexit. The historical r3 failure remains unattributed. |
| TST-23 | A native call holding the GIL can delay startup/coordination beyond the requested deadline and still receive a successful self-test result | Applied accounting passed 12 private controls and 88 main-tree tests. The initial warning is retained; two subsequent 12-case native-fixture gates each passed without warnings, with native exit 0 and 1,191 unchanged inputs. Thread ownership precedes startup; read-only closure review confirmed join-before-rebind and monkeypatch restoration. These gates used b8ca8f; current e9cc6ee7 adds separate robustness repairs while preserving deadline decisions. Root selfcheck r4 passed 29/29 on the earlier revision. Native work is not preempted and no historical YARA cause is established. The core repair is published in narrow checkpoint b10e0f0; broader validation remains held. |
| TST-24 | Formatting an unrenderable callback exception can leave the bounded-call API reporting success without a value or error, hiding a notification failure | Source review confirmed this predates the deadline correction. Applied failure-marker handling preserves a failure even when exception formatting raises. Private 76-case and main-tree 110-case gates passed with native exit 0, unchanged inputs and MainThread-only atexit. Fresh revised-source selfcheck r5 passed 29/29 with 1,193 unchanged inputs and the same clean retirement. No observed host incident or historical YARA cause is attributed. The core repair is published in narrow checkpoint b10e0f0; broader validation remains held. |
| TST-25 | Event or Thread construction after capacity acquisition can raise before the start guard and leak a worker permit | Source review confirmed this predates the deadline correction. Applied pre-start cleanup returns exactly the acquired capacity and rethrows construction failures, including controlled BaseException cases. Private 76-case and main-tree 110-case gates plus fresh root selfcheck r5 (29/29) passed; existing start-interruption uncertainty, worker-owned release and concurrency caps remain. The core repair is published in narrow checkpoint b10e0f0; broader validation remains held. |
| TST-26 | A module-admission test retained its own Enclave manager without calling stop_all, leaving a rotation thread at normal atexit | The original 71-test main-tree gate remains recorded with EnclaveMesh-rotate. A test-only owner cleanup preserved all assertions and other top-level nodes; repeated 71 tests passed without warnings, with native exit 0, 1,192 unchanged inputs, actual kernel retirement and MainThread-only atexit. No production Enclave lifecycle defect is inferred. |
| TST-27 | The two-launch GUI fixture omitted both pulse.shutdown and joining its actual sampler, leaving SystemPulseSampler at r3 atexit | Applied fixture cleanup passed both actual r4 launches with native exit 0, 1,193 unchanged inputs, actual kernel retirement and MainThread-only atexit. The r3 thread record is retained. This proves fixture retirement; production repair and its wider failed acceptance remain tracked separately under GUI-15. Public five-case assertions later passed but the gate rejected Pulse/FI ownership residue. Selected18 now retires MainThread only after public FI/fixture repair; original failed acceptance is retained, no post-exit orphan is claimed. |
| TST-28 | Shared GUI AAR/run aliases and PID-based trace names can overwrite another case's evidence | Applied case-local diagnostics passed r4's two launches while all four prior shared aliases stayed byte-identical. Each launch verified 37/37 simulation responses, 36 source removals/hash matches, three process witnesses and no modals; native analytics remained 0/37. Archived r3 has 18 matching files; r2 has 14, with four overwritten old aliases unavailable. No historical reconstruction or native analytic efficacy is claimed. |
| DET-01 | The generic -ma/lsass semantic matcher also matched --max-cases and a case label | Reviewed raw-argument boundary is applied and included in366 passing focused checks, with 23 new regressions and five weak-response negative controls. Later frozen full R10 passed with this correction present. Narrative-token ambiguity remains; earlier notices still lack ancestry proof and receive no blanket exemption. |
| DOC-01 | Current manual Chapter1.1 still described the older84-capability inventory | Updated current reference and routing to the exported86=13 native declarations+73 adapters; dated historical validation remains unchanged. Generator is idempotent; all 54 rendered pages and the full current-reference page were inspected without clipping. |
| AUTH-05 | R6-03 lacked retained native process custody across Windows termination | Published ffb41c4 retains a least-rights native handle through intent, exact dispatch/wait and signed terminal verification. No PID fallback. Suspend/resume/undo, executable-file custody and persistent pathname firewall lifetime remain open. |
| OBS-02 | Final-only health discarded a sampled C2 degradation after recovery | Bounded interval summaries now retain completed-cycle gaps, minimum health, liveness, loss and crash evidence. Startup warming remains separate. All58 matrix checks passed; two600-second cases now complete with native exit0 and retained provider/timing gaps. Historical pair evidence retains its sampled 65-health gap and unknown cause. |
| OBS-03 | Recursive private-path discovery left native diagnostic readers running after their limited-output shell pipelines returned exit 0 | All three exact owned readers were retired using matched command arguments and retained process handles with creation-time checks. Bounded source/path discovery guidance is applied. Shell pipeline completion is not native-child retirement proof. This is a diagnostic workflow issue, with no application defect or historical failure/timing attribution established. Separate external RealTime-priority configuration risk is recorded with zero observed CPU deltas/no starvation proof; normalization remains held for OS permissions and unproven action ownership, without historical attribution. |
| OPS-01 | cleanup.ps1 recursively deletes workspace databases, logs and diagnostic artifacts that may be forensic evidence | Preserving c2d6 is applied and public in narrow checkpoint 12 after actual PS5/PS7 and permanent 28-case acceptance. CI passed 12/12 and Security 3/3; each Python run passed 6,049 with 18 skips/native 0. Historical source 947 invocation was not observed or linked to external Temp loss. Earlier PS5 harness-module-path failure and child-only correction remain retained. |
| UPD-01 | Original Settings called the network updater synchronously and discarded its returned status | Reviewed R6 controller/source is applied in 20 files with settings unchanged. Private focused successor passed 83 with one optional skip/native 0, including cancellation before Git/network and 30 CLI cases; R5's 330/3/2 failure is retained. Root R3 accepted 179 passes/one optional skip/native 0 plus uninstrumented selfcheck 29/0/native 0. R2's recorder acceptance failure (ExitCode serialized null) is retained. This is focused acceptance, without public daily-feature publication. |
| UPD-02 | Daily checks and preserving source staging lack an accepted activation/release-authority workflow | R6 source is applied and focused main-tree validation passed; daily networking stays OFF unless selected and runtime settings were unchanged. Private controls passed both junction tests and 30 CLI cases. Root 179/1 and selfcheck 29 accepted, but activation ALWAYS HELD. HTTPS/source SHA is not release authority, CRLF may conflict. No daily feature publication. R5's failed gate is retained; earlier private candidate bundles R1–R4 remained unexecuted. |
| RED-01 | Twenty-two validation refusal conditions shared one generic producer-liveness message | Added typed first-refusal diagnostics while preserving predicate order and authority. A fresh 80-step signed campaign completed; 76 simulation validations/responses verified, native analytic detections 0/76. The historical incomplete campaign's cause remains unknown. |
| GUI-13 | A second showEvent definition overrode Threat Intelligence refresh-timer restart | Removed the overriding duplicate and restored the single refresh timer after hide/show. Independently reviewed and applied; all18 focused checks pass with normal native exit. |
| GUI-14 | The Flight Instructor daemon has no terminal queue path and retains its bound MainWindow | Applied repair passed private R3 25/25 and 71 main-tree tests, retaining private R2's 24/25 minimal-fixture failure. The first main-tree gate retained an unrelated test-owned EnclaveMesh-rotate. After test-only owner cleanup, repeated 71 tests passed without warnings, with native exit 0, 1,192 unchanged inputs and MainThread-only atexit, as did root selfcheck r4 (29/29). No fully constructed window defect, production Enclave leak or historical crash cause is inferred. Separate public GUI gate passed 5 assertions/native0 but acceptance rejected retained Pulse/FI workers. Public FI backport and fixture cleanup then passed 18 selected tests with MainThread-only retirement; The selected public repair is now published in checkpoint 14 (943fb9a). Its new CI failures are a separate stale lexical audit, not a retirement failure. Original CI310 response cause is not closed. |
| GUI-15 | The production SystemPulse worker retains its Qt card and lacks complete quit/destroy cancellation, leaving a check-to-emit lifetime race | Applied 6d7100 plus 27 controls and three fixture adaptations after fresh uninstrumented private R4 passed 74 cases with native 0, complete phases and normal cleanup. Original watchdog/framing gaps and private R3's 72/2 remain unattributed. Root combined gate failed 142/2 despite all 27 new Pulse cases passing. Later instrumented 144-pass/four-witness diagnostics grant no acceptance or causal closure; two legacy timer assertions remain under investigation. Both calls passed in R6c; this is nonreproduction, not historical-cause closure. R7 also retired normally without this error recurring; historical cause remains open. |
| GUI-16 | AsyncSnapshot.request does not recheck closed/paused state after prepare and updating-status callbacks, allowing synchronous owner disposal before worker creation or timer access | Applied exact two guards as 60bef with eight controls: original six typed failures/two passes/native 1 versus candidate eight passes/native 0, with exact cleanup/provenance. All eight new cases also passed in the failed 142/2 root combined gate. The worker stays detached with no Qt emission; read cancellation remains cooperative and close does not prove retirement. No native crash cause or full acceptance is claimed. |
| PER-05 | Distinct CVE detail requests could create unbounded concurrent analysis workers | Applied a shared two-active-analysis, zero-waiting-queue coordinator with Qt-owned worker retirement and valid late callbacks; all18 focused checks pass. Native TLS cleanup remains outside its physical-thread bound, and whole-application shutdown is not proven by this change. |
| SEC-05 | Kernel Posture Ledger uses unqualified inbox executable names | Absolute trusted-directory paths and missing-tool refusal are applied and included in366 focused passes. They grant no whole-provider deadline or runtime admission; provider remains held. |
| SEC-08 | Engine control could admit or start queued work after shutdown won, or report ready after stopping | Admission, running transition and start/close share the existing lock; stopped readiness is refused. Published in reviewed checkpoint b89c5356; included in419 root focused passes. All12 exact CI and3 Security jobs passed. In-flight operations finish; unstarted receipts remain queued on a closed engine, without fabricated cancellation/success. |
| SEC-09 | Metadata-only directory handles were assumed to enforce sharing restrictions against ancestor rename | Reviewed read and atomic-writer guards now use sharing-relevant directory-list access with no delete sharing. Compatible nested writes and sealed-leaf refusal passed; the two original initrd assertions now pass unchanged. Private337-pass and main-tree563-pass gates exited natively0. Listing denial stays explicit; original failures are retained. |
| SEC-06 | Authentication component drive syntax does not establish fixed-local or no-reparse access before stat/open | Authentication-component custody is applied and included in563 main-tree passes. Fixed-local validation precedes filesystem access; bounded no-reparse ancestry stays held through byte hashing/probes. Four owned native cases passed. The whole provider remains held for offline signature/cancellation/budget review; no mapped-drive or remote test was performed. |
| SEC-07 | Driver signature validation does not prove offline retrieval | No transfer was observed. Cache-only signature policy and fixed-local component custody remain unproven; provider remains held from the no-egress runtime lane. |
| PER-06 | Kernel ledger parses unbounded file bytes before enforcing record count | Bounded held reads and lazy parsing are applied and included in366 focused passes. Strict UTF-8, original Windows writer bytes and signed timestamps are preserved. Superseded newline/encoding/allocation regressions were rejected. No hostile live file was used; provider admission remains held. |
| PER-07 | App Control EvtNext uses its infinite default without a cancellation owner | Reviewed commit5523293 is published through6fb7f929 and integrated locally, with a500ms read bound. Its native/contract checks and actual GitHub matrix passed. Exhaustion and timeout remain distinct; whole-provider deadline/cancellation and active-runtime admission remain unproven. |
| PER-09 | Idle engine shutdown waited for the half-second queue poll | An identity-only stop marker wakes the owned queue without executing a command, changing poll/join limits or evicting accepted requests. Published in reviewed checkpoint b89c5356; included in419 root focused passes. All12 exact CI and3 Security jobs passed; an in-flight operation can still require the existing bounded wait. |
| PER-10 | Release syntax validation launched a separate PowerShell process for each of13 inert sources | Each source is parsed independently in one child with exact indexed results and mismatch/error refusal. Published in reviewed checkpoint b89c5356; included in419 root focused passes. All12 exact CI and3 Security jobs passed; native side-effect and single-source controls passed. Earlier failed private collection semantics are retained. No controlled whole-suite speedup claimed. |
| PER-08 | Several read-only provider timeouts exceed the matrix's 15-second worker drain | Driver, Platform, Peripheral, Kernel and Authentication providers remain held. Native timeout totals and cooperative cancellation do not establish a hard shutdown deadline. |
| TST-29 | Two recorder-negative fixtures fail earlier cold-producer admission instead of their intended recorder refusal | Full R6c failed both recorder negatives at earlier fresh 13-contract admission within 0.2 seconds; the smaller original baseline reproduced the first while the instance-spoof case passed. Stage-specific test-only correction is included in 73 accepted selected cases/native 0 with strict retirement. No production transport/deadline change or unique historical timing cause is claimed. Both previously failing R6c nodes passed R7; R7 failed a separate GUI launch assertion, and the historical result remains. A later cadence cohort failed 121/1 when another recorder-negative fixture reached real host Process coverage refusal first; production failed closed correctly. A test-only recorder fixture then passed122 selected cases/native0 with unchanged production/health/coverage rules; the original physical collection gap remains unresolved. |
| TST-30 | Lexical unguarded-requests audit mistakes self._requests.get() queue access for requests.get networking | Original full R6c/selected 53/3 failed a lexical audit on queue.Queue access, not a new HTTP call. Root’s AST test-only correction passed 73 selected cases and its node passed R7/full R10. The old public test failed all four CI 14 Python jobs6113/1/18. Public AST successor with 17 added controls passed 25, published as checkpoint 15/e715, then exact CI 12/Security 3 passed with all four Python 6131/18/native 0. Original failed runs remain retained; no production-networking change or historical-cause closure follows. |
| TST-31 | Per-row CVE analysis admission returned None in the owned-worker lifecycle test | Full and original selected baseline failed CVE worker admission. Source/test-order evidence identified a real global aboutToQuit emission closing an already-created shared coordinator. Scoped signal and nonintrusive identity/QThread cleanup corrections passed 73 selected cases/native 0; production shutdown is unchanged. The original full result remains. The previously failing R6c node passed R7; R7 failed a separate GUI launch assertion, and the historical result remains. |
| TST-32 | Restored-mtime YARA edit returned scanned but produced no event in the test bus | Full R6c used actual yara_x and retained the exact 55-byte marker; scanned also labels cache hits. Original-product deterministic controls failed all 17 new cases while 66 existing cases passed, including the original restored-mtime test. Applied one-file per-file-USN/no-cache repair passed the identical 83 cases, and fresh module selfcheck passed 29 phases with clean retirement. The controlled timestamp-only weakness is proven; the original failed full-run branch remains unobserved. No sleep workaround, benchmark or complete regression is claimed. The previously failing R6c node passed R7; R7 failed a separate GUI launch assertion, and the historical result remains. |
| PER-11 | Black Box repeatedly requests cap-sized status bytes and reads historical self-test failures without a byte bound | Applied two-file bounded status/history reads passed 136 selected cases/no skips/native 0, stable inputs and exact retirement. At most 64 KiB requests retain 4 MiB caps plus sentinel, partial-fault refusal, both schemas and informational gaps. Exactly 501 rows preserve 500 history plus one fresh live failure; report bytes/mtime stay unchanged and the original code backup remains. Namespace is 1,850, Python inventory 1,147; only the two changed files received fresh AST/Ruff checks. No throughput benchmark, new module selfcheck or complete regression is claimed. The later frozen full R10 passed 7554/0/49 with this repair present; that is regression coverage, not a throughput benchmark. |
| PER-12 | Discretionary background pacing can consume a fresh Process observation lease before a retained retry | A supplied factor-8/one-second-base control exhausted the unchanged eight-second lease on original code, then passed after a two-file one-token retry credit. All 12 new controls passed. The cohort's original 121/1 failed at a genuine host-coverage prerequisite; test-only recorder confinement then passed 122/no skips/native 0 with exact retirement. Only discretionary background addition is omitted; mandatory cadence/throttle/Chill/health/deadlines/coalesced wakes remain. R7 factor/last refusal/cause stay unknown; no total wakeup bound, token-expiry contract, benchmark or complete regression claimed. Later frozen full R10 passed 7554/0/49 with the source repair present; no historical R7 cause or performance claim follows. |
| UPD-03 | Packaged installer cleanup can discard previous payload backups after a failed restoration | Original source could discard previous payload after failed restoration; no observed host data-loss incident was attributed. Reviewed preservation source passed 27 confined controls within accepted 141, native 0 with exact retirement. Twenty-one actual PS5.1 child receipts were reviewed:19 normal0/two intentional abrupt99, all process/stdio handles closed/no gaps; six inert failure controls are not physical-process proof. Earlier R3/R4/R5 plans remain historical. Durable crash reconciliation, forward file-object leases, administrator/ACL/disk-full races, restart health and trusted activation/signing remain open. Source-stage activation is separate. |
| TST-33 | Foreign Qt-thread identity observation leaves a Dummy bookkeeping object in a rejected gate journal | The first selected successor passed 73 assertions/native 0 but acceptance rejected MainThread+Dummy-2. CPython foreign-thread Dummy bookkeeping and actual QThread.wait do not prove a live OS thread or leak. The applied identity-observer correction passed 73/native 0 with MainThread-only retirement under unchanged strict criteria; the original rejected journal remains, without filtering. |
| GUI-17 | External plain summaries can become Qt tooltip markup after entity decoding | Original Qt baseline passed one canary and failed six formatting controls: four image-format interpretations and two entity-text redecodes. Six external tooltip sinks now escape literal text through trusted Qt wrapping. All seven controls passed in the accepted 141-case installer/page/news/release/authority gate, native 0 with exact clean retirement. Runtime HTTP/file/script execution or response/trust authority was not proved. Full R10 predates this correction; its coverage is separate. |
| TST-34 | Hidden-child no-run refusal occurs after resolving a nonexistent venv interpreter | All four c3 hosted Python jobs failed the same hidden-child refusal test. Source ordering reached strict interpreter resolution before the explicit no-run guard. The applied guard now rejects the hidden child before runtime preparation; explicit missing-venv controls retain that boundary. The eight-file ROOT successor passed 238 controls/no skips/native 0 and a fresh default 29-phase selfcheck, with unchanged inputs and exact retirement. This scoped result does not replace the original c3 failures or establish a new hosted-matrix pass. |
| AUTH-06 | Fresh response-session files can receive a Windows default owner that fails strict token-user custody | Four safe-response-session tests failed in every c3 hosted Python job. The source repair creates new private files through the existing strict creator with token-user ownership; owner verification is not relaxed. The legacy saved-label fixture now uses the same strict private-file creation while its labels remain history without execution authority. The eight-file ROOT successor passed 238 controls/no skips/native 0 and a fresh default 29-phase selfcheck, including the authority and revocation boundaries, with exact retirement. No host-compromise incident or later hosted-CI success is inferred. |
| TST-35 | Witness integration fixture uses ordinary writes for files governed by strict private custody; original Python 3.13 drip startup cause is unknown | The c3 witness test failed on all four hosted Python versions. Python 3.10–3.12 retained an owner rejection for an ordinarily written fixture public key; fixture public keys, certificates and CA material now use strict private creation. Python 3.13 instead lacked the header-drip started event and its underlying OSError was not recorded, so that original startup cause remains unknown. The focused ROOT successor passed 238 controls/no skips/native 0 and a fresh default 29-phase selfcheck with exact retirement. Later fixture acceptance does not causally explain or overwrite the original Python 3.13 failure, deploy an independent witness, or prove a new hosted-matrix pass. |
| TST-36 | Strict TLS verification rejects the witness fixture certificate for a missing Authority Key Identifier | Published 434 failed the witness test on Python 3.13 with an explicit Missing Authority Key Identifier error. The fixture now supplies CA Subject Key Identifier/critical Key Usage and leaf Authority Key Identifiers, with strict verification explicitly enabled on every supported Python version. The applied fixture passed 40 local Python 3.12 controls with strict verification. The joint changed-source gate then passed 71 controls/no skips/native 0 and a fresh default 29-phase selfcheck, with unchanged inputs and exact retirement. These scoped results do not establish a later hosted 3.13 pass or explain c3’s older swallowed startup failure, whose cause stays unknown. |
| TST-37 | Release-fixture timeout handling discards output from the initial confinement preflight | Published 434 Python 3.13 retained 27 setup errors cascading from one 45-second confinement-paths PowerShell timeout. After the primary failure, stdout/stderr reads were skipped and temporary streams closed, leaving the original output unavailable. A later cleanup return code 1 is not the primary timeout cause. The applied helper captures failure-only bounded 2 KiB tails with explicit truncation/read faults, advisory stage and native phase/elapsed/retirement details, preserving the primary error, 45-second wait and 10-second cleanup; no retries, skips or product-installer changes. The joint gate passed 71 controls and a fresh default 29-phase selfcheck with exact retirement. A separate audit proved 21 unique real PowerShell generations retired with handles/stdio closed: 19 expected exit 0 and two intentional exit 99. Ten inert controls remain separate, including all four new cases; seven retained mock receipts are not native-process proof. Original timeout cause remains unknown after this nonreproduction, no product-installer defect is proved, and new markers are not retroactive causal evidence. |
| PER-13 | Sigma runtime reconstructs immutable field and condition decisions for each active and shadow evaluation | Applied per-binding immutable runtime plans retain genuine per-event digest/canonical verification, unchanged public matching/evaluation and unchanged grammar/admission. The 17-file ROOT gate passed 255 tests with one POSIX-fork platform skip, followed by a fresh 29-phase selfcheck with exact retirement. A separate accepted synthetic direct-call benchmark recorded 108 rows/188928 genuine verified evaluations and full vector/hit parity; median wall time was 31.8425–42.7175% lower across nine cases. CPU samples are 15.625ms-quantized and zero samples are not zero cost. No GUI, end-to-end sensor or whole-product speed improvement is established. |
| PER-14 | Exporters perform separate durable enqueue commits for a cohort that can share one atomic transaction | Applied exporters use at most 100 items per atomic FULL commit before cursor advancement. Canonical payload limits are 256KiB each/25MiB total, not a RAM bound. Fallback is restricted to OutboxFull; authorization, conflict and commit failures do not enter that fallback. Existing single enqueue, acknowledgement and transport contracts remain. The 17-file ROOT gate passed 255 tests with one POSIX-fork skip and a fresh 29-phase selfcheck, with exact retirement. The batch contract compares three single COMMITs with one batch COMMIT; it is not elapsed-time, throughput or abrupt-power-loss evidence. |
| TST-38 | Private pair-observation state and fallible identity sidecar handling can leave core lifetime evidence unadmitted | R5 aborted after 0.578 seconds with ambiguous private-read/sidecar EngineError and missing historical core native retirement proof. A private observer successor creates protected run state, retains the core handle before fallible sidecar work and records nonraising stage diagnostics. R7 observed the earlier 1854/fabb snapshot for 90.204 seconds with 347 repeated status/heartbeat views and 18 scheduled cycles per module, not 18 full persistence scans. Core and both outer generations retired/exit 0; four outer handles and the retained core query handle closed. Original launcher Popen closure is not claimed. Coverage gaps and five response-ineligible events remain; no confirmed spyware or supported false positive was adjudicated. R7 is a nonreproduction, not R5 causal closure or live proof of the later 1856 revision; this is diagnostic-harness evidence, not a product protection upgrade. |
| SCN-04 | Historical R7 Run-view alias remains unadjudicated; independent source review confirms repeated reads of shared HKCU Run/RunOnce keys | Read shared user keys once while retaining separate HKLM views and coverage gaps; initial 214 controls passed. Later four-target reads match R7 commands but do not prove historical identity or benignity; their supervisor gate failed. No finding suppression. |
| GUI-18 | Same-CVE inputs or reversed batch/detail completions can reuse stale analysis; unknown worker state could bypass close deferral | Full-row/request identity, indexed matching rows, conservative valid-worker lifetime and startup cleanup passed in the initial 214-test cohort; default 29 also passed. |
| UPD-04 | An interrupted conflict resolution can leave candidate bytes without a committed resolution index | Same-choice reconciliation and POSIX pre-stream descriptor checks passed the final 54-test follow-up and default 29; changed/unowned states stay held. Process interruption only; no power-loss or universal device deadline. |
| TST-39 | Floating-point JSON review can round 64-bit native clock or generation values | Preserve exact integer lexemes/decimal strings before parsing; originals stay untouched and corrections remain advisory. No new observation or clock-stability proof. |


## Testing loop

The native pipe response-loss reproduction matches Microsoft's documented
[disconnect behavior](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-disconnectnamedpipe):
unread bytes can be discarded when the server disconnects. The fix uses a
bounded connection receipt; it avoids the unbounded peer-read dependency of
[synchronous pipe flushing](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers).
That receipt proves neither execution authorization nor a host postcondition.

1. Enable live sharing explicitly, identify the process and connect the local
   reader. Preserve the run identifier, sequence, original signature metadata,
   integrity result and coverage notices.
2. Classify the observation as confirmed threat, false positive, health,
   exposure or unresolved. Record the evidence and reasoning. A reviewer label
   grants no response or trust authority.
3. Reproduce the software defect in disposable data. Correct its cause and
   independently check valid attacks that the change must still detect.
4. Run relevant regressions, native lifecycle/security checks, bounded-load
   measurements and the offline application selfcheck. Review the exact diff.
5. Publish the completed reviewed commit through the guarded publisher. Restart
   the application to load source changes; an enrolled integrity baseline must
   account for intentional edits explicitly. Required independent witness
   enrollment/reconciliation must also account for changed vault/baseline
   identities without deleting state or resetting its head. Reconnect and
   inspect new evidence.

An empty stream is not a clean-host attestation. Missing readers, inaccessible
logs, dropped events, expired process identity and incomplete collectors remain
visible gaps. The read-only connection cannot execute source patches or security
commands. Actual response stays in Angerona's existing governed workflow.

## Performance evidence

`tools/benchmark_live_debug.py` publishes inert Self-Test records on a fresh
private EventBus without starting scanners or response modules. It measures
publisher cost, export delay, bounded-history reads, burst loss and shutdown.
Results describe the measured workload under host contention; they do not
promise lossless production capture. Overflow must produce explicit gap records.

The [recorded benchmark](benchmark-under-validation-load.json) ran alongside
offline regression validation. Its paced workload delivered all 1,000 records
with zero queue drops in 2.65 seconds (about 378 events/second, below the nominal
500/second sleep target). Publisher p95 was 250 microseconds and export p95 was
1.02 ms. Median export delay rounded to zero at the event clock's resolution;
this is not a sub-millisecond guarantee. A 5,000-event burst overflowed the
512-entry ingress queue by 2,602 records, reported explicitly. A 100-record
history read took 1.64 ms median; shutdown took 45.4 ms in that run.

The scanner remains a separate raw forwarder: merging it into the GUI would
remove an independent failure domain. Rich process/network facts already share
coalesced snapshots. The review found no measured justification for adding more
continuous scanners or collapsing unrelated security modules.

A later stable-source control/all-14 attribution repeat exited normally with
no reported drops or errors and maximum worker-loop gaps of **1.109 / 1.312
seconds**. Its own diagnostic heartbeat persistence measured maxima of **0.852 /
1.036 seconds**; cached module views stayed below 5 ms and capture draining
below 50 ms. The maxima need not belong to the same iteration and cannot be
subtracted to attribute a residual stall. This does not establish the cause of
the earlier 3.50-second observer gap or historical native Qt delays.

All-14 used **7.796875 CPU seconds in 60.188 seconds**, about **13% of one
logical CPU**, and roughly **9.34 MiB** more end-of-run RSS than control.
This is combined process cost, not whole-machine utilization or per-module
attribution. Eight permission/provider/preview health gaps remained. The
15-case serial scanner/solo run later completed alongside the frozen-tree full
suite attempt; concurrent validation load is part of that observation's scope.

Fresh digest verification deliberately costs fresh I/O. Warm-filesystem medians
in the review were approximately 5.4 ms for 1 MiB, 30.6 ms for 8 MiB and 157.3 ms
for 32 MiB. These are workload observations, not latency guarantees. A cooperative
read deadline cannot preempt a stalled kernel operation. Reusing mutable file
metadata as content authorization is not an acceptable performance shortcut.

Final release validation remains in progress. The complete frozen r4 run ended
with **6,501 passed /17 failed /40 skipped**, native exit1 and all1,160 inputs
unchanged. Its failed families subsequently passed a focused rerun of162 tests
with1 skip; the original failures remain recorded. The next complete run ended
with **6,808 passed /3 failed /34 skipped** across6,845 collected tests, native
exit1 and normal Python shutdown. All1,172 frozen source/test/tool/release inputs
stayed unchanged. The live call counter omitted8 setup skips; JUnit supplies
the complete totals. Verified Git was an explicit repository-test dependency.
The three failures concern diagnostic publication ordering, second-launch
Process Monitor readiness and UGCAP worker startup; focused corrections and
mechanism investigations are recorded individually above.

Historical frozen full R7 is **FAILED: 7,489 passed /1 failed /49 skipped** across
7,539 cases, native exit 1 (2,102.437 seconds outer/2,070.418 JUnit). Root,
HEAD/index, runtime and harness stayed stable. Both exact native generations
reached WAIT0/native 1, all four handles closed, and normal atexit was
MainThread/no QApplication/zero widgets. No timeout or supervisor failure was
recorded. Its sole failure was the second GUI launch: fresh Process Monitor
proof was refused after 6.579 seconds with worker stage retry/waiting true,
and no red-team report run was created. The first launch passed 37/37 signed
simulated-response contracts plus OS witness; this is not native detection
efficacy. The time-correlated case-process evidence was not independently
attested. The cause remains unknown. The applied test-only diagnostic passed a
focused two-launch GUI test (135.078 seconds outer/129.119 JUnit, native 0),
with stable root/HEAD/index/runtime/harness, both exact generations retired,
four handles closed and MainThread/no QApplication/zero widgets. It is a scoped
nonreproduction: the failure-only capture branch did not run. The original gap
and cause remain open; no health/readiness/pacing/deadline override follows. All five R6c failing nodes passed in R7, with the original failed
results retained. Exact retirement does not make the failed gate accepted.

Historical frozen full R6c is **FAILED: 7,451 passed /5 failed /49 skipped** across
7,505 cases, native exit 1 (2,111.578 seconds outer/2,096.325 JUnit). Root,
HEAD/index, runtime and harness stayed stable. Both exact native generations
reached WAIT0/native 1, all four handles closed, and normal atexit was
MainThread/no QApplication/zero widgets. No timeout or supervisor failure was
recorded. The 49 skips comprise 22 setup/27 call skips. Clean retirement is not
acceptance of failed assertions.

Two recorder-negative fixtures failed earlier cold admission; the lexical
network audit matched queue access, the CVE worker returned None, and the
restored-mtime YARA scan produced no bus event (TST-29 through TST-32). The
smaller original five-file baseline failed 53/3; its second Purple negative
passed. Four test-only corrections passed 73 selected checks/native 0 with
unchanged strict thread criteria and MainThread-only retirement. The first
73-pass/native 0 successor remains rejected because its atexit journal retained
a foreign-thread Dummy bookkeeping object. That alone does not prove a live
OS thread or leak (TST-33); the later correction passed without filtering the
original journal. Separately, 17 deterministic YARA controls failed against the
original product (66 passes/17 failures). After a one-file per-file-USN/no-cache
repair, the identical 83-case gate passed. The original restored-mtime test
passed in that baseline, so its full-run cache branch remains unobserved.
Those focused corrections remain accepted, but full R7 failed a separate GUI launch assertion.

Authentic-venv preflight passed 29 PYTEST prerequisite cases across four files;
it was not the 29-phase module selfcheck. Both formerly failing Pulse calls and
the two-launch GUI call passed in R6c; the GUI call took 124.2396095 seconds plus
teardown. No performance or historical-cause closure follows. C0 did not recur,
but its original cause, earlier 142/2 timer causes and unavailable symbol/evidence
artifacts remain open. No whole 1.14 release is accepted.

The original refreshed selfcheck ended normally with native exit 1: **27/29
phases passed**, three module calls exceeded their 12-second deadlines, and
two later checks could not start because unfinished calls occupied bounded
capacity. Its 1,172 inputs stayed unchanged; attribution remains open. A later
r2 invocation passed **29/29 phases**, reconciled 86 modules, passed eight
controlled verification canaries and report readback, retired Qt owners, and
exited normally with all 1,179 inputs unchanged. That passing run remains
historical evidence.

The earlier r3 selfcheck passed **27/29 phases** in **87.469 seconds**, with
normal native exit 1, actual kernel retirement and **1,187 unchanged inputs**.
YARA's self-test exceeded its 12-second deadline (12,740 ms measured); Red Team
LIVE refused a fresh Process observation with health 70, cycle 4, baseline 1,
generation 1 and incomplete request evidence. All eight controlled verification
canaries and report reconciliation passed. The raw module-results summary
includes a separate pipeline verification row; it is not an extra module.
Neither failure has an established historical cause. The later applied Process
retry repair passed 163 supplied-inventory tests. A later uninstrumented r4
passed 29/29; that does not identify the cause of the earlier failures.
Offline checks do not establish active coverage or
native detection efficacy.

Latest actual uninstrumented main-tree module selfcheck **passed 29/29 phases**
in **31.485 seconds**, after the YARA USN repair. Native exit was 0; root,
HEAD/index, runtime and harness stayed stable. Both exact generations reached
WAIT0, all four handles closed and normal atexit was MainThread/no QApplication/
zero widgets. The raw report contains 86 rows with kind=module (68 passed,
18 optional/unstarted skips), plus one separate passing pipeline row. Its
reported 69 passes therefore are not 69 unique modules. Nine verifier checks
reconciled the inventory and saved JSON. Teardown retired 13 widget owners,
13 readers and eight Python/zero Qt workers. This is 29 phases, not 29 module
self-tests or an additional runtime observation of all modules. The prior
35.328-second updater check predates scanner changes; older failures and passes
remain historical. Elapsed time is uncontrolled, and neither this check nor
focused acceptance establishes a benchmark, historical cause or full pass.

UGCAP's startup/retirement correction is now applied across eight reviewed
source and fixture files. Private R8 passed 137 selected tests; main-tree
acceptance also passed **137 tests with no skips**, normal native exit 0,
actual kernel retirement and **1,190 unchanged inputs**. Strict authentication,
expiry and cleanup deadlines remain enforced. Private R7's earlier 135 passes
and two failures remain unexplained and were not reproduced by those gates.

The fresh GUI acceptance failed initial Process Monitor readiness before any
campaign launched. A separate cold probe demonstrated373 whole-system parent
map calls in one inventory. The reviewed one-map/fresh-identity correction is
applied and passed419 root focused tests. The fresh applied
GUI campaign completed both launches, signed reports and independent OS
containment checks with native exit0 and1,180 unchanged inputs. Each launch
verified37/37 simulation containments; native analytics remained0/37 each.
The original failures remain recorded.

The15 scanner/solo cases and eight priority pair cases completed with native
exit0 and no reported errors or drops, while retaining permission, provider,
preview and timing limitations. Both600-second combined/scanner cases completed with normal exit0 and retain
interval health rather than crediting only the final recovered sample; see the
[long observation review](long-observation.md). Three
earlier observation-only LSASS notices remain unbound to a retained process
ancestry; neither suppression nor a credential-theft conclusion is justified.

Fourteen narrow maintenance checkpoints are public; the current checkpoint14
verdict is summarized above and in validation.json. Historical checkpoint13
a74 published Black Box bounds/test/guide after128 selected passes. Publisher0
was followed by a wrapper formatting assertion1 and a fresh reconciliation0,
without republishing. Its Security passed3/3, while CI ended10/12 with Python
3.10 GUI response and3.13 Forge-stage failures. Their original causes remain
unknown. Both preserving root forwards completed without losing working bytes.
The prior07 CI12/Security3 and6049/18 per Python remain historical. Missing
external proof/PDB originals were not reconstructed. Latest completed R7 failed
one; later R10 passed7,554/0/49 for its frozen snapshot, while packaging remains stale.

The prior [b792 CI run](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/39875092502)
retains 11 successful jobs and one failed Python 3.10 worker-stop assertion.
Its failure and historical-cause uncertainty remain recorded under CI-04;
the green successor does not publish the broader 1.14 tree.

The final static check passed across `src`, `tests` and `tools` after the
applied UGCAP and Process retry changes. It does not replace runtime or full
regression acceptance. Test groups overlap and must not be added as unique
cases. Current status and sanitized measurements are in
[validation.json](validation.json).

The separate instrumented cold selfcheck passed 29/29 phases with native exit 0,
1,190 unchanged root inputs and 16 unchanged private inputs. YARA completed
with all 26 bounded markers and no marker loss; the prior failure did not
reproduce. FlightInstructorWorker remained listed at atexit, so this result
does not establish all-worker shutdown or replace unmodified-root acceptance.
The private Flight shutdown gate passed 24/25 before fixture-only isolation of
an inherited presentation callback against the minimal test window. R3 then
passed all 25 cases without warnings, with actual kernel retirement, only
MainThread at normal atexit and 1,191 root plus 30 private pins unchanged. The
three-file repair is applied. Main-tree focused acceptance passed 71 tests with
native exit 0 and 1,192 unchanged inputs, but retained a test-owned Enclave
rotation thread at atexit. After test-only owner cleanup, a fresh 71-test gate
passed without warnings, with native exit 0, 1,192 unchanged inputs and
MainThread-only atexit. Selfcheck r4 separately reached MainThread-only atexit.
Both earlier gate records remain retained, without inferring a production
Enclave leak or fully constructed window fault.

After the 88-test deadline-accounting gate, two main-tree native-fixture checks
each passed all 12 cases without warnings, with actual kernel retirement,
normal native exit 0 and 1,191 unchanged inputs. The first used captured JSON
reporting; the second retained the worker before startup, allowing a legitimate
deadline before callback entry. Read-only review confirmed each worker joins
before loop variables change and monkeypatch cleanup restores the module
binding. Production b8ca8f stayed unchanged during those checks. The current
e9cc6ee7 revision adds separate repairs for two older defects (TST-24/25): failed
exception rendering could hide callback/notification failure, and pre-start
Event/Thread construction could leak capacity. The reviewed repair passed 76
private cases with 1,192 root plus 15 private pins unchanged, then 110 main-tree
cases with 1,193 unchanged inputs. Both exited normally with native exit 0,
actual kernel retirement and MainThread-only atexit. Fresh revised-source
selfcheck r5 passed 29/29 with 1,193 unchanged inputs and the same clean retirement.
Deadline decisions and the existing startup-interruption
boundary remain; no native preemption or historical failure cause is established.

The earlier two-launch GUI test r4 passed with native exit 0, actual kernel
retirement, MainThread-only atexit and 1,193 unchanged inputs after fixture-owned
sampler shutdown/join and case-local diagnostics. Each launch verified 37/37
simulation responses, 36 source removals/hash matches and three process
witnesses, without modal errors; native analytics remained 0/37. The four prior
shared aliases stayed byte-identical. Archives retain all 18 r3 files and 14 r2
files with matching digests; four overwritten old r2 aliases remain unavailable,
and r1's trace does not reconstruct a signed AAR. This GUI observation predates
the joint lifecycle changes.
Historical GUI r5 failed after its first verified simulation: 38 engine steps,
37 simulation response contracts, signed AAR and OS witnesses passed; second
launch refused fresh Process evidence with a blank error. Native exit 1,
1,195 unchanged inputs and normal MainThread-only retirement are recorded.
Cause is unknown. Typed diagnostics are now applied with 198 focused passes; GUI r6 passed both
actual launches. These results establish no prior r5 cause or health/readiness/
pacing/deadline change.

SystemPulse 6d7100 and AsyncSnapshot's two guards are now applied in exactly
seven files, preserving index, HEAD54c and unrelated bytes. That joint lifecycle tree
contained 1,195 inputs. Fresh uninstrumented private Pulse R4 passed 74 cases with
74 starts/calls, 36 phases, native exit 0, normal MainThread-only atexit, zero
widgets and 1,193 root plus 80 private stable inputs. Earlier Pulse R3's 72
passes/two failures, the watchdog and framing gaps remain retained, without an
established cause. Timer diagnostic A passed two cases/four witnesses but only
27/28 auxiliary markers; diagnostic B passed 74/four witnesses/36 phases. Those
instrumented diagnostics grant no lifecycle acceptance or benchmark claim.

Async controls recorded six typed failures/two passes on original b8279be
(native 1), versus eight passes on 60bef (native 0), with cleanup and provenance.
The first combined main-tree gate nevertheless **failed: 142 passes/two
failures**, native exit 1, 1,195 unchanged inputs and MainThread-only retirement.
All 35 new controls passed; an orb Chill assertion and a visible resource-dialog
callback assertion failed after their original waits. Cause remains under
investigation. Fresh selfcheck r6 passed 29/29 on the same 1,195-input tree;
full regression r6/package acceptance remains held. Detached workers,
cooperative read cancellation and close-versus-retirement boundaries remain;
these checks neither prove every Qt deletion safe nor explain C0. The scoped
MainWindow source review found no explicit import-time host operations, without
whole-graph purity, speed or cause proof. Earlier static and 54-page render
reviews remain historical.
A later instrumented root diagnostic passed 144 cases with native exit 0,
1,195 root plus three observer pins unchanged and normal MainThread-only
retirement. Four witness rows were complete with no loss and prior tracing
restored. Orb callbacks moved from zero to two, resource callbacks from one to
six; their timers were active and visible without Chill. This is explicitly
diagnostic only, with acceptance false. It does not explain or close the 142/2
failure or establish a performance improvement.

## Platform contracts checked

- Qt objects, timers and GUI work retain their owning thread; application
  lifetime and deferred deletion require explicit ordering. The teardown fix
  follows the [Qt 6.11 ownership and event-loop guidance](https://doc.qt.io/qt-6.11/threads-qobject.html)
  and is separately verified by two normal native selfcheck exits.
- Windows cancellation requests do not themselves complete pending I/O.
  Overlapped structures and buffers stay owned until completion is observed,
  following [Microsoft's CancelIoEx contract](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex).
- Named-pipe generic write rights also permit creating instances. The ordinary
  producer needs that right to open its additional outbound instances, so the
  reader's OS PID/birth checks remain essential; the ACL is not an enclave
  against the same user. See [Microsoft's named-pipe access-rights guidance](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights).
- pywin32's wrapper can return accepted connection status codes directly,
  including `ERROR_PIPE_CONNECTED`, which did not submit the supplied
  overlapped operation. The native lifecycle fix follows the
  [installed wrapper's return-value contract](https://github.com/mhammond/pywin32/blob/b312/win32/src/win32pipe.i#L165).

Historical 1,196-input evidence: the six-file Process/cleanup application passed
198 focused cases and GUI r6 passed two actual launches, native 0/MainThread
only. Prior GUI r5 cause remains unknown; typed diagnostics changed no health,
readiness, pacing or deadline. Latest UNINSTRUMENTED Pulse r3 still failed 142/2:
ordinary/cosmetic 40ms and orb 50ms missed original 160ms waits. R5's 144-pass/
proof_valid observation is DIAGNOSTIC ONLY. R4 diagnostic is unexecuted; later full
R6c failed five, package STALE, whole v1.14 in progress.

## Updater source validated; activation remains held

Applied R6 source adds daily-OFF Settings/FullSetup controls, asynchronous visible
manual checks, a shared 24h failure-inclusive cadence/60s manual floor and backup
three-way source staging. The [operator guide](../../docs/github-updates.md)
describes these controls and the activation boundary. The private manual chapter
still awaits rendering; no root manual was changed by this documentation task.

Private R6 focused acceptance passed 83 with one optional native-8.3 skip/native
0, including both actual junction controls and 30 CLI cases. Cancellation precedes
Git/network, and unused/mixed CLI flags are rejected before producer imports.
Fifteen other candidate files remain byte-identical to R5. Root application made
exactly 20 changes, seven backups/13 new files, namespace 1,835->1,848, preserving
unrelated bytes, HEAD/index and runtime/operator settings.

Root R3 accepted 179 passes/one optional skip/native 0 (18.578 seconds outer,
15.291 JUnit) and uninstrumented selfcheck 29/0/native 0 (35.328 seconds outer).
Root/runtime/harness and HEAD/index stayed stable; both exact native generations
retired, both handles closed and atexit was MainThread-only/no QApplication.
R2's earlier 179/1/native 0 remains a failed recorder acceptance because the
pytest ExitCode IntEnum serialized null. R3 changed only numeric recording,
preserving reraised exceptions and actual targets. R5's failed 330/3/2/native 1
also remains: an incorrect pre-cancel intent expectation and two junction-fixture
quoting failures before product. No earlier alias bypass was demonstrated.

These selected gates are no full regression or live-host efficacy result.
Activation ALWAYS HELD: HTTPS/source SHA, clean merge or static syntax grants no
installer, trust-root or UGCAP authority. Stopped-suite/runtime/dependency/service
and attestation phases remain incomplete. CRLF edits may conflict. The daily
source feature is not public; full regression r6/package/whole 1.14 remain held.

## Scoped scanner read bounds

SCN-03 replaces two cap-based regular-file requests (YARA 64 MiB and APID 128MiB)
with opened size+1, retaining caps, identity checks, cache/receipt authority,
pacing and retries. YARA rejects a size mismatch before scanning. Four applied
files changed no unrelated bytes or HEAD/index; namespace 1,848 stayed unchanged.
Five new controls cover actual append/truncate/refusal and authenticated
receipt/cache/retry behavior. The exact root gate passed 84/native 0 (17.125
seconds outer/14.628 JUnit), stable pins, same-generation retirement, both handles
closed, MainThread-only/no QApplication. The updater selfcheck above predates
this four-file change. Requested-byte bounds prove no allocator or product
throughput improvement; a tiny 20-read diagnostic is not a benchmark. Other
bounded-read candidates remain deferred.

Post-scanner Ruff across src/tests/tools/blackbox_recorder, git diff whitespace
and all 1,146 present tracked/unignored Python 3.10 AST parses passed with exit
0. These are static checks. Full R6c completed with five failures under its existing 7,200-second
supervisor; package/whole-publication remain held.


## Applied Black Box and installer preservation, held manual

PER-11's two-file repair is applied after the original source review found
cap-sized status requests and an unbounded historical report read. Status and
history now use at most 64 KiB requests while retaining 4 MiB caps plus a
sentinel, partial-fault refusal, both report schemas and explicit informational
omission/coverage gaps. The fixture retains exactly 501 rows: 500 historical
plus one fresh live failure, with original bytes and mtime unchanged. The
eight-cohort selected gate passed 136 cases/no skips/native 0 (18.172 seconds
outer/13.981 JUnit), with stable root/HEAD/index/runtime/harness, both exact
generations retired, four handles closed and MainThread/no QApplication/zero
widgets. The original source backup remains. Namespace is now 1,850 and Python
inventory 1,147; fresh Ruff and Python 3.10 AST covered only the two changed
files. No all-1,147 AST gate, throughput benchmark or complete regression is
claimed. This follows R7 and the latest module selfcheck; their revision limits
remain explicit.

UPD-03 is a distinct existing packaged-installer backup-retention gap, not merely
a source-activation deployment boundary. Source ordering can discard previous
payload after failed restoration; no filesystem/ACL fault injection or observed
data loss proves the path at runtime. The preservation product remains private;
its reviewed preservation source and 27-control fixture are now applied and
accepted within final 141. Twenty-one actual child receipts were reviewed; six
inert controls are not physical-process evidence. Earlier unexecuted proposals
remain historical. A durable packaged crash journal, recovery surviving installer
replacement, restart-health proof and anti-rollback recovery policy remain
separate gaps. External release authority is not provisioned by a source stage.

The optional private DOCX appendix is unapplied and undelivered; current
operator/AI instructions are in [the Markdown update guide](../../docs/github-updates.md).
The latest renderer handshake failed with ModuleNotFoundError for win32com
before source open or export. At that failure capture, owned Word cleanup was
still pending and no new retirement was asserted; the original unknown-owner
Word instance was untouched. A later normal WM_CLOSE signaled the owned
temporary Word handle (WAIT0), without force-kill or touching the original
unknown-owner Word; supervisor retirement was still pending at that later
observation. These are capture-time facts, not current liveness assertions.
Prior attempts are historical: render R2b lacked
Get-FileHash; R3 corrected the child module path but hidden blank Word had no
Window and stopped before source open. A background Word instance has unknown
ownership pending user clarification. No process action or DOCX delivery is
authorized here; historical 54-page QA does not validate the new chapter.

The first selected successor passed 73 assertions/native 0 but acceptance
rejected MainThread+Dummy-2. The four test-only corrections then passed the same
five-file gate: 73 passes/no skips/native 0, 45.656 seconds outer/42.357 JUnit,
with stable root/HEAD/index/runtime/harness, both exact generations retired and
all four handles closed. MainThread/no QApplication/zero widgets met the
unchanged strict criterion. Actual QThread.wait/isRunning/admission cleanup
passed; the earlier Dummy journal did not prove a live OS thread or leak.
Original 53/3 and rejected 73 evidence remain. This gate accepts the scoped
test corrections, not the complete regression or an installer repair.

Three later YARA test files add 17 deterministic actual-scanner controls. The
original product failed all 17 while 66 existing cases passed, including the
original restored-mtime test (12.953 seconds outer/9.875 JUnit, native 1). The
one-file USN/no-cache repair then passed the identical 83-case successor
(12.078 seconds outer/8.739 JUnit, native 0). Both gates retained unchanged
root/HEAD/index/runtime/harness, exact two-generation retirement, four closed
handles and MainThread/no QApplication/zero widgets. This independently proves
the controlled timestamp-token weakness; the original failed full-run branch
remains unobserved. The fresh 29-phase selfcheck and post-fix Ruff, whitespace
and all 1,146 Python 3.10 AST checks passed. No elapsed-time comparison is a
product benchmark. All five formerly failing R6c nodes passed R7, whose separate
GUI failure still holds complete regression acceptance.

## Queued spyware research designs

These are reviewed design proposals, **not implemented** collectors, feeds,
rules or actions. They add no release, allowlist or response authority.

| Source and date | Queued design and boundary |
| --- | --- |
| [Project Zero, 14 January 2026](https://projectzero.google/2026/01/pixel-0-click-part-3.html) | Read-only effective process-mitigation receipts bound to exact process identity and reviewed application roles, retaining legitimate JIT and unknown denied/unsupported/stale states. The source concerns Android; the Windows use is an engineering inference, with [GetProcessMitigationPolicy](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessmitigationpolicy) as a possible read-only API, not enforcement. |
| [Amnesty Security Lab, 12 May 2026](https://securitylab.amnesty.org/latest/2026/05/android-intrusion-logging-as-a-new-source-of-data-for-consensual-forensic-analysis/) | Explicitly consented offline Intrusion Logging/MVT import with versioned schema and a separate imported-device evidence lane. The report's initial Android 16/Pixel availability is not a current compatibility claim. Source hash is not acquisition authentication or local response authority; no ADB, automatic upload or credential values. |
| [Citizen Lab, 15 October 2026](https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/) | Optional browser request provenance through a consented Edge extension/[native host](https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/native-messaging): redirects, origins, frames, sessions and sequence/loss evidence. Historical infrastructure association is not malicious-domain proof. No full query strings, cookies, content or advertising IDs by default; no WebView or renderer-PID attribution claim. |

## Process observation scheduling fairness

PER-12 records a separate controlled scheduling-fairness gap, not the cause of
R7. With shared background factor 8 and a one-second base poll, original code
failed the unchanged real eight-second observation lease; the identical
positive control passed after two product files added a generation/token-bound
one-retry credit. It removes only discretionary background addition, preserving
mandatory cadence/throttle/Chill, health, coverage, deadlines and existing
coalesced wakes. No total caller wakeup bound or token-expiry contract is
claimed. All 12 new controls passed. The original four-cohort gate failed
121/1 when a recorder-negative fixture reached genuine live-host collection
gaps before its intended stage (TST-29). After test-only recorder confinement,
the same selected cohort passed122/no skips/native0, with stable inputs, both
exact generations retired, four handles closed and MainThread/no QApplication/
zero widgets. The original physical collection gap was not fixed or suppressed;
production was unchanged by the fixture. This is selected acceptance, not a
complete regression or historical GUI cause conclusion.
The controlled paired result is not a throughput benchmark or proof of R7's
actual pacing, last refusal or cause.

The same canonical post-cadence GUI test passed one node/two actual launches,
native0 (129.734 seconds outer/125.787 JUnit), with unchanged1851/HEAD07/index/
runtime/harness, both exact generations retired, four handles closed and
MainThread/no QApplication/zero widgets. Physical collectors, real admission,
recorder and AAR contracts were unchanged. This selected observation does not
prove R7's actual pacing/last refusal/cause or validate the failure-only capture
branch. Elapsed times are uncontrolled, not a benchmark.
