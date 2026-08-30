# Cycle 27, Round 1 — Defensive Red-Team Shard A

Scope: exhaustive, read-only review of the 25 assigned files in `src/angerona/modules/`. The audit used static data-flow review plus inert in-memory/temporary-directory probes only. No product code, host posture, network target, shared loop log, commit, or publication state was changed. Prior findings were checked before assigning new IDs.

## Result

| Severity | New findings |
|---|---:|
| CRITICAL | 0 |
| HIGH | 3 |
| MEDIUM | 13 |
| LOW | 1 |
| INFO | 0 |
| **Total** | **17** |

The highest-risk defects are a crash-recovery path that silently closes a non-reversible response intent and re-arms mutation, a chaos harness whose own probe announcements satisfy all three probes, and a Security-log reader that skips bursts/channel generations while continuing to report 100% health.

## Findings

### C27-R1-A01 — Crash recovery terminalizes an unverifiable non-reversible mutation and re-arms response

- Severity: **HIGH**
- Component: `src/angerona/modules/adversary_combat.py:1542-1572`, `src/angerona/modules/adversary_combat.py:1955-2011`, `src/angerona/modules/adversary_combat.py:2048-2061`
- Evidence: an in-process commit failure for a non-reversible action correctly calls `_trip_mutation_circuit()`. The restart path does not. For an orphaned non-reversible intent, `_recover_orphaned_journal()` creates a terminal `failure` record saying manual verification is required, but never opens the mutation circuit or retains `_recovery_required`; `_reconcile_state()` then returns true. An inert temporary journal containing only a `terminate_process` intent reproduced `reconcile=True`, `mutation_blocked=False`, `recovery_required=False`, with the final record changed to `failure`.
- Impact: if the suite or host stops after a process was terminated but before the commit was fsynced, Angerona discards the only pending-recovery state and resumes additional elevated mutations without operator verification. The HMAC chain still preserves what was written, and the crash window is narrow, but the non-reversible custody invariant is broken exactly where an attacker could terminate the service.
- Recommendation: treat every orphaned non-reversible intent as `recovery_required`, call `_trip_mutation_circuit()`, keep the intent non-terminal, expose the exact action/target and source lines in health/UI, and require an authenticated operator disposition before re-arming. Add a restart fixture for intent → external effect → crash-before-commit.

### C27-R1-A02 — The response journal has quadratic append cost and silently ignores old live actions

- Severity: **MEDIUM**
- Component: `src/angerona/modules/adversary_combat.py:1432-1517`, `src/angerona/modules/adversary_combat.py:2048-2093`, `src/angerona/modules/adversary_combat.py:2282-2335`, `src/angerona/modules/adversary_combat.py:2507-2520`
- Evidence: every `_append_journal()` reads, splits, JSON-parses, and HMAC-verifies the entire journal before appending one record. There is no byte/record/age bound or compaction, making a sequence of appends quadratic. `list_actions()` also processes the whole file, but startup state rebuild and `undo_last()` retain only 500 returned actions and `undo_all()` only 5,000. Older still-applied firewall/isolation receipts can therefore fall outside runtime state and “undo all.”
- Impact: a long incident stream can progressively consume response CPU, memory, and startup time when availability matters most. Sufficient history can also make the UI/state sets forget an older active containment rule even though the OS mutation remains. Journal authentication and fsync are meaningful controls but do not bound resource use or semantic retention.
- Recommendation: use an authenticated checkpoint/segment format with bounded incremental verification, size/record quotas, atomic compaction, and a separately authenticated index of every live action. Refuse new mutation before exhaustion, expose journal size/verification latency/oldest live receipt, and make “undo all” truly exhaustive or explicitly partial.

### C27-R1-A03 — Quarantine moves one hard-link name while an executable alias remains live

- Severity: **MEDIUM**
- Component: `src/angerona/modules/adversary_combat.py:164-189`, `src/angerona/modules/adversary_combat.py:480-498`, `src/angerona/modules/adversary_combat.py:1672-1722`
- Evidence: the POSIX pin validates type and owner but not `st_nlink`; the Windows pin retrieves `nNumberOfLinks` but never checks it. Quarantine renames only the contracted directory entry and commits after verifying the moved object's identity/hash. An inert same-volume probe created a two-link file, used `_PinnedFileMove.rename_to()`, and observed `source_exists=False`, `quarantine_exists=True`, while the alternate link still returned the original bytes.
- Impact: malware can prepare a hard-link alias before detection; Angerona reports the target quarantined while the same executable object remains reachable under another name. Handle pinning, no-follow traversal, no-replace rename, owner checks, and post-move hashing correctly stop path swaps but do not remove aliases.
- Recommendation: fail closed when link count is not exactly one, record link count in the intent/receipt, and revalidate it on the pinned handle immediately before and after the move. If supported, enumerate same-volume aliases under an explicit policy; otherwise report “alias-safe quarantine unavailable” and withhold a successful postcondition.

### C27-R1-A04 — Model attestation silently re-enrolls lost state, missing files, and new content

- Severity: **MEDIUM**
- Component: `src/angerona/modules/ai_model_integrity.py:75-86`, `src/angerona/modules/ai_model_integrity.py:295-356`, `src/angerona/modules/ai_model_integrity.py:361-421`; consumer: `src/angerona/modules/ai_triage.py:99-175`, `src/angerona/modules/ai_triage.py:259-305`
- Evidence: baseline JSON is unauthenticated and non-atomic. Any load/parse failure resets it to `{}`, after which `run()` TOFU-enrolls the current directory. `_verify_pass()` examines only currently discovered blobs, never flags baseline entries that disappeared, and auto-pins every new name. `_hash_file()` returns string sentinels; `FILE_NOT_FOUND` and `ERROR:*` are eligible for pinning and can produce no mismatch. Inert probes returned `(0, [])` for a deleted baseline blob, `(1, [])` while pinning `FILE_NOT_FOUND`, and treated malformed JSON as a first run. AI Triage checks only daemon/tag availability and never gates inference on an attested model digest.
- Impact: deletion, transient I/O denial, baseline corruption, or a newly introduced self-consistent poisoned model can lead to “attested clean” health. The content-address check still catches bytes that disagree with a `sha256-*` filename, and governed model packs have a stronger catalog verifier elsewhere, but the live generic triage model is not bound to that verifier.
- Recommendation: store a strict, HMAC-protected, atomically replaced inventory with schema, root identity, enrollment authority, tag/manifest digest, and complete blob set. Treat missing/new/unreadable/error entries as non-clean until explicit approval; never persist sentinel strings. Require AI Triage to obtain a fresh successful attestation receipt for the exact configured tag/manifest before inference, with deterministic fallback on failure.

### C27-R1-A05 — API Patch Detector reports zero checked exports as 100% clean and caches failure forever

- Severity: **MEDIUM**
- Component: `src/angerona/modules/api_patch_detector.py:41-49`, `src/angerona/modules/api_patch_detector.py:171-234`, `src/angerona/modules/api_patch_detector.py:353-374`
- Evidence: `_disk_prologues()` catches every baseline read/parse failure, caches the resulting empty dictionary permanently, and never retries. `scan_once()` then performs zero comparisons and returns no findings. `run()` interprets that as success and sets health 100 with “0 exports clean”; it also overwrites the non-Windows health 60 on the first loop. An inert preloaded empty-cache probe returned `findings=[]`, `checked=0` for both watched DLLs.
- Impact: startup races, denied reads, parser incompatibility, or a poisoned `SystemRoot` launch environment can disable the anti-blinding comparison for the process lifetime while the dashboard is green. Cross-process scan controls remain useful when baselines exist.
- Recommendation: make baseline acquisition a typed required capability; never cache failure as data, retry with bounded backoff, require the complete expected export set from a fixed trusted Windows directory/object, and cap health below 100 for any missing disk or memory comparison. Surface per-DLL/export coverage and exact failure lines.

### C27-R1-A06 — ARP Watchdog trusts startup/new poison and treats collector failure as healthy

- Severity: **MEDIUM**
- Component: `src/angerona/modules/arp_watchdog.py:69-90`, `src/angerona/modules/arp_watchdog.py:111-176`, `src/angerona/modules/arp_watchdog.py:373-376`
- Evidence: `_parse_arp_cache()` converts every command/parse error to an empty mapping. `run()` accepts that mapping as its volatile first-seen baseline and unconditionally sets health 100. Every previously unseen IP is also silently added to the baseline on first observation; neither baseline nor gateway identity is persisted or independently verified. `self_test()` always passes, including an empty cache. An inert monkeypatch reproduced `baseline={}`, `health=100`, and a passing self-test.
- Impact: an on-link attacker present before startup, after restart, or when a new address appears can have the poisoned mapping blessed as normal. A missing/broken `arp` collector creates the same green state. Optional Scapy change observation can catch later changes but cannot repair poisoned enrollment.
- Recommendation: persist an authenticated adapter/gateway-scoped baseline, enroll only after independent neighbor/router/DHCP evidence or operator approval, and model collector status separately from an empty valid cache. Health must include polling success, adapter coverage, baseline age/source, and Scapy liveness; unknown/new mappings should remain untrusted.

### C27-R1-A07 — AV Telemetry Bridge deliberately discards retained detections and has no restart-safe cursor

- Severity: **MEDIUM**
- Component: `src/angerona/modules/av_telemetry_bridge.py:188-241`, `src/angerona/modules/av_telemetry_bridge.py:278-338`
- Evidence: event-log mode drains the complete retained backlog without processing it on every start, then tracks only an in-memory handle position. A read error reopens without an authenticated bookmark/generation proof. PowerShell fallback likewise seeds all existing detection IDs as already seen, and recurring poll exceptions are swallowed while health remains 80. No retained-history gap, channel clear, duplicate/replay, or durable cursor state is recorded.
- Impact: restarting Angerona after a Defender detection removes that detection from this bridge, and collector failure can create an unreported visibility interval. Defender retains its own evidence and this module clearly labels the PowerShell path as lower fidelity, which limits impact, but downstream EventBus/SOAR consumers cannot reconstruct the gap.
- Recommendation: use the modern WEVT API with an authenticated bookmark plus channel-generation/anchor continuity, bounded retained replay, exact EID dedup, and explicit gap events. Persist fallback cursors safely, degrade on every failed poll, close handles, and expose retained/processed/skipped/error totals.

### C27-R1-A08 — Connection-based detectors fail open; the inference-port allowlist is basename-only

- Severity: **MEDIUM**
- Component: `src/angerona/modules/beacon_detector.py:100-128`; `src/angerona/modules/counter_agentic.py:64-67`, `src/angerona/modules/counter_agentic.py:170-206`, `src/angerona/modules/counter_agentic.py:219-232`
- Evidence: Beacon Detector catches a `list_connections()` exception and returns; its outer loop then sets health 100. Counter-Agentic does the same and also unconditionally reports health 100 after its other checks. Its local-model-port policy exempts generic process basenames including `python.exe`, `pythonw.exe`, and `angerona.exe`, without executable path, birth time, signer/digest, owner, or connection-side identity.
- Impact: a failed shared connection snapshot silently blinds beacon cadence and inference-port observation. A local client can rename itself to an allowed basename and use the unauthenticated Ollama port without a Counter-Agentic alert. Other event-chain logic in Counter-Agentic and other network sensors remain active.
- Recommendation: return a typed snapshot receipt with freshness/completeness/error counts and propagate failure into module health; preserve prior state across short outages without claiming clean. Bind port authorization to process birth plus handle-resolved executable identity and a sealed publisher/digest policy, and read the configured local endpoint rather than hard-coding only port 11434.

### C27-R1-A09 — Canary Drill can reach 100% without testing the promised durable recorder path

- Severity: **MEDIUM**
- Component: `src/angerona/modules/canary_drill.py:15-22`, `src/angerona/modules/canary_drill.py:316-342`, `src/angerona/modules/canary_drill.py:499-504`
- Evidence: the module contract says it verifies that a confirmed canary was persisted to the FlightRecorder SQLite ledger. The implementation marks a drill caught as soon as an EventBus echo satisfies the in-memory expectation, increments `_drills_caught`, and computes health up to 100 from that ratio. There is no ledger query, recorder receipt, durable sequence, or canary-tag persistence check anywhere in the file.
- Impact: the live sensor-to-bus path can work while forensic persistence is broken, yet the drill reports complete pipeline health. UUID-tagged expectations and trusted-event filtering make the process echo itself meaningful; the missing leg is bus-to-ledger durability.
- Recommendation: require a second authenticated expectation from FlightRecorder for the exact canary tag/event digest and sequence after the bus echo; score and display sensor echo and durable persistence separately, never 100 unless both complete before deadline, and link a miss to the recorder database/receipt line.

### C27-R1-A10 — Continuous Chaos Harness satisfies every probe with its own announcement

- Severity: **HIGH**
- Component: `src/angerona/modules/chaos_harness.py:79-110`, `src/angerona/modules/chaos_harness.py:112-153`, `src/angerona/modules/chaos_harness.py:156-180`
- Evidence: `_wait_for_echo()` accepts any post-start event when either the requested code or any broad keyword appears in concatenated module/message text. It does not exclude the Chaos module or bind an unguessable probe ID to a designated responder. `_probe_apid()` emits “APID”; `_probe_ndrd()` emits “entropy DNS”; `_probe_fim_amsi()` emits “EICAR ... FIM/AMSI” before waiting, so each announcement matches its own predicate. An inert fake-bus probe reproduced `True` for APID, NDRD, and FIM with only the Chaos module's own messages present.
- Impact: all three detector pipelines can be absent or blind while CHAOS announces that every detector responded and sets health 100. The real DNS/file actions do not rescue the result because the self-event is already sufficient.
- Recommendation: issue a cryptographically random probe ID and strict expected response contract per sensor; accept only an allowlisted module identity, matching probe ID, observation type, source epoch, and time window, and explicitly reject self/practice announcements. Remove broad text fallback and add negative tests with no responders and spoofed/wrong-sensor echoes.

### C27-R1-A11 — Compliance artifact calls mappings “enforced” and hides bounded-bus loss

- Severity: **MEDIUM**
- Component: `src/angerona/modules/compliance_mapper.py:79-100`, `src/angerona/modules/compliance_mapper.py:132-175`
- Evidence: every event containing a MITRE identifier is copied into fields named `nist_control_enforced` and `stig_baseline_enforced`; a detection-to-control mapping is not evidence that the control is implemented, effective, or tested. The module keeps only 2,000 in-memory incidents, ignores the EventBus overflow flag, overwrites unauthenticated JSON, loses state on restart, and still sets health 100.
- Impact: audit or operator consumers can mistake a partial relevance mapping for proof of compliance enforcement and completeness. The static ATT&CK-to-framework crosswalk itself is useful and unmapped techniques are counted honestly.
- Recommendation: rename fields to `mapped_control`/`control_relevance`; represent implementation, assessment, evidence, result, scope, freshness, and exceptions as separate typed claims. Use a durable authenticated cursor/artifact, record overflow/truncation/restart gaps, atomic writes, and cap health for any incomplete interval.

### C27-R1-A12 — “Daily” briefing is an unbounded-age last-500 sample and reports success before persistence

- Severity: **LOW**
- Component: `src/angerona/modules/daily_briefing.py:52-87`, `src/angerona/modules/daily_briefing.py:162-191`, `src/angerona/modules/daily_briefing.py:214-243`
- Evidence: `_gather()` reads `EventBus.recent(500)` with no 24-hour lower/upper bound, durable cursor, overflow/gap marker, or source epoch. In a burst it covers seconds; on a quiet host it can include stale multi-day events. `_make_briefing()` increments its count and emits “ready” before writing, then swallows both file-write failures; `run()` sets health 100. Local-model narrative is also persisted without a strict output schema, although AI Triage's telemetry neutralizer is not used here.
- Impact: the report may omit most of a busy day, include stale history, or exist only on the bus while health says generated. It is informational and has a deterministic fallback, so direct security impact is low.
- Recommendation: derive a closed `[last_success, now]` interval from the durable recorder, include counts/coverage/gaps and source epochs, neutralize untrusted fields, validate AI output as non-authoritative narrative, and only increment/emit success after atomic durable writes. Show the exact interval and omitted-event reason.

### C27-R1-A13 — Deception detects writes/deletes, not the credential reads it promises to trap

- Severity: **MEDIUM**
- Component: `src/angerona/modules/deception.py:90-100`, `src/angerona/modules/deception.py:134-161`, `src/angerona/modules/deception.py:197-227`
- Evidence: file canaries store and poll only `st_mtime`; ordinary reads do not change modification time. Dynamic lures state “Any access is logged & isolated,” but use the same mtime check. `_plant_fake_registry_cred()` claims any read is a definitive tripwire, yet it only invokes `reg add`; no registry audit subscription or observer exists. An inert temporary-file read left `st_mtime_ns` unchanged.
- Impact: a credential stealer can read the decoy files or HKCU value without any Deception alert/SOAR recommendation. Deletion and modification remain detected, and personal-folder deployment is opt-in, which reduces default exposure.
- Recommendation: use OS-native audited access telemetry (object-access/SACL + WEVT/ETW or a narrowly scoped minifilter) bound to exact file IDs and registry key/value identity; attribute actor PID/birth/image, deduplicate access, verify policy activation, and score health below 100 when read visibility is unavailable. Change wording to “write/delete canary” until proven.

### C27-R1-A14 — Driver provenance describes mutable path samples, not one pinned loaded image

- Severity: **MEDIUM**
- Component: `src/angerona/modules/driver_provenance_guard.py:273-313`, `src/angerona/modules/driver_provenance_guard.py:359-469`
- Evidence: PowerShell obtains a running driver's pathname, samples length/mtime, hashes the path, calls `Get-AuthenticodeSignature` on the path separately, and only compares length/mtime afterward. It does not retain a file handle/object ID, reject hard links, bind signature/catalog evidence to the hashed bytes, or prove that those disk bytes are the image loaded in kernel memory. Same-size/same-timestamp swaps can compose mismatched evidence; post-load replacement can describe a different object. The output then labels signer/catalog status as trusted.
- Impact: an administrator/state-level attacker able to load or replace driver files can make a malicious loaded image appear associated with benign disk provenance. Completeness/truncation checks and Secure Boot/HVCI context are strong mitigations, and the module is observational rather than mutating.
- Recommendation: collect loaded-module identity from a kernel/OS primitive, open the exact image without following links, verify volume/file ID/link count/owner/DACL, hash and verify signature/catalog against the same retained object, then revalidate that object remains bound to the loaded module. Mark any unbound path sample UNKNOWN, not trusted. The separate prior-known `-ExecutionPolicy Bypass` issue remains open at lines 334-343.

### C27-R1-A15 — eBPF telemetry can be name-filtered away and loses events without accounting

- Severity: **MEDIUM**
- Component: `src/angerona/modules/ebpf_sensor.py:38-50`, `src/angerona/modules/ebpf_sensor.py:53-78`, `src/angerona/modules/ebpf_sensor.py:108-134`, `src/angerona/modules/ebpf_sensor.py:158-184`
- Evidence: the execve probe drops every event whose current `comm` starts with `sys`, intending to suppress `systemd*`; this is neither exact nor bound to executable identity and is evaluated before forwarding the new `argv0`. A process can choose such a name before exec. Both perf buffers are opened without lost-event callbacks; callback parse/emit errors are swallowed, IPv6 destination identity is omitted, and each successful poll restores health 100 regardless of loss.
- Impact: an attacker can evade this sensor's exec stream by controlling `comm`, while high-rate `tcp_sendmsg` activity can overflow perf buffers invisibly. The module is Linux-only, opt-in, root-gated, and other remote-node sensors may provide coverage.
- Recommendation: remove kernel-level basename filtering or use exact cgroup/service/object policy after capture; register lost callbacks, count per-CPU sequence/loss/callback failures, preserve IPv6 addresses, and make health reflect attachment plus measured delivery completeness. Add a regression for arbitrary `sys*` names.

### C27-R1-A16 — Security-log reader skips event bursts and never recovers from channel generation reset

- Severity: **HIGH**
- Component: `src/angerona/modules/etw_listener.py:53-96`, `src/angerona/modules/etw_listener.py:140-178`
- Evidence: `_read_security_log()` opens the Security log backward, calls `ReadEventLog()` exactly once, and advances `_last_record` to the highest record in that newest batch. If more than one batch arrived since the prior poll, older new records are skipped forever. First startup discards the sampled history. If the channel is cleared and record numbers restart below `_last_record`, every record remains `<= _last_record`, the cursor never resets, and the loop continues setting health 100. No durable bookmark, generation anchor, retention gap, or batch-drain bound exists.
- Impact: a local attacker can create a Security-event burst around process/logon activity or combine log clear/refill with activity to hide it from this core process/logon sensor while the UI is green. ETW Real-Time and Audit Log Guard provide independent coverage when healthy, but this module's own advertised capture is incomplete and its psutil fallback is not activated for silent logical gaps.
- Recommendation: use WEVT bookmarks and forward bounded pagination through a sampled high watermark, persist an authenticated record anchor/generation, detect clear/refill/retention gaps and replay retained evidence, and report processed/skipped/truncated totals. Never advance past unread records or report 100 without a continuity proof.

### C27-R1-A17 — Real-time ETW health is a sticky local boolean, not session liveness or delivery

- Severity: **MEDIUM**
- Component: `src/angerona/modules/etw_realtime_sensor.py:134-146`, `src/angerona/modules/etw_realtime_sensor.py:215-274`, `src/angerona/modules/etw_realtime_sensor.py:333-366`
- Evidence: `start()` sets `_running=True` after calling the pywintrace job and only `stop()` clears it. There is no completion/error callback or underlying thread/session query to clear the flag when the asynchronous consumer dies. Callback exceptions set text but do not degrade health; no ETW buffer-loss/sequence/heartbeat metric exists. The wrapper checks only this sticky property and therefore continues health 100 with an unchanged event count.
- Impact: a dropped/stalled session or repeated callback failure silently removes the real-time process stream while the module claims it is live. Startup failures and lack of elevation are handled honestly at health 0, and ETWG polling can provide partial fallback.
- Recommendation: supervise the actual consumer thread/session handle, attach termination/error/loss callbacks, require a bounded kernel heartbeat or cross-check canary, track last-event/last-heartbeat and dropped buffers, and restart with backoff or remain degraded. Health should distinguish attached, flowing, idle-proven, stalled, and lossy.

## Complete module review ledger

| Assigned file | Disposition | Reviewed evidence |
|---|---|---|
| `adversary_combat.py` | New A01–A03; prior R6-03 still open | Full 1–2601 review; response admission, process/file pinning, journal phases, crash recovery, undo, and resource bounds. R6-03's process-handle/program-image lease remains known and was not re-filed. |
| `ai_model_integrity.py` | New A04 | Full 1–450 review; robust catalog verifier was credited, but daemon baseline/TOFU/error semantics fail clean. |
| `ai_triage.py` | Contributes to A04 | Full 1–347 review; loopback URL/executable policy and prompt neutralization credited; exact model digest is not attestation-gated. |
| `amsi_bridge.py` | No new finding | Full 1–387 review; default in-process AMSI is intentionally disabled at 228–246, health is 50 in observation fallback, and failed EICAR lowers health at 248–270. |
| `api_patch_detector.py` | New A05 | Full 1–389 review; disk baseline, own/cross-process comparison, health and self-test examined. |
| `app_control_monitor.py` | No new finding | Full review; strict checkpoint schema at 216–298 and generation/anchor transaction at 548–858 fail visibly on gaps and were previously remediated. |
| `arp_watchdog.py` | New A06 | Full 1–380 review; poll parsing, TOFU baseline, Scapy helper lifecycle and health tested. |
| `audit_log_guard.py` | No new finding | Full review; authenticated checkpoint, independent-freshness cap, pre/mid/post-query anchor checks and gap health at 181–530 were credited. |
| `authentication_extension_guard.py` | Prior A04 boundary only; no new finding | Full review; fixed-surface completeness/staleness and explicit enrollment at 211–366 credited. Same-process producer authenticity remains the documented residual boundary, not re-filed. |
| `av_telemetry_bridge.py` | New A07 | Full 1–363 review; event-log startup/reopen and PowerShell fallback cursor semantics examined. |
| `beacon_detector.py` | New A08 | Full 1–206 review; shared connection snapshot, process-birth binding, TI corroboration and response contract examined. |
| `behavioral_tuner.py` | No new finding | Full 1–664 review; learning remains untrusted until exact-hash approval and enforcement fails open at 478–541. Caller-selected `EDR_DB_PATH` is a setup boundary; no separate exploit was established. |
| `canary_drill.py` | New A09 | Full 1–537 review; UUID expectations and source-silence handling credited; recorder leg absent. |
| `chaos_harness.py` | New A10 | Full 1–190 review plus inert self-echo reproduction. |
| `cloud_escalation.py` | No new finding | Full review; explicit opt-in, protected key retrieval, minimized payload, bounded call/rate, loopback/cloud policy and visible failure were credited. |
| `compliance_mapper.py` | New A11 | Full 1–207 review; mapping semantics, bus cursor/overflow, retention, write and health paths examined. |
| `counter_agentic.py` | New A08 | Full 1–263 review; bus chain analysis, shared socket table, process allowlist and health examined. |
| `daily_briefing.py` | New A12 | Full 1–270 review; sample interval, active-threat classification, local AI boundary, write ordering and failure health examined. |
| `deception.py` | New A13 | Full 1–250 review; default static data boundary/personal opt-in credited; file and registry read observability absent. |
| `driver_provenance_guard.py` | New A14; prior A06 still open | Full review; strict result schema/completeness credited. Existing broad PowerShell `ExecutionPolicy Bypass` at 334–343 was not re-filed. |
| `dynamic_resource.py` | No new finding | Full 1–210 review; priority is capped below REALTIME, failures are emitted, and clean stop restores priority. Event-driven HIGH priority can be abused for load amplification, but no independent boundary beyond EventBus producer trust was established. |
| `ebpf_sensor.py` | New A15 | Full 1–211 review; BPF filters, IPv4/IPv6 evidence, perf delivery/loss, callbacks, root/config/lifecycle examined. |
| `etw_listener.py` | New A16 | Full 1–207 review; legacy Security-log pagination/generation and psutil fallback examined. |
| `etw_realtime_sensor.py` | New A17 | Full 1–408 review; native availability/elevation, parser/cache, pywintrace session lifecycle and health examined. |
| `evidence_lattice.py` | Prior A04 boundary only; no new finding | Full 1–382 review; structured entities, practice/exposure/health rejection, multi-module/domain threshold, PID clock agreement and exact IP response credited. Same-process module-name independence is the known extension-producer residual and was not duplicated. |

## Inert validation evidence

| Probe | Result |
|---|---|
| Chaos echo isolation | APID, NDRD, and FIM predicates each returned `True` with only the harness's own announcement present. |
| Model baseline loss/error | Deleted baseline entry returned `(0, [])`; missing discovered file returned `(1, [])` and pinned `FILE_NOT_FOUND`; malformed JSON became empty/first-run. |
| API baseline absence | Empty cached baselines returned zero findings and `checked=0`. |
| ARP collector absence | Empty collector produced empty baseline, health 100, passing self-test. |
| Deception read | Reading a temporary canary left `st_mtime_ns` unchanged. |
| Non-reversible crash recovery | Intent-only temporary journal reconciled successfully, cleared recovery state, and wrote terminal failure. |
| Hard-link quarantine | Pinned rename removed the contracted name but left a byte-identical alternate link reachable. |

## Prior-finding reconciliation

- Verified resolved in this shard: **6** prior response/app-control/authentication continuity findings inspected in the current implementations.
- Verified still open, not duplicated: **3** — R6-03 process/program object lease (`adversary_combat.py`), A06 broad PowerShell ExecutionPolicy bypass (`driver_provenance_guard.py`), and A04 same-process extension/producer authenticity (`authentication_extension_guard.py`, `evidence_lattice.py`).
