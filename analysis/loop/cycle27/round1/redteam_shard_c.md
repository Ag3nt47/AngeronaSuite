# Cycle 27, Round 1 — Defensive Red-Team Shard C

Scope: exhaustive, inert review of the 27 assigned files in `src/angerona/modules/`. No product code, host posture, network resource, shared loop log, commit, or publication state was changed. Every assigned file has a review row below. Existing controls and previously known residuals are credited rather than re-reported.

## Result

| Severity | New findings |
|---|---:|
| CRITICAL | 0 |
| HIGH | 4 |
| MEDIUM | 14 |
| LOW | 7 |
| INFO | 0 |
| **Total** | **25** |

The highest-risk defects are non-recursive ransomware coverage, an action that can disable any named Windows service while calling it a driver, attacker-controlled unbounded honeytoken reads, and an unpinned top-level native-module import executed during module discovery.

## Findings

### C27-R1-C01 — PID reuse merges unrelated process provenance while source loss stays green

- Severity: **LOW**
- Component: `src/angerona/modules/provenance_graph.py:73-92`, `src/angerona/modules/provenance_graph.py:153-194`, `src/angerona/modules/provenance_graph.py:294-360`
- Evidence: every process node is only `PROC:<pid>`; an existing node updates only its timestamp, so a reused PID retains its old label, parents, files, and endpoints. Malformed rows are advanced and skipped, database/subscription exceptions are swallowed, and the loop still reports health 100.
- Impact: blast-radius and ancestry views can join two process lifetimes and present an incomplete graph as complete. Repository search found no current production consumer beyond this module, limiting immediate authority.
- Recommendation: key processes by `(pid, create_time/ProcessGuid, boot identity)`, store source/cursor completeness and rejected-row counts, expose gaps in health, and return provenance with exact source-event links.

### C27-R1-C02 — Purple Guard policy loss silently disables reviewed drills at health 100

- Severity: **LOW**
- Component: `src/angerona/modules/purple_guard.py:126-145`, `src/angerona/modules/purple_guard.py:290-322`, `src/angerona/modules/purple_guard.py:455-476`
- Evidence: missing, malformed, or wrong-type policy JSON becomes `{}`. The detector then performs no checks and reports health 100 as “learning mode,” without distinguishing never-configured policy from a lost/corrupt installed policy.
- Impact: assurance drills can stop exercising installed detectors while the dashboard remains green. The file normally resides under Angerona's protected data root and the feature is practice-only.
- Recommendation: authenticate/version the policy, retain an expected-policy receipt, distinguish UNCONFIGURED from TAMPERED/UNREADABLE, fail health below 100 after an installed policy disappears, and show its exact path and parse/authentication error.

### C27-R1-C03 — Ransomware detection ignores every nested user directory

- Severity: **HIGH**
- Component: `src/angerona/modules/ransomware_heuristics.py:119-129`, `src/angerona/modules/ransomware_heuristics.py:194-223`, `src/angerona/modules/ransomware_heuristics.py:252-280`, `src/angerona/modules/ransomware_heuristics.py:322-342`
- Evidence: each watched root is enumerated with one `os.scandir()` and only direct child files are entropy-scored or included in rename snapshots. Permission/read skips are not counted, and the mere presence of top-level roots produces health 100.
- Impact: ransomware can encrypt `Documents\Projects\...`, `Pictures\Years\...`, and other ordinary nested content without either detector seeing a candidate. Same-directory correlation and top-level bounds are useful existing controls, but do not cover subtrees.
- Recommendation: add bounded recursive, reparse-safe traversal or journal/USN telemetry; maintain per-root cursors and depth/file/time budgets; report visited/skipped/truncated counts; and never report 100 without fresh recursive coverage.

### C27-R1-C04 — “Disable driver” accepts any Windows service name without driver identity

- Severity: **HIGH**
- Component: `src/angerona/modules/remediation_actions.py:237-304`, `src/angerona/modules/remediation_actions.py:350-364`
- Evidence: `_svc()` accepts an arbitrary `driver` value or derives a stem from any `.sys` pathname. `matches()` checks only Windows plus a nonempty stem; it never proves service type, image path, signer, vulnerable digest, report provenance, or a BYOVD policy hit before running `sc config <name> start= disabled`.
- Impact: an admitted weakness row can disable a critical non-driver service or unrelated boot/system driver. Explicit `apply=True`, `ANGERONA_AUTO_REMEDIATE=1`, durable journaling, and postcondition verification are meaningful gates, but they do not validate the target's security semantics.
- Recommendation: accept only a typed, authenticated BYOVD finding bound to service registry object, kernel-driver type, stable image object, pinned signer/hash policy and freshness; deny critical/recovery services; show reboot/current-load impact; and require exact operator approval for that identity.

### C27-R1-C05 — Free-text weakness fields can authorize process termination or broad firewall blocks

- Severity: **MEDIUM**
- Component: `src/angerona/modules/remediation_actions.py:45-79`, `src/angerona/modules/remediation_actions.py:768-839`, `src/angerona/modules/remediation_actions.py:1063-1095`
- Evidence: network isolation extracts the first IP from generic fields or display text and excludes only loopback, unspecified, and link-local addresses; private gateways, DNS servers, multicast, and reserved ranges remain eligible. Kill matching requires a good live process identity but grants irreversible authority when generic text contains a trigger substring such as `exfil` or `worm`.
- Impact: a misleading/poisoned posture row can terminate an exact but benign process or isolate an essential network peer. Host opt-in and process birth/image checks reduce exploitability.
- Recommendation: remove display-text matching; require authenticated typed response contracts with exact action, target, source authority, confidence/corroboration, expiry and nonce; classify infrastructure/reserved addresses; and bind a fresh operator approval to the complete plan.

### C27-R1-C06 — Remediation rolls back stale service/registry state without external-state compare-and-swap

- Severity: **MEDIUM**
- Component: `src/angerona/modules/remediation_actions.py:264-323`, `src/angerona/modules/remediation_actions.py:511-579`, `src/angerona/modules/remediation_actions.py:1548-1629`
- Evidence: prior service/registry state is read before durable preparation, then the runner journals and later writes the named resource without re-proving that the live value is still the retained prior value. Compensation restores that stale snapshot.
- Impact: a GPO refresh, administrator, MDM, or security product can change a control during review/dispatch; Angerona can overwrite it and a later rollback can undo the intervening legitimate policy. Durable transaction custody records Angerona's intent but not external ownership/version.
- Recommendation: retain stable resource identity plus observed value/version, perform an apply-time compare-and-swap, refuse conflicts, and compensate only when the current state is exactly Angerona's committed postcondition. Surface GPO/MDM ownership and conflict explicitly.

### C27-R1-C07 — Remote Bridge sessions have no forward secrecy

- Severity: **LOW**
- Component: `src/angerona/modules/remote_bridge.py:76-137`, `src/angerona/modules/remote_bridge.py:484-527`, `src/angerona/modules/remote_bridge.py:708-749`
- Evidence: mutual proofs and AES-GCM session keys are derived only from one long-term symmetric key plus public nonces. There is no ephemeral Diffie-Hellman contribution or key epoch/rotation protocol.
- Impact: passive recordings of forwarded high-severity telemetry become decryptable if the PSK is later recovered. The bridge is off by default, loopback by default, mutually authenticated, encrypted, bounded, and strips local-response identifiers.
- Recommendation: use a reviewed TLS 1.3/mTLS or Noise-style ephemeral authenticated handshake, rotate node credentials, bind node/role/protocol identities, and expose credential age and negotiated cipher/peer identity.

### C27-R1-C08 — Governor can suppress security sensors and leave stale throttles after restart

- Severity: **MEDIUM**
- Component: `src/angerona/modules/resource_governor.py:36-43`, `src/angerona/modules/resource_governor.py:70-103`, `src/angerona/modules/resource_governor.py:115-167`
- Evidence: exemption is a mutable display-name set plus category string, so many security sensors are slowed up to 8x under attacker-induced CPU/RAM pressure. There is no `finally` reset. A restarted governor starts at level 1 and, when load is low, never calls `_apply(1)`, leaving sibling modules at an old 8x throttle indefinitely.
- Impact: detection windows can widen precisely during pressure and remain widened after governor failure/restart while the new governor reports 100. Cooperative throttling still helps prevent suite OOM and named response modules remain exempt.
- Recommendation: use immutable capability/criticality metadata, minimum sensor deadlines and a manager-owned lease with expiry; reset all owned leases on stop/restart; reconcile actual sibling throttles every cycle; and degrade health for incomplete application or unavailable memory telemetry.

### C27-R1-C09 — Self-Healer permanently consumes crash snapshots before successful diagnosis

- Severity: **MEDIUM**
- Component: `src/angerona/modules/self_healer.py:118-161`, `src/angerona/modules/self_healer.py:163-216`, `src/angerona/modules/self_healer.py:254-264`
- Evidence: pre-launch snapshots are ignored and new filenames are added to `_seen` before parsing, source access, model diagnosis, syntax validation, or staging. Any transient failure is therefore at-most-once; the following empty poll overwrites health 50/70 with 100.
- Impact: a real crash can never receive a staged diagnosis after temporary file/model failure, while health says all work is complete.
- Recommendation: use durable states (`NEW`, `PROCESSING`, `RETRY`, `STAGED`, `REJECTED`) with bounded exponential retry/dead-letter, authenticate and size-bound snapshots, constrain source paths to the release/source root, and derive health from oldest pending age and terminal outcomes.

### C27-R1-C10 — Self-Integrity trusts its current runtime and silently omits missing enforcement targets

- Severity: **MEDIUM**
- Component: `src/angerona/modules/self_integrity.py:103-125`, `src/angerona/modules/self_integrity.py:181-231`, `src/angerona/modules/self_integrity.py:271-304`
- Evidence: `arm()` fingerprints whatever code is live at module start, skips every unresolved target, and health is set to 100 even when zero of six targets resolve. Fingerprints cover the selected callable but not mutable global/helper dependencies; ACL audit failures and detected weak ACLs do not lower health.
- Impact: pre-arm monkeypatching, missing imports, or replacement of referenced helpers can be accepted as the baseline and the dashboard can claim an intact enforcement core. Same-process code execution is required, and runtime replacement of a watched callable is detected.
- Recommendation: verify an independently signed release manifest before import, require every mandatory target and dependency closure, compare code/module file identities to the manifest, fail closed on unresolved targets/ACL collector errors, and expose watched/expected counts plus exact source lines.

### C27-R1-C11 — Shadow-copy dedup and coverage are PID-only and fail green

- Severity: **LOW**
- Component: `src/angerona/modules/shadowcopy_guard.py:153-157`, `src/angerona/modules/shadowcopy_guard.py:167-226`
- Evidence: `_alerted` is keyed only by PID even though `create_time` is collected. A rapid PID reuse between polls inherits the old suppression. Per-process command-line/access failures become an empty nonmatch and are not counted; the sweep still sets health 100.
- Impact: a recovery-tamper command can be missed during PID reuse or access-denied collection. Exact trusted-tool argv gating correctly prevents ambiguous commands from receiving host authority.
- Recommendation: key by PID, create time and executable identity; report enumerated/readable/denied/failed counts; ingest Sysmon/ETW process-create evidence for short-lived tools; and make incomplete coverage reduce health.

### C27-R1-C12 — SIEM health 100 means socket handoff, not collector ingestion

- Severity: **LOW**
- Component: `src/angerona/modules/siem_forwarder.py:183-210`, `src/angerona/modules/siem_forwarder.py:309-327`, `src/angerona/modules/siem_forwarder.py:367-394`
- Evidence: TCP/TLS `sendall()` or UDP `sendto()` immediately acknowledges and deletes the durable outbox row. No application receipt is required, yet an empty queue is health 100 while the note admits collector ACK is unavailable.
- Impact: a collector/proxy can accept bytes and discard them, causing irrecoverable evidence loss behind a green module. TLS-by-default, bounded durable staging, capacity-gap receipts, and retry on socket failure are strong controls.
- Recommendation: support an acknowledged protocol (RELP/HTTPS with idempotent event ID), retain until authenticated application ACK, separate transport from end-to-end delivery health, and display last acknowledged sequence/age.

### C27-R1-C13 — Honeytoken tamper handling enables memory exhaustion and repeated critical alerts

- Severity: **HIGH**
- Component: `src/angerona/modules/smart_deception.py:66-109`, `src/angerona/modules/smart_deception.py:224-257`, `src/angerona/modules/smart_deception.py:260-296`
- Evidence: `_check_decoy()` calls unbounded `f.read()` on a path whose overwrite is the attacker signal. A huge/sparse replacement can exhaust memory. After token loss/lock, `_trip()` calls `_write_decoy()`, but that helper refuses an existing file, so the same path emits CRITICAL every 2.5 seconds while health remains 100. Creation also uses check-then-create and can clobber a file won in the race.
- Impact: in opt-in user-folder mode, the actor being detected can crash or flood the EDR/event store. Default protected runtime-only placement lowers default exposure.
- Recommendation: open no-follow with stable identity, exclusive-create decoys, read exactly `len(anchor)+1` bytes under a size/type cap, quarantine/rename a tampered object safely before restaging, deduplicate by incident/object, rate-limit alerts, and report live/failed/tripped coverage below 100.

### C27-R1-C14 — Both SOAR loops commit revision cursors before processing the batch

- Severity: **MEDIUM**
- Component: `src/angerona/modules/soar.py:196-261`, `src/angerona/modules/soar_engine.py:160-240`
- Evidence: each priority/general `*_since()` call assigns its cursor to `current` before the returned oldest-first events are evaluated. An exception or module-generation failure partway through the list leaves the cursor past unprocessed events; only the legacy timestamp path advances per event.
- Impact: a malformed/buggy event can make later serious events in the same retained batch disappear from SOAR processing on restart of the same module instance. Overflow events are visible and response sinks independently revalidate authority.
- Recommendation: stage the batch and commit revision only after each admitted event reaches a terminal per-event receipt, persist idempotent delivery IDs, retry failures/dead-letter without advancing siblings, and include lag/drop/error age in health.

### C27-R1-C15 — Active SOAR can report old receipts as a new mitigation

- Severity: **MEDIUM**
- Component: `src/angerona/modules/soar_engine.py:383-428`, `src/angerona/modules/soar_engine.py:498-517`
- Evidence: receipt matching uses only near-equal trigger timestamp, module, verified integrity, and applied status. If delegation yields no new receipt, line 415 falls back to the entire prior matching list, making `mitigated=True` from an old action.
- Impact: duplicate timestamp/module evidence or a failed/asynchronous delegation can be presented as newly mitigated, hiding an uncontained incident. Combat remains the hardened mutation sink.
- Recommendation: create a fresh immutable correlation/action-request ID before delegation, require a receipt bound to it and the exact evidence/target digest, never fall back to prior receipts, and report timeout as unmitigated/pending.

### C27-R1-C16 — Speculative Triage reports 100 despite no production consumer, stale PID frames, or model failure

- Severity: **LOW**
- Component: `src/angerona/modules/speculative_triage.py:60-70`, `src/angerona/modules/speculative_triage.py:97-127`, `src/angerona/modules/speculative_triage.py:137-164`, `src/angerona/modules/speculative_triage.py:188-214`
- Evidence: repository-wide reference search found `get_primed()` only at its definition. Frames are keyed solely by PID with no expiry or birth identity; queue-full drops and Ollama errors are not health inputs, and the loop always reports 100.
- Impact: the advertised latency benefit is not realized, and a future consumer could reuse an unrelated process's stale prompt. Output is advisory/local and has no response authority.
- Recommendation: either wire the feature through a typed triage API or mark it unavailable; bind frames to process birth/image and incident ID, impose TTL/single-use, count queue/model failures, and derive health from successful reusable frames.

### C27-R1-C17 — Privileged storage migration reopens mutable pathnames after its safety scan

- Severity: **MEDIUM**
- Component: `src/angerona/modules/storage_hygiene.py:41-45`, `src/angerona/modules/storage_hygiene.py:87-140`, `src/angerona/modules/storage_hygiene.py:171-203`, `src/angerona/modules/storage_hygiene.py:237-258`
- Evidence: the legacy source is derived from mutable `LOCALAPPDATA`. Reparse/tree checks occur before string-path `shutil.move()`/`shutil.rmtree()`, and per-item checks still leave a swap window before the cross-volume move. Unreadable/reparse source state can also become `find_stray=False` and health 100.
- Impact: with opt-in auto-migration, an unprivileged writer racing the spill tree can make elevated Angerona copy/move a different tree or reparse-backed content into its protected data root. Explicit auto-migrate/purge gates and repeated reparse checks reduce exploitability.
- Recommendation: derive the canonical profile through OS APIs, use fixed-root directory handles and no-follow object identities, reopen/compare immediately before handle-relative move, claim destinations exclusively, run migration unelevated where possible, and model inaccessible/unsafe source as degraded—not clean.

### C27-R1-C18 — Module discovery executes an unpinned top-level `syscall_bridge` import

- Severity: **HIGH**
- Component: `src/angerona/modules/sys_bridge.py:41-47`, `src/angerona/modules/sys_bridge.py:52-69`, `src/angerona/modules/sys_bridge.py:188-221`
- Evidence: import-time `import syscall_bridge` uses ambient `sys.path`; there is no package-relative fixed artifact, release-manifest digest, signer, owner/DACL, reparse, ABI, or protocol validation. Any substitute Python module or native extension executes during discovery and can return plausible SSNs for health 100. The fallback native calls also omit HANDLE-safe ctypes prototypes.
- Impact: a writable current/import directory can turn elevation/module discovery into arbitrary code execution under the suite token. Protected installed/frozen layouts reduce exposure, but portable/developer launches remain material.
- Recommendation: package under a fixed private namespace, locate from the sealed release manifest, verify publisher/digest/owner/DACL/no-reparse before loading, isolate native code behind a least-privileged authenticated broker, validate ABI/protocol, and fully declare ctypes signatures.

### C27-R1-C19 — Sysmon cursor cannot prove log generation continuity and persistence failure is green

- Severity: **MEDIUM**
- Component: `src/angerona/modules/sysmon_listener.py:363-430`, `src/angerona/modules/sysmon_listener.py:476-568`, `src/angerona/modules/sysmon_listener.py:587-631`
- Evidence: authenticated state contains only channel and record number. If a cleared/refilled channel's new range already contains the old number, range checks accept it and seek past earlier events in the new generation. When the HMAC key is unavailable, `_save_cursor()` only sets `last_error`; first-run tail drain and later successful channel open can still show health 100. Reopen after a read error also does not reseek the durable cursor.
- Impact: clear/wrap/restart and cursor-custody failures can silently lose retained security events or create duplicates behind a healthy sensor.
- Recommendation: bind cursor to channel generation/file identity plus first/last event hashes/timestamps, persist atomically or fail health, reseek after every reopen, emit explicit loss ranges, and show durable cursor age/sequence and parse rejection counts.

### C27-R1-C20 — Temporal correlator health never follows its live assessment state

- Severity: **LOW**
- Component: `src/angerona/modules/temporal_tradecraft_correlator.py:150-219`, `src/angerona/modules/temporal_tradecraft_correlator.py:384-416`
- Evidence: health is set once to 35 or 70 during startup. Later `stable`, `missing`, `blind`, `overflow`, and recovered assessments emit events but never update the score/note.
- Impact: the row can remain 70 after restart continuity has recovered, or remain 70 when later blind/overflow state warrants worse health; operators cannot use the percentage as current completeness.
- Recommendation: map every assessment state, persistence status, dropped count and evidence age to an atomic health snapshot; recover health only after a complete window; link the current continuity reason and state file.

### C27-R1-C21 — One failed USB identity probe can transfer trust to replacement media

- Severity: **MEDIUM**
- Component: `src/angerona/modules/usb_monitor.py:474-520`; approval state `src/angerona/core/usb_policy.py:299-355`, `src/angerona/core/usb_policy.py:424-469`
- Evidence: same-letter replacement is recognized only when both old and current volume identities are nonempty and differ. If the new device's identity probe returns empty once, `_known_identities` is overwritten with empty; a later successful different identity no longer satisfies the swap predicate, and the existing trusted mount record is retained.
- Impact: a physical/local attacker can replace approved media between polls while inducing/transiently hitting metadata failure, causing Angerona scanners to treat the new volume as trusted. The PIN controls Angerona workflows only and correctly does not claim OS device denial.
- Recommendation: fail trust closed whenever a trusted volume identity becomes unknown, never overwrite last-known identity with an unknown, bind approval to stable volume/device instance plus insertion epoch, revalidate before every scan, and surface identity-coverage failures in health.

### C27-R1-C22 — Watchdog does not detect the hung modules advertised by its contract

- Severity: **MEDIUM**
- Component: `src/angerona/modules/watchdog_monitor.py:30-55`, `src/angerona/modules/watchdog_monitor.py:57-93`
- Evidence: `_module_dead()` checks only status `error` or a dead thread. A live thread blocked forever with status `running` is considered healthy; no cycle-completion age, heartbeat, deadline, or queue progress is inspected. Restart counts never decay, and a permanently down module emits CRITICAL every sweep.
- Impact: a sensor can hang indefinitely while watchdog health says “all modules healthy”; repeated failures can also create an alert storm and exhaust a lifetime restart budget despite long stable intervals.
- Recommendation: consume manager-owned generation/cycle heartbeats with per-module deadlines, distinguish slow/busy/hung, use a restart lease and bounded backoff, decay/reset budgets after stability, deduplicate terminal alerts, and lower health while any required module is stale/down.

### C27-R1-C23 — WFP Controller neither uses WFP telemetry nor proves any network coverage

- Severity: **MEDIUM**
- Component: `src/angerona/modules/wfp_controller.py:164-237`, `src/angerona/modules/wfp_controller.py:258-287`, `src/angerona/modules/wfp_controller.py:477-530`
- Evidence: `_try_init_wfp()` only loads `fwpuclnt.dll`; `_refresh()` always uses IP Helper tables. The map key is just `(protocol, local_port)`, overwriting address/family/connection collisions and retaining no remote endpoint/state. `_scan_suspicious()` describes outbound traffic but emits on local ports. Missing APIs, per-table exceptions, psutil absence, or an empty table still leave health 100.
- Impact: operators can believe WFP/outbound monitoring is active while the module has only ambiguous local endpoint ownership, producing both blind spots and repeated false alerts.
- Recommendation: implement a versioned WFP/ETW net-event collector or rename the capability honestly; retain full five-tuple, direction, PID birth/image and source sequence; count per-family collection failures/collisions; deduplicate alerts; and cap health by proven source coverage.

### C27-R1-C24 — Disconnect/reconnect is a deterministic Evil-Twin detection bypass

- Severity: **MEDIUM**
- Component: `src/angerona/modules/wlan_monitor.py:109-149`, `src/angerona/modules/wlan_monitor.py:151-214`
- Evidence: any query failure/disconnect sets `_last=None`. The next connection is always informational and immediately added to history, even when a known SSID now has a never-seen BSSID. A failed/disconnected initial probe parks the module in a permanent idle loop, and later query failures do not lower health. Baseline is volatile first-observation trust.
- Impact: a nearby attacker can force a disconnect and lure the host to an Evil Twin; the exact new BSSID transition the module advertises will not alert. TLS and other NDR controls limit but do not remove MITM exposure.
- Recommendation: distinguish collector error from disconnected state, retry startup, persist an authenticated/operator-approved per-SSID BSSID/security baseline, evaluate every reconnect against it before enrollment, ingest native WLAN notifications/security properties, and expose freshness/coverage in health.

### C27-R1-C25 — A 10,000-file prefix can starve YARA coverage indefinitely

- Severity: **MEDIUM**
- Component: `src/angerona/modules/yara_scanner.py:19-24`, `src/angerona/modules/yara_scanner.py:151-174`, `src/angerona/modules/yara_scanner.py:184-210`, `src/angerona/modules/yara_scanner.py:251-267`
- Evidence: traversal stops after 10,000 yielded files per root with no continuation cursor, rotation, truncation event, or health change. Enumeration errors and per-file scan/timeouts only update `last_error`; each cycle restarts from the same filesystem order at health 100.
- Impact: an attacker who can populate Downloads can keep a malicious file outside the repeatedly scanned prefix. In-process YARA-X, file-size/scan timeouts, no-follow directory checks, and compile-gated rule activation are strong controls.
- Recommendation: use a durable fair cursor/rotation keyed by stable file identity, prioritize new/changed files from filesystem telemetry, publish visited/skipped/truncated/timeout counts and oldest-unscanned age, and lower health whenever a root is incomplete.

## Per-file review ledger

| File | Lines | Disposition | Finding IDs / evidence | Recommendation |
|---|---:|---|---|---|
| `provenance_graph.py` | 1-379 | FINDING | C27-R1-C01; PID-only lifetime and green source gaps | Birth-bound graph identities and completeness receipts |
| `purple_guard.py` | 1-504 | FINDING | C27-R1-C02; lost policy becomes learning mode | Authenticated policy lifecycle and fail-visible health |
| `rag_provenance_guard.py` | 1-201 | NO_NEW_FINDING | Strict manifest loader, bounded schema, observe-only output, and degraded missing/invalid health held | Retain manifest provenance tests and runtime wiring evidence |
| `ransomware_heuristics.py` | 1-429 | FINDING | C27-R1-C03; only direct child files observed | Bounded recursive/journal coverage |
| `release_transparency_guard.py` | 1-238 | NO_NEW_FINDING | Threshold authorization, payload verification and authenticated floor held; pathname TOCTOU is within the already documented local trust-root limit | Prefer opened-object verification in future updater integration |
| `remediation_actions.py` | 1-1893 | FINDING | C27-R1-C04/C05/C06; target authority and external-state conflicts | Typed authenticated targets plus resource CAS |
| `remote_bridge.py` | 1-899 | FINDING | C27-R1-C07; PSK-only sessions | Ephemeral authenticated transport and rotation |
| `resource_governor.py` | 1-176 | FINDING | C27-R1-C08; brittle exemptions and stale leases | Manager-owned expiring throttle leases |
| `self_healer.py` | 1-299 | FINDING | C27-R1-C09; at-most-once snapshots | Durable retry/dead-letter workflow |
| `self_integrity.py` | 1-317 | FINDING | C27-R1-C10; TOFU and optional targets | Signed mandatory dependency closure |
| `shadow_shield.py` | 1-397 | PRIOR_OPEN_NOT_REREPORTED | Scoped digest-bound restore exists; legacy broad `trigger_rollback()` remains known and has no current production caller | Remove/private-gate legacy sink; object-bind cache creation |
| `shadowcopy_guard.py` | 1-241 | FINDING | C27-R1-C11; PID-only suppression/coverage | Birth-bound dedup and collection counters |
| `siem_forwarder.py` | 1-444 | FINDING | C27-R1-C12; socket handoff is terminal | End-to-end acknowledged delivery |
| `smart_deception.py` | 1-308 | FINDING | C27-R1-C13; unbounded read and non-restaging storm | Bounded object-safe tamper handling |
| `soar.py` | 1-527 | FINDING_AND_PRIOR_OPEN | C27-R1-C14; known R5-03 PID-only corroboration remains separate | Per-event cursor commit; birth-bound corroboration |
| `soar_engine.py` | 1-517 | FINDING | C27-R1-C14/C15; cursor and receipt attribution | Correlation-ID-bound idempotent receipts |
| `speculative_triage.py` | 1-236 | FINDING | C27-R1-C16; unused/stale frames and green failures | Wire safely or mark unavailable |
| `ssh_surface_guard.py` | 1-978 | NO_NEW_FINDING | Complete manual review: authenticated baseline, producer broker, bounded object reads, explicit coverage/retry states and observe-only output held | Retain channel-generation and hostile-config regressions |
| `storage_hygiene.py` | 1-355 | FINDING | C27-R1-C17; safety-check/use race | Handle-relative least-privilege migration |
| `sys_bridge.py` | 1-253 | FINDING | C27-R1-C18; ambient native import | Sealed private native broker/artifact |
| `sysmon_listener.py` | 1-761 | FINDING | C27-R1-C19; generationless cursor | Generation-bound durable continuity |
| `temporal_tradecraft_correlator.py` | 1-419 | FINDING | C27-R1-C20; health frozen at startup | Assessment-derived live health |
| `usb_monitor.py` | 1-681 | FINDING | C27-R1-C21; unknown identity carries trust | Fail-closed insertion identity binding |
| `watchdog_monitor.py` | 1-131 | FINDING | C27-R1-C22; no hung/stale detection | Cycle-heartbeat supervision |
| `wfp_controller.py` | 1-547 | FINDING | C27-R1-C23; advertised WFP/outbound path absent | Real WFP/ETW full-tuple collector |
| `wlan_monitor.py` | 1-224 | FINDING | C27-R1-C24; reconnect bypass and volatile TOFU | Persistent approved WLAN baseline |
| `yara_scanner.py` | 1-267 | FINDING | C27-R1-C25; deterministic cap starvation | Fair durable traversal and coverage health |

## Prior-finding reconciliation

Verified resolved or materially mitigated in this shard: **7**.

- `A-07` resolved: Shadow Shield path keys use SHA-256 (`shadow_shield.py:77-82`).
- `R6-01` resolved: Shadow-Copy host authority requires exact trusted recovery-tool argv; ambiguous PowerShell remains alert-only (`shadowcopy_guard.py:95-139,199-221`).
- `R6-02` resolved in its original scope: ransomware entropy/rename corroboration is normalized to the same directory; C27-R1-C03 is the distinct recursive-coverage gap.
- `C7-R3-01` resolved: Remote Bridge strips receiver-local action keys and forces remote observe-only authority (`remote_bridge.py:843-866`).
- `C26-R2-D06`, `C26-R2-D07`, and `C26-R2-D08` verified remediated: proposal dominance, truthful rollback/circuit handling, and pathname-only quarantine were replaced by typed/durable/object-bound paths.

Verified still open or deferred, not duplicated as new findings: **5**.

- `A-04`: arbitrary admitted in-process extension code still shares the suite token; architectural isolation remains deferred.
- `A-06`: Shadow Shield retains broad PowerShell VSS command trust (`shadow_shield.py:325-364`).
- `R5-03`: SOAR corroboration remains PID-only (`soar.py:105-108,361-394`), although final containment now revalidates exact identity in Combat.
- `R5-04` residual: public legacy `trigger_rollback()` still trusts cache pathnames (`shadow_shield.py:274-322`), but repository search found no production caller; safe mobile flow uses the scoped artifact API.
- Cycle-26 response-custody recovery limitation: crashed `PREPARED`/`MUTATING` transactions remain fail-closed and require separately governed repair; current explicit reconciliation claims only `RECOVERY_REQUIRED`. This is availability debt, not re-reported here.

## Validation and safety

- Manual context review: **PASS**, all 27 assigned files read in full and represented once in the ledger.
- Prior reconciliation: **PASS**, known issues were credited or retained without duplicate IDs.
- Scope safety: **PASS**, no payload, exploit execution, web research, network activity, credential access, host mutation, source edit, shared log edit, commit, or publication.
