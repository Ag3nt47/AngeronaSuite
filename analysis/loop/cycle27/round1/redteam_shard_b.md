# Cycle 27, Round 1 — Defensive Red-Team Shard B

Scope: exhaustive, inert review of the 31 assigned files in `src/angerona/modules/`. No product code, host posture, network resource, shared loop log, or publication state was changed. Findings below require a concrete code path and are rated for Angerona's intended single-host deployment. Existing controls are credited explicitly.

## Result

| Severity | New findings |
|---|---:|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 11 |
| LOW | 7 |
| INFO | 0 |
| **Total** | **20** |

The most material issues are a basename-only exclusion that lets an attacker opt out of memory-injection scanning, and an unpinned `signal-cli` subprocess boundary that can inherit mobile credentials and forge commands into a host-response surface.

## Findings

### C27-R1-B01 — FRZ watchdog trust is signer-generic, pathname-based, and cached

- Severity: **MEDIUM**
- Component: `src/angerona/modules/frz_heartbeat.py:56-88`, `src/angerona/modules/frz_heartbeat.py:163-188`; trust helper `src/angerona/core/executable_trust.py:10-44`
- Evidence: `_watchdog_path()` selects the first existing filename next to the interpreter or in the repository. `_trusted_watchdog_path()` caches one mutable pathname for the process lifetime. `executable_is_trusted()` rejects a symlink and checks only that Authenticode reports `Valid`; it does not pin Angerona's publisher, an expected digest, owner/DACL, link count, or an opened file object. `_launch_watchdog()` later reopens that pathname with an inherited environment.
- Impact: a locally replaceable but validly signed substitute can execute with the suite's token and inherited environment, or a checked file can be replaced between verification and launch. A protected installed directory and the valid-signature requirement materially reduce exploitability; source/portable deployments and writable sidecar directories remain exposed.
- Recommendation: bind launch to a sealed release manifest and exact publisher/digest, verify owner/DACL/reparse/link state, stage or retain the verified object through launch, pass a minimal environment, and do not cache trust for a mutable pathname. Health should expose exact sidecar identity and trust failure.

### C27-R1-B02 — Hermetic status and build launch do not bind to a reviewed binary/script identity

- Severity: **MEDIUM**
- Component: `src/angerona/modules/hermetic_packager.py:43-80`, `src/angerona/modules/hermetic_packager.py:117-150`
- Evidence: `_is_frozen()` trusts forgeable Python metadata, `_find_binary()` accepts the first neighboring/dist filename rather than the current OS process image, and `_check_signature()` accepts any valid Authenticode signer. `_assess()` can therefore return 100 for a different file. `trigger_build()` immediately launches the mutable repository batch through PATH-resolved `cmd` after emitting a “review gated” message; no explicit confirmation or object-integrity check occurs.
- Impact: the UI can overstate packaging provenance, and a build click can execute a substituted script/interpreter under the current token. The action requires an operator click and normally lives in a developer-controlled tree, which limits exploitability.
- Recommendation: derive the current image with an OS API, verify a signed manifest plus pinned publisher/digest/owner/DACL, and separate “frozen,” “signed,” and “current image verified” health factors. Require explicit confirmation after showing the exact digest/diff, use the absolute trusted command processor, a minimal environment, and never run the build elevated.

### C27-R1-B03 — Hardware-Rooted Integrity can report 100 while TPM binding is explicitly absent

- Severity: **LOW**
- Component: `src/angerona/modules/hardware_crypto.py:100-111`, `src/angerona/modules/hardware_crypto.py:153-173`, `src/angerona/modules/hardware_crypto.py:184-199`
- Evidence: the module accurately describes TPM database-key sealing as unsupported, and `bind_db_key_to_tpm()` always returns false even when the dependency is present. Nevertheless, a successful DPAPI IPC-key check sets overall module health to 100 and the periodic loop continues to report 100 without incorporating `tpm_ok`.
- Impact: dashboards and automation can interpret 100 as complete hardware-rooted integrity although database-at-rest TPM binding is not present. DPAPI protection is real and the description is candid, so this is an accuracy/assurance weakness rather than a direct bypass.
- Recommendation: expose independent capability scores for protected IPC secret custody and TPM database sealing/attestation; cap aggregate health below 100 until the advertised hardware binding is proven, and link the missing capability to `bind_db_key_to_tpm()`.

### C27-R1-B04 — Judgment subprocess text can certify or “promote” a control without authenticated success

- Severity: **MEDIUM**
- Component: `src/angerona/modules/intel_sync.py:465-479`, `src/angerona/modules/intel_sync.py:546-573`, `src/angerona/modules/posture_hardening.py:903-929`
- Evidence: both call `sys.executable -m angerona.shark.verify`, then accept the first stdout/stderr line containing `VERIFICATION_RESULT:`. Neither requires return code zero, an exact schema, a run nonce, the tested artifact digest, or a recorder receipt. Intel Sync inherits the ambient environment/current directory and sets `rec["active"] = True` while announcing “rule promoted,” although this path installs no rule. Posture Hardening similarly certifies and calls `mark_patched()` on the marker alone. An inert monkeypatch returned `BLOCKED` with `returncode=9`; the method still added the technique to `_certified`.
- Impact: import shadowing, a substituted child, dependency output, or a stale/spoofed marker can create false interception assurance and close a real weakness. Operator action is required for these paths, and generated advice remains inert, limiting automatic impact.
- Recommendation: invoke an isolated, trusted bootstrap (`-I`, fixed trusted working directory and source closure), bound output/resources, require exit zero, and accept only a strict JSON receipt containing a fresh nonce, technique, build/rule digest, test identity, sequence, and independently verified recorder signature. Never say “active/promoted” without an installed rule identity and postcondition.

### C27-R1-B05 — Kernel Bridge treats a device-name open as proven sensor health

- Severity: **MEDIUM**
- Component: `src/angerona/modules/kernel_bridge.py:70-108`, `src/angerona/modules/kernel_bridge.py:167-215`
- Evidence: `CreateFileW` and `DeviceIoControl` are used without complete ctypes prototypes. After any handle to the fixed device name opens, `_verify_version()` may receive no response or any version and `run()` still unconditionally sets health to 100. Later telemetry IOCTL failures return silently without degrading or reopening the bridge. No expected protocol tag/version, driver service/file identity, publisher, digest, or device ACL is checked.
- Impact: an incompatible or substituted device can produce false “kernel callbacks connected” assurance, while handle truncation or IOCTL failure can silently eliminate telemetry. Creating a kernel device ordinarily requires administrative/signed-driver authority, which lowers exploitability.
- Recommendation: declare every native signature, require an exact protocol/capability handshake, bind the device to the expected service and pinned signed driver identity, validate the device ACL, track sequence/loss/heartbeat, and degrade/reconnect immediately on IOCTL or parse failure.

### C27-R1-B06 — Kernel driver inventory can truncate or fail closed as an apparently complete digest

- Severity: **MEDIUM**
- Component: `src/angerona/modules/kernel_posture_ledger.py:132-172`, `src/angerona/modules/kernel_posture_ledger.py:182-230`, `src/angerona/modules/kernel_posture_ledger.py:393-417`
- Evidence: `_driver_services()` enumerates only `min(count, 2048)`, silently skips per-key errors, and returns an empty list on registry-open failure. The snapshot records only `driver_count` and a digest; it carries no total, truncation, skipped, or collector-status field. `assess()` does not consider driver inventory completeness, so the module may report “posture verified” and health 100 for a partial/empty inventory.
- Impact: driver-service drift can be absent from an authenticated ledger while consumers believe the snapshot is complete. Other Secure Boot/HVCI checks remain useful and unknown booleans are scored honestly.
- Recommendation: return a typed collection receipt with total/enumerated/skipped/truncated/error counts and collection epoch; treat anything short of complete as UNKNOWN and below 100, paginate boundedly across the full namespace, and expose exact rejected paths/errors without sensitive values.

### C27-R1-B07 — A basename alone disables Memory Injection Scanner coverage

- Severity: **HIGH**
- Component: `src/angerona/modules/mem_inject_scanner.py:66-80`, `src/angerona/modules/mem_inject_scanner.py:120-146`, `src/angerona/modules/mem_inject_scanner.py:186-226`, `src/angerona/modules/mem_inject_scanner.py:228-268`
- Evidence: `_scan_all_pids()` skips every process whose unverified basename appears in `_JIT_SAFE_NAMES` (`python.exe`, `chrome.exe`, and others), before opening or resolving its executable. This directly contradicts the adjacent comment that basename must not grant trust. The Toolhelp enumeration APIs and `CloseHandle` also lack explicit HANDLE-safe prototypes; all enumeration exceptions are swallowed into an empty map. `run()` sets health 100 before proving any PID was enumerated/opened/scanned. An inert fixture containing `chrome.exe` and a non-allowlisted process reaches `_scan_pid()` only for the latter.
- Impact: an attacker can rename a payload to an allowlisted basename, or inject into a real allowlisted process, to remove it entirely from this sensor. Enumeration ABI failure can blind the whole module while health stays green. Other process/behavior sensors may still detect the attack, but this module's central T1055 claim is bypassed.
- Recommendation: never skip memory inspection by basename. Resolve process birth, object-bound image path, signer/digest, and policy only to tune severity after inspection. Define all A/W Toolhelp/HANDLE prototypes, close in `finally`, and report totals for enumerated/opened/scanned/denied/failed/skipped with health below 100 for incomplete coverage.

### C27-R1-B08 — Memory Time-Machine drops telemetry after permanently deduplicating it

- Severity: **MEDIUM**
- Component: `src/angerona/modules/memory_timemachine.py:85-94`, `src/angerona/modules/memory_timemachine.py:165-186`, `src/angerona/modules/memory_timemachine.py:207-229`, `src/angerona/modules/memory_timemachine.py:232-291`
- Evidence: `delta_for()` records hashes before queue admission. `_sweep()` increments `_forwarded` before `put_nowait()` and silently drops `queue.Full`; the same strings will then be suppressed until cache eviction. The mmap ring overwrites its oldest record without a loss counter. A ring-open failure initially sets health 40, but the next sweep sets 100 because `reduction_pct >= 0` is tautologically true. Opt-in mode also collects full environment values and writes carved strings to a plaintext persistent mmap.
- Impact: event bursts can deterministically erase novel indicators and prevent retry while telemetry and health metrics claim they were forwarded. The opt-in environment capture can persist secrets. The feature is local and bounded in size, limiting blast radius.
- Recommendation: commit dedup state only after durable admission or maintain a retry spool; count queue/ring drops, overwrites, collector failures, high-water and age; make health depend on complete delivery; use bounded backpressure; and encrypt/restrict/zeroize persistent telemetry. Keep environment collection separately consented and redact secret-like keys.

### C27-R1-B09 — Mobile response trusts an unpinned external CLI that inherits credentials

- Severity: **HIGH**
- Component: `src/angerona/modules/mobile_bridge.py:135-205`, `src/angerona/modules/mobile_bridge.py:803-837`
- Evidence: configured `signal-cli` is launched directly with inherited cwd/environment; there is no absolute-path, owner/DACL, reparse, publisher, digest, or retained-object check. The environment can contain the portable plaintext PIN or same-user-decryptable DPAPI PIN blob. Receive output is accepted as the sender/message authority without checking return code, bounding total output, or authenticating a local transcript. `self_test()` proves only path existence, and a send/receive health failure can be overwritten by the loop's unconditional 100.
- Impact: a locally replaced/configured CLI can steal the mobile PIN, forge the configured sender and command stream, and reach lockdown or token-gated host responses under the suite's token. Signal end-to-end encryption and sender comparison protect the remote channel, but do not authenticate the local executable boundary. The module is opt-in, reducing default exposure.
- Recommendation: seal an absolute CLI artifact to a pinned digest/publisher/owner/DACL/no-reparse policy and bind launch to the verified object; provide a minimal environment with no Angerona secrets; use authenticated, bounded IPC receipts with nonces and return-code checks; impose job/time/output limits; and score health from a verified round trip and binary identity.

### C27-R1-B10 — Mobile ECO/LOCKDOWN authorization is weaker than the response surface

- Severity: **MEDIUM**
- Component: `src/angerona/modules/mobile_bridge.py:143-163`, `src/angerona/modules/mobile_bridge.py:333-405`, `src/angerona/modules/mobile_bridge.py:436-456`
- Evidence: after sender-number comparison, `ECO ON/OFF` changes monitoring cadence without a PIN or token. `LOCKDOWN` accepts only a fixed four-digit PIN. Authentication failures are logged but have no attempt counter, rate limit, lockout, replay window, or monotonic challenge. ECO directly calls `set_throttle()` across non-response modules.
- Impact: compromise/spoofing of the configured messaging identity can reduce monitoring cadence immediately, then try at most 10,000 PINs for lockdown. Signal transport identity is a meaningful first factor and KILL/SUSPEND/ROLLBACK additionally require short-lived alert tokens.
- Recommendation: apply a typed authorization policy to every state change, including ECO/MUTE; require a fresh cryptographic challenge plus protected approval for lockdown; rate-limit and lock out failures by identity/session; bind tokens to command/target/expiry/nonce; and return a signed state-change receipt with rollback information.

### C27-R1-B11 — IPv4-mapped public IPv6 endpoints are classified as local

- Severity: **MEDIUM**
- Component: `src/angerona/modules/network_monitor.py:133-148`, `src/angerona/modules/network_monitor.py:250-305`
- Evidence: `_is_local()` returns true for every string beginning with `::`. The inert check `_is_local('::ffff:8.8.8.8')` returned `True` while `_is_local('8.8.8.8')` returned `False`. The loop discards “local” endpoints before IOC, suspicious-port, and novelty logic. Novelty is also keyed by `(pid, ip)` rather than `(pid, process_create_time, canonical_ip)`.
- Impact: external connections represented as IPv4-mapped IPv6 bypass this network detector, and rapid PID reuse can inherit old novelty state. Other NDR layers may retain visibility.
- Recommendation: canonicalize with `ipaddress.ip_address()`, convert `ipv4_mapped` before classification, use explicit loopback/private/link-local policy, normalize zone IDs/endpoints, and bind process state to birth time from the same snapshot. Add mapped-address regression fixtures.

### C27-R1-B12 — Packet Sniffer can deadlock on its undrained worker pipe

- Severity: **MEDIUM**
- Component: `src/angerona/modules/packet_sniffer.py:92-157`, `src/angerona/modules/packet_sniffer_worker.py:26`, `src/angerona/modules/packet_sniffer_worker.py:48-89`
- Evidence: the parent redirects stdout to a pipe, polls only for child exit, and reads stdout only after exit. The worker emits and flushes up to 256 JSON records from inside the capture callback. Once the OS pipe fills, the worker blocks in `print()`, cannot finish its Scapy timeout, and the parent has no absolute deadline. The child also uses `sys.executable -m` without isolated import/cwd or OS job resource limits.
- Impact: sufficiently dense cleartext-token traffic can wedge the capture generation indefinitely and leave module health stale. The module is disabled by default and records classifications rather than payload contents.
- Recommendation: drain stdout concurrently with a strict byte/record cap, enforce a parent-side hard deadline and process-tree termination, use a trusted isolated child bootstrap, place it in CPU/memory/process limits, and require an end receipt carrying packet/record/drop/error counts.

### C27-R1-B13 — Forensic capture has no memory, disk, or privacy budget

- Severity: **MEDIUM**
- Component: `src/angerona/modules/forensics.py:49-80`, `src/angerona/modules/forensics.py:106-135`, `src/angerona/modules/forensics.py:137-178`, `src/angerona/modules/forensics.py:193-200`
- Evidence: any HIGH event with an integer PID can initiate capture. Supplied event birth time is trusted and marked captured before a process handle/image is verified. Each committed region is allocated as one `ctypes` buffer and printable strings are written without per-region, per-case, total-byte, time, retention, or free-space limits. Every case copies the current operator's complete PowerShell history, unrelated to the suspect PID.
- Impact: a process with a very large committed region or repeated serious-event identities can exhaust RAM/disk and collect unrelated credentials/commands. The module is disabled by default and failures are locally contained, reducing baseline exposure.
- Recommendation: bind a retained handle to verified PID/create-time/image before admission; require trusted event provenance; read in fixed chunks; enforce region/case/time/free-space/global-retention quotas; encrypt and ACL evidence; redact secrets; and make shell-history capture separately consented and case-relevant. Report coverage and truncation in health.

### C27-R1-B14 — Unvalidated technique IDs escape the posture remediation directory

- Severity: **LOW**
- Component: `src/angerona/modules/posture_hardening.py:370-394`, `src/angerona/modules/posture_hardening.py:767-800`; input policy `src/angerona/core/report_attest.py:134-157`
- Evidence: report `mitre` values are used directly in `self.remediations / f"{mitre}.advisory.md"` and written without a strict technique-ID schema or resolved-path containment check. Unsigned reports are ingested in the default lenient mode. The forced `.advisory.md` suffix constrains the target type but does not prevent `..`, rooted, or separator-bearing values from escaping the intended directory.
- Impact: a writable or imported unsigned AAR can overwrite/create an advisory-suffixed file anywhere accessible to the process and poison weakness records. The content is explicitly inert and the forced extension limits code-execution value.
- Recommendation: accept only canonical `Tdddd`/`Tdddd.ddd` identifiers, derive a fixed safe slug, resolve and verify containment under `remediations`, use exclusive/atomic no-follow writes, and require authenticated reports by default for any filesystem/database mutation.

### C27-R1-B15 — Missing posture evidence is rendered as “posture clean”

- Severity: **LOW**
- Component: `src/angerona/modules/posture_hardening.py:354-368`, `src/angerona/modules/posture_hardening.py:758-764`
- Evidence: unreadable/missing/untrusted reports only return or update `last_error`; the run loop does not degrade health. `_recompute_health()` equates zero database rows in `VULNERABLE` state with health 100 and note “posture clean,” without proving feed presence, freshness, authenticity, expected coverage, or a completed assessment.
- Impact: first-run, stale, or broken evidence can look indistinguishable from an evidence-backed clean posture. The module does alert integrity failures and does not automatically execute model advice.
- Recommendation: model `UNKNOWN`, `STALE`, `UNTRUSTED`, `PARTIAL`, and `ASSESSED_CLEAN` separately; require a fresh authenticated coverage receipt before 100; include source path, last successful epoch, expected/observed rounds, and exact failure line in details.

### C27-R1-B16 — PID-only state can suppress new process and LSASS detections after reuse

- Severity: **LOW**
- Component: `src/angerona/modules/lsass_guard.py:171-175`, `src/angerona/modules/lsass_guard.py:193-234`, `src/angerona/modules/process_monitor.py:37-40`, `src/angerona/modules/process_monitor.py:87-140`
- Evidence: both modules deduplicate by integer PID. LSASS Guard retains a PID while it appears in the current live set; Process Monitor primes and carries only PID values. If one process exits and another receives the same PID between snapshots, the PID never disappears from the live set and the new generation is skipped. Both already collect `create_time` but do not use it for state identity.
- Impact: a narrow timing window can suppress process-creation evaluation or one credential-dump alert. Exploitation requires controlling or winning PID reuse timing and other sensors may still alert.
- Recommendation: key state by `(pid, normalized_create_time)` and verify executable object identity; treat missing birth time as incomplete coverage, expire by generation/TTL, and add deterministic same-PID/new-birth fixtures.

### C27-R1-B17 — File Integrity Monitor uses startup TOFU and silently excludes failed/metadata-preserving changes

- Severity: **MEDIUM**
- Component: `src/angerona/modules/file_integrity.py:194-218`, `src/angerona/modules/file_integrity.py:239-284`, `src/angerona/modules/file_integrity.py:354-359`, `src/angerona/modules/file_integrity.py:374-443`
- Evidence: the baseline is an in-memory snapshot built at module startup with no authenticated persisted reference or operator approval. Hash/stat exceptions are silently represented as absence. Non-high-value files reuse a prior digest whenever size and `mtime_ns` match; the source explicitly acknowledges the evasion. The module does not record scanned/failed/excluded counts or set health based on coverage, so BaseModule's default green state survives empty/partial scans.
- Impact: preexisting tampering is enrolled, inaccessible paths vanish as apparent deletions/absence, and an attacker able to preserve size and mtime can modify ordinary watched files without detection. High-value/paranoid roots are always rehashed, which narrows the bypass.
- Recommendation: persist an authenticated, reviewed baseline with provenance; hash an opened no-follow object and revalidate identity/metadata after reading; add USN/event-assisted invalidation or randomized full rehash; explicitly count roots/files/failures/exclusions; and reserve 100 for complete fresh coverage.

### C27-R1-B18 — Large startup entries are monitored by forgeable metadata only

- Severity: **LOW**
- Component: `src/angerona/modules/persistence_sweep.py:252-313`
- Evidence: startup files larger than `_MAX_STARTUP_HASH_BYTES` receive the literal digest `not-hashed-size-bound`; their drift identity is only path, size, and `mtime_ns`. Content can be changed while restoring both metadata fields. The module does honestly keep its startup baseline unreviewed at health 75 and exposes partial collector errors.
- Impact: an oversized startup payload can change without triggering persistence drift. Creating and preserving a large startup file requires local filesystem access and may be caught by other file/process controls.
- Recommendation: compute streaming hashes regardless of size under a per-cycle I/O budget, carry deferred/pending state rather than metadata-only completeness, use file IDs/no-follow opens and post-read revalidation, and prioritize executable/script startup entries.

### C27-R1-B19 — Concurrent Evolution workers can lose or corrupt proposal history

- Severity: **LOW**
- Component: `src/angerona/modules/evolution_engine.py:147-153`, `src/angerona/modules/evolution_engine.py:401-470`
- Evidence: different techniques may run in separate worker threads. `_record_history()` performs an unlocked read/append/full-file write, is not atomic, and swallows every exception. Two workers can read the same history and last-writer-wins, or a crash can leave partial JSON. One finishing worker also sets module health 100 while another may still be drafting.
- Impact: review evidence for inert proposals can disappear or become unreadable, weakening auditability and giving an inaccurate lifecycle state. The engine remains proposal-only and cannot activate generated rules, sharply limiting security impact.
- Recommendation: serialize history under the engine lock or append to a transactionally durable store, write atomically with fsync/replace, expose write failures, assign proposal/run IDs, and derive health from all active workers plus durable receipt status.

### C27-R1-B20 — IPC Guard can remain health 100 after its accept loop exits

- Severity: **LOW**
- Component: `src/angerona/modules/ipc_guard.py:306-355`, `src/angerona/modules/ipc_guard.py:370-426`
- Evidence: an `OSError` in `accept()` breaks the daemon accept loop without recording an error or changing health. The parent generation loop never tests `accept_thread.is_alive()` and continues setting health 100 every five seconds. Worker-start failure similarly stops the accept loop, but the parent can overwrite its health 40 on the next tick.
- Impact: the loopback authentication probe can be unavailable while dashboards report it healthy. The listener is loopback-only, bounded, HMAC-authenticated, and intentionally carries no production commands, so host-security impact is low.
- Recommendation: propagate an accept-loop terminal receipt/error to the generation, require listener and worker liveness for green health, restart with bounded backoff when safe, and retain the first failure until a verified end-to-end challenge succeeds.

## Per-file review ledger

Every assigned file was read in full. “No new formal finding” means no new exploitable weakness was confirmed in this round; it is not a claim of proof-of-security.

| File | Reviewed lines | Disposition | Finding IDs | Pinpoint conclusion / tune-up |
|---|---:|---|---|---|
| `evolution_engine.py` | 1-513 | Finding | C27-R1-B19 | Proposal-only authority boundary is preserved; concurrent history durability/aggregate health is weak. |
| `fast_path.py` | 1-312 | No new formal finding | — | Alert-only fast path is deterministic and bounded. Add per-rule coverage counters and exact evidence links to improve explainability. |
| `file_integrity.py` | 1-443 | Finding | C27-R1-B17 | Startup TOFU, silent exclusions, and metadata-cache evasion prevent complete health claims. |
| `flight_cache.py` | 1-251 | No new formal finding | — | Read-only SQL verb filtering is present. Tune up with SQLite authorizer/progress deadline and returned-row cap for recursive/expensive `WITH` queries. |
| `forensics.py` | 1-200 | Finding | C27-R1-B13 | Capture authority, resource budgets, and unrelated shell-history privacy need hard limits. A-05 shell injection remains resolved. |
| `frz_heartbeat.py` | 1-322 | Finding | C27-R1-B01 | Authenticated v2 heartbeat is strong; sidecar object/supply-chain binding is incomplete. |
| `hardware_crypto.py` | 1-215 | Finding | C27-R1-B03 | DPAPI path is useful and candid; aggregate 100 does not represent absent TPM sealing. |
| `hermetic_packager.py` | 1-201 | Finding | C27-R1-B02 | Current-image provenance and build-script launch are not cryptographically/object bound. |
| `identity_session_guard.py` | 1-345 | No new formal finding | — | Supplied-only metadata, privacy tokenization, bounded retention, and observe-only output held. EventBus deduplicates restart subscriptions centrally. |
| `immutable_recovery_guard.py` | 1-177 | No new formal finding | — | Fail-closed signed-manifest/recovery boundary held. Retained-handle validation and external freshness remain worthwhile defense in depth. |
| `intel_sync.py` | 1-718 | Finding | C27-R1-B04 | IOC verification metadata is bounded, but Judgment text is not proof of rule activation. |
| `ipc_guard.py` | 1-486 | Finding | C27-R1-B20 | Loopback, HMAC, caps, and generation shutdown are good; accept-thread liveness is not reflected in health. |
| `kernel_bridge.py` | 1-274 | Finding | C27-R1-B05 | Device presence is not protocol/driver identity or live telemetry proof. |
| `kernel_posture_ledger.py` | 1-468 | Finding | C27-R1-B06 | Authenticated chaining is valuable; driver inventory completeness is absent from the receipt. |
| `linux_observe.py` | 1-122 | No new formal finding | — | Read-only platform observation degrades honestly on unavailable sources. Add source freshness/coverage fields per collector. |
| `lsass_guard.py` | 1-252 | Finding | C27-R1-B16 | Response scope is narrow and create time is emitted; dedup must actually use process generation. |
| `macos_observe.py` | 1-95 | No new formal finding | — | Observe-only parsing is bounded and unsupported states are explicit. Add per-source last-success timestamps. |
| `mem_inject_scanner.py` | 1-507 | Finding | C27-R1-B07 | Basename skip is a direct scanner bypass; native enumeration/coverage must be proven. |
| `memory_timemachine.py` | 1-318 | Finding | C27-R1-B08 | Bounded storage exists, but silent overwrite/drop and premature dedup make loss invisible. |
| `mobile_bridge.py` | 1-841 | Finding | C27-R1-B09, C27-R1-B10 | Remote sender comparison and typed process receipts help; local CLI trust and command authorization remain exploitable. |
| `network_monitor.py` | 1-349 | Finding | C27-R1-B11 | Mapped IPv4 is discarded before external-connection analysis; process novelty lacks birth identity. |
| `network_protocol_decoder.py` | 1-237 | No new formal finding | — | Parser is bounded and emits alerts only. Health should distinguish subscribed-but-no-evidence from verified input flow. |
| `network_trust_monitor.py` | 1-1280 | No new formal finding | — | Completeness/independence scoring and response ineligibility are unusually explicit. C23 independent baseline freshness remains deferred; A-06 command trust remains open. |
| `packet_sniffer.py` | 1-259 | Finding | C27-R1-B12 | Crash isolation is good, but parent/pipe lifecycle is not deadline-safe. |
| `packet_sniffer_worker.py` | 1-105 | Finding | C27-R1-B12 | Payload value is not emitted and records are capped; flushed stdout can still block the worker. |
| `peripheral_dma_guard.py` | 1-154 | No new formal finding | — | Read-only Windows posture with explicit UNKNOWN/limited states held. Add device-instance evidence links and collection freshness. |
| `persistence_sweep.py` | 1-651 | Finding | C27-R1-B18 | Coverage receipts and unreviewed baseline state are good; oversized startup content remains metadata-only. A-06 command trust remains open. |
| `platform_attestation_guard.py` | 1-396 | No new formal finding | — | Multi-signal fail-closed posture and evidence-only authority held. Prior A-06 `ExecutionPolicy Bypass`/command-path hardening remains open rather than re-reported. |
| `posture_hardening.py` | 1-1042 | Finding | C27-R1-B04, C27-R1-B14, C27-R1-B15 | Advice remains inert and vetted changes are gated; verification receipt, path schema, and evidence-health semantics need repair. |
| `process_egress_guard.py` | 1-233 | No new formal finding | — | Exact process-generation binding, bounded state, and fail-closed policy held. Add collector-denial counts and last-complete-snapshot details. |
| `process_monitor.py` | 1-162 | Finding | C27-R1-B16 | Creation details include birth time, but the state machine still keys only on PID. |

## Prior-finding reconciliation

- Verified resolved/mitigated in this shard: **2** — A-01 remains proposal-only with no auto-activation; A-05 still invokes `netstat` as an argv list and filters in Python.
- Verified still open/deferred in this shard: **2** — A-06 broad PowerShell/host-command trust remains present in owned posture/persistence/platform collectors; C23's independently fresh network baseline remains explicitly deferred/local-auth-only.
- Other prior findings were outside this shard or were not re-adjudicated; they are not counted.

## Inert validation evidence

- Full manual context review: all 31 files, line ranges recorded above.
- Deterministic locality probe: `_is_local('::ffff:8.8.8.8') == True`; `_is_local('8.8.8.8') == False`.
- Deterministic scanner-flow inspection/fixture: allowlisted basename is skipped before `_scan_pid`; a non-allowlisted basename reaches it.
- Deterministic verification-flow fixture: a child result containing `VERIFICATION_RESULT: BLOCKED` with return code 9 is accepted as BLOCKED/certified by the current parser.
- No exploit payload, network scan, host mutation, source edit, destructive command, or external research was performed.
