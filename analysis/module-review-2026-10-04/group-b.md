# Module review, group B — 2026-10-04

## Scope and evidence

Reviewed all 29 source files at zero-based inventory positions 29–57 in
`diagnostics/module-audit-inventory-2026-10-04.json`: `fast_path.py` through
`posture_hardening.py`. The review covered correctness, security boundaries,
long-running state, polling work, collection completeness, and shutdown behavior.
Related telemetry, lifecycle, response-authority and test helpers were followed
where needed. This is source review with bounded offline reproductions, not a
claim that every host, driver, privilege level or attack has been tested.

No live sensor campaign, watchdog launch, process-memory read, Signal command,
network capture, firewall mutation or host remediation was performed for this
review. Native calls in new reproductions are inert Python fixtures. Existing
tests listed below are coverage references; only the validation section states
which tests this reviewer actually ran. Other agents own repository-wide
validation, platform CI, publication and the consolidated manual.

## Confirmed findings and changes

| ID | Finding and bounded reproduction | Resolution and regression evidence |
| --- | --- | --- |
| B01 | FRZ's repeated heartbeat-write failure set health 40, then a live trusted watchdog overwrote it with health 100 during the same loop. Six inert failed writes reproduced the false healthy state. | Writer failure is applied after watchdog custody/liveness checks. Five consecutive errors remain degraded; a successful write recovers. No heartbeat interval, watchdog launch or custody gate changed. `test_module_review_group_b.py` covers persistent failure and recovery. |
| B02 | Forensics treated failed `netstat` execution with empty stdout as a complete, empty socket capture. | A known integer zero exit code is required before writing a successful artifact. Exit codes 1, -1 and missing/unknown are incomplete; successful empty output remains valid. New group-B tests and `test_cycle29_forensics_budgets.py`. |
| B03 | Mobile ECO ON selected every non-Response category. FRZ is Resilience: its 0.5-second heartbeat became 3 seconds at 6x, exceeding the watchdog's 2-second freeze threshold. | ECO requires the concrete type's explicit `adaptive_throttle_allowed` declaration, validates its cap, respects builtin/release trust metadata, and excludes Response. It preserves transaction locks, rollback, nonce/PIN checks and signed change receipts. Tests prove FRZ/response/inherited-only/instance-only/external opt-ins stay unchanged and approved analytics obey their cap. |
| B04 | Mobile flood aggregation bounded displayed lines but retained every token and every 60-second arrival timestamp. A 600-alert fixture retained 600 tokens and timestamps; filtering the growing list per alert made a burst quadratic. Expiry also launched one phone send per token. | Pending tokens are capped at 256 without revoking previously issued authority. Excess alerts remain available on the host and in a bounded digest with an explicit admission-loss count. The latest four timestamps preserve the three-alert threshold; the digest retains 15 samples plus a scalar total. Expiry preserves individual local audit records and sends one phone summary. A 1,000-alert regression proves 256 tokens, four timestamps, 15 lines, exact counts and preserved first-token scope. |
| B05 | Intel self-test temporarily replaced the shared IOC snapshot, then restored its old value. A successful feed refresh interleaved with the test was discarded; live readers also saw fixture IOCs. | Public lookups and self-test use the same pure immutable-snapshot matcher. Self-test never publishes fixture state. A deterministic interleaved refresh remains the current snapshot after self-test; unsigned fixtures still cannot authorize response. |
| B06 | Network Monitor ignored its typed connection receipt. An empty `ConnectionList` with `complete=False` still produced health 100. | Initial and subsequent health reflect receipt completeness. Missing/untyped receipts are unknown, not healthy. Failed snapshots remain degraded until a complete snapshot arrives; a fixture verifies 55 → 55 → 100. The loop also stops before collecting again after a stop request. |
| B07 | Memory Injection Scanner's five-minute cooldown was keyed only by PID. Two observations with distinct handle-bound creation times but the same PID emitted only one alert. | Cooldown now binds PID and creation time from the scanned process handle. A cheap creation-time read precedes the cooldown; existing same-generation cooldown still avoids executable hashing and enrichment without skipping the memory scan. Missing birth evidence cannot create a PID-only suppression. Tests cover PID reuse, missing identity, scan retention and expiry. |
| B08 | Forensics charged its memory budget only for successful reads and reported failed reads as complete. An inert 256-byte region, 64-byte chunks and 128-byte budget performed four failed reads and returned `complete=True`, zero bytes. | Attempted bytes consume the work budget; failed and partial reads make capture incomplete. The inner chunk loop checks stop. Fixtures verify at most two attempts under that budget, successful capture, partial reads, cancellation and handle closure. Receipts expose attempted bytes and failed-read count. |
| B09, earlier performance work | Memory Time Machine's old 256-PID cache evicted a 257-PID working set cyclically. Three unchanged sweeps of three strings per PID queued `[771, 771, 771]` chunks. Long-string truncation also misaligned committed fingerprints with original source strings. | The lazy PID index is now 4,096 entries under the existing aggregate 1,048,576-fingerprint ceiling. Correct admission/acknowledgement binds each original string to accepted chunks. The same fixture queues `[771, 0, 0]`; incomplete enumeration does not delete live state, complete enumeration releases absent PIDs, and synthetic self-test identities survive sweep cleanup. Existing cache-efficiency and delivery regressions cover this work. This is an operation-count result, not a measured whole-PC CPU improvement. |

## Per-file review

Paths below are relative to `src/angerona/modules/`. “No additional confirmed
finding” means this pass did not reproduce another defect; it is not a security
certification. Test filenames are relative to `tests/`.

| File and purpose | Reviewed boundaries and performance behavior | Confirmed result / test coverage | Limits and residual concerns |
| --- | --- | --- | --- |
| `fast_path.py` — deterministic event rules | Event cursor/overflow, self-event exclusion, TTL deduplication, rule evaluation and split-tunnel correlation; kept immediate detection outside scan pacing. | No additional confirmed finding. `test_cycle27_remaining_a_second_remediation.py`, `test_cycle34_round2_followup.py`, `test_v12_event_cursors.py`. | Split-tunnel inspection precedes deduplication and can repeat PID connection work under a burst; no end-to-end cost measurement or safe freshness-preserving cache change was made. |
| `file_integrity.py` — file/driver change monitoring | Authenticated reviewed baseline, bounded inventory/content, handle identity and USN cache proof, reparse exclusions, immutable one-use scan custody, practice/response gates, partial-scan retry, driver/file cadence separation, cancellation and hashing. | No new confirmed finding beyond prior scan pacing work. `test_cycle29_fim_approved_baseline.py`, `test_cycle37_fim_churn_retry.py`, `test_fim_scan_liveness.py`, `test_background_pacing.py` and simulation custody suites. | Baseline size is checked after reading bytes; unusually large local artifacts can allocate before rejection. Windows USN/filesystem races require native-host validation. File scans yield every 16 files and 8 MiB; frequent driver checks remain outside interval pacing. |
| `fleet_health_monitor.py` — authenticated remote coverage status | Transport binding/tenant scope, stale/missing device coverage, retained/dropped evidence accounting, fingerprint deduplication, explicit analytical throttle declaration. | No additional confirmed finding. `test_cycle31_fleet_center_and_module.py`, `test_cycle34_round1_remediation.py`. | Remote fleet transport and cryptographic custody were not exercised against a real backend. This observer does not establish host containment authority. |
| `flight_cache.py` — bounded in-memory event SQL mirror | Row eviction, write batching, locking, close/unsubscribe lifecycle, read-only query gate, SQLite work budget and query result-row bound. | Confirmed generated-cell byte-allocation residual B10 below. `test_cycle37_flight_cache_eviction.py`, `test_flight_cache_query_budget.py`, `test_cycle4_performance_full_sweep.py`. | Row and VM-step limits do not bound one generated BLOB/text value. No production external query caller was found. API remains unchanged pending a portable engine-limit decision. |
| `forensics.py` — opt-in process evidence capture | PID-generation admission, evidence-root quotas, native-handle creation identity, memory/output budgets, shell-history exclusion, socket capture and receipt completeness. | B02 and B08 fixed. `test_module_review_group_b.py`, `test_cycle29_forensics_budgets.py`, `test_cycle4_round3_state_bounds.py`. | Native evidence was simulated. The address-space query loop still lacks the memory scanner's separate query/time cap; attempted-byte bounds constrain committed-region reads, not all possible mapping queries. Capture admission is marked before capture success. |
| `frz_heartbeat.py` — external freeze-watchdog heartbeat | Exact executable digest/publisher, protected object custody, authenticated v2 heartbeat, failed-write health, restart and resource cleanup. | B01 fixed; B03 prevents Mobile ECO from stretching this safety deadline. `test_cycle29_frz_object_bound_trust.py`, `test_resilience_heartbeat_auth.py`, `test_idle_io_guards.py`, new group-B tests. | No watchdog binary launched or isolation/termination exercised. Watchdog and heartbeat are deliberately excluded from adaptive scan pacing. |
| `hardware_crypto.py` — protected local secret storage | OS-store migration, plaintext residue handling, explicit unsupported TPM status and health reporting. | No additional confirmed finding. `test_cycle28_hardware_health.py`. | DPAPI, TPM firmware and real migration permissions were not independently validated on hardware. Unsupported hardware is not reported as complete hardware protection. |
| `hermetic_packager.py` — reviewed package-build control | Exact approved digest gate, sealed script custody, explicit build launch, frozen executable/package identity, metadata-vs-verification distinctions, job reaping. | No additional confirmed finding. `test_cycle29_hermetic_identity_gate.py`. | No build or packaging action executed. Platform publisher/MSIX integration remains a native validation boundary; completed jobs are retained until reaped. |
| `identity_session_guard.py` — session identity observations | Bounded ingress, producer/provenance admission, synchronous tokenization of identifiers, overflow and degraded startup state, observe-only policy. | No additional confirmed finding. `test_identity_session_guard.py`. | Real identity-provider events and raw identifier custody were not exercised; initialization/concurrent public observer calls need integration coverage. |
| `immutable_recovery_guard.py` — signed recovery readiness | Pinned Ed25519 authorities, duplicate-key/schema validation, freshness/revision handling, missing backup coverage and observe-only actions. | No additional confirmed finding. `test_recovery_assurance.py`, `test_combat_response_readiness.py`. | Local authority-store custody and real recovery media were not proven. Pre-read checks are not a sealed-file guarantee under concurrent local replacement. |
| `intel_sync.py` — KEV correlation and IOC snapshots | Public HTTPS fetching, byte/indicator bounds, snapshot expiry, pinned exact-content verification, unsigned advisory separation, product correlation and offline self-test. | B05 fixed. `test_v12_round1_intel_and_cve.py`, `test_module_review_group_b.py`, `test_cycle29_judgment_receipt_gate.py`. | No live feed or local model request made. Coarse KEV product correlation is advisory; it does not prove the exact installed version is vulnerable or authorize automatic repair. |
| `ipc_guard.py` — authenticated local IPC sentinel | Protected 32-byte key, loopback binding, nonce/HMAC authentication, bounded clients/timeouts, generation-owned helper lifecycle and stop handling. | No additional confirmed finding. `test_cycle30_ipc_liveness.py`, `test_v12_ipc_guard.py`, `test_cycle4_round3_lifecycle.py`. | No real listener opened. A fragmented TCP handshake may be conservatively rejected by single-read framing; that is an availability limitation, not an authentication bypass. |
| `kernel_bridge.py` — typed driver event observer | v2 capability/handshake parsing, event counts/sequences, explicit loss accounting, unverified driver identity status, observer-only delivery. | No additional confirmed finding. `test_cycle29_kernel_bridge_protocol.py`, `test_machine_module_usage.py`. | Real DeviceIoControl/driver custody and high-rate ring behavior remain untested. The bounded drain rate can lose events under load; existing loss reporting must remain visible. |
| `kernel_posture_ledger.py` — recorded driver/control posture | Driver collection completeness, HMAC hash chain and bounded anchors, unknown-control health, state fingerprinting and persistent ledger rewrite. | No additional confirmed finding. `test_cycle29_kernel_driver_collection_receipt.py`, `test_kernel_posture_ledger.py`. | Timestamp-bearing driver observations can produce periodic changes even when posture is stable. Ledger file bytes are read before record-count validation; native collection and local-file resource abuse were not reproduced. |
| `linux_observe.py` — Linux process/socket observer | Rootless collection, failures, cadence bounds and explicit absence of native enforcement. | No additional confirmed finding. `test_linux_platform_contract.py`. | Windows review environment; real Linux permissions and performance need platform CI/host validation. Routine inventory is not yet opted into the new UI-derived pacing controller. |
| `lsass_guard.py` — credential-access process indicators | PID birth binding, role-aware executable/argv checks, shared process evidence, conservative partial coverage and response-contract gates. | No additional confirmed finding. `test_cycle30_process_generation_identity.py`, `test_shared_process_evidence.py`, `test_semantic_response_contracts.py`. | It does not read LSASS memory or prove absence of credential theft. Immediate credential detection stays outside scan pacing. |
| `macos_observe.py` — macOS observe-only inventory | Collection/error handling, cadence bounds and explicit native-enforcement limitations. | No additional confirmed finding. `test_macos_platform_contract.py`. | Real macOS permissions/Endpoint Security were not tested. This optional observer does not yet opt into UI-derived scan pacing. |
| `mem_inject_scanner.py` — process address-map/RWX observer | PID enumeration completeness, handle custody, native query/time/evidence budgets, exact image policy, alert-only semantics, cancellation and bounded intentional-wait accounting. | B07 fixed; inner-query pacing and identity cooldown regressions in `test_memory_scanner_lifecycle.py`; `test_detector_observations.py`, `test_semantic_response_contracts.py`. | RWX is an observation, not proof of injection. Native calls were mocked. Per-PID work budgets may yield explicitly partial coverage; no complete-scan claim is made for exhausted budgets. |
| `memory_timemachine.py` — protected differential string snapshots | Ring/payload privacy, complete-enumeration cleanup, lazy bounded fingerprint cache, long-string chunk correspondence, queue acknowledgement, failure retry and self-test identity isolation. | B09 fixed. `test_memory_timemachine_cache_efficiency.py`, `test_cycle29_memory_timemachine_delivery.py`, `test_background_pacing.py`. | No production consumer of the bounded delta queue was found in this review; a full queue retains retry/degraded behavior. Working sets beyond cache bounds can replay evicted data. No real process memory sampled. |
| `mobile_bridge.py` — opt-in authenticated Signal administration | CLI digest/publisher/object/job custody, output bounds, sender/PIN/nonce/replay/action/expiry gates, exact process identity, signed change receipts, Combat reconciliation, ECO transactions and flood state. | B03/B04 fixed. `test_cycle29_mobile_typed_authorization.py`, `test_cycle27_b10_independent_reattack.py`, `test_soar_mobile_response_boundaries.py`, `test_module_review_group_b.py`. | Disabled by default; no Signal CLI or account contacted. Revalidating a large pinned binary/publisher every receive cycle may be expensive; trust caching needs independent custody design. Capacity exhaustion now explicitly withholds new tokens instead of weakening authorization. |
| `network_monitor.py` — connection novelty and corroborated IOC alerts | IPv4/IPv6 normalization, process birth/socket identities, local/global address classification, private event copies, bounded novelty state, shared receipt and response separation. | B06 fixed. `test_cycle28_network_identity.py`, `test_cycle4_round3_state_bounds.py`, `test_adversary_response_producers.py`, `test_module_review_group_b.py`. | Existing connections seed the baseline and are not claimed novel. Failed/partial collection is degraded, but unavailable connections cannot be evaluated. No real network probe used. |
| `network_protocol_decoder.py` — bounded DNS lexical observation | DNS label/name bounds, cooldown/recent-flag caps, self-event exclusion, lexical findings and explicit observer semantics. | No additional confirmed finding. `test_detector_observations.py`, `test_module_review_patches.py`, `test_session_efficiency.py`. | Lexical suspicion alone cannot authorize response. Synthetic drill echoes deliberately differ from ordinary cooldown behavior; live resolver diversity was not tested. |
| `network_trust_monitor.py` — adapter, gateway and DNS trust observation | Interface scoping, typed incomplete collection, baseline comparison, captive-portal probes, DHCP/DNS/proxy observations, deterministic policy and response separation. | No additional confirmed finding. `test_network_trust.py`. | Native adapter/VPN transitions, captive portals, DHCP/WMI and real connectivity were not exercised. Optional probes are distinct from the FPS monitor, which adds no network probe. |
| `packet_sniffer.py` — isolated packet-worker supervisor | Child-process failure containment, bounded JSON/output/record/time budgets, stop/reaping, end-receipt counts and honest partial capture health. | No additional confirmed finding. `test_cycle29_packet_sniffer_delivery.py`, `test_packet_sniffer_isolation.py`. | No Npcap/Scapy live capture. Descendant-held pipe/native termination behavior needs Windows integration testing; output limits cannot certify driver reliability. |
| `packet_sniffer_worker.py` — bounded packet classification child | `store=False`, capped frame inspection/emission, redacted plaintext-token findings, drop counts and terminal receipts. | No additional confirmed finding. `test_packet_sniffer_isolation.py`. | Protocol coverage is restricted (primarily IPv4 TCP for plaintext markers). This is not full payload reconstruction or general encrypted-traffic inspection. |
| `peripheral_dma_guard.py` — peripheral/DMA posture observer | Typed OS collection, unknown/degraded results and no host mutation or unsupported enforcement claims. | No additional confirmed finding. `test_peripheral_dma_guard.py`. | Firmware, IOMMU and actual peripheral attacks were not tested. Posture observation does not establish hardware isolation. |
| `persistence_sweep.py` — startup/persistence change observer | Complete/partial collectors, unreviewed startup reference, bounded outputs/records/change cooldown, content hashing and observe-only reporting. | No additional confirmed finding. `test_cycle30_persistence_startup_hash.py`, `test_v12_persistence_sweep.py`. | Up to 512 MiB of startup hashing per sweep lacks the new inter-chunk pacing hook. Collector output caps are applied after subprocess capture, so producer allocation can precede rejection. No live WMI/task/registry enumeration. |
| `platform_attestation_guard.py` — OS posture and quote verification | Rooted executable collection, strict typed fields, nonce-bound quote verification, OS-only vs hardware-attested state and change fingerprinting. | No additional confirmed finding. `test_platform_attestation_guard.py`. | No TPM quote/hardware attestation performed. OS-only observations remain explicitly lower assurance rather than being promoted to full attestation. |
| `posture_hardening.py` — signed weakness tracking and typed repair coordination | Signed report ingestion, reviewed candidate installation/rollback, exact displayed report binding, practice verification, evidence freshness, inert AI advisories and refusal of arbitrary script execution. | No additional confirmed finding. `test_cycle28_posture_paths.py`, `test_cycle29_judgment_receipt_gate.py`, `test_policy_and_drill_resolution.py`, `test_posture_ai_advisory.py`. | `_seen`/context retention and action logs can grow with distinct historical findings; no sustained-growth threshold was reproduced. Report I/O/database failure ordering deserves transactional fault-injection follow-up. Real host remediation and local-model output were not executed. |

## B10: FlightCache generated-value allocation remains open

An inert `FlightCache(cap=2)` call to
`query("SELECT zeroblob(8388608) AS payload")` returns one 8 MiB value. Its
two-row result budget and 50,000-step VM budget do not bound that allocation.
The issue is confirmed for the query API; no production external query ingress
was found. It is not evidence that this caused the reported GUI lag.

SQLite provides an engine-side string/BLOB/row ceiling through
`SQLITE_LIMIT_LENGTH`; its default is much larger than this cache needs.
[SQLite limits documentation](https://www.sqlite.org/limits.html).
The standard Python `Connection.setlimit`/`getlimit` APIs were added in Python
3.11. They are available for the supported newer runtimes but absent from the
Python 3.10 stdlib API. [Python 3.11 SQLite reference](https://docs.python.org/3.11/library/sqlite3.html#sqlite3.Connection.setlimit),
[Python 3.10 SQLite reference](https://docs.python.org/3.10/library/sqlite3.html).

A follow-up should select an engine-side length bound plus total returned-byte
budget and decide the supported-runtime strategy for 3.10. Checking bytes only
after fetching does not prevent the original allocation. A SQL regex function
ban is not a general expression-size bound. This review did not disable the API,
invent a SQL parser, add unsafe CPython/SQLite pointer access, or claim a portable
limit that the runtime does not provide.

## Pacing coverage and practical limits

The separate default-enabled background pacing controller uses existing UI/host
samples, with no new sensor thread or probe. In this group, Memory Time Machine,
Memory Injection Scanner and Network Monitor opt into routine-worker pacing.
FIM only paces its full file-scan interval and cooperative file/hash checkpoints;
its frequent driver checks stay active. Memory-map checkpoints account for
intentional waits separately from the native work deadline, with bounded total
extra waiting. Direct self-tests and action paths do not inherit the worker's
background interval adjustment. FRZ, IPC and immediate event/response paths do
not receive blanket slowdown.

This does not yet mean every expensive operation in every module cooperatively
yields: the table records Linux/macOS observer and persistence-hash gaps. The
FPS/pace display is an observed UI heartbeat and requested cadence factor, not a
measurement of actual security throughput, host CPU allocation, or completed
coverage. Work can remain limited by protected process access, native API time,
capture privileges, external tools and unavailable evidence.

## Validation run by this reviewer

All new fixtures were offline and inert. Results overlap and must not be added
together as unique-test totals.

- Initial FRZ/socket fixes: **19 passed** — `test_module_review_group_b.py`,
  `test_cycle29_forensics_budgets.py`, `test_cycle29_frz_object_bound_trust.py`,
  `test_idle_io_guards.py`.
- Mobile/Intel fixes: **70 passed, 1 skipped** — `test_module_review_group_b.py`,
  `test_cycle29_mobile_typed_authorization.py`,
  `test_cycle27_b10_independent_reattack.py`,
  `test_v12_round1_intel_and_cve.py`, `test_cycle4_performance_full_sweep.py`.
- Final network/memory/forensic fixes: **96 passed** —
  `test_module_review_group_b.py`, `test_memory_scanner_lifecycle.py`,
  `test_cycle29_forensics_budgets.py`, `test_cycle28_network_identity.py`,
  `test_cycle4_round3_state_bounds.py`, `test_adversary_response_producers.py`,
  `test_detector_observations.py`, `test_round7_performance_boundaries.py`.
- Ruff passed for all six product files changed during this module audit and
  the five corresponding changed/new test files. Earlier Memory Time Machine,
  FIM and pacing checks are recorded in their task reports; the final integrated
  suite/CI result belongs in the consolidated review.

No commit or publication was performed by this reviewer. Repository-wide
validation, manual rendering, reviewed-file commit and guarded GitHub publication
remain the integrating maintainer agent's responsibility.
