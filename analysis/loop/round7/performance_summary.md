# Round 7 Performance Audit — Final Release Candidate

Date: 2026-08-25

Scope: final review of the current real-time response path, UI polling and
backpressure, EventBus/storage reads, authenticated Combat journal, attested
Ollama/ARIA transport, and directory-bound ransomware correlation. Changes were
accepted only when detection cadence, response authority, target identity,
attestation, journal durability, and observable event output stayed unchanged.

## Applied optimizations

### 1. Literal loopback pinning avoids redundant resolver calls — APPLIED

- **Component:** `core/url_policy.py`; shared ARIA/Ollama local transport.
- **Problem:** a numeric loopback address was still sent through
  `socket.getaddrinfo()` every time it was validated or re-pinned. A normal
  hostname request is resolved and converted to a numeric loopback URL before
  connection, so the later validation paid a second resolver/system call for an
  identity that can no longer be DNS-rebound.
- **Change:** validate IP literals directly with `ipaddress`; hostname
  destinations still resolve and are pinned exactly as before. Ollama listener
  ownership, process birth time, executable path/signature, fixed API-route,
  no-proxy, no-redirect, and response-size attestation remain call-time gates.
- **Measured improvement:** 5,000 literal loopback pins fell from **0.355909 s**
  to **0.164860 s**: **2.16x faster / 53.7% lower validation time**. A regression
  proves literals do not enter DNS while `localhost` still resolves once and is
  converted to `127.0.0.1`.
- **Gate:** URL/Ollama transport and process-attestation regressions pass.
- **Status:** **APPLIED**

### 2. Directory-identity memoization under ransomware rename floods — APPLIED

- **Component:** `modules/ransomware_heuristics.py`.
- **Problem:** same-directory flood evidence stored an already normalized
  directory with every rename, but correlation normalized the same string again
  for every deque item and again while clearing the triggered directory. At
  ransomware-scale event volumes, this turned cheap counting into repeated
  filesystem path work.
- **Change:** normalize each distinct raw directory once per correlation cycle,
  then reuse that exact normalized identity for rate grouping and selective
  clearing. Same-directory entropy binding, time window, severity, threshold,
  emitted evidence, and Maximum response contract are unchanged.
- **Measured improvement:** ten correlation passes over **100,000 rename
  records** fell from **4.644651 s** to **0.672474 s**: **6.91x faster / 85.5%
  lower CPU time**. The regression proves a threshold-sized same-directory flood
  performs one normalization and still emits/clears normally.
- **Gate:** semantic response-contract and ransomware cross-directory negative
  tests pass.
- **Status:** **APPLIED**

### 3. In-place network novelty-state expiry — APPLIED

- **Component:** `modules/network_monitor.py`.
- **Problem:** every poll rebuilt both bounded novelty maps with full dictionary
  comprehensions even when no PID/host identity expired. Maximum Combat can poll
  every 0.75 seconds, making the unchanged-state allocation and GC cost steady.
- **Change:** collect and remove only stale keys in place, then retain the exact
  existing newest-entry cap. Connection enumeration, fresh Combat cache age,
  novelty windows, Community-ID, IOC correlation, emitted detections, and poll
  cadence are unchanged.
- **Measured improvement:** 100 no-expiry cycles over two 10,000-entry maps fell
  from **0.312131 s** to **0.165633 s**: **1.88x faster / 46.9% lower cycle
  time**. The benchmark includes fixture-map copies, so the isolated prune-path
  allocation reduction is conservative.
- **Gate:** state-expiry/cap, Community-ID, and network response-producer tests
  pass; a new regression proves unchanged maps are reused.
- **Status:** **APPLIED**

## Proposed / deliberately not applied

### Authenticated Combat journal segmentation — PROPOSED

- **Component:** `modules/adversary_combat.py`.
- **Finding:** every phase append rereads and verifies the complete HMAC chain
  before its fsynced write. Current clean-root measurements were **0.865322 s / 50
  records**, **1.777236 s / 100**, and **3.848091 s / 200** (mean append cost
  grows from **17.306 ms** to **19.240 ms** as history grows).
- **Proposal:** bounded signed segments with an authenticated prefix checkpoint
  and fully verified active tail, retaining complete archived action/undo
  visibility and strict verification before every mutation.
- **Why not applied:** stat/mtime/tail caching cannot prove that an earlier record
  was not modified while metadata was restored. Segmentation needs forged-prefix,
  crash-between-segments, rotation, recovery, and old-action undo tests first.
- **Status:** **PROPOSED**

### Ollama service-attestation cache — NOT APPLIED

- **Component:** `core/ollama_lifecycle.py`, `core/url_policy.py`.
- **Finding:** full listener enumeration and exact process/image revalidation are
  materially more expensive than URL parsing.
- **Decision:** do not cache the listener proof. Even a short TTL creates a port
  owner/process replacement window in which prompts could reach a different
  process. Only redundant literal resolution was removed; every request still
  re-attests listener ownership and executable identity.
- **Status:** **PROPOSED only if a future OS-native listener handle can bind the
  verified owner through connection establishment**

### Further GUI/ATT&CK refresh restructuring — NOT APPLIED

- **Component:** main dashboard, telemetry worker, ATT&CK tracker.
- **Finding:** current dashboard reads are revision-gated/asynchronous, telemetry
  delivery is bounded and batched, and the heatmap refresh is five-second
  presentation work. An all-active tracker snapshot measured approximately
  **0.811 ms**; no new release-blocking hot path was found.
- **Decision:** no timer or detection cadence was relaxed. Moving more host
  collection or changing snapshot semantics would need Qt lifecycle tests beyond
  the release-candidate gate.
- **Status:** **PROPOSED**

## Gates

- Changed Python/test files: `py_compile` **PASS**.
- Ruff on all changed source/tests: **PASS**.
- Initial broad affected regression set: **52 passed**, 0 failed.
- Final focused performance-boundary file after the last regression addition:
  **4 passed**, 0 failed.
- The combined second regression invocation was deliberately stopped when two
  concurrently launched pytest processes showed no progress under Windows I/O
  contention; only this agent's processes were terminated. The same tests are
  covered by the clean first run and the root agent's single-owner final suite.

| Optimization | Component | Status | Expected/measured win |
|---|---|---|---|
| Skip resolver for numeric loopback identities | URL / ARIA / Ollama transport | APPLIED | 2.16x; 53.7% lower literal-pin time |
| Normalize each ransomware directory once per cycle | Ransomware correlation | APPLIED | 6.91x; 85.5% lower 100k-record correlation time |
| Prune only expired novelty identities | Network Monitor | APPLIED | 1.88x; 46.9% lower no-expiry state-cycle time |
| Signed segmented action journal | Adversary Combat | PROPOSED | Bound append verification as history grows |
| OS-native listener-bound attestation proof | Ollama transport | PROPOSED | Avoid full listener scan only with equivalent owner binding |
| Additional refresh restructuring | GUI / ATT&CK | PROPOSED | Low priority; current all-active snapshot ~0.811 ms |
