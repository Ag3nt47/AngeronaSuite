# Cycle 24 Round 2 — Performance

Date: 2026-08-26

## Result

Two bounded, behavior-preserving optimizations were applied to remediated
Cycle 24 paths. Personal Sentinel reuses one exact canonical unsigned-state
buffer for its external-floor digest and state signature. Identity/session
analytics uses a bounded, eviction-synchronized digest index for replay
membership while retaining the ordered deque as the authoritative evidence
window. No polling interval, evidence field, cryptographic validation,
stable-read check, fail-closed branch, or response boundary changed.

## Measurements

Measurements used in-memory synthetic fixtures only. They did not launch the
GUI, contact a network service, read live host telemetry, or weaken a test.

- Personal Sentinel's state save kernel was measured with 64, 512, and 4,096
  retained nonce digests. Reusing the canonical unsigned state reduced median
  serialization/signing time from **0.1943 ms to 0.1185 ms (39.0%)**, **1.0246
  ms to 0.6520 ms (36.4%)**, and **8.5772 ms to 5.9857 ms (30.2%)**,
  respectively. The old and proposed functions produced byte-for-byte equal
  persisted payloads in the benchmark. Disk flush and atomic replacement are
  intentionally unchanged, so these are CPU-kernel results rather than an
  end-to-end request-latency claim.
- Identity replay membership at 32, 128, and 4,096 retained events fell from
  **4.030 us to 0.082 us (48.9x)**, **12.234 us to 0.065 us (187.7x)**, and
  **410.488 us to 0.060 us (6,800.7x)**. This isolates duplicate membership;
  unique-event correlation still evaluates the ordered bounded window exactly
  as before. The maximum-size set table is about **128.2 KiB** and references
  the existing digest strings rather than duplicating them.

## Optimizations

### Canonical Personal Sentinel state reuse — APPLIED

- **Component:** `src/angerona/core/personal_sentinel_authority.py`
- **Problem:** Every durable request serialized the growing unsigned state for
  SHA-256, serialized it again for the response/state signature, then
  serialized the final signed document. The SHA-256 result was unused when no
  external generation floor was configured.
- **Change:** Canonicalize unsigned state once after incrementing its
  generation. Use those exact bytes for the optional generation-floor SHA-256
  and state signature. Continue using the ordinary canonical encoder for the
  final signed document.
- **Expected/measured improvement:** 30.2–39.0% less CPU in the bounded state
  serialization/signing kernel across 64–4,096 nonces.
- **Security/behavior gate:** Generation advancement, external-floor ordering,
  signature algorithm, final canonical encoding, fsync, atomic replacement,
  nonce consumption, rollback detection, and error behavior remain unchanged.
  A regression recomputes the floor digest from the persisted unsigned state.
- **Gate result:** Focused tests PASS; self-test PASS; Ruff PASS; `py_compile`
  PASS.

### O(1) identity/session replay membership — APPLIED

- **Component:** `src/angerona/core/identity_session.py`
- **Problem:** Every supplied event linearly scanned up to 4,096 retained
  events solely to reject a duplicate digest, before the separate ordered
  correlation pass.
- **Change:** Maintain a companion set of the exact digest objects already in
  the authoritative deque. Capacity and time-window evictions remove the same
  digest immediately. The deque still controls ordering, retention, findings,
  overflow, and public assessments.
- **Expected/measured improvement:** Duplicate-membership kernel reduced from
  410.488 us to 0.060 us at the artificial 4,096-event bound; normal bounded
  capacities show the same constant-time behavior.
- **Security/behavior gate:** Duplicates remain ignored; overflow and time
  pruning remain explicit; a digest can be admitted again only after its
  authoritative evidence row is evicted, matching prior semantics. A new
  regression covers duplicate rejection and capacity-eviction re-admission.
- **Gate result:** Focused tests PASS; module self-test PASS; Ruff PASS;
  `py_compile` PASS.

### Temporal persistence write coalescing — PROPOSED / NOT APPLIED

- **Component:** `src/angerona/core/temporal_tradecraft.py`
- **Problem:** Authenticated temporal state is serialized, HMACed, fsynced, and
  atomically replaced after every admitted or coverage-changing signal.
- **Reason withheld:** Delaying or batching those writes would change restart
  continuity and could hide the final sequence of evidence after a crash.
  Persistence cadence is part of the security behavior, not cosmetic I/O.
- **Safe future direction:** A write-ahead journal or separately durable broker
  could reduce full-snapshot rewrites only after crash-equivalence and tamper
  tests prove that no admitted signal becomes silently healthy after restart.

### Process-egress lease material reuse — PROPOSED / NOT APPLIED

- **Component:** `src/angerona/core/process_egress_lease.py`
- **Problem:** Authorization canonicalizes the lease for HMAC verification and
  separately serializes/hashes it for the broker-issued-state fingerprint.
- **Reason withheld:** Both checks protect a connection-admission boundary.
  Combining their material or retaining an exact issued object is plausible,
  but it requires dedicated equivalence, mutation, collision, and concurrency
  review before altering this security-critical hot path.

### Coalesced Windows posture collection — PROPOSED / NOT APPLIED

- **Component:** platform attestation, driver posture, and peripheral/DMA
  collectors.
- **Problem:** Separate trusted PowerShell processes query overlapping Windows
  posture near startup and at their independent five-/fifteen-minute cadences.
- **Reason withheld:** A shared cache or combined snapshot changes freshness,
  evidence boundaries, and partial-failure semantics. No equivalence proof was
  available in this round, so fresh fail-closed probes remain intact.

## Static hot-path review

- The remediated TLS listener bounds pre-authentication to 16 handshakes and
  authenticated workers to 32. Handshake threads retain the deadline and slot
  release in `finally`; pooling or relaxing timeouts was not justified.
- Driver overflow accounting adds only fixed integer/schema checks. Fresh
  per-image SHA-256, Authenticode, catalog, reparse, size, and before/after
  stability checks remain uncached because trust disposition and file state
  can change independently of an mtime.
- Live Defense Activity already gates rendering on EventBus revision and a
  coarse module-state snapshot, requests at most 16 events, displays five, and
  never reads raw details. Its small two-second panel refresh needs no change.
- Defense Memory is pinned and loaded once per process; Runbook RAG retains
  build-time term frequencies/length normalization, and cloud fallback admits
  at most one ranked canonical excerpt. No repeated asset parse was found.
- Release/payload, recovery-cohort, and RAG provenance verification are bounded
  but deliberately re-read and hash configured evidence. Mtime-only caching
  would weaken stable-read, content-completeness, or revocation semantics.
- Recovery cohorting is bounded to 64 verified statements. The deterministic
  cohort selection cost is negligible beside Ed25519 verification and hourly
  evidence collection; no algorithmic change was warranted.
- Peripheral and attestation subprocess probes run off the GUI thread at a
  five-minute cadence. The probes remain fresh and fail toward UNKNOWN rather
  than reusing a potentially stale posture.

## Gates

- Focused pytest: **27 passed / 0 failed** across Personal Sentinel authority
  and identity/session guard tests.
- Standalone self-tests: **2 passed / 0 failed** (Personal Sentinel authority
  and Identity Session Guard).
- Ruff: PASS for both changed product files and both changed test files.
- `py_compile`: PASS for both changed product files.

| Optimization | Component | Status | Expected/measured win |
|---|---|---|---|
| Canonical state reuse | Personal Sentinel authority | APPLIED | 30.2–39.0% lower save-kernel CPU |
| Digest membership index | Identity/session analytics | APPLIED | O(n) to O(1); 410.488 us to 0.060 us at 4,096 rows |
| Crash-equivalent temporal journal | Temporal tradecraft | PROPOSED | Avoid full snapshot rewrites without evidence loss |
| Lease material reuse | Process-egress broker | PROPOSED | Remove one serialization/hash after equivalence proof |
| Coalesced Windows posture query | Platform/driver/peripheral collectors | PROPOSED | Reduce trusted-process startup overhead without stale evidence |
