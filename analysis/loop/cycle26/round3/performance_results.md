# Cycle 26 Round 3 Performance Gate

Date: 2026-08-28
Scope: final hardened module-health, Capability Center, object-bound scan,
remediation-custody, authentication-baseline, and isolated-self-test paths
Result: **two behavior-preserving optimizations applied; security-sensitive
I/O retained unchanged**

## Applied optimizations

### 1. Atomic lightweight Capability Center health rows — APPLIED

- **Component:** `core/module_base.py`, `gui/pages.py`
- **Problem:** every 1.5-second Capability Center refresh read `status` and
  `health_state` repeatedly for each module. An 81-module rebuild therefore
  acquired the same health lock several times per module and could combine
  lifecycle and health values observed at different instants. Replacing those
  reads with the full operational dictionary would have increased CPU and
  allocation cost.
- **Change:** `BaseModule.health_summary()` returns the exact status, bounded
  health integer, and existing colour state from one lock acquisition and one
  tuple. The Capability Center reuses that tuple for filtering, refresh
  fingerprinting, and row rendering.
- **Measured improvement:** a paired 81-module pure refresh benchmark measured
  **438.564 microseconds** for the repeated-property path versus **251.523
  microseconds** for the proposed atomic tuple, a **42.7% elapsed reduction**.
  A post-application run measured **204.467 microseconds** per 81-module tuple
  batch. A full operational-dictionary alternative measured 510.137
  microseconds and was rejected.
- **Behavior/security:** status values, health thresholds, colours, filters,
  sorting inputs, event-overflow counters, and the 1.5-second freshness cadence
  are unchanged. No state is cached and no sensor or response path is
  throttled.

### 2. One thread-liveness probe per operational snapshot — APPLIED

- **Component:** `core/module_base.py`
- **Problem:** a running module's operational snapshot called
  `thread.is_alive()` once for uptime and again for the returned liveness flag.
  Besides duplicate work, the two calls could disagree during thread exit.
- **Change:** capture liveness once and reuse the boolean for both fields.
- **Measured improvement:** **2 to 1 liveness probes per running-module
  snapshot (50% fewer)**, while making uptime and `thread_alive` coherent.
- **Behavior/security:** freshness ages, lifecycle generation, cycle counts,
  overflow/crash evidence, and health evidence remain freshly computed on
  every request.

## Measured and retained unchanged

### Object-bound scan and cancellation — no change

- Three interleaved scans of 300 stable 256-byte files completed with medians
  of **0.707 s without a token** and **0.573 s with a non-cancelled token**.
  The apparent negative overhead is filesystem-cache/AV noise; it demonstrates
  no measurable cancellation penalty, not a speedup claim.
- An already-cancelled scan returned in **3.97 ms** with **zero files read**.
- A 16 MiB admitted immutable snapshot completed in **31.27 ms** and peaked at
  **32.014 MiB** in parent `tracemalloc`, matching the bounded chunk-plus-joined
  byte snapshot. Streaming or caching was not substituted because YARA must
  inspect the exact descriptor-validated immutable bytes and late results must
  remain discardable.

### Durable remediation journal — no change

- Under the documented post-staging antivirus/I/O pressure, eight ordinary
  transactions measured medians of **254.36 ms PREPARED**, **270.61 ms
  MUTATING**, and **272.77 ms terminal receipt**. Three exact recovery
  claim/verify/finish sequences measured **542.42 ms median** and left **zero
  unresolved rows**.
- This isolated benchmark intentionally did not provision the production
  receipt-attestation key, so receipt authenticity reported `unsigned`; it was
  a timing run, not a chain-authentication gate.
- The dominant work is `synchronous=FULL` durability plus canonical path,
  parent/object identity, single-link, sidecar, owner-capability, claim, and
  retained-record checks. None was cached, weakened, or moved after mutation.

### Authentication baseline observation — no change

- One complete fixed-slot trusted enrollment took **1.716 s** including durable
  creation and slot registration. Thirty stable authenticated observations
  measured **19.922 ms median**, **30.246 ms maximum**, and **766.10 KiB** peak
  parent allocation; all returned `stable`. Pure bounded snapshot comparison
  measured **42.05 microseconds median**.
- Baseline file/root identity, HMAC, fixed-slot registry, freshness, and
  post-read checks remain per-observation. Caching them would create stale or
  replayable trust and was rejected.

### Isolated resilience self-test runner — no change

- Three diagnostics runs all passed with a **3.962 s median** and **10.609 s
  maximum** under AV pressure.
- The clean environment, `-I` bootstrap, suspended-start Windows job custody,
  process/memory/CPU limits, 16 KiB streaming output cap, timeout, and owned
  temporary-directory cleanup dominate intentionally. No process reuse or
  environment cache was introduced.

## Gates and cleanup

- Scoped `py_compile`: **PASS** for `module_base.py`, `pages.py`, and the
  focused performance regression file.
- `BaseModule.self_test()`: **PASS** (`running, health 100%`).
- New regressions prove one health-summary call per Capability Center refresh
  and one thread-liveness probe per operational snapshot.
- The combined focused pytest invocation displayed **15 passing dots and
  reached 100% with no failure output**, but did not return a terminal summary
  after roughly five minutes of known AV/I/O pressure. Only its verified PIDs
  were stopped; this run is recorded as **INTERRUPTED / non-authoritative** and
  must be covered again by the cooled-down final suite.
- `git diff --check`: **PASS** (line-ending notices only).
- Verified test/benchmark PIDs were absent after cleanup. All three bounded
  benchmark trees were identity-checked and removed; no benchmark residue or
  owned orphan process remained.

| Optimization | Component | Status | Expected/measured win |
|---|---|---|---|
| Atomic lightweight health tuple | Capability Center / module base | APPLIED | 42.7% lower 81-module data-refresh time |
| Coalesced thread liveness | Module operational snapshot | APPLIED | 50% fewer `is_alive()` probes |
| Deadline/cancellation checks | Security Scan Center | RETAINED | No measurable steady-state penalty; 3.97 ms pre-cancel exit |
| FULL-sync custody and recovery | Remediation journal | RETAINED | Security boundary; zero unresolved rows |
| Per-observation identity/HMAC | Authentication baseline | RETAINED | 19.922 ms median stable observation |
| Fresh isolated child custody | Resilience self-test runner | RETAINED | 3/3 passed; 3.962 s median under AV pressure |
