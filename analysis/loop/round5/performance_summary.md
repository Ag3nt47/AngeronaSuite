# Round 5 Performance Audit — Hardened Response and ARIA Paths

Date: 2026-08-25

Scope: the current authenticated Adversary Combat journal/recovery path,
SourceSandbox handle pinning, HMAC-protected Sysmon cursor, local-model blob
verification, automatic-response producers, and ARIA/Upgrade Console refresh and
model-pack lifecycle. Optimizations were applied only where integrity, response
authority, event production, and postcondition behavior remain unchanged.

## Applied optimizations

### 1. Sysmon cursor authority derivation — APPLIED

- **Component:** `modules/sysmon_listener.py`
- **Problem:** every durable cursor checkpoint reread `bus.key` and re-derived the
  purpose-separated HMAC key. The install authority is immutable for the life of
  the running bus, so this repeated filesystem/key work did not add integrity.
- **Change:** cache only a successfully derived 32-byte cursor key. Missing or
  invalid authority is not cached, preserving first-start retry and fail-closed
  behavior. Cursor HMAC verification, atomic replacement, and per-batch `fsync`
  are unchanged.
- **Measured improvement:** 5,000 derivations fell from **1.410556 s / 282.11
  microseconds each** to **0.000477 s / 0.095 microseconds each** after the first
  successful derivation: approximately **2,969x faster** and **99.97% less CPU/I/O**
  on the checkpoint key path.
- **Gate:** cursor HMAC/tamper/restart tests pass; new regression proves one key
  read across repeated derivations; live running module self-test passed with the
  Sysmon channel open.
- **Status:** **APPLIED**

### 2. SourceSandbox pinned-chain validation — APPLIED

- **Component:** `core/source_sandbox.py`
- **Problem:** the Windows read guard walked the complete ancestor chain again
  for every child component while opening and pinning those same components,
  making validation quadratic in path depth.
- **Change:** enumerate each normalized component once, validate its leaf
  immediately before opening, pin it without delete sharing, and revalidate it
  immediately after opening. Every ancestor is still validated and remains
  handle-pinned; symlink/reparse rejection and the stronger atomic-write handle
  gates are unchanged.
- **Measured improvement:** a representative eight-level Windows path dropped
  from **6.862 ms** to **1.742 ms** per guarded operation: **3.94x faster / 74.6%
  lower validation latency**.
- **Gate:** all SourceSandbox confinement, parent-reparse-swap, GUI isolation, and
  Windows parent-handle TOCTOU tests pass.
- **Status:** **APPLIED**

### 3. Embedded model-pack RAG rebuild coalescing — APPLIED

- **Component:** `gui/upgrade_console.py`, main-window ARIA callback
- **Problem:** a successful lifecycle action in the embedded Upgrade Console
  built an unused console-local runbook index and then invoked the main-window
  callback, which built and installed the authoritative ARIA index again.
- **Change:** embedded consoles invoke exactly one authoritative rebuild through
  the callback. Standalone consoles retain their own local build. Lifecycle
  completion, catalog verification, and runbook content remain identical.
- **Measured improvement:** the current 68-document corpus takes **14.858 ms** per
  build; the embedded post-change path falls from **29.716 ms (two builds)** to
  **14.858 ms (one build)**, a **50% reduction** in Markdown I/O/parsing.
- **Gate:** new regression proves no duplicate `RunbookRAG` construction when an
  authoritative callback exists; asynchronous operation/shutdown tests pass.
- **Status:** **APPLIED**

### 4. Batched model-pack admission snapshot — APPLIED

- **Component:** `core/model_pack_manager.py`, `gui/main_window.py`,
  `gui/upgrade_console.py`
- **Problem:** status surfaces called the RAM/disk resource probe once per catalog
  pack, creating N identical psutil/disk queries and potentially mixing resource
  readings from different instants in one view.
- **Change:** `admission_plans()` captures one resource snapshot and evaluates all
  catalog requirements against it. The actual install path still performs a fresh
  single-pack admission immediately before mutation, so security admission is not
  cached or weakened. Compatibility fallback remains for injected legacy managers.
- **Measured improvement:** a 128-pack bounded-catalog benchmark fell from
  **34.666 ms** to **0.784 ms**, **44.22x faster / 97.7% less status-probe time**.
- **Gate:** new test proves two catalog entries share exactly one probe/snapshot;
  governed pack, ARIA boundary, provider, URL, Upgrade async, and shutdown tests pass.
- **Status:** **APPLIED**

## Proposed / deliberately not applied

### Authenticated Combat journal segmentation — PROPOSED

- **Component:** `modules/adversary_combat.py`
- **Problem:** every intent/commit/failure append strictly rereads, reparses, and
  verifies the entire HMAC chain before writing. Synthetic append measurements
  were **0.8551 s for 50**, **1.9286 s for 100**, and **4.9859 s for 200** records,
  confirming superlinear accumulated cost. The JSONL file is also unbounded.
- **Proposal:** add bounded, HMAC-authenticated journal segments with a signed
  prefix checkpoint/aggregate and an independently verified active tail, while
  retaining archived action visibility and strict full-chain validation before
  any mutation or undo.
- **Why not applied:** a naive tail/stat cache, rotation, or reduced verification
  could fail to notice earlier-record tampering before an automatic host mutation.
  No optimization was accepted without crash, forged-prefix, timestamp-preserving
  tamper, rotation, recovery, and undo compatibility tests.
- **Expected improvement:** amortized near-constant append verification for the
  active segment instead of whole-history growth.
- **Status:** **PROPOSED**

### Model-blob hash caching — NOT APPLIED

- **Component:** `modules/ai_model_integrity.py`, `core/model_pack_manager.py`
- **Finding:** multi-GB model blob hashing dominates install/activate/rollback and
  removal by design.
- **Decision:** no stat/mtime cache was added. Each governed lifecycle mutation
  continues to validate the real manifest and every content-addressed blob from
  disk; replacing that with metadata caching would weaken the new local-model
  integrity boundary.
- **Status:** **PROPOSED only if a future OS-backed immutable file identity and
  change-notification gate can prove equivalence**

## Gates

- Changed Python files: `py_compile` **PASS**.
- Ruff on all changed source/tests: **PASS**.
- Broad affected regression set: **62 passed**, 0 failed.
- Additional SourceSandbox/Sysmon/Upgrade focused set: **19 passed**, 0 failed.
- Running Sysmon module `self_test()`: **PASS** (`Sysmon channel open`).

| Optimization | Component | Status | Expected/measured win |
|---|---|---|---|
| Cache derived cursor HMAC key | Sysmon cursor | APPLIED | 2,969x / 99.97% lower repeated key cost |
| Linear pinned-chain validation | SourceSandbox | APPLIED | 3.94x / 74.6% lower guarded-path latency |
| One authoritative RAG rebuild | Upgrade/ARIA | APPLIED | 50% less post-lifecycle indexing |
| One admission resource snapshot | Model-pack status UI | APPLIED | 44.22x / 97.7% lower 128-pack probe time |
| Signed segmented journal | Adversary Combat | PROPOSED | Near-constant active-tail append cost |
| OS-backed safe blob verification cache | ARIA model integrity | PROPOSED | Avoid repeat multi-GB reads only if equivalence is proven |
