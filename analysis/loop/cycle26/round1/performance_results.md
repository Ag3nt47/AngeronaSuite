# Cycle 26 Round 1 Performance Gate

Date: 2026-08-28
Scope: handle-bound Security Scan Center reads and module-health evidence/UI paths
Result: **PASS — three behavior-preserving optimizations applied**

## Applied optimizations

### 1. Descriptor-size and aggregate-budget preflight — APPLIED

- **Component:** `core/security_scan_center.py`
- **Problem:** the handle-bound scanner read up to the full 64 MiB per-file
  allowance before discovering that the remaining aggregate budget could not
  admit the file. This created avoidable I/O and a two-copy peak while joining
  chunks.
- **Change:** after the no-follow open, regular-file/volume proof, and final
  handle-path proof, the scanner now uses the descriptor's `fstat` size to
  classify a stable file as `oversize` or `budget` before reading content. It
  repeats both the root-identity and descriptor-identity/mutation checks before
  returning the fast-path disposition. Unknown, changed, or unsafe identities
  still fail closed. Reads that are admitted are capped at one proof byte past
  the tighter per-file/remaining-total bound.
- **Measured improvement:** a stable 64 MiB sparse file with 1 KiB aggregate
  budget remaining fell from **0.182130 s / 128.12 MiB peak** to
  **0.103039 s / 0.71 MiB peak** in `tracemalloc` (43.4% lower elapsed time and
  99.4% lower measured peak allocation). The observable result remained
  `limited`, zero files/bytes scanned, and one budget skip.
- **Gate:** regressions prove no content `read` occurs for a stable over-budget
  object and that a root identity change on this fast path is reported as an
  unsafe scope, never as a benign budget skip.

### 2. Coalesced per-file root/Windows handle proof work — APPLIED

- **Component:** `core/security_scan_center.py`
- **Problem:** every candidate recomputed the same normalized root, initialized
  the Windows final-handle-path API, allocated a 32,768-character buffer, and
  re-statted the selected root to detect links after already obtaining a
  no-follow stat result.
- **Change:** normalize the validated root and classify root type once per
  scan; initialize the immutable Windows API once; start with a 1,024-character
  path buffer and grow only when the API reports a longer path; classify
  link/reparse state from the same no-follow root stat used for identity proof.
  The final-handle containment check and pre/post root checks remain mandatory.
- **Measured improvement:** five scans of 1,000 stable 256-byte files, with YARA
  disabled to isolate the object-bound read path, improved from a **1.763615 s
  median (567.0 files/s)** to **1.464359 s (682.9 files/s)**: 17.0% lower
  median elapsed time and 20.4% higher throughput on this host.

### 3. Coherent health snapshot and unchanged-widget coalescing — APPLIED

- **Component:** `gui/pages.py` (`ModuleInspector`)
- **Problem:** each two-second inspector refresh obtained the module operational
  snapshot once for health evidence and again for the contract summary, then
  rewrote and re-laid out the clickable health-evidence button even when its
  content had not changed.
- **Change:** one coherent operational snapshot now serves both sections, and a
  bounded evidence fingerprint suppresses unchanged button text/visibility
  writes. Clicking still obtains a fresh snapshot before opening details.
- **Expected/measured improvement:** operational snapshots measured
  **3.876 microseconds each** over 200,000 calls. The refresh now makes exactly
  one instead of two calls (50% fewer) and avoids repeated Qt widget work on
  unchanged health. A regression asserts the one-call contract.

## Reviewed without change

- **`core/module_base.py` health capture — no change required.** Degraded-only
  frame capture already uses bounded reasons and LRU-cached source
  classification; full health avoids frame inspection. Snapshot locking is
  required for atomic health/note/evidence parity. Further caching would risk
  stale exact-line evidence or weaken concurrency semantics, so no speculative
  optimization was applied.
- **Health source dialog I/O — no change required.** The bounded source read is
  operator-click initiated rather than timer-driven. Its repeated trust and
  post-read identity checks are security controls, not hot-path redundancy.

## Security and behavior gate

The optimizations preserve the existing no-follow open, regular-file proof,
same-volume proof, OS final-handle path containment, selected-root identity
checks before and after, descriptor identity/size/mtime revalidation, bounded
immutable byte snapshot, and YARA scan-from-bytes behavior. No cadence,
detection, finding, event, or response control was throttled.

- `py_compile`: PASS for all three scoped product files and focused tests.
- Ruff: PASS for all scoped product/test files.
- Focused tests: **36 passed, 2 expected platform/symlink-capability skips**.
- `git diff --check`: PASS (only repository line-ending notices).

| Optimization | Component | Status | Expected/measured win |
|---|---|---|---|
| Stable descriptor budget preflight | Security Scan Center | APPLIED | 99.4% lower peak allocation on 64 MiB rejected file |
| Coalesced root/Win32 handle proof | Security Scan Center | APPLIED | 17.0% lower median for 1,000-file scan |
| Single snapshot + UI fingerprint | Module Inspector | APPLIED | 50% fewer operational snapshots per refresh |
