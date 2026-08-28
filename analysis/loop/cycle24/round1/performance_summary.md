# Cycle 24 Round 1 — Performance

Date: 2026-08-26

## Result

One bounded driver-inventory optimization was applied. No protection cadence,
evidence field, detection rule, fail-closed branch, or response boundary was
relaxed. Cross-scan signature caching was deliberately rejected because an
unchanged image can acquire a different Windows trust/revocation disposition.

## Measurements

- The unmodified live provider's first collection took **36.429 s** for 194
  running driver-service rows. A later unmodified warm query took **14.571 s**;
  its separate boot-posture query took **1.688 s**.
- Component profiling over 194 rows measured **2.713 s** hashing and **11.310
  s** Authenticode verification. This confirms that recurring signature work,
  rather than Python assessment, dominates the scan.
- An alternating, same-process CIM enumeration benchmark produced:
  client-side filter **7.0873 s**, provider-side filter **1.5406 s**,
  client-side filter **3.1479 s**, provider-side filter **1.5663 s**. The warm
  comparison is a **50.7% reduction in the enumeration phase**. End-to-end scan
  time remains load- and Windows-trust-service-dependent, so no whole-scan
  percentage is claimed.
- The retained collector's live evidence gate returned **194 rows / 193
  SHA-256 hashes / 193 valid signatures**. One backing image remained unknown,
  exactly as the collector's fail-closed contract requires.

## Optimizations

### Driver inventory pushdown and bounded row construction — APPLIED

- **Component:** `src/angerona/modules/driver_provenance_guard.py`
- **Problem:** `Get-CimInstance Win32_SystemDriver` materialized every service
  before `Where-Object` selected running drivers, and `$rows +=` repeatedly
  copied the growing PowerShell array.
- **Change:** Push `State='Running'` into CIM's `-Filter` and build the bounded
  result with `Collections.Generic.List[object]`.
- **Expected/measured improvement:** 50.7% lower warm enumeration time in the
  controlled alternating sample; row construction changes from repeated array
  copying to amortized constant-time append. Signature verification still
  dominates the 15-minute scan.
- **Security/behavior gate:** Every admitted service still receives the same
  per-file SHA-256, Authenticode/catalog lookup, reparse rejection, 128 MiB
  bound, and before/after length/mtime stability check on every scan. No cache
  or cadence change was introduced.
- **Gate result:** `py_compile` PASS; Ruff PASS; driver tests **9 passed / 0
  failed**; module `self_test()` PASS; live evidence-count gate PASS.

### Cross-scan driver signature cache — PROPOSED / NOT APPLIED

- **Component:** Windows driver evidence provider.
- **Problem:** Authenticode verification consumed 11.310 s in a warm component
  profile and is repeated at the 15-minute scan cadence.
- **Reason withheld:** A content-hash-only cache would miss a changed certificate
  trust, catalog, revocation, or policy disposition for unchanged bytes. A TTL
  would only delay that detection and therefore change security semantics.
- **Safe future direction:** A separately tested long-lived verifier may remove
  process/cmdlet setup overhead only if it performs a fresh Windows trust
  decision for every image and preserves the current stable-file checks.

### Coalesced Windows platform evidence query — PROPOSED / NOT APPLIED

- **Component:** `platform_attestation_guard.py` and the driver posture join.
- **Problem:** Platform posture, TPM presence, DMA capability, and driver boot
  posture currently start multiple trusted PowerShell processes near startup.
- **Reason withheld:** Coalescing changes evidence observation boundaries and
  was not proven equivalent during this remediation-heavy round. The existing
  five-, fifteen-, and thirty-minute cadences are bounded and run off the GUI
  thread.

## Static hot-path review

- Temporal and identity analytics use bounded subscription queues (256 rows)
  rather than repeatedly polling EventBus history; no polling stampede found.
- Process-egress audit retention is bounded to 1,024 event tokens and the
  default disconnected observer is constant-time. Its five-second cadence was
  retained because it is a protection visibility path.
- RAG provenance, release authorization, and recovery assurance deliberately
  re-read and re-hash configured evidence at bounded 5-, 30-, and 60-minute
  intervals. Mtime-only caching was rejected because a privileged adversary can
  preserve metadata while changing content.
- Live Defense Activity already revision-gates EventBus rendering, requests at
  most 16 events, displays at most five sanitized rows, and avoids event
  details. Its small module-state scan was retained.
- Public gallery capture is a one-shot synthetic-data tool. It stops background
  UI timers and does not affect the production refresh path.

## Deferred risks

- The driver scan remains expensive on hosts with large loaded-driver sets;
  fresh trust evaluation is the cost of preserving evidence quality.
- The red-team completeness finding for inventories beyond the bounded driver
  limit is owned by the Round 1 remediation pass and intentionally not changed
  here.
