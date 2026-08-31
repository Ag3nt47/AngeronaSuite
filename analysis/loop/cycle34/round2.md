# Cycle 34 Round 2 — lifecycle, atomicity, and Fleet custody

## DetectionForge convergence

Round 2 found and fixed five detection-authority classes:

- same-root policy downgrade, reopen, and runtime injection;
- detached or stopped runtime split brain, including direct coordinators;
- non-atomic registry/state/checkpoint/anchor changes across crash boundaries;
- stale reconciliation clearing a newer runtime epoch; and
- missing active-rule expiry, signer-revocation, quarantine, and trust
  revalidation.

The repair added an authenticated transaction journal and recovery for every
commit boundary, exact live-module lifecycle guards, full-set reconciliation,
and fail-closed runtime revalidation. Independent QA then closed rogue registry
sync, captured-journal rollback, stop/replacement races, old capability replay,
prestart restore and normal-restart gaps, manager replacement, and stopped
external processing.

## Canvas and Local Operations Center

The canvas server now reads descriptor-only regular single-link files, verifies
the final path on Windows, Linux, and macOS, checks identity after read, and
rejects reparse, hard-link, parent-swap, escape, stale, or non-contract input.
Metrics use the canonical data directory, exact bounded schema, and freshness
window. Browser insertion uses text content. The launcher uses the exact suite
interpreter, an operating-system-selected loopback port, bounded clients, and a
header timeout.

Local Operations Center construction moved off the GUI thread and became
cancellable and single-flight. A discovery reservation is distinct from
published readiness, so neither the module loader nor UI can start dependent
modules before exact composition succeeds; shutdown closes an orphan once.

Fleet rollout reads were batched and authenticated orphan rollout history is
rejected.

## Fleet follow-up findings

Independent QA found two further defects:

- **F1:** retained Fleet health rows outside the UI limit were not all covered
  by custody. Custody manifest v2 now binds every retained row, per-device
  chain/head, prune boundary, count, and exact-row projection. Legacy v1
  migration verifies the complete retained set before resealing.
- **F2 (High):** an at-capacity health mutation performed 3N+1 retained decodes
  and Ed25519 verification work. A tenant cache is now guarded by custody
  generation, SQLite `total_changes`, and `data_version`; a mismatch forces a
  full fail-closed verification. Exact HMAC-bound XOR projections make a known
  insert/prune delta incremental. Invalid envelopes fail before retained-state
  work.

Retention is limited to **5,000 rows**, each at most **8 KiB**, with an encoded
cache ceiling of about **40.96 MB**. On the same benchmark fixture, an N=250
mutation fell from about **0.7446 s to 0.0216 s**, and the final transactional
path measured about **0.0188 s** with zero retained-row decodes. A cached N=5,000
mutation measured about **0.289 s**; opening and fully authenticating 5,000
retained rows measured about **4.475 s**. Startup verification deliberately
remains O(retained state).
