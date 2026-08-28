# Cycle 25 / Round 2 — Reliability remediation summary

Date: 2026-08-27

## Durable delivery

- Added one bounded SQLite durable-outbox primitive with persistent idempotency
  tombstones, leases, retries, dead-letter state, capacity limits, payload
  digests/HMACs, mutable-state HMACs, and fail-closed integrity checks.
- SIEM Forwarder and Remote Bridge drain existing work, durably stage the full
  selected EventBus delta, commit the revision cursor, then drain again. A
  staging failure leaves the cursor unchanged; replay is idempotent.
- Same-instance restarts preserve the enrolled cursor so events published while
  stopped remain stageable. Ring overflow creates an explicit gap receipt.
- The Remote queue key is independent of the rotatable transport key. This
  protects queued data during ordinary key rotation but does not provide a live
  coordinated peer-epoch protocol.

## Transaction and lifecycle safety

- Core configuration uses exclusive candidate creation, flush/fsync, atomic
  replace, and compensation for protected push credentials when replacement
  fails.
- The Settings GUI stages values and compensates exact prior settings,
  protected credentials, environment state, and autostart if a later step
  fails.
- Intel Sync uses generation-owned workers, cancellation/status rechecks, and
  atomic publication so stale completion cannot overwrite current state.
- IPC and Remote helper-start failure closes the connection, retires helper
  ownership, and releases the exact admission slot.
- EventBus subscriber delivery budgets expose latency/failure SLO data without
  changing ordered inline delivery.

## Focused evidence

Round 2 QA compiled 346 product files, discovered 80 modules without duplicate
identities, passed 24 standalone core self-tests, passed direct and batch
selfcheck 26/26, and passed the focused durability/adaptation/IPC/lifecycle
groups recorded in [bugtest_results.md](bugtest_results.md). One IPC accounting
race was found and fixed; no security limit or timeout was weakened.
