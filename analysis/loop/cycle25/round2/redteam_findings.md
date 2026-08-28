# Cycle 25 / Round 2 — Reliability and integration re-audit

Date: 2026-08-27
Product target: 1.12.0

## Outcome

Round 2 re-audited the Round 1 durability, lifecycle, and transaction lineages
under saturation, restart, injected I/O failure, external SQLite mutation, and
worker-start failure. The records below overlap Round 1 and are not additional
unique-vulnerability totals.

| ID | Reliability finding | Disposition |
| --- | --- | --- |
| C25-R2-01 | Export cursors could not advance before the entire selected delta was durably staged, and saturation still needed an explicit gap receipt. | **Fixed.** Cursor commit follows complete durable staging; drain-stage-drain frees capacity first; retained-ring loss stages explicit capacity-gap evidence. |
| C25-R2-02 | Authenticating only the original outbox payload would not detect tampering with lease, attempt, timer, error, size, or state fields. | **Fixed.** The mutable row state has its own HMAC; external `data_version`/change detection triggers a full sweep before trusted use. |
| C25-R2-03 | Using the rotatable Remote Bridge transport key as durable queue custody could make pending work unreadable after rotation. | **Fixed.** Durable queue custody uses an independent protected local key. Live peer coordination still uses restart epochs. |
| C25-R2-04 | A restarted instance could reseed its EventBus cursor and skip events published while that same capability was stopped. | **Fixed.** Cursor enrollment happens only for the first module generation; later generations resume the committed revision. |
| C25-R2-05 | Settings, protected credentials, and autostart could become mutually inconsistent if one step failed. | **Fixed.** Settings replacement is atomic and the GUI transaction compensates exact prior settings bytes, protected credentials, environment projection, and autostart state. Composite rollback failure is explicit. |
| C25-R2-06 | Threat-intelligence refresh could publish stale/cancelled generation output or leave partially replaced state. | **Fixed.** Candidate generation, cancellation and status are rechecked around exclusive atomic replacement; workers retire deterministically. |
| C25-R2-07 | IPC's isolated self-test could restore a stale counter snapshot and erase concurrently completed production authorization counts. | **Fixed.** Test handshakes use isolated accounting and never snapshot/restore live counters. |
| C25-R2-08 | Failed connection-helper startup could leak an IPC/Remote admission slot; inline EventBus subscriber latency/failure also needed observability. | **Fixed.** Startup failure closes and retires helpers/capacity; bounded subscriber budgets expose deliveries, failures, maximum latency, and budget violations. |

## Retained reliability boundaries

- Outbox delivery is at least once. A crash after remote acceptance but before
  durable acknowledgement can produce a duplicate.
- Local row HMACs do not independently witness deletion or rollback of the
  complete database and its local state.
- Transport-key rotation does not yet provide a coordinated, no-restart peer
  epoch protocol.
- Subscriber budgets are observability/SLO evidence; callbacks remain inline
  and ordered rather than being silently dropped or reordered.
