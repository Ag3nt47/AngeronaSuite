# Cycle 27, Round 1 — Eighth High-A Remediation

Date: 2026-08-28
Scope: independently reopened `C27-R1-A01` and `C27-R1-A16` residuals only
Status: **remediated and author-validated; independent re-attack required**

All validation was defensive and inert: temporary directories, fake Security
channel records, in-memory protected-store stand-ins, and an in-process test
EventBus. No live process, host Security log, firewall, policy, credential, or
network target was attacked or changed.

## C27-R1-A01 — bounded protected authority and continuous undo custody

Status: **REMEDIATED — PENDING INDEPENDENT RE-ATTACK**.

- `src/angerona/modules/adversary_combat.py` applies the journal's strict
  structural contract to protected recovery anchors and witnesses before
  authentication: 16 KiB byte ceilings, a 16-level pre-parse depth scan,
  duplicate-member rejection, non-finite-value rejection, bounded members and
  containers, exact UTF-8 decoding, and conversion of `MemoryError`,
  `RecursionError`, decode, parse, and numeric failures to
  `JournalIntegrityError`. Reconciliation therefore opens the visible health-0
  mutation circuit instead of letting hostile nested JSON escape the worker.
- The shared current undo implementation retains the receipt lock, OS writer
  lease, capacity reservation, and one descriptor-pinned canonical journal
  session across trusted-record selection, undo intent, `_undo_record()` host
  compensation, postcondition, and terminal phase. This code was preserved
  rather than refactored because a concurrent scoped remediation had already
  installed the exact custody fix; its inert deletion-at-effect regression is
  green.

Deep 4,000-level anchor and witness values now both return reconciliation
failure, `_mutation_blocked=true`, and health 0 without `RecursionError`.

## C27-R1-A16 — authenticated at-least-once Security delivery

Status: **REMEDIATED — PENDING INDEPENDENT RE-ATTACK**.

`src/angerona/modules/etw_listener.py` now persists an authenticated, bounded
Security-delivery outbox before committing cursor progress. Each pending row is
bound to the host, channel, predecessor cursor sequence/HMAC, target generation,
target record/anchor, and stable `generation + record + record-anchor` identity.
The outbox is byte/record bounded and written atomically under the existing OS
cursor-writer lease.

On restart, an unacknowledged batch is replayed before the Security channel is
read again and health remains below 100. `run()` removes the exact batch only
after every EventBus publication returns successfully. A process loss or bus
exception before that acknowledgement therefore causes duplicates, never a
silent omission. If outbox preparation fails, cursor progress is restored and
the detector remains visibly degraded; if cursor commit fails after outbox
preparation, the authenticated batch remains replayable from the old cursor.

## Gates

| Gate | Result |
|---|---|
| New eighth-remediation crash/custody matrix | `PASS` — `16 passed` (combined A/C) |
| Updated seventh hostile reproductions + seventh author regressions | `PASS` — `40 passed` |
| Directly affected High-A/High-C/module compatibility matrix | `PASS` — `197 passed, 2 expected skips` |
| `py_compile` for four product modules and four changed/new tests | `PASS` |
| Ruff for the same product/test files | `PASS` |
| Combat armed-state, ETW decoder, RANS, and SDEC `self_test()` | `PASS` — `4/4` |
| Owned-file `git diff --check` | `PASS` (line-ending notices only) |

## Honest residual boundary

EventBus publication is an in-process acknowledgement, not an external SIEM
receipt; downstream consumers requiring end-to-end delivery must retain their
own durable acknowledgement. Complete rollback of every local schema-2
authority object together with the stable signing identity remains the
disclosed whole-host snapshot boundary and requires TPM monotonic state or a
separately administered witness. POSIX cannot promise Windows-style
deny-delete custody against a privileged non-cooperating unlink.
