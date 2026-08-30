# Cycle 27, Round 1 — Eighth High-C Remediation

Date: 2026-08-28
Scope: independently reopened `C27-R1-C03` and `C27-R1-C13` residuals only
Status: **remediated and author-validated; independent re-attack required**

All probes used fake directory streams, temporary files/SQLite databases, and
an in-memory exact-CAS authority. No user document, live decoy, host policy,
service, driver, registry object, or network endpoint was attacked or changed.

## C27-R1-C03 — bounded enumeration and adjacent state/witness recovery

Status: **REMEDIATED — PENDING INDEPENDENT RE-ATTACK**.

`src/angerona/modules/ransomware_heuristics.py` now checks the traversal
deadline and generation stop token inside the held directory iterator, closes
the iterator on interruption, marks the directory truncated, and returns a
non-green coverage receipt immediately. The inert 100-entry stream that used
to consume all entries after a 250 ms budget now stops after the third yielded
entry; a stop raised during enumeration stops on the second.

Every state/witness replacement is now preceded by a small authenticated
adjacent transition binding the exact old/new sequence, scan epoch, and state
HMAC. Startup accepts only the finite proven states: old state + old witness
(no state commit), new state + old witness (repair witness), or new state + new
witness (clear completed intent). Genesis uses the same signed intent. Gaps,
forks, deletion, wrong installation key, changed HMAC, reversed ordering, and
ambiguous pairs remain refused.

## C27-R1-C13 — genesis and local metadata transaction reconciliation

Status: **REMEDIATED — PENDING INDEPENDENT RE-ATTACK**.

`src/angerona/modules/smart_deception.py` commits the authenticated genesis
external-transition intent before SQLite, local head, or witness enrollment can
make the installation appear authoritative. Restart can complete only that
exact sequence-zero intent, including interruptions before the ledger, before
the head, before the witness, during authority outage, or after a lost CAS
response.

For subsequent events, startup validates the authenticated outbox and ledger
chain before requiring head/witness equality. It accepts only no local commit,
SQLite-new/head-old/witness-old, head-new/witness-old, fully local-new/remote-old,
or remote-new response-lost states. Exact old metadata is repaired forward
under the existing OS writer lease. The transition is retained across an
ambiguous SQLite `COMMIT` exception and removed only after restart proves the
predecessor or completes the exact new state. Forks, gaps, missing intent,
changed installation/domain, witness-before-head ordering, and inconsistent
digests remain recovery-required.

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

A traversal deadline necessarily produces incomplete metadata coverage; it is
reported as truncated/non-green rather than described as a complete scan. The
process-private keyed reservoir prevents a public fixed ranking, but a truly
fair resumable walk across an arbitrarily slow namespace still requires a
platform-specific durable directory continuation primitive. Smart Deception's
external head proves rollback freshness, not remote/WORM custody of local
evidence bytes; the existing `captured_unverified` semantics and health-95
ceiling remain.
