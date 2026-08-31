# Cycle 34 Round 3 — temporal, admission, and trust closure

## Detection authority

The Round 3 re-attack found and fixed four authority gaps:

- **High:** a consumed receipt could be pruned after a clock jump and replayed
  after rollback. State, checkpoint, anchor, and journal now bind a
  nondecreasing `authority_time_floor`.
- **High:** two supported processes could own the same promotion root and live
  engines. A lifetime operating-system owner lease permits only the exact
  in-process owner (with controlled reference sharing); a contender fails
  closed, and crash/reopen releases the operating-system lock normally.
- **Low:** signature-policy strength previously relied partly on a process-local
  floor. A root-HMAC governance anchor now binds policy identity, signed mode,
  trust path, and generation. A complete root-plus-key rollback remains an
  external-witness boundary.
- **Medium:** revocation or quarantine could strand an invalid active binding.
  Validation is side-effect-free, and a journaled quarantine transition
  removes invalid state, registry, and runtime bindings with restart recovery.

Fresh-process re-attack then reproduced a published-v2/floorless-v3 A→B→A
migration replay. Migration now proves the complete authenticated transition
history: nondecreasing authorization time, current time at or above the newest
authorization, exact head/predecessors/active set, unique receipt identities,
and receipt tombstones through `authorized_at + 86,400 seconds`. Ambiguous or
truncated history fails closed. The malformed-history matrix passed **16/16**;
lease crash/reopen and quarantine recovery re-attacks found no new issue.

A publication-bound lease re-attack then found same-process authority aliasing,
a close/use check-to-lock race, mutable registry/state-lock rebinding, and POSIX
`fork` inheritance of the in-memory lease and file descriptor. The lease now
captures creator PID, canonical registry/state/checkpoint/anchor/lock/
transaction/quality paths, governance configuration, transition capability,
clock, policy, quality authority, and runtime identities. Configuration is
revalidated under the coordinator lock; a forked child discards inherited
descriptors without `LOCK_UN`. Exact siblings retain reference sharing, while
foreign, mutated, closed, and fork-inherited owners fail closed. The bounded
final re-attack found no remaining owner-lease bypass.

## Fleet admission and cache integrity

Round 3 found and fixed five admission/lifecycle gaps:

- **High:** invalid pre-admission input could commit the clock floor and force a
  cold-cache/full-verification denial of service. Clock inspection is now
  nonmutating, and its durable advance occurs only inside an accepted
  transaction.
- **High:** an exact captured replay consumed fresh burst capacity. Exact
  idempotent replay is recognized before quota consumption.
- **Medium:** process-local limiter state reset at restart. Bounded admission
  state is rebuilt from custody-authenticated retained evidence.
- **Medium:** the prior 50,000 bucket bound did not cover the possible 100,000
  tenant/device identities. The retained/cached authority is now capped at
  5,000 and admission state is bounded to that contract.
- **Medium:** a rolled-back transaction could consume volatile quota. A
  reservation is held through commit and cancelled on rollback.

When retained history has been pruned, restart reconstruction deliberately
starts conservatively and refills only from elapsed trusted time. Same-
connection, external-connection, and delete/insert cache tampering all force
full fail-closed revalidation.

## Detection performance and trust re-attack

Detection Runtime coalesces event decoding once per active or shadow lane while
preserving per-rule elapsed-budget attribution and visible malformed-input
failures. The benchmark fixture reduced **1,920 decodes to 30** and ran about
**4× faster**.

Full-set reconciliation reads registry governance twice per operation instead
of once per package; a 32-package fixture reduced **64 reads to 2** and ran
about **2× faster**. A subsequent High trust-store time-of-check/time-of-use
re-attack showed that per-package reads could mix key generations. Registry
validation now uses one bounded immutable publisher-key snapshot, stable
package/signature generation proofs, and exit identity/hash checks. A
16-package fixture reduced trust-store reads from **N to 2**. Key rotation,
malformed/oversized trust stores, exit-time mutation, and signature replacement
all fail closed.

## Final targeted gates

Cycle 34's targeted suite passed **91 tests with two expected Windows host-
capability skips** (symlink creation and POSIX `fork`); the adjacent selection
passed **128 tests**. Package compile
passed **368/368**. Standalone self-tests passed **93 with 0 failures**, plus
**16 expected platform, disabled, or optional-prerequisite skips**. Supported
selfcheck passed **26/26**. The full serial run and authoritative release gate
remain pending.

The canonical Word manual was regenerated from its pristine snapshot and all 41
rendered pages passed structural, accessibility-high-severity, and visual QA.
