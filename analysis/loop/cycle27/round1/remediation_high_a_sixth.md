# Cycle 27, Round 1 — Sixth High-A Remediation

Scope was limited to the residuals in the fifth independent High-A re-attack
for `C27-R1-A01` and `C27-R1-A16`. All reproductions were defensive, local,
inert, and confined to temporary directories, in-memory protected-store
stand-ins, fake action records, and an in-memory EventBus. No live process was
mutated, no host Security channel or policy was changed, and no network target
was contacted. These author-side fixes remain **pending an independent hostile
re-attack** and do not self-close either finding.

## `C27-R1-A01` — legacy floor, writer authority, and journal custody

- `src/angerona/modules/adversary_combat.py:1875-1962` now serializes first
  enrollment and legacy migration, then treats any surviving
  authenticated recovery witness as a monotonic schema floor. A valid schema-1
  anchor can migrate only on a genuine pre-witness installation. If a witness
  already exists, legacy replay fails closed, leaves the mutation circuit
  disarmed, and never rewrites or lowers that witness.
- `src/angerona/modules/adversary_combat.py:153-260` and `:988-995` add a
  state-root-scoped, re-entrant in-process lock plus a single-link/no-reparse OS
  byte-range lease. The complete read, append, protected-anchor advance,
  signing-key-witness advance, and final reread run beneath that lease. A
  duplicate instance therefore cannot report a second false success.
- `src/angerona/modules/adversary_combat.py:2067-2219` replaces path-based
  journal reads/appends with descriptor-pinned custody. Both the state root and
  receipt parent must remain non-link directories; the journal must remain the
  same regular, single-link, non-reparse object before and after I/O; exact byte
  growth and parent identities are checked after `fsync`.
- `src/angerona/modules/adversary_combat.py:2297-2330` does not return success
  until the exact appended record is reread and the full journal/anchor/witness
  transaction verifies.

Exact inert regressions prove that (1) restoring a copied schema-1 empty anchor
and journal after advancing an intent/orphan cannot overwrite the surviving
newer witness, (2) one of two overlapping module instances is rejected before
it can append or claim success and the remaining journal is restart-valid, and
(3) a planted hard-link receipt path is rejected before a byte reaches the
unrelated linked file. A genuine pre-witness schema-1 installation still
migrates once.

## `C27-R1-A16` — non-replayable Security authority schema floor

- `src/angerona/modules/etw_listener.py:729-762` now checks the independent
  authority witness before any schema-1 migration. If a current witness
  survives, an authenticated legacy protected anchor is treated as rollback,
  explicit enrollment remains required, and migration cannot replace the
  witness. Only a genuine pre-witness installation can perform the one-time
  schema-1-to-schema-2 migration.
- The complete record identity, honest bounds, live authority verification,
  commit order/final reread, and existing state-root writer lease remain
  unchanged.

The inert regression creates a valid legacy anchor, advances the current
schema-2 authority revision, restores only the legacy anchor while retaining
the newer witness, and verifies that loading fails closed and the witness is
byte-identical afterward. A separate regression preserves legitimate
pre-witness migration.

## Gates

| Gate | Result |
|---|---|
| New sixth-remediation regressions | `PASS` — `6 passed` |
| New + all directly affected Combat/ETW suites | `PASS` — `90 passed` |
| `py_compile` for both product modules | `PASS` |
| Ruff for both product modules and the new test | `PASS` |
| Combat inert armed-state `self_test()` | `PASS` |
| ETW inert 4688-decoder `self_test()` | `PASS` |
| `git diff --check` for owned product/test files | `PASS` (line-ending notices only) |
| Independent hostile re-attack | **PENDING — required before closure** |

The disclosed all-local-snapshot boundary is unchanged: software on the same
host cannot distinguish rollback of every durable witness plus its stable
signing identity and matching host telemetry snapshot. TPM monotonic state or
an independently administered append-only witness is required for that
stronger claim.
