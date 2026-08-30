# Cycle 27 Round 1 — Third High-C Remediation

Date: 2026-08-28
Scope: `C27-R1-C03` and `C27-R1-C13` only
Safety: inert temporary-directory filesystem fixtures only; no service, driver,
registry, security-control, user-document, or non-temporary host mutation.

## Result

| Finding | Remediation verdict | Defensive result |
|---|---|---|
| C27-R1-C03 | REMEDIATED | Every pathname ancestor is opened no-follow and held, the exact file is re-read from its held object, sample length and SHA-256 are compared with the enumeration receipt, and those objects remain held through event publication. Stale content or ancestry makes coverage incomplete and health less than 100. |
| C27-R1-C13 | REMEDIATED | Evidence custody is an HMAC-chained append-only SQLite ledger with an independently stored authenticated high-water, exact root/file identity, size, digest, and monotonic sequence. Inventory must exactly equal the active ledger set. Missing, foreign, substituted, rolled-back, pending-crash, alias-residue, and retention-eviction states are fail-visible. |

## C27-R1-C03 changes

- `ransomware_heuristics.py:697` now admits only a lexical child of the enrolled
  root and opens/holds the root plus every intermediate directory no-follow.
  On Windows the reviewed handles omit delete sharing, preventing a junction or
  rename from replacing an accepted ancestor while the next component opens.
- `ransomware_heuristics.py:761` converts the exact held file handle to a
  descriptor, rereads the bounded sample, compares length and SHA-256 using
  constant-time digest comparison, verifies exact file identity/size/generation,
  and computes entropy from those current held bytes.
- `ransomware_heuristics.py:1143` retains the exact file and ancestry across the
  decision and event publication boundary. Any acquisition, ancestry, identity,
  length, or digest mismatch increments errors/skips, marks coverage incomplete,
  records the exact reason, and prevents health 100.

Hostile regressions cover both directions of same-inode overwrite with restored
size and nanosecond mtime, and both directions of an intermediate NTFS junction
to a hard link of the sampled file ID. Neither stale false-negative nor stale
false-positive evidence is published.

## C27-R1-C13 changes

- `smart_deception.py:839` validates every append-only custody record from
  genesis through the independently authenticated head. Sequence gaps, chain
  changes, row authentication failures, missing high-water, and ledger rollback
  fail closed.
- `smart_deception.py:911` appends only `commit` and `evict` events, binds exact
  evidence/root identity, bytes, digest, and prior HMAC, uses a full-sync
  transaction, and advances the separate authenticated head. The ledger has a
  hard 4,096-event capacity and refuses new evidence rather than pruning state.
- `smart_deception.py:986` requires the physical inventory to exactly equal the
  ledger's active record set. A filename-selected plain digest is still checked
  as integrity metadata but is no longer custody authority. Missing evidence,
  injected self-consistent records, foreign identities, and substitutions set
  custody loss and saturation.
- Bounded single-link pending crash objects are removed by exact held-object
  disposition, but the interruption permanently remains visible as custody
  degradation/loss rather than silently becoming healthy.
- Capacity pressure retains every unresolved legitimate evidence object and
  refuses the incoming archive. Age-policy eviction is authenticated and also
  records continuity loss; it never looks like uninterrupted custody.
- `smart_deception.py:1339` commits the sealed evidence receipt before source
  retirement, rechecks source identity/size/link count immediately before and
  after delete disposition, accounts late aliases, and conservatively degrades
  custody because the reviewed Windows APIs cannot prove a race-free complete
  hard-link namespace enumeration.

The authenticated high-water and protected key live outside the mutable
evidence directory. This is local tamper evidence, not a claim that local files
can defeat an attacker who already captured every protected authority at an
earlier point in time; external/TPM-backed monotonic anchoring remains the
stronger deployment option.

## Validation

```text
python -m pytest -q tests/test_cycle27_round1_high_c.py \
  tests/test_cycle27_high_c_third_remediation.py
33 passed, 1 skipped

python -m py_compile src/angerona/modules/ransomware_heuristics.py \
  src/angerona/modules/smart_deception.py
PASS

python -m ruff check src/angerona/modules/ransomware_heuristics.py \
  src/angerona/modules/smart_deception.py \
  tests/test_cycle27_round1_high_c.py \
  tests/test_cycle27_high_c_third_remediation.py
PASS

RANS self_test: PASS
SDEC self_test: PASS
```

The single skip is the pre-existing directory-symlink privilege fixture; both
unprivileged NTFS junction cases and all new same-inode, evidence-substitution,
retention-pressure, late-alias, pending-crash, and rollback probes passed.
