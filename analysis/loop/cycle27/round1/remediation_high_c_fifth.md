# Cycle 27 Round 1 — Fifth High-C Remediation

Date: 2026-08-28
Scope: `C27-R1-C03` and `C27-R1-C13` only
Status: **implemented and author-validated; independent re-attack required**

This pass responds directly to the fourth independent re-attack.  It does not
self-close either finding and it does not claim perfect ransomware detection or
administrator-proof anti-rollback.

## C27-R1-C03 — timestamp-independent, bounded content proof

`src/angerona/modules/ransomware_heuristics.py` now:

- removes last-write time from entropy admission; an old or restored timestamp
  no longer suppresses analysis;
- streams every byte of eligible files through 8 MiB (`:80`, `:890-976`) and
  binds the whole-file entropy and SHA-256 receipt to the exact held identity,
  size, generation and ancestry;
- uses start/middle/end plus identity-keyed, per-process unpredictable ranges
  for larger files, records every offset and length, and marks that evidence as
  incomplete rather than promoting it to health 100 (`:890-976`, `:1113-1175`);
- enforces a 64 MiB per-root content-read budget and reports exact analyzed,
  incomplete, byte and exhausted counts (`:676-715`, `:1365-1475`,
  `:1514-1548`); and
- maintains bounded, HMAC-authenticated, identity/path/content receipts across
  restart.  Missing, mismatched, malformed, oversized or unauthenticated state
  is fail-visible and cannot be silently recreated while its key remains
  (`:365-566`).  These receipts are continuity evidence, not a substitute for
  the current held full/range reread.

The exact fourth-attack shape is now covered: a 4 MiB file with a preserved
64 KiB header and high-entropy tail is read in full and detected even with a
two-hour-old restored timestamp.  If its content changes between discovery and
publication, the stale full-file receipt is rejected, coverage is downgraded,
and the timestamp-independent next scan analyzes the current generation.

## C27-R1-C13 — durable degradation, enrollment witness and reserved capacity

`src/angerona/modules/smart_deception.py` now:

- expands the closed authenticated event schema with `evict_intent`, `alias`,
  `topology`, `pending_loss`, `refuse`, and `continuity_loss` (`:77-88`);
- reconstructs latched loss, alias, topology uncertainty, refusal, eviction and
  pending-transition state from the complete HMAC chain on every restart
  (`:965-1157`);
- creates a separately keyed high-water witness outside the create-on-missing
  key/SQLite/head bundle.  Main-bundle deletion, partial authority loss and a
  paired older database/head are rejected behind that witness (`:708-823`,
  `:965-1157`).  Health explicitly reports `local-authenticity-only` because a
  same-host witness is not a TPM or separately administered monotonic service;
- records pending recovery before deleting the pending object and appends an
  eviction intent before deleting retained evidence.  Evidence is never
  retired merely to make room before terminal ledger capacity is durable
  (`:1278-1325`, `:1452-1525`);
- reserves 32 terminal events, exposes remaining/capture capacity before the
  next incident, and refuses source retirement when a full archive transaction
  cannot fit (`:84-90`, `:1173-1261`, `:1452-1525`, `:1684-1770`,
  `:1923-1973`); and
- performs a second full digest/link-count reconciliation at the publication
  boundary.  Because reviewed userspace APIs cannot make NTFS link-topology
  observation indivisible, every accepted archive first persists a permanent
  `topology` uncertainty event.  A link observed at either reconciliation is
  also persisted as `alias`, so a post-final-link race can never retain or
  regain health 100 (`:1653-1770`, `:2048-2096`).

Complete deletion of both the custody bundle *and* its independently located
enrollment key/witness remains a same-host administrator boundary.  The module
does not hide that limitation: even a clean locally witnessed custody state is
capped below 100 until a TPM/remote monotonic authority exists.

## Regression coverage

New file: `tests/test_cycle27_high_c_fifth_remediation.py`

The ten new regressions reproduce:

1. old-mtime, header-preserving 4 MiB encryption;
2. a same-inode tail swap with exact timestamp restoration, followed by retry;
3. large-file representative-range coverage and non-green disclosure;
4. content byte-budget exhaustion;
5. authenticated change receipts across restart, timestomp and state deletion;
6. source-alias/topology degradation across restart;
7. pending-crash and authenticated eviction loss across restart;
8. complete main-authority deletion and paired database/head rollback;
9. a real hard link created after the final evidence observation; and
10. terminal ledger reservation before source retirement.

## Validation

```text
python -m pytest -q tests/test_cycle27_round1_high_c.py \
  tests/test_cycle27_high_c_third_remediation.py \
  tests/test_cycle27_high_c_fifth_remediation.py
43 passed, 1 skipped in 17.14s

python -m pytest -q tests/test_round7_performance_boundaries.py \
  tests/test_semantic_response_contracts.py -k "ransomware or Ransomware"
4 passed, 20 deselected in 6.59s

python -m py_compile src/angerona/modules/ransomware_heuristics.py \
  src/angerona/modules/smart_deception.py
PASS

python -m ruff check src/angerona/modules/ransomware_heuristics.py \
  src/angerona/modules/smart_deception.py \
  tests/test_cycle27_round1_high_c.py \
  tests/test_cycle27_high_c_third_remediation.py \
  tests/test_cycle27_high_c_fifth_remediation.py
PASS

RANS self_test: PASS
SDEC self_test: PASS
```

The one skip is the pre-existing Windows directory-link privilege fixture.
All attack-shaped regressions use inert temporary files only.
