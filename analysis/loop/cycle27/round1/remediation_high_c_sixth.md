# Cycle 27 Round 1 — Sixth High-C Remediation

Date: 2026-08-28
Scope: `C27-R1-C03` and `C27-R1-C13` only
Status: **implemented and author-validated; independent re-attack required**

This pass addresses only the residuals reproduced by the fifth independent
high-C re-attack. It does not claim perfect ransomware detection, immutable
userspace evidence, or rollback resistance against an administrator who can
replace every local authority. All attack-shaped tests use inert files under
pytest temporary directories.

## C27-R1-C03 — active change authority and deterministic content evasions

`src/angerona/modules/ransomware_heuristics.py` now:

- upgrades content state to schema v2 and maintains a separately keyed,
  authenticated high-water witness outside the replaceable key/state bundle
  (`:84-91`, `:501-573`, `:636-755`); an older valid sequence, isolated witness
  loss, key+state deletion while enrollment survives, and legacy re-enrollment
  after v2 are refused;
- consumes prior identity/path/content receipts before replacement and emits
  typed `unchanged`, `changed`, `new`, `missing`, and `incomplete` transitions
  (`:771-899`); changed and missing evidence produce bounded alerts, while an
  incomplete cycle retains the last complete receipt set;
- replaces suffix-only exclusions with suffix **plus magic bytes plus a prior
  unchanged authenticated receipt**. New recognized containers are counted as
  `unproved_exclusions` and remain below health 100 until reviewed by an
  unchanged subsequent observation (`:223-286`, `:1815-1872`, `:1923-1951`,
  `:1971-2028`);
- retains fixed 64 KiB entropy windows even during a complete full-file read.
  A file is scored on its maximum window when at least 25% of measured windows
  are high entropy, closing the deterministic 50% alternating/strided evasion
  without promoting a single random fragment (`:80-88`, `:1253-1329`); and
- persists and advances a scan epoch on complete *and incomplete* cycles. Each
  bounded directory view is sorted then rotated by that durable epoch, so a
  stable directory prefix cannot starve the same tail forever (`:849-899`,
  `:1652-1694`). Existing large-file range and byte-budget misses remain
  explicitly incomplete/non-green.

Local files still cannot prove freshness against an administrator who replaces
the state key, enrollment key, state, and witness coherently. Accordingly,
loaded local-only state is capped at health 90 with the exact reason
`local-authenticity-only: TPM/remote monotonic witness not configured`.

## C27-R1-C13 — protected namespace, external monotonic authority, typed custody

`src/angerona/modules/smart_deception.py` now:

- accepts an optional `IndependentHighWater` authority and binds each local
  sequence/head to an authenticated remote/TPM-style monotonic digest
  (`:783-877`). Fresh local absence is refused as `RECOVERY_REQUIRED` when the
  independent authority retains history; coherent local rollback, deletion,
  and key/witness substitution are likewise local-behind or forked rather than
  silently enrolled;
- applies and verifies the packaged service/admin-only ACL boundary on the
  quarantine directory, every newly published evidence object, and retained
  evidence encountered during inventory (`:1440-1472`, `:1537-1550`,
  `:1919-1926`). Required ACL failure refuses capture before source retirement;
- records a typed `CustodyCaptureOutcome`. Userspace captures remain
  `captured_unverified` while NTFS link topology is not kernel-sealed, even when
  current digest/link checks pass (`:111-122`, `:1888-2017`). A compatibility
  boolean now means only that durable capture and source retirement completed;
  it is not an immutability assertion; and
- reports exact freshness, independent verification, namespace protection,
  capture outcome, and `prior_history_may_have_been_erased` in health. Purely
  local authority is capped at 70 (or 65 when the namespace ACL is unverified),
  and even independent freshness is capped at 95 until evidence is replicated
  to remote append-only/WORM custody (`:2288-2350`).

The post-final hard-link race is preventable for ordinary user processes in a
packaged/elevated deployment because the evidence namespace and file DACL are
verified before success. It is **not** cryptographically preventable against a
same-host administrator from userspace. For that actor, the module provides
durable non-green disclosure and remote monotonic rollback detection, but true
preservation still requires a reviewed minifilter, TPM policy, or separately
administered append-only/WORM replication.

## Regression coverage

New file: `tests/test_cycle27_high_c_sixth_remediation.py`

The nine regressions cover:

1. valid authenticated ransomware state rollback;
2. key+state deletion while the enrolled witness survives;
3. changed and missing receipt transitions with restored timestamps;
4. entropy-8 content under a mutable `.zip` suffix;
5. deterministic 50% alternating 64 KiB encryption;
6. fail-visible enrollment of a valid new packed container;
7. durable fair-epoch advancement without receipt loss on incomplete scans;
8. independent-authority refusal of total local deletion and coherent rollback;
9. typed `captured_unverified` custody plus verified ACL enforcement.

## Gates

```text
python -m pytest -q tests/test_cycle27_round1_high_c.py \
  tests/test_cycle27_high_c_third_remediation.py \
  tests/test_cycle27_high_c_fifth_remediation.py \
  tests/test_cycle27_high_c_sixth_remediation.py \
  tests/test_deception_data_boundary.py \
  tests/test_semantic_response_contracts.py \
  tests/test_round7_performance_boundaries.py
80 passed, 1 skipped in 24.61s

python -m py_compile src/angerona/modules/ransomware_heuristics.py \
  src/angerona/modules/smart_deception.py \
  tests/test_cycle27_high_c_sixth_remediation.py
PASS

python -m ruff check src/angerona/modules/ransomware_heuristics.py \
  src/angerona/modules/smart_deception.py \
  tests/test_cycle27_high_c_sixth_remediation.py
PASS

RANS self_test: PASS
SDEC self_test: PASS
```

The one skip is the pre-existing privilege-dependent directory-link fixture.
Author validation does not close either finding; a sixth independent hostile
re-attack must decide closure.
