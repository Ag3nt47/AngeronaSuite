# Cycle 27 Round 2 — Red Team Simulation Seventh Remediation

Date: 2026-08-28
Scope: frozen reopenings `RTS-R4-02` and `RTS-R4-03` only
Version retained: `1.12.1`
Disposition: **FIXED at the declared same-process simulation boundary**

## Safety and scope

This remediation used only temporary directories, inert marker text, temporary
authenticated event buses/SQLite recorders, and synthetic receipt-free events.
It did not run an exploit, probe a live host or network, access credentials,
install persistence, change a service/driver/registry object, or weaken an
existing test. The frozen independent suite
`tests/test_cycle27_redteam_simulation_sixth_independent_reattack.py` was not
edited.

Product changes were limited to:

- `src/angerona/modules/file_integrity.py`
- `src/angerona/modules/purple_guard.py`

The dedicated regression suite is
`tests/test_cycle27_redteam_simulation_seventh_remediation.py`.

## `RTS-R4-02` — immutable FIM scan custody and monotonic claim state

**Status: FIXED.**

`FileIntegrityModule._scan()` now creates a frozen, slots-only
`_FIMScanCustody` record whose canonical snapshot, path identities, reviewed
baseline, serialized scan receipt, generation, and coverage digest are retained
independently from the writable evaluator-facing `_FIMScanSnapshot`. The public
mapping remains a compatibility view and is never used to reconstruct proof.

`_claim_scan_evaluation()` now:

- requires the exact retained evaluator object and producer owner token;
- reads receipt and evidence only from immutable custody;
- requires the custody/receipt generation to equal the producer's exact current
  scan generation and lifecycle generation;
- compares the evaluator view to the canonical captured snapshot;
- burns the producer-owned consumed generation whether validation succeeds or
  fails;
- clears both pending handles after the single claim; and
- returns fresh receipt, identity, and baseline copies to the evaluator.

The lease issuer also retains a monotonic generation plus per-path claim set.
The producer capability refuses an older generation or a duplicate
coverage/path claim, and verification requires that exact issuer-owned claim.
The corresponding lease-authority façade no longer returns the live claim map.

The frozen post-scan injection and consumed-generation replay probes now fail
closed. An older genuine scan is also refused once a newer scan becomes current.

## `RTS-R4-03` — immutable acceptance dispatch and public-key verification

**Status: FIXED at the declared boundary.**

Native FIM and Process Monitor receipts now use one capability-owned ephemeral
Ed25519 private signer. Verification retains copied 32-byte public material and
accepts only the corresponding 64-byte signature. The lease façade's historical
`key` compatibility property returns a one-way public diagnostic digest, not the
HMAC key or native signer; using it to construct a receipt fails closed.

The façade also refuses ordinary reads or writes of native producer,
generation, capability, verifier, and FIM replay-state dictionaries. Internal
enrollment, claim, lookup, and revocation are narrow operations; verification
material is copied before use. Release revokes producer bindings and clears
public verifier and replay state.

The public verifier keeps the historical `verify_native_impl` closure-cell name
only so older compatibility probes can locate it. Acceptance dispatch uses the
original implementation captured as a default argument instead. Replacing the
closure cell can therefore cause only denial and cannot redirect an invalid
event to acceptance. Class-method replacement remains ineffective.

The evidence label was deliberately downgraded from
`same-process-object-capability` to
`same-process-simulation-validation`. Angerona does **not** claim that CPython
private attributes, function defaults, closure cells, module globals, or native
memory provide a process isolation boundary. Code already executing with
arbitrary interpreter introspection can ultimately inspect or mutate in-process
objects. A stronger "native analytic proof" claim requires moving the signer,
replay ledger, and verifier into a separately measured/restricted service and
exposing only opaque IPC handles and public keys. This remediation closes the
reported ordinary module API and mutable-dispatch paths without overstating that
irreducible boundary.

## Preserved closures

- `RTS-R4-05` fixed-head/AAR continuity and signed handoff stayed green.
- Native evidence remains bound to the exact enrolled producer object,
  capability ID, and lifecycle generation.
- The mandatory campaign denominator remains 13 contracts, including Process
  Monitor/T1059; incomplete or duplicate-only campaigns remain unscored.
- FIM and Purple Guard module versions remain exactly `1.12.1`.

## Gate results

- Frozen sixth independent reattack: **7 passed** (before remediation:
  **4 failed, 3 passed**).
- Dedicated seventh remediation suite: **4 passed**.
- Complete Cycle 27 Red Team simulation history matrix: **56 passed**.
- Exact full Cycle 27 selection (`pytest tests -k cycle27 -q -x`):
  **413 passed, 2 skipped, 2237 deselected**. A concurrent earlier report of
  52 façade-related failures sampled the shared `purple_guard.py` while its
  internal callers were being migrated from direct dictionary reads to the
  completed narrow operations. No such failure exists in the completed tree;
  no compatibility metadata or live capability-object view was added.
- Purple/drill compatibility matrix: **29 passed**.
- Wider lease/AAR/FIM matrix: **97 passed, 2 failed**. Both failures are
  unrelated Cycle 29 Windows path-case assertions already present in
  `tests/test_cycle29_fim_approved_baseline.py`:
  `test_missing_approved_file_is_detected_on_first_complete_scan` and
  `test_metadata_preserving_rewrite_invalidates_windows_change_token_cache`.
  Current `_canonical_roots()` applies `os.path.normcase`, so captured Windows
  keys/event paths are lowercase while those tests require the mixed-case input
  spelling. This remediation did not change that out-of-scope behavior.
- `py_compile`: **PASS** for both changed product modules and the dedicated test.
- Ruff: **PASS** for both changed product modules and the dedicated test.
- `FileIntegrityModule.self_test()`: **PASS**.
- `PurpleGuard.self_test()`: **PASS**.

No commit or publication was performed by this remediation agent.
