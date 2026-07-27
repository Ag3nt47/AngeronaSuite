# Cycle 4 / Round 2 — Purple-Team Summary

## Scope

Reviewed the Posture Hardening paths that consume Red Team AARs and install
Purple Guard detector candidates. The security invariant is now uniform:
automatic ingestion and operator-triggered `resolve_redteam_report()` must both
authenticate the exact loaded JSON document before it can change weakness,
acknowledgement, or detector-policy state.

## Findings and fixes

### P-01 — Verifier exceptions were trusted

- **Finding:** `_aar_trusted()` returned `True` when the attestation module could
  not import or `classify_for_ingest()` raised. A verifier/key/canonicalization
  failure therefore converted an unknown-authenticity document into trusted
  self-hardening input.
- **Fix:** verifier exceptions now produce a HIGH-severity, fail-closed integrity
  decision, set `last_error`, emit/log the existing integrity event, and return
  untrusted. Exception text is newline-normalized and bounded.
- **Security result:** verifier failure cannot create/reopen weaknesses or
  authorize detector-policy installation.

### P-02 — Manual Red Team resolution bypassed AAR authentication

- **Finding:** `resolve_redteam_report()` loaded `redteam_aar.json` and directly
  acknowledged findings and installed Purple Guard candidates without calling
  `_aar_trusted()`. Under strict mode, an unsigned or tampered report rejected by
  automatic ingestion could still reach the same state-changing workflow through
  the GUI/manual action.
- **Fix:** the manual path now applies the same HMAC and strict-mode trust gate to
  the already-loaded document before extracting findings or writing resolution/
  policy files. Rejection returns explicit `authentication_failed` and
  `fail_closed` fields.
- **Compatibility:** valid HMAC-signed reports retain the existing candidate
  installation and rerun-verification workflow. Lenient-mode legacy behavior
  remains governed by `report_attest.classify_for_ingest()`.

## Proof matrix

| Case | Expected result | Gate |
|---|---|---|
| Valid signed miss, strict mode | Ingest weakness and install candidate | PASS |
| Unsigned report, strict mode | No ingest, acknowledgement, or policy write | PASS |
| Signed then tampered report | No ingest, acknowledgement, or policy write | PASS |
| Verifier raises | HIGH/fail-closed; no state mutation | PASS |
| Candidate's source run reports caught | Remains `VULNERABLE` | PASS |
| Distinct later signed run, Purple Guard caught | Transitions to `PATCHED` | PASS |
| Later signed miss after patch | Reopens as `VULNERABLE` | PASS |
| Duplicate supported and unsupported findings | One candidate; unsupported ID remains visible | PASS |

## Verification

- `python -m py_compile src/angerona/modules/posture_hardening.py
  tests/test_cycle4_round2_purple.py`: **PASS**
- New focused suite `tests/test_cycle4_round2_purple.py`: **7 passed**
- New suite plus existing policy/drill and Cycle 3 security regressions:
  **18 passed**
- `PostureHardening.self_test()`: **PASS**
- `git diff --check` on owned files: **PASS**

Files changed:

- `src/angerona/modules/posture_hardening.py`
- `tests/test_cycle4_round2_purple.py`
- `analysis/loop/cycle4/round2/purple_summary.md`
