# Reported fixes — deep review round 2, 2026-09-23

The patch applier fixed **D23-R2-01 (LOW)** from `adversary-round2.md`.
No other finding or product area was changed in this pass.

| Finding | Change | Compile | Self-test / regression | Status |
|---|---|---|---|---|
| D23-R2-01 | `modules/lsass_guard.py` and `modules/shadowcopy_guard.py` classify uncorroborated command-text matches as observations with `active_attack=False` and `response_authorized=False`. `core/threat.py` recognizes only these exact producers' old `semantic-indicator-alert-only` policy for compatible historical observations. | PASS | Both detector self-tests PASS; 102 focused/adjacent tests PASS. | FIXED |

The original CRITICAL severity, finding message, command evidence, MITRE labels,
coverage counts and alert visibility are retained. The observed text alone no
longer claims an active attack or wakes Chill's deep workers.

Exact tool/argument findings remain active independently of response-contract
availability. A genuine dangerous command with missing process birth still
wakes investigation, reports incomplete identity coverage, and cannot authorize
an unsafe process response. Complete exact procdump and trusted destructive
recovery-command fixtures retain the previous typed process/host response
contracts and their action sets.

The historical classifier requires the exact normalized module name, exact old
policy, complete typed PID/birth, no response contract and no affirmative
response authorization. The complete identity requirement distinguishes a
semantic-parser rejection from an exact command that the old producer could
not bind safely to a process generation. Ambiguous historical identity remains
active. Independent exploitation, threat-intel/entropy corroboration, other
detector policies and other modules are not demoted. Stored event bytes and
severity are not rewritten.

## Validation

- `py_compile` passed all three changed product files and the new test file.
- Both LSASS and Shadow-Copy module `self_test()` methods passed their synthetic
  signature checks. `core/threat.py` has no `self_test()` method.
- **102 tests passed, 0 failed, 0 skipped in 7.15 seconds** across
  `test_deep_review_round2_semantic_chill`, `test_semantic_response_contracts`,
  `test_threat_observations`, `test_threat_coverage` and `test_chill_mode`.
- The new 21-case regression selection exercises real detector loops with
  inert process metadata, threat classification, Chill transitions and typed
  response parsing. The native recovery-tool signature/path boundary is mocked;
  no native destructive command or response action is run.
- An initial assertion expected an empty action set instead of the consumer's
  actual `None` denial result. Only that fixture expectation was corrected;
  no product response gate was weakened.
- The product diff passed `git diff --check`; targeted Ruff checks passed for
  all three product files and the new regression file.

Interpreter: existing `AngeronaSuite/venv/Scripts/python.exe`; `PYTHONPATH`
points to this worktree's `src`; final fixtures use
`.tmp/patches-round2-pytest`. No live sensor, inference, VM, host containment,
commit or publication was performed by the patch applier. The parent owns
consolidated findings/log status, integrated validation and publication.
