# Cycle 27 Round 1 — Shard C final convergence

Date: 2026-08-28
Scope: frozen final-verification gates for `C27-R1-C09`, `C27-R1-C10`,
and `C27-R1-C19`. `C27-R1-C17` was already closed and its implementation was
not changed.
Boundary: inert temporary files, in-process policy monkeypatches that are always
restored, and fake event-log backends only. No host mutation, live attack,
hostile-test edit, commit, or publication.

## Closed final-verification gates

| Finding | Final convergence closure |
|---|---|
| `C27-R1-C09` | The authenticated healer state is now paired with a separately replaced, purpose-separated HMAC receipt containing a monotonically increasing generation and the exact SHA-256 digest of the current state bytes. A fresh process rejects a missing, forged, mismatched, or older-main/newer-receipt pair before loading completion, retry, schedule, or dead-letter data. Replaying only an older authentic empty main state can no longer erase a pending retry or its process-monotonic deadline. A crash between the two portable file replaces fails closed on restart. The legacy Boolean return contract of `_snapshot_candidates` was restored while the processing path retains explicit complete/overflow/unreadable health evidence. |
| `C27-R1-C10` | The compiled prompt-injection policy is captured as an immutable tuple in the `scan_input` closure. Replacing the module-level `_INJECTION_RE` compatibility name therefore cannot disable enforcement. Mutating the closure/default/code changes the already watched callable fingerprint and produces a self-integrity finding. State-directory ACL evidence is normalized, recollected every monitor cycle, and re-scored immediately; a later weak, failed, or unknown collector posture cannot inherit an earlier health-100 result. Distinct ACL failures are emitted once to avoid alert storms. |
| `C27-R1-C19` | Resume delivery now admits and checkpoints only the exact contiguous prefix from the requested record through the captured retained high-water. A missing, duplicate, reordered, invalid, or prematurely terminated row changes continuity to `delivery-gap`, records the expected/observed evidence, holds the cursor at the last proven contiguous record, and degrades health to 30. Rows beyond the captured high-water are deferred to the next generation pass. Persistence failure still stops advancement and remains non-green. |

## Added deterministic convergence tests

`tests/test_cycle27_shard_c_final_convergence.py` adds six collected cases:

- newer signed HEAL receipt rejects replay of the older authentic main state;
- missing or modified HEAL receipt fails closed;
- module-global guardrail policy replacement is inert, while closure mutation is
  detected by the armed integrity engine;
- a later unknown ACL posture is recollected and made non-green;
- a mid-batch Sysmon gap checkpoints only the contiguous prefix;
- an end-of-delivery Sysmon gap cannot advance through the missing retained row.

The frozen independent verifier was not modified.

## Validation

- Frozen final independent verifier: **4 passed, 0 failed**.
- New final-convergence regression file: **6 passed, 0 failed**.
- Preserved earlier shard-C gates: **34 passed, 0 failed**.
- Broader affected suite (guardrail, HEAL, SINT, Sysmon and adjacent producers):
  **95 passed, 0 failed**.
- Four shard-C module self-tests: **4 passed, 0 failed**; `HEAL`, `SINT`,
  `SHYG`, and `SYSL` remain version **1.12.1**.
- Headless selfcheck: **26 passed, 0 failed**; internal module runner:
  **66 passed, 0 failed, 16 optional skips**.
- Wider Cycle27 snapshot: **361 passed, 52 failed, 2 skipped**. Every failure
  is outside this ownership boundary and originates in the concurrent Purple
  Guard validation-lease/native-authority cluster (`native_modules` or
  `native_capabilities` access); no failure references HEAL, the AI guardrail,
  SINT, Sysmon, C17, or the convergence tests.
- Repository `compileall`, targeted `py_compile`, targeted Ruff, JSON validation,
  and scoped `git diff --check`: **passed**.

## Honest remaining platform limits

- C09's companion receipt is independent of the main state file, but both are
  still local files protected by the same installation authority. A coherent
  rollback of both authentic files, theft of the local HMAC authority, or a
  whole-volume rollback cannot be distinguished without an external monotonic
  witness such as TPM-backed storage or a separately administered high-water
  service. The portable two-file replace deliberately favors fail-closed
  availability over silently accepting an incomplete transaction.
- C09's process-monotonic deadline prevents wall-clock changes while running;
  no local file proves real elapsed time while the process is stopped.
- C10 remains user-mode detection. Same-privilege code can attempt to suspend
  the interpreter, mutate closure cells, or interfere between 15-second checks;
  callable mutation is detected after enrollment, but prevention requires OS
  process protection and an independently approved release manifest. ACL
  collection is also a point-in-time `icacls` observation, not a kernel lease.
- C19's classic Windows Event Log interface exposes oldest record plus count,
  not an atomic retained-range snapshot or stable generation UUID. Concurrent
  channel change can therefore produce conservative replay, duplicates, or a
  fail-closed delivery-gap health state. It can no longer silently skip a row
  that the sampled range says exists, but stronger generation identity requires
  modern subscription/bookmark or EVTX evidence outside this module.
- A coherent cross-process rollback of both an authentic Sysmon cursor and all
  local supporting evidence remains indistinguishable without a separately
  protected monotonic high-water authority.
