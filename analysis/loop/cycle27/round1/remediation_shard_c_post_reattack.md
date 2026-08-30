# Cycle 27 Round 1 — Shard C post-reattack remediation

Date: 2026-08-28
Scope: frozen reattack gates for `C27-R1-C09`, `C27-R1-C10`,
`C27-R1-C17`, and `C27-R1-C19`, plus the reported C09 Boolean/integer
compatibility failure.
Boundary: inert temporary files and fake event-log backends only. No live attack,
host mutation, hostile-test edit, commit, or publication.

## Closed frozen gates

| Finding | Post-reattack closure |
|---|---|
| `C27-R1-C09` | Retry waits are converted into process-monotonic deadlines and restored delays are capped to the exact authenticated attempt schedule, so wall-clock rollback cannot expand a 5-second retry toward the 300-second absolute ceiling. Authenticated state requires exact integer retry counters and schema values; Boolean-as-integer input is rejected both before persistence and during load. Source selection retains thread-local path/object identity, revalidates the trusted root, requires a single-link regular object, compares pathname metadata to the opened descriptor before/after the bounded read, and rejects a hardlink/symlink/object substitution before model ingestion. Deep JSON recursion is normalized to fail-closed health. |
| `C27-R1-C10` | The mandatory dependency closure now includes `angerona.core.threat:is_active_threat`, producing 19 mandatory callable targets. Replacing that helper is detected directly. ACL health accepts only the enumerated `ok`, `not-applicable`, `weak`, and `collection-failed` states; every unknown collector state is degraded and named as unknown ACL evidence. |
| `C27-R1-C17` | Spill inspection captures the source-directory object identity, rechecks it immediately after the safety walk and again after bounded enumeration, and rejects junction, reparse, ordinary-directory, metadata, or availability changes as unsafe/unavailable. Enumeration is capped at 1,000 entries. Retired migration/purge paths remain inert, including hardlink fixtures. |
| `C27-R1-C19` | An authenticated cursor whose sequence regresses, or whose same-sequence content forks, is rejected against the accepted in-process high-water. Lower record numbers are allowed only when checkpointing a newly observed generation. Any generation change now replays from the oldest retained record even if the previous cursor record has identical content, preventing new lower-prefix loss. Record anchors incrementally hash every admitted character instead of truncating each field at 4 KiB; records beyond the 2 MiB anchor bound fail closed. Cursor schema and record-number APIs also require exact integers, and deep JSON recursion is rejected. |

## Added deterministic remediation tests

`tests/test_cycle27_shard_c_post_reattack_remediation.py` adds nine cases:

- authentic Boolean retry state rejected on mint and load;
- monotonic retry enforcement across a wall rollback and exact restart cap;
- post-selection hardlink swap rejected even after the outside alias is removed;
- direct single-link trusted-read compatibility retained;
- complete threat helper closure and unknown ACL state degradation;
- ordinary directory-object swap rejected after validation;
- authenticated cursor-sequence rollback rejected;
- new-generation lower-prefix replay plus lower-number checkpoint transition;
- full post-4-KiB anchor differentiation and oversized-anchor refusal.

The frozen hostile test file was not modified.

## Validation

- Frozen hostile reattack: **14 passed, 0 failed**.
- New post-reattack regression file: **9 passed, 0 failed**.
- Combined scoped/adjacent suite: **63 passed, 0 failed**.
- Four owned module self-tests: **4 passed, 0 failed**; every module remains
  version **1.12.1**.
- Headless selfcheck: **26 passed, 0 failed**; internal module runner:
  **66 passed, 0 failed, 16 optional skips**.
- Cycle27 broad snapshot: **379 passed, 5 failed, 2 skipped**. The five failures
  are unrelated frozen gates in Adversary Combat, AV Telemetry Bridge, and
  Driver Provenance Guard; none exercises an owned shard-C module.
- Repository `compileall`, targeted `py_compile`, Ruff, JSON validation, and
  scoped `git diff --check`: **passed**.

## Honest remaining platform limits

- A durable authenticated timestamp/sequence is not an independent clock or
  rollback authority. C09 bounds restart delay from the authenticated attempt;
  it cannot prove real elapsed time while the process was stopped.
- Source file IDs/link counts are filesystem-provided. The selected/opened race
  is closed, but a pre-selection single-link replacement already present inside
  the trusted root still requires an independently signed release manifest to
  distinguish from the installed source.
- C10 remains user-mode detection. Default live TOFU is deliberately non-green;
  full assurance still requires a separately authenticated release manifest and
  OS process protection outside this Python monitor.
- C17 performs no host mutation. Its repeated object checks detect the frozen
  swaps, but Python does not provide one portable, handle-relative directory
  enumeration contract across Windows and POSIX. A swap-and-restore wholly
  between checks may affect observation; because move/purge execution is retired,
  it cannot redirect a privileged filesystem action.
- C19 rejects rollback against memory retained by the running process. A complete
  cross-process rollback of an authentic local cursor remains indistinguishable
  without a separately administered monotonic high-water authority. The classic
  event-log API also exposes no stable log-generation UUID; an endpoint-preserving
  wholesale log replacement can require stronger Windows Event Log/EVTX identity
  evidence. Generation uncertainty is handled by replay, favoring duplicates over
  silent loss.
