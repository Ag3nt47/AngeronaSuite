# Cycle 27 Round 1 — Shard C HIGH remediation

Scope was limited to `C27-R1-C03`, `C27-R1-C04`, `C27-R1-C13`, and
`C27-R1-C18`. No host posture mutation, network activity, commit, publication,
or unrelated finding work was performed.

## C27-R1-C03 — FIXED

- File: `src/angerona/modules/ransomware_heuristics.py`
- Change: the bounded recursive traversal now enrolls each watched root by stable
  volume/file identity, rejects root and child reparses, enumerates through held
  directory objects, and reopen-compares every queued directory. Directory
  handles deny delete sharing so their namespace cannot be swapped while held.
- Second-remediation closure: candidate content is sampled while the exact
  enumerated regular-file handle remains held with write/delete sharing denied.
  The typed scoring receipt carries root identity, file identity, size, stable
  modification generation, and bounded sample entropy/SHA-256/length. At
  decision time both root and file are revalidated and held through entropy
  scoring/event publication.
  Mutable pathnames are never sent to the process pool or reopened for content.
- Evidence: root junctions, root replacement, nested reparse entries, file/read
  mismatch, post-enumeration root swap, and every budget/error condition add
  exact skipped/error/truncated counts, set `complete=false`, and hold health
  below 100. The inert post-scan NTFS-junction reproduction emitted no false
  event and produced an explicit root/file-identity error receipt.
- Gates: compile PASS; module `self_test()` PASS; Ruff PASS; recursive traversal,
  root-junction, root-replacement, identity-bound entropy, nested rename, and
  fail-visible budget tests PASS (the separate symlink test is an expected skip
  where Windows denies test symlink creation).

## C27-R1-C04 — FIXED

- File: `src/angerona/modules/remediation_actions.py`
- Change: the typed/HMAC target-and-approval contracts remain available for
  operator review, but automatic BYOVD service mutation is deliberately
  unavailable until one held SCM service handle and held image identity can span
  approval, mutation, postcondition, and rollback.
- Safety: `DisableDriverServiceAction` is absent from executable `ACTIONS` and is
  present only in `PROPOSAL_ONLY_ACTIONS`. It contains no `sc.exe`, registry, or
  SCM mutation sink. Direct, transactional, rollback, and both verification
  entry points always fail closed with `ok=false`, `changed=false`, and
  `mutation_started=false`; even a pre-populated successful transaction is
  overwritten to failure.
- Gates: compile PASS; Ruff PASS; plain-record denial, exact proposal
  classification, post-claim identity swap, stale/tampered approval, and
  no-mutation/no-success regressions PASS. No module `self_test()` exists.

## C27-R1-C13 — FIXED

- File: `src/angerona/modules/smart_deception.py`
- Change: decoy creation, monitor reads, retirement, failure cleanup, and restart
  cleanup are no-follow and exact-object bound. Mutable pathname rename/unlink is
  not used for decoy custody. Source handles deny write/delete sharing through
  the complete retirement transaction.
- Second-remediation closure: retained evidence is never the attacked source
  inode. Angerona creates a new exclusive evidence inode inside the enrolled,
  held quarantine root, copies from the frozen source handle within the item
  bound, fsyncs, computes SHA-256, rereads and compares the digest, requires one
  link, and then renames that evidence handle relative to the held root. The
  digest is embedded in its durable bounded receipt name. Only after this proof
  does Angerona handle-delete the original decoy link and restage.
- Alias/custody safety: a pre-existing hard-link alias remains a non-evidence
  object and cannot change the sealed copy. Its residue is counted and keeps
  custody health below 100. Every periodic inventory reopens evidence by exact
  identity, requires one link and bounded size, recomputes its filename-bound
  digest, and sets quarantine saturation/health below 100 on any drift.
- Bounded state: quarantine item/count/byte/age/scan limits remain enforced.
  Trip dedup is pruned inside every `_trip()` independently of the run loop,
  hard-capped at 256 entries, and exposes eviction/cap-saturation counters;
  abnormal cap eviction lowers health.
- Gates: compile PASS; module `self_test()` PASS; Ruff PASS; hard-link alias,
  post-archive mutation, digest drift, 5,000-epoch dedup, cap saturation,
  exact-handle cleanup, retention, and restage tests PASS.

## C27-R1-C18 — FIXED

- File: `src/angerona/modules/sys_bridge.py`
- Change: removed the ambient top-level `import syscall_bridge` execution path.
  Native loading remains unavailable until a fixed private namespace,
  publisher/digest-sealed release manifest, no-reparse object binding, and
  authenticated broker ABI exist. The safe ctypes/psutil fallback is the only
  admitted default.
- Safety: the Windows fallback loads `kernel32.dll` with
  `LOAD_LIBRARY_SEARCH_SYSTEM32`, declares HANDLE-safe `OpenProcess`,
  `TerminateProcess`, and `CloseHandle` prototypes, validates PID/exit-code
  ranges, and closes the exact opened handle. Initialization and runtime health
  report 55% with the explicit missing-native-integrity reason; no hook-bypass
  claim is made.
- Gates: compile PASS; module `self_test()` PASS; Ruff PASS; poisoned ambient
  import, unavailable-native health, invalid PID, and ctypes prototype tests
  PASS.

## Consolidated gates

- `py_compile` for the owned modules and regression file: PASS.
- Ruff across the owned modules and regression file: PASS.
- Exact second-remediation regression file: **24 passed, 1 expected
  symlink-availability skip**.
- Expanded owned + neighboring response/deception/ransomware suite: **57 passed, 1
  expected symlink-availability skip**.
- Module self-tests: PASS (`RANS`, `SDEC`; the remediation helper has none).
- Closure JSON parse and assigned finding states: PASS.
