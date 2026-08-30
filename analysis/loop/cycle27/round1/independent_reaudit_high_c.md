# Cycle 27 Round 1 — Independent High-C Re-audit

Date: 2026-08-28
Scope: C27-R1-C03, C27-R1-C04, C27-R1-C13, and C27-R1-C18 only
Method: manual source review plus inert temporary-directory, NTFS-junction, import-poison, and mocked mutation-boundary reproductions. No operational intrusion was attempted and no product code was changed by this re-audit.

## Verdict summary

| Finding | Verdict | Residual severity | Independent result |
|---|---|---:|---|
| C27-R1-C03 | **REOPENED** | MEDIUM | Ordinary nested recursion and truthful child-skip accounting work, but a watched root that is itself a junction is followed without validation and can still produce `complete=True`, health 100. |
| C27-R1-C04 | **REOPENED** | HIGH | The typed/HMAC policy is meaningful, and the default registry action is unavailable without an authority, but exact identity is released before the pathname-based `sc.exe config` mutation. A post-claim object swap still reaches the mutation sink. |
| C27-R1-C13 | **REOPENED** | MEDIUM | Anchor reads are bounded and exclusive creation works, but the verified decoy handle is closed before pathname rename. A replacement can be moved in the gap. Successful restaging also retains an unbounded quarantine object and creates a new alert identity per cycle. |
| C27-R1-C18 | **CLOSED** | — | No ambient `syscall_bridge` import occurs; the native bridge is unavailable by construction, the System32 DLL search and ctypes prototypes are explicit, and degraded health is truthful. |

Totals: **1 CLOSED, 3 REOPENED** (0 critical, 1 high, 2 medium).

## C27-R1-C03 — Watched-root reparse identity is not checked

**Verdict: REOPENED (MEDIUM residual).**

### Exact source evidence

- `src/angerona/modules/ransomware_heuristics.py:124-134` admits candidate watch roots using `Path.is_dir()`, which follows a directory junction/reparse target.
- `src/angerona/modules/ransomware_heuristics.py:333-349` converts that pathname to an absolute string and immediately calls `os.scandir(current)`. It does not `lstat` or object-bind the root before following it.
- `src/angerona/modules/ransomware_heuristics.py:357-380` correctly refuses *child* symlinks/reparse points, so the gap is specifically the root and the later check/use interval for queued directories.
- `src/angerona/modules/ransomware_heuristics.py:401-407` can therefore label the redirected enumeration complete, while `src/angerona/modules/ransomware_heuristics.py:433-452` converts that receipt to health 100.

### Independent inert reproduction

An NTFS junction named `Documents` was created inside a temporary directory and pointed at a separate temporary directory containing one recent file. Calling `_collect_entropy_candidates(junction, now)` returned the redirected file and produced:

```text
candidate_count=1
coverage={roots:1, directories:1, visited:1, skipped:0,
          truncated:0, errors:0, complete:True}
health=100
```

This is a silent scope-identity failure. It also demonstrates why the author test for a *nested* link is not enough: that test exercises an entry after `scandir`, while the root reaches `scandir` before any reparse check. The repository's symlink author test was skipped on this host because symlink privilege was unavailable; the unprivileged NTFS-junction reproduction exercised the Windows boundary directly.

### Controls that held

- Nested directory entries are statted without following links and reparse children are skipped.
- File, directory, depth, and wall-clock budgets are independent.
- Skips, errors, and budget truncation lower health below 100.
- Recursive snapshots now cover ordinary nested directories and preserve same-directory rename attribution.

### Required remediation

Enroll each intended watch root with a stable volume/file identity and an explicit policy for legitimate Known Folder redirection. Before claiming coverage, open the root without following an unapproved reparse point (on Windows, use a fixed-root handle with `FILE_FLAG_OPEN_REPARSE_POINT`/`FILE_FLAG_BACKUP_SEMANTICS` as appropriate), compare the enrolled identity/generation, and enumerate from the held object. Apply the same reopen-and-compare rule immediately before descending a queued child. If handle-relative traversal is unavailable, refuse the redirected root and report its exact path/reparse reason below 100 rather than following it silently.

## C27-R1-C04 — Exact BYOVD identity ends before the service mutation

**Verdict: REOPENED (HIGH).**

### Exact source evidence

- `src/angerona/modules/remediation_actions.py:424-587` builds a strict typed target, exact hash/signer/service policy, fresh observation, HMAC approval, and live verification.
- `src/angerona/modules/remediation_actions.py:590-598` atomically claims an approval, but the claim only proves the last observer snapshot; it does not retain an SCM service handle or registry/image object handle.
- `src/angerona/modules/remediation_actions.py:694-720` completes `claim()` and then invokes `sc.exe config <service-name> ...` through a string name. A service can be deleted/recreated or repointed after claim and before this lookup.
- `src/angerona/modules/remediation_actions.py:725-732` marks the transaction `ok=True` from the command return code alone.
- `src/angerona/modules/remediation_actions.py:789-798` can detect the identity mismatch afterward, but that postcondition is too late to stop the mutation and cannot safely compensate a different live object.
- `src/angerona/modules/remediation_actions.py:1642-1647` registers `DisableDriverServiceAction()` with no authority, so the current default deployment is fail-closed. The bypass applies if the new authority-backed capability is configured or injected.

### Independent inert reproduction

A valid target, pinned policy, fresh approval, and HMAC authority were built with an in-memory observer. The live target was changed at the `_sc_path()` boundary—after `claim()` succeeded but before mocked `run_hidden()` received its argv. The result was:

```text
mutation_calls=[[System32\\sc.exe, config, VulnerableDriver, start=, disabled]]
record_ok=True
live_still_exact=False
post_verify=False
```

No service was touched; `run_hidden` was fully mocked. This proves that the postcondition notices the wrong-object race but does not prevent it.

### Controls that held

- Plain `driver`/`path` fields no longer authorize this action.
- Exact dataclass types, closed schemas, bounded fields, service type, hash, signer, allow-listed service, freshness, target digest, HMAC, expiry, and single-use in-memory claim checks all fail closed.
- A critical-service deny set and exact rollback start mode are present.
- With the production registry's authority left `None`, the action cannot match or mutate.

### Required remediation

Keep the action unavailable until query, approval verification, and mutation can share one object-bound transaction. Use the Windows SCM API directly: open the service once, query and authenticate type/config/security/object evidence from that held service handle, bind the image evidence to a held no-follow file identity, claim the approval, and call `ChangeServiceConfigW` through the same still-open service handle. Re-query the same handle for the postcondition. If an exact held-object mutation cannot be implemented, retain proposal-only behavior; a second pathname observation immediately before `sc.exe` only narrows, but does not close, the race.

## C27-R1-C13 — Decoy retirement releases identity before rename and has no retention bound

**Verdict: REOPENED (MEDIUM residual).**

### Exact source evidence

- `src/angerona/modules/smart_deception.py:375-401` safely opens an existing decoy without following the final component and returns a handle-derived identity.
- `src/angerona/modules/smart_deception.py:477-500` reads only `_MAX_ANCHOR_READ` bytes and validates size plus exact anchor content. The original memory-exhaustion primitive is closed.
- `src/angerona/modules/smart_deception.py:507-524` verifies the original identity, but line 520 closes the descriptor before the pathname operation.
- `src/angerona/modules/smart_deception.py:525-539` then renames by mutable path. The post-rename identity comparison detects a swap only after the replacement has already been moved.
- The same section leaves every successfully retired object at `.angerona-tripped-<random>` with no count, byte, age, or durable-ledger retention bound.
- `src/angerona/modules/smart_deception.py:546-571` includes the current object identity in the incident key and restages a new identity. Repeated overwrites therefore evade the prior incident's five-minute dedup and retain another quarantine object each cycle.
- `src/angerona/modules/smart_deception.py:576-591` truthfully degrades unresolved traps, but a successful restage clears the unresolved state even while retained objects accumulate.

### Independent inert reproductions

1. **Close/rename replacement race:** the pathname was swapped inside a mocked `os.rename` after `_retire_tampered_decoy` closed its verified descriptor. The method returned `False`, but the replacement was already absent from the target path and present in the generated quarantine path:

```text
retired=False, target_exists=False, quarantine_count=1,
replacement_moved=True
```

2. **Restage retention/alert churn:** two bounded overwrites of the same logical decoy followed by `_trip()` produced two critical event emissions, two distinct retained quarantine files totaling 131,072 bytes, and another active decoy. Repetition is bounded only by the 2.5-second monitor cadence and external storage:

```text
events=2, trips=2, quarantine_count=2,
quarantine_bytes=131072, active_recreated=True
```

All files were confined to temporary directories and removed after the reproduction.

### Controls that held

- Creation is exclusive and does not overwrite a pre-existing final component.
- Anchor reads are exactly bounded.
- Final-component symlink/reparse checks and pre/open/post identity comparisons are present.
- A replacement present before retirement is refused.
- Identical unresolved incidents are rate-limited and unresolved traps lower health.

### Required remediation

Keep the verified descriptor open and rename the same object by handle (for Windows, an appropriate `SetFileInformationByHandle` rename contract) into a protected, bounded evidence store. Do not perform pathname unlink/rename after an identity check. Add explicit per-module and global retained-object count/byte/age limits, durable custody receipts, and a fail-visible saturation state. Rate-limit by logical decoy slot plus attack epoch—not newly restaged file identity—or aggregate repeated tamper alerts while continuing recovery attempts. Apply the same held-object rule to cleanup at `smart_deception.py:310-329`.

## C27-R1-C18 — Ambient native import and unsafe ctypes handle width

**Verdict: CLOSED.**

### Exact source evidence

- `src/angerona/modules/sys_bridge.py:35-44` fixes `_SC_BRIDGE=None` and `_BRIDGE_AVAILABLE=False`; no import loader, `__import__`, `importlib`, or top-level `syscall_bridge` import remains.
- `src/angerona/modules/sys_bridge.py:49-70` loads `kernel32.dll` with `LOAD_LIBRARY_SEARCH_SYSTEM32` and declares `OpenProcess`, `TerminateProcess`, and `CloseHandle` signatures with pointer-width-safe `c_void_p` handles.
- `src/angerona/modules/sys_bridge.py:73-88` rejects non-exact/out-of-range integer PID and exit-code inputs and closes every opened handle in `finally`.
- `src/angerona/modules/sys_bridge.py:138-146` and `225-234` expose native coverage as unavailable and health 55, rather than claiming indirect-syscall protection.

### Independent inert reproduction

A temporary `syscall_bridge.py` that raises immediately on import was placed first on `sys.path`, `syscall_bridge` was removed from `sys.modules`, and `angerona.modules.sys_bridge` was reloaded. The poison module did not execute or enter `sys.modules`; the bridge remained unavailable with health 55 and an explicit sealed-broker explanation.

The fallback prototype test also confirmed the call order `OpenProcess` → `TerminateProcess` → `CloseHandle`, with all HANDLE parameters/results declared as `ctypes.c_void_p`. No real process operation was performed.

### Remaining limitation, not a reopening

Suspend/resume use the ordinary pinned `psutil` dependency rather than a native sealed broker, so hook-bypass coverage is unavailable. That limitation is explicitly disclosed and health-capped; it is not the ambient optional-extension execution flaw reported in C27-R1-C18.

## Validation record

```text
python -m pytest -q tests/test_cycle27_round1_high_c.py
12 passed, 1 skipped in 8.17s

python -m py_compile \
  src/angerona/modules/ransomware_heuristics.py \
  src/angerona/modules/remediation_actions.py \
  src/angerona/modules/smart_deception.py \
  src/angerona/modules/sys_bridge.py
PASS
```

The skipped author test required Windows symlink privilege (`WinError 1314`). The independent NTFS-junction test did not require that privilege and exposed the watched-root gap. The three adversarial reproductions used only temporary filesystem objects or mocked command execution. No real process, service, driver, registry object, or host security control was mutated.
