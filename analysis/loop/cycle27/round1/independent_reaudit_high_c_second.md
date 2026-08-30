# Cycle 27 Round 1 — Second Independent High-C Re-audit

Date: 2026-08-28
Scope: second remediation of C27-R1-C03, C27-R1-C04, and C27-R1-C13 only
Method: manual source review plus inert temporary-directory, NTFS-junction, hard-link, bounded-state, and mocked-mutation tests. No service, driver, registry object, security control, or non-temporary host object was changed. This audit did not edit product code or tests.

## Verdict summary

| Finding | Verdict | Residual severity | Independent result |
|---|---|---:|---|
| C27-R1-C03 | **REOPENED** | MEDIUM | Root and directory enumeration is now held-object and identity-pinned, but the resulting file identities are discarded. Entropy scoring later reopens mutable pathnames, so a post-enumeration root swap can still evade the detector while coverage and health remain 100. |
| C27-R1-C04 | **CLOSED** | — | The BYOVD action is absent from the executable catalog, has no service-mutation sink, and every direct, transactional, verification, and rollback entry point fails closed or returns proposal-only failure. |
| C27-R1-C13 | **REOPENED** | MEDIUM | Exact handle rename and quarantine count/byte/age caps work, but pre-existing hard-link aliases remain live after archival and can modify the retained evidence behind health 100. The epoch-keyed alert-dedup dictionary also has no eviction or cap and can grow indefinitely behind health 100. |

Totals: **1 CLOSED, 2 REOPENED** (0 critical, 0 high residual, 2 medium residual).

## C27-R1-C03 — Held enumeration releases authority before entropy scoring

**Verdict: REOPENED (MEDIUM residual).**

### Exact source evidence

- `src/angerona/modules/ransomware_heuristics.py:433-607` now rejects root reparse points, opens each directory without following the final component, obtains a stable volume/file identity, and enumerates a held directory handle.
- `src/angerona/modules/ransomware_heuristics.py:642-710` compares the enrolled root and queued child identities and reopens the directory after enumeration. Those controls close the previously demonstrated admitted-root and queued-directory replacement cases.
- The held enumeration supplies each file's `entry_identity` at `src/angerona/modules/ransomware_heuristics.py:653-662`, but `src/angerona/modules/ransomware_heuristics.py:695-703` drops that identity and retains only a pathname, relative name, size, and modification time.
- `src/angerona/modules/ransomware_heuristics.py:735-749` returns pathname-only entropy candidates. After every root handle has been closed, `src/angerona/modules/ransomware_heuristics.py:783-820` sends those names to the entropy evaluator and ultimately uses ordinary `open(path, "rb")`. There is no no-follow open, file-identity comparison, held ancestor, or post-read identity proof at this action boundary.

### Independent inert reproduction

A temporary watched root contained a recent 64 KiB random file. `_tick()` completed its held enumeration, after which the test renamed the root and installed an NTFS junction with the same name to a second temporary directory containing a low-entropy file at the same relative pathname. The real `_evaluate_entropy()` and `_file_entropy()` then ran unchanged:

```text
high_entropy_original=7.9974
redirect_entropy=0.0
alerts=0
coverage_complete=True
health=100
last_error=""
```

The original enumerated object met the high-entropy threshold, but the later pathname action followed the replacement root and scored a different object. Reversing the samples similarly permits an out-of-scope object to manufacture an alert. The junction and both trees were confined to one temporary directory and removed after the test.

### Controls that held

- A root that is already a junction/reparse point is rejected and lowers health.
- Root identities are enrolled once per module lifetime; a replacement present on the next traversal is rejected.
- Recursive directory discovery is handle-based, child identities are compared before descent, reparse entries are skipped, and all skip/error/budget conditions prevent a 100% coverage claim.
- The residual window is after enumeration and before file scoring. A subsequent scan detects the replaced root, but that does not repair the already corrupted detection decision.

### Required remediation

Carry each enumerated file's stable volume/file identity into the scoring contract and read the sample from that same object. On Windows, open the file relative to the still-held parent/root object without following a reparse component, compare the held file identity and type to the enumerated record, retain the handle through the bounded read, and count any mismatch or read failure as incomplete coverage. Do not batch mutable pathnames into the pool. If pool offload is retained, hand off a bounded sample or a safely duplicated exact handle plus identity receipt; otherwise score while the authoritative handle is held. Add a regression that swaps the watched root after `_scan_root()` but before `_evaluate_entropy()` and requires zero path traversal, an error receipt, and health below 100.

## C27-R1-C04 — Vulnerable-driver disablement is inert and proposal-only

**Verdict: CLOSED.**

### Exact source evidence

- `src/angerona/modules/remediation_actions.py:616-640` retains typed BYOVD approval matching only to produce an operator-visible proposal.
- `src/angerona/modules/remediation_actions.py:642-682` contains no command or SCM call: `begin_transaction()` raises, `apply()` and `apply_transactional()` return `ok=False`, `changed=False`, `mutation_started=False`, rollback returns `ok=False`, and both verification methods return `False`.
- `src/angerona/modules/remediation_actions.py:1525-1550` excludes `DisableDriverServiceAction` from `ACTIONS` and places it only in `PROPOSAL_ONLY_ACTIONS`.
- `src/angerona/modules/remediation_actions.py:1642-1681` dispatches only a unique member of `ACTIONS`; the BYOVD instance can therefore only become `RemediationDecision.proposal`.
- A repository-wide source search found no `sc.exe`, `ChangeServiceConfigW`, service-registry mutation, or equivalent sink in this action. The only other `sc.exe` text is an inert Shark simulation description.

### Independent result

The targeted regression exercised plain data, an exact valid approval, a post-claim target swap, direct apply, transaction apply, rollback, and verification with `run_hidden` replaced by a function that raises if reached. All returned or raised fail-closed results and the mutation spy remained empty. The action was not present in `ACTIONS`, while classification returned it only as a proposal.

### Controls that held

- Legacy free-text driver/path records do not match the BYOVD action.
- The typed authority remains useful for planning and authenticated target review but grants no mutation capability.
- Both ordinary application and durable recovery are bound to the executable `ACTIONS` registry, which does not contain this class.

### Retention recommendation

Keep this action outside `ACTIONS` until one held SCM service handle and one held image-object identity span observation, approval, mutation, postcondition, and rollback. As declarative defense in depth, set class-level `proposal_only=True` and `executable=False` and include `executable=False` in every direct result, matching the other proposal-only actions; this consistency improvement is not required to close the removed execution route.

## C27-R1-C13 — Hard-link aliases defeat evidence custody; dedup state is unbounded

**Verdict: REOPENED (MEDIUM residual).**

### Exact source evidence

- `src/angerona/modules/smart_deception.py:505-580` now opens the exact expected decoy with delete rights and retains the descriptor through later mutation. However, it neither requires a single-link object nor records/rejects `st_nlink > 1`; its Windows share mode includes delete sharing.
- `src/angerona/modules/smart_deception.py:791-824` correctly renames the held object into the held quarantine directory, so a pathname replacement is no longer moved. A pre-existing hard-link alias is another name for that same object and survives this rename.
- `src/angerona/modules/smart_deception.py:681-721` inventories only name, identity, size, and timestamp. It does not reject multiple links, retain a content digest/custody receipt, or detect that an alias outside the evidence directory can still modify the same object.
- `src/angerona/modules/smart_deception.py:246` initializes `_trip_alerts`; `src/angerona/modules/smart_deception.py:1004-1033` adds one distinct key for every logical slot and five-minute epoch but never evicts an expired epoch or enforces a maximum. `src/angerona/modules/smart_deception.py:1035-1055` does not include dedup size/saturation in health.

### Independent inert reproductions

1. **Hard-link evidence mutation:** a hard-link alias was created to a temporary deployed decoy, the decoy was modified through the alias, and the normal trip/recovery flow archived the exact object and restaged a fresh active decoy. The alias survived and remained the same file as the `.evidence` object. Appending through the alias changed the retained evidence while the module reported green:

```text
evidence_mutated=True
samefile=True
active_recreated=True
health=100
health_note=""
quarantine_saturated=False
quarantine_dropped=0
```

2. **Unbounded dedup state:** with recovery and emission replaced by inert functions, one logical slot was advanced through 5,000 legitimate five-minute epochs. The dictionary retained every expired key:

```text
epochs=5000
dedup_entries=5000
trips=5000
health=100
health_note=""
```

Both tests operated only on temporary files or in-memory state. No user file was read or changed.

### Controls that held

- Substitution by a different file identity is rejected; the verified descriptor stays open through the native handle-relative rename.
- A pathname swap after custody acquisition leaves the replacement untouched while the held original is archived.
- The quarantine inventory now enforces explicit item, total-byte, file-count, age, and scan bounds. Unknown objects and failed pruning set saturation and lower health.
- Logical-slot plus epoch alerting suppresses immediate restage spam within an epoch.

### Required remediation

Before claiming evidence custody, require a single-link file from the held handle and prevent new aliases during the custody transition (for example, acquire the file without delete sharing if the same-handle rename remains valid). If a multiple-link object is observed, keep the incident unresolved and do not label the archive protected; alternatively enumerate and secure every link using reviewed Windows file-ID/hard-link APIs. After archival, persist and periodically revalidate an authenticated receipt containing object identity, link count, size, and digest under a protected quarantine-root identity, and degrade health on custody drift.

Bound `_trip_alerts` independently of attacker duration: evict epochs older than the active dedup window, cap entries relative to the bounded number of logical slots, and expose eviction/saturation counts in health. Add regressions for a pre-existing hard-link alias, post-archive alias mutation, long-running epoch advancement, and health below 100 whenever custody or bounded-state proof is lost.

## Validation record

```text
python -m pytest -q tests/test_cycle27_round1_high_c.py
21 passed, 1 skipped in 2.65s

python -m py_compile \
  src/angerona/modules/ransomware_heuristics.py \
  src/angerona/modules/remediation_actions.py \
  src/angerona/modules/smart_deception.py
PASS

python -m ruff check \
  src/angerona/modules/ransomware_heuristics.py \
  src/angerona/modules/remediation_actions.py \
  src/angerona/modules/smart_deception.py \
  tests/test_cycle27_round1_high_c.py
PASS
```

The one skip is the author regression that needs directory-symlink privilege. The unprivileged NTFS-junction author regression passed, as did both independent NTFS-junction reproductions. No operational intrusion was attempted.
