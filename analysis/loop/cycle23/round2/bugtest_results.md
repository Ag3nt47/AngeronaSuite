# Cycle 23 Round 2 — Bug Test Results

Date: 2026-08-26  
Environment: Windows, repository virtual environment, `PYTHONPATH=src`,
offscreen Qt; the complete pytest run used `CI=true` and one serial process.

## Outcome

No crash, syntax error, package import regression, duplicate module identity,
module discovery failure, self-test failure, selfcheck failure, Ruff error, or
pytest failure remained on the final tree. One clearly safe compatibility bug
introduced with the SSH guard was fixed: the module omitted the optional
zero-argument `register()` export used by legacy loaders. The manager's native
subclass discovery was never broken.

R2-01 is deliberately **not** reported as fixed. The new client/store protocol
rejects rollback when a conforming independent authority is injected, but this
repository still contains no separately administered monotonic service or
policy-bound TPM implementation. Without that injection, matching older local
state pairs remain locally authentic but explicitly lack independent
freshness.

| Gate | Result |
|---|---:|
| Whole-package `python -m py_compile` | **321 passed, 0 failed** |
| `angerona.modules.*` recursive imports | **73 passed, 0 failed** |
| Discovered `BaseModule` classes / manager instances | **71 / 71, 0 discovery errors** |
| Callable zero-argument compatibility `register()` hooks | **58/58 valid** |
| Duplicate module names / duplicate non-empty module codes | **0 / 0** |
| Standalone core + Shark `self_test()` functions | **22 passed, 0 failed** |
| Direct `tools/selfcheck.py` | **26 passed, 0 failed** |
| Batch `run-selfcheck.bat` | **26 passed, 0 failed; exit 0** |
| Selfcheck module harness | **50 module passes, 0 failures, 21 skips** |
| Selfcheck EventBus pipeline | **1 passed** |
| Focused Round 2 regression set | **135 passed, 2 skipped, 0 failed** |
| Corrected external-first second-write crash probes | **2 passed, 0 failed** |
| Ruff (`src`, `tests`, and `tools`) | **PASS** |
| Complete serial pytest | **1,455 passed, 5 skipped, 0 failed** |
| Complete collection | **1,460 tests across 208 files** |

No stale/truncated sandbox-mount read or false syntax error occurred.

## Compile, import, discovery, and registration

- Invoked `python -m py_compile` over every Python file under
  `src/angerona`: 321/321 compiled.
- Imported every file returned by `pkgutil.iter_modules(angerona.modules)`:
  73/73 imported.
- Compared the 71 in-module `BaseModule` subclasses with a real
  `ModuleManager.discover()` run rooted in isolated selfcheck data. The manager
  created all 71 modules with no discovery errors.
- Called every zero-argument compatibility hook. All 58 returned a
  `BaseModule`; the new Audit Log, Network Trust, and SSH Surface modules all
  now expose the hook.
- Fifteen older module files have no zero-argument compatibility hook. Two are
  helper-only (`packet_sniffer_worker`, `remediation_actions`) and thirteen are
  legacy subclasses already covered by native discovery. No new missing hook
  remains after the SSH fix.
- Non-empty module codes and module names are unique. Older classes without a
  code were not falsely treated as duplicate-code failures.

## Self-tests and project harnesses

- AST discovery found 21 top-level core self-tests and one Shark Red Team
  self-test. All 22 passed when imported and invoked directly.
- Direct and batch selfcheck runs each discovered 71 modules and finished
  26/26 phases. The internal summary was 51 passes, 0 failures, and 21 skips;
  one pass is the synthetic EventBus pipeline, leaving 50 actual module
  self-test passes.
- The 21 module skips are explicit environment/policy states: 13
  inactive/optional prerequisites, 5 operator-disabled modules, and 3
  platform-unavailable modules on this Windows host.

## Independent high-water adversarial checks

The injected in-memory authority in `tests/test_independent_high_water.py` is a
contract fixture, not a bundled anti-rollback service. QA exercised both the
audit and network domains and kept those claims separate.

| State transition | Result |
|---|---|
| Older locally authenticated pair behind the independent head | Both audit and network loads reject it as `local-behind`. |
| Same-revision fork | Digest conflict is rejected as `fork-detected`. |
| Installation clone | Authority/local installation mismatch is rejected. |
| Mixed cursor/epoch members | Local authentication fails closed before independent freshness can be claimed. |
| Authority unavailable after enrollment | Audit becomes provisional; network retains useful local-authenticity state while freshness is `provisional-offline`; both block advancement. |
| Legacy state with an empty authority namespace | Freshness is `migration-required`, independently fresh is false, and advancement is blocked. |
| Authority commits before the first local write fails | Existing regression returns `external-ahead-crash-recovery-required`; restart rejects the local state as behind. |
| Authority commits and the second local member write fails | Corrected probes for both stores return `external-ahead-crash-recovery-required`; restart rejects the mixed pair as untrusted. |
| No authority is configured | Local HMAC authenticity remains available, but freshness is explicitly `local-authenticity-only` and false. A controlled paired replay remains accepted locally, preserving the honest R2-01 residual. |

The offline/migration dual status is intentional: a locally authenticated
network baseline remains useful for drift detection instead of causing sensor
blindness, while its separate independent-freshness field, emitted health, and
non-advancing store state remain fail visible. It does not become
independently current while the authority is absent.

## Round 2 remediation regressions

- **R2-02:** per-user SSH key and principals sources resolve plain relative
  paths from each bounded home; `%h`, `%u`, `%U`, and `%%` expansion passes;
  unresolved UID/account/Match inputs remain incomplete rather than false
  missing paths. Windows ACL tests cover the admitted file and parent-chain
  delete-child/replacement rights with user-aware custody.
- **R2-03:** omitted interfaces, rejected addresses, per-family route overflow,
  and per-link route caps clear completeness. Positive gateway labeling is
  rejected for incomplete pre- and post-attestation snapshots.
- **R2-04:** transient OpenSSH WEVT opens retry after capped backoff; repeated
  query failures close stale sources; successful reopen is labeled as a
  history-bounded recovery and does not claim missed evidence was recovered.
- **R2-05:** the consuming SSH option grammar detects direct and supported
  split/attached `-o` forwarding forms, treats `-F` as uninspected coverage,
  and does not substring-match benign options into forwarding alerts.
- **R2-06:** audit records require the fixed provider/channel/event identity;
  attacker-shaped XML names never become EventBus keys; rejected parseable
  records advance the cursor and emit one bounded normalized reason without a
  replay loop.

## Round 1 performance fast-path regression check

The complete and focused suites retain the security boundaries behind all
three Round 1 optimizations:

- quiescent audit polling verifies unchanged cursor/enrollment bytes without
  rotating them, and tampering still fails closed;
- the SSH process iterator does not request command lines globally, server
  command lines remain unread, and one admitted SSH client is queried once;
- already-untrusted network snapshots avoid immutable rebuilding, while any
  collector-forged positive attestation is still stripped and full pre/post
  route completeness checks still run.

No cadence, anchor, route, source-completeness, or privacy gate regressed.

## Pytest skip classification

The five complete-suite skips are unchanged host-capability gates:

1. `test_cycle6_round2_remediation.py`: symlink creation unavailable.
2. `test_event_log_integrity_guard.py`: directory links unavailable.
3. `test_ir_bundle_privacy.py`: symlinks unavailable for this account.
4. `test_security_scan_center.py`: symlinks unavailable for this account.
5. `test_ssh_surface_guard.py`: POSIX permission bits unavailable on Windows.

The focused Round 2 run contains items 2 and 5 only. Equivalent negative
link/reparse and ACL-custody paths remain covered with platform-appropriate
fixtures.

## Bugs

### QA-R2-01 — SSH compatibility registration hook omitted — FIXED

- **Component:** `src/angerona/modules/ssh_surface_guard.py`
- **Symptom:** native manager discovery found the module, but a legacy loader
  expecting the repository's optional zero-argument `register()` contract
  could not obtain it through that compatibility path.
- **Root cause:** the new module ended after `run()` without the small export
  used by most current modules.
- **Fix:** added a typed `register()` returning `SSHSurfaceGuardModule` and a
  narrow `__all__`; added a regression assertion for both.
- **Gates:** changed-file compile PASS; changed-file Ruff PASS; SSH suite
  **33 passed, 1 expected skip**; all-module registration **58/58**; full serial
  pytest **1,455 passed, 5 expected skips**.

### R2-01 / QA-R1-01 — independent authority remains external — REPORTED

- **Status:** **REPORTED / DEFERRED**, not falsely closed.
- **Residual:** without an injected, separately administered monotonic
  authority, a matching older authenticated local pair can still be replayed.
- **Current value:** the strict client/store contract makes behind, fork,
  clone, outage, migration, and crash states fail visible when an authority is
  present, and it never promotes the Personal Sentinel compact receipt or
  another local HMAC file to independent custody.
- **Required closure:** deploy and threat-model a durable server-enforced CAS
  service or policy-bound TPM authority, including authentication, backup,
  clone/re-enrollment, loss, clearing, and recovery behavior.

**Bugs fixed: 1. Bugs reported: 1 retained architectural residual.**
