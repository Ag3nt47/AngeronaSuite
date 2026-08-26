# Cycle 23 Round 3 — Bug Test Results

Date: 2026-08-26  
Environment: Windows, repository `venv`, `PYTHONPATH=src`, offscreen Qt;
the complete pytest run used `CI=true`, an empty `PYTEST_ADDOPTS`, and one
serial process.

## Outcome

No crash, syntax error, import regression, duplicate module identity, broken
Cycle 23 registration hook, standalone self-test failure, selfcheck failure,
privacy-boundary regression, or pytest failure was reproduced. Independent QA
confirms that the R3-01 repair survives restart, does not silently promote an
absent or changed pending path, and conservatively migrates legacy provisional
schema-v1 state. No product or test code was changed by bug test.

The separate high-water authority remains an honestly deferred deployment
dependency. In the default configuration, audit and network state retain local
HMAC authenticity but explicitly report `local-authenticity-only` with
`independent_freshness_verified=False`; Angerona does not represent an on-host
file, the Personal Sentinel receipt, or the in-memory test fixture as
independent anti-rollback custody.

| Gate | Result |
|---|---:|
| Whole-package `python -m py_compile` | **321 passed, 0 failed** |
| `angerona.modules.*` imports | **73 passed, 0 failed** |
| Discovered `BaseModule` classes / manager instances | **71 / 71, 0 discovery errors** |
| Callable zero-argument compatibility `register()` hooks | **58/58 valid** |
| Duplicate module names / duplicate non-empty codes | **0 / 0** |
| Standalone core + Shark `self_test()` functions | **22 passed, 0 failed** |
| Direct `tools/selfcheck.py` | **26 passed, 0 failed** |
| Batch `run-selfcheck.bat` | **26 passed, 0 failed; exit 0** |
| Selfcheck module harness | **50 module passes, 0 failures, 21 skips** |
| Selfcheck EventBus pipeline | **1 passed** |
| Focused Cycle 23/R3 security and integration set | **155 passed, 2 skipped, 0 failed** |
| Ruff (`src`, `tests`, and `tools`) | **PASS** |
| Complete serial pytest | **1,460 passed, 5 skipped, 0 failed** |
| Complete collection | **1,465 tests across 208 files** |

No stale/truncated sandbox-mount read or false syntax error occurred.

## Compile, import, discovery, and registration

- Walked every `.py` file below `src/angerona` and invoked the repository
  virtual environment's `python -m py_compile` in bounded batches. All 321
  product files compiled.
- Combined `pkgutil` discovery with the manager's filesystem fallback and
  imported all 73 module files. Source inspection found 71 in-module
  `BaseModule` subclasses; an isolated Windows `ModuleManager.discover()` run
  constructed all 71 with no error.
- All 58 zero-argument compatibility hooks returned a `BaseModule`. The Audit
  Log, SSH Surface, and Zero-Trust Network Path modules each expose a valid
  hook. Fifteen older files have no hook: 13 contain legacy classes already
  covered by native subclass discovery and two are helper-only files
  (`packet_sniffer_worker` and `remediation_actions`). This is unchanged and is
  not a missing-discovery defect.
- No duplicate module name or non-empty `CODE` was found. Nineteen older
  manager instances have no code; none of the three Cycle 23 guards is among
  them and no collision is hidden by an empty value.
- AST discovery found 21 top-level core `self_test()` functions and the Shark
  Red Team self-test. All 22 imported and passed.

## R3-01 restart and migration verification

The focused gate ran all tests in `test_network_trust.py`,
`test_independent_high_water.py`, `test_personal_sentinel_gateway.py`,
`test_event_log_integrity_guard.py`, `test_ssh_surface_guard.py`,
`test_live_defense_activity.py`, and `test_defense_memory.py`.

- An established one-path baseline reports a bounded `network.path_added`
  finding when a second physical path appears. The event omits raw adapter,
  network, route, DNS, DHCP, gateway, and profile identifiers and retains
  `response_authorized=False`.
- The addition-only candidate is authenticated as schema v2, revision 3,
  `trusted=False`, with exactly one tokenized pending path. Restarting against
  a changed version of that path produces DNS drift and does not advance the
  stored revision.
- Restarting while the pending path is absent leaves the store provisional,
  retains revision 3, and degrades health. Presenting the same active,
  unchanged path on a later sample promotes through the authenticated gate to
  schema v2 revision 4 with an empty pending set. A further steady sample does
  not rewrite the state.
- The peer-review edge is covered directly: a correctly re-signed provisional
  schema-v1 cursor with no `pending_path_tokens` field reloads with its path
  reconstructed as pending. If that path is absent, the module remains
  provisional at health 40 and the on-disk cursor remains schema 1, revision 1;
  migration does not silently bless or rewrite it.
- A new path cannot evict authenticated history at the 64-link bound. Path
  removal/reappearance retains the earlier epoch comparison semantics.

## Independent-freshness honesty

A separate temporary-directory probe exercised both stores with no injected
authority:

```text
event:   first-enrollment -> save -> authenticated;
         freshness=local-authenticity-only, independently_fresh=false
network: missing -> save -> provisional;
         freshness=local-authenticity-only, independently_fresh=false
```

The focused high-water regressions also passed for witnessed rollback,
same-revision fork, installation clone, authority outage, legacy migration,
external-first crash, and privacy-bounded transition fields. Those tests use a
strict in-memory contract fixture only. They do not close or obscure the
deferred requirement for a separately administered server-enforced CAS or
policy-bound TPM authority.

## Dashboard, Defense Memory, and privacy boundaries

- The live activity card remains bounded to five displayed rows and a
  16-event public-history request, refreshes only on EventBus/module-state
  revisions, and never reads raw `Event.details`. Runtime text redacts local
  network identifiers, users, paths, addresses, credentials, and explicit
  hidden-reasoning requests.
- ARP public messages remain identity-free while structured details stay on
  the local bus. The new network findings likewise retain tokenized, bounded,
  observe-only details.
- The bundled ARIA Defense Memory remains strict-schema, canonical-SHA-256
  pinned, root-confined, non-reparse, bounded, data-only, actor-neutral, and
  free of secrets/live telemetry/executable actions. Local RAG retrieval finds
  the capability, SSH, log-clearing, and Personal Sentinel entries. Cloud
  fallback receives only the bounded pinned excerpt, never operator files,
  data-directory runbooks, live context, or the complete memory asset.
- Main-window rebuilding admits exactly the verified in-memory Defense Memory
  source alongside local-only operator references. The dashboard integration
  constructed successfully in both official selfcheck runs.

## Expected skips

The complete suite's five skips are unchanged host-capability gates:

1. `test_cycle6_round2_remediation.py`: symlink creation unavailable.
2. `test_event_log_integrity_guard.py`: directory links unavailable.
3. `test_ir_bundle_privacy.py`: symlinks unavailable for this account.
4. `test_security_scan_center.py`: symlinks unavailable for this account.
5. `test_ssh_surface_guard.py`: POSIX permission bits unavailable on Windows.

The focused run contains items 2 and 5. Platform-appropriate reparse, opened-
identity, ACL-custody, and privacy-negative tests cover the corresponding
Windows boundaries.

The 21 selfcheck skips are also explicit: 13 stopped/optional prerequisites,
five operator-disabled modules, and three non-Windows platform modules. No
timeout or exception was converted into a skip.

## Non-defect environment artifacts

- The system Python on `PATH` lacks pytest, so the first targeted invocation
  ended before collection with `No module named pytest`. Every reported gate
  was rerun with the repository's documented `venv\Scripts\python.exe`.
- An initial custom discovery probe isolated `Config.data_dir` but not the
  process-wide `ANGERONA_DATA` root, so two constructors correctly rejected
  missing/unavailable persistent state. The corrected fully isolated probe
  passed 73 imports and 71/71 discovery.
- A temporary-directory variant tried to remove its data root while the live
  manager still held the EDR log open and received Windows sharing error 32.
  This was a probe-lifetime mistake, not an application crash: rerunning with a
  process-lifetime temporary root exited cleanly, and both official selfcheck
  paths also passed.

## Documentation drift held for the end-of-round docs agent

As instructed, bug test did not edit `README.md`, `analysis/llms.txt`, or the
Word manual. Their current status blocks still cite older test, compile, and
module counts (including the README `1305/3` marker and `llms.txt` `310/310`,
`68 modules`). The final documentation agent must update them to the final
post-performance/visionary tree rather than freezing this intermediate QA
count prematurely.

## Bugs and changes

No new product defect was found and no product/test change was applied.
**Bugs fixed: 0. Newly reported bugs: 0. Retained deferred architectural
dependency: 1 (separately administered monotonic high-water authority).**
