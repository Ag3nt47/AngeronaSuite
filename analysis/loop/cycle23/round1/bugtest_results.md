# Cycle 23 Round 1 — Bug Test Results

Date: 2026-08-26  
Environment: Windows, repository virtual environment, `PYTHONPATH=src`,
offscreen Qt; the complete pytest run used `CI=true` and one serial process.

## Outcome

No crash, syntax error, import regression, duplicate module identity, broken
registration hook, module self-test failure, selfcheck failure, or pytest
failure was reproduced. The nine remediation areas all pass their focused
regressions. One additional design-level continuity defect was confirmed:
event-log and network state stores reject a missing or modified member, but
accept a replayed *pair* of older, valid cursor/enrollment documents. It is
**REPORTED**, not fixed, because genuine anti-rollback requires independent
monotonic custody and a deliberate migration/recovery policy.

| Gate | Result |
|---|---:|
| Whole-package `py_compile` / compile-check | **320 passed, 0 failed** |
| `angerona.modules.*` recursive imports | **73 passed, 0 failed** |
| Discovered `BaseModule` classes | **71/71, 0 discovery errors** |
| Callable compatibility `register()` hooks | **57/57 valid** |
| Duplicate module names / non-empty codes | **0 / 0** |
| Standalone core + Shark `self_test()` functions | **22 passed, 0 failed** |
| Direct `tools/selfcheck.py` | **26 passed, 0 failed** |
| Batch `run-selfcheck.bat` | **26 passed, 0 failed; exit 0** |
| Selfcheck module harness | **50 module passes, 0 failures, 21 skips** |
| Selfcheck EventBus pipeline | **1 passed** |
| Focused Cycle 23 regression set | **126 passed, 2 skipped, 0 failed** |
| Ruff (`src` + `tests`) | **PASS** |
| Complete serial pytest | **1,431 passed, 5 skipped, 0 failed** |
| Complete collection | **1,436 tests across 207 files** |

No sandbox stale/truncated-read artifact or false syntax error occurred.

## Commands and coverage

- Ran `tools/compile_check.py` directly and through
  `run-compile-check.bat`; both byte-compiled every Python file under
  `src/angerona`.
- Imported every file reported by `pkgutil.iter_modules(angerona.modules)`,
  instantiated every in-module `BaseModule` subclass, exercised every callable
  `register()` hook, and compared source classes against `ModuleManager`.
- Ran every top-level `self_test()` discovered by AST under `angerona.core` and
  `angerona.shark`: 21 core checks and the Shark Red Team check passed.
- Ran both selfcheck entry points. The module summary printed by the harness is
  `51 passed, 0 failed, 21 skipped` because it includes the passing EventBus
  pipeline; the exact module-only count is 50/0/21.
- Ran the six focused files for event-log integrity, SSH surface, network trust,
  Personal Sentinel Gateway, live defense activity, and Defense Memory.
- Collected and ran the entire suite without xdist or another parallel runner.

### Module skip classification

The 21 module skips are expected and explicit:

- **13 inactive/optional prerequisites:** AI Triage, AMSI Bridge, Active
  Deception, Active Response SOAR, Adversary Combat, Dynamic Resource Governor,
  Memory Injection Scanner, Network Monitor, Process Monitor, SOAR Automation,
  Sysmon Event Bridge, TUNE, and WFP Controller.
- **5 operator-disabled:** Cloud CTI Escalation, Forensics Capture, Packet
  Sniffer, Remote Bridge, and SIEM Forwarder.
- **3 platform-unavailable:** Linux Observe Sensor, Linux eBPF Sensor, and
  macOS Observe Sensor on the Windows test host.

Sixteen module files do not expose the optional legacy `register()` helper.
Fourteen contain directly discoverable `BaseModule` subclasses and two are
helper-only files (`packet_sniffer_worker` and `remediation_actions`). This is
not a missing-registration defect: the current manager contract discovers
subclasses, all 71 source classes were found, and there were no class or
manager mismatches. The 57 hooks that do exist all returned valid modules.

### Pytest skip classification

The complete run's five skips are host-capability gates, not test failures:

1. `test_cycle6_round2_remediation.py`: symlink creation unavailable.
2. `test_event_log_integrity_guard.py`: directory links unavailable.
3. `test_ir_bundle_privacy.py`: symlinks unavailable for this account.
4. `test_security_scan_center.py`: symlinks unavailable for this account.
5. `test_ssh_surface_guard.py`: POSIX permission bits unavailable on Windows.

The focused run contains items 2 and 5 only. Equivalent link/reparse and
custody rejection paths remain covered by platform-appropriate tests.

## Verification of Round 1 remediations

| Finding | Independent QA result |
|---|---|
| R1-01 | Retained 1102 replay, first enrollment, authenticated round trip, cursor deletion, signature tamper, CAS conflict, and link/reparse rejection pass. The paired-state rollback residual below remains. |
| R1-02 | Both deterministic late and post-commit clear/refill races discard staged evidence and report the gap. |
| R1-03 | Include precedence/escape/cycle/change bounds, aggregate digest, configured key/CA/principals sources, ACL custody, schema-v1 compatibility, and privacy tests pass. |
| R1-04 | Fixed Windows OpenSSH channels/providers/event IDs, bounded XML, non-service `sshd.exe`, client `ssh.exe`, forwarding flags, PID birth, sockets, and source-completeness tests pass. |
| R1-05 | Stable key derivation, restart/offline DNS drift, incomplete enrollment, missing baseline, in-flight output cap, and authenticated persistence pass. The paired-state rollback residual below remains. |
| R1-06 | Lower-metric competitor, standby competitor, IPv6 bypass, ambiguous route, and post-exchange route-context changes all prevent a positive gateway label. |
| R1-07 | MAC/EUI, SSID, adapter/account labels, secrets, and spaced/quoted Windows paths are redacted; real ARP public messages are identity-free; the card never reads `Event.details`. |
| R1-08 | AST preflight admits the network monitor on Linux and macOS; an undeclared legacy module still defaults to Windows-only. Cross-platform manager probes had zero discovery errors. |
| R1-09 | Root confinement, bounded descriptor reads, canonical digest, duplicate-key/schema checks, symlink/reparse rejection, and opened-identity swap rejection pass. |

## QA-R1-01 — authenticated state pairs remain replayable

- **Severity:** MEDIUM
- **Status:** **REPORTED** for Round 2 remediation/design review
- **Components:** `src/angerona/core/event_log_integrity.py:324,507-537` and
  `src/angerona/core/network_trust.py:892,1076-1122`

### Symptom

A controlled restart probe saved revision 1, advanced to a newer authenticated
revision, restored both older files byte-for-byte, and loaded through a new
store instance:

```text
EVENT_PAIRED_ROLLBACK status=authenticated revision=1 record=10 latest_before_replay=2
NETWORK_TRUSTED_PAIR_ROLLBACK state=trusted revision=2 latest_before_replay=3
```

By contrast, cursor tamper, cursor deletion, epoch tamper, and epoch deletion
all returned `untrusted` in both stores, as intended.

### Root cause

The cursor and enrollment document authenticate one another's enrollment ID and
revision, but the latest accepted revision exists only inside those two
replayable files and process memory. HMAC proves integrity and origin; it does
not prove freshness. After restart there is no independently retained
high-water value or append-only witness against which an older matching pair
can be rejected.

### Impact and limits

An offline actor must already be able to copy and later replace both protected
state files; no HMAC forgery, remote entry point, response authority, or raw
identity disclosure was demonstrated. Event rows newer than a rolled-back
cursor are normally replayed when still retained, so this probe does not by
itself prove suppression of a clear event. It does prove that the advertised
monotonic continuity property does not survive paired rollback, and a chosen
older network baseline can be accepted as current. That matters for the
state-grade local-tampering threat model these remediations target.

### Required design work

Bind revisions to an independent, non-replayable or externally witnessed
high-water source (for example, a TPM-backed monotonic value or a separately
operated append-only witness), then define explicit upgrade, loss, recovery,
and availability behavior. Merely adding another HMAC file under the same
replaceable custody would reproduce the defect. This exceeds the bug-test
agent's safe-fix authority and was not patched.

## Changes made by bug test

No product or test code was changed. **Bugs fixed: 0. Bugs reported: 1.**

