# Cycle 23 Round 2 — Remediation Summary

Date: 2026-08-26  
Scope: only R2-01 through R2-06 from this round's red-team findings.

All changes remain actor-neutral and observe-only. They do not change SSH
configuration, authorized-key material, Windows Event Log state, routes,
firewall policy, network profiles, or gateway configuration. Routine evidence
remains bounded and privacy-minimized, and no response authority was added.

## R2-01 — DEFERRED (client/store contract delivered; external enforcement absent)

- **Changed:** `src/angerona/core/independent_high_water.py` defines a strictly
  injected, privacy-minimal independent high-water protocol. Separate audit and
  network domains bind installation ID, revision, exact authenticated-pair
  digest, previous state digest, and previous opaque head in a monotonic
  compare-and-swap transition. No local-file implementation is provided.
- **Changed:** `src/angerona/core/event_log_integrity.py` and
  `src/angerona/core/network_trust.py` query an injected authority on load,
  reject behind/forked/installation-mismatched pairs, block advancement while
  offline or awaiting migration, and commit the external head before the local
  pair so a crash is detected as an external-ahead recovery state.
- **Changed:** `src/angerona/modules/audit_log_guard.py` and
  `src/angerona/modules/network_trust_monitor.py` report local authenticity and
  independent freshness separately. Missing/offline/migration freshness is
  provisional and cannot silently become independently current.
- **Regression:** `tests/test_independent_high_water.py` covers exact paired
  rollback for both domains, same-revision fork, clone/installation mismatch,
  offline witness loss, legacy migration, external-first crash ordering, and a
  fixed transition schema that cannot carry raw logs or network identifiers.
- **Deferred residual:** the repository does not implement or prove a
  separately administered server/TPM authority that durably enforces monotonic
  CAS, device authentication, backup/re-enrollment policy, and authenticated
  responses. The existing Personal Sentinel compact receipt API is therefore
  explicitly *not* treated as this authority. A third replayable local HMAC
  file was not added. These controls detect rollback only when a conforming
  injected authority exists, and they do not claim resistance to
  Administrator/SYSTEM denial, kernel/firmware tampering, TPM clearing, or
  destruction of the external service.
- **Gates:** compile PASS; Ruff PASS; combined focused suite PASS; Audit Log
  Integrity Guard and Zero-Trust Network Path Monitor `self_test()` PASS.

## R2-02 — FIXED

- **Changed:** `src/angerona/core/ssh_surface.py` applies plain-relative-home
  semantics to per-user key/principals directives and bounded expansion for
  `%%`, `%h`, `%u`, and `%U`. It records explicit `unresolved`, `incomplete`,
  and `not-applicable` states when account, UID, Match, group, or token
  semantics cannot be proven, rather than recording a false missing path.
- **Changed:** Windows SSH custody now checks the admitted file and its bounded
  parent chain for owner/DACL write, delete, generic mutation, and
  `FILE_DELETE_CHILD` replacement rights. Per-user files admit the resolved
  user SID plus SYSTEM/Administrators; shared files remain administrative.
  Unavailable SID/ACL evidence stays unknown rather than verified.
- **Regression:** `tests/test_ssh_surface_guard.py` covers custom relative key
  and principals names, all admitted tokens, missing UID, conditional and
  incomplete account sets, path escape, unsafe parent replacement rights, and
  user-aware custody.
- **Gates:** compile PASS; Ruff PASS; combined focused suite PASS; SSH Surface
  Guard `self_test()` PASS.

## R2-03 — FIXED

- **Changed:** `src/angerona/modules/network_trust_monitor.py` detects interface
  overflow before bounded retention, accounts for rejected address and route
  rows per family, marks per-link route overflow incomplete, and removes route
  completeness when a route-bearing interface was omitted.
- **Changed:** positive Personal Sentinel labeling now requires complete
  interface, address, IPv4-route, and IPv6-route evidence in both pre- and
  post-exchange snapshots. Overflow is represented by omission of the existing
  authenticated completeness token, which fails closed without expanding the
  core schema.
- **Regression:** `tests/test_network_trust.py` covers 65-interface omitted
  standby routes, Windows family-specific rejection, Linux/Windows route caps,
  and incomplete pre/post-attestation snapshots.
- **Gates:** compile PASS; Ruff PASS; combined focused suite PASS; Zero-Trust
  Network Path Monitor `self_test()` PASS.

## R2-04 — FIXED

- **Changed:** `src/angerona/modules/ssh_surface_guard.py` replaces permanent
  attempted-source suppression with capped exponential reopen backoff and
  bounded stable jitter. Repeated query failures close the stale source and
  re-enter the same lifecycle; health exposes fixed failure/retry/recovery
  states without exception text or source identity.
- **Boundary retained honestly:** reopened channels initialize from a bounded
  retained tail and keep a history-bounded warning. Recovery never claims that
  evidence missed during the blind interval was recovered.
- **Regression:** transient open failure, backoff/no-hot-loop, successful
  reopen, repeated query failure, stale-source close, and bounded-tail recovery
  are covered.
- **Gates:** compile PASS; Ruff PASS; combined focused suite PASS; SSH Surface
  Guard `self_test()` PASS.

## R2-05 — FIXED

- **Changed:** `src/angerona/core/ssh_surface.py` uses a bounded, consuming
  subset of the OpenSSH client grammar. It recognizes direct forwarding forms
  and supported `-oName=Value`, `-o Name=Value`, and `-o "Name Value"` forms
  for local, remote, dynamic, and tunnel forwarding without substring tests.
- **Changed:** `-F` produces `client-config-uninspected` unless its operand is
  `none`; malformed/unknown grammar produces a normalized completeness label.
  No raw argument, endpoint, command, or referenced client-config contents are
  retained or emitted.
- **Regression:** split/attached `-o`, direct short operands, benign
  `-oLogLevel=DEBUG`, `Tunnel=no`, destination-boundary, malformed, and `-F`
  cases are covered.
- **Gates:** compile PASS; Ruff PASS; combined focused suite PASS; SSH Surface
  Guard `self_test()` PASS.

## R2-06 — FIXED

- **Changed:** `src/angerona/core/event_log_integrity.py` admits only fixed
  channel/provider/event-ID triples, requires the XML System/Channel to match
  the fixed source, and maps per-event inputs only to Angerona-owned output
  keys. Non-enumerated retained values are redacted and unexpected XML field
  names never become EventBus dictionary keys.
- **Changed:** `src/angerona/core/windows_event_log.py` binds the same provider
  identities into the fixed WEVT XPath; `src/angerona/modules/audit_log_guard.py`
  advances parseable rejected record IDs and emits one bounded normalized
  rejection reason per transition, without raw XML/provider-controlled text.
- **Regression:** foreign provider, XML channel mismatch, path-shaped generic
  fields, provider-bound query construction, fixed-key output, cursor advance,
  and no-replay-loop behavior are covered.
- **Gates:** compile PASS; Ruff PASS; combined focused suite PASS; Audit Log
  Integrity Guard `self_test()` PASS.

## Aggregate gates

- `py_compile`: PASS for all eight changed production files and five focused
  test files.
- Ruff: PASS for the same affected set.
- Focused cross-module pytest: **135 passed, 2 skipped, 0 failed**. The skips
  are existing host-capability gates for directory links/reparse simulation and
  POSIX permission bits on Windows.
- Self-tests: network-trust core, Audit Log Integrity Guard, Zero-Trust Network
  Path Monitor, and SSH Surface Guard all PASS.

