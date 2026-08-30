# Cycle 26 round 1 remediation summary

## C26-R1-A04 — FIXED

- **Finding:** threshold release signer jobs executed candidate repository code
  while exportable witness keys were present; the finalizer likewise executed
  candidate code with the protected threshold root policy.
- **Change:** `.github/workflows/release.yml` removes both in-repository signer
  jobs and the candidate-code finalizer. It preserves the canonical prepared
  statement as a short-lived, explicitly untrusted handoff artifact and replaces
  finalization with a no-permission, no-checkout, no-secret, no-download gate
  that always fails before packaging or publication.
- **Policy:** `tools/validate_workflow_policy.py` rejects reintroduction of the
  exportable threshold secrets, candidate checkout/download in the authority
  gate, missing failure, or an `always()` / `continue-on-error` downstream
  bypass. `docs/enterprise/RELEASE_SIGNING_BOUNDARY.md` records the external
  OIDC, immutable-code, non-exportable two-party provisioning contract and the
  exact residual needed to re-enable publication.
- **Regression:** `tests/test_cycle26_release_signing_boundary.py` parses the
  workflow, proves the gate consumes no prepared artifact, and proves packaging
  and publication remain transitively blocked. Existing release assertions in
  `tests/test_release_setup.py` now enforce the same truthful disabled state.
- **Gate results:** Python compile PASS for the changed validator/tests; workflow
  YAML/parser, release policy, release setup, and documentation drift tests PASS
  (25 passed); helper `self_test()` not applicable.
- **Infrastructure residual:** releases are deliberately disabled until an
  independently maintained OIDC-backed authority with non-exportable signer
  custody is actually provisioned. No fictitious service or action identifier
  was added.

## C26-R1-B01 — FIXED

- **Finding:** concurrent resilience self-tests could overwrite each other's
  process environment, restore absent/empty values incorrectly, and redirect
  diagnostics cleanup by changing `ANGERONA_DIAG_DIR` during a failure path.
- **Change:** `src/angerona/resilience/_selftest_environment.py` provides one
  process-wide re-entrant custody gate for every env-routed resilience
  self-test. It captures the exact temp directory object, restores each prior
  environment value including absent and empty states, and never rereads the
  environment for cleanup. Diagnostics, manager, scanner, ecosystem, and
  supervisor self-tests use the gate.
- **Lifecycle hardening:** `src/angerona/resilience/manager.py` records the
  creation time, executable, command marker, and ancestry of its detached test
  scanner chain and reaps children before their exact launcher on every exit.
  A forced-exception regression proves an unrelated process survives.
- **Gate results:** compile PASS; all five affected resilience `self_test()`
  functions PASS; deterministic concurrency, sentinel, exception, and exact
  child-custody regressions PASS.

## C26-R1-B02 — FIXED

- **Finding:** Scan Center validated a pathname, reopened it for content, then
  let YARA-X reopen the pathname again, permitting file, parent, root, or
  reparse swaps between checks.
- **Change:** `src/angerona/core/security_scan_center.py` opens each candidate
  once with no-follow semantics where the OS exposes them, binds the open
  handle's final OS path to the selected root, preserves root and volume
  identity before and after a bounded read, rejects mutation during the read,
  and passes the resulting immutable bytes to `Scanner.scan`. It never calls
  `Scanner.scan_file` for selected content.
- **Fail-closed residual:** final-handle resolution is native on Windows and
  `/proc/self/fd`-bound on Linux. A platform without either proof skips the
  object as unsafe and reports a limited scan; it does not fall back to a
  pathname reopen.
- **Gate results:** compile PASS; Scan Center focused suite PASS (17 passed,
  2 expected symlink-capability skips); deterministic pre-open link swap and
  no-pathname-reopen regressions PASS.

## C26-R1-B03 — FIXED

- **Finding:** the combined result inherited the local scanner's top-level
  status, so the GUI could display Complete when the requested Defender scan
  failed, was rejected, unsupported, limited, or cancelled.
- **Change:** `src/angerona/gui/scan_center.py` now emits a bounded typed
  aggregate with every requested component's status, support/execution truth,
  and errors. Complete is possible only when all requested scanners completed;
  other matrices resolve to limited, partial, unsupported, rejected, error, or
  cancelled and render accordingly.
- **Gate results:** compile PASS; seven-state aggregation matrix PASS; the
  complete Cycle 26 surface-hardening suite PASS (10 passed).
