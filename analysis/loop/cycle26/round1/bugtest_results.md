# Cycle 26 round 1 bug-test results

Date: 2026-08-28
Scope: independent post-remediation QA; inert fixtures and failure injection only

## Verdict

The Cycle 26 round 1 product changes compile and their focused and full
regression gates pass. No crash, import regression, duplicate capability code,
failed self-test, or orphan helper process was found. Two security defects were
independently confirmed and are **REPORTED** for round 2; both require design
judgment and were not changed under the bug tester's obvious-fix gate.

## Gates run

- Whole package compile: **347/347** Python files under `src/angerona/` passed
  `py_compile`.
- Module-file import inventory (project venv): **82/82** files imported;
  **64/64** compatibility `register()` hooks constructed without error. The 18
  class-discovered compatibility files without a module-level hook match the
  established inventory and are not a new missing-hook regression.
- Manager discovery: **80/80** capabilities, 80 unique names, 80 unique
  capability IDs, and zero discovery errors. All **61** capabilities that
  declare an explicit `CODE` have unique codes; zero duplicates.
- Focused security/release/UI gate: **102 passed, 2 skipped, 0 failed** across
  module health evidence and exact-line navigation, source authority, release
  signing boundary, resilience custody, Scan Center object binding and status
  aggregation, launchers, source install, hash locks, and release setup.
- Top-level self-tests: **37/37 passed**, zero failed and zero timed out. Each
  was run in an isolated subprocess with a 45-second limit. This covered every
  zero-argument `self_test()` discovered in core, resilience, GUI utility,
  connector, and defensive red-team packages.
- Capability `SelfTestRunner`: **64 passed, 0 failed, 17 skipped** (the pass
  count includes its event-pipeline check). The 17 skips were explicitly
  classified unstarted, optional-prerequisite, disabled-by-configuration, or
  unsupported-platform states; no exception or timeout was converted to a
  skip.
- Headless project harness: `venv\\Scripts\\python.exe -X utf8
  tools\\selfcheck.py` exited 0 with **26 passed, 0 failed** phases. It
  discovered all 80 capabilities and constructed the main window, dashboards,
  Module Inspector, and defensive drill gates offscreen.
- Full regression suite: **1,836 passed, 7 skipped, 0 failed** in 193.81
  seconds.
- Hygiene: `git diff --check` reported no whitespace defect (line-ending
  conversion notices only). Post-test process inventory found **0** Angerona,
  scanner, resilience, or selfcheck helper processes left behind.

The first raw import probe used the host `python` rather than the repository
venv and correctly failed on absent `defusedxml`/`psutil` dependencies. This was
an environment mismatch, not a product import failure; the required venv rerun
imported all 82 module files and the complete suite passed.

## Bugs

### QA-C26-R1-01 — exportable Windows publisher key remains exposed to candidate code

- **Severity/status:** HIGH — **REPORTED**, not fixed by bug testing.
- **Component:** `.github/workflows/release.yml:89-139,222-251,352-377,
  431-439,504-535`.
- **Symptom:** the fail-closed `finalize-release-authority` job prevents public
  packaging, but the earlier `prepare-windows` job still checks out, installs,
  and executes repository-controlled Python before receiving the exportable
  `ANGERONA_WINDOWS_SIGNING_PFX_B64` and its password. A release-triggered
  candidate revision could read or exfiltrate the publisher private key during
  preparation. The currently blocked package/migration job retains the same
  hazardous secret pattern and would restore exposure if the finalizer were
  re-enabled without redesign.
- **Root cause:** public release signing still treats an exportable PFX as a
  normal workflow secret in a workspace/process controlled by the candidate
  repository. Removing the threshold witness secrets and blocking publication
  fixed one authority path, but did not establish an immutable signer boundary
  for Authenticode/MSIX custody.
- **Required remediation:** remove the exportable PFX/password from every
  candidate-code job. An independently maintained immutable signer should use
  OIDC and a non-exportable key/HSM to sign only a canonical, digest-bound
  request, returning attestable signatures/artifacts to an unprivileged
  verifier. Keep publication fail-closed until that boundary exists. Add a
  workflow-policy regression that rejects all publisher private-key material
  in jobs that checkout or execute repository code.
- **Why not fixed here:** changing signer custody and the release handoff is a
  security architecture decision, not an obvious typo or local logic repair.

### QA-C26-R1-02 — Defender remediation can claim success after its apply command failed

- **Severity/status:** HIGH — **REPORTED**, not fixed by bug testing.
- **Component:** `src/angerona/modules/remediation_actions.py:450-477,
  892-913`.
- **Symptom/reproduction:** an inert mocked run made the Defender apply command
  return exit code 1 while the subsequent query reported the pre-existing
  `DisableRealtimeMonitoring=False` state. `apply_remediation` returned
  `applied=1`, `skipped=0`, with a record containing the contradictory values
  `ok=False` and `verified=True`. No host preference was read or changed during
  this reproduction.
- **Root cause:** `DefenderHardeningAction.apply` requests three preference
  changes (real-time monitoring, MAPS reporting, and sample consent) through a
  PATH-resolved `powershell`, uses `-ExecutionPolicy Bypass` and
  `-ErrorAction SilentlyContinue`, and is non-reversible. Its `verify` ignores
  the apply record/exit code and checks only a substring in the real-time
  monitoring preference. `apply_remediation` trusts that partial check as proof
  for the whole action.
- **Impact:** an already-enabled real-time setting can mask failure to apply
  cloud reporting/sample submission and can even mask total apply failure,
  producing a false PATCHED/applied audit receipt for a host-level action. A
  PATH-searchable PowerShell executable also leaves privileged executable
  identity implicit.
- **Required remediation:** use a trusted absolute system executable (or a
  constrained native API), remove execution-policy bypass and silent error
  suppression, snapshot every governed prior value, apply each exact setting
  with terminating errors, and verify all requested postconditions from typed
  output. Verification must require `record["ok"]`, and any partial mutation
  needs explicit compensation or a truthful partial/failed result. Add the
  inert total-failure/pre-existing-real-time regression above plus per-setting
  partial-failure matrices.
- **Why not fixed here:** rollback semantics, Defender policy ownership, and
  the trusted PowerShell boundary are host-remediation architecture decisions.

## Bug accounting

- Clearly-safe bugs fixed behind gates: **0**.
- Design/security defects reported: **2**.
- Product regressions or self-test failures remaining from round 1 product
  remediation: **0**.
