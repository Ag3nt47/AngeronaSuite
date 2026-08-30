# Cycle 26 round 2 bug-test results

Date: 2026-08-28
Scope: independent post-remediation QA with inert fixtures and failure injection

## Verdict

The round 2 changes compile, discover all 80 capabilities, and pass the
focused release, response, Scan Center, resilience, source-authority, and
module-health gates. Bug testing found three clearly bounded regressions and
fixed them behind focused gates. It also broke the initial workflow-policy
implementation with three valid-YAML bypasses; the release-authority
remediation owner replaced the substring checks with structural policy during
this QA pass, and all three original bypass fixtures are now rejected.

This result does not close or rewrite the separate round 2 red-team findings.
Their status remains owned by the remediation coordinator.

## Gates run

- Whole product compile: **348/348** Python files under `src/angerona/` passed
  `py_compile`, including the concurrently added package-identity boundary.
- Module import and discovery: **82/82** `angerona.modules` files imported;
  **64/64** compatibility `register()` hooks constructed; all **80/80**
  capabilities were discovered with zero errors. The 16 remaining capability
  files are intentionally class-discovered under the repository's no-register
  contract. All **61** declared module `CODE` values were unique.
- Core top-level self-tests: **24/24 passed**, with zero import or execution
  errors.
- Capability runner through the headless harness: **64 passed, 0 failed, 17
  expected skips**. Skips were limited to unstarted/optional prerequisites,
  disabled capabilities, or unsupported host platforms.
- Headless project harness: **26 passed, 0 failed** phases. It discovered all
  80 capabilities and exercised the offscreen main window, Module Inspector,
  response gates, ATT&CK coverage, and defensive drills.
- Focused regression gates: **105 passed, 2 expected symlink-capability skips,
  0 failed**. This consists of 54 release/workflow/setup/hash/authorization
  tests and 51 Defender/Scan Center/resilience/module-health/source-authority
  tests.
- Defender proposal matrix: dry-run/apply crossed with explicit host denial,
  explicit host approval, and environment-derived approval made **zero**
  subprocess calls and produced no applied receipt.
- Failed-apply injection: an action returning `ok=False` never invoked its
  verifier, never became applied, and entered rollback/audit handling.
- Scan identity/budget gates: both budget and oversize fast paths performed no
  content read, retained root/object revalidation, and returned a truthful
  limited result when content could not be scanned.
- Module-health parity: all 80 inventory snapshots shared the v12 evidence
  schema; trusted callsites retained exact path/line evidence; packaged and
  external sources withheld invented paths; the issue line remained highlighted
  dark red. A deterministic refresh-race fixture verified that health text and
  evidence now come from one atomic snapshot.
- Workflow policy: direct validator execution passed. The original bracketed
  secret alias, unsigned-as-final artifact spoof, and comment-only dependency
  spoof are each rejected after structural remediation.
- Hygiene: `git diff --check` returned no whitespace defect; only informational
  working-tree line-ending notices were printed.

The first raw module-construction probe intentionally lacked a test data root
and encountered the protected live `bus.key` plus an unavailable live database.
That was the expected host custody boundary, not an import regression. The
hermetic D-drive rerun produced the zero-error counts above.

## Bugs

### QA-C26-R2-01 — workflow policy accepted valid secret and artifact-graph bypasses

- **Severity/status:** HIGH — **REPORTED, THEN FIXED BY ROUND 2 REMEDIATION**.
- **Component:** `tools/validate_workflow_policy.py`,
  `.github/workflows/release.yml`, and
  `tests/test_cycle26_release_signing_boundary.py`.
- **Reproduction:** three independently YAML-valid workflow mutations returned
  `validate(...) == []`:
  1. `secrets['CI_BLOB']` supplied to `prepare-windows` under a neutral env
     alias bypassed the dot-only secret search;
  2. the authority retained `exit 1` only in a comment, executed `exit 0`, and
     renamed the unsigned upload to `finalized-windows-release-assets` while
     preserving the expected prepared name in a YAML comment; and
  3. `publish-release.needs` omitted both Windows gates while their names
     appeared only in a comment.
- **Root cause:** a security graph was being inferred from unparsed text and
  substring presence rather than executable YAML structure, exact edges, exact
  gate shape, and artifact producer/consumer custody.
- **Closure gate:** the policy now uses duplicate-key-rejecting YAML parsing,
  exact job edges, exact authority-step structure, secret-context rejection,
  exact unsigned upload custody, and a ban on repository-produced finalized
  assets. The release-focused suite passed **54/54** and all three original
  bypasses are rejected.

### QA-C26-R2-02 — an oversize skip was reported as a complete scan

- **Severity/status:** MEDIUM — **FIXED**.
- **Component:** `src/angerona/core/security_scan_center.py` and
  `tests/test_security_scan_center.py`.
- **Symptom:** a selected directory containing one stable 4 KiB file under a
  1 KiB per-file limit produced `files_scanned=0` and
  `oversize_files_skipped=1`, but the operation status was `completed`.
- **Root cause:** final limited-state calculation included total-budget and
  unsafe-scope skips but omitted the existing oversize counter.
- **Fix/gate:** `skipped_oversize > 0` now makes the result limited. The new
  descriptor-bound no-read regression and the complete Scan Center/surface
  group passed **30 tests with 2 expected skips**.

### QA-C26-R2-03 — Module Inspector could mix two health generations

- **Severity/status:** LOW — **FIXED**; independently closes the runtime
  red-team symptom recorded as C26-R2-D05.
- **Component:** `src/angerona/gui/pages.py` and
  `tests/test_cycle26_module_health_evidence.py`.
- **Symptom:** `_refresh()` captured one atomic `operational_snapshot()` for the
  evidence button, then reread live `health`, `health_note`, `health_state`, and
  `status` for the adjacent label. A concurrent restoration/degradation could
  transiently hide the reason or label it with the wrong percentage.
- **Root cause:** the newly shared snapshot was only partially adopted by the
  presentation path.
- **Fix/gate:** status text, color, percentage, reason, and evidence visibility
  now derive from the same snapshot. The module-health suite passed **8/8**,
  including deterministic opposing live/snapshot state injection.

### QA-C26-R2-04 — selfcheck and ATT&CK coverage still claimed executable Defender response

- **Severity/status:** LOW — **FIXED**.
- **Component:** `src/angerona/core/attack_coverage.py` and
  `tools/selfcheck.py`.
- **Symptom:** the first post-remediation selfcheck failed two phases because it
  expected `select_action(...).key == "defender_hardening"` and T1562 still
  advertised that key in the executable remediation column.
- **Root cause:** the product response was correctly moved to proposal-only,
  but the assurance harness and curated coverage metadata retained the old
  executable contract.
- **Fix/gate:** T1562 no longer inflates executable response coverage; selfcheck
  now proves Defender is absent from `ACTIONS` and present as a non-executable
  proposal. The final selfcheck passed **26/26** phases.

### QA-C26-R2-05 — structural parser made a comment-only policy fixture stale

- **Severity/status:** LOW — **REPORTED, THEN FIXED BY ROUND 2 REMEDIATION**.
- **Component:** `tests/test_cycle26_release_signing_boundary.py`.
- **Symptom:** after the structural policy landed, one test expected a signing
  secret written only inside a YAML comment to be rejected. The release subset
  reported 42 passes and this single failure.
- **Root cause:** comments correctly ceased to be policy inputs, while the old
  test still relied on text matching.
- **Closure gate:** the fixture now inserts a real parsed job environment secret
  reference. The expanded release subset passed **54/54**.

## Bug accounting

- Clearly-safe bug groups fixed by bug testing behind gates: **3**.
- Security/test defects reported and independently fixed during the same QA
  pass: **2**.
- QA findings left unreported or silently converted to skips: **0**.
- Separate red-team findings modified by bug testing: **0**.
