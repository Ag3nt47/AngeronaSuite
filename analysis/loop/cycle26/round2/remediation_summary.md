# Cycle 26 round 2 remediation summary

## C26-R2-A01 — FIXED

- **Finding:** candidate-controlled `prepare-windows` and `package-windows`
  workflow steps received an exportable Windows publisher PFX, its password,
  and certificate metadata, then imported and used the private key.
- **Change:** `.github/workflows/release.yml` removes every publisher secret,
  PFX import, SignTool operation, and code-signing environment from repository
  jobs. Candidate builders now create only unsigned executables/catalog,
  unsigned MSIX/ZIP packages, canonical SHA-256 request material, SBOM,
  provenance, and explicitly untrusted signing requests.
- **Fail-closed graph:** `package-windows` emits only
  `prepared-windows-publisher-request`; the no-permission external-authority
  gate depends on that package request and exits 1. `publish-release` depends
  explicitly on both jobs and requests `finalized-windows-release-assets`, an
  artifact no repository job produces.
- **Policy:** `tools/validate_workflow_policy.py` rejects known publisher and
  threshold key markers plus generic exportable signing-secret names in every
  workflow. It also rejects signing APIs in unsigned builders, a missing
  package-to-authority-to-publisher dependency, prepared-artifact publication,
  and `always()` / `continue-on-error` bypasses.
- **Contract/tests:** `docs/enterprise/RELEASE_SIGNING_BOUNDARY.md` documents
  the independently maintained OIDC, non-exportable threshold and Windows
  publisher contract. Focused workflow tests parse the graph and inject a
  prohibited PFX secret into a different workflow to prove global enforcement.
- **Gate results:** Python compile PASS for the policy validator and affected
  tests; Ruff PASS; workflow policy validator PASS; workflow PowerShell parser
  and expanded authorization/update/release/policy sweep PASS (**66 passed**);
  diff check and merged JSON/dependency-graph validation PASS; no helper
  `self_test()` applies (**N/A**).
- **Residual:** publication remains intentionally disabled. No fictitious
  signer, action, service, or finalized artifact was introduced.

## C26-R2-B01 — FIXED

- **Finding:** Defender hardening used a PATH-resolved PowerShell process,
  execution-policy bypass, and silent error suppression to change three host
  preferences without exact prior-state or rollback custody. A failed apply
  could be promoted to an applied/verified receipt when the pre-existing
  real-time setting already matched.
- **Safe boundary:** `src/angerona/modules/remediation_actions.py` removes
  `DefenderHardeningAction` from executable `ACTIONS`. The action is inert and
  retained only in `PROPOSAL_ONLY_ACTIONS`, with explicit `proposal_only=true`,
  `executable=false`, and a reason explaining the missing custody and the need
  for an independently authorized administration channel.
- **Operator evidence:** remediation plans continue to name the Defender
  response gap and present its reason. Even with `apply=True` and
  `allow_host=True`, the runner records only a proposal-only skip and cannot
  invoke a Defender subprocess or emit an applied/verified receipt.
- **Receipt integrity:** the generic runner now requires `record["ok"] is True`
  before calling an action verifier. A failed apply therefore cannot be
  promoted merely because its desired postcondition was already true.
- **Regression:** `tests/test_cycle26_defender_remediation_boundary.py` proves
  direct and runner-mediated Defender handling is non-executable, validates the
  operator-visible reason, rejects applied/verified audit outcomes, and covers
  the generic failed-apply/pre-existing-postcondition case.
- **Gate results:** changed product and test Python compile PASS; Ruff PASS;
  focused remediation, posture, UI, lifecycle, receipt, and purple-path tests
  PASS (**35 passed**). This module has no `self_test()` (**N/A**).
- **Residual:** automatic Defender preference mutation remains intentionally
  unavailable until a separately reviewed design can provide typed policy
  ownership, exact prior-state custody, complete verification, and reliable
  compensation. No privileged mutation broker was improvised in this round.

## C26-R2-C01 — FIXED

- **Finding:** `sys.frozen` packaging metadata was treated as sufficient
  installed authority to request UAC and retain an Administrator token.
- **Change:** `src/angerona/core/windows_package_identity.py` adds a bounded,
  process-bound `GetCurrentPackageFullName` / `GetCurrentPackageFamilyName`
  proof and requires the exact independently provisioned package-family and
  publisher-ID pins. It never reads pins from argv, environment variables,
  the registry, PATH resolution, or adjacent mutable files.
- **Entrypoint:** `src/angerona/__main__.py` now refuses frozen execution before
  UAC unless that exact proof passes, and repeats the proof after the elevation
  helper returns. Unpinned, unpackaged, wrong-family, wrong-publisher, and
  unverifiable builds cannot request or retain privileged execution.
- **Fail-closed residual:** no genuine independent Windows publisher/package
  pin exists today, so the checked-in immutable defaults are deliberately
  empty and frozen elevation remains disabled. The future non-exportable
  signer must inject the exact reviewed pins before signing; no fictitious
  identity was invented.
- **Gate results:** both changed product files and the new identity module
  compile PASS; Ruff PASS; focused source-authority plus release regression
  sweep PASS (**54 passed**); helper `self_test()` N/A.

## C26-R2-C02 — FIXED

- **Finding:** the workflow gate relied on substrings and missed bracketed or
  dynamic secret expressions, reusable-workflow secret inheritance, alternate
  failed-dependency conditions, expression-valued continuation, and comments
  masquerading as dependency/artifact/failure proof.
- **Change:** `tools/validate_workflow_policy.py` now parses workflows with a
  duplicate-key-rejecting safe YAML loader, walks expressions structurally,
  forbids every secrets-context form and all job-level reusable workflows in
  the release graph, and requires the exact parsed `needs` edges.
- **Fail-closed proof:** the authority job is constrained to one static-notice
  Bash step ending in an executable `exit 1`; candidate artifact producers and
  the publisher's finalized-artifact download are validated as parsed action
  steps. Downstream status functions, conditional package/authority gates, and
  every `continue-on-error` representation are rejected.
- **Regression:** inert mutations cover dot/bracket/dynamic secrets,
  `secrets: inherit`, pinned job-level reuse, `!cancelled()` / `failure()` /
  `always()`, expression continuation, missing structural publication needs,
  comment-only `exit 1`, artifact-name comment spoofing, and duplicate keys.
- **Gate results:** validator and affected tests compile PASS; Ruff PASS;
  checked-in workflow validator PASS; focused source/release/setup/hash sweep
  PASS (**54 passed**); helper `self_test()` N/A.

## C26-R2-D06 — FIXED

- **Finding:** first-match dispatch let generic path/IP/PID/driver matchers turn
  a Defender/T1562 proposal-only weakness into an executable mutation.
- **Change:** `src/angerona/modules/remediation_actions.py` now produces one
  typed `RemediationDecision`, evaluates dominant Defender safety
  classifications before the executable catalog, and rejects ambiguous
  executable matches instead of resolving them by list order. Target-shaped
  fields and misleading text cannot override the Defender proposal boundary.
- **Regression:** `tests/test_cycle26_round2_response_actions.py` combines a
  Defender/T1562 record with path, IP, PID identity, driver, threat, ransomware,
  and exfil fields while an always-matching mutation is installed; planning and
  host-approved apply remain proposal-only and invoke no mutation. A separate
  multi-match injection proves ambiguous executable matches are rejected.
- **Gate results:** changed product/test Python compile PASS; Ruff PASS; focused
  response, Defender, transaction, receipt, posture, UI, purple-path, and prior
  remediation regressions PASS (**44 passed**); helper `self_test()` N/A.

## C26-R2-D07 — FIXED

- **Finding:** failed compensation was audited as `rolled_back`; an exception
  after a partial multi-step mutation skipped rollback and allowed later batch
  actions to continue against unknown state.
- **Change:** `src/angerona/modules/remediation_actions.py` creates a retained
  transaction before dispatch, records each firewall rule identity before its
  command, compensates failure/timeout/verification exceptions, and emits
  distinct `apply_failed`, `rolled_back`, `rollback_failed`, and
  `recovery_required` outcomes. Only exact `rollback.ok is True` can emit
  `rolled_back`. Failed/unknown records remain operator-visible and open a
  per-batch mutation circuit that blocks later actions.
- **Regression:** the focused hostile test times out the second firewall add,
  fails the second rollback delete, proves both attempted rule identities are
  retained, observes `rollback_failed` then `recovery_required`, and proves the
  following mutation never runs. A proven `changed=False` path emits
  `apply_failed` without unnecessary rollback.
- **Gate results:** changed product/test Python compile PASS; Ruff PASS; focused
  regression sweep PASS (**44 passed**); helper `self_test()` N/A.

## C26-R2-D08 — FIXED

- **Finding:** both legacy quarantine actions authorized, moved, and verified
  mutable pathnames rather than the sensor-detected file object.
- **Change:** `src/angerona/modules/remediation_actions.py` removes both legacy
  quarantine classes from executable `ACTIONS`, makes them explicit inert
  proposal-only entries, and makes even direct `apply()` calls return a
  non-executable failure without touching the source or quarantine directory.
  Operator guidance points to the separately reviewed exact-object broker and
  its sensor-bound identity/digest/rollback requirements; no rushed second path
  broker was introduced.
- **Regression:** both legacy classes are called directly against real files;
  each leaves bytes and paths unchanged, creates no quarantine directory, and
  cannot verify a receipt. Catalog assertions prove host-approved generic apply
  cannot reach them.
- **Gate results:** changed product/test Python compile PASS; Ruff PASS; focused
  regression sweep PASS (**44 passed**); helper `self_test()` N/A.
- **Residual:** pathname-only automatic quarantine remains intentionally
  unavailable here. Exact-object quarantine remains available only through the
  separately tested response broker that already owns pinned object custody.

## C26-R2-D01 — FIXED

- **Finding:** a same-volume hard link inside a selected scan root could alias
  an otherwise unselected file object and pass pathname/volume checks.
- **Change:** `src/angerona/core/security_scan_center.py` now requires an exact
  single-link regular file from the opened descriptor before reading any
  content. Missing or multi-link provenance is an explicit unsafe-scope skip
  and makes the result `limited`; Angerona does not claim a Windows parent-chain
  proof it cannot currently produce.
- **Regression:** the same-volume outside-object hard-link fixture scans zero
  bytes, records one unsafe-scope skip, and never reaches `os.read`.
- **Gate results:** product/test compile PASS; Ruff PASS; focused Scan Center
  and runtime-boundary tests PASS.

## C26-R2-D02 — FIXED

- **Finding:** file-free directory traversal did not consult cancellation,
  deadline, directory-entry, or queued-directory bounds.
- **Change:** traversal now owns bounded entry, visited-directory, and
  discovered/queued-directory accounting and checks cancellation/deadline both
  before and after each iterator step. Empty/wide/deep trees return truthful
  `limited`, `timed_out`, or `cancelled` results with explicit metrics and a
  bounded limit reason.
- **Regression:** hostile empty wide/deep trees, a slow iterator, and
  cancellation during iteration all stop at the expected boundary without
  yielding a regular file.
- **Gate results:** product/test compile PASS; Ruff PASS; focused Scan Center
  and runtime-boundary tests PASS.

## C26-R2-D03 — FIXED

- **Finding:** resilience self-tests temporarily changed the parent process's
  data/diagnostic environment and could divert unrelated live worker threads.
- **Change:** `src/angerona/resilience/_selftest_environment.py` now runs only a
  fixed allowlist of complete resilience self-tests in a separately custodied
  child with an explicit environment copy. Windows descendants are held in a
  kill-on-close Job Object; POSIX descendants use a dedicated process group.
  Root creation and the variables callback are inside final custody, cleanup
  detaches and revalidates the owned directory object, and no parent environment
  value is changed. The five affected call sites are thin wrappers; test-owned
  processes/threads are reaped or joined before the child exits.
- **Regression:** a concurrent ordinary diagnostics writer remains on its
  original live root throughout the child self-test, and a raising variables
  callback still removes its captured temporary root.
- **Gate results:** product/test compile PASS; Ruff PASS; diagnostics, scanner,
  ecosystem, supervisor, and manager `self_test()` PASS; post-run test-owned
  helper audit is empty.

## C26-R2-D04 — FIXED

- **Finding:** `co_filename` alone could forge a trusted health-evidence path
  and unrelated highlighted line.
- **Change:** `src/angerona/core/module_base.py` now requires the exact loaded
  `angerona.*` module globals, a code object declared by that module/function or
  class, matching canonical module/spec/source paths, stable file identity, and
  a bounded SHA-256 source digest. Unproven in-process callsites are explicitly
  `untrusted-external`. `src/angerona/gui/pages.py` re-hashes the descriptor-
  bound source before presenting a line as verified implementation evidence.
- **Regression:** compiled code carrying `module_base.py` as forged filename is
  withheld with no path or line, while a genuine built-in degradation retains
  the exact red-highlighted line.
- **Gate results:** product/test compile PASS; Ruff PASS; health-evidence tests
  PASS.

## C26-R2-D05 — FIXED

- **Finding:** Inspector refresh mixed an operational snapshot with later live
  health/status reads.
- **Change:** BaseModule status transitions share the health snapshot lock.
  Inspector health value, state, note, status, evidence visibility, and button
  text now derive exclusively from one operational snapshot; a snapshot failure
  produces one coherent fail-closed record instead of mixed fallbacks.
- **Regression:** deterministic healthy-to-degraded and degraded-to-healthy
  interleavings both display only the captured snapshot.
- **Gate results:** product/test compile PASS; Ruff PASS; health-evidence tests
  PASS.

### D01–D05 combined gate

- Python compile: **PASS** for all changed product and focused test files.
- Ruff: **PASS**.
- Focused tests: **45 passed, 2 expected platform/link-capability skips**.
- Affected resilience self-tests: **5/5 passed**.
- Test-owned helper-process audit: **zero survivors**.
