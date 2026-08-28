# Cycle 24 Round 3 — Final Red-Team Re-audit

Date: 2026-08-27
Mode: authorized, actor-neutral defensive secure-code review using static
inspection and benign local fixtures only

## Outcome

Round 3 found three actionable trust/completeness defects and one documentation
correctness defect after the Round 2 remediation. All four were closed and
retested. No Critical finding was identified, and the converged tree has no
open product-code finding from this cycle.

| ID | Severity | Finding | Final disposition |
| --- | --- | --- | --- |
| R3-01 | High | A publicly downloadable classic migration Setup could still run on a clean host, leaving the original candidate-controlled first-use path available. | **Fixed.** The wrapper is non-public, `PrivilegesRequired=lowest`, proves a complete protected prior authority before UAC, copies no application files, and delegates all mutation to the installed updater. Exact release downloads/publication, provenance subjects, and SBOM subjects exclude it. |
| R3-02 | Medium | Portable "protected custody" checked only three broad identities and skipped owner and file-specific ACL validation, so a custom low-privilege writer could replace an authority file before elevation. | **Fixed.** Both preflight and elevated passes require SYSTEM/Administrators ownership, inspect all explicit/inherited ACEs for every target/authority/evidence/floor file, reject every other write-capable Allow ACE or unresolved identity, and recheck exact non-reparse path metadata. |
| R3-03 | Low | Linux Thunderbolt posture stopped at the first readable controller, allowing an early `secure` domain to mask a later `none` domain. | **Fixed.** Every bounded domain is read stably/no-follow, the least-protective definite state wins, and mixed unreadable/invalid evidence is incomplete unless a definite open state is already proven. |
| R3-04 | Low (documentation) | README/capability guidance still described v1.10.3, a public classic Setup, and an absent Sentinel server after the code contracts changed. | **Fixed.** v1.11.0 documentation now matches signed-MSIX first install, protected upgrade-only ZIP, restricted prior-install migration, supplied reference authority/server, platform counts, privacy boundaries, and explicit deployment residuals. |

An informational presentation note was also closed by regenerating the
synthetic SOAR screenshot without an active selected row. This was not a
security or privacy defect.

## Re-audit evidence

- The migration wrapper cannot create an application directory, copy payload
  files, create an uninstall key, persist a version floor, or launch Full Setup.
  Its unelevated preflight calls the fixed installed authority; `runas` is used
  only for that authority after custody succeeds.
- The public release job downloads exact named artifacts. The restricted
  migration artifact does not match those names and is absent from GitHub
  Release files, build-provenance subjects, and SBOM subjects.
- ACL regressions reject low-privilege, custom/unresolved, file-specific writer,
  bad-owner, reparse, and inspection-race cases; a safe SYSTEM/Administrators
  case remains accepted.
- An authenticated SSH wrong-schema event is rejected after HMAC verification
  but before broker continuity mutation. A later sequence exposes the gap and
  cannot seed a trusted known-source baseline.
- Sentinel shutdown stops admission and drains bounded pre-authentication and
  request workers before the irreversible authority close releases its lease.
- Trusted-time transport verification and appraisal use independent durable
  floor namespaces, so a valid receipt succeeds once per domain and replay
  remains rejected.
- Linux removable absence and Thunderbolt posture require complete stable
  bounded evidence; unknown siblings cannot silently become healthy.
- Live Defense Activity reads only bounded public EventBus summaries/coarse
  module status. Defense Memory cloud fallback is capped to one ranked
  canonical redacted excerpt. Neither surface exposes source code, raw event
  details, credentials, or private model reasoning.

## Validation

- Fresh combined high-risk regression set: **111 passed, 1 expected platform
  skip**.
- Release-boundary focused set: **29 passed** with PowerShell, YAML, XML, JSON,
  contract, Ruff, compile, and diff gates clean.
- Linux peripheral focused set: **24 passed** plus module self-test, Ruff,
  compile, and diff gates clean.
- Final serial suite: **1,675 collected across 229 files; 1,670 passed; 5
  expected host-capability skips; 0 failed**.

## Residual boundaries retained

- The repository does not contain or provision a publisher PFX, Microsoft
  Store identity, enterprise allow policy, protected threshold-root service,
  TPM-backed rollback floor, or independently administered witness. CI fails
  closed when required release inputs are absent.
- A local ACL/signature floor does not defeat an already authorized
  Administrator/SYSTEM principal or whole-host snapshot rollback.
- Personal Sentinel reference code is not a router appliance, routing role,
  firmware attestor, remote command plane, or automatic firewall manager.
- User-mode evidence cannot guarantee truth after kernel, hypervisor, firmware,
  or trusted-authority compromise.
- In-process extension authority, broad legacy PowerShell policy surface, and a
  retained OS process/file lease across path-wide firewall mutation remain
  older architectural hardening opportunities.

No residual is re-labeled as a shipped capability or independent
certification.
