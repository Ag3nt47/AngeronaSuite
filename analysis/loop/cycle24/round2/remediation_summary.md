# Cycle 24 Round 2 — Remediation Summary

Date: 2026-08-26
Scope: defensive release trust, authenticated sensor ingestion, trusted-time
composition, Sentinel lifecycle safety, and removable-device completeness

## Outcome

All seven Round 2 code findings were remediated and covered by focused
regressions. Three controls still depend on honest deployment boundaries that
repository code cannot create by itself: Windows package trust must be backed
by a provisioned signing identity and deployment policy, release roots/policy
must remain in protected environments, and whole-host rollback resistance
requires a TPM or independent witness rather than only a local ACL-protected
floor.

| Finding | Remediation status | Defensive result |
|---|---|---|
| R2-01 | Fixed in repository contract; deployment validation required | The supported public first-install artifact is now a signed full-trust x64 MSIX. Windows validates its block map and publisher signature before activation. Classic Inno Setup fails compilation unless explicitly built as migration/enterprise-only. |
| R2-02 | Fixed in code; protected root provisioning required | Signer responses no longer carry public keys. Each response must match a separately supplied enrolled root, and finalization requires the canonical versioned 2-of-2 root policy at an exact protected SHA-256 digest. |
| R2-03 | Fixed in code; whole-host rollback remains external | The installed native verifier validates threshold authorization plus protected numeric version and sequence floors before any portable target mutation. Downgrade and root-replacement fixtures fail closed. |
| R2-04 | Fixed in code; broker custody remains external | SSH live evidence is accepted only through a `SensorProvenanceBroker` envelope with a fixed producer, schema, provider/channel contract, and loss-free sequence continuity. Unprovenanced text cannot advance the trusted known-source baseline. |
| R2-05 | Fixed | Transport verification and trusted-time appraisal now use deterministic, separate floor namespaces, so one fresh receipt advances once in each declared domain while replay and challenge substitution remain rejected. |
| R2-06 | Fixed | `PersonalSentinelAuthority.close()` is irreversible; processing and state I/O require a held lease, and shutdown serializes worker completion before lease release. |
| R2-07 | Fixed | Linux removable posture reports complete absence only when every enumerated flag is a stable, no-follow, valid zero. Mixed, empty, disappearing, invalid, or unreadable inventories remain incomplete. |

## Release trust changes

- Added a parameterized MSIX manifest and deterministic builder with an exact
  externally configured package identity, four-part version, full-trust entry
  point, signed x64 artifact, and pinned Windows SDK toolchain.
- Added certificate, manifest, archive-structure, block-map, signature, version,
  and publication gates to the release workflow. The workflow does not claim a
  Microsoft Store deployment; chain trust and sideload policy remain explicit
  operator/deployment responsibilities.
- Renamed and gated the classic installer as a migration/enterprise path. It is
  no longer represented as the public first-install trust bootstrap.
- Split threshold response creation from finalization. The finalizer receives
  protected enrolled roots and a protected policy digest; a response artifact
  contains its label, statement digest, and signature, never an authority root.
- Added an installed portable verifier that reconstructs and validates release
  authorization, enforces the enrolled root set, and atomically advances the
  protected version/sequence floor before the installer writes the target.

## Focused verification

- Release remediation: **20 passed**.
- Core remediation: **88 passed, 1 skipped**.
- Ruff: clean for changed Python files.
- Python compileall: clean for changed modules, tools, and tests.
- Release workflow YAML and MSIX XML: parsed successfully.
- PowerShell syntax: all 13 embedded release-workflow blocks plus both
  repository release scripts parsed successfully.
- `git diff --check`: clean apart from informational line-ending notices.

The independent serial suite and fresh Round 3 audit are recorded separately;
this document does not substitute focused proof for deployment validation on a
clean Windows VM using the protected signing environments.

## Honest residual boundaries

- The repository cannot prove that the GitHub protected environments, enrolled
  Ed25519 roots, publisher PFX, certificate chain, or enterprise/App Installer
  policy have been provisioned correctly. Release jobs fail closed when their
  required configuration is absent.
- The portable floor is protected by Windows ACLs and authenticated contents,
  but a privileged whole-host rollback can restore it with the filesystem.
  TPM-backed or independently witnessed monotonic state is required for that
  attacker model.
- Broker keys, response high-water state, and trusted-time floors must be kept
  outside a restorable monitored-host snapshot when snapshot rollback is in
  scope.
- Linux sysfs evidence remains local observe-only evidence; it cannot prove
  truth after kernel compromise.
