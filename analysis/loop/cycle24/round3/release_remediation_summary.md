# Cycle 24 Round 3 — Release Boundary Remediation

Date: 2026-08-27

## Result

The Windows release boundary now has two distinct supported paths and no
repository-supported classic clean-install path:

- A signed full-trust MSIX is the only Windows public first-install artifact.
- The threshold-authorized portable ZIP is public but upgrade-only. It can be
  applied only by an already installed, protected Angerona upgrade authority.
- Classic Inno Setup is a non-public legacy-migration wrapper. It cannot copy
  application files, create an application directory, write an uninstall key,
  or act as a trust bootstrap.
- A future enterprise clean-install package must be a separately governed
  artifact under an external allow/deployment policy. It is not produced by
  this workflow and cannot be the public or migration artifact under the v2
  Windows installation contract.

## Remediation applied

### Pre-elevation custody and trusted mutation delegation

The migration wrapper now runs with `PrivilegesRequired=lowest`. Before any
UAC request it authenticates its own publisher and invokes the installed
`Install-Angerona-Release.ps1 -CustodyPreflightOnly` authority from the fixed
64-bit Program Files location. Only after that preflight succeeds does the
wrapper use the `runas` verb to launch that same installed authority. Inno
Setup itself never copies an application file.

The portable batch entry point follows the same sequence: protected custody
preflight first, then a waited elevation handoff whose exit code is propagated.
It no longer describes classic Setup as an enterprise clean-install option.

The elevated installed authority repeats the complete custody check immediately
before creating staging state or changing a destination. This prevents a
successful unelevated preflight from being reused as stale authority after the
privilege boundary.

### Complete protected-file custody

The installed target directory and every required authority/evidence file are
checked individually. The inventory includes both launchers, the PowerShell and
native verifiers, both executables, the SBOM, publisher pin, payload manifest
and catalog, build provenance, threshold authorization, trust roots, and outer
release-file manifest. The monotonic `release-floor.json` receives the same
check whenever present; an older authorized installation without that file is
still anchored from its installed signed authorization before the first
upgrade writes the floor.

For each path, validation fails closed unless:

- the owner resolves and is exactly SYSTEM or BUILTIN\Administrators;
- every explicit and inherited access rule resolves to a Windows identity;
- every write-capable Allow ACE belongs exactly to SYSTEM or Administrators;
- the path has the expected file/directory type and exact full name;
- no link or reparse point is present; and
- path attributes, length, and last-write metadata remain stable across ACL
  inspection.

Custom/unresolvable identities, low-privilege writers, file-specific write
rights, bad owners, reparse aliases, and inspection-time path changes are
rejected before elevation and again before mutation. Publisher signatures and
the protected publisher pin are also verified in both custody passes.

### Exact publication, attestation, and SBOM boundary

The publish job no longer downloads artifacts through `angerona-*` pattern
matching or merged wildcard selection. It downloads exactly three named gated
artifacts: Windows public assets, Linux x86-64, and macOS arm64. POSIX upload
paths now name the exact archive extension and checksum instead of using
`${{ matrix.artifact }}.*`.

GitHub Release publication, build-provenance subjects, and SBOM-attestation
subjects remain explicit. The restricted migration Setup and its checksum are
absent from all three. They are stored only in the separately named
`restricted-windows-migration-setup-do-not-publish` Actions artifact with a
one-day retention period.

The canonical `angerona.windows-install-contract/v2` now records the exact two
public Windows artifact roles, protected-ZIP prerequisites and rollback floor,
pre-elevation migration custody, installed-authority mutation delegation, and
the requirement that any enterprise clean-install artifact be separate and
externally governed.

## Validation

- Focused release pytest: **29 passed** across setup/workflow custody, MSIX
  manifest and contract, portable anti-rollback, and threshold release
  authorization.
- Windows ACL cases: safe directory/file accepted; low-privilege, unresolved
  custom group, file-specific writer, and bad owner rejected.
- Inspection-race regression: metadata mutation during ACL inspection rejected.
- PowerShell parser: both repository release scripts and every `pwsh` block in
  the release workflow parsed successfully.
- YAML/XML/JSON: release workflow, MSIX manifest template, and canonical Windows
  installation contract parsed successfully.
- Contract validator: PASS for the v2 canonical installation contract.
- Ruff: PASS for all release Python/tool/test files in scope.
- `py_compile`: PASS for all release Python/tool/test files in scope.
- `git diff --check`: PASS for all release-boundary files; only line-ending
  notices were emitted.

## Files changed in this remediation pass

- `.github/workflows/release.yml`
- `Install-Angerona-Release.bat`
- `Install-Angerona-Release.ps1`
- `installer/Angerona.iss`
- `installer/windows-install-contract.json`
- `tools/build_msix_package.py`
- `tests/test_release_setup.py`
- `tests/test_msix_package.py`
- `analysis/loop/cycle24/round3/release_remediation_summary.md`

## Residual boundaries

- No publisher PFX, protected MSIX package identity, Store reservation, SDK
  signing environment, or enterprise allow policy is present in the repository.
  CI fails closed until operators provision those external controls; this pass
  does not claim that a public MSIX has been deployed.
- The local host did not possess the pinned Inno compiler or release signing
  keys, so a signed migration executable was not built or executed here. Its
  PowerShell delegates and workflow were parser-tested and its contract is
  regression-gated; CI performs the pinned-compiler and signature checks.
- A local rollback floor cannot resist an attacker who already controls an
  approved administrator/SYSTEM identity or can roll back the entire host.
  TPM-backed/external monotonic authority remains the production answer to that
  threat.
- The public ZIP is not a clean-install alternative to MSIX. It deliberately
  fails on a host without the complete prior protected authority and evidence
  set.
