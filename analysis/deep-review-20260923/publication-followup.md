# Publication and native CI follow-up — 2026-09-23

The guarded publisher verified commit `a5d9905b6bca9ebe12806535a3271249aaf9b0ab`
on public `main` and `codex/enterprise-cycle7`, with a clean worktree and all five
README images byte-identical to their public copies. The original 21 pending
Lab files were preserved separately before fast-forward integration.

## First native CI execution

[CI run 35885787265](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/35885787265)
ran the new installer matrix on actual hosted operating systems:

- **Ubuntu 24.04 passed:** staged installation, pinned dependencies, `pip check`,
  actual offscreen QApplication rendering, XCB plugin loading, platform discovery
  and executable/syntactically valid installed entry points.
- **Both Mac architectures failed:** an unquoted literal space in the Darwin
  default runtime assignment treated `Support/Angerona/runtime` as a command.
  Windows shell syntax checks did not execute this branch.
- **Mac/Linux platform fixtures failed:** the fake `uname` returned `x86_64`
  for both `-s` and `-m`, preventing the intended failed-download preservation
  test from reaching its deliberate download failure.
- Public README integrity, the Windows platform contract and dependency audit
  passed. Full Windows Python matrix results are separate from the local review
  reconciliation.

The [security run](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/35885787312)
reported one secret-scan false positive. The fixed Qt dependency tuple contains
public shared-library names: the generic rule interpreted the name following
`libxcb-keysyms.so.1` as a credential. The exact historical commit/file/rule/line
fingerprint is documented in `.gitleaksignore`; no path-wide, rule-wide or future
commit exemption was added. No credential occurs in that tuple.

## Correction and validation

The Mac installer and uninstaller quote their complete default runtime paths.
The native fixture distinguishes OS and architecture queries. Behavioral shell
regressions exercise ARM and Intel Darwin defaults containing spaces, rather
than relying on syntax checks alone. The targeted installer file passed
**28 tests with 1 expected platform skip**, including six actual-shell Mac
install/uninstall scenarios under Git Bash. Shell syntax and whitespace checks
also passed. Repeat native CI acceptance remains separate: a passing offline
test does not imply a passing native installer.

## Corrected installer CI

At `5efa0d188b032f20646827a19519aea50141f9cd`,
[CI run 35886949539](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/35886949539)
passed **all three native source installers: Intel macOS, Apple Silicon macOS
and Ubuntu**, including
dependency consistency, actual offscreen QApplication rendering, platform
discovery and installed entry points. The Mac/Linux platform-contract jobs also
passed, including the corrected failed-download fixture. Intel built pinned
cryptography 50.0.0 from source and passed its runtime/rendering checks.
This proves automated source setup
and rendering, not every visible desktop interaction or full packaged releases.

The [corrected security run](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/35886949469)
passed secret scanning, CodeQL and Scorecard. The dependency audit and public README
integrity checks also passed.

The initial hosted Windows Python 3.12/3.13 runs each reported **3,980 passes,
8 skips and 3 failures**: absent `win32job` in the base-only CI environment,
another obsolete literal README phrase, and a PowerShell directory-custody
fixture failure (a timeout on one runner, early failure on another). These are
recorded separately from the local Windows snapshot; their correction must
retain the actual custody assertions and service-mutation prohibitions.

The PowerShell failure was reproduced locally by marking one owned ancestor
hidden: `Get-Item` without `-Force` could not inspect it. Both the embedded setup
program and standalone service helper now use `-Force` for their three file/
directory inspections. This permits inspection of hidden entries; explicit
reparse rejection, retained handles, vendor checks and registration checks are
unchanged. Tests cover hidden ancestors/images and refusal of redirected paths.
The test-only diagnostic copy exposes bounded failure details and suppresses
PowerShell progress output. No service change is allowed by those fixtures.

The Windows test matrix installs the already release-pinned `pywin32==312`, so
the real Job Object integration test remains mandatory. The README assertion
checks the current signed-MSIX installation and source/Protect boundaries.

The corrected local gate passed **74 tests** across the Analysis Lab, source
authority and optional VMware setup files, plus a separate passing rerun under
an external hidden ancestor. See the [Windows follow-up report](windows-ci-followup-bugs.md).
Compile, lint, PowerShell parsing and
whitespace checks passed. The native custody fixture has a bounded 90-second
cold-start budget for PowerShell module initialization and C# compilation;
production deadlines were unchanged. The repeated hosted Windows matrix is a
separate acceptance check, not part of the earlier reconciliation count.

The pre-publication **3,972 passes / 19 skips** reconciliation is a Windows review
snapshot. New native regressions and later CI checks are not silently added to
that count. The VMware Lab compatibility blocker and elevated-to-medium Ollama
native acceptance gap remain as described in [native acceptance](native-acceptance.md).
