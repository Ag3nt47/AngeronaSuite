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

The pre-publication **3,972 passes / 19 skips** reconciliation is a Windows review
snapshot. New native regressions and later CI checks are not silently added to
that count. The VMware Lab compatibility blocker and elevated-to-medium Ollama
native acceptance gap remain as described in [native acceptance](native-acceptance.md).
