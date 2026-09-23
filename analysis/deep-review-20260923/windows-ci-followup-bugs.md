# Windows CI follow-up — 2026-09-23

The three Windows CI failures were investigated without changing the earlier
pre-publication full-suite snapshot. This follow-up has a **74-pass focused
gate**, plus a separate **1-pass** reproduction rerun beneath a hidden ancestor.
Hosted Windows CI must verify the follow-up commit after publication.

## Findings and fixes

| Finding | Diagnosis | Fix and gate |
|---|---|---|
| Native Job Object integration could not import `win32job` | The Windows Python matrix installed the base package, which does not include the optional Windows dependency. The integration test deliberately requires the real binding. | CI now installs `pywin32==312`, matching the repository's release constraint. The native child-only memory/termination test remains mandatory and passes locally. No skip was added. |
| Public installation-policy test used removed README sentences | The new README retained the signed-MSIX first-install and unelevated-source boundaries but changed their wording. Two old literal assertions were stale. | The test normalizes whitespace and checks the exact versioned MSIX, classic-wrapper first-install refusal, signed installed Protect authority, and unelevated Observe/development scope. The supported-editions assertion remains intact. |
| VMware service fixture returned 1 instead of the expected denied-rename code | A controlled hidden ancestor reproduces the failure: PowerShell `Get-Item` without `-Force` reports an existing hidden directory as missing. Hosted fixtures were beneath AppData, consistent with this mechanism. The original script swallowed the exception into exit 1. | The embedded and standalone programs use `-Force` for their three metadata reads. Explicit reparse rejection, file/directory custody, signature and service-registration checks stay intact. Plain, hidden-directory, hidden-image and reported-reparse cases pass. The exact external-hidden-ancestor reproduction also passes after the change. |

The Python 3.12 job timed out during its 30-second native fixture run; Python
3.13 returned 1. The hidden-path failure is reproduced and fixed independently
of timing. A fresh hosted PowerShell process also initializes inbox modules and
compiles the small `Add-Type` binding, so the **test-only** outer bound is now
90 seconds. No retry, skip or production timeout was added. The copied fixture
program exposes its caught diagnostic and suppresses progress XML; unexpected
exit reports are bounded and redact the fixture prefix. No encoded command is
printed by the explicit timeout/failure report.

This is a hidden-entry usability fix, not permission bypass: `-Force` exposes
metadata for subsequent checks and does not bypass Windows ACLs. The reparse
negative fixture still requires the explicit redirected-directory refusal.
Foreign service paths still require the exact trusted-installation refusal.
Accepted fixture paths must still deny ancestor rename through retained native
handles. All service configuration/start functions remain inert rejecting mocks.

## Validation

- `test_analysis_lab.py`, `test_cycle26_source_authority.py`, and
  `test_vmware_optional_setup.py`: **74 passed in 31.23 seconds**.
- Separate original-style external hidden ancestor: **1 passed in 10.97
  seconds** after the product fix. Before the fix this deterministic fixture
  returned 1 with the hidden item lookup error.
- The native custody variants' measured call times were 4.14 seconds (plain),
  2.18 seconds (hidden directory), 2.08 seconds (hidden image), and 2.19 seconds
  (reported reparse). The real Job Object test passed in 1.92 seconds.
- Whole package compile: **388 files passed**, no syntax errors or mount
  artifacts (`compile-windows-ci-followup.json`). Changed Python files also
  passed their direct compile gate.
- Targeted Ruff, standalone PowerShell parser-only validation, and whitespace
  checks pass. The immutable embedded/standalone script equivalence test passes.
- The earlier full-suite, core self-test and offline selfcheck records are not
  rewritten or represented as new executions by this follow-up.

The remote failures were read from the
[Python 3.12 job](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/35885787265/job/107265448762)
and [Python 3.13 job](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/35885787265/job/107265449013).
Only disposable fixture metadata and the existing owned sleeping child were
used locally. No VMware installer, service change, guest, or Ollama launch was
performed. The coordinating maintainer owns review, commit and publication.
