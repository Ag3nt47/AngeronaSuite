# Continuation validation — 2026-09-23

The first complete offline run executed **4,125 tests: 4,103 passed, 19 skipped,
and 3 failed**, in **705.51 seconds**. All three failures were stale VMware
expectations in the custody regression tests. After adapting those tests to the
current QEMU job runner, the complete affected Lab gate passed **188 tests**.
The skip audit also found and corrected one hard-link fixture that had skipped
because its destination already existed; its entire regression file then
passed **6 tests**, including the actual hard-link rejection check.

This reconciles the original test population to **4,107 passed and 18 skipped**.
It is a complete baseline plus focused correction checks, **not a second full
suite execution**. The shared checkout continued changing during integration;
native Lab and Ollama acceptance are recorded separately by their owners.
The final affected Lab gate then passed **192 tests**, including three new
unsupported-architecture setup cases and one new visible-panel refresh case.
The later Ollama selection passed **146 tests**, including two additional real
Windows token-only cases. These later focused selections overlap earlier runs;
their totals are reported separately rather than presented as a new full run.

## Checks performed

| Gate | Result |
|---|---|
| First full offline pytest run | 4,103 passed, 19 skipped, 3 stale-contract failures; 705.51 seconds |
| Corrected custody regression file | 13 passed; 7.33 seconds |
| Initial corrected Analysis Lab, QEMU, setup UI, readiness retirement, optional VMware, and custody gate | 188 passed; 23.64 seconds |
| Final same nine-file Lab gate, including architecture and visible-panel refresh regressions | 192 passed; 24.29 seconds |
| Focused Lab and optional emulator setup UI checks after the panel fix | 8 passed; 2.78 seconds |
| Complete QEMU setup file after the early architecture guard (integration owner) | 33 passed; 7.44 seconds |
| Final Ollama lifecycle/token selection, including two native token-only cases | 146 passed; 7.36 seconds |
| Corrected journal hard-link fixture and its complete remediation file | 6 passed; 2.08 seconds |
| Earlier QEMU supervisor/setup/runtime gate | 105 passed; 9.87 seconds |
| Fresh bootstrap ordering and native read-only directory-custody checks after the product fix | 2 passed; 8.59 seconds |
| `python -m compileall -q src/angerona tools` | Passed; 393 package Python files and 56 tool Python files at execution time |
| Focused QEMU implementation/tests, corrected custody/journal tests, and changed Lab UI/test Ruff gates | Passed |

Pytest used the original workspace's Python 3.12 virtual environment, with
`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` and `QT_QPA_PLATFORM=offscreen`. The repository
conftest retained its disposable per-test data roots and disabled automatic
Ollama startup. No vendor installer, elevation request, or actual VM was started
by these QA runs. Existing native tests used only their owned inert child
processes or read-only PowerShell boundary checks.

Local raw evidence is retained under `.tmp/continuation-20260923/`:
`pytest-full-offline.log`, `pytest-full-offline.xml`, `pytest-final-lab.log`, and
`pytest-final-lab.xml`, plus `pytest-final-lab-after-ui.xml` for the final
192-test gate. These ignored local records are not GitHub artifacts.

## Failure analysis and correction

| Original failing test | Diagnosis | Preserved contract in the correction |
|---|---|---|
| `test_supervisor_rejects_failed_custody_before_start_go_or_report[3]` | The fixture expected the old multi-byte `GO:<uuid>` message after the common guest protocol moved to one control byte. | Expects `b'G'`; still proves that failed custody prevents startup, authorization, or report acceptance at the appropriate boundary, and that the owned job stops. |
| `test_job_runner_pins_generated_profile_until_report_is_parsed` | The job runner now creates a sealed initrd and starts fixed-argument QEMU; the test still patched VMware and expected an `analysis.vmx` file. | The renamed initrd test explicitly mocks QEMU installation custody and supervision. Windows denies kernel/initrd mutation and deletion during supervision and report parsing, and the generated job is removed after successful parsing. |
| `test_job_runner_rejects_profile_swapped_between_generation_and_sealing` | The replacement hook targeted a VMX file that the QEMU runner no longer writes. | The renamed initrd test corrupts `initrd.cpio.gz` immediately after generation. The runner rejects it before supervision, and no report can be accepted. |

The two old runner fixtures reached read-only validation of the installed QEMU
file set and stopped there; neither launched the emulator. Their replacement
fixtures always substitute the installation context, so subsequent tests never
consult the operator's protected runtime. Standalone VMware configuration-custody
tests remain active.

## Bootstrap ordering finding

The initial setup helper assigned `PSModulePath` using `Join-Path` on the
right-hand side. That cmdlet could resolve before the trusted module path was
installed. Both product bootstrap assignments now use pure .NET string
concatenation first. A fresh native read-only probe and the bounded privileged
copy-script contract passed after the change. The Ollama acceptance owner also
applied the correction to its private bootstrap payload.

## Final setup and visible-panel corrections

The integration owner added an early Windows architecture check so unsupported
ARM or 32-bit hosts fail before downloading the 197 MiB optional installer.
Three new architecture fixtures pass in the final gate.

Closing the emulator setup dialog previously cleared the panel's ready state
without refreshing the already visible panel. Choosing Skip could leave the
old ready label displayed while Run remained disabled. The panel now starts
its existing background readiness load immediately after the dialog closes.
The new regression uses a fake Skip dialog and mocked readiness: it observes
the checking label, a responsive GUI during the blocked worker, and restored
Run/Setup buttons after readiness completes, with no native setup calls.

## Skip audit

The **18 remaining skips** are fourteen symlink/directory-link checks whose
required privileges are unavailable to this non-administrator Windows account,
plus four explicit POSIX or native macOS/Linux shell checks.

The original additional skip was incorrectly described as unsupported hard
links: `test_combat_hard_link_journal_is_rejected_without_append` received
`WinError 183` because reconciliation had already created its disposable journal
destination. The corrected fixture verifies that the initialized journal is the
exact expected temporary path, empty, regular, unaliased, and not a reparse point
before removing it. It then creates the actual hard link, checks its link count,
and proves that attempting a journal append fails without changing either
sentinel view. Only genuine permission/unsupported-operation errors can now
skip this fixture; an existing destination or another unexpected error fails.
The whole six-test remediation file passes on this host.
