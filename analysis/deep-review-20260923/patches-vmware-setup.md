# Optional VMware setup — 2026-09-23

Scope: the maintainer's explicit request to offer VMware setup and explain why a
user might install or skip it. This task does not change the Lab's execution,
custody, analyzer catalog, or readiness gates.

## Changes

- `src/angerona/gui/setup_wizard.py`: a Windows-only **Set up Analysis Lab**
  action, with **Skip** as the page's default. The prompt explains that VMware
  runs fixed Python security/secret checks on copied source in an isolated VM;
  it is optional for monitoring, autonomous defense, and Ollama. It describes
  extra download/disk/RAM/virtualization requirements and explicit Lab starts.
  macOS/Linux users are told to skip. The welcome text distinguishes staged
  settings from immediately confirmed installer/service actions.
- `src/angerona/gui/analysis_vmware_setup.py`: optional dialog with official
  portal/instructions, selected-installer launch, a separate service action,
  and access to the existing Lab prepare/check controls. All native actions
  require explicit default-No confirmation. Opening or skipping changes
  nothing. A single bounded worker handles verification/install/configuration;
  independent bounded progress and completion channels avoid losing the final
  result. Busy close is refused until the native installer/UAC finishes or is
  cancelled, preserving file custody. No Qt calls occur on the worker.
- `src/angerona/core/analysis_vmware_setup.py`: original local Workstation
  filename, regular single-link file, 2 GiB bound, valid exact VMware/Broadcom
  signer, and signed Workstation product identity are required. Parent directory
  handles and the selected file's deny-write/delete handle remain held through
  native installer exit; held/path identities are rechecked before handoff.
  SHA-256 records the inspected bytes; it is not represented as an independent
  package trust pin. No unsigned or unrelated signed utility is accepted.
  Inbox PowerShell is held open and receives a sanitized environment. The
  selected path is environment data rather than interpolated script code.
  Native installation uses interactive UAC/license prompts, with no unattended
  arguments or license acceptance. Cancellation/error/restart exit codes do
  not claim Lab readiness.
- Service configuration embeds the reviewed
  `tools/enable_analysis_lab_vmware.ps1` mechanics in a fixed encoded program;
  elevation does not read a mutable helper script. It validates the existing
  installation before UAC, validates and holds the signed authorization-service
  image, rechecks registration, sets `VMAuthdService` to Manual, starts it,
  and verifies Running. The registered service image must reside in the exact
  trusted Workstation directory held by the caller; an outside image fails
  with repair guidance. The elevated script independently holds every ancestor
  directory against rename/replacement and rejects reparse directories through
  verification/start. The standalone helper discards any inherited expected
  directory and resolves fixed HKLM Workstation registration before running the
  same guarded body. It does not start or alter any VM.

## Download behavior and limits

Broadcom's current [download instructions, KB 368734](https://knowledge.broadcom.com/external/article/368734)
require a registered account and export-compliance approval. Setup therefore
opens the official portal and accepts the user's downloaded installer. It does
not collect credentials, bypass account/compliance requirements, claim an
anonymous automatic download, or use an unofficial mirror.

The dialog explicitly states that installing VMware does not establish Lab
readiness and that the current native run is blocked by configuration-file
custody. This warning must only change after the separate native Lab acceptance
work succeeds. Existing guest/configuration protections remain in place.

## Validation

- **34 passed:** `tests/test_vmware_optional_setup.py` and
  `tests/test_full_setup_program.py`.
- Coverage includes invalid signatures and signer confusion, unrelated signed
  products, hard links, changed path identities, native Windows denied writes
  and renames while a fixture installer is held, custody release after exit,
  cancellation/failure/restart results, sanitized path-as-data handoff, fixed
  service program, trust-before-elevation, unsupported platforms, no automatic
  action, default Skip, responsive worker, and completion despite full progress.
  A Windows PowerShell fixture overrides service and signature commands: it
  proves a foreign service directory is rejected before signature inspection,
  and an attempted ancestor rename is denied during inspection. It never calls
  actual service mutation commands. The standalone helper shares the exact
  guarded immutable body, verified by a drift check.
- `py_compile`: all three changed product files and new test file passed.
- `setup_wizard.self_test()`: passed, 20 steps with complete Config mapping.
- Ruff and reviewed-file `git diff --check`: passed.
- Windows PowerShell **parser-only** checks of the inspect, install, and
  configure constants: passed. None of those programs was executed by this
  parser gate.
- Root independently performed a read-only native `verified_installer` probe on
  `D:/VMware-Workstation-Full-25H2u1-25219725.exe`: signature, product identity,
  custody, and digest passed. SHA-256:
  `b592c47756d47c932a3ce2c2b83ad3af1fa23ccc1dd1d3166a51bcc1d2bd58e0`.
  No installer or UAC was launched by that probe.
- Adversary reviewed the three setup files and reported no confirmed bypass.
  Bug hunter owns subsequent aggregate/integration QA.

Native interactive installer execution and configuration through the new GUI
remain untested. No installer, UAC, VM, or service mutation was performed by the
patch agent. No commit/push was performed; root owns reviewed publication.

| Request/finding | Status | Gate result |
| --- | --- | --- |
| Optional VMware setup | IMPLEMENTED | 34 tests, compile, self-test, lint, parser checks pass; native read-only installer identity accepted |
| D23-R1-01 native Lab compatibility | DEFERRED to root's native acceptance | Existing configuration custody retained; no readiness bypass |
