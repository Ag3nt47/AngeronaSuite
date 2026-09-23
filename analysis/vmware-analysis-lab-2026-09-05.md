# VMware Analysis Lab implementation and validation

Status: local implementation and runtime preparation complete; live VMware
acceptance, final review, commit and GitHub publication remain pending.

## Implemented

- Fixed Bandit 1.9.4 and Gitleaks 8.30.1 offline adapters. Arbitrary imported
  repositories remain inert source-review archives and cannot supply commands,
  hooks, executable adapters, dependencies or response authority.
- A reproducible Alpine initramfs prepared from 30 exact HTTPS artifacts.
  The runtime checks download sizes/SHA-256 values, boot component hashes and
  the completed image hash. No Linux archive path is extracted on the host.
- VMware Workstation discovery via Windows registration, valid vendor signatures,
  a new diskless appliance configuration, restricted serial named pipe and a
  guest/host startup handshake. The host verifies the pipe client's VM path and
  process creation time, then applies a Windows Job Object before sending GO.
- Bounded UTF-8 input copies, explicit exclusions, redacted structured findings,
  separate external-analysis receipts and history/export. Findings cannot become
  native sensor evidence or authorize Combat or other protective actions.
- Background preparation/readiness/analysis workers, cancellation, literal result
  rendering and bounded cleanup of interrupted analysis VM copies.

Limits: one active job, two panel workers, 2,000 input files, 1 MiB per file,
16 MiB total input, 20,000 enumerated entries, five-minute job deadline,
768 MiB guest RAM, one VMX process, 2 GiB VMX memory, 4 MiB guest report files,
2 MiB serial output, 1 MiB saved report, 100 reports and two interrupted jobs.
Network sockets use ten-second timeouts; VMware start/stop control calls have
45/20-second bounds. OS/DNS stalls are not claimed as hard real-time guarantees.

## Host evidence

- Windows 11 Home has no installed Windows Sandbox/Hyper-V management backend.
- VMware Workstation **25.0.1.25219725** is installed at `D:\`.
- `D:\vmrun.exe` and `D:\x64\vmware-vmx.exe` have valid Broadcom signatures.
- VMware inventory includes `D:\Ubuntu 64-bit.vmx`; it was not modified, started,
  cloned or used as an analysis target. No existing virtual disk was attached.
- `vmrun list` reported zero running VMs. A disposable appliance startup failed.
  VMware's VIX log explicitly identified the stopped Authorization Service;
  Windows denied the non-administrator session's `Start-Service VMAuthdService`.
- The verified appliance was prepared and staged at
  `%LOCALAPPDATA%\Angerona\SourceData\analysis-lab\appliance`.
  No readiness selfcheck receipt exists and Run remains disabled.

## Validation

- Runtime assembly succeeded: **30 pinned artifacts**, **2,110 guest entries**,
  **24,415,704-byte compressed image**. Image SHA-256:
  `67a58f7c1c930eb95a3c27ac7c5765dfeebd9f0d3630ab9118eee4a916e43532`.
- Combined initial focused source review, UI, report, image, dependency-lock and
  surface-contract tests: **103 passed, 1 expected skip**.
- Follow-up analysis/cleanup/Windows Job Object/UI checks: **45 passed**.
  The native Windows test used an inert Python child, verified memory/process
  limits and proved that closing its Job Object terminated that child.
- Correctness lint passed. Compact Analysis Lab rendering was inspected with
  Segoe UI; prerequisite text and all actions remain visible.
- Full regression suite: **3,133 passed, 17 expected platform skips** in
  **270.31 seconds**. After the final guest serial/device-validation adjustments,
  all **38 focused analysis/UI checks** passed again. **380 source files** compile;
  correctness lint, documentation drift and whitespace checks pass.

These checks do **not** establish real VMware guest isolation, valid analyzer
results or guest cancellation/output-quota behavior. Those remain acceptance
gates. No release publication is claimed for this work in progress.

## Resume after the service is started

Start **VMware Authorization Service** from Windows Services as administrator.
Angerona itself must remain a normal-user session. Then use Analysis Lab's
**Check readiness**, or from this checkout:

```powershell
& ./venv/Scripts/python.exe tools/check_analysis_lab.py --check
```

Complete the real guest checks for both inert fixtures, cancellation, output
bounds, failure cleanup and unchanged original input before enabling/publishing.
Do not clear or bypass the selfcheck gate to satisfy a readiness label. Re-run
the relevant checks after any resulting fixes, update this record, review and
commit the scoped files, then run the guarded GitHub publisher required by
`AGENTS.md`.

## Upstream provenance

- [Alpine release artifacts](https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/)
  and its versioned main/community package indexes supplied guest components.
  `core/analysis_catalog.py` records exact URLs, hashes and package source commits.
- [Bandit 1.9.4 on PyPI](https://pypi.org/project/bandit/1.9.4/) supplied the pinned
  Apache-2.0 wheel. [Bandit CLI documentation](https://bandit.readthedocs.io/en/latest/man/bandit.html)
  supports the fixed configuration and syntax-analysis adapter.
- [Gitleaks 8.30.1](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1)
  supplied the MIT-licensed Linux executable and published checksums.
  [Gitleaks usage](https://github.com/gitleaks/gitleaks#usage) documents directory
  scanning, explicit configuration, redaction and disabled nested decoding.
- [PyCdlib 1.20.0](https://pypi.org/project/pycdlib/1.20.0/) is pinned in the Windows
  dependency set for constructing boot ISOs; license LGPL-2.1-only.
- [Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
  provide the supervisor's process/memory limits and kill-on-close mechanism.

Downloaded artifacts remain local runtime dependencies; their upstream licenses
and source links remain with their catalog/provenance records. The repository
does not redistribute their binaries.
