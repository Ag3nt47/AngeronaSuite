# Build cleanup and local evidence

The former cleanup script selected databases and logs recursively across the
checkout. Manual use could therefore remove security state and forensic data.
Ignored files are not necessarily disposable.

The replacement removes only root `build` and exact `src/angerona.egg-info` by
default. It leaves runtime databases, logs, diagnostics, remediations, keys,
quarantine, backups, `.tmp`, virtual environments and source Python caches alone.
`dist` requires the explicit `-IncludeDist` option. There is no runtime purge
option.

Preview the plan from the checkout before maintenance:

```powershell
.\cleanup.ps1 -WhatIf
.\cleanup.ps1 -IncludeDist -WhatIf
```

All selected targets are checked before any removal. Links/reparse points,
unexpected file targets, known evidence names/types, excessive trees and access
errors cause refusal. A target is checked again immediately before its removal;
errors are reported rather than hidden.

Run while build/install processes are idle. Preflight and recheck cannot prevent
all concurrent directory-replacement races. Unknown evidence placed inside an
explicitly selected build directory can still be removed; naming checks are not
a complete evidence classifier. I/O failures can leave partially removed build
outputs.

The regression tests copy the reviewed script into newly owned dummy
projects. It covers WhatIf preservation, exact build-target removal, retained
runtime/evidence bytes, explicit dist selection, junction and linked-ancestor
refusal, misplaced evidence and file targets. It runs each available Windows
PowerShell 5.1/PowerShell 7 host separately and explicitly skips missing hosts:

```text
python -m pytest -q tests/test_cleanup_preservation.py
```

PowerShell 7 is discovered on PATH or in its standard installation directory;
`ANGERONA_TEST_PWSH` may name an installed absolute `pwsh.exe` path. Tests use a
host-specific module path only for each child process. They never invoke cleanup
against the real checkout or start runtime security providers. These focused
controls do not establish full-provider or release validation.
