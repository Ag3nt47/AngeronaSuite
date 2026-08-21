# Cycle 19 — Windows Bootstrap and Credential Boundary Remediation

Date: 2026-08-21  
Scope: compound R4-01/R4-04/R4-02 chain assigned to the Python bootstrap,
trusted system-path resolution, supervised/interactive child environments, and
first local fleet credential migration.

## Outcome

The exploitable Windows bootstrap chain is closed. Both source launchers derive
Windows/System32 from cmd.exe's process-owned `__APPDIR__`, rebuild trusted
system/registry paths, and clear inherited code-loading, proxy, credential, and
resilience controls before requesting elevation. The elevated process no longer
accepts inherited Windows/Python/proxy/Angerona control values, ACL verification
resolves inbox PowerShell from `GetSystemDirectoryW`, and the `--setup` launch
argument survives the sanitized source/frozen relaunch. Sidecars, Black Box, and
the Upgrade Console shell now receive explicit allowlisted environments without
provider, connector, fleet, proxy, or watchdog credentials.

The signed Go watchdog's legitimate per-launch heartbeat credential is preserved
without reopening the general environment channel. It is restored to the core
only after all of the following pass: exact 32-byte token, canonical heartbeat
path, fresh matching HMAC proof, heartbeat PID equal to the real parent PID,
parent image equal to the expected watchdog binary, and valid Authenticode. The
token is not copied to generic sidecar environments.

First fleet migration now reads only the OS-protected credential map. The app
purges any inherited `ANGERONA_FLEET_SERVICE_KEY`; the compatibility function
rejects an unprotected argument when no protected legacy value exists; and the
Settings enable path checks/generates protected material directly instead of
letting an inherited value suppress safe generation.

## Finding disposition

### R4-01 — privileged inherited environment — **FIXED**

- `src/angerona/core/privilege.py`: WinAPI Windows/System32/known-folder
  resolution, minimal bootstrap environment, safe Windows argument quoting,
  fixed source working directory, checked `ShellExecuteW` result, and narrow
  signed-watchdog context attestation.
- `src/angerona/core/data_paths.py`: ACL verification uses the trusted absolute
  PowerShell path and a clean one-purpose environment.
- `src/angerona/__main__.py`: existing `--setup` handling remains intact and is
  covered across the sanitized relaunch.
- `start-angerona.bat`: cmd-owned system trust root is installed before the
  first external command or UAC; all inbox utilities use pinned absolute paths;
  path/control/secret inputs are scrubbed; Program Files and Local AppData are
  reconstructed from trusted absolute `reg.exe` queries. A non-mutating exact
  `--bootstrap-selftest` hook exercises this boundary without elevation.
- `start-angerona-guarded.bat`: performs an initial scrub before redirecting and
  delegates the exact self-test literal safely to the canonical launcher.

### R4-04 — credential-bearing child environments

- **Assigned child-process propagation: FIXED.**
- `src/angerona/resilience/supervisor.py`: every supervised child receives the
  allowlisted environment.
- `src/angerona/app.py`: Black Box receives the same secret-free environment.
- `src/angerona/gui/upgrade_console.py`: the operator PowerShell uses trusted
  absolute PowerShell plus the secret-free environment.
- **Residual architectural work:** protected values are still published for
  in-process legacy consumers. Replacing that delivery mechanism with a
  just-in-time broker is required before the broad original R4-04 wording can be
  marked completely resolved; it was not weakened or silently relabeled here.

### R4-02 — inherited fleet authority

- **FIXED for all production migration paths.**
- `src/angerona/app.py`: environment fleet material is purged and never passed
  into credential migration.
- `src/angerona/core/fleet_credentials.py`: unprotected compatibility arguments
  cannot seed durable authority; existing/protected credentials retain their
  precedence and verified atomic migration behavior.
- `src/angerona/gui/pages.py`: fleet enablement examines protected storage and
  generates protected random material even when the launch environment is
  hostile.

## Regression evidence

New gates: `tests/test_cycle19_boundary_remediation.py` and
`tests/test_cycle19_launcher_boundary.py`

- hostile `SystemRoot`, `PATH`, `PYTHONPATH`, proxy, provider, fleet, resilience,
  and core-command values are absent from the UAC child;
- `--setup` remains on the safely quoted relaunch command;
- ACL verification uses only the trusted PowerShell executable and target path;
- provider/fleet/watchdog credentials do not reach supervised sidecars;
- a genuine signed-parent watchdog context is retained only in the core;
- an unprotected fleet compatibility argument performs no protected write.
- both launchers pin `__APPDIR__` before redirect/elevation and contain no
  inherited `%SystemRoot%\System32` executable resolution;
- real `cmd.exe` hostile-environment probes pass for both launchers without UAC
  or host mutation.

Gate results at this checkpoint:

| Gate | Result |
|---|---:|
| Changed-file `py_compile` | PASS |
| Ruff on changed source/tests | PASS |
| Focused boundary/fleet/regression suite | **59 passed** |
| Related resilience/security/performance/setup suite | **53 passed** |
| Launcher static + live hostile-environment gates | PASS (included above) |
| Supervisor `self_test()` | PASS |
| Full repository suite | **809 passed, 2 skipped, 0 failed** |
