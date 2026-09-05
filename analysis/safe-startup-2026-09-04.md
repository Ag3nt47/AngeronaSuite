# Separate Windows startup assistant — 2026-09-04

The source launcher and Windows autostart now launch `angerona.startup` in a
separate process. Windows bundle builds include `AngeronaStartup.exe`; the MSIX
entry, upgrade shortcut and post-upgrade launch select it. The dashboard keeps
its independent authority, singleton, module and response gates.

The helper repairs missing helper directories and prepares a clean child
environment, checks free space and an actual write/flush cycle, and probes the
source Python/Qt runtime offscreen with a 30-second deadline. It launches the
dashboard in Chill Mode once and waits at most 120 seconds. Failed startup
retains an explanation instead of entering a restart loop. Tk startup profiles
and caller-selected Tcl/Tk library paths are disabled; frozen library paths
come only from PyInstaller's bundled runtime. A native Windows dialog reports
failure if Tk itself cannot open.

Readiness is a bounded nonce/PID message on IPv4 loopback, sent from a worker
after the visible dashboard has returned to the Qt event loop. Source identity
validation also covers the real Windows venv redirector/interpreter child
relationship. Packaged UAC handoff requires a fresh process running the exact
installed dashboard image. The old readiness file is not used by the helper.

Validation:

- Focused startup, authority, cancellation, autostart, setup, installer, release
  authorization, Linux compatibility and documentation tests: **226 passed**. The sole
  expected skip is Windows symlink creation without the required privilege;
  synthetic reparse rejection tests execute on this host.
- Offline application/dashboard self-check: **26 passed, 0 failed**.
- Real source Python/Qt dependency probe passed in disposable `.tmp` storage.
- Real hidden Tk assistant / offscreen Qt fixture handoff passed; the helper
  exited successfully while the synthetic dashboard continued running. No
  live sensors or response actions were started.
- The source batch uses `Process.WaitForExit()` for the helper only, avoiding
  PowerShell `Start-Process -Wait` waiting for the dashboard descendant too.
  The actual PowerShell wrapper returned exit 0 in approximately 3 seconds,
  before the synthetic dashboard finished.
- PyInstaller produced the separate **11,687,668-byte** helper, SHA-256
  `e3181f7b2ee00d8ee8c52003b58522c38355d96678e665dd932d4e8c588b529c`.
  Archive checks verified bundled Tcl/Tk and no Qt payload. The executable's
  actual interface displayed the expected unsigned-installation refusal and
  exited cleanly after that test window was closed.
- Ruff, compile checks and documentation drift checks passed. Actual build
  testing also caught relative icon paths resolving below the spec directory;
  build icons and release workflow data paths now use absolute source paths.

The helper cannot repair missing protection privileges, native drivers or
recovery evidence. It preserves settings and authenticated journals. Production
MSIX pins/external signing remain unprovisioned; no signed release is claimed.
Older installed updaters with the strict previous evidence allowlist require
an approved installer-authority upgrade for the additional helper executable.
Generated binaries and smoke-test data remain ignored build artifacts; the
source/build integration is published through the guarded GitHub batch flow.
