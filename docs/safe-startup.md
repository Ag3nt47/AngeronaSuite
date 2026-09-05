# Windows Safe Startup

Use `start-angerona.bat` in a source checkout. After its existing trusted Python
setup and source checks, it opens the separate **Angerona Safe Startup** window.
The release build includes **AngeronaStartup.exe**, and the Windows package,
desktop shortcut and Windows sign-in startup use that helper. `--setup` opens
the setup page after the dashboard starts. Direct dashboard execution remains
available for diagnostics, with its existing authority and singleton checks.

The helper uses Tk, independently of the dashboard's Qt runtime. It:

1. Verifies the installation location and existing Windows source/MSIX authority.
2. Creates missing helper log/temp directories, checks at least 128 MB of free
   space, and performs a temporary write/flush/delete probe.
3. Checks source Python 3.12 x64, reviewed pip and required Python/Qt imports in
   an isolated process with a 30-second deadline. The probe runs Qt offscreen
   and does not start Angerona sensors.
4. Launches one dashboard in Chill Mode using a clean environment. A helper
   lease prevents concurrent helpers; the dashboard retains its own singleton.
5. Waits up to 120 seconds for a per-launch nonce and live process confirmation.
   The dashboard sends readiness from a worker only after its visible window
   has yielded back to the Qt event loop. The helper then closes automatically.

The readiness receipt is a small, one-way message on an ephemeral IPv4 loopback
socket. It accepts no commands or file paths and grants no security authority.
Source launches require the launched PID or its fresh Windows venv interpreter
child using the helper's same CPython image. Packaged UAC handoff also
requires a fresh live process running the installed `Angerona.exe` image.
Old `dashboard-ready.signal` files cannot satisfy this handshake.

## Repairs and failures

Automatic repairs are limited to missing startup directories and clean launch
environment values. Source first-run dependency installation continues through
the existing hash-locked batch setup. Runtime replacement remains available
through `Repair-Angerona-Python.bat`, which preserves the previous environment
and asks before replacing it. The startup assistant never resets configuration,
credentials, response approvals, singleton records, evidence or journals; it
does not change privileges, install drivers, or invent recovery evidence.

A failed dependency probe or early application exit leaves the helper open with
an explanation. A timeout leaves the existing dashboard process running and
does not retry. Closing the assistant also leaves a launched dashboard running;
an active disposable dependency probe is cancelled and reaped before the helper
process exits. Check the tray before manually retrying a failed launch.

Source helper logs are under `%LOCALAPPDATA%\Angerona\SourceData\logs`:

- `startup-preflight.log`: isolated source dependency/Qt check.
- `startup-dashboard.log`: dashboard stdout/stderr from the helper launch.
- The immediately preceding copy of each log uses `.previous.log`.

Packaged helper logs use `%LOCALAPPDATA%\Angerona\Startup\logs`. The protected
dashboard keeps its existing separate runtime data and crash logs. The helper
rotates its launch logs once per attempt; it does not continuously cap the
dashboard's output after the helper exits.

## Build and deployment limits

`build.bat` builds both the dashboard and `dist\Angerona\AngeronaStartup.exe`
with the existing environment's PyInstaller. The Windows release workflow also
builds the helper and includes it in candidate signature, catalog and payload
verification. Existing installations without a helper can pass prior custody
checks; when a helper is present its custody and signature are checked.

Production MSIX identity pins and external signing authority remain required.
An unsigned local helper displays the existing installation-authority refusal;
it does not bypass that requirement. Older installed upgrade scripts with the
old strict evidence allowlist need an approved installer-authority upgrade to
accept a release containing the new helper. Source launch works through the
normal unelevated batch path.

Dashboard readiness confirms a visible, responding window. It does not certify
all protection modules or guarantee future stability; the dashboard continues
to show genuine missing prerequisites and degraded modules.
