# Windows Safe Startup

The current source supervisor has ordered recovery alternatives and an
independent recovery interface. Read [Safe Startup recovery](safe-startup-recovery.md)
for the automatic/GitHub controls, persistent diagnostics, preserved source
edits, transaction holds and storage budgets. The helper checks and signed
installed boundary below still apply; a helper's failed attempt is no longer
the end of the source supervisor's recovery round.

Use `start-angerona.bat` in a source checkout. Its trusted supervisor verifies
the runtime and source checks, then opens **Angerona Safe Startup**.
The release build includes **AngeronaStartup.exe**, and the Windows package,
desktop shortcut and Windows sign-in startup use that helper. `--setup` opens
the setup page after the dashboard starts. Direct dashboard execution remains
available for diagnostics, with its existing authority and singleton checks.

The helper uses Tk, independently of the dashboard's Qt runtime. It:

1. Verifies the installation location and existing Windows source/MSIX authority.
2. Creates missing helper directories, independently requires 128 MB free on
   the canonical data drive, and verifies flushed bytes by reading them back.
   Temporary work uses fresh private scratch. If the usual temporary location
   is unusable, checked scratch on the installation drive can be selected;
   persistent settings and evidence stay in their canonical location.
3. Checks source Python 3.12 x64, exact reviewed dependency versions, dependency
   consistency and native offscreen Qt in separate processes sharing the
   original 30-second probe deadline. These probes do not start sensors.
4. Launches one dashboard in Chill Mode using a clean environment. A helper
   lease prevents concurrent helpers; the dashboard retains its own singleton.
5. Waits up to 120 seconds for a per-launch nonce and live process confirmation.
   The dashboard sends readiness from a worker only after its visible window
   has yielded back to the Qt event loop. The helper then closes automatically.

New package builds prepare an independent `AngeronaSafeStart.exe` MSIX entry
outside that Python/Tk helper. Its OS .NET/Windows Forms interface can display
recovery even if the frozen helper cannot import or execute. Exact helper pins,
native leases and the unchanged signed release boundary still apply; signing
and accepted release deployment are not provisioned by a source build. See
[the packaged entry contract](safe-startup-recovery.md#independent-entry-for-signed-package-builds).

The readiness receipt is a small, one-way message on an ephemeral IPv4 loopback
socket. It accepts no commands or file paths and grants no security authority.
Source launches require the launched PID or its fresh Windows venv interpreter
child using the helper's same CPython image. Packaged UAC handoff also
requires a fresh live process running the installed `Angerona.exe` image.
Old `dashboard-ready.signal` files cannot satisfy this handshake.

## Repairs and failures

For a source checkout, the supervisor automatically invokes the Angerona repair
tool once when a check positively identifies a missing/wrong runtime, a reviewed
dependency failure, or a recognized Tk/Qt runtime failure. The helper exits
before repair begins. Repair builds a candidate with PSF-signed CPython 3.12
x64, hash-locked dependencies and reviewed local packages. It preserves the
previous environment, refreshes launchers at their final path, and independently
checks ABI, dependencies, Tk and native Qt before accepting the replacement.
The supervisor then repeats the startup checks and can continue through its
other eligible fixed strategies. After a bounded round is exhausted, the
independent recovery UI offers diagnostics, Retry and Close. It does not claim
the protection engine is active. The manual `Repair-Angerona-Python.bat` entry
point retains its confirmation.

Repair holds both checkout and canonical helper locks, so direct helper,
check-only and launcher startup cannot overlap replacement. A flushed private
transaction records directory identities before either rename. A later launch
detects interrupted work before executing the environment; repair restores the
identified original environment when the transaction is consistent. Corrupt,
missing or ambiguous custody evidence stops recovery and preserves the files.

The fixed repair tools have a 900-second overall command budget, bounded child
commands, and owned-process cleanup. They do not use Ollama, Llama or AI-generated
commands. Successful retry always starts in Chill; automatic repair cannot
enable AI. Settings, credentials, approvals, evidence and journals are preserved.
Source/MSIX trust failures, insufficient persistent storage, busy environments,
cancellation and unknown failures require their specific corrective action.
Packaged installations retain their signed installer repair boundary.

A nonrepairable failure or early dashboard exit leaves the helper open with
an explanation. A dashboard timeout leaves the existing process running and
does not retry. Closing the assistant also leaves a launched dashboard running;
an active disposable dependency probe is cancelled and reaped before the helper
process exits. Check the tray before manually retrying a failed launch.

Source helper logs are under `%LOCALAPPDATA%\Angerona\SourceData\logs`:

- `startup-preflight.log`: isolated source dependency/Qt check.
- `startup-dashboard.log`: dashboard stdout/stderr from the helper launch.
- The immediately preceding copy of each log uses `.previous.log`.

Supervisor diagnostics also persist under
`SourceData\logs\startup-recovery`, with bounded journal rotation and command
capture. Selected private scratch is under `SourceData\tmp` or the checkout's
`.tmp`; its dedicated attempt budgets hold new work when full rather than
deleting unreviewed evidence. The dashboard's direct output and native installer
logs are not hard-capped for their entire lifetime. Failed transactions and the
preserved environment remain available for diagnosis. See the
[automatic repair engineering record](../analysis/startup-repair-2026-10-21/README.md)
for test scope and limitations.

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
