# Angerona Architecture

Angerona is a local security workbench with a Qt dashboard, supervised modules,
shared telemetry, an authenticated event pipeline and governed response. A
visible dashboard, a working sensor and authority to change the host are
separate states. See the [complete security flow and review matrix](security-flow.md)
and [Master Manual](../Angerona_Master_Manual.docx).

```
                ┌─────────────────────────────────────────────┐
                │                   GUI (Qt)                   │
                │  Dashboard · Modules · Alerts · Settings     │
                └───────────────▲───────────────▲─────────────┘
                                │ polls (1.5s)  │ enable/disable
                                │               │
   ┌──────────────┐   publish   │        ┌──────┴───────┐
   │  Module A     ├────────────►│        │ ModuleManager │  discover + supervise
   │  Module B     ├────────────►│ EventBus │──────────────┘
   │  Module C     ├────────────►│  (ring) │
   └──────────────┘             └────┬─────┘
                                     │ every event
                                     ▼
                            ┌─────────────────┐
                            │ FlightRecorder  │  append-only SQLite ledger
                            └─────────────────┘
```

![Angerona security architecture and authority boundaries](../assets/security-flow-overview.png)

## Components

| Layer | File | Responsibility |
|-------|------|----------------|
| Entry | `__main__.py`, `startup.py` | Verify source or installed authority, prepare the GUI and check lifecycle gates |
| Wiring | `app.py` | Construct core services + window, manage lifecycle |
| Bus | `core/eventbus.py` | Thread-safe pub/sub + bounded recent-events ring |
| Module API | `core/module_base.py` | `BaseModule`: threading, lifecycle, `emit()` |
| Supervisor | `core/module_manager.py` | Auto-discover + start/stop modules |
| Config | `core/config.py` | Settings, paths, `.env` loading |
| Privilege | `core/privilege.py` | Preserve source Observe and signed installed Protect authority boundaries |
| Storage | `core/storage.py` | Flight-recorder SQLite ledger |
| Telemetry | `telemetry/sensors.py` | Process/connection sampling; `KernelSensor` seam |
| GUI | `gui/` | Window, pages, theme, tray |
| Modules | `modules/` | Built-in capabilities (auto-discovered) |
| Engines | `engines/` | Original Angerona code, held for porting |
| Updater | `updater/` | GitHub Releases version check |

## Threading model

Qt runs on its owning thread. Shared services, module workers, bounded queues,
IPC and timers prepare data for the GUI. Different services have different
lifecycle and pacing requirements; there is no universal fixed polling rate.
Modules publish through the EventBus and use shared core services. Python
extensions are not mutually isolated sandboxes.

## Security model

- **User mode and explicit authority.** Ordinary-user source startup is
  Observe/development. Installed Protect requires the trusted signed payload,
  provisioned identities and separately accepted native enforcement. UAC does
  not make Python a kernel component or guarantee complete visibility.
- **Evidence and loss.** ETW, WMI/CIM, AMSI, WFP and other integrations depend
  on platform, permission, configuration and available collectors. Missing,
  stale, denied or dropped evidence remains a coverage gap. Authentication of
  record bytes is separate from producer provenance and truth.
- **Governed response.** Typed target identity, evidence, policy and approval
  checks precede supported actions. Outcomes and unresolved rollback remain
  explicit. AI prose, imported reports and review notes grant no authority.
- **Data custody.** Credentials, baselines, case evidence, recovery and
  disposable logs have different custody and retention rules. Opt-in AI and
  integrations have their own data/endpoint controls.

The desktop application runs in Ring 3. OS APIs can provide kernel-originated
observations, but Angerona does not ship an unsigned kernel driver or claim
immunity to a hostile administrator, kernel, hypervisor, firmware or compromised
OS. See Microsoft's [user and kernel mode boundary](https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/user-mode-and-kernel-mode).

## Startup and independent recovery

`start-angerona.bat` and its fixed PowerShell supervisor verify paths, storage,
runtime and fresh dashboard readiness. They can try bounded safe alternatives
and verified recovery. The independent Tk/Windows Forms recovery interfaces
import no application package and expose bounded diagnostics and Retry/Close.
An open recovery window never attests an active engine.

The [Safe Startup recovery guide](safe-startup-recovery.md) explains controls,
ordered candidates, preserved source edits, transaction holds, quotas and exact
GitHub egress. Recovery snapshots are rollback candidates, not approved security
baselines; startup cannot clear alerts, replace keys or weaken trust to appear
healthy.

Signed package builds also prepare an independent OS .NET/Windows Forms
`AngeronaSafeStart.exe` entry around the pinned frozen helper. Native file and
process leases survive the readiness deadline without killing a possible live
core. Final helper signing must precede pin embedding; wrapper signing and
independent release acceptance remain required and unprovisioned.

## Data locations

Source runtime state lives under `%LOCALAPPDATA%\Angerona\SourceData`.
Signed installed authority retains its verified payload/data locations.
Configuration, credentials, approved baselines, audit journals, quarantine,
cases, disposable logs and recovery copies use separate retention policies.
