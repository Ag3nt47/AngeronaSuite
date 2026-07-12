# Angerona Architecture

Angerona is a small, strict core with everything else as **modules**. The core
never imports a module directly; modules never import each other. They
communicate only through the **EventBus**.

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

## Components

| Layer | File | Responsibility |
|-------|------|----------------|
| Entry | `__main__.py` | Elevate, build `QApplication`, start app |
| Wiring | `app.py` | Construct core services + window, manage lifecycle |
| Bus | `core/eventbus.py` | Thread-safe pub/sub + bounded recent-events ring |
| Module API | `core/module_base.py` | `BaseModule`: threading, lifecycle, `emit()` |
| Supervisor | `core/module_manager.py` | Auto-discover + start/stop modules |
| Config | `core/config.py` | Settings, paths, `.env` loading |
| Privilege | `core/privilege.py` | UAC elevation |
| Storage | `core/storage.py` | Flight-recorder SQLite ledger |
| Telemetry | `telemetry/sensors.py` | Process/connection sampling; `KernelSensor` seam |
| GUI | `gui/` | Window, pages, theme, tray |
| Modules | `modules/` | Built-in capabilities (auto-discovered) |
| Engines | `engines/` | Original Angerona code, held for porting |
| Updater | `updater/` | GitHub Releases version check |

## Threading model

Each module runs on its own daemon thread. They only ever **publish** to the
bus (thread-safe). The GUI is the single Qt thread and **polls** the bus/storage
on a `QTimer` — no cross-thread Qt signals, no locks in the UI. This keeps the
UI smooth and makes modules trivial to reason about.

## Security model

- **Elevated user mode.** UAC prompt on launch (`core/privilege.py`). Full
  visibility without an unsigned kernel driver.
- **Kernel-sourced telemetry via supported APIs.** ETW, WMI/CIM, AMSI, WFP. The
  `KernelSensor` abstract class in `telemetry/sensors.py` is the seam where a
  *signed* driver could later attach — nothing unsigned ships.
- **Secrets stay local.** Only a git-ignored `.env`; never committed.
- **Tamper-evident audit.** Every event is persisted to the flight recorder.

## Data locations

Runtime state lives under `%LOCALAPPDATA%\Angerona\` (db, logs, settings, and
the user `modules/` drop-in folder), keeping the install directory clean.
