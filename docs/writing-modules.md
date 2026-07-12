# Writing an Angerona Module

A module is one Python file with one class. Drop it in either:

- `src/angerona/modules/` (ships with the app), or
- `%LOCALAPPDATA%\Angerona\modules\` (your personal drop-in folder, shown in Settings)

It is discovered and listed in the **Modules** page automatically — no
registration, no core edits.

## Minimal module

```python
from angerona.core.module_base import BaseModule, Severity

class HelloModule(BaseModule):
    name = "Hello"                 # unique; shown in the UI
    description = "Demo module."
    category = "Diagnostics"
    enabled_by_default = True

    def run(self):
        while not self.stopping:           # cooperative shutdown
            self.emit("hello", Severity.INFO)
            self.sleep(10)                  # interruptible sleep
```

## The API you get

| Member | Use |
|--------|-----|
| `self.emit(msg, severity, **details)` | Publish an event (shows in UI + ledger) |
| `self.sleep(seconds)` | Sleep that wakes immediately on stop |
| `self.stopping` | `True` once the user disables/quits — exit your loop |
| `self._bus.recent(n)` | Read recent events (for consumer modules like AI triage) |

`Severity` is `INFO < LOW < MEDIUM < HIGH < CRITICAL`.

## Rules

1. **Loop on `self.stopping`** and use `self.sleep()` so the module stops cleanly.
2. **Never block the GUI** — you're on your own thread; just `emit`.
3. **Catch your own exceptions** where you can; the manager will catch the rest
   and mark your module `error` rather than crash the app.
4. **No secrets in code** — read from `os.environ` / `.env`.

## Reading data

Use `angerona.telemetry.sensors` for process/connection snapshots so your module
stays OS-portable and testable:

```python
from angerona.telemetry.sensors import list_processes, list_connections
```

That's the whole contract. Ship a file, get a module.
