# Writing an Angerona Module

A module is one Python file with one class. Put it in either:

- `src/angerona/modules/` for a module shipped and reviewed with Angerona, or
- `<Angerona data directory>\modules\` for an external capability.

Built-in release modules are discovered automatically. External Python is
disabled by default because importing it executes top-level code with
Angerona's token. Enabling external modules also requires a detached
`<name>.angerona.json` Capability Manifest v1. Angerona validates that manifest
and the exact source digest before Python imports the file.

## Minimal module

```python
from angerona.core.module_base import BaseModule, Severity


class HelloModule(BaseModule):
    name = "Hello"                 # unique; shown in the UI
    description = "Demo module."
    category = "Diagnostics"
    enabled_by_default = True

    def run(self):
        while not self.stopping:   # cooperative shutdown
            self.emit("hello", Severity.INFO)
            self.sleep(10)         # interruptible sleep and cycle boundary
```

## The API you get

| Member | Use |
| --- | --- |
| `self.emit(msg, severity, **details)` | Publish an authenticated event to the UI and ledger |
| `self.sleep(seconds)` | Sleep that wakes immediately on stop and marks a cycle boundary |
| `self.stopping` | Becomes `True` when the module is disabled or Angerona exits |
| `self._bus.recent(n)` | Read bounded recent events for consumer modules |

`Severity` is `INFO < LOW < MEDIUM < HIGH < CRITICAL`.

## Rules

1. Loop on `self.stopping` and use `self.sleep()` so shutdown is cooperative.
2. Never touch Qt widgets from a module. Emit data and let the UI render it.
3. Catch expected operational failures. The manager catches the rest and
   quarantines repeatedly crashing modules without taking down Angerona.
4. Use Angerona's encrypted credential store. Never place credentials in a
   module, source-control file, or manifest.
5. Declare permissions, data classes, egress, retention, and resource budgets
   honestly. A manifest is a review and trust contract; it is not an OS sandbox.
6. Keep state bounded and use interruptible waits.

## Reading data

Use `angerona.telemetry.sensors` for process and connection snapshots so a
module stays testable and does not duplicate expensive host scans:

```python
from angerona.telemetry.sensors import list_connections, list_processes
```

## External Capability Manifest v1

Set `ANGERONA_EXTERNAL_MODULES=1` only after reviewing the external module.
Alongside `hello.py`, create `hello.angerona.json`:

```json
{
  "schema_version": 1,
  "id": "example.hello",
  "name": "Hello",
  "version": "1.0.0",
  "api_version": "1",
  "entrypoint": "hello.py",
  "sha256": "<lowercase SHA-256 of hello.py>",
  "permissions": ["event.emit"],
  "events": {
    "inputs": [],
    "outputs": ["example.hello"]
  },
  "mitre": [],
  "privacy": {
    "data_classes": ["none"],
    "egress": "none",
    "retention": "memory"
  },
  "performance": {
    "cpu_budget_pct": 5.0,
    "memory_budget_mb": 128,
    "poll_interval_s": 10.0
  },
  "publisher": "example.publisher",
  "signature": "<Ed25519 signature in base64 or hex>"
}
```

The machine's publisher trust store is:

`<Angerona data directory>\trust\module_publishers.json`

```json
{
  "schema_version": 1,
  "publishers": [
    {
      "id": "example.publisher",
      "public_key": "<32-byte Ed25519 public key in base64 or hex>"
    }
  ]
}
```

The signature covers canonical JSON with the `signature` field removed. It binds
the publisher, source SHA-256, compatibility version, permissions, privacy
declaration, telemetry contract, and resource budget.

For reviewed local development only,
`ANGERONA_ALLOW_UNSIGNED_EXTERNAL_MODULES=1` accepts an unsigned manifest after
its exact source digest passes. The Enterprise readiness page labels this as a
lower-trust development override. Invalid signatures and changed sources always
fail closed before top-level module code executes.

The machine-readable schema is
[`capability-manifest-v1.schema.json`](capability-manifest-v1.schema.json).
