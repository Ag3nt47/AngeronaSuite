"""Closed control catalog and bounded operation queue for one protection graph."""
from __future__ import annotations

from collections import OrderedDict
import os
import queue
import secrets
import threading
import time

from .engine_transport import EngineError, MAX_RESPONSE, canonical

# No credentials, command strings, arbitrary paths, response capabilities or
# model-generated configuration can cross this boundary.
SETTINGS = {
    "eco_mode": (bool, None, None),
    "alert_retention_enabled": (bool, None, None),
    "alert_retention_days": (int, 1, 3650),
    "alert_retention_max_mib": (int, 8, 16384),
}


def _text(value: object, limit: int = 512) -> str:
    return str(value).replace("\x00", "")[:limit]


def _status_text(value: object, limit: int = 512) -> str:
    """Bound the escaped JSON representation, including supplementary Unicode."""
    text = _text(value, limit)
    if len(canonical(text)) <= limit + 2:
        return text
    low, high = 0, len(text)
    while low < high:
        middle = (low + high + 1) // 2
        if len(canonical(text[:middle])) <= limit + 2:
            low = middle
        else:
            high = middle - 1
    return text[:low]


class EngineControl:
    def __init__(self, stop: threading.Event):
        self.stop = stop
        self.state = "starting"
        self.reason = "Loading the protection engine"
        self.started = time.monotonic()
        self.manager = self.bus = self.config = self.chill = None
        self._lock = threading.RLock()
        self._queue: queue.Queue = queue.Queue(maxsize=16)
        self._operations: OrderedDict[str, dict] = OrderedDict()
        self._worker: threading.Thread | None = None
        self.instance = ""
        self.retention = None
        self.runtime_metrics = None
        self._last_operation_seconds = 0.0

    def attach(self, manager, bus, config, chill) -> None:
        self.manager, self.bus, self.config, self.chill = manager, bus, config, chill

    def ready(self) -> None:
        self.state = "ready"
        self.reason = "Protection engine running independently of its windows"
        self._worker = threading.Thread(target=self._work, name="EngineControl", daemon=True)
        self._worker.start()

    def fail(self, reason: str) -> None:
        self.state, self.reason = "failed", _text(reason)

    def close(self) -> None:
        self.state, self.reason = "stopping", "Protection engine is stopping"
        self.stop.set()
        if self._worker is not None:
            self._worker.join(timeout=2.0)
        if self.chill is not None:
            self.chill.stop()

    def _module(self, name):
        if not isinstance(name, str) or not 1 <= len(name) <= 160 or self.manager is None:
            raise EngineError("Invalid module identity")
        module = self.manager.modules.get(name)
        if module is None:
            raise EngineError("Unknown module identity")
        return module

    def settings(self) -> dict:
        config = self.config
        if config is None:
            return {}
        return {name: getattr(config, name) for name in SETTINGS if hasattr(config, name)}

    def status(self) -> dict:
        rows = []
        if self.manager is not None:
            for name, module in tuple(self.manager.modules.items())[:256]:
                usage = self.manager.module_usage(name)
                operational = module.operational_snapshot()
                rows.append({
                    "name": _status_text(name, 160), "enabled": bool(usage.enabled),
                    "eligible": bool(usage.eligible), "usage": _status_text(usage.state, 40),
                    "reason": _status_text(usage.reason),
                    "status": _status_text(operational.get("status", "unknown"), 40),
                    "health": max(0, min(100, int(operational.get("health", 0)))),
                    "health_note": _status_text(operational.get("health_note", "")),
                    "mode": _status_text(getattr(module, "capability_mode", "unknown"), 40),
                    "paused": bool(getattr(module, "_chill_paused", False)),
                })
        with self._lock:
            operations = [dict(value) for value in self._operations.values()][-16:]
        response = {"ready": False, "state": "UNAVAILABLE", "reason": "Response module unavailable",
                    "ollama_required": False}
        if self.manager is not None:
            combat = self.manager.modules.get("Adversary Combat")
            from angerona.modules.adversary_combat import AdversaryCombat
            if isinstance(combat, AdversaryCombat):
                snapshot = combat.response_snapshot()
                response.update(ready=snapshot.get("ready") is True,
                                state=_text(snapshot.get("state", "UNKNOWN"), 64),
                                reason=_text(snapshot.get("reason", "")),
                                queue_depth=max(0, min(100000, int(snapshot.get("queue_depth", 0)))),
                                queue_drops=max(0, int(snapshot.get("queue_drops", 0))),
                                last_decision=_text(snapshot.get("last_decision", ""), 160))
        return {"instance": self.instance, "state": self.state, "reason": self.reason,
                "pid": os.getpid(), "uptime_seconds": round(time.monotonic() - self.started, 1),
                "mode": "Chill" if self.config is None or self.config.eco_mode else "Full",
                "modules": rows, "enabled_count": sum(row["enabled"] for row in rows),
                "settings": self.settings(), "operations": operations,
                "control_metrics": {"queued": self._queue.qsize(), "queue_capacity": 16,
                                    "retained_receipts": len(self._operations),
                                    "last_operation_seconds": self._last_operation_seconds},
                "alert_retention": self.retention.snapshot() if self.retention is not None else {},
                "response": response}

    def _events(self, cursor: int) -> dict:
        if self.bus is None:
            return {"instance": self.instance, "cursor": 0, "overflow": False, "events": []}
        current, records, overflow = self.bus.records_since(cursor)
        # Preserve the oldest available next page. Advancing straight to the
        # latest revision would silently lose events during a large burst.
        records = sorted(records, key=lambda pair: pair[0])
        selected = []
        encoded_size = 1024  # envelope, identity, cursor and loss flags
        for revision, event in records[:200]:
            row = {"revision": revision, "module": _text(event.module, 160),
                   "message": _text(event.message, 1000), "severity": int(event.severity),
                   "timestamp": float(event.ts), "message_truncated": len(str(event.message)) > 1000}
            row_bytes = len(canonical(row)) + 1
            if encoded_size + row_bytes > MAX_RESPONSE - 4096:
                break
            selected.append(row)
            encoded_size += row_bytes
        next_cursor = selected[-1]["revision"] if selected else current
        return {"instance": self.instance, "cursor": next_cursor, "overflow": bool(overflow),
                "events": selected}

    def dispatch(self, request: dict) -> dict:
        operation = request.get("operation")
        if operation == "status" and set(request) == {"operation"}:
            return self.status()
        if operation == "settings" and set(request) == {"operation"}:
            return {"settings": self.settings()}
        if operation == "metrics" and set(request) == {"operation"}:
            if self.runtime_metrics is None:
                raise EngineError("Runtime queue metrics are not available yet")
            return self.runtime_metrics.snapshot()
        if operation == "events" and set(request) == {"operation", "cursor"}:
            cursor = request["cursor"]
            if type(cursor) is not int or not -1 <= cursor <= 2**63 - 1:
                raise EngineError("Invalid event cursor")
            return self._events(cursor)
        if operation == "operation_status" and set(request) == {"operation", "id"}:
            identity = request["id"]
            if not isinstance(identity, str) or len(identity) != 32:
                raise EngineError("Invalid operation identity")
            with self._lock:
                if identity not in self._operations:
                    raise EngineError("Unknown or expired operation")
                return dict(self._operations[identity])
        if self.state != "ready" or self.stop.is_set():
            raise EngineError("Engine is not ready for control operations")
        if operation in {"module_enable", "module_restart", "module_selftest"}:
            expected = {"operation", "name"} | ({"enabled"} if operation == "module_enable" else set())
            if set(request) != expected:
                raise EngineError("Invalid module request schema")
            self._module(request["name"])
            if operation == "module_enable" and type(request["enabled"]) is not bool:
                raise EngineError("Enabled must be a boolean")
            if operation != "module_enable" and not self.manager.is_enabled(request["name"]):
                raise EngineError("Disabled modules cannot be restarted or self-tested")
        elif operation == "settings_patch":
            if set(request) != {"operation", "settings"} or not isinstance(request["settings"], dict):
                raise EngineError("Invalid settings request schema")
            changes = request["settings"]
            if not changes or not set(changes) <= SETTINGS.keys():
                raise EngineError("Settings are outside the local control catalog")
            for name, value in changes.items():
                kind, low, high = SETTINGS[name]
                if type(value) is not kind or (kind is int and not low <= value <= high):
                    raise EngineError("Invalid setting value")
                if not hasattr(self.config, name):
                    raise EngineError("Setting unavailable in this engine")
        elif operation == "stop_engine" and set(request) == {"operation", "confirmation"}:
            if request["confirmation"] != "stop-protection":
                raise EngineError("Explicit stop-protection confirmation required")
        else:
            raise EngineError("Unknown control operation")
        identity = secrets.token_hex(16)
        with self._lock:
            if self._queue.full():
                raise EngineError("Engine operation queue is full")
            # Keep at most 64 receipts; queued/running work is never evicted.
            while len(self._operations) >= 64:
                removable = next((key for key, value in self._operations.items()
                                  if value["state"] in {"completed", "failed"}), None)
                if removable is None:
                    raise EngineError("Engine operation receipt limit reached")
                del self._operations[removable]
            self._operations[identity] = {"id": identity, "operation": operation, "state": "queued"}
            self._queue.put_nowait((identity, dict(request)))
        return {"id": identity, "state": "queued"}

    def _set_chill(self, enabled: bool) -> None:
        if enabled == (self.chill is not None):
            return
        from .chill_runtime import ChillRuntimeController
        if enabled:
            controller = ChillRuntimeController(self.manager, self.bus, self.config)
            controller.prepare_runtime()
            paused = controller.prepare_modules()
            selected = []
            for name in paused:
                module = self.manager.modules.get(name)
                if module is not None and self.manager.is_enabled(name):
                    module.stop()
                    selected.append(name)
            controller.start(selected)
            self.chill = controller
        else:
            controller = self.chill
            paused = controller.paused_names
            controller.stop()
            controller._apply_throttles(False)
            controller._set_runtime_quiet(False)
            self.chill = None
            for name in paused:
                module = self.manager.modules.get(name)
                if module is not None:
                    setattr(module, "_chill_paused", False)
                    self.manager.start_if_enabled(module)

    def _execute(self, request: dict) -> dict:
        operation = request["operation"]
        if operation == "stop_engine":
            self.stop.set()
            return {"message": "Protection engine stop requested"}
        if operation == "settings_patch":
            previous = {name: getattr(self.config, name) for name in request["settings"]}
            try:
                for name, value in request["settings"].items():
                    setattr(self.config, name, value)
                self.config.save()
            except Exception:
                for name, value in previous.items():
                    setattr(self.config, name, value)
                raise
            if "eco_mode" in request["settings"]:
                self._set_chill(self.config.eco_mode)
            if self.retention is not None:
                from .alert_retention import RetentionPolicy
                self.retention.update_policy(RetentionPolicy.from_config(self.config))
            return {"settings": self.settings()}
        module = self._module(request["name"])
        if operation == "module_enable":
            self.manager.set_enabled(request["name"], request["enabled"])
            return {"enabled": self.manager.is_enabled(request["name"])}
        if not self.manager.is_enabled(request["name"]):
            raise EngineError("Module was disabled before operation execution")
        if operation == "module_restart":
            generation = module.operational_snapshot()["lifecycle_generation"]
            result = self.manager.restart_module_generation(request["name"], module, generation)
            return {"restarted": bool(result)}
        from .selftest import run_module_selftest
        passed, reason = run_module_selftest(module, timeout=15.0)
        return {"passed": bool(passed), "reason": _text(reason)}

    def _work(self) -> None:
        while not self.stop.is_set():
            try:
                identity, request = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            with self._lock:
                self._operations[identity]["state"] = "running"
            started = time.monotonic()
            try:
                result = self._execute(request)
                completed = {"state": "completed", "result": result}
            except Exception as exc:
                completed = {"state": "failed", "error": type(exc).__name__}
            with self._lock:
                self._operations[identity].update(completed)
                self._last_operation_seconds = round(time.monotonic() - started, 3)
            self._queue.task_done()
