"""Discovers, instantiates, and supervises modules.

Discovery sources (both scanned automatically):
  1. Built-in modules shipped in ``angerona.modules``.
  2. User drop-in modules: any ``*.py`` in the per-user data ``modules/`` dir.

A module is any subclass of ``BaseModule``. To add a capability, drop one file —
no registration, no core edits.
"""
from __future__ import annotations

import importlib
import importlib.util
import inspect
import os
import pkgutil
import time
from pathlib import Path
from typing import Dict, List

from angerona.core.config import Config
from angerona.core.eventbus import EventBus
from angerona.core.module_base import BaseModule


class ModuleManager:
    def __init__(self, bus: EventBus, config: Config) -> None:
        self.bus = bus
        self.config = config
        self.modules: Dict[str, BaseModule] = {}
        self.discovery_errors: List[str] = []

    # ── Discovery ───────────────────────────────────────────────────────────
    def discover(self) -> None:
        for cls in self._builtin_classes() + self._external_classes():
            try:
                inst = cls()
            except Exception as exc:
                self.discovery_errors.append(f"{cls.__module__}.{cls.__name__}: {exc}")
                continue
            if inst.name in self.modules:
                continue
            inst.bind(self.bus)
            # Optional: give supervisor-type modules (e.g. Watchdog Monitor) a
            # handle to the manager so they can see/restart their siblings.
            if hasattr(inst, "bind_manager"):
                try:
                    inst.bind_manager(self)
                except Exception:
                    pass
            self.modules[inst.name] = inst

    def _builtin_classes(self) -> List[type]:
        import angerona.modules as pkg
        found: List[type] = []
        for info in pkgutil.iter_modules(pkg.__path__):
            try:
                mod = importlib.import_module(f"angerona.modules.{info.name}")
            except Exception as exc:
                self.discovery_errors.append(f"angerona.modules.{info.name}: {exc}")
                continue
            found.extend(self._subclasses_in(mod))
            # Briefly yield the GIL between imports so the GUI thread (which just
            # painted the freshly-shown window) stays responsive during the import
            # burst instead of freezing until all ~40 modules finish loading.
            time.sleep(0.003)
        return found

    def _external_classes(self) -> List[type]:
        # A-04: importing a drop-in executes arbitrary top-level Python with the
        # suite's elevated token. Keep the extensibility feature explicit opt-in
        # rather than silently trusting every file under a user-writable folder.
        if os.environ.get("ANGERONA_EXTERNAL_MODULES", "0").strip().lower() not in {
            "1", "true", "yes", "on"
        }:
            return []
        found: List[type] = []
        for path in sorted(self.config.external_modules_dir.glob("*.py")):
            if path.name.startswith("_"):
                continue
            try:
                spec = importlib.util.spec_from_file_location(f"angerona_ext_{path.stem}", path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)  # type: ignore[union-attr]
            except Exception as exc:
                self.discovery_errors.append(f"{path}: {exc}")
                continue
            found.extend(self._subclasses_in(mod))
        return found

    @staticmethod
    def _subclasses_in(mod) -> List[type]:
        out = []
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if issubclass(obj, BaseModule) and obj is not BaseModule and obj.__module__ == mod.__name__:
                out.append(obj)
        return out

    # ── Lifecycle ───────────────────────────────────────────────────────────
    def is_enabled(self, name: str) -> bool:
        return self.config.module_states.get(name, self.modules[name].enabled_by_default)

    # Safety-critical modules must come up immediately — never staggered.
    _NO_STAGGER = {
        "Watchdog Monitor", "Anti-Suspension Heartbeat", "Active Response SOAR",
        "Zero-Trust Local IPC Guard", "SOAR Automation",
    }

    def start_enabled(self) -> None:
        # Stagger the first poll of each non-critical module by a small,
        # increasing offset. Starting ~40 threads in a tight loop means they all
        # run their first (often full process/connection) scan at once — a CPU
        # spike that froze the freshly-shown window. Spreading the first polls
        # over a few seconds keeps the GUI responsive during boot; steady-state
        # behaviour is unchanged. Capped so late modules still start promptly.
        step, cap = 0.15, 6.0
        i = 0
        for name, mod in self.modules.items():
            if not self.is_enabled(name):
                continue
            if name in self._NO_STAGGER:
                mod.start()
            else:
                mod.start(initial_delay=min(i * step, cap))
                i += 1

    def set_enabled(self, name: str, enabled: bool) -> None:
        self.config.module_states[name] = enabled
        self.config.save()
        mod = self.modules.get(name)
        if not mod:
            return
        mod.start() if enabled else mod.stop()

    def stop_all(self) -> None:
        for mod in self.modules.values():
            mod.stop()
