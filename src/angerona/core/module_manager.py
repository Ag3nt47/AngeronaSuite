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
        seen: set[str] = set()

        def _load(name: str) -> None:
            if name in seen or name.startswith("_"):
                return
            seen.add(name)
            try:
                mod = importlib.import_module(f"angerona.modules.{name}")
            except Exception as exc:
                self.discovery_errors.append(f"angerona.modules.{name}: {exc}")
                return
            found.extend(self._subclasses_in(mod))
            # Briefly yield the GIL between imports so the GUI thread stays
            # responsive during the import burst instead of freezing.
            time.sleep(0.003)

        for info in pkgutil.iter_modules(pkg.__path__):
            _load(info.name)
        # Filesystem fallback: a strict (PEP 660) editable install freezes the
        # module map at install time, so a module file added LATER is invisible to
        # pkgutil — it would silently never load until a reinstall. Scan the
        # package's real directory too so new modules discover without reinstalling.
        # Derive the dir from __file__ (the physical __init__.py) — reliable even
        # when the editable finder gives __path__ a non-filesystem value.
        roots = list(getattr(pkg, "__path__", []) or [])
        pkg_file = getattr(pkg, "__file__", None)
        if pkg_file:
            roots.append(os.path.dirname(pkg_file))
        scanned: set[str] = set()
        for root in roots:
            try:
                real = os.path.realpath(root)
            except Exception:
                continue
            if not real or real in scanned or not os.path.isdir(real):
                continue
            scanned.add(real)
            try:
                for fn in os.listdir(real):
                    if fn.endswith(".py"):
                        _load(fn[:-3])
            except Exception:
                continue
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

    def start_enabled(
        self,
        deferred_names: set[str] | None = None,
        *,
        sequential_cycles: bool = True,
        cycle_timeout: float = 30.0,
        min_settle: float = 0.10,
    ) -> list[str]:
        """Start enabled modules without creating a first-scan stampede.

        Safety-critical response modules are brought online immediately. Remaining
        modules start one at a time and, by default, must reach a real first-cycle
        boundary before the next module starts. A bounded timeout prevents one
        broken sensor from blocking the entire suite forever.

        Returning the skipped names lets Eco Mode wake exactly those modules later.
        Deferred modules never create a thread or begin their first scan.
        """
        deferred = set(deferred_names or ())
        skipped: list[str] = []
        critical: list[BaseModule] = []
        staged: list[BaseModule] = []
        for name, mod in self.modules.items():
            if not self.is_enabled(name):
                continue
            if name in deferred:
                skipped.append(name)
                continue
            if name in self._NO_STAGGER:
                critical.append(mod)
            else:
                staged.append(mod)

        # Do not make containment, IPC protection, or the watchdog wait behind a
        # slow scanner. These modules are intentionally lightweight.
        for mod in critical:
            mod.start()

        for mod in staged:
            mod.start()
            if not sequential_cycles:
                continue
            waiter = getattr(mod, "wait_for_first_cycle", None)
            if callable(waiter):
                timeout = max(
                    0.1,
                    float(getattr(mod, "startup_cycle_timeout", cycle_timeout)),
                )
                waiter(timeout=timeout)
            # Keep adjacent setup work from landing in the same scheduler slice,
            # even when a module completes almost instantly.
            if min_settle > 0:
                time.sleep(min_settle)
        return skipped

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
