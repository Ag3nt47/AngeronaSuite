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
from typing import Any, Dict, List

from angerona.core.capability_manifest import verify_external_module
from angerona.core.config import Config
from angerona.core.eventbus import EventBus
from angerona.core.module_base import BaseModule
from angerona.core.platforms import (
    availability_for,
    declared_platforms_from_source,
    normalize_platform,
)


_TRUE = frozenset({"1", "true", "yes", "on"})


def _env_enabled(name: str) -> bool:
    return os.environ.get(name, "0").strip().casefold() in _TRUE


def _unsigned_development_allowed() -> bool:
    """Unsigned extensions are unavailable in protected/elevated launch mode."""
    return (
        _env_enabled("ANGERONA_ALLOW_UNSIGNED_EXTERNAL_MODULES")
        and _env_enabled("ANGERONA_DEVELOPMENT_MODE")
        and not _env_enabled("ANGERONA_ENFORCE_KEY_ACL")
    )


class ModuleManager:
    def __init__(
        self,
        bus: EventBus,
        config: Config,
        *,
        target_platform: str | None = None,
    ) -> None:
        self.bus = bus
        self.config = config
        self.platform = normalize_platform(target_platform)
        self.modules: Dict[str, BaseModule] = {}
        self.discovery_errors: List[str] = []
        # Enterprise extension inventory. Built-ins inherit the release trust
        # boundary; external modules are recorded only after their detached
        # manifest and source digest pass before-import verification.
        self.module_trust: Dict[str, dict[str, Any]] = {}
        self.external_rejections: List[dict[str, str]] = []

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
            platform = availability_for(inst, self.platform)
            setattr(inst, "_angerona_platform_availability", platform)
            if not platform.available:
                inst.status = "unavailable"
                inst.set_health(0, platform.reason)
            # Optional: give supervisor-type modules (e.g. Watchdog Monitor) a
            # handle to the manager so they can see/restart their siblings.
            if hasattr(inst, "bind_manager"):
                try:
                    inst.bind_manager(self)
                except Exception:
                    pass
            self.modules[inst.name] = inst
            manifest = getattr(cls, "_angerona_manifest", None)
            origin = "external" if manifest is not None else "builtin"
            trust = str(getattr(cls, "_angerona_trust", "release"))
            setattr(inst, "_angerona_origin", origin)
            setattr(inst, "_angerona_trust", trust)
            setattr(inst, "_angerona_manifest", manifest)
            self.module_trust[inst.name] = {
                "origin": origin,
                "trust": trust,
                "capability_id": (
                    manifest.capability_id
                    if manifest is not None
                    else f"angerona.builtin.{cls.__module__.rsplit('.', 1)[-1]}"
                ),
                "version": (
                    manifest.version
                    if manifest is not None
                    else str(getattr(inst, "version", "1.0.0"))
                ),
                "permissions": (list(manifest.permissions) if manifest is not None else []),
                "high_risk_permissions": (
                    list(manifest.high_risk_permissions) if manifest is not None else []
                ),
                "publisher": manifest.publisher if manifest is not None else "Angerona",
            }

    def _builtin_classes(self) -> List[type]:
        import angerona.modules as pkg

        found: List[type] = []
        seen: set[str] = set()
        roots = list(getattr(pkg, "__path__", []) or [])
        pkg_file = getattr(pkg, "__file__", None)
        if pkg_file:
            roots.append(os.path.dirname(pkg_file))

        def _source_path(name: str) -> Path | None:
            for root in roots:
                try:
                    candidate = Path(root) / f"{name}.py"
                    if candidate.is_file():
                        return candidate
                except (OSError, TypeError):
                    continue
            return None

        def _load(name: str) -> None:
            if name in seen or name.startswith("_"):
                return
            seen.add(name)
            # On non-Windows hosts, preflight the literal declaration without
            # importing the file.  Legacy modules default to Windows-only, which
            # prevents top-level imports such as winreg/ETW/AMSI from crashing a
            # macOS or Linux startup.
            if self.platform != "windows":
                source_path = _source_path(name)
                supported = (
                    declared_platforms_from_source(source_path)
                    if source_path is not None
                    else frozenset({"windows"})
                )
                if self.platform not in supported:
                    return
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
        # suite's elevated token. Keep the extensibility feature explicit opt-in,
        # then verify a detached manifest and source digest before Python ever
        # sees the file. Signed publisher trust is the default; a hash-pinned
        # unsigned mode exists only behind an explicit development override.
        if not _env_enabled("ANGERONA_EXTERNAL_MODULES"):
            return []
        found: List[type] = []
        allow_unsigned = _unsigned_development_allowed()
        root = self.config.external_modules_dir.resolve()
        trust_store = self.config.data_dir / "trust" / "module_publishers.json"
        for path in sorted(root.glob("*.py")):
            if path.name.startswith("_"):
                continue
            try:
                resolved = path.resolve()
                if resolved.parent != root:
                    raise ValueError("module resolves outside the external module directory")
            except Exception as exc:
                reason = f"unsafe module path: {exc}"
                self.discovery_errors.append(f"{path}: {reason}")
                self.external_rejections.append({"path": str(path), "reason": reason})
                continue
            decision = verify_external_module(
                path,
                trust_store,
                allow_unsigned=allow_unsigned,
            )
            if not decision.accepted or decision.manifest is None:
                self.discovery_errors.append(
                    f"{path}: external capability rejected before import: {decision.reason}"
                )
                self.external_rejections.append({"path": str(path), "reason": decision.reason})
                continue
            try:
                spec = importlib.util.spec_from_file_location(f"angerona_ext_{path.stem}", path)
                if spec is None or spec.loader is None:
                    raise ImportError("Python could not create an import specification")
                if decision.source_bytes is None:
                    raise ImportError("verified external module source is unavailable")
                mod = importlib.util.module_from_spec(spec)
                # Execute the exact byte snapshot whose digest and publisher
                # signature were verified. Reopening the path here would permit
                # a local verify-then-swap race against the elevated process.
                code = compile(decision.source_bytes, str(path), "exec")
                # External Python is executable by design, but only this exact
                # bounded byte snapshot reaches exec after digest, manifest,
                # publisher-signature, path, and protected-mode checks.
                exec(code, mod.__dict__)  # nosec B102
            except Exception as exc:
                self.discovery_errors.append(f"{path}: {exc}")
                continue
            classes = self._subclasses_in(mod)
            for cls in classes:
                setattr(cls, "_angerona_manifest", decision.manifest)
                setattr(cls, "_angerona_trust", decision.trust)
            found.extend(classes)
        return found

    @staticmethod
    def _subclasses_in(mod) -> List[type]:
        out = []
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if (
                issubclass(obj, BaseModule)
                and obj is not BaseModule
                and obj.__module__ == mod.__name__
            ):
                out.append(obj)
        return out

    # ── Lifecycle ───────────────────────────────────────────────────────────
    def is_enabled(self, name: str) -> bool:
        mod = self.modules[name]
        if not availability_for(mod, self.platform).available:
            return False
        return self.config.module_states.get(name, mod.enabled_by_default)

    # Safety-critical modules must come up immediately — never staggered.
    _NO_STAGGER = {
        "Watchdog Monitor",
        "Anti-Suspension Heartbeat",
        "Active Response SOAR",
        "Zero-Trust Local IPC Guard",
        "SOAR Automation",
        # Network-first Chill must not spend minutes waiting behind unrelated
        # module first-cycle gates before its live edge sensors exist. These
        # modules are event-driven/lightweight at startup and form the minimum
        # always-on detection plane requested for unattended monitoring.
        "Network Monitor",
        "C2 Beacon Detector",
        "WFP Controller",
        "ARP Watchdog",
        "WLAN Monitor",
        "ETW Core Listener",
        "ETW Real-Time Process Sensor",
        "AMSI Bridge",
        "AV Telemetry Bridge",
        "Removable-Media / USB Monitor",
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
        mod = self.modules.get(name)
        if not mod:
            return
        platform = availability_for(mod, self.platform)
        if enabled and not platform.available:
            mod.status = "unavailable"
            mod.set_health(0, platform.reason)
            return
        self.config.module_states[name] = enabled
        self.config.save()
        mod.start() if enabled else mod.stop()

    def stop_all(self) -> None:
        for mod in self.modules.values():
            mod.stop()

    # ── Enterprise trust/readiness inventory ───────────────────────────────
    def capability_inventory(self) -> List[dict[str, Any]]:
        """Return a stable, serialisable trust inventory for UI/API/export."""
        rows: List[dict[str, Any]] = []
        for name in sorted(self.modules):
            mod = self.modules[name]
            trust = dict(self.module_trust.get(name, {}))
            trust.update(
                {
                    "name": name,
                    "category": str(getattr(mod, "category", "General")),
                    "status": str(getattr(mod, "status", "unknown")),
                    "health": int(getattr(mod, "health", 0)),
                    "enabled": bool(self.is_enabled(name)),
                }
            )
            trust.update(availability_for(mod, self.platform).as_dict())
            rows.append(trust)
        return rows

    def extension_security_summary(self) -> dict[str, Any]:
        external = [row for row in self.capability_inventory() if row.get("origin") == "external"]
        return {
            "external_loading_enabled": _env_enabled("ANGERONA_EXTERNAL_MODULES"),
            "unsigned_development_override_requested": _env_enabled(
                "ANGERONA_ALLOW_UNSIGNED_EXTERNAL_MODULES"
            ),
            "unsigned_development_override": _unsigned_development_allowed(),
            "loaded_external": len(external),
            "signed_external": sum(1 for row in external if row.get("trust") == "signed"),
            "rejected_external": len(self.external_rejections),
            "rejections": list(self.external_rejections),
        }
