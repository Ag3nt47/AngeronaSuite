"""Discovers, instantiates, and supervises modules.

Discovery sources (both scanned automatically):
  1. Built-in modules shipped in ``angerona.modules``.
  2. User drop-in modules: any ``*.py`` in the per-user data ``modules/`` dir.

A module is any subclass of ``BaseModule``. To add a capability, drop one file —
no registration, no core edits.
"""

from __future__ import annotations

import importlib
import importlib.abc
import importlib.util
import inspect
import hashlib
import math
import os
import pkgutil
import re
import secrets
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List

from angerona.core.assurance_receipts import (
    PRODUCER_CONTRACTS,
    AssuranceReceiptBroker,
)
from angerona.core.capability_assurance import assess_capability
from angerona.core.capability_manifest import verify_external_module
from angerona.core.config import Config
from angerona.core.eventbus import EventBus
from angerona.core.independent_high_water import IndependentHighWater
from angerona.core.module_base import BaseModule, Severity
from angerona.core.module_contract import ContractError, build_capability_contract
from angerona.core.module_usage import (
    ModuleUsage, has_optional_policy, kernel_service_installed, module_identity, usage_for,
)
from angerona.core.platforms import (
    availability_for,
    declared_platforms_from_source,
    normalize_platform,
)


_TRUE = frozenset({"1", "true", "yes", "on"})
_UGCAP_BOOTSTRAP = frozenset({"angerona.modules.ugcap_guard", "angerona.modules.adversary_combat"})
_UGCAP_TOKEN = re.compile(r"[0-9a-f]{32}\Z")
_UGCAP_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_HIGH_WATER_CONSUMERS = {
    ("angerona.modules.audit_log_guard", "AuditLogIntegrityGuard"): "constructor",
    ("angerona.modules.network_trust_monitor", "NetworkTrustMonitorModule"): "constructor",
    ("angerona.modules.smart_deception", "SmartDeception"): "binder",
}


def _high_water_binding_kind(cls: type) -> str | None:
    """Recognize an already-discovered bundled class without importing it.

    A matching module-name prefix alone is not service enrollment. In strict
    UGCAP startup these consumers must remain unimported until discovery has
    admitted their source, so this lookup never imports or loads a module.
    """
    identity = (cls.__module__, cls.__name__)
    kind = _HIGH_WATER_CONSUMERS.get(identity)
    module = sys.modules.get(identity[0]) if kind else None
    if (module is None or vars(module).get(identity[1]) is not cls
            or getattr(cls, "_angerona_manifest", None) is not None):
        return None
    return kind


def _is_ugcap_control(module) -> bool:
    return (type(module).__module__, type(module).__name__, module.name) in {
        ("angerona.modules.ugcap_guard", "UGCAPGuardModule", "UGCAP Integrity Guard"),
        ("angerona.modules.adversary_combat", "AdversaryCombat", "Adversary Combat"),
    }


class _AttestedSourceLoader(importlib.abc.Loader):
    """Execute only the byte snapshot checked against the live golden receipt.

    SourceFileLoader can accept a forged timestamp/hash-valid .pyc after a
    separate source check. This loader never opens or writes bytecode caches.
    The trusted bootstrap/interpreter/libraries remain outside this boundary.
    """

    def __init__(self, manager, fullname: str, source: Path) -> None:
        self.manager, self.fullname, self.source = manager, fullname, source

    def create_module(self, spec):
        return None

    def exec_module(self, module) -> None:
        manager = self.manager
        if (self.fullname.startswith("angerona.modules.")
                and self.fullname not in _UGCAP_BOOTSTRAP and manager.ugcap_paused
                and manager._ugcap_preparing_thread != threading.get_ident()):
            raise ImportError("ordinary module imports are held by the UGCAP gate")
        content, digest = manager._verified_source_bytes(self.source)
        code = compile(content, str(self.source), "exec", dont_inherit=True)
        exec(code, module.__dict__)  # nosec B102 -- exact attested bounded bytes.
        module._angerona_attested_load = (str(manager._ugcap_repository), digest)


class _AttestedSourceFinder(importlib.abc.MetaPathFinder):
    def __init__(self, manager) -> None:
        self.manager = manager

    def find_spec(self, fullname, path=None, target=None):
        if not fullname.startswith("angerona."):
            return None
        root = self.manager._ugcap_repository
        if root is None:
            raise ImportError("attested installation source is unavailable")
        source = root / "src" / Path(*fullname.split("."))
        package = source / "__init__.py"
        is_package = package.is_file()
        source = package if is_package else source.with_suffix(".py")
        # Missing source is intentionally an error, never a .pyc/native fallback.
        loader = _AttestedSourceLoader(self.manager, fullname, source)
        return importlib.util.spec_from_file_location(fullname, source, loader=loader,
            submodule_search_locations=[str(source.parent)] if is_package else None)


def _env_enabled(name: str) -> bool:
    return os.environ.get(name, "0").strip().casefold() in _TRUE


def _unsigned_development_allowed() -> bool:
    """Unsigned extensions are unavailable in protected/elevated launch mode."""
    return (
        _env_enabled("ANGERONA_ALLOW_UNSIGNED_EXTERNAL_MODULES")
        and _env_enabled("ANGERONA_DEVELOPMENT_MODE")
        and not _env_enabled("ANGERONA_ENFORCE_KEY_ACL")
    )


class _PriorityScanFocus:
    """One app-owned cadence lease; it carries no security or response authority."""

    def __init__(self, manager, owner: str, background_percent: int):
        self.manager = manager
        self.owner = owner
        self.background_percent = background_percent
        self.token = object()
        self.pacer_owner = secrets.token_hex(16)
        self.entered = False
        self.closed = False

    def __enter__(self):
        if self.entered or self.closed:
            raise RuntimeError("Priority scan focus cannot be reused.")
        self.manager._begin_priority_scan_focus(self)
        self.entered = True
        return self

    def renew(self) -> bool:
        return bool(self.entered and not self.closed
                    and self.manager._renew_priority_scan_focus(self))

    def snapshot(self) -> dict:
        return self.manager.priority_scan_focus_snapshot()

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            if self.entered:
                self.manager._end_priority_scan_focus(self.token)

    def __exit__(self, *_error):
        self.close()


class ModuleManager:
    PRIORITY_FOCUS_SECONDS = 900.0

    def __init__(
        self,
        bus: EventBus,
        config: Config,
        *,
        target_platform: str | None = None,
        recorder: object | None = None,
        high_water_provider: IndependentHighWater | None = None,
        module_factory: Callable[[type], BaseModule] | None = None,
    ) -> None:
        self.bus = bus
        self.config = config
        self.platform = normalize_platform(target_platform)
        self.recorder = recorder
        self.high_water_provider = high_water_provider
        self._module_factory = module_factory
        self.modules: Dict[str, BaseModule] = {}
        # Serialises operator enable/disable changes with watchdog generation
        # recovery.  The module itself performs the generation compare-and-
        # restart; this manager lock additionally proves the registered object
        # and enabled policy did not change underneath that request.
        self._module_control_lock = threading.RLock()
        self._control_generation = 0
        self._runtime_active = False
        self._shutdown = False
        self._priority_scan_focus: dict | None = None
        self._priority_scan_modules: dict[int, BaseModule] = {}
        self._ugcap_paused = getattr(config, "ugcap_enabled", False) is True
        self._ugcap_reason = "UGCAP user challenge required" if self._ugcap_paused else ""
        self._ugcap_held: set[str] = set()
        self._ugcap_deferred_discovery = self._ugcap_paused
        self._ugcap_verified_files: dict[str, str] = {}
        self._ugcap_repository: Path | None = None
        self._ugcap_finder = None
        self._ugcap_preparing_thread = None
        self._ugcap_resume_lock = threading.Lock()
        if self._ugcap_paused:
            self.bus.require_mesh()
        self._optional_enabled: dict[str, bool] = {}
        self._kernel_installed: bool | None = None
        from angerona.core import attack_coverage
        self.verified_readiness = attack_coverage.bind_manager(self)
        self.assurance_receipt_broker = AssuranceReceiptBroker(
            lambda: self.modules, on_verified=self.verified_readiness.observe_assurance,
        )
        self.discovery_errors: List[str] = []
        # Enterprise extension inventory. Built-ins inherit the release trust
        # boundary; external modules are recorded only after their detached
        # manifest and source digest pass before-import verification.
        self.module_trust: Dict[str, dict[str, Any]] = {}
        self.external_rejections: List[dict[str, str]] = []

    # ── Discovery ───────────────────────────────────────────────────────────
    def discover(self, *, continue_bootstrap: bool = False) -> None:
        capability_ids: set[str] = {
            row.get("capability_id", "") for row in self.module_trust.values()
        } if continue_bootstrap else set()
        for cls in self._builtin_classes() + self._external_classes():
            if continue_bootstrap and any(type(module) is cls for module in self.modules.values()):
                continue
            try:
                inst = self._construct_module(cls)
            except Exception as exc:
                self.discovery_errors.append(f"{cls.__module__}.{cls.__name__}: {exc}")
                continue
            if inst.name in self.modules:
                if continue_bootstrap and type(self.modules[inst.name]) is cls:
                    continue
                self.discovery_errors.append(
                    f"{cls.__module__}.{cls.__name__}: duplicate module name {inst.name!r}"
                )
                continue
            inst.bind(self.bus)
            if (self.platform == "windows" and module_identity(inst) == (
                    "angerona.modules.kernel_bridge", "KernelBridgeModule")):
                self._kernel_installed = kernel_service_installed()
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
            if self.recorder is not None and hasattr(inst, "bind_recorder"):
                try:
                    inst.bind_recorder(self.recorder)
                except Exception as exc:
                    self.discovery_errors.append(
                        f"{cls.__module__}.{cls.__name__}: recorder binding: {exc}"
                    )
            manifest = getattr(cls, "_angerona_manifest", None)
            origin = "external" if manifest is not None else "builtin"
            trust = str(getattr(cls, "_angerona_trust", "release"))
            capability_id = (
                manifest.capability_id
                if manifest is not None
                else f"angerona.builtin.{cls.__module__.rsplit('.', 1)[-1]}"
            )
            if capability_id in capability_ids:
                self.discovery_errors.append(
                    f"{cls.__module__}.{cls.__name__}: duplicate capability id {capability_id!r}"
                )
                continue
            try:
                contract = build_capability_contract(
                    inst,
                    capability_id=capability_id,
                    origin=origin,
                    trust=trust,
                    publisher=(manifest.publisher if manifest is not None else "Angerona"),
                    manifest_permissions=(manifest.permissions if manifest is not None else ()),
                    manifest_high_risk_permissions=(
                        manifest.high_risk_permissions if manifest is not None else ()
                    ),
                )
            except ContractError as exc:
                self.discovery_errors.append(f"{cls.__module__}.{cls.__name__}: {exc}")
                continue
            setattr(inst, "_angerona_origin", origin)
            setattr(inst, "_angerona_trust", trust)
            setattr(inst, "_angerona_manifest", manifest)
            setattr(inst, "_angerona_contract", contract)
            capability_ids.add(capability_id)
            self.modules[inst.name] = inst
            if self.bus.mesh_required:
                try:
                    self._enroll_mesh_module(inst)
                except Exception as exc:
                    self.discovery_errors.append(f"{inst.name}: mesh enrollment {type(exc).__name__}")
                    self.modules.pop(inst.name, None)
                    continue
            try:
                if getattr(inst, "CODE", "") == "CHAOS" and inst.name == "CHAOS":
                    self.assurance_receipt_broker.enroll_consumer(inst)
                producer_code = str(getattr(inst, "CODE", ""))
                if producer_code in PRODUCER_CONTRACTS:
                    issuer = self.assurance_receipt_broker.enroll_producer(
                        inst,
                        code=producer_code,
                        module_name=inst.name,
                        capability_id=capability_id,
                    )
                    binder = getattr(inst, "bind_assurance_receipt_issuer", None)
                    if callable(binder):
                        binder(issuer)
            except Exception as exc:
                self.discovery_errors.append(
                    f"{cls.__module__}.{cls.__name__}: assurance enrollment: {exc}"
                )
            self.module_trust[inst.name] = {
                "origin": origin,
                "trust": trust,
                "capability_id": capability_id,
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
            with self._module_control_lock:
                self._sync_priority_scan_module(inst.name, inst)
            self.verified_readiness.register(inst)

    def priority_scan_focus(self, *, owner: str, background_percent: int = 10):
        """Temporarily pace reviewed analysis while leaving control/intake live."""
        if type(owner) is not str or re.fullmatch(r"[a-f0-9]{32}", owner) is None:
            raise ValueError("Priority scan owner must be an exact request identity.")
        if type(background_percent) is not int or not 1 <= background_percent <= 100:
            raise ValueError("Background cadence must be between 1 and 100 percent.")
        return _PriorityScanFocus(self, owner, background_percent)

    def _priority_scan_ceiling(self, name, mod) -> float:
        trust = self.module_trust.get(name, {})
        if (not isinstance(mod, BaseModule) or _is_ugcap_control(mod)
                or module_identity(mod) == ("angerona.modules.spyware_guard", "SpywareGuardModule")
                or trust.get("origin") != "builtin" or trust.get("trust") != "release"
                or type(mod).__dict__.get("adaptive_throttle_allowed") is not True):
            return 1.0
        try:
            ceiling = float(type(mod).__dict__["adaptive_throttle_max"])
        except (KeyError, TypeError, ValueError, OverflowError):
            return 1.0
        return ceiling if math.isfinite(ceiling) and 1 <= ceiling <= 8 else 1.0

    def _sync_priority_scan_module(self, name, mod, *, blocking=True) -> bool:
        focus = self._priority_scan_focus
        if focus is None or focus["expires_at"] <= time.monotonic():
            return False
        ceiling = self._priority_scan_ceiling(name, mod)
        if ceiling <= 1:
            return False
        factor = min(ceiling, 100.0 / focus["background_percent"])
        if BaseModule.set_priority_throttle(mod, factor, focus["expires_at"], blocking=blocking):
            self._priority_scan_modules[id(mod)] = mod
            return True
        return False

    def _begin_priority_scan_focus(self, lease) -> None:
        from angerona.core.background_pacing import get_pacing_controller

        with self._module_control_lock:
            if self._shutdown or self._ugcap_paused:
                raise RuntimeError("Priority scans are held by shutdown or workspace policy.")
            previous = self._priority_scan_focus
            if previous is not None:
                if previous["expires_at"] > time.monotonic():
                    raise RuntimeError("Another priority scan is already active.")
                self._end_priority_scan_focus(previous["token"])
            get_pacing_controller().begin_priority_focus(
                lease.pacer_owner, lease.background_percent, seconds=self.PRIORITY_FOCUS_SECONDS)
            self._priority_scan_focus = {
                "owner": lease.owner, "token": lease.token, "pacer_owner": lease.pacer_owner,
                "background_percent": lease.background_percent,
                "expires_at": time.monotonic() + self.PRIORITY_FOCUS_SECONDS,
            }
            try:
                for name, mod in tuple(self.modules.items()):
                    self._sync_priority_scan_module(name, mod)
            except BaseException:
                self._end_priority_scan_focus(lease.token)
                raise

    def _renew_priority_scan_focus(self, lease) -> bool:
        """Memory-only best effort; safe for an app-owned UI timer."""
        from angerona.core.background_pacing import get_pacing_controller

        if not self._module_control_lock.acquire(blocking=False):
            return False
        try:
            focus = self._priority_scan_focus
            if (focus is None or focus["token"] is not lease.token or self._shutdown
                    or self._ugcap_paused or focus["expires_at"] <= time.monotonic()):
                return False
            try:
                renewed = get_pacing_controller().begin_priority_focus(
                    lease.pacer_owner, lease.background_percent,
                    seconds=self.PRIORITY_FOCUS_SECONDS, blocking=False)
            except RuntimeError:
                return False  # A newer routine-pacing owner cannot be displaced.
            if not renewed:
                return False
            focus["expires_at"] = time.monotonic() + self.PRIORITY_FOCUS_SECONDS
            for name, mod in tuple(self.modules.items()):
                self._sync_priority_scan_module(name, mod, blocking=False)
            return True
        finally:
            self._module_control_lock.release()

    def _end_priority_scan_focus(self, token) -> None:
        from angerona.core.background_pacing import get_pacing_controller

        with self._module_control_lock:
            focus = self._priority_scan_focus
            if focus is None or focus["token"] is not token:
                return
            self._priority_scan_focus = None
            known, self._priority_scan_modules = self._priority_scan_modules, {}
            get_pacing_controller().end_priority_focus(focus["pacer_owner"])
            for mod in known.values():
                BaseModule.set_priority_throttle(mod, 1.0)

    def cancel_priority_scan_focus(self) -> None:
        with self._module_control_lock:
            if self._priority_scan_focus is not None:
                self._end_priority_scan_focus(self._priority_scan_focus["token"])

    def priority_scan_focus_snapshot(self) -> dict:
        if not self._module_control_lock.acquire(blocking=False):
            return {"active": None, "state": "policy-update-in-progress"}
        try:
            focus = self._priority_scan_focus
            if focus is None or focus["expires_at"] <= time.monotonic():
                return {"active": False}
            return {"active": True, "owner": focus["owner"],
                    "requested_background_percent": focus["background_percent"],
                    "affected_modules": len(self._priority_scan_modules),
                    "remaining_seconds": max(0.0, focus["expires_at"] - time.monotonic()),
                    "scope": "reviewed analysis cadence; critical intake/control unchanged; not a CPU quota"}
        finally:
            self._module_control_lock.release()

    def _construct_module(self, cls: type) -> BaseModule:
        """Construct one module and bind application-owned security services.

        The optional factory keeps production composition explicit and testable.
        Independent high-water authority is offered only to bundled modules;
        an external drop-in never receives this privileged service implicitly.
        """
        provider = self.high_water_provider
        binding = _high_water_binding_kind(cls) if provider is not None else None
        if self._module_factory is not None:
            # Preserve the public factory(cls) contract. A custom factory must
            # compose constructor-time consumers before they admit local state.
            instance = self._module_factory(cls)
        elif binding == "constructor":
            instance = cls(high_water=provider)
        else:
            instance = cls()
        if not isinstance(instance, BaseModule):
            raise TypeError("module factory did not return a BaseModule")
        if binding is not None and type(instance) is not cls:
            raise TypeError("independent high-water consumer factory changed the bundled class")
        if binding == "constructor" and instance.high_water_provider is not provider:
            raise ValueError("module factory omitted constructor-time independent high-water authority")
        if binding == "binder":
            instance.bind_high_water(provider)
        return instance

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
            if self._ugcap_deferred_discovery and name not in {"ugcap_guard", "adversary_combat"}:
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
                if self._ugcap_verified_files:
                    source = _source_path(name)
                    if source is None:
                        raise RuntimeError("attested source is unavailable")
                    self._verified_source_digest(source)
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
        if self._ugcap_deferred_discovery:
            return []
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
                if self.bus is not None and self.bus.mesh_required:
                    attested, _digest = self._verified_source_bytes(path)
                    if decision.source_bytes != attested:
                        raise ImportError("external source differs from the UGCAP byte snapshot")
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
        return self.module_usage(name).enabled

    def module_usage(self, name: str):
        module = self.modules[name]
        usage = usage_for(module, self.config, self.platform,
                          kernel_installed=self._kernel_installed)
        if self._ugcap_guard_required(module) and usage.eligible:
            return ModuleUsage(True, True, True, "enabled",
                "UGCAP integrity policy requires its challenge and cadence service.")
        return usage

    def _ugcap_guard_required(self, module: BaseModule) -> bool:
        return (module_identity(module) == ("angerona.modules.ugcap_guard", "UGCAPGuardModule")
                and (getattr(self.config, "ugcap_enabled", False) is True or self._ugcap_paused))

    def reconcile_usage(self) -> None:
        """Apply changed opt-in policy without waking paused/failed detectors.

        Called by existing GUI/headless ticks and immediately after settings or
        drill policy changes. No probes, extra polling thread or settings writes.
        Only policy transitions start workers; watchdog remains recovery owner.
        """
        with self._module_control_lock:
            if not self._runtime_active or self._shutdown:
                return
            for name, mod in tuple(self.modules.items()):
                if not has_optional_policy(mod):
                    continue
                enabled = self.is_enabled(name)
                previous = self._optional_enabled.get(name, False)
                self._optional_enabled[name] = enabled
                if previous != enabled:
                    mod.start() if enabled and self._ugcap_allows(mod) else mod.stop()

    @property
    def ugcap_paused(self) -> bool:
        return self._ugcap_paused

    def _ugcap_allows(self, mod: BaseModule) -> bool:
        if not self._ugcap_paused or _is_ugcap_control(mod):
            return True
        self._ugcap_held.add(mod.name)
        mod.set_health(min(mod.health, 40), self._ugcap_reason)
        return False

    def pause_for_ugcap(self, reason: str) -> dict:
        """Hold managed workers; retain the integrity UI and response broker."""
        with self._module_control_lock:
            self._ugcap_paused = True
            self._ugcap_reason = str(reason)[:160]
            for mod in tuple(self.modules.values()):
                if _is_ugcap_control(mod):
                    continue
                if mod.status in {"running", "starting"}:
                    self._ugcap_held.add(mod.name)
                    mod.stop()
            return {"paused": True, "held": sorted(self._ugcap_held),
                    "scope": "managed-workers; in-flight OS calls may still retire"}

    def resume_after_ugcap(self, *, permit=None) -> dict:
        """Prepare trusted modules while closed, then commit one small gate-open.

        Production supplies permit(open_gate), which checks its authorization
        epoch under the guard's own state lock. No imports, hashing or starts
        happen under that lock or the manager's operator-control mutex.
        """
        with self._ugcap_resume_lock:
            if self._ugcap_deferred_discovery:
                if not self._ugcap_verified_files or self._ugcap_finder is None:
                    raise RuntimeError("UGCAP source attestation has not activated")
                previous_errors = len(self.discovery_errors)
                self._ugcap_preparing_thread = threading.get_ident()
                self._ugcap_deferred_discovery = False
                try:
                    self.discover(continue_bootstrap=True)
                except Exception:
                    self._ugcap_deferred_discovery = True
                    self.bus.freeze_mesh()
                    raise
                finally:
                    self._ugcap_preparing_thread = None
                if len(self.discovery_errors) != previous_errors:
                    self._ugcap_deferred_discovery = True
                    self._ugcap_reason = "UGCAP deferred discovery could not establish source/mesh trust"
                    self.bus.freeze_mesh()
                    raise RuntimeError(self._ugcap_reason)
                with self._module_control_lock:
                    self._ugcap_held.update(self.modules)
            with self._module_control_lock:
                def open_gate():
                    self._ugcap_paused = False
                    self._ugcap_reason = ""
                approved = not self._shutdown
                if approved and permit is not None:
                    try:
                        approved = permit(open_gate) is True
                    except Exception:
                        self._ugcap_paused = True
                        self.bus.freeze_mesh()
                        raise
                elif approved:
                    open_gate()
                if not approved or self._ugcap_paused:
                    self._ugcap_paused = True
                    self.bus.freeze_mesh()
                    return {"paused": True, "resumed": []}
                held = tuple(self._ugcap_held)
                self._ugcap_held.clear()
                generation = self._control_generation
            resumed = []
            for name in held:
                mod = self.modules.get(name)
                if mod is not None and self._start_current(mod, generation):
                    resumed.append(name)
            return {"paused": self._ugcap_paused, "resumed": sorted(resumed)}

    def _verified_source_digest(self, source: Path) -> str:
        return self._verified_source_bytes(source)[1]

    def _verified_source_bytes(self, source: Path) -> tuple[bytes, str]:
        from blake3 import blake3
        if self._ugcap_repository is None:
            raise RuntimeError("attested repository is unavailable")
        # Preserve the requested lexical name: resolve() before this check can
        # turn an unlisted symlink into a listed source and bless the redirect.
        source = Path(os.path.abspath(os.fspath(source)))
        relative = source.relative_to(self._ugcap_repository).as_posix()
        expected = self._ugcap_verified_files.get(relative)
        if not isinstance(expected, str) or len(expected) != 64:
            raise RuntimeError("module source is outside the verified manifest")
        from angerona.core.source_sandbox import _read_bytes
        content = _read_bytes(source, root=self._ugcap_repository)
        if blake3(content).hexdigest() != expected:
            raise RuntimeError("source changed after the user integrity challenge")
        return content, expected

    def _enroll_mesh_module(self, module: BaseModule) -> None:
        source = Path(inspect.getfile(type(module)))
        control = _is_ugcap_control(module)
        if control and getattr(module, "_mesh_publishers", None):
            return
        if self._ugcap_verified_files:
            digest = self._verified_source_digest(source)
        elif control:
            # The externally trusted bootstrap is the TCB, not a golden match.
            from angerona.core.source_sandbox import _read_bytes
            digest = hashlib.sha256(_read_bytes(source,
                root=Path(os.path.abspath(__file__)).parents[3])).hexdigest()
        else:
            raise RuntimeError("non-bootstrap module cannot enroll before attestation")
        names = [module.name]
        if module.name == "Active Response SOAR":
            names.append("Active Response SOAR Request")
        module._mesh_publishers = {name: self.bus.enroll_mesh_publisher(name, digest, control=control)
                                   for name in names}

    def activate_enclave_mesh(self, report: dict) -> bool:
        receipt = report.get("verification_receipt") if isinstance(report, dict) else None
        if (not isinstance(report, dict) or report.get("status") != "verified" or not isinstance(receipt, dict)
                or any(not isinstance(report.get(name), str) or not _UGCAP_TOKEN.fullmatch(report[name])
                       or receipt.get(name) != report[name] for name in ("report_id", "generation"))
                or not isinstance(report.get("source_manifest_digest"), str)
                or not _UGCAP_DIGEST.fullmatch(report["source_manifest_digest"])
                or receipt.get("source_manifest_digest") != report["source_manifest_digest"]):
            raise RuntimeError("verified source receipt is missing")
        files = receipt.get("verified_files")
        if (not isinstance(files, dict) or not files
                or any(not isinstance(path, str) or not path or not isinstance(digest, str)
                       or not _UGCAP_DIGEST.fullmatch(digest) for path, digest in files.items())
                or ("verified_files" in report and report["verified_files"] != files)):
            raise RuntimeError("verified source receipt has an invalid source map")
        for name in ("repository", "vault_path"):
            value = receipt.get(name)
            if (not isinstance(value, str) or not value or not Path(value).is_absolute()
                    or (name in report and report[name] != value)):
                raise RuntimeError("verified source receipt has inconsistent installation/vault context")
        expected_root = Path(os.path.abspath(__file__)).parents[3]
        root = Path(os.path.abspath(receipt.get("repository", "")))
        if root != expected_root:
            raise RuntimeError("verified source receipt names another installation")
        from angerona.core.source_sandbox import _validate_chain
        _validate_chain(root)
        self._ugcap_repository = root
        self._ugcap_verified_files = dict(receipt["verified_files"])
        if self.requires_ugcap_restart:
            raise RuntimeError("UGCAP requires a fresh process: ordinary modules were loaded without source attestation")
        for relative in ("src/angerona/core/eventbus.py", "src/angerona/core/module_base.py",
                         "src/angerona/core/module_manager.py", "src/angerona/core/enclave_mesh.py",
                         "src/angerona/core/ugcap_worker.py", "src/angerona/core/ugcap.py",
                         "src/angerona/core/ugcap_hardware.py", "src/angerona/modules/ugcap_guard.py",
                         "src/angerona/modules/adversary_combat.py"):
            self._verified_source_digest(root / relative)
        if self._ugcap_finder is None:
            self._ugcap_finder = _AttestedSourceFinder(self)
            sys.meta_path.insert(0, self._ugcap_finder)
        self.bus.activate_mesh(admission_gate=lambda: not self._ugcap_paused and not self._shutdown)
        for module in self.modules.values():
            if not _is_ugcap_control(module):
                self._enroll_mesh_module(module)
        return True

    @property
    def requires_ugcap_restart(self) -> bool:
        """A disk match cannot attest already executed ordinary Python code."""
        for name, module in tuple(sys.modules.items()):
            if (not name.startswith("angerona.modules.") or name in _UGCAP_BOOTSTRAP
                    or module is None):
                continue
            marker = getattr(module, "_angerona_attested_load", None)
            if not marker or self._ugcap_repository is None or marker[0] != str(self._ugcap_repository):
                return True
            source = getattr(module, "__file__", None)
            try:
                relative = Path(os.path.abspath(source)).relative_to(self._ugcap_repository).as_posix()
            except (TypeError, ValueError):
                return True
            if marker[1] != self._ugcap_verified_files.get(relative):
                return True
        return False

    def freeze_enclave_mesh(self) -> None:
        self.bus.freeze_mesh()

    def _start_current(self, mod: BaseModule, generation: int) -> bool:
        with self._module_control_lock:
            if (generation != self._control_generation or self._shutdown
                    or self.modules.get(mod.name) is not mod
                    or not self.is_enabled(mod.name) or not self._ugcap_allows(mod)):
                return False
            mod.start()
            return True

    def start_if_enabled(self, mod: BaseModule) -> bool:
        """Wake only the current, selected instance; never revive shutdown."""
        return self._start_current(mod, self._control_generation)

    # Safety-critical modules must come up immediately — never staggered.
    _NO_STAGGER = {
        "Watchdog Monitor",
        "Anti-Suspension Heartbeat",
        "Adversary Combat",
        "UGCAP Integrity Guard",
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
        "Zero-Trust Network Path Monitor",
        "ETW Core Listener",
        "ETW Real-Time Process Sensor",
        "AMSI Bridge",
        "AV Telemetry Bridge",
        "Audit Log Integrity Guard",
        "SSH Surface / Key / Tunnel Guard",
        # These consumers subscribe to the authenticated EventBus. Starting
        # them late would create a blind interval precisely where an early SSH,
        # identity, tunnel, or log-clear sequence could be lost.
        "Temporal Tradecraft Correlator",
        "Identity Session Guard",
        # The lease audit surface is lightweight and is part of the default
        # deny/attest network boundary, so it comes online with the edge plane.
        "Process Egress Lease Guard",
        "Removable-Media / USB Monitor",
    }

    def start_enabled(
        self,
        deferred_names: set[str] | None = None,
        *,
        sequential_cycles: bool = True,
        cycle_timeout: float = 30.0,
        min_settle: float = 0.10,
        progress: Callable[[int, int, str], None] | None = None,
    ) -> list[str]:
        """Start enabled modules without creating a first-scan stampede.

        Safety-critical response modules are brought online immediately. Remaining
        modules start one at a time and, by default, must reach a real first-cycle
        boundary before the next module starts. A bounded timeout prevents one
        broken sensor from blocking the entire suite forever.

        Returning the skipped names lets Eco Mode wake exactly those modules later.
        Deferred modules never create a thread or begin their first scan. The
        optional progress callback receives ``(completed, total, module_name)``;
        callback failures never weaken or interrupt module startup.
        """
        with self._module_control_lock:
            self._control_generation += 1
            generation = self._control_generation
            self._runtime_active = True
            self._shutdown = False
            self._optional_enabled = {
                name: self.is_enabled(name) for name, mod in self.modules.items()
                if has_optional_policy(mod)
            }
        deferred = set(deferred_names or ())
        skipped: list[str] = []
        critical: list[BaseModule] = []
        staged: list[BaseModule] = []
        for name, mod in tuple(self.modules.items()):
            if not self.is_enabled(name):
                continue
            if name in deferred:
                skipped.append(name)
                continue
            if name in self._NO_STAGGER:
                critical.append(mod)
            else:
                staged.append(mod)

        total = len(critical) + len(staged)
        completed = 0

        def _report(mod: BaseModule) -> None:
            if progress is None:
                return
            try:
                progress(completed, total, mod.name)
            except Exception:
                pass

        # Do not make containment, IPC protection, or the watchdog wait behind a
        # slow scanner. These modules are intentionally lightweight.
        for mod in critical:
            if not self._start_current(mod, generation):
                continue
            completed += 1
            _report(mod)

        for mod in staged:
            if not self._start_current(mod, generation):
                continue
            completed += 1
            _report(mod)
            if not sequential_cycles:
                continue
            waiter = getattr(mod, "wait_for_first_cycle", None)
            if callable(waiter):
                timeout = max(
                    0.1,
                    float(getattr(mod, "startup_cycle_timeout", cycle_timeout)),
                )
                ready = bool(waiter(timeout=timeout))
                with self._module_control_lock:
                    current = (generation == self._control_generation
                               and not self._shutdown
                               and self.modules.get(mod.name) is mod
                               and self.is_enabled(mod.name))
                if not ready and current:
                    mod.set_health(
                        min(int(getattr(mod, "health", 100)), 40),
                        f"startup cycle did not complete within {timeout:.1f}s",
                    )
                    mod.emit(
                        "Capability startup deadline elapsed before a completed work cycle.",
                        Severity.MEDIUM,
                        finding_code="module.lifecycle.startup_timeout",
                        response_authorized=False,
                    )
            # Keep adjacent setup work from landing in the same scheduler slice,
            # even when a module completes almost instantly.
            if min_settle > 0:
                time.sleep(min_settle)
        return skipped

    def set_enabled(
        self, name: str, enabled: bool, *,
        start_admission: Callable[[BaseModule], bool] | None = None,
    ) -> None:
        """Persist selection, optionally veto startup after the save completes.

        The callback runs under the lifecycle lock and must be a quick policy
        check. It cannot grant startup authority, change required-guard selection,
        or stop an already-running worker merely by returning False.
        This revalidates admission; it does not make external policy setters
        atomic with the whole start call or preempt an entered native operation.
        """
        with self._module_control_lock:
            mod = self.modules.get(name)
            if not mod:
                return
            if self._ugcap_guard_required(mod):
                enabled = True
            platform = availability_for(mod, self.platform)
            if enabled and not platform.available:
                mod.status = "unavailable"
                mod.set_health(0, platform.reason)
                return
            generation = self._control_generation
            self.config.module_states[name] = enabled
            self.config.save()
            effective = self.is_enabled(name)
            if has_optional_policy(mod):
                self._optional_enabled[name] = effective
            if effective and not self._shutdown and self._ugcap_allows(mod):
                if start_admission is not None:
                    if start_admission(mod) is not True:
                        return
                    # A veto callback cannot override manager authority, even
                    # if its own execution changes a policy or registration.
                    if (self._shutdown or generation != self._control_generation
                            or self.modules.get(name) is not mod
                            or not self.is_enabled(name) or not self._ugcap_allows(mod)):
                        return
                mod.start()
            else:
                mod.stop()

    def restart_module_generation(
        self,
        name: str,
        expected_module: BaseModule,
        expected_generation: int,
    ) -> bool:
        """Restart only the still-enabled, still-registered observed worker.

        This is the watchdog's sole restart authority.  It prevents a stale
        sweep from acting on a replacement object, a newer lifecycle
        generation, or an operator-disabled capability.
        """
        with self._module_control_lock:
            current = self.modules.get(name)
            if (self._shutdown or current is not expected_module
                    or not self.is_enabled(name) or not self._ugcap_allows(current)):
                return False
            restart = getattr(current, "restart_if_generation", None)
            if not callable(restart):
                return False
            return bool(restart(int(expected_generation)))

    def stop_all(self) -> None:
        with self._module_control_lock:
            self.cancel_priority_scan_focus()
            self._control_generation += 1
            self._runtime_active = False
            self._shutdown = True
            for mod in tuple(self.modules.values()):
                mod.stop()
            if self.bus is not None:
                self.bus.close_mesh()
            if self._ugcap_finder in sys.meta_path:
                sys.meta_path.remove(self._ugcap_finder)

    # ── Enterprise trust/readiness inventory ───────────────────────────────
    def capability_inventory(self) -> List[dict[str, Any]]:
        """Return a stable, serialisable trust inventory for UI/API/export."""
        rows: List[dict[str, Any]] = []
        for name in sorted(self.modules):
            mod = self.modules[name]
            trust = dict(self.module_trust.get(name, {}))
            contract = getattr(mod, "_angerona_contract", None)
            if contract is None:
                fallback_id = trust.get("capability_id") or (
                    f"angerona.runtime.{type(mod).__module__.rsplit('.', 1)[-1]}."
                    f"{type(mod).__name__.casefold()}"
                )
                try:
                    contract = build_capability_contract(
                        mod,
                        capability_id=str(fallback_id),
                        origin=str(trust.get("origin", "runtime")),
                        trust=str(trust.get("trust", "unclassified")),
                        publisher=str(trust.get("publisher", "runtime")),
                    )
                    setattr(mod, "_angerona_contract", contract)
                except ContractError:
                    contract = None
            operational = mod.operational_snapshot()
            platform = availability_for(mod, self.platform)
            enabled = bool(self.is_enabled(name))
            assurance = assess_capability(
                mod,
                contract=contract,
                operational=operational,
                platform=self.platform,
                enabled=enabled,
            )
            trust.update(
                {
                    "name": name,
                    "category": str(getattr(mod, "category", "General")),
                    "status": str(getattr(mod, "status", "unknown")),
                    "health": int(getattr(mod, "health", 0)),
                    "enabled": enabled,
                    "usage": self.module_usage(name).as_dict(),
                    "operational": operational,
                    "assurance": assurance.as_dict(),
                    "assurance_score": assurance.score,
                }
            )
            if contract is not None:
                contract_dict = contract.as_dict()
                trust.update(
                    {
                        "contract": contract_dict,
                        "contract_schema": contract.schema,
                        "contract_schema_version": contract.schema_version,
                        "implementation_version": contract.implementation_version,
                        "maturity": contract.maturity,
                        "metadata_level": contract.metadata_level,
                        "response_authority": contract.response_authority,
                        "self_test": contract.self_test,
                        "metadata_gaps": list(contract.metadata_gaps),
                    }
                )
            trust.update(platform.as_dict())
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
