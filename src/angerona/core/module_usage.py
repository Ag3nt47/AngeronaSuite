"""Cheap, explicit runtime selection; catalog membership is never coverage.

Only positive platform/optional-integration evidence parks a capability. A
failed sensor, absent permissions, quiet network or missing telemetry remains
an expected capability and therefore a visible coverage gap.
"""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass

from angerona.core.platforms import availability_for


_OPTIONAL_FLAGS = {
    ("angerona.modules.mobile_bridge", "MobileResponseBridge"): (
        "mobile_enabled", "Mobile integration is off in Settings."),
    ("angerona.modules.ebpf_sensor", "EbpfSensorNode"): (
        "ebpf_enabled", "eBPF integration is off in Settings."),
}
_SOAR = ("angerona.modules.soar_engine", "ActiveResponseSOAR")
_KERNEL = ("angerona.modules.kernel_bridge", "KernelBridgeModule")
_OPTIONAL_POLICIES = frozenset((*_OPTIONAL_FLAGS, _SOAR))


def module_identity(module: object) -> tuple[str, str]:
    cls = type(module)
    return cls.__module__, cls.__name__


def has_optional_policy(module: object) -> bool:
    return module_identity(module) in _OPTIONAL_POLICIES


def kernel_service_installed() -> bool | None:
    """One read-only installation probe; access failure is NOT absence.

    The manager samples this during discovery, never in a display refresh.
    An installed driver that subsequently fails remains expected protection.
    Explicitly enabling the bridge also overrides initial absence.
    """
    if os.name != "nt":
        return None
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\AngeronaSensor",
            0, winreg.KEY_READ,
        ):
            return True
    except FileNotFoundError:
        return False
    except OSError:
        return None


@dataclass(frozen=True)
class ModuleUsage:
    selected: bool
    eligible: bool
    enabled: bool
    state: str
    reason: str

    def as_dict(self) -> dict:
        return asdict(self)


def usage_for(module, config, platform=None, *, kernel_installed=None) -> ModuleUsage:
    states = getattr(config, "module_states", {})
    selected = states.get(module.name, getattr(module, "enabled_by_default", True)) is True
    availability = availability_for(module, platform)
    if not availability.available:
        return ModuleUsage(selected, False, False, "unsupported", availability.reason)
    identity = module_identity(module)
    flag = _OPTIONAL_FLAGS.get(identity)
    if flag and getattr(config, flag[0], False) is not True:
        return ModuleUsage(selected, False, False, "not_configured", flag[1])
    if identity == _SOAR and os.environ.get("ANGERONA_SOAR_KILL_AND_ROLLBACK") != "1":
        return ModuleUsage(selected, False, False, "not_configured",
                           "Active Response SOAR is not armed by operator policy.")
    if (identity == _KERNEL and kernel_installed is False
            and states.get(module.name) is not True):
        return ModuleUsage(selected, False, False, "not_installed",
                           "Optional AngeronaSensor driver is not installed. "
                           "Install it, then enable this module to request monitoring.")
    if not selected:
        return ModuleUsage(False, True, False, "disabled", "Off in module settings.")
    return ModuleUsage(True, True, True, "enabled", "Enabled for this machine.")


def enabled_module_items(manager):
    """Shared count policy; tolerate minimal legacy display adapters."""
    predicate = getattr(manager, "is_enabled", None)
    for name, module in tuple(getattr(manager, "modules", {}).items()):
        if callable(predicate):
            enabled = bool(predicate(name))
        else:
            enabled = getattr(module, "enabled_by_default", True) is True
        if enabled:
            yield name, module


def module_counts(manager) -> dict[str, int]:
    selected = list(enabled_module_items(manager))
    discovered = len(getattr(manager, "modules", {}))
    return {
        "enabled": len(selected),
        "running": sum(getattr(mod, "status", "") == "running" for _, mod in selected),
        "off": discovered - len(selected),
        "discovered": discovered,
    }


def reconcile_module_usage(manager) -> None:
    reconcile = getattr(manager, "reconcile_usage", None)
    if callable(reconcile):
        reconcile()


def start_module_if_enabled(manager, module) -> bool:
    """Route delayed UI wake/repair requests through manager lifecycle policy."""
    start = getattr(manager, "start_if_enabled", None)
    if callable(start):
        return bool(start(module))
    predicate = getattr(manager, "is_enabled", None)
    if callable(predicate) and not predicate(module.name):
        return False
    module.start()
    return True
