"""Version 12 machine-readable contracts for every defensive capability.

Product releases and capability implementations have independent versions.
The contract makes that distinction explicit and gives the GUI, CLI, tests and
readiness exports one bounded source of truth. Legacy modules are represented
honestly through a compatibility adapter; missing declarations become visible
metadata gaps instead of silently inheriting capabilities they may not have.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from typing import Any, Mapping

from angerona.core.platforms import KNOWN_PLATFORMS, normalize_platforms

CONTRACT_SCHEMA_VERSION = 12
CONTRACT_SCHEMA_ID = "angerona.capability-contract.v12"

_CAPABILITY_ID_RE = re.compile(r"^angerona\.[a-z0-9][a-z0-9._-]{2,126}$")
_SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_MODES = frozenset({"unknown", "observe", "detect", "protect", "respond"})
_AUTHORITIES = frozenset({"none", "propose", "typed-response"})
_MATURITY = frozenset({"stable", "preview", "experimental", "compatibility"})


class ContractError(ValueError):
    """A capability declaration is unsafe or not machine-readable."""


def _bounded_strings(values: object, field: str, *, limit: int = 64) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        candidates = (values,)
    else:
        try:
            candidates = tuple(values)  # type: ignore[arg-type]
        except TypeError as exc:
            raise ContractError(f"{field} must be a string collection") from exc
    if len(candidates) > limit:
        raise ContractError(f"{field} exceeds {limit} entries")
    result: list[str] = []
    for value in candidates:
        text = str(value).strip()
        if not text or len(text) > 160:
            raise ContractError(f"{field} contains an empty or oversized entry")
        if text not in result:
            result.append(text)
    return tuple(result)


def _settings_schema(value: object) -> dict[str, Any]:
    if value is None:
        return {"type": "object", "properties": {}, "additionalProperties": False}
    if not isinstance(value, Mapping):
        raise ContractError("settings_schema must be a mapping")
    result = dict(value)
    if result.get("type") != "object" or not isinstance(result.get("properties", {}), dict):
        raise ContractError("settings_schema must describe an object")
    result.setdefault("additionalProperties", False)
    try:
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ContractError("settings_schema must be JSON serialisable") from exc
    if len(encoded.encode("utf-8")) > 64 * 1024:
        raise ContractError("settings_schema exceeds 64 KiB")
    return result


@dataclass(frozen=True)
class ResourceBudget:
    worker_model: str = "undeclared"
    throttle_min: float = 1.0
    throttle_max: float = 8.0
    startup_cycle_timeout_seconds: float = 30.0
    event_delivery: str = "best-effort-undeclared"


@dataclass(frozen=True)
class CapabilityContract:
    schema: str
    schema_version: int
    capability_id: str
    implementation_version: str
    display_name: str
    description: str
    category: str
    maturity: str
    metadata_level: str
    mode: str
    supported_platforms: tuple[str, ...]
    platform_requirements: tuple[str, ...]
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    permissions: tuple[str, ...]
    high_risk_permissions: tuple[str, ...]
    data_classes: tuple[str, ...]
    egress: str
    retention: str
    response_authority: str
    dependencies: tuple[str, ...]
    conflicts: tuple[str, ...]
    source_health_semantics: tuple[str, ...]
    restart_policy: str
    loss_behavior: str
    self_test: str
    settings_schema: dict[str, Any]
    resource_budget: ResourceBudget
    metadata_gaps: tuple[str, ...]
    origin: str
    trust: str
    publisher: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _explicit(cls: type, attribute: str) -> bool:
    return attribute in cls.__dict__


def build_capability_contract(
    module: object,
    *,
    capability_id: str,
    origin: str = "builtin",
    trust: str = "release",
    publisher: str = "Angerona",
    manifest_permissions: object = (),
    manifest_high_risk_permissions: object = (),
) -> CapabilityContract:
    """Validate and return the v12 contract for one instantiated module."""
    cls = type(module)
    identifier = str(capability_id).strip().casefold()
    if not _CAPABILITY_ID_RE.fullmatch(identifier):
        raise ContractError(f"invalid capability_id: {capability_id!r}")

    version = str(getattr(module, "version", "")).strip()
    if not _SEMVER_RE.fullmatch(version):
        raise ContractError(f"{identifier} has invalid implementation version {version!r}")
    name = str(getattr(module, "name", "")).strip()
    description = str(getattr(module, "description", "")).strip()
    category = str(getattr(module, "category", "General")).strip() or "General"
    if not name or len(name) > 160 or len(description) > 4096 or len(category) > 80:
        raise ContractError(f"{identifier} has invalid display metadata")

    platforms = tuple(sorted(normalize_platforms(getattr(module, "supported_platforms", None))))
    if not platforms or any(item not in KNOWN_PLATFORMS for item in platforms):
        raise ContractError(f"{identifier} has no valid supported platform")
    mode = str(getattr(module, "capability_mode", "unknown")).strip().casefold()
    if mode not in _MODES:
        raise ContractError(f"{identifier} has invalid mode {mode!r}")

    self_test = "module-specific" if _explicit(cls, "self_test") else "readiness-only"
    explicit_fields = {
        "implementation_version": _explicit(cls, "version"),
        "supported_platforms": _explicit(cls, "supported_platforms"),
        "mode": _explicit(cls, "capability_mode"),
        "permissions": _explicit(cls, "capability_permissions") or origin == "external",
        "inputs": _explicit(cls, "capability_inputs"),
        "outputs": _explicit(cls, "capability_outputs"),
        "data_classes": _explicit(cls, "data_classes"),
        "egress": _explicit(cls, "egress"),
        "retention": _explicit(cls, "retention"),
        "response_authority": _explicit(cls, "response_authority"),
        "self_test": self_test == "module-specific",
        "settings_schema": _explicit(cls, "settings_schema"),
        "resource_budget": _explicit(cls, "resource_budget"),
        "restart_policy": _explicit(cls, "restart_policy"),
        "loss_behavior": _explicit(cls, "loss_behavior"),
    }
    gaps = tuple(key for key, declared in explicit_fields.items() if not declared)
    metadata_level = "native" if not gaps else "compatibility-adapter"

    maturity = str(
        getattr(module, "maturity_channel", "stable" if metadata_level == "native" else "compatibility")
    ).strip().casefold()
    if maturity not in _MATURITY:
        raise ContractError(f"{identifier} has invalid maturity {maturity!r}")
    authority = str(getattr(module, "response_authority", "none")).strip().casefold()
    if authority not in _AUTHORITIES:
        raise ContractError(f"{identifier} has invalid response authority {authority!r}")
    egress = str(getattr(module, "egress", "undeclared")).strip().casefold()
    if egress not in {"none", "optional", "required", "undeclared"}:
        raise ContractError(f"{identifier} has invalid egress declaration {egress!r}")

    permissions = (
        _bounded_strings(manifest_permissions, "permissions")
        if origin == "external"
        else _bounded_strings(getattr(module, "capability_permissions", ()), "permissions")
    )
    high_risk = (
        _bounded_strings(manifest_high_risk_permissions, "high_risk_permissions")
        if origin == "external"
        else _bounded_strings(
            getattr(module, "high_risk_permissions", ()), "high_risk_permissions"
        )
    )
    if any(item not in permissions for item in high_risk):
        raise ContractError(f"{identifier} high-risk permissions must be declared permissions")

    raw_budget = getattr(module, "resource_budget", {})
    if raw_budget is None:
        raw_budget = {}
    if not isinstance(raw_budget, Mapping):
        raise ContractError(f"{identifier} resource_budget must be a mapping")
    try:
        startup_timeout = float(
            raw_budget.get(
                "startup_cycle_timeout_seconds",
                getattr(module, "startup_cycle_timeout", 30.0),
            )
        )
        throttle_min = float(raw_budget.get("throttle_min", 1.0))
        throttle_max = float(raw_budget.get("throttle_max", 8.0))
    except (TypeError, ValueError, OverflowError) as exc:
        raise ContractError(f"{identifier} has invalid numeric resource budget") from exc
    if not (0.1 <= startup_timeout <= 300.0):
        raise ContractError(f"{identifier} startup timeout is outside 0.1..300 seconds")
    if not (1.0 <= throttle_min <= throttle_max <= 8.0):
        raise ContractError(f"{identifier} throttle budget is outside 1.0..8.0")
    worker_model = str(raw_budget.get("worker_model", "undeclared")).strip()
    event_delivery = str(
        raw_budget.get("event_delivery", "best-effort-undeclared")
    ).strip()
    if not worker_model or len(worker_model) > 160 or not event_delivery or len(event_delivery) > 160:
        raise ContractError(f"{identifier} resource budget labels are invalid")

    return CapabilityContract(
        schema=CONTRACT_SCHEMA_ID,
        schema_version=CONTRACT_SCHEMA_VERSION,
        capability_id=identifier,
        implementation_version=version,
        display_name=name,
        description=description,
        category=category,
        maturity=maturity,
        metadata_level=metadata_level,
        mode=mode,
        supported_platforms=platforms,
        platform_requirements=_bounded_strings(
            getattr(module, "platform_requirements", ()), "platform_requirements"
        ),
        inputs=_bounded_strings(getattr(module, "capability_inputs", ()), "inputs"),
        outputs=_bounded_strings(getattr(module, "capability_outputs", ()), "outputs"),
        permissions=permissions,
        high_risk_permissions=high_risk,
        data_classes=_bounded_strings(getattr(module, "data_classes", ()), "data_classes"),
        egress=egress,
        retention=str(getattr(module, "retention", "runtime-policy")).strip(),
        response_authority=authority,
        dependencies=_bounded_strings(getattr(module, "capability_dependencies", ()), "dependencies"),
        conflicts=_bounded_strings(getattr(module, "capability_conflicts", ()), "conflicts"),
        source_health_semantics=(
            "availability", "health", "health_note", "thread_liveness",
            "crash_count", "declared-continuity-only",
        ),
        restart_policy=str(
            getattr(module, "restart_policy", "runtime-observed-undeclared")
        )[:160],
        loss_behavior=str(
            getattr(module, "loss_behavior", "best-effort-undeclared")
        )[:160],
        self_test=self_test,
        settings_schema=_settings_schema(getattr(module, "settings_schema", None)),
        resource_budget=ResourceBudget(
            worker_model=worker_model,
            throttle_min=throttle_min,
            throttle_max=throttle_max,
            startup_cycle_timeout_seconds=startup_timeout,
            event_delivery=event_delivery,
        ),
        metadata_gaps=gaps,
        origin=str(origin),
        trust=str(trust),
        publisher=str(publisher),
    )
