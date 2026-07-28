"""Platform capability contracts for Angerona.

Angerona's original modules were written for Windows.  Treating an imported
module as automatically portable is unsafe: a sensor that cannot observe its
advertised signal must never be counted as healthy protection.  This module
provides one canonical platform vocabulary and an explicit availability
contract used by discovery, lifecycle management, the GUI/API inventory, and
tests.

Bundled modules without an explicit declaration remain Windows-only.  New
cross-platform modules opt in with both a module-level declaration (so discovery
can avoid importing incompatible code) and the matching ``BaseModule`` class
attribute::

    SUPPORTED_PLATFORMS = ("windows", "macos", "linux")

    class ExampleModule(BaseModule):
        supported_platforms = SUPPORTED_PLATFORMS
"""
from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

WINDOWS = "windows"
MACOS = "macos"
LINUX = "linux"
KNOWN_PLATFORMS = frozenset({WINDOWS, MACOS, LINUX})
LEGACY_MODULE_PLATFORMS = frozenset({WINDOWS})

_ALIASES = {
    "win32": WINDOWS,
    "cygwin": WINDOWS,
    "msys": WINDOWS,
    "windows": WINDOWS,
    "darwin": MACOS,
    "mac": MACOS,
    "macos": MACOS,
    "osx": MACOS,
    "linux": LINUX,
    "linux2": LINUX,
}


def normalize_platform(value: str | None = None) -> str:
    """Return Angerona's canonical identifier for a runtime platform."""
    raw = (value if value is not None else sys.platform).strip().casefold()
    canonical = _ALIASES.get(raw)
    if canonical is None:
        # Unknown systems get their normalized Python platform name.  They will
        # not accidentally match any declared capability.
        return raw or "unknown"
    return canonical


def current_platform() -> str:
    return normalize_platform()


def normalize_platforms(
    values: Iterable[object] | object | None,
    *,
    default: frozenset[str] = LEGACY_MODULE_PLATFORMS,
) -> frozenset[str]:
    """Normalize one capability declaration, failing closed on bad values."""
    if values is None:
        return default
    if isinstance(values, str):
        candidates: Iterable[object] = (values,)
    else:
        try:
            candidates = tuple(values)  # type: ignore[arg-type]
        except TypeError:
            return default
    out = {
        normalize_platform(str(item))
        for item in candidates
        if str(item).strip()
    }
    return frozenset(item for item in out if item in KNOWN_PLATFORMS) or default


@dataclass(frozen=True)
class PlatformAvailability:
    platform: str
    supported_platforms: tuple[str, ...]
    available: bool
    mode: str
    reason: str
    requirements: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "platform": self.platform,
            "supported_platforms": list(self.supported_platforms),
            "available": self.available,
            "capability_mode": self.mode,
            "availability_reason": self.reason,
            "platform_requirements": list(self.requirements),
        }


def availability_for(module: object, platform: str | None = None) -> PlatformAvailability:
    target = normalize_platform(platform)
    supported = normalize_platforms(
        getattr(module, "supported_platforms", None)
    )
    mode = str(getattr(module, "capability_mode", "protect")).strip().casefold()
    if mode not in {"observe", "detect", "protect", "respond"}:
        mode = "detect"
    requirements = tuple(
        str(item).strip()
        for item in getattr(module, "platform_requirements", ())
        if str(item).strip()
    )
    available = target in supported
    if available:
        reason = (
            f"{mode.capitalize()} capability is available on {target}."
        )
    else:
        supported_text = ", ".join(sorted(supported))
        reason = (
            f"Unavailable on {target}; this capability supports "
            f"{supported_text or 'no declared platform'}."
        )
    return PlatformAvailability(
        platform=target,
        supported_platforms=tuple(sorted(supported)),
        available=available,
        mode=mode,
        reason=reason,
        requirements=requirements,
    )


def declared_platforms_from_source(path: Path) -> frozenset[str]:
    """Read a bundled module's import-safe platform declaration.

    The AST-only preflight is deliberately conservative.  It recognizes only a
    literal module-level ``SUPPORTED_PLATFORMS`` assignment.  Missing, dynamic,
    malformed, or unreadable declarations are treated as legacy Windows-only
    code, preventing an incompatible top-level import on macOS/Linux.
    """
    try:
        source = Path(path).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (OSError, UnicodeError, SyntaxError):
        return LEGACY_MODULE_PLATFORMS
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        if isinstance(node, ast.Assign):
            names = [
                target.id for target in node.targets
                if isinstance(target, ast.Name)
            ]
            value = node.value
        else:
            names = [node.target.id] if isinstance(node.target, ast.Name) else []
            value = node.value
        if "SUPPORTED_PLATFORMS" not in names or value is None:
            continue
        try:
            declared = ast.literal_eval(value)
        except (ValueError, TypeError):
            return LEGACY_MODULE_PLATFORMS
        return normalize_platforms(declared)
    return LEGACY_MODULE_PLATFORMS
