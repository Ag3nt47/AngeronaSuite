"""Conservative, source-anchored assurance for Angerona capabilities.

The assurance percentage is *not* a promise that a module catches a given
percentage of attacks.  It is the weakest currently observed assurance
dimension: declaration completeness, host availability, runtime health,
evidence continuity, and self-test depth.  Every deduction carries a bounded
reason and, for bundled source builds, a descriptor-verified module source
path, digest, and exact line suitable for a read-only red-highlight view.
"""
from __future__ import annotations

import ast
import hashlib
import inspect
import os
import re
import stat
import sys
import threading
import time
from collections import OrderedDict
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping

from angerona.core.module_base import _source_checkout_root
from angerona.core.platforms import availability_for


ASSURANCE_SCHEMA = "angerona.capability-assurance.v1"
_MAX_SOURCE_BYTES = 512 * 1024
_REPARSE_POINT = 0x400
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class SourceAnchor:
    """One verified declaration location in a bundled module source file."""

    source_state: str = "unavailable"
    source_path: str | None = None
    source_line: int | None = None
    source_sha256: str | None = None
    source_provenance: str = "source-less-runtime"
    class_line: int | None = None
    field_lines: tuple[tuple[str, int], ...] = ()

    def for_field(self, field: str | None = None) -> dict[str, object]:
        lines = dict(self.field_lines)
        line = lines.get(str(field), self.class_line or self.source_line)
        return {
            "source_state": self.source_state,
            "source_path": self.source_path,
            "source_line": line,
            "source_sha256": self.source_sha256,
            "source_provenance": self.source_provenance,
            "source_anchor": (
                f"class-field:{field}" if field in lines else "module-class-declaration"
            ),
        }


@dataclass(frozen=True)
class AssuranceDimension:
    dimension: str
    label: str
    score: int
    state: str
    explanation: str


@dataclass(frozen=True)
class AssuranceReason:
    code: str
    dimension: str
    dimension_score: int
    reason: str
    remediation: str
    source_state: str
    source_path: str | None
    source_line: int | None
    source_sha256: str | None
    source_provenance: str
    source_anchor: str


@dataclass(frozen=True)
class CapabilityAssurance:
    schema: str
    score: int
    interpretation: str
    dimensions: tuple[AssuranceDimension, ...]
    reasons: tuple[AssuranceReason, ...]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _unavailable_anchor(provenance: str = "source-less-runtime") -> SourceAnchor:
    return SourceAnchor(source_provenance=provenance)


def _safe_module_source(module: object) -> tuple[Path, str] | None:
    """Resolve only the exact loaded built-in module within this checkout."""
    if bool(getattr(sys, "frozen", False)):
        return None
    cls = type(module)
    module_name = str(getattr(cls, "__module__", ""))
    if not module_name.startswith("angerona.modules."):
        return None
    loaded = sys.modules.get(module_name)
    if loaded is None or getattr(loaded, cls.__name__, None) is not cls:
        return None
    root = _source_checkout_root()
    if root is None:
        return None
    try:
        candidate = Path(inspect.getfile(cls)).resolve(strict=True)
        module_file = Path(str(getattr(loaded, "__file__", ""))).resolve(strict=True)
        spec = getattr(loaded, "__spec__", None)
        spec_origin = Path(str(getattr(spec, "origin", ""))).resolve(strict=True)
        if candidate != module_file or candidate != spec_origin:
            return None
        relative = candidate.relative_to(root).as_posix()
        if not relative.startswith("src/angerona/modules/") or not relative.endswith(".py"):
            return None
        current = root
        for part in Path(relative).parts:
            current = current / part
            if current.is_symlink():
                return None
            is_junction = getattr(current, "is_junction", None)
            if callable(is_junction) and is_junction():
                return None
        info = candidate.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)
            or info.st_size > _MAX_SOURCE_BYTES
        ):
            return None
        return candidate, relative
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        return None


@lru_cache(maxsize=512)
def _cached_declaration_anchor(
    filename: str,
    relative: str,
    device: int,
    inode: int,
    size: int,
    modified_ns: int,
    class_name: str,
) -> SourceAnchor:
    """Read and parse one identity-pinned source declaration."""
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(filename, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or bool(getattr(before, "st_file_attributes", 0) & _REPARSE_POINT)
            or before.st_dev != device
            or before.st_ino != inode
            or before.st_size != size
            or before.st_mtime_ns != modified_ns
            or before.st_size > _MAX_SOURCE_BYTES
        ):
            return _unavailable_anchor("source-identity-rejected")
        chunks: list[bytes] = []
        remaining = _MAX_SOURCE_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(raw) > _MAX_SOURCE_BYTES
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
        ):
            return _unavailable_anchor("source-identity-changed")
        path_info = Path(filename).stat(follow_symlinks=False)
        if path_info.st_dev != after.st_dev or path_info.st_ino != after.st_ino:
            return _unavailable_anchor("source-path-changed")
        tree = ast.parse(raw, filename=filename)
        declarations = [
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == class_name
        ]
        if len(declarations) != 1:
            return _unavailable_anchor("declaration-not-unique")
        declaration = declarations[0]
        field_lines: dict[str, int] = {}
        for node in declaration.body:
            targets: list[ast.expr] = []
            if isinstance(node, ast.Assign):
                targets.extend(node.targets)
            elif isinstance(node, ast.AnnAssign):
                targets.append(node.target)
            for target in targets:
                if isinstance(target, ast.Name):
                    field_lines.setdefault(target.id, int(node.lineno))
        digest = hashlib.sha256(raw).hexdigest()
        if not _DIGEST_RE.fullmatch(digest):
            return _unavailable_anchor("source-digest-invalid")
        return SourceAnchor(
            source_state="available",
            source_path=relative,
            source_line=int(declaration.lineno),
            source_sha256=digest,
            source_provenance="verified-loaded-declaration",
            class_line=int(declaration.lineno),
            field_lines=tuple(sorted(field_lines.items())),
        )
    except (OSError, RuntimeError, SyntaxError, TypeError, ValueError):
        return _unavailable_anchor("source-read-failed")
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def declaration_anchor(module: object) -> SourceAnchor:
    """Return an immutable verified source anchor for one bundled capability."""
    anchor = _read_declaration_anchor(module)
    _DISPLAY_ANCHORS.remember(module, anchor)
    return anchor


def _read_declaration_anchor(module: object) -> SourceAnchor:
    resolved = _safe_module_source(module)
    if resolved is None:
        return _unavailable_anchor(
            "source-less-runtime" if bool(getattr(sys, "frozen", False))
            else "unverified-external-declaration"
        )
    candidate, relative = resolved
    try:
        info = candidate.stat(follow_symlinks=False)
        return _cached_declaration_anchor(
            str(candidate),
            relative,
            int(info.st_dev),
            int(info.st_ino),
            int(info.st_size),
            int(info.st_mtime_ns),
            type(module).__name__,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return _unavailable_anchor("source-stat-failed")


class _DisplayAnchorCache:
    """Bounded presentation snapshots; all filesystem work stays off the GUI.

    Expired snapshots are unavailable until reverified, and are never used as
    authority for source edits or response actions. One daemon drains requests
    so a slow volume cannot create a thread per capability/refresh.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: OrderedDict = OrderedDict()
        self._pending: OrderedDict = OrderedDict()
        self._worker: threading.Thread | None = None

    @staticmethod
    def _key(module: object) -> tuple:
        cls = type(module)
        loaded = sys.modules.get(cls.__module__)
        return (
            cls, id(loaded), getattr(loaded, cls.__name__, None) is cls,
            str(getattr(loaded, "__file__", "")),
            str(getattr(getattr(loaded, "__spec__", None), "origin", "")),
            bool(getattr(sys, "frozen", False)),
        )

    def remember(self, module: object, anchor: SourceAnchor) -> None:
        self._remember_key(self._key(module), anchor)

    def _remember_key(self, key: tuple, anchor: SourceAnchor) -> None:
        with self._lock:
            self._entries[key] = (time.monotonic(), anchor)
            self._entries.move_to_end(key)
            while len(self._entries) > 512:
                self._entries.popitem(last=False)

    def get(self, module: object) -> SourceAnchor:
        key = self._key(module)
        with self._lock:
            entry = self._entries.get(key)
            if entry is not None and time.monotonic() - entry[0] < 30.0:
                return entry[1]
            if key not in self._pending and len(self._pending) < 512:
                self._pending[key] = module
            if self._worker is None and self._pending:
                self._worker = threading.Thread(
                    target=self._drain, name="CapabilitySourceReader", daemon=True
                )
                self._worker.start()
        return _unavailable_anchor("source-verification-pending")

    def _drain(self) -> None:
        while True:
            with self._lock:
                if not self._pending:
                    self._worker = None
                    return
                key, module = next(iter(self._pending.items()))
            try:
                anchor = _read_declaration_anchor(module)
            except Exception:
                anchor = _unavailable_anchor("source-read-failed")
            self._remember_key(key, anchor)
            with self._lock:
                self._pending.pop(key, None)


_DISPLAY_ANCHORS = _DisplayAnchorCache()


def cached_declaration_anchor(module: object) -> SourceAnchor:
    """Return a recent display snapshot or queue verification without I/O."""
    return _DISPLAY_ANCHORS.get(module)


def _contract_value(contract: object, key: str, default: object = None) -> object:
    if isinstance(contract, Mapping):
        return contract.get(key, default)
    return getattr(contract, key, default)


def _bounded_score(value: object, default: int = 0) -> int:
    try:
        return max(0, min(100, int(value)))
    except (TypeError, ValueError, OverflowError):
        return default


def _nonnegative_int(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError, OverflowError):
        return 0


def _reason(
    *,
    code: str,
    dimension: str,
    score: int,
    reason: str,
    remediation: str,
    source: Mapping[str, object],
) -> AssuranceReason:
    return AssuranceReason(
        code=str(code)[:160],
        dimension=str(dimension)[:80],
        dimension_score=_bounded_score(score),
        reason=str(reason).replace("\x00", " ").strip()[:1000],
        remediation=str(remediation).replace("\x00", " ").strip()[:1000],
        source_state=str(source.get("source_state") or "unavailable")[:80],
        source_path=(
            str(source["source_path"])[:500]
            if isinstance(source.get("source_path"), str)
            else None
        ),
        source_line=(
            max(1, int(source["source_line"]))
            if isinstance(source.get("source_line"), int)
            else None
        ),
        source_sha256=(
            str(source["source_sha256"]).casefold()
            if _DIGEST_RE.fullmatch(str(source.get("source_sha256") or "").casefold())
            else None
        ),
        source_provenance=str(
            source.get("source_provenance") or "unavailable"
        )[:80],
        source_anchor=str(source.get("source_anchor") or "unavailable")[:160],
    )


def _runtime_source(
    evidence: object,
    anchor: SourceAnchor,
) -> Mapping[str, object]:
    """Prefer verified callsite evidence; otherwise label a declaration fallback."""
    if isinstance(evidence, Mapping):
        state = str(evidence.get("source_state") or "")
        provenance = str(evidence.get("source_provenance") or "")
        digest = str(evidence.get("source_sha256") or "").casefold()
        if (
            state == "available"
            and provenance == "verified-loaded-implementation"
            and isinstance(evidence.get("source_path"), str)
            and isinstance(evidence.get("source_line"), int)
            and _DIGEST_RE.fullmatch(digest)
        ):
            return {
                "source_state": state,
                "source_path": evidence.get("source_path"),
                "source_line": evidence.get("source_line"),
                "source_sha256": digest,
                "source_provenance": provenance,
                "source_anchor": "runtime-health-callsite",
            }
    return anchor.for_field(None)


def assess_capability(
    module: object,
    *,
    contract: object | None = None,
    operational: Mapping[str, object] | None = None,
    platform: str | None = None,
    enabled: bool = True,
    source_anchor: SourceAnchor | None = None,
) -> CapabilityAssurance:
    """Assess one capability without executing probes or changing host state."""
    contract = contract if contract is not None else getattr(module, "_angerona_contract", None)
    operational = dict(operational or {})
    anchor = source_anchor if source_anchor is not None else declaration_anchor(module)
    reasons: list[AssuranceReason] = []
    dimensions: list[AssuranceDimension] = []

    raw_gaps = _contract_value(contract, "metadata_gaps", ())
    try:
        gaps = tuple(str(item) for item in raw_gaps or ())
    except TypeError:
        gaps = ("contract",)
    declaration_score = max(20, 100 - (6 * len(gaps))) if gaps else 100
    dimensions.append(
        AssuranceDimension(
            "declaration",
            "Contract completeness",
            declaration_score,
            "complete" if not gaps else "metadata-gaps",
            (
                "All required capability declarations are explicit."
                if not gaps
                else f"{len(gaps)} required declaration(s) use compatibility defaults."
            ),
        )
    )
    for gap in gaps:
        reasons.append(
            _reason(
                code=f"assurance.contract.{gap}",
                dimension="declaration",
                score=declaration_score,
                reason=(
                    f"The module does not explicitly declare '{gap}'; the class "
                    "declaration line is shown because an absent field has no source line."
                ),
                remediation=(
                    f"Declare and test '{gap}' on this module instead of relying on "
                    "the compatibility default."
                ),
                source=anchor.for_field(gap),
            )
        )

    availability = availability_for(module, platform)
    platform_score = 100 if availability.available else 0
    dimensions.append(
        AssuranceDimension(
            "platform",
            "Host availability",
            platform_score,
            "available" if availability.available else "unavailable",
            availability.reason,
        )
    )
    if not availability.available:
        reasons.append(
            _reason(
                code="assurance.platform.unsupported",
                dimension="platform",
                score=platform_score,
                reason=availability.reason,
                remediation=(
                    "Use the capability on a declared platform or implement and verify a "
                    "native sensor for this host before counting it as protection."
                ),
                source=anchor.for_field("supported_platforms"),
            )
        )

    status = str(operational.get("status", getattr(module, "status", "unknown")))[:80]
    health = _bounded_score(operational.get("health", getattr(module, "health", 0)))
    if not availability.available:
        runtime_score = 0
        runtime_state = "unavailable"
        runtime_explanation = "The host platform cannot run this capability."
    elif not enabled:
        runtime_score = 0
        runtime_state = "disabled"
        runtime_explanation = "The capability is disabled by the current operator configuration."
        reasons.append(
            _reason(
                code="assurance.runtime.disabled",
                dimension="runtime",
                score=runtime_score,
                reason=runtime_explanation,
                remediation="Enable the module when its protection is required on this host.",
                source=anchor.for_field("enabled_by_default"),
            )
        )
    elif status != "running":
        runtime_score = 0
        runtime_state = status or "unknown"
        runtime_explanation = (
            f"Lifecycle status is '{status or 'unknown'}'; the capability is not currently live."
        )
        reasons.append(
            _reason(
                code="assurance.runtime.not-running",
                dimension="runtime",
                score=runtime_score,
                reason=runtime_explanation,
                remediation="Start the module and verify a completed work cycle.",
                source=anchor.for_field(None),
            )
        )
    elif "thread_alive" in operational and not bool(operational.get("thread_alive")):
        runtime_score = 0
        runtime_state = "thread-not-alive"
        runtime_explanation = (
            "Lifecycle status says running, but no live module thread was observed."
        )
        reasons.append(
            _reason(
                code="assurance.runtime.thread-not-alive",
                dimension="runtime",
                score=runtime_score,
                reason=runtime_explanation,
                remediation="Restart the module and verify thread liveness plus a completed work cycle.",
                source=anchor.for_field("run"),
            )
        )
        if health < 100:
            health_evidence = operational.get("health_evidence")
            note = str(operational.get("health_note") or "").strip()
            if isinstance(health_evidence, Mapping):
                note = str(health_evidence.get("reason") or note).strip()
            reasons.append(
                _reason(
                    code="assurance.runtime.health",
                    dimension="runtime",
                    score=health,
                    reason=note or f"The module also reports {health}% health.",
                    remediation="Open the highlighted health evidence and correct the reported condition.",
                    source=_runtime_source(health_evidence, anchor),
                )
            )
    else:
        runtime_score = health
        runtime_state = "healthy" if health == 100 else "degraded"
        runtime_explanation = (
            "The live module reports full runtime health."
            if health == 100
            else f"The live module reports {health}% runtime health."
        )
        if health < 100:
            health_evidence = operational.get("health_evidence")
            note = str(operational.get("health_note") or "").strip()
            if isinstance(health_evidence, Mapping):
                note = str(health_evidence.get("reason") or note).strip()
            reasons.append(
                _reason(
                    code="assurance.runtime.health",
                    dimension="runtime",
                    score=runtime_score,
                    reason=note or f"The module reports {health}% health without a diagnostic note.",
                    remediation="Open the highlighted evidence, correct the reported condition, and re-test.",
                    source=_runtime_source(health_evidence, anchor),
                )
            )
    dimensions.append(
        AssuranceDimension(
            "runtime", "Runtime health", runtime_score, runtime_state, runtime_explanation
        )
    )

    continuity_score = 100
    continuity_state = "complete"
    continuity_notes: list[str] = []
    if status == "running" and "first_cycle_complete" in operational:
        if not bool(operational.get("first_cycle_complete")):
            continuity_score = min(continuity_score, 60)
            continuity_state = "startup-unproven"
            continuity_notes.append("No completed work cycle has been observed for this generation.")
            reasons.append(
                _reason(
                    code="assurance.continuity.first-cycle",
                    dimension="continuity",
                    score=60,
                    reason=continuity_notes[-1],
                    remediation="Wait for or diagnose the first bounded sensor work cycle.",
                    source=anchor.for_field("run"),
                )
            )
    overflow_count = _nonnegative_int(operational.get("event_overflow_count", 0))
    if overflow_count:
        continuity_score = min(continuity_score, 55)
        continuity_state = "evidence-loss"
        continuity_notes.append(
            f"Event retention overflow has occurred {overflow_count} time(s); negative conclusions are incomplete."
        )
        reasons.append(
            _reason(
                code="assurance.continuity.event-loss",
                dimension="continuity",
                score=55,
                reason=continuity_notes[-1],
                remediation="Inspect load/retention pressure and re-establish a gap-free observation window.",
                source=_runtime_source(operational.get("health_evidence"), anchor),
            )
        )
    crash_count = _nonnegative_int(operational.get("crash_count", 0))
    if crash_count:
        continuity_score = min(continuity_score, 70)
        continuity_state = "crash-history"
        continuity_notes.append(
            f"This process lifetime records {crash_count} module crash(es)."
        )
        reasons.append(
            _reason(
                code="assurance.continuity.crash-history",
                dimension="continuity",
                score=70,
                reason=continuity_notes[-1],
                remediation="Inspect crash evidence and complete an uninterrupted verification window.",
                source=_runtime_source(operational.get("health_evidence"), anchor),
            )
        )
    dimensions.append(
        AssuranceDimension(
            "continuity",
            "Evidence continuity",
            continuity_score,
            continuity_state,
            " ".join(continuity_notes) or "No retained evidence-loss or crash marker is present.",
        )
    )

    self_test = str(_contract_value(contract, "self_test", "readiness-only"))
    verification_score = 100 if self_test == "module-specific" else 60
    dimensions.append(
        AssuranceDimension(
            "verification",
            "Self-test depth",
            verification_score,
            self_test,
            (
                "The module implements a capability-specific safe self-test."
                if verification_score == 100
                else "Only the shared lifecycle/readiness test is declared."
            ),
        )
    )
    if verification_score < 100:
        reasons.append(
            _reason(
                code="assurance.verification.readiness-only",
                dimension="verification",
                score=verification_score,
                reason=(
                    "This module relies on the shared readiness-only self-test; it does not "
                    "independently exercise its sensor or response contract."
                ),
                remediation="Add a bounded, non-destructive module-specific self_test implementation.",
                source=anchor.for_field("self_test"),
            )
        )

    score = min(item.score for item in dimensions)
    reasons.sort(key=lambda item: (item.dimension_score, item.dimension, item.code))
    return CapabilityAssurance(
        schema=ASSURANCE_SCHEMA,
        score=score,
        interpretation=(
            "Weakest-dimension implementation assurance; not attack coverage, "
            "breach probability, or a guarantee."
        ),
        dimensions=tuple(dimensions),
        reasons=tuple(reasons),
    )


__all__ = [
    "ASSURANCE_SCHEMA",
    "AssuranceDimension",
    "AssuranceReason",
    "CapabilityAssurance",
    "SourceAnchor",
    "assess_capability",
    "declaration_anchor",
]
