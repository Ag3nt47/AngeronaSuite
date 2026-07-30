"""Signed, offline-first lifecycle for reviewed Angerona extensions.

Activation only moves already verified source/manifest pairs into the external
module directory. It never imports or executes plugin code; ModuleManager still
re-verifies exact bytes before import on the next restart.
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import stat
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

from angerona.core.archive_safety import safe_archive_path
from angerona.core.capability_manifest import (
    manifest_path_for,
    verify_external_module,
)

_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
MAX_CATALOG = 2 * 1024 * 1024
_RECORD_FIELDS = frozenset(
    {
        "capability_id",
        "name",
        "version",
        "publisher",
        "source_digest",
        "entrypoint",
        "state",
        "staged_at",
        "activated_at",
        "reason",
    }
)
_STATES = frozenset({"staged", "active", "revoked"})


def _no_duplicate_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate plugin catalog field: {key}")
        value[key] = item
    return value


def _is_reparse_point(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(attributes & reparse_flag)


def _safe_entrypoint(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 260:
        raise ValueError("plugin entrypoint must be a bounded filename")
    try:
        portable = safe_archive_path(value)
    except ValueError as exc:
        raise ValueError("plugin entrypoint must be a portable filename") from exc
    if len(portable.parts) != 1 or portable.suffix.casefold() != ".py":
        raise ValueError("plugin entrypoint must be one Python filename")
    return portable.name


def _bounded_text(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str) or len(value) > maximum or "\x00" in value:
        raise ValueError(f"plugin {field} must be a bounded string")
    return value


def _timestamp(value: float | None) -> float:
    stamp = time.time() if value is None else float(value)
    if not math.isfinite(stamp) or stamp < 0:
        raise ValueError("plugin lifecycle timestamp is invalid")
    return stamp


def _validate_record(key: str, value: Any) -> dict[str, Any]:
    if not isinstance(key, str) or not _ID.fullmatch(key):
        raise ValueError("plugin catalog contains an invalid capability ID")
    if type(value) is not dict or set(value) != _RECORD_FIELDS:
        raise ValueError("plugin catalog record schema is invalid")
    if value["capability_id"] != key:
        raise ValueError("plugin catalog key and capability ID differ")
    name = _bounded_text(value["name"], "name", 256)
    version = _bounded_text(value["version"], "version", 128)
    publisher = _bounded_text(value["publisher"], "publisher", 256)
    reason = _bounded_text(value["reason"], "reason", 2000)
    digest = value["source_digest"]
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise ValueError("plugin catalog source digest is invalid")
    entrypoint = _safe_entrypoint(value["entrypoint"])
    state_value = value["state"]
    if state_value not in _STATES:
        raise ValueError("plugin catalog state is invalid")
    timestamps: list[float] = []
    for field in ("staged_at", "activated_at"):
        raw = value[field]
        if type(raw) not in (int, float):
            raise ValueError(f"plugin catalog {field} is invalid")
        stamp = float(raw)
        if not math.isfinite(stamp) or stamp < 0:
            raise ValueError(f"plugin catalog {field} is invalid")
        timestamps.append(stamp)
    return {
        "capability_id": key,
        "name": name,
        "version": version,
        "publisher": publisher,
        "source_digest": digest,
        "entrypoint": entrypoint,
        "state": state_value,
        "staged_at": timestamps[0],
        "activated_at": timestamps[1],
        "reason": reason,
    }


def _atomic_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + f".{os.getpid()}.{time.time_ns()}.tmp")
    try:
        with open(temp, "xb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


@dataclass(frozen=True)
class PluginRecord:
    capability_id: str
    name: str
    version: str
    publisher: str
    source_digest: str
    entrypoint: str
    state: str
    staged_at: float
    activated_at: float = 0
    reason: str = ""


class PluginLifecycle:
    def __init__(
        self,
        root: Path,
        active_dir: Path,
        trust_store: Path,
        *,
        verifier: Callable[..., Any] = verify_external_module,
    ) -> None:
        self.root = Path(root)
        self.active_dir = Path(active_dir)
        self.trust_store = Path(trust_store)
        self.staging = self.root / "staging"
        self.history = self.root / "history"
        self.quarantine = self.root / "quarantine"
        self.catalog_path = self.root / "catalog.json"
        self.verifier = verifier
        self.root.mkdir(parents=True, exist_ok=True)
        if _is_reparse_point(self.root):
            raise ValueError(f"plugin lifecycle directory is redirected: {self.root}")
        for path in (self.staging, self.history, self.quarantine, self.active_dir):
            path.mkdir(parents=True, exist_ok=True)
            if _is_reparse_point(path):
                raise ValueError(f"plugin lifecycle directory is redirected: {path}")

    @staticmethod
    def _confined(base: Path, *parts: str) -> Path:
        root = base.resolve()
        if _is_reparse_point(base):
            raise PermissionError("plugin path root is redirected")
        candidate = base.joinpath(*parts)
        try:
            candidate.resolve(strict=False).relative_to(root)
        except (OSError, ValueError) as exc:
            raise PermissionError("plugin path escapes its lifecycle root") from exc
        current = base
        for part in parts[:-1]:
            current = current / part
            if current.exists() and _is_reparse_point(current):
                raise PermissionError("plugin path contains a redirected directory")
        return candidate

    def _write_catalog(self, records: dict[str, dict[str, Any]]) -> None:
        validated = {key: _validate_record(key, record) for key, record in records.items()}
        encoded = json.dumps(
            {"schema_version": 1, "plugins": validated},
            sort_keys=True,
            indent=2,
            allow_nan=False,
        ).encode()
        if len(encoded) > MAX_CATALOG:
            raise ValueError("plugin catalog exceeds byte budget")
        temp = self.catalog_path.with_suffix(f".{os.getpid()}.tmp")
        with open(temp, "xb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, self.catalog_path)

    def _catalog(self) -> dict[str, dict[str, Any]]:
        if not self.catalog_path.exists():
            return {}
        if _is_reparse_point(self.catalog_path):
            raise ValueError("plugin catalog cannot be a symlink or reparse point")
        if self.catalog_path.stat().st_size > MAX_CATALOG:
            raise ValueError("plugin catalog exceeds byte budget")
        try:
            value = json.loads(
                self.catalog_path.read_text(encoding="utf-8"),
                object_pairs_hook=_no_duplicate_object,
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("plugin catalog is unreadable or malformed") from exc
        if (
            type(value) is not dict
            or set(value) != {"schema_version", "plugins"}
            or value["schema_version"] != 1
            or type(value["plugins"]) is not dict
            or len(value["plugins"]) > 4096
        ):
            raise ValueError("plugin catalog is invalid")
        return {key: _validate_record(key, record) for key, record in value["plugins"].items()}

    def stage(self, source: Path, *, now: float | None = None) -> PluginRecord:
        source = Path(source)
        decision = self.verifier(source, self.trust_store, allow_unsigned=False)
        if not decision.accepted or decision.manifest is None:
            raise PermissionError(f"plugin rejected: {decision.reason}")
        manifest = decision.manifest
        capability_id = manifest.capability_id
        if not _ID.fullmatch(capability_id):
            raise ValueError("invalid capability ID")
        entrypoint = _safe_entrypoint(manifest.entrypoint)
        stage_dir = self._confined(self.staging, capability_id)
        stage_dir.mkdir(parents=True, exist_ok=True)
        if _is_reparse_point(stage_dir):
            raise PermissionError("plugin staging directory is redirected")
        destination = self._confined(stage_dir, entrypoint)
        destination_manifest = manifest_path_for(destination)
        source_bytes = decision.source_bytes
        if source_bytes is None:
            raise PermissionError("verified source snapshot is unavailable")
        stamp = _timestamp(now)
        record = PluginRecord(
            capability_id,
            manifest.name,
            manifest.version,
            manifest.publisher,
            manifest.sha256,
            entrypoint,
            "staged",
            stamp,
        )
        _validate_record(capability_id, asdict(record))
        # Use the same parsed snapshot whose signature was checked. Reopening
        # the untrusted adjacent manifest here would create a verify/copy race.
        manifest_bytes = json.dumps(
            dict(manifest.raw),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        if len(manifest_bytes) > 256 * 1024:
            raise ValueError("plugin manifest exceeds byte budget")
        _atomic_bytes(destination, source_bytes)
        _atomic_bytes(destination_manifest, manifest_bytes)
        catalog = self._catalog()
        catalog[capability_id] = asdict(record)
        self._write_catalog(catalog)
        return record

    def activate(self, capability_id: str, *, now: float | None = None) -> PluginRecord:
        if not _ID.fullmatch(capability_id):
            raise ValueError("invalid capability ID")
        catalog = self._catalog()
        try:
            record = catalog[capability_id]
        except KeyError as exc:
            raise KeyError(capability_id) from exc
        if record["state"] != "staged":
            raise PermissionError("plugin is not in the staged state")
        entrypoint = _safe_entrypoint(record["entrypoint"])
        stage_dir = self._confined(self.staging, capability_id)
        source = self._confined(stage_dir, entrypoint)
        decision = self.verifier(source, self.trust_store, allow_unsigned=False)
        if not decision.accepted or decision.manifest is None:
            self._quarantine_pair(source, decision.reason)
            raise PermissionError(f"staged plugin failed revalidation: {decision.reason}")
        manifest = decision.manifest
        if (
            manifest.capability_id != capability_id
            or _safe_entrypoint(manifest.entrypoint) != entrypoint
            or manifest.sha256 != record["source_digest"]
        ):
            self._quarantine_pair(source, "staged plugin identity changed")
            raise PermissionError("staged plugin identity or digest changed")
        stamp = _timestamp(now)
        active = self._confined(self.active_dir, entrypoint)
        active_manifest = manifest_path_for(active)
        if active.exists():
            current = self.verifier(active, self.trust_store, allow_unsigned=False)
            if (
                not current.accepted
                or current.manifest is None
                or current.manifest.capability_id != capability_id
            ):
                raise PermissionError("active entrypoint belongs to another or invalid plugin")
            version = str(int(time.time_ns()))
            old = self.history / f"{capability_id}-{version}.py"
            shutil.copy2(active, old)
            shutil.copy2(active_manifest, manifest_path_for(old))
        os.replace(source, active)
        os.replace(manifest_path_for(source), active_manifest)
        record = PluginRecord(
            capability_id,
            manifest.name,
            manifest.version,
            manifest.publisher,
            manifest.sha256,
            manifest.entrypoint,
            "active",
            catalog[capability_id]["staged_at"],
            stamp,
        )
        catalog[capability_id] = asdict(record)
        self._write_catalog(catalog)
        return record

    def revoke(self, capability_id: str, reason: str) -> PluginRecord:
        if not isinstance(reason, str) or len(reason.strip()) < 8:
            raise ValueError("revocation requires a reason")
        catalog = self._catalog()
        if capability_id not in catalog:
            raise KeyError(capability_id)
        source = self._confined(
            self.active_dir,
            _safe_entrypoint(catalog[capability_id]["entrypoint"]),
        )
        self._quarantine_pair(source, reason)
        catalog[capability_id].update({"state": "revoked", "reason": reason[:1000]})
        self._write_catalog(catalog)
        return PluginRecord(**catalog[capability_id])

    def _quarantine_pair(self, source: Path, reason: str) -> None:
        resolved = source.resolve(strict=False)
        if not any(
            resolved.is_relative_to(root.resolve()) for root in (self.staging, self.active_dir)
        ):
            raise PermissionError("refusing to quarantine outside plugin roots")
        if source.exists():
            stamp = str(time.time_ns())
            target = self.quarantine / f"{source.stem}-{stamp}.py.disabled"
            os.replace(source, target)
            adjacent = manifest_path_for(source)
            if adjacent.exists():
                os.replace(adjacent, target.with_suffix(".manifest.disabled"))
            target.with_suffix(".reason.txt").write_text(str(reason)[:2000], encoding="utf-8")

    def records(self) -> tuple[PluginRecord, ...]:
        return tuple(PluginRecord(**value) for _key, value in sorted(self._catalog().items()))
