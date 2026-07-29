"""Signed, offline-first lifecycle for reviewed Angerona extensions.

Activation only moves already verified source/manifest pairs into the external
module directory. It never imports or executes plugin code; ModuleManager still
re-verifies exact bytes before import on the next restart.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

from angerona.core.capability_manifest import (
    manifest_path_for, verify_external_module,
)

_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
MAX_CATALOG = 2 * 1024 * 1024


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
        self, root: Path, active_dir: Path, trust_store: Path, *,
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
        for path in (self.staging, self.history, self.quarantine, self.active_dir):
            path.mkdir(parents=True, exist_ok=True)

    def _write_catalog(self, records: dict[str, dict[str, Any]]) -> None:
        encoded = json.dumps(
            {"schema_version": 1, "plugins": records},
            sort_keys=True, indent=2,
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
        value = json.loads(self.catalog_path.read_text(encoding="utf-8"))
        if value.get("schema_version") != 1 or not isinstance(value.get("plugins"), dict):
            raise ValueError("plugin catalog is invalid")
        if self.catalog_path.stat().st_size > MAX_CATALOG:
            raise ValueError("plugin catalog exceeds byte budget")
        return dict(value["plugins"])

    def stage(self, source: Path, *, now: float | None = None) -> PluginRecord:
        source = Path(source)
        decision = self.verifier(source, self.trust_store, allow_unsigned=False)
        if not decision.accepted or decision.manifest is None:
            raise PermissionError(f"plugin rejected: {decision.reason}")
        manifest = decision.manifest
        capability_id = manifest.capability_id
        if not _ID.fullmatch(capability_id):
            raise ValueError("invalid capability ID")
        stage_dir = self.staging / capability_id
        destination = stage_dir / manifest.entrypoint
        destination_manifest = manifest_path_for(destination)
        source_bytes = decision.source_bytes
        if source_bytes is None:
            raise PermissionError("verified source snapshot is unavailable")
        # Use the same parsed snapshot whose signature was checked. Reopening
        # the untrusted adjacent manifest here would create a verify/copy race.
        manifest_bytes = json.dumps(
            dict(manifest.raw), sort_keys=True, separators=(",", ":"),
        ).encode()
        if len(manifest_bytes) > 256 * 1024:
            raise ValueError("plugin manifest exceeds byte budget")
        _atomic_bytes(destination, source_bytes)
        _atomic_bytes(destination_manifest, manifest_bytes)
        stamp = time.time() if now is None else float(now)
        record = PluginRecord(
            capability_id, manifest.name, manifest.version, manifest.publisher,
            manifest.sha256, manifest.entrypoint, "staged", stamp,
        )
        catalog = self._catalog()
        catalog[capability_id] = asdict(record)
        self._write_catalog(catalog)
        return record

    def activate(self, capability_id: str, *, now: float | None = None) -> PluginRecord:
        if not _ID.fullmatch(capability_id):
            raise ValueError("invalid capability ID")
        catalog = self._catalog()
        try:
            entrypoint = str(catalog[capability_id]["entrypoint"])
        except KeyError as exc:
            raise KeyError(capability_id) from exc
        source = self.staging / capability_id / entrypoint
        decision = self.verifier(source, self.trust_store, allow_unsigned=False)
        if not decision.accepted or decision.manifest is None:
            self._quarantine_pair(source, decision.reason)
            raise PermissionError(f"staged plugin failed revalidation: {decision.reason}")
        active = self.active_dir / entrypoint
        active_manifest = manifest_path_for(active)
        if active.exists():
            current = self.verifier(
                active, self.trust_store, allow_unsigned=False
            )
            if (
                not current.accepted or current.manifest is None
                or current.manifest.capability_id != capability_id
            ):
                raise PermissionError(
                    "active entrypoint belongs to another or invalid plugin"
                )
            version = str(int(time.time_ns()))
            old = self.history / f"{capability_id}-{version}.py"
            shutil.copy2(active, old)
            shutil.copy2(active_manifest, manifest_path_for(old))
        os.replace(source, active)
        os.replace(manifest_path_for(source), active_manifest)
        stamp = time.time() if now is None else float(now)
        manifest = decision.manifest
        record = PluginRecord(
            capability_id, manifest.name, manifest.version, manifest.publisher,
            manifest.sha256, manifest.entrypoint, "active",
            catalog[capability_id]["staged_at"],
            stamp,
        )
        catalog[capability_id] = asdict(record)
        self._write_catalog(catalog)
        return record

    def revoke(self, capability_id: str, reason: str) -> PluginRecord:
        if len(reason.strip()) < 8:
            raise ValueError("revocation requires a reason")
        catalog = self._catalog()
        if capability_id not in catalog:
            raise KeyError(capability_id)
        source = self.active_dir / str(catalog[capability_id]["entrypoint"])
        self._quarantine_pair(source, reason)
        catalog[capability_id].update({"state": "revoked", "reason": reason[:1000]})
        self._write_catalog(catalog)
        return PluginRecord(**catalog[capability_id])

    def _quarantine_pair(self, source: Path, reason: str) -> None:
        if source.exists():
            stamp = str(time.time_ns())
            target = self.quarantine / f"{source.stem}-{stamp}.py.disabled"
            os.replace(source, target)
            adjacent = manifest_path_for(source)
            if adjacent.exists():
                os.replace(adjacent, target.with_suffix(".manifest.disabled"))
            target.with_suffix(".reason.txt").write_text(
                str(reason)[:2000], encoding="utf-8"
            )

    def records(self) -> tuple[PluginRecord, ...]:
        return tuple(
            PluginRecord(**value)
            for _key, value in sorted(self._catalog().items())
        )
