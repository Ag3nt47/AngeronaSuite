"""Capability Manifest v1 for Angerona modules.

Built-in modules are trusted as part of the signed Angerona release. External
Python modules are a different trust boundary: importing one executes its
top-level code with the suite's token. This module validates a detached manifest
and the source digest *before* ModuleManager imports an external module.

The manifest is intentionally small and deterministic. It records the module's
requested privileges, privacy posture, telemetry contract, resource budget, and
an optional Ed25519 publisher signature. An unsigned external module is refused
unless the operator enables the explicit development override.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


SCHEMA_VERSION = 1
API_VERSION = "1"
MANIFEST_SUFFIX = ".angerona.json"
MAX_MANIFEST_BYTES = 128 * 1024
MAX_MODULE_BYTES = 8 * 1024 * 1024

_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{1,126}[a-z0-9])?$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_MITRE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_MANIFEST_FIELDS = frozenset({
    "schema_version",
    "id",
    "name",
    "version",
    "api_version",
    "entrypoint",
    "sha256",
    "permissions",
    "events",
    "mitre",
    "privacy",
    "performance",
    "publisher",
    "signature",
})

ALLOWED_PERMISSIONS = frozenset({
    "ai.infer",
    "credentials.read",
    "event.emit",
    "filesystem.read",
    "filesystem.write",
    "firewall.modify",
    "network.connect",
    "process.control",
    "process.inspect",
    "registry.read",
    "registry.write",
    "telemetry.read",
})

HIGH_RISK_PERMISSIONS = frozenset({
    "credentials.read",
    "filesystem.write",
    "firewall.modify",
    "network.connect",
    "process.control",
    "registry.write",
})

ALLOWED_DATA_CLASSES = frozenset({
    "command_line",
    "credential_metadata",
    "file_content",
    "file_metadata",
    "identity",
    "memory",
    "network",
    "none",
    "process",
})

ALLOWED_EGRESS = frozenset({"none", "local", "operator-approved"})
ALLOWED_RETENTION = frozenset({"memory", "flight-recorder", "custom"})


class ManifestError(ValueError):
    """Raised when a capability manifest violates the v1 contract."""


@dataclass(frozen=True)
class CapabilityManifest:
    schema_version: int
    capability_id: str
    name: str
    version: str
    api_version: str
    entrypoint: str
    sha256: str
    permissions: tuple[str, ...]
    event_inputs: tuple[str, ...]
    event_outputs: tuple[str, ...]
    mitre: tuple[str, ...]
    data_classes: tuple[str, ...]
    egress: str
    retention: str
    cpu_budget_pct: float
    memory_budget_mb: int
    poll_interval_s: float
    publisher: str
    signature: str
    raw: Mapping[str, Any]

    @property
    def high_risk_permissions(self) -> tuple[str, ...]:
        return tuple(p for p in self.permissions if p in HIGH_RISK_PERMISSIONS)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "id": self.capability_id,
            "name": self.name,
            "version": self.version,
            "api_version": self.api_version,
            "entrypoint": self.entrypoint,
            "sha256": self.sha256,
            "permissions": list(self.permissions),
            "events": {
                "inputs": list(self.event_inputs),
                "outputs": list(self.event_outputs),
            },
            "mitre": list(self.mitre),
            "privacy": {
                "data_classes": list(self.data_classes),
                "egress": self.egress,
                "retention": self.retention,
            },
            "performance": {
                "cpu_budget_pct": self.cpu_budget_pct,
                "memory_budget_mb": self.memory_budget_mb,
                "poll_interval_s": self.poll_interval_s,
            },
            "publisher": self.publisher,
            "signature": self.signature,
        }


@dataclass(frozen=True)
class ManifestDecision:
    accepted: bool
    trust: str
    reason: str
    manifest: CapabilityManifest | None = None
    # The exact bytes whose digest was checked. ModuleManager executes this
    # snapshot instead of reopening the path after verification, closing the
    # verify-then-swap window for elevated external-module imports.
    source_bytes: bytes | None = None


def manifest_path_for(module_path: Path) -> Path:
    """Return ``foo.angerona.json`` for ``foo.py``."""
    path = Path(module_path)
    return path.with_name(f"{path.stem}{MANIFEST_SUFFIX}")


def _bounded_text(value: Any, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str):
        raise ManifestError(f"{field} must be a string")
    text = value.strip()
    if not text or len(text) > maximum or "\x00" in text:
        raise ManifestError(f"{field} is empty or exceeds {maximum} characters")
    return text


def _string_list(
    value: Any,
    field: str,
    *,
    maximum: int = 128,
    item_maximum: int = 128,
) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ManifestError(f"{field} must be a list with at most {maximum} items")
    items: list[str] = []
    for item in value:
        text = _bounded_text(item, field, item_maximum)
        if text not in items:
            items.append(text)
    return tuple(items)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink():
            raise ManifestError("manifest symlinks are not accepted")
        size = path.stat().st_size
        if size <= 0 or size > MAX_MANIFEST_BYTES:
            raise ManifestError(
                f"manifest size must be between 1 and {MAX_MANIFEST_BYTES} bytes"
            )
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except ManifestError:
        raise
    except FileNotFoundError as exc:
        raise ManifestError(f"missing detached manifest: {path.name}") from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read manifest {path.name}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ManifestError("manifest root must be a JSON object")
    return loaded


def read_module_source(path: Path) -> tuple[bytes, str]:
    """Read one bounded module once and return its exact bytes plus SHA-256.

    The caller must execute these returned bytes, not reopen ``path``. A path can
    be replaced after this function returns, but that replacement will not
    affect the already-verified code snapshot.
    """
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ManifestError("external module must be a regular non-symlink file")
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(
            os, "O_NOFOLLOW", 0
        )
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ManifestError("external module must open as a regular file")
        if opened.st_size <= 0 or opened.st_size > MAX_MODULE_BYTES:
            raise ManifestError(
                f"external module size must be between 1 and {MAX_MODULE_BYTES} bytes"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(128 * 1024, MAX_MODULE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_MODULE_BYTES:
                raise ManifestError(
                    f"external module exceeds {MAX_MODULE_BYTES} bytes"
                )
        if total <= 0:
            raise ManifestError("external module is empty")
        source = b"".join(chunks)
        return source, hashlib.sha256(source).hexdigest()
    except ManifestError:
        raise
    except OSError as exc:
        raise ManifestError(f"cannot read external module: {exc}") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def sha256_file(path: Path) -> str:
    """Hash one bounded regular module file."""
    return read_module_source(path)[1]


def parse_manifest(data: Mapping[str, Any], module_path: Path) -> CapabilityManifest:
    """Validate and normalize a manifest, without yet checking its signature."""
    if not isinstance(data, Mapping):
        raise ManifestError("manifest root must be an object")
    unknown = set(data) - _ALLOWED_MANIFEST_FIELDS
    if unknown:
        raise ManifestError(f"manifest contains {len(unknown)} unknown field(s)")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ManifestError(f"schema_version must be {SCHEMA_VERSION}")
    capability_id = _bounded_text(data.get("id"), "id", 128).casefold()
    if not _ID_RE.fullmatch(capability_id):
        raise ManifestError("id must contain only lowercase letters, digits, . _ or -")
    name = _bounded_text(data.get("name"), "name", 160)
    version = _bounded_text(data.get("version"), "version", 64)
    if not _VERSION_RE.fullmatch(version):
        raise ManifestError("version must use semantic version form (for example 1.2.3)")
    api_version = _bounded_text(data.get("api_version"), "api_version", 16)
    if api_version != API_VERSION:
        raise ManifestError(f"api_version {api_version!r} is not supported")
    entrypoint = _bounded_text(data.get("entrypoint"), "entrypoint", 260)
    if Path(entrypoint).name != entrypoint or entrypoint != Path(module_path).name:
        raise ManifestError("entrypoint must exactly match the adjacent module filename")
    digest = _bounded_text(data.get("sha256"), "sha256", 64).casefold()
    if not _SHA256_RE.fullmatch(digest):
        raise ManifestError("sha256 must be 64 lowercase hexadecimal characters")

    permissions = _string_list(data.get("permissions", []), "permissions", maximum=32)
    unknown_permissions = sorted(set(permissions) - ALLOWED_PERMISSIONS)
    if unknown_permissions:
        raise ManifestError(
            f"unknown permission(s): {', '.join(unknown_permissions)}"
        )

    events = data.get("events", {})
    if not isinstance(events, dict):
        raise ManifestError("events must be an object")
    if set(events) - {"inputs", "outputs"}:
        raise ManifestError("events contains unknown fields")
    event_inputs = _string_list(events.get("inputs", []), "events.inputs")
    event_outputs = _string_list(events.get("outputs", []), "events.outputs")

    mitre = _string_list(data.get("mitre", []), "mitre", maximum=128, item_maximum=16)
    invalid_mitre = [item for item in mitre if not _MITRE_RE.fullmatch(item)]
    if invalid_mitre:
        raise ManifestError(f"invalid MITRE technique ID: {invalid_mitre[0]}")

    privacy = data.get("privacy", {})
    if not isinstance(privacy, dict):
        raise ManifestError("privacy must be an object")
    if set(privacy) - {"data_classes", "egress", "retention"}:
        raise ManifestError("privacy contains unknown fields")
    data_classes = _string_list(
        privacy.get("data_classes", ["none"]),
        "privacy.data_classes",
        maximum=16,
        item_maximum=64,
    )
    unknown_classes = sorted(set(data_classes) - ALLOWED_DATA_CLASSES)
    if unknown_classes:
        raise ManifestError(f"unknown privacy data class: {unknown_classes[0]}")
    egress = _bounded_text(privacy.get("egress", "none"), "privacy.egress", 32)
    retention = _bounded_text(
        privacy.get("retention", "memory"), "privacy.retention", 32
    )
    if egress not in ALLOWED_EGRESS:
        raise ManifestError(f"privacy.egress must be one of {sorted(ALLOWED_EGRESS)}")
    if retention not in ALLOWED_RETENTION:
        raise ManifestError(
            f"privacy.retention must be one of {sorted(ALLOWED_RETENTION)}"
        )
    if egress != "none" and "network.connect" not in permissions:
        raise ManifestError("non-local egress requires the network.connect permission")

    performance = data.get("performance", {})
    if not isinstance(performance, dict):
        raise ManifestError("performance must be an object")
    if set(performance) - {
        "cpu_budget_pct", "memory_budget_mb", "poll_interval_s",
    }:
        raise ManifestError("performance contains unknown fields")
    try:
        raw_cpu = performance.get("cpu_budget_pct", 5.0)
        raw_memory = performance.get("memory_budget_mb", 128)
        raw_poll = performance.get("poll_interval_s", 1.0)
        if (
            type(raw_cpu) not in (int, float)
            or type(raw_memory) is not int
            or type(raw_poll) not in (int, float)
        ):
            raise TypeError
        cpu_budget = float(raw_cpu)
        memory_budget = raw_memory
        poll_interval = float(raw_poll)
    except (TypeError, ValueError) as exc:
        raise ManifestError("performance budgets must be numeric") from exc
    if not math.isfinite(cpu_budget) or not (0.1 <= cpu_budget <= 100.0):
        raise ManifestError("cpu_budget_pct must be between 0.1 and 100")
    if not (8 <= memory_budget <= 4096):
        raise ManifestError("memory_budget_mb must be between 8 and 4096")
    if not math.isfinite(poll_interval) or not (0.01 <= poll_interval <= 86_400.0):
        raise ManifestError("poll_interval_s must be between 0.01 and 86400")

    raw_publisher = data.get("publisher", "")
    raw_signature = data.get("signature", "")
    if not isinstance(raw_publisher, str) or not isinstance(raw_signature, str):
        raise ManifestError("publisher and signature must be strings")
    publisher = raw_publisher.strip()
    signature = raw_signature.strip()
    if signature and not publisher:
        raise ManifestError("a signed manifest must identify its publisher")
    if len(publisher) > 128 or len(signature) > 512:
        raise ManifestError("publisher or signature is too long")

    return CapabilityManifest(
        schema_version=SCHEMA_VERSION,
        capability_id=capability_id,
        name=name,
        version=version,
        api_version=api_version,
        entrypoint=entrypoint,
        sha256=digest,
        permissions=permissions,
        event_inputs=event_inputs,
        event_outputs=event_outputs,
        mitre=mitre,
        data_classes=data_classes,
        egress=egress,
        retention=retention,
        cpu_budget_pct=cpu_budget,
        memory_budget_mb=memory_budget,
        poll_interval_s=poll_interval,
        publisher=publisher,
        signature=signature,
        raw=dict(data),
    )


def _canonical_signed_body(data: Mapping[str, Any]) -> bytes:
    body = dict(data)
    body.pop("signature", None)
    return json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _decode_key(value: str, expected_bytes: int, field: str) -> bytes:
    text = value.strip()
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        try:
            raw = base64.b64decode(text, validate=True)
        except Exception as exc:
            raise ManifestError(f"{field} is not valid hex or base64") from exc
    if len(raw) != expected_bytes:
        raise ManifestError(f"{field} must decode to {expected_bytes} bytes")
    return raw


def load_trusted_publishers(path: Path) -> dict[str, bytes]:
    """Load the local Ed25519 publisher trust store.

    Trust-store format::

        {"schema_version": 1,
         "publishers": [{"id": "publisher.example", "public_key": "<base64>"}]}
    """
    trust_path = Path(path)
    if not trust_path.exists():
        return {}
    data = _read_json(trust_path)
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ManifestError("publisher trust store has an unsupported schema")
    rows = data.get("publishers", [])
    if not isinstance(rows, list) or len(rows) > 256:
        raise ManifestError("publishers must be a list with at most 256 entries")
    publishers: dict[str, bytes] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ManifestError("each publisher entry must be an object")
        publisher_id = _bounded_text(row.get("id"), "publisher.id", 128)
        if publisher_id in publishers:
            raise ManifestError(f"duplicate publisher id: {publisher_id}")
        if row.get("revoked") is True:
            continue
        publishers[publisher_id] = _decode_key(
            _bounded_text(row.get("public_key"), "publisher.public_key", 256),
            32,
            "publisher.public_key",
        )
    return publishers


def verify_signature(
    manifest: CapabilityManifest,
    trusted_publishers: Mapping[str, bytes],
) -> None:
    if not manifest.signature:
        raise ManifestError("manifest is unsigned")
    public_key = trusted_publishers.get(manifest.publisher)
    if not public_key:
        raise ManifestError(f"publisher is not trusted: {manifest.publisher}")
    signature = _decode_key(manifest.signature, 64, "signature")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature,
            _canonical_signed_body(manifest.raw),
        )
    except ManifestError:
        raise
    except Exception as exc:
        raise ManifestError("Ed25519 publisher signature is invalid") from exc


def verify_external_module(
    module_path: Path,
    trust_store_path: Path,
    *,
    allow_unsigned: bool = False,
) -> ManifestDecision:
    """Validate an external module without importing or executing it."""
    module_path = Path(module_path)
    try:
        raw = _read_json(manifest_path_for(module_path))
        manifest = parse_manifest(raw, module_path)
        source_bytes, actual = read_module_source(module_path)
        if actual != manifest.sha256:
            raise ManifestError(
                "source digest does not match the manifest (module was changed)"
            )
        if manifest.signature:
            verify_signature(manifest, load_trusted_publishers(trust_store_path))
            return ManifestDecision(
                True,
                "signed",
                "trusted Ed25519 publisher",
                manifest,
                source_bytes,
            )
        if not allow_unsigned:
            raise ManifestError(
                "manifest is unsigned; use the explicit development override only "
                "for reviewed local modules"
            )
        return ManifestDecision(
            True,
            "hash-pinned-dev",
            "unsigned development override; source digest verified",
            manifest,
            source_bytes,
        )
    except ManifestError as exc:
        return ManifestDecision(False, "rejected", str(exc), None)
    except Exception as exc:  # fail closed on unexpected verification failures
        return ManifestDecision(
            False,
            "rejected",
            f"manifest verification failed: {type(exc).__name__}: {exc}",
            None,
        )


def sample_manifest(module_path: Path, *, capability_id: str, name: str) -> dict[str, Any]:
    """Build an unsigned starter manifest for a reviewed external module."""
    module_path = Path(module_path)
    return {
        "schema_version": SCHEMA_VERSION,
        "id": capability_id,
        "name": name,
        "version": "1.0.0",
        "api_version": API_VERSION,
        "entrypoint": module_path.name,
        "sha256": sha256_file(module_path),
        "permissions": ["event.emit"],
        "events": {"inputs": [], "outputs": []},
        "mitre": [],
        "privacy": {
            "data_classes": ["none"],
            "egress": "none",
            "retention": "memory",
        },
        "performance": {
            "cpu_budget_pct": 5.0,
            "memory_budget_mb": 128,
            "poll_interval_s": 1.0,
        },
        "publisher": "",
        "signature": "",
    }
