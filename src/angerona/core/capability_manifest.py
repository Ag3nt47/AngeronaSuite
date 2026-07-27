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
import re
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


def sha256_file(path: Path) -> str:
    """Hash one bounded regular file without loading it into memory."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ManifestError("external module must be a regular non-symlink file")
    size = path.stat().st_size
    if size <= 0 or size > MAX_MODULE_BYTES:
        raise ManifestError(
            f"external module size must be between 1 and {MAX_MODULE_BYTES} bytes"
        )
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_manifest(data: Mapping[str, Any], module_path: Path) -> CapabilityManifest:
    """Validate and normalize a manifest, without yet checking its signature."""
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
    event_inputs = _string_list(events.get("inputs", []), "events.inputs")
    event_outputs = _string_list(events.get("outputs", []), "events.outputs")

    mitre = _string_list(data.get("mitre", []), "mitre", maximum=128, item_maximum=16)
    invalid_mitre = [item for item in mitre if not _MITRE_RE.fullmatch(item)]
    if invalid_mitre:
        raise ManifestError(f"invalid MITRE technique ID: {invalid_mitre[0]}")

    privacy = data.get("privacy", {})
    if not isinstance(privacy, dict):
        raise ManifestError("privacy must be an object")
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
    try:
        cpu_budget = float(performance.get("cpu_budget_pct", 5.0))
        memory_budget = int(performance.get("memory_budget_mb", 128))
        poll_interval = float(performance.get("poll_interval_s", 1.0))
    except (TypeError, ValueError) as exc:
        raise ManifestError("performance budgets must be numeric") from exc
    if not (0.1 <= cpu_budget <= 100.0):
        raise ManifestError("cpu_budget_pct must be between 0.1 and 100")
    if not (8 <= memory_budget <= 4096):
        raise ManifestError("memory_budget_mb must be between 8 and 4096")
    if not (0.01 <= poll_interval <= 86_400.0):
        raise ManifestError("poll_interval_s must be between 0.01 and 86400")

    publisher = str(data.get("publisher", "") or "").strip()
    signature = str(data.get("signature", "") or "").strip()
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
        actual = sha256_file(module_path)
        if actual != manifest.sha256:
            raise ManifestError(
                "source digest does not match the manifest (module was changed)"
            )
        if manifest.signature:
            verify_signature(manifest, load_trusted_publishers(trust_store_path))
            return ManifestDecision(True, "signed", "trusted Ed25519 publisher", manifest)
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
