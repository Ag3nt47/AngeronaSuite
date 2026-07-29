"""Deterministic, offline release metadata and update-bundle verification."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from angerona.core.archive_safety import (
    read_bounded_member,
    safe_archive_path,
    validate_zip_members,
)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    _CRYPTO_ERROR: Exception | None = None
except Exception as exc:  # pragma: no cover
    Ed25519PublicKey = None  # type: ignore
    _CRYPTO_ERROR = exc

MAX_FILES = 10_000
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_RATIO = 200
MAX_ENVELOPE_BYTES = 1024 * 1024
SCHEMA_VERSION = 1
_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.-]+)?$")
_PLATFORM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _digest(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


@dataclass(frozen=True)
class Artifact:
    path: str
    sha256: str
    size: int
    platform: str
    version: str

    def __post_init__(self) -> None:
        safe_archive_path(self.path)
        if not isinstance(self.sha256, str) or not re.fullmatch(
            r"[0-9a-f]{64}", self.sha256
        ):
            raise ValueError("invalid artifact digest")
        if (
            isinstance(self.size, bool)
            or not isinstance(self.size, int)
            or not 0 <= self.size <= MAX_FILE_BYTES
        ):
            raise ValueError("invalid artifact size")
        if not isinstance(self.platform, str) or not _PLATFORM.fullmatch(self.platform):
            raise ValueError("invalid artifact platform")
        if not isinstance(self.version, str) or not _VERSION.fullmatch(self.version):
            raise ValueError("invalid artifact version")


@dataclass(frozen=True)
class ArtifactManifest:
    product: str
    version: str
    artifacts: tuple[Artifact, ...]
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifacts", tuple(self.artifacts))
        if (
            isinstance(self.schema_version, bool)
            or self.schema_version != SCHEMA_VERSION
            or not isinstance(self.product, str)
            or not self.product
            or len(self.product) > 100
        ):
            raise ValueError("invalid artifact manifest")
        if not isinstance(self.version, str) or not _VERSION.fullmatch(self.version):
            raise ValueError("invalid release version")
        if not all(isinstance(item, Artifact) for item in self.artifacts):
            raise ValueError("manifest artifacts must be typed")
        paths = [item.path for item in self.artifacts]
        if len(paths) != len({path.casefold() for path in paths}) or len(paths) > MAX_FILES:
            raise ValueError("artifact paths must be unique and bounded")
        if any(item.version != self.version for item in self.artifacts):
            raise ValueError("artifact version does not match manifest")

    def canonical(self) -> bytes:
        return _canonical(asdict(self))


def build_manifest(
    root: Path, files: Sequence[Path], *, product: str, version: str,
    platform: str,
) -> ArtifactManifest:
    root = Path(root).resolve()
    artifacts: list[Artifact] = []
    for candidate in sorted({Path(item).resolve() for item in files}, key=str):
        try:
            relative = candidate.relative_to(root).as_posix()
        except ValueError as exc:
            raise ValueError("artifact is outside release root") from exc
        digest, size = _digest(candidate)
        artifacts.append(Artifact(relative, digest, size, platform, version))
    return ArtifactManifest(product, version, tuple(artifacts))


def generate_cyclonedx(
    product: str, version: str,
    dependencies: Sequence[Mapping[str, str]],
) -> dict[str, Any]:
    """Generate deterministic CycloneDX JSON from supplied locked metadata."""
    components = []
    for item in sorted(dependencies, key=lambda x: (x["name"].casefold(), x["version"])):
        name, dep_version = item["name"], item["version"]
        components.append({
            "type": "library", "name": name, "version": dep_version,
            "purl": item.get("purl", f"pkg:pypi/{name}@{dep_version}"),
            "bom-ref": f"pkg:{name}@{dep_version}",
        })
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": {
            "type": "application", "name": product, "version": version,
        }},
        "components": components,
    }


def slsa_provenance(
    manifest: ArtifactManifest, *, builder_id: str, invocation_id: str
) -> dict[str, Any]:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {"name": item.path, "digest": {"sha256": item.sha256}}
            for item in manifest.artifacts
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://angerona.local/build/v1",
                "externalParameters": {
                    "product": manifest.product, "version": manifest.version,
                },
                "internalParameters": {},
                "resolvedDependencies": [],
            },
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {"invocationId": invocation_id},
            },
        },
    }


@dataclass(frozen=True)
class VexStatement:
    vulnerability: str
    component: str
    status: str
    justification: str

    def __post_init__(self) -> None:
        if self.status not in {
            "affected", "not_affected", "fixed", "under_investigation"
        }:
            raise ValueError("invalid VEX status")
        if not self.vulnerability or not self.component or not self.justification:
            raise ValueError("complete VEX statement required")


@dataclass(frozen=True)
class Preflight:
    platform: str
    current_version: str
    minimum_version: str
    target_version: str
    disk_available: int
    disk_required: int

    def validate(self) -> tuple[bool, tuple[str, ...]]:
        failures = []
        if not all(_VERSION.fullmatch(item) for item in (
            self.current_version, self.minimum_version, self.target_version
        )):
            failures.append("invalid version syntax")
        if _version_tuple(self.current_version) < _version_tuple(self.minimum_version):
            failures.append("current version is below update minimum")
        if _version_tuple(self.target_version) <= _version_tuple(self.current_version):
            failures.append("target version is not newer")
        if self.disk_available < self.disk_required:
            failures.append("insufficient staging disk space")
        return not failures, tuple(failures)


def _version_tuple(value: str) -> tuple[int, ...]:
    core = value.split("-", 1)[0].split("+", 1)[0]
    try:
        return tuple(int(part) for part in core.split("."))
    except ValueError:
        return ()


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    errors: tuple[str, ...]
    manifest: ArtifactManifest | None
    publisher_id: str


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("JSON object contains duplicate keys")
        value[key] = item
    return value


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{label} has an invalid schema")
    return value


def _decode_signature(value: Any) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{86}", value):
        raise ValueError("invalid release signature encoding")
    try:
        decoded = base64.b64decode(value + "==", altchars=b"-_", validate=True)
    except Exception as exc:
        raise ValueError("invalid release signature encoding") from exc
    if len(decoded) != 64:
        raise ValueError("invalid release signature length")
    return decoded


def _parse_envelope(raw: bytes) -> tuple[str, ArtifactManifest, bytes]:
    try:
        envelope = json.loads(raw, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("release envelope is not valid UTF-8 JSON") from exc
    envelope = _exact_keys(
        envelope,
        {"publisher_id", "manifest", "signature"},
        "release envelope",
    )
    publisher_id = envelope["publisher_id"]
    if (
        not isinstance(publisher_id, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", publisher_id)
    ):
        raise ValueError("invalid publisher identity")
    raw_manifest = _exact_keys(
        envelope["manifest"],
        {"product", "version", "artifacts", "schema_version"},
        "artifact manifest",
    )
    raw_artifacts = raw_manifest["artifacts"]
    if not isinstance(raw_artifacts, list) or len(raw_artifacts) > MAX_FILES:
        raise ValueError("manifest artifacts must be a bounded list")
    artifacts: list[Artifact] = []
    artifact_keys = {"path", "sha256", "size", "platform", "version"}
    for raw_artifact in raw_artifacts:
        item = _exact_keys(raw_artifact, artifact_keys, "artifact")
        artifacts.append(Artifact(**item))
    manifest = ArtifactManifest(
        raw_manifest["product"],
        raw_manifest["version"],
        tuple(artifacts),
        raw_manifest["schema_version"],
    )
    return publisher_id, manifest, _decode_signature(envelope["signature"])


def verify_update_bundle(
    bundle_path: Path, trust_store: Mapping[str, bytes],
    preflight: Preflight | None = None,
) -> VerificationResult:
    if _CRYPTO_ERROR is not None:
        raise RuntimeError("Ed25519 support is required") from _CRYPTO_ERROR
    errors: list[str] = []
    manifest = None
    publisher_id = ""
    try:
        with zipfile.ZipFile(bundle_path) as archive:
            infos = validate_zip_members(
                archive.infolist(),
                max_files=MAX_FILES + 1,
                max_member_bytes=MAX_FILE_BYTES,
                max_total_bytes=MAX_TOTAL_BYTES,
                max_ratio=MAX_RATIO,
            )
            names = [item.filename for item in infos]
            try:
                envelope_info = infos[names.index("release-envelope.json")]
            except ValueError as exc:
                raise ValueError("release envelope is missing") from exc
            publisher_id, manifest, signature = _parse_envelope(
                read_bounded_member(
                    archive,
                    envelope_info,
                    max_bytes=MAX_ENVELOPE_BYTES,
                )
            )
            public = trust_store.get(publisher_id)
            if not isinstance(public, bytes) or len(public) != 32:
                raise ValueError("publisher is not trusted")
            Ed25519PublicKey.from_public_bytes(public).verify(
                signature, manifest.canonical()
            )
            expected = {item.path: item for item in manifest.artifacts}
            payload_names = set(names) - {"release-envelope.json"}
            if payload_names != set(expected):
                raise ValueError("archive payload does not match manifest")
            for name, artifact in expected.items():
                digest = hashlib.sha256()
                size = 0
                with archive.open(name) as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        size += len(chunk)
                        if size > MAX_FILE_BYTES:
                            raise ValueError("expanded member exceeds bound")
                        digest.update(chunk)
                if size != artifact.size or digest.hexdigest() != artifact.sha256:
                    raise ValueError(f"artifact digest mismatch: {name}")
            if preflight is not None:
                okay, failures = preflight.validate()
                if not okay:
                    errors.extend(failures)
                if any(item.platform != preflight.platform for item in manifest.artifacts):
                    errors.append("artifact platform is incompatible")
                if manifest.version != preflight.target_version:
                    errors.append("manifest target version mismatch")
    except Exception as exc:
        errors.append(str(exc) or type(exc).__name__)
    return VerificationResult(not errors, tuple(errors), manifest, publisher_id)


@dataclass(frozen=True)
class StagedInstallPlan:
    plan_id: str
    bundle_sha256: str
    target_version: str
    stage_directory: str
    files: tuple[tuple[str, str], ...]
    rollback_files: tuple[tuple[str, str], ...]
    install_authorized: bool = False

    def __post_init__(self) -> None:
        if self.install_authorized:
            raise ValueError("release assurance creates staging plans only")
        if not self.plan_id or not _VERSION.fullmatch(self.target_version):
            raise ValueError("invalid staged plan identity/version")
        if not re.fullmatch(r"[0-9a-f]{64}", self.bundle_sha256):
            raise ValueError("invalid bundle digest")
        if len(self.files) > MAX_FILES or len(self.rollback_files) > MAX_FILES:
            raise ValueError("staged plan file count exceeds bound")
        for name, digest in (*self.files, *self.rollback_files):
            pure = PurePosixPath(name)
            if pure.is_absolute() or ".." in pure.parts or "\\" in name:
                raise ValueError("unsafe staged path")
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("invalid staged file digest")


def write_staged_plan(path: Path, plan: StagedInstallPlan) -> None:
    data = _canonical(asdict(plan))
    temp = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(temp, "xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
