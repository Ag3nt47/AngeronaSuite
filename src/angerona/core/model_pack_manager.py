"""Governed, data-only ARIA model and defensive-runbook pack lifecycle.

The manager has deliberately narrow authority. It can pull an immutable model
manifest from the loopback Ollama service, create an Angerona-owned alias, and
install JSON runbook data from the bundled catalog. It cannot execute package
code, install Python dependencies, accept URLs, or accept operator-supplied
Modelfiles.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import tempfile
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from angerona.core import report_attest
from angerona.core.atomic_io import replace_with_retry
from angerona.core.data_paths import data_dir as default_data_dir
from angerona.core.ollama_lifecycle import (
    copy_model,
    delete_model,
    list_models,
    pull_model,
    show_model,
    validate_model_ref,
)
from angerona.modules.ai_model_integrity import (
    LocalModelVerification,
    ModelIntegrityError,
    verify_ollama_model_files,
)


SCHEMA_VERSION = 1
BUILTIN_CATALOG_SHA256 = (
    "sha256:05e6f35571a2e84a3c98f5e98444ef36c1524581c309191d38829b52b3b1f01b"
)
_PACK_ID = re.compile(r"[a-z0-9][a-z0-9-]{2,63}")
_VERSION = re.compile(r"[0-9][0-9a-z.-]{0,31}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_CATALOG_FIELDS = {"schema_version", "packs"}
_PACK_FIELDS = {
    "id",
    "version",
    "title",
    "description",
    "model",
    "requirements",
    "runbooks_sha256",
    "runbooks",
}
_MODEL_FIELDS = {"source", "manifest_digest", "managed_name", "model_bytes"}
_REQUIREMENT_FIELDS = {"ram_bytes", "vram_bytes", "disk_bytes"}
_RUNBOOK_FIELDS = {"id", "title", "content"}
_PROCESS_LOCK = threading.Lock()


class ModelPackError(RuntimeError):
    """Base error for governed model-pack operations."""


class CatalogValidationError(ModelPackError):
    """Raised when catalog structure, identity, or content digest is invalid."""


class StateIntegrityError(ModelPackError):
    """Raised when local pack state cannot be authenticated."""


class AdmissionDenied(ModelPackError):
    """Raised before download when the host cannot safely admit a pack."""


class OperationInProgress(ModelPackError):
    """Raised when a process-wide lifecycle operation is already in flight."""


@dataclass(frozen=True)
class ModelSpec:
    source: str
    manifest_digest: str
    managed_name: str
    model_bytes: int

    @property
    def pinned_ref(self) -> str:
        return f"{self.source}@{self.manifest_digest}"


@dataclass(frozen=True)
class PackRequirements:
    ram_bytes: int
    vram_bytes: int
    disk_bytes: int


@dataclass(frozen=True)
class Runbook:
    id: str
    title: str
    content: str


@dataclass(frozen=True)
class ModelPack:
    id: str
    version: str
    title: str
    description: str
    model: ModelSpec
    requirements: PackRequirements
    runbooks_sha256: str
    runbooks: tuple[Runbook, ...]


@dataclass(frozen=True)
class ResourceSnapshot:
    ram_bytes: int
    vram_bytes: int
    disk_bytes: int


@dataclass(frozen=True)
class AdmissionPlan:
    pack_id: str
    admitted: bool
    requirements: PackRequirements
    available: ResourceSnapshot
    deficits: tuple[str, ...]


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CatalogValidationError(f"duplicate catalog field: {key}")
        result[key] = value
    return result


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _exact_fields(value: Mapping[str, Any], allowed: set[str], label: str) -> None:
    unknown = set(value) - allowed
    missing = allowed - set(value)
    if unknown:
        raise CatalogValidationError(
            f"{label} contains unknown fields: {', '.join(sorted(unknown))}"
        )
    if missing:
        raise CatalogValidationError(
            f"{label} is missing fields: {', '.join(sorted(missing))}"
        )


def _text(value: Any, label: str, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value
        or len(value) > maximum
        or any(ord(ch) < 32 and ch not in "\n\t" for ch in value)
    ):
        raise CatalogValidationError(f"{label} is invalid")
    return value


def _bytes_count(value: Any, label: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= 2**50:
        raise CatalogValidationError(f"{label} is invalid")
    return value


def load_catalog(
    path: str | Path,
    *,
    expected_sha256: str | None = None,
) -> dict[str, ModelPack]:
    """Load a duplicate-key-rejecting, exact-schema, digest-verified catalog."""
    catalog_path = Path(path)
    raw = catalog_path.read_bytes()
    if len(raw) > 2 * 1024 * 1024:
        raise CatalogValidationError("catalog exceeds its size bound")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except CatalogValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CatalogValidationError("catalog is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise CatalogValidationError("catalog root must be an object")
    if expected_sha256 is not None:
        if not _DIGEST.fullmatch(expected_sha256) or not hmac.compare_digest(
            _sha256(_canonical(document)), expected_sha256
        ):
            raise CatalogValidationError("catalog content digest is invalid")
    _exact_fields(document, _CATALOG_FIELDS, "catalog")
    if document["schema_version"] != SCHEMA_VERSION:
        raise CatalogValidationError("catalog schema version is unsupported")
    pack_rows = document["packs"]
    if not isinstance(pack_rows, list) or not 1 <= len(pack_rows) <= 128:
        raise CatalogValidationError("catalog packs must be a bounded non-empty list")

    result: dict[str, ModelPack] = {}
    managed_names: set[str] = set()
    for index, row in enumerate(pack_rows):
        label = f"pack[{index}]"
        if not isinstance(row, dict):
            raise CatalogValidationError(f"{label} must be an object")
        _exact_fields(row, _PACK_FIELDS, label)
        pack_id = _text(row["id"], f"{label}.id", maximum=64)
        if not _PACK_ID.fullmatch(pack_id) or pack_id in result:
            raise CatalogValidationError(f"{label}.id is invalid or duplicated")
        version = _text(row["version"], f"{label}.version", maximum=32)
        if not _VERSION.fullmatch(version):
            raise CatalogValidationError(f"{label}.version is invalid")

        model_row = row["model"]
        if not isinstance(model_row, dict):
            raise CatalogValidationError(f"{label}.model must be an object")
        _exact_fields(model_row, _MODEL_FIELDS, f"{label}.model")
        source = validate_model_ref(
            _text(model_row["source"], f"{label}.model.source", maximum=64)
        )
        if ":" in source or "@" in source:
            raise CatalogValidationError("catalog model source must be an untagged name")
        digest = _text(
            model_row["manifest_digest"],
            f"{label}.model.manifest_digest",
            maximum=71,
        )
        if not _DIGEST.fullmatch(digest):
            raise CatalogValidationError("catalog model manifest digest is invalid")
        managed_name = validate_model_ref(
            _text(model_row["managed_name"], f"{label}.model.managed_name", maximum=96)
        )
        if not managed_name.startswith("angerona-") or "@" in managed_name:
            raise CatalogValidationError("managed model must use an Angerona-owned name")
        if managed_name in managed_names:
            raise CatalogValidationError("managed model name is duplicated")
        managed_names.add(managed_name)
        model = ModelSpec(
            source=source,
            manifest_digest=digest,
            managed_name=managed_name,
            model_bytes=_bytes_count(
                model_row["model_bytes"], f"{label}.model.model_bytes"
            ),
        )
        validate_model_ref(model.pinned_ref, digest_required=True)

        requirement_row = row["requirements"]
        if not isinstance(requirement_row, dict):
            raise CatalogValidationError(f"{label}.requirements must be an object")
        _exact_fields(requirement_row, _REQUIREMENT_FIELDS, f"{label}.requirements")
        requirements = PackRequirements(
            ram_bytes=_bytes_count(
                requirement_row["ram_bytes"], f"{label}.requirements.ram_bytes"
            ),
            vram_bytes=_bytes_count(
                requirement_row["vram_bytes"],
                f"{label}.requirements.vram_bytes",
                allow_zero=True,
            ),
            disk_bytes=_bytes_count(
                requirement_row["disk_bytes"], f"{label}.requirements.disk_bytes"
            ),
        )
        if requirements.disk_bytes < model.model_bytes:
            raise CatalogValidationError("pack disk admission is below model size")

        runbook_rows = row["runbooks"]
        if not isinstance(runbook_rows, list) or not 1 <= len(runbook_rows) <= 256:
            raise CatalogValidationError("pack runbooks must be a bounded non-empty list")
        expected_runbooks = _text(
            row["runbooks_sha256"], f"{label}.runbooks_sha256", maximum=71
        )
        if not _DIGEST.fullmatch(expected_runbooks) or not hmac.compare_digest(
            _sha256(_canonical(runbook_rows)), expected_runbooks
        ):
            raise CatalogValidationError("runbook content digest is invalid")
        runbooks: list[Runbook] = []
        runbook_ids: set[str] = set()
        for runbook_index, runbook_row in enumerate(runbook_rows):
            runbook_label = f"{label}.runbooks[{runbook_index}]"
            if not isinstance(runbook_row, dict):
                raise CatalogValidationError(f"{runbook_label} must be an object")
            _exact_fields(runbook_row, _RUNBOOK_FIELDS, runbook_label)
            runbook_id = _text(runbook_row["id"], f"{runbook_label}.id", maximum=64)
            if not _PACK_ID.fullmatch(runbook_id) or runbook_id in runbook_ids:
                raise CatalogValidationError(f"{runbook_label}.id is invalid or duplicated")
            runbook_ids.add(runbook_id)
            runbooks.append(
                Runbook(
                    id=runbook_id,
                    title=_text(
                        runbook_row["title"], f"{runbook_label}.title", maximum=160
                    ),
                    content=_text(
                        runbook_row["content"], f"{runbook_label}.content", maximum=16_000
                    ),
                )
            )

        result[pack_id] = ModelPack(
            id=pack_id,
            version=version,
            title=_text(row["title"], f"{label}.title", maximum=160),
            description=_text(
                row["description"], f"{label}.description", maximum=1000
            ),
            model=model,
            requirements=requirements,
            runbooks_sha256=expected_runbooks,
            runbooks=tuple(runbooks),
        )
    return result


def _default_resource_probe(root: Path) -> ResourceSnapshot:
    disk = shutil.disk_usage(root).free
    ram = 0
    try:
        import psutil

        ram = int(psutil.virtual_memory().available)
    except (ImportError, AttributeError, OSError):
        if hasattr(os, "sysconf"):
            try:
                ram = int(os.sysconf("SC_AVPHYS_PAGES") * os.sysconf("SC_PAGE_SIZE"))
            except (OSError, ValueError):
                ram = 0
    return ResourceSnapshot(ram_bytes=ram, vram_bytes=0, disk_bytes=int(disk))


def _model_names(rows: list[dict]) -> set[str]:
    names: set[str] = set()
    for row in rows:
        for key in ("name", "model"):
            value = row.get(key)
            if isinstance(value, str) and value:
                names.add(value)
    return names


class ModelPackManager:
    """Install and switch catalog-governed local ARIA capability packs."""

    def __init__(
        self,
        *,
        data_dir: str | Path | None = None,
        catalog_path: str | Path | None = None,
        catalog_sha256: str | None = None,
        ollama_host: str = "http://localhost:11434",
        attestation_key: bytes | None = None,
        resource_probe: Callable[[Path], ResourceSnapshot] | None = None,
        config_update: Callable[[str], None] | None = None,
        config_current: Callable[[], str | None] | None = None,
        model_api: Any | None = None,
        model_verifier: Callable[
            [str, str | None], LocalModelVerification | Mapping[str, Any]
        ] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        root = Path(data_dir) if data_dir is not None else default_data_dir()
        self.root = root.resolve() / "aria_model_packs"
        self.state_path = self.root / "state.json"
        self.runbook_root = self.root / "runbooks"
        default_catalog = Path(__file__).resolve().parents[3] / "assets" / "aria_model_packs.json"
        self.catalog_path = Path(catalog_path) if catalog_path else default_catalog
        expected = catalog_sha256
        if expected is None and catalog_path is None:
            expected = BUILTIN_CATALOG_SHA256
        if catalog_path is not None and expected is None:
            raise CatalogValidationError(
                "an external catalog requires an expected canonical SHA-256 digest"
            )
        self.catalog = load_catalog(self.catalog_path, expected_sha256=expected)
        self.ollama_host = ollama_host
        self._key = attestation_key if attestation_key is not None else self._load_install_key(root)
        if self._key is not None and (not isinstance(self._key, bytes) or len(self._key) != 32):
            raise StateIntegrityError("model-pack attestation key must contain 32 bytes")
        self._resource_probe = resource_probe or _default_resource_probe
        self._config_update = config_update or (lambda _model: None)
        self._config_current = config_current or (lambda: None)
        self._api = model_api or _OllamaApi()
        self._model_verifier = model_verifier or verify_ollama_model_files
        self._now = now or (lambda: datetime.now(timezone.utc))
        self.root.mkdir(parents=True, exist_ok=True)
        self.runbook_root.mkdir(parents=True, exist_ok=True)
        self._protect(self.root, directory=True)
        self._protect(self.runbook_root, directory=True)

    @staticmethod
    def _load_install_key(root: Path) -> bytes | None:
        try:
            value = bytes.fromhex((root / "bus.key").read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            return None
        return value if len(value) == 32 else None

    @staticmethod
    def _protect(path: Path, *, directory: bool = False) -> None:
        try:
            path.chmod(0o700 if directory else 0o600)
        except OSError:
            pass

    def _sign(self, body: dict[str, Any]) -> str:
        if self._key is None:
            raise StateIntegrityError(
                "model-pack mutation requires the per-install HMAC authority"
            )
        signature = report_attest.sign_doc(body, key=self._key)
        if signature is None:
            raise StateIntegrityError("model-pack state could not be attested")
        return signature

    def _empty_state(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "revision": 0,
            "active_pack": None,
            "active_model": None,
            "installed": {},
            "activation_history": [],
            "receipts": [],
        }

    def state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return self._empty_state()
        try:
            document = json.loads(
                self.state_path.read_text(encoding="utf-8"),
                object_pairs_hook=_strict_object,
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, CatalogValidationError) as exc:
            raise StateIntegrityError("model-pack state is not valid JSON") from exc
        if not isinstance(document, dict) or set(document) != {
            "schema_version",
            "revision",
            "active_pack",
            "active_model",
            "installed",
            "activation_history",
            "receipts",
            report_attest.SIG_FIELD,
        }:
            raise StateIntegrityError("model-pack state schema is invalid")
        if self._key is None:
            raise StateIntegrityError("model-pack state cannot be authenticated")
        signature = document.get(report_attest.SIG_FIELD)
        expected = report_attest.sign_doc(document, key=self._key)
        if (
            document.get("schema_version") != SCHEMA_VERSION
            or not isinstance(signature, str)
            or expected is None
            or not hmac.compare_digest(signature, expected)
        ):
            raise StateIntegrityError("model-pack state HMAC is invalid")
        result = dict(document)
        result.pop(report_attest.SIG_FIELD, None)
        if (
            isinstance(result["revision"], bool)
            or not isinstance(result["revision"], int)
            or result["revision"] < 0
            or not isinstance(result["installed"], dict)
            or not isinstance(result["activation_history"], list)
            or not isinstance(result["receipts"], list)
        ):
            raise StateIntegrityError("model-pack state values are invalid")
        return result

    def _atomic_json(self, path: Path, value: Any) -> None:
        payload = _canonical(value)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._protect(path.parent, directory=True)
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{path.name}-", suffix=".tmp", dir=path.parent
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            temporary_path = Path(temporary)
            self._protect(temporary_path)
            replace_with_retry(temporary_path, path)
            self._protect(path)
        finally:
            try:
                Path(temporary).unlink()
            except FileNotFoundError:
                pass

    def _durable_file(self, path: Path, payload: bytes) -> None:
        if not payload:
            raise ValueError("model-pack file payload must not be empty")
        with path.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        self._protect(path)

    @staticmethod
    def _runbook_markdown(pack: ModelPack, runbook: Runbook) -> bytes:
        return (
            f"# {runbook.title}\n\n"
            f"Angerona governed pack: {pack.id} {pack.version}\n\n"
            f"{runbook.content}\n"
        ).encode("utf-8")

    def _install_runbooks(self, pack: ModelPack, destination: Path) -> list[str]:
        """Atomically install catalog text as RAG-discoverable Markdown files."""
        if destination.exists():
            raise ModelPackError("runbook destination exists but is not owned by state")
        staging = Path(
            tempfile.mkdtemp(prefix=f".{pack.id}-", dir=self.runbook_root)
        ).resolve()
        self._protect(staging, directory=True)
        filenames: list[str] = []
        try:
            for runbook in pack.runbooks:
                filename = f"{runbook.id}.md"
                self._durable_file(
                    staging / filename, self._runbook_markdown(pack, runbook)
                )
                filenames.append(filename)
            manifest = {
                "schema_version": 1,
                "pack_id": pack.id,
                "version": pack.version,
                "content_sha256": pack.runbooks_sha256,
                "files": filenames,
            }
            self._durable_file(staging / "manifest.json", _canonical(manifest))
            replace_with_retry(staging, destination)
            return filenames
        finally:
            if staging.exists():
                shutil.rmtree(staging)

    def _verified_runbook_dir(
        self, pack: ModelPack, installed: Mapping[str, Any]
    ) -> Path:
        expected_name = f"{pack.id}-{pack.version}"
        if installed.get("runbook_dir") != expected_name:
            raise StateIntegrityError("runbook ownership record is invalid")
        directory = (self.runbook_root / expected_name).resolve()
        if directory.parent != self.runbook_root.resolve() or not directory.is_dir():
            raise StateIntegrityError("owned runbook directory is missing or escaped")
        expected_files = {f"{runbook.id}.md" for runbook in pack.runbooks}
        actual_files = {
            path.name for path in directory.iterdir() if path.is_file() and path.suffix == ".md"
        }
        if actual_files != expected_files:
            raise StateIntegrityError("owned runbook file inventory changed")
        for runbook in pack.runbooks:
            actual = (directory / f"{runbook.id}.md").read_bytes()
            expected = self._runbook_markdown(pack, runbook)
            if not hmac.compare_digest(_sha256(actual), _sha256(expected)):
                raise StateIntegrityError("owned runbook content digest changed")
        return directory

    def runbook_roots(self) -> tuple[Path, ...]:
        """Return only HMAC-owned, catalog-matching Markdown roots for ARIA RAG."""
        state = self.state()
        roots = []
        for pack_id, installed in sorted(state["installed"].items()):
            if not isinstance(installed, dict):
                raise StateIntegrityError("installed pack record is invalid")
            roots.append(self._verified_runbook_dir(self._pack(pack_id), installed))
        return tuple(roots)

    def _write_state(self, state: dict[str, Any]) -> None:
        body = dict(state)
        body["revision"] = int(body["revision"]) + 1
        body[report_attest.SIG_FIELD] = self._sign(body)
        self._atomic_json(self.state_path, body)
        state["revision"] = body["revision"]

    def _receipt(self, action: str, pack: ModelPack, **details: Any) -> dict[str, Any]:
        receipt = {
            "receipt_version": 1,
            "timestamp": self._now().astimezone(timezone.utc).isoformat(),
            "action": action,
            "pack_id": pack.id,
            "pack_version": pack.version,
            "manifest_digest": pack.model.manifest_digest,
            "details": details,
        }
        receipt[report_attest.SIG_FIELD] = self._sign(receipt)
        return receipt

    def admission_plan(self, pack_id: str) -> AdmissionPlan:
        pack = self._pack(pack_id)
        available = self._resource_probe(self.root)
        return self._admission_plan_for(pack, available)

    @staticmethod
    def _admission_plan_for(
        pack: ModelPack, available: ResourceSnapshot
    ) -> AdmissionPlan:
        """Evaluate one pack against an already captured resource snapshot."""
        if not isinstance(available, ResourceSnapshot):
            raise TypeError("resource probe must return ResourceSnapshot")
        deficits = []
        for name in ("ram_bytes", "vram_bytes", "disk_bytes"):
            required = getattr(pack.requirements, name)
            actual = getattr(available, name)
            if isinstance(actual, bool) or not isinstance(actual, int) or actual < 0:
                raise ValueError("resource probe returned an invalid byte count")
            if required and actual < required:
                deficits.append(f"{name}: requires {required}, available {actual}")
        return AdmissionPlan(
            pack_id=pack.id,
            admitted=not deficits,
            requirements=pack.requirements,
            available=available,
            deficits=tuple(deficits),
        )

    def admission_plans(self) -> dict[str, AdmissionPlan]:
        """Evaluate the catalog using one coherent host-resource snapshot.

        Status surfaces render every catalog entry together.  Capturing RAM and
        disk once avoids an N+1 series of identical psutil/disk probes and also
        prevents one refresh from mixing measurements taken at different times.
        Lifecycle admission continues to call :meth:`admission_plan` immediately
        before a mutation, so this display optimization cannot weaken admission.
        """
        available = self._resource_probe(self.root)
        if not isinstance(available, ResourceSnapshot):
            raise TypeError("resource probe must return ResourceSnapshot")
        return {
            pack_id: self._admission_plan_for(pack, available)
            for pack_id, pack in sorted(self.catalog.items())
        }

    def _pack(self, pack_id: str) -> ModelPack:
        if not isinstance(pack_id, str) or not _PACK_ID.fullmatch(pack_id):
            raise ValueError("pack identifier is invalid")
        try:
            return self.catalog[pack_id]
        except KeyError as exc:
            raise CatalogValidationError("pack is not listed in the trusted catalog") from exc

    def _model_digest(self, model_name: str) -> str | None:
        for row in self._api.list(self.ollama_host):
            names = {row.get("name"), row.get("model")}
            aliases = {model_name}
            if ":" not in model_name and "@" not in model_name:
                aliases.add(f"{model_name}:latest")
            if names & aliases:
                digest = row.get("digest")
                return str(digest) if isinstance(digest, str) else None
        return None

    def _has_digest(self, digest: str) -> bool:
        return any(
            isinstance(row.get("digest"), str)
            and hmac.compare_digest(str(row["digest"]), digest)
            for row in self._api.list(self.ollama_host)
        )

    def _verify_local_model(
        self,
        model_name: str,
        expected_digest: str | None,
        *,
        minimum_bytes: int = 1,
    ) -> dict[str, Any]:
        """Return validated on-disk evidence independent of the Ollama API."""
        try:
            result = self._model_verifier(model_name, expected_digest)
        except (ModelIntegrityError, OSError, ValueError) as exc:
            raise ModelPackError(f"local model verification failed: {exc}") from exc
        if isinstance(result, LocalModelVerification):
            evidence = asdict(result)
        elif isinstance(result, Mapping):
            evidence = dict(result)
        else:
            raise ModelPackError("local model verifier returned an invalid result")
        digest = evidence.get("manifest_digest")
        blob_count = evidence.get("blob_count")
        bytes_verified = evidence.get("bytes_verified")
        if (
            not isinstance(digest, str)
            or not _DIGEST.fullmatch(digest)
            or isinstance(blob_count, bool)
            or not isinstance(blob_count, int)
            or blob_count < 1
            or isinstance(bytes_verified, bool)
            or not isinstance(bytes_verified, int)
            or bytes_verified < minimum_bytes
        ):
            raise ModelPackError("local model verifier returned incomplete evidence")
        if expected_digest is not None and not hmac.compare_digest(
            digest, expected_digest
        ):
            raise ModelPackError("local model manifest digest did not match the catalog")
        return {
            "manifest_digest": digest,
            "blob_count": blob_count,
            "bytes_verified": bytes_verified,
        }

    def install(self, pack_id: str) -> dict[str, Any]:
        pack = self._pack(pack_id)
        if self._key is None:
            raise StateIntegrityError(
                "model-pack mutation requires the per-install HMAC authority"
            )
        plan = self.admission_plan(pack_id)
        if not plan.admitted:
            raise AdmissionDenied("; ".join(plan.deficits))
        if not _PROCESS_LOCK.acquire(blocking=False):
            raise OperationInProgress("another model-pack operation is in progress")
        copied = False
        runbooks_installed = False
        runbook_path = self.runbook_root / f"{pack.id}-{pack.version}"
        try:
            state = self.state()
            current = state["installed"].get(pack.id)
            if current is not None:
                if (
                    current.get("manifest_digest") == pack.model.manifest_digest
                    and current.get("managed_model") == pack.model.managed_name
                ):
                    verification = self._verify_local_model(
                        pack.model.managed_name,
                        pack.model.manifest_digest,
                        minimum_bytes=pack.model.model_bytes,
                    )
                    return self._receipt(
                        "install-noop",
                        pack,
                        already_installed=True,
                        local_verification=verification,
                    )
                raise ModelPackError("a different catalog version of this pack is installed")
            local_names = _model_names(self._api.list(self.ollama_host))
            if pack.model.managed_name in local_names:
                raise ModelPackError("managed model name exists but is not owned by this registry")
            self._api.pull(pack.model.pinned_ref, self.ollama_host)
            observed = self._model_digest(pack.model.pinned_ref)
            if observed is None:
                show = self._api.show(pack.model.pinned_ref, self.ollama_host)
                observed_value = show.get("digest")
                observed = str(observed_value) if isinstance(observed_value, str) else None
            if observed is not None and not hmac.compare_digest(
                observed, pack.model.manifest_digest
            ):
                raise ModelPackError("Ollama model manifest digest did not match the catalog")
            if observed is None and self._has_digest(pack.model.manifest_digest):
                observed = pack.model.manifest_digest
            if observed is None:
                raise ModelPackError("Ollama did not report a verifiable model manifest digest")
            self._api.copy(
                pack.model.pinned_ref, pack.model.managed_name, self.ollama_host
            )
            copied = True
            copied_digest = self._model_digest(pack.model.managed_name)
            if copied_digest is None or not hmac.compare_digest(
                copied_digest, pack.model.manifest_digest
            ):
                raise ModelPackError("managed model copy did not retain the verified digest")
            verification = self._verify_local_model(
                pack.model.managed_name,
                pack.model.manifest_digest,
                minimum_bytes=pack.model.model_bytes,
            )
            installed_runbooks = [asdict(item) for item in pack.runbooks]
            if not hmac.compare_digest(
                _sha256(_canonical(installed_runbooks)), pack.runbooks_sha256
            ):
                raise CatalogValidationError("runbook digest changed before installation")
            runbook_files = self._install_runbooks(pack, runbook_path)
            runbooks_installed = True
            receipt = self._receipt(
                "install",
                pack,
                managed_model=pack.model.managed_name,
                runbook_dir=runbook_path.name,
                runbook_files=runbook_files,
                resource_plan=asdict(plan),
                local_verification=verification,
            )
            state["installed"][pack.id] = {
                "version": pack.version,
                "manifest_digest": pack.model.manifest_digest,
                "managed_model": pack.model.managed_name,
                "verified_manifest_digest": verification["manifest_digest"],
                "verified_blob_count": verification["blob_count"],
                "runbook_dir": runbook_path.name,
                "installed_at": receipt["timestamp"],
            }
            state["receipts"] = (state["receipts"] + [receipt])[-256:]
            self._write_state(state)
            return receipt
        except Exception:
            if copied:
                try:
                    self._api.delete(pack.model.managed_name, self.ollama_host)
                except Exception:
                    pass
            if runbooks_installed and runbook_path.is_dir():
                shutil.rmtree(runbook_path)
            raise
        finally:
            _PROCESS_LOCK.release()

    def activate(self, pack_id: str) -> dict[str, Any]:
        pack = self._pack(pack_id)
        if self._key is None:
            raise StateIntegrityError(
                "model-pack mutation requires the per-install HMAC authority"
            )
        if not _PROCESS_LOCK.acquire(blocking=False):
            raise OperationInProgress("another model-pack operation is in progress")
        try:
            state = self.state()
            installed = state["installed"].get(pack.id)
            if not isinstance(installed, dict) or installed.get("managed_model") != pack.model.managed_name:
                raise ModelPackError("pack must be installed before activation")
            managed_digest = self._model_digest(pack.model.managed_name)
            if managed_digest is None or not hmac.compare_digest(
                managed_digest, pack.model.manifest_digest
            ):
                raise ModelPackError("owned managed model is missing or has changed")
            verification = self._verify_local_model(
                pack.model.managed_name,
                pack.model.manifest_digest,
                minimum_bytes=pack.model.model_bytes,
            )
            previous_pack = state["active_pack"]
            previous_model = state["active_model"] or self._config_current()
            if not isinstance(previous_model, str) or not previous_model:
                raise ModelPackError("current ARIA model is unavailable for rollback")
            validate_model_ref(previous_model)
            previous_verification = self._verify_local_model(previous_model, None)
            self._config_update(pack.model.managed_name)
            try:
                receipt = self._receipt(
                    "activate",
                    pack,
                    previous_pack=previous_pack,
                    previous_model=previous_model,
                    active_model=pack.model.managed_name,
                    local_verification=verification,
                )
                state["active_pack"] = pack.id
                state["active_model"] = pack.model.managed_name
                state["activation_history"] = (
                    state["activation_history"]
                    + [{
                        "pack_id": previous_pack,
                        "model": previous_model,
                        "manifest_digest": previous_verification["manifest_digest"],
                    }]
                )[-64:]
                state["receipts"] = (state["receipts"] + [receipt])[-256:]
                self._write_state(state)
            except Exception:
                if isinstance(previous_model, str) and previous_model:
                    self._config_update(previous_model)
                raise
            return receipt
        finally:
            _PROCESS_LOCK.release()

    def rollback(self) -> dict[str, Any]:
        if self._key is None:
            raise StateIntegrityError(
                "model-pack mutation requires the per-install HMAC authority"
            )
        if not _PROCESS_LOCK.acquire(blocking=False):
            raise OperationInProgress("another model-pack operation is in progress")
        try:
            state = self.state()
            if not state["activation_history"]:
                raise ModelPackError("no previous ARIA model is recorded")
            current_pack_id = state["active_pack"]
            if not isinstance(current_pack_id, str):
                raise ModelPackError("no governed pack is active")
            pack = self._pack(current_pack_id)
            previous = state["activation_history"][-1]
            if not isinstance(previous, dict) or set(previous) != {
                "pack_id", "model", "manifest_digest"
            }:
                raise StateIntegrityError("activation history is invalid")
            previous_model = previous["model"]
            if not isinstance(previous_model, str) or not previous_model:
                raise ModelPackError("rollback target is not a usable model")
            validate_model_ref(previous_model)
            previous_digest = previous["manifest_digest"]
            if not isinstance(previous_digest, str) or not _DIGEST.fullmatch(previous_digest):
                raise StateIntegrityError("rollback model digest is invalid")
            verification = self._verify_local_model(previous_model, previous_digest)
            current_model = state["active_model"]
            self._config_update(previous_model)
            try:
                receipt = self._receipt(
                    "rollback",
                    pack,
                    prior_model=current_model,
                    restored_model=previous_model,
                    local_verification=verification,
                )
                state["active_pack"] = previous["pack_id"]
                state["active_model"] = previous_model
                state["activation_history"] = state["activation_history"][:-1]
                state["receipts"] = (state["receipts"] + [receipt])[-256:]
                self._write_state(state)
            except Exception:
                if isinstance(current_model, str) and current_model:
                    self._config_update(current_model)
                raise
            return receipt
        finally:
            _PROCESS_LOCK.release()

    def remove(self, pack_id: str) -> dict[str, Any]:
        pack = self._pack(pack_id)
        if self._key is None:
            raise StateIntegrityError(
                "model-pack mutation requires the per-install HMAC authority"
            )
        if not _PROCESS_LOCK.acquire(blocking=False):
            raise OperationInProgress("another model-pack operation is in progress")
        try:
            state = self.state()
            if state["active_pack"] == pack.id:
                raise ModelPackError("active pack must be rolled back before removal")
            installed = state["installed"].get(pack.id)
            if not isinstance(installed, dict):
                raise ModelPackError("pack is not installed")
            if installed.get("managed_model") != pack.model.managed_name:
                raise StateIntegrityError("installed model ownership record is invalid")
            owned_digest = self._model_digest(pack.model.managed_name)
            if owned_digest is None or not hmac.compare_digest(
                owned_digest, pack.model.manifest_digest
            ):
                raise StateIntegrityError("owned model is missing or its digest changed")
            verification = self._verify_local_model(
                pack.model.managed_name,
                pack.model.manifest_digest,
                minimum_bytes=pack.model.model_bytes,
            )
            runbook_path = self._verified_runbook_dir(pack, installed)
            self._api.delete(pack.model.managed_name, self.ollama_host)
            if self._model_digest(pack.model.managed_name) is not None:
                raise ModelPackError("Ollama did not remove the owned managed model")
            if runbook_path.is_dir():
                shutil.rmtree(runbook_path)
            receipt = self._receipt(
                "remove",
                pack,
                removed_model=pack.model.managed_name,
                local_verification=verification,
            )
            del state["installed"][pack.id]
            state["receipts"] = (state["receipts"] + [receipt])[-256:]
            self._write_state(state)
            return receipt
        finally:
            _PROCESS_LOCK.release()


class _OllamaApi:
    """Injectable fixed-endpoint adapter used by the manager."""

    @staticmethod
    def list(host: str) -> list[dict]:
        return list_models(host)

    @staticmethod
    def show(model: str, host: str) -> dict[str, Any]:
        return show_model(model, host)

    @staticmethod
    def pull(model: str, host: str) -> dict[str, Any]:
        return pull_model(model, host)

    @staticmethod
    def copy(source: str, destination: str, host: str) -> dict[str, Any]:
        return copy_model(source, destination, host)

    @staticmethod
    def delete(model: str, host: str) -> dict[str, Any]:
        return delete_model(model, host)


__all__ = [
    "AdmissionDenied",
    "AdmissionPlan",
    "BUILTIN_CATALOG_SHA256",
    "CatalogValidationError",
    "ModelPack",
    "ModelPackError",
    "ModelPackManager",
    "OperationInProgress",
    "PackRequirements",
    "ResourceSnapshot",
    "Runbook",
    "StateIntegrityError",
    "load_catalog",
]
