"""ai_model_integrity.py — AI Model Integrity Guard (Code: AMIG).

Purpose
    Local LLM weights (e.g. Ollama blobs) are loaded into RAM and trusted by the
    triage engine. If an attacker tampers with or poisons a model file on disk,
    every downstream AI decision is compromised. AMIG computes cryptographic
    SHA-256 hashes of the local model blobs and compares them against a recorded
    baseline, raising a CRITICAL alert on any mismatch BEFORE the suite trusts a
    model for inference.

Explicit authenticated baseline
    Live files are never trusted on first use. An operator must explicitly call
    ``rebaseline(approved=True)`` after independently approving the local model
    set. The resulting exact manifest/blob inventory, model-root identity and
    approval metadata are HMAC authenticated and atomically replaced. Missing,
    new, unreadable, malformed, linked or changed objects all fail closed, and a
    corrupt authority file is preserved for investigation rather than overwritten.

Discovery
    Ollama blob directory, in priority order:
      1. ``ANGERONA_OLLAMA_MODELS`` (env)   2. ``OLLAMA_MODELS`` (env)
      3. ``%USERPROFILE%\\.ollama\\models`` (Windows) / ``~/.ollama/models``
    Hashes the ``blobs/sha256-*`` files. (An Ollama blob is content-addressed by
    its own sha256, so AMIG also flags a blob whose *content* no longer matches
    the sha256 embedded in its filename — a strong, self-describing check.)

Safety
    Normal monitoring is read-only and hashes files in 4 MB chunks. Baseline
    mutation is an explicit operator action only. AI Triage requires a fresh,
    exact-tag attestation receipt before every bounded inference window.

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import stat
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from angerona.core.atomic_io import replace_with_retry
from angerona.core.module_base import BaseModule, Severity


_SHA256_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_MAX_MANIFEST_BYTES = 16 * 1024 * 1024
_MAX_MANIFEST_BLOBS = 10_000
_MAX_BASELINE_BYTES = 4 * 1024 * 1024
_MAX_INVENTORY_FILES = 20_000
_BASELINE_SCHEMA = 2
_BASELINE_HMAC = "hmac_sha256"
_BASELINE_DOMAIN = b"Angerona-AI-Model-Baseline-v2"
_ATTESTATION_TTL_SECONDS = 60.0


class ModelIntegrityError(RuntimeError):
    """Raised when a local Ollama model cannot be verified from disk."""


@dataclass(frozen=True)
class LocalModelVerification:
    """Bounded evidence from an on-disk Ollama manifest and its blobs."""

    manifest_digest: str
    blob_count: int
    bytes_verified: int
    manifest_path: str


@dataclass(frozen=True)
class ModelAttestationReceipt:
    """Short-lived evidence binding one exact tag to approved local bytes."""

    model_ref: str
    manifest_digest: str
    baseline_sha256: str
    blob_count: int
    bytes_verified: int
    issued_monotonic: float
    expires_monotonic: float


_ATTESTATION_LOCK = threading.Lock()
_ATTESTATION_CACHE: dict[str, ModelAttestationReceipt] = {}


def _repo_root() -> Path:
    from angerona.core.data_paths import data_dir
    return data_dir()


def _hash_file(filepath: str | os.PathLike, chunk: int = 4096 * 1024) -> str:
    """Hash one stable, regular, no-follow object or raise a typed failure."""
    path = Path(filepath)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        before_path = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(before_path.st_mode)
            or path.is_symlink()
            or bool(
                getattr(before_path, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            )
        ):
            raise ModelIntegrityError("model inventory object is not a regular file")
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
            before_path.st_dev,
            before_path.st_ino,
            before_path.st_size,
            before_path.st_mtime_ns,
        ):
            raise ModelIntegrityError("model inventory object changed before hashing")
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, chunk)
            if not block:
                break
            digest.update(block)
        after = os.fstat(descriptor)
        after_path = path.stat(follow_symlinks=False)
        identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ModelIntegrityError("model inventory object changed during hashing")
        if identity != (
            after_path.st_dev,
            after_path.st_ino,
            after_path.st_size,
            after_path.st_mtime_ns,
        ):
            raise ModelIntegrityError("model inventory path changed during hashing")
        return digest.hexdigest()
    except ModelIntegrityError:
        raise
    except OSError as exc:
        raise ModelIntegrityError("model inventory object could not be hashed") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    except OSError:
        return True


def _require_confined_regular_file(path: Path, root: Path) -> tuple[Path, os.stat_result]:
    """Resolve a model file while rejecting links/junctions and non-files."""
    try:
        root_resolved = root.resolve(strict=True)
        resolved = path.resolve(strict=True)
        resolved.relative_to(root_resolved)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ModelIntegrityError("Ollama model path escaped or is unavailable") from exc

    current = resolved.parent
    while current != root_resolved:
        if current.is_symlink() or _is_reparse_point(current):
            raise ModelIntegrityError("Ollama model path contains a link or junction")
        parent = current.parent
        if parent == current:
            raise ModelIntegrityError("Ollama model path is not confined")
        current = parent
    if resolved.is_symlink() or _is_reparse_point(resolved):
        raise ModelIntegrityError("Ollama model file is a link or reparse point")
    try:
        info = resolved.stat()
    except OSError as exc:
        raise ModelIntegrityError("Ollama model file is unavailable") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ModelIntegrityError("Ollama model object is not a regular file")
    return resolved, info


def _read_verified_file(path: Path, root: Path, *, maximum: int) -> bytes:
    resolved, before = _require_confined_regular_file(path, root)
    if before.st_size < 1 or before.st_size > maximum:
        raise ModelIntegrityError("Ollama manifest has an invalid size")
    try:
        with resolved.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_size) != (
                before.st_dev,
                before.st_ino,
                before.st_size,
            ):
                raise ModelIntegrityError("Ollama manifest changed before verification")
            payload = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
    except OSError as exc:
        raise ModelIntegrityError("Ollama manifest could not be read") from exc
    if len(payload) != before.st_size or len(payload) > maximum:
        raise ModelIntegrityError("Ollama manifest changed during verification")
    if (after.st_dev, after.st_ino, after.st_size) != (
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
    ):
        raise ModelIntegrityError("Ollama manifest changed during verification")
    return payload


def _hash_verified_blob(path: Path, root: Path, expected_size: int) -> str:
    resolved, before = _require_confined_regular_file(path, root)
    if before.st_size != expected_size:
        raise ModelIntegrityError("Ollama blob size does not match its manifest")
    digest = hashlib.sha256()
    try:
        with resolved.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_size) != (
                before.st_dev,
                before.st_ino,
                before.st_size,
            ):
                raise ModelIntegrityError("Ollama blob changed before verification")
            for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
                digest.update(block)
            after = os.fstat(stream.fileno())
    except OSError as exc:
        raise ModelIntegrityError("Ollama blob could not be read") from exc
    if (after.st_dev, after.st_ino, after.st_size) != (
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
    ):
        raise ModelIntegrityError("Ollama blob changed during verification")
    return digest.hexdigest()


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ModelIntegrityError(f"duplicate Ollama manifest field: {key}")
        result[key] = value
    return result


def verify_ollama_model_files(
    model_ref: str,
    expected_manifest_digest: str | None = None,
    *,
    models_root: str | os.PathLike[str] | None = None,
) -> LocalModelVerification:
    """Verify a local Ollama manifest and every referenced content-addressed blob.

    This does not consult Ollama's loopback API.  The manifest digest is computed
    from the actual file and each referenced blob is checked against both the
    manifest size and the SHA-256 embedded in its content-addressed filename.
    """
    from angerona.core.ollama_lifecycle import validate_model_ref

    normalized = validate_model_ref(model_ref)
    if "@" in normalized:
        raise ModelIntegrityError("local verification requires a named model tag")
    name, separator, tag = normalized.partition(":")
    tag = tag if separator else "latest"
    if expected_manifest_digest is not None and not _SHA256_DIGEST.fullmatch(
        expected_manifest_digest
    ):
        raise ModelIntegrityError("expected model manifest digest is invalid")

    if models_root is None:
        root = AIModelIntegrityGuardModule._models_root()
    else:
        root = Path(models_root)
    if root is None:
        raise ModelIntegrityError("Ollama model directory is unavailable")
    try:
        root = root.resolve(strict=True)
    except OSError as exc:
        raise ModelIntegrityError("Ollama model directory is unavailable") from exc
    if root.is_symlink() or _is_reparse_point(root) or not root.is_dir():
        raise ModelIntegrityError("Ollama model directory is not trusted")

    manifest_path = (
        root / "manifests" / "registry.ollama.ai" / "library" / name / tag
    )
    raw = _read_verified_file(manifest_path, root, maximum=_MAX_MANIFEST_BYTES)
    actual_manifest_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if expected_manifest_digest is not None and not hmac.compare_digest(
        actual_manifest_digest, expected_manifest_digest
    ):
        raise ModelIntegrityError("local Ollama manifest digest does not match the catalog")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_json_object)
    except ModelIntegrityError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ModelIntegrityError("Ollama manifest is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise ModelIntegrityError("Ollama manifest root is invalid")
    config = document.get("config")
    layers = document.get("layers")
    if not isinstance(config, dict) or not isinstance(layers, list):
        raise ModelIntegrityError("Ollama manifest descriptors are invalid")
    descriptors = [config, *layers]
    if not 1 <= len(descriptors) <= _MAX_MANIFEST_BLOBS:
        raise ModelIntegrityError("Ollama manifest blob inventory is invalid")

    total = 0
    seen: set[str] = set()
    blob_root = root / "blobs"
    for descriptor in descriptors:
        if not isinstance(descriptor, dict):
            raise ModelIntegrityError("Ollama manifest blob descriptor is invalid")
        digest = descriptor.get("digest")
        size = descriptor.get("size")
        if (
            not isinstance(digest, str)
            or not _SHA256_DIGEST.fullmatch(digest)
            or isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= 2**50
        ):
            raise ModelIntegrityError("Ollama manifest blob identity is invalid")
        if digest in seen:
            raise ModelIntegrityError("Ollama manifest contains a duplicate blob")
        seen.add(digest)
        hexadecimal = digest.removeprefix("sha256:")
        actual = _hash_verified_blob(blob_root / f"sha256-{hexadecimal}", root, size)
        if not hmac.compare_digest(actual, hexadecimal):
            raise ModelIntegrityError("Ollama blob content digest does not match its manifest")
        total += size
    return LocalModelVerification(
        manifest_digest=actual_manifest_digest,
        blob_count=len(descriptors),
        bytes_verified=total,
        manifest_path=str(manifest_path),
    )


class AIModelIntegrityGuardModule(BaseModule):
    CODE = "AMIG"
    NAME = "AI Model Integrity Guard"
    name = "AI Model Integrity Guard"
    description = ("Cryptographically attests local LLM weights (Ollama blobs) "
                   "against a pinned baseline; flags tampering/poisoning before load.")
    category = "AI Defense"
    version = "1.13.0"

    _INTERVAL = 30 * 60.0     # re-attest every 30 min

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._baseline_path = _repo_root() / "shared_logs" / "model_baselines.json"
        self._baseline: dict[str, str] = {}
        self._baseline_root: dict[str, object] = {}
        self._baseline_sha256 = ""
        self._baseline_status = "not-loaded"
        self._baseline_key_override: bytes | None = None
        self._verified = 0
        self._mismatches = 0
        self._last_alert_signature = ""

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── discovery ────────────────────────────────────────────────────────────
    @staticmethod
    def _models_root() -> Path | None:
        for env in ("ANGERONA_OLLAMA_MODELS", "OLLAMA_MODELS"):
            v = os.environ.get(env)
            if v and Path(v).exists():
                return Path(v)
        home = Path(os.environ.get("USERPROFILE") or Path.home())
        cand = home / ".ollama" / "models"
        return cand if cand.exists() else None

    def _validated_root(self) -> tuple[Path, dict[str, object]]:
        candidate = self._models_root()
        if candidate is None:
            raise ModelIntegrityError("Ollama model directory is unavailable")
        try:
            before = candidate.stat(follow_symlinks=False)
            root = candidate.resolve(strict=True)
            after = root.stat(follow_symlinks=False)
        except OSError as exc:
            raise ModelIntegrityError("Ollama model directory is unavailable") from exc
        if (
            candidate.is_symlink()
            or root.is_symlink()
            or _is_reparse_point(candidate)
            or not stat.S_ISDIR(after.st_mode)
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise ModelIntegrityError("Ollama model directory is not trusted")
        return root, {
            "resolved": str(root),
            "device": int(after.st_dev),
            "inode": int(after.st_ino),
        }

    def _discover_files(self) -> tuple[dict[str, Path], dict[str, object]]:
        """Return a complete, bounded, no-follow manifest/blob inventory."""
        root, identity = self._validated_root()
        pending = [path for path in (root / "blobs", root / "manifests") if path.exists()]
        files: dict[str, Path] = {}
        directories: dict[Path, tuple[int, int, int]] = {}
        objects = 0
        while pending:
            directory = pending.pop()
            try:
                info = directory.stat(follow_symlinks=False)
                if (
                    directory.is_symlink()
                    or _is_reparse_point(directory)
                    or not stat.S_ISDIR(info.st_mode)
                ):
                    raise ModelIntegrityError("model inventory directory is not trusted")
                directories[directory] = (info.st_dev, info.st_ino, info.st_mtime_ns)
                with os.scandir(directory) as entries:
                    for entry in entries:
                        objects += 1
                        if objects > _MAX_INVENTORY_FILES:
                            raise ModelIntegrityError("model inventory exceeds object limit")
                        path = Path(entry.path)
                        entry_info = entry.stat(follow_symlinks=False)
                        if entry.is_symlink() or bool(
                            getattr(entry_info, "st_file_attributes", 0)
                            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                        ):
                            raise ModelIntegrityError(
                                "model inventory contains a link or reparse point"
                            )
                        if stat.S_ISDIR(entry_info.st_mode):
                            pending.append(path)
                        elif stat.S_ISREG(entry_info.st_mode):
                            relative = path.relative_to(root).as_posix()
                            if relative in files:
                                raise ModelIntegrityError(
                                    "model inventory contains a duplicate path"
                                )
                            files[relative] = path
                        else:
                            raise ModelIntegrityError(
                                "model inventory contains a non-regular object"
                            )
            except ModelIntegrityError:
                raise
            except OSError as exc:
                raise ModelIntegrityError("model inventory traversal failed") from exc
        for directory, expected in directories.items():
            try:
                current = directory.stat(follow_symlinks=False)
            except OSError as exc:
                raise ModelIntegrityError("model inventory changed during traversal") from exc
            if (current.st_dev, current.st_ino, current.st_mtime_ns) != expected:
                raise ModelIntegrityError("model inventory changed during traversal")
        return dict(sorted(files.items())), identity

    def _snapshot_inventory(self) -> tuple[dict[str, str], dict[str, object]]:
        files, identity = self._discover_files()
        if not files:
            raise ModelIntegrityError("model inventory is empty")
        hashes: dict[str, str] = {}
        for relative, path in files.items():
            if self.stopping:
                raise ModelIntegrityError("model attestation interrupted")
            digest = _hash_file(path)
            name = path.name.casefold()
            if name.startswith("sha256-"):
                expected = name.removeprefix("sha256-")
                if not re.fullmatch(r"[0-9a-f]{64}", expected) or not hmac.compare_digest(
                    digest.casefold(), expected
                ):
                    raise ModelIntegrityError(
                        f"{relative} content does not match its content address"
                    )
            hashes[relative] = digest
        self._validate_manifest_inventory(files, hashes, Path(str(identity["resolved"])))
        after, after_identity = self._discover_files()
        if identity != after_identity or tuple(files) != tuple(after):
            raise ModelIntegrityError("model inventory changed during attestation")
        return hashes, identity

    @staticmethod
    def _validate_manifest_inventory(
        files: dict[str, Path], hashes: dict[str, str], root: Path
    ) -> None:
        manifests = {
            relative: path
            for relative, path in files.items()
            if relative.startswith("manifests/")
        }
        blobs = {
            relative: path
            for relative, path in files.items()
            if relative.startswith("blobs/sha256-")
        }
        if not manifests or not blobs:
            raise ModelIntegrityError(
                "model inventory requires both manifests and content-addressed blobs"
            )
        for relative, path in manifests.items():
            raw = _read_verified_file(path, root, maximum=_MAX_MANIFEST_BYTES)
            try:
                document = json.loads(
                    raw.decode("utf-8"), object_pairs_hook=_strict_json_object
                )
            except ModelIntegrityError:
                raise
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ModelIntegrityError(
                    f"{relative} is not a valid Ollama manifest"
                ) from exc
            if not isinstance(document, dict):
                raise ModelIntegrityError(f"{relative} manifest root is invalid")
            config = document.get("config")
            layers = document.get("layers")
            if not isinstance(config, dict) or not isinstance(layers, list):
                raise ModelIntegrityError(f"{relative} descriptors are invalid")
            descriptors = [config, *layers]
            if not 1 <= len(descriptors) <= _MAX_MANIFEST_BLOBS:
                raise ModelIntegrityError(f"{relative} descriptor count is invalid")
            seen: set[str] = set()
            for descriptor in descriptors:
                if not isinstance(descriptor, dict):
                    raise ModelIntegrityError(f"{relative} descriptor is invalid")
                digest = descriptor.get("digest")
                size = descriptor.get("size")
                if (
                    not isinstance(digest, str)
                    or not _SHA256_DIGEST.fullmatch(digest)
                    or isinstance(size, bool)
                    or not isinstance(size, int)
                    or not 0 <= size <= 2**50
                    or digest in seen
                ):
                    raise ModelIntegrityError(f"{relative} descriptor identity is invalid")
                seen.add(digest)
                hexadecimal = digest.removeprefix("sha256:")
                blob_relative = f"blobs/sha256-{hexadecimal}"
                blob = blobs.get(blob_relative)
                if blob is None or hashes.get(blob_relative) != hexadecimal:
                    raise ModelIntegrityError(
                        f"{relative} references a missing or changed blob"
                    )
                try:
                    observed_size = blob.stat(follow_symlinks=False).st_size
                except OSError as exc:
                    raise ModelIntegrityError(
                        f"{relative} referenced blob is unavailable"
                    ) from exc
                if observed_size != size:
                    raise ModelIntegrityError(
                        f"{relative} referenced blob size does not match"
                    )

    # ── baseline persistence ─────────────────────────────────────────────────
    def _baseline_key(self) -> bytes | None:
        master = self._baseline_key_override
        if master is None:
            try:
                master = bytes.fromhex(
                    (_repo_root() / "bus.key").read_text(encoding="ascii").strip()
                )
            except (OSError, ValueError):
                return None
        if len(master) != 32:
            return None
        return hmac.new(master, _BASELINE_DOMAIN, hashlib.sha256).digest()

    @staticmethod
    def _baseline_body(document: dict[str, object]) -> bytes:
        unsigned = {
            key: value for key, value in document.items() if key != _BASELINE_HMAC
        }
        return json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

    def _load_baseline(self) -> bool:
        key = self._baseline_key()
        if key is None:
            self._baseline_status = "key-unavailable"
            return False
        try:
            raw = self._baseline_path.read_bytes()
        except FileNotFoundError:
            self._baseline_status = "approval-required"
            return False
        except OSError as exc:
            self.last_error = str(exc)
            self._baseline_status = "unreadable"
            return False
        try:
            if not 1 <= len(raw) <= _MAX_BASELINE_BYTES:
                raise ModelIntegrityError("baseline size is invalid")
            document = json.loads(
                raw.decode("utf-8"), object_pairs_hook=_strict_json_object
            )
            if not isinstance(document, dict) or set(document) != {
                "schema",
                "approved_at",
                "authority",
                "root",
                "files",
                _BASELINE_HMAC,
            }:
                raise ModelIntegrityError("baseline schema is invalid")
            approved_at = document["approved_at"]
            root = document["root"]
            files = document["files"]
            if (
                document["schema"] != _BASELINE_SCHEMA
                or document["authority"] != "operator-explicit"
                or isinstance(approved_at, bool)
                or not isinstance(approved_at, (int, float))
                or not math.isfinite(float(approved_at))
                or not isinstance(root, dict)
                or set(root) != {"resolved", "device", "inode"}
                or not isinstance(root["resolved"], str)
                or not root["resolved"]
                or isinstance(root["device"], bool)
                or not isinstance(root["device"], int)
                or isinstance(root["inode"], bool)
                or not isinstance(root["inode"], int)
                or not isinstance(files, dict)
                or not 1 <= len(files) <= _MAX_INVENTORY_FILES
            ):
                raise ModelIntegrityError("baseline values are invalid")
            clean: dict[str, str] = {}
            for relative, digest in files.items():
                parsed = PurePosixPath(relative) if isinstance(relative, str) else None
                if (
                    parsed is None
                    or parsed.is_absolute()
                    or "\\" in relative
                    or any(part in {"", ".", ".."} for part in parsed.parts)
                    or not isinstance(digest, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", digest)
                ):
                    raise ModelIntegrityError("baseline file entry is invalid")
                clean[relative] = digest
            supplied = document[_BASELINE_HMAC]
            expected = hmac.new(
                key, self._baseline_body(document), hashlib.sha256
            ).hexdigest()
            if (
                not isinstance(supplied, str)
                or len(supplied) != 64
                or not hmac.compare_digest(supplied, expected)
            ):
                raise ModelIntegrityError("baseline authentication failed")
        except (ModelIntegrityError, UnicodeError, json.JSONDecodeError, TypeError) as exc:
            self.last_error = str(exc)
            self._baseline_status = "invalid"
            return False
        self._baseline = clean
        self._baseline_root = dict(root)
        self._baseline_sha256 = hashlib.sha256(raw).hexdigest()
        self._baseline_status = "approved"
        return True

    def _write_baseline(self, document: dict[str, object]) -> None:
        payload = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        if len(payload) > _MAX_BASELINE_BYTES:
            raise ModelIntegrityError("baseline exceeds byte limit")
        path = self._baseline_path
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}-", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                temporary.chmod(0o600)
            except OSError:
                pass
            replace_with_retry(temporary, path)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def rebaseline(self, *, approved: bool = False) -> int:
        """Explicitly approve one complete, stable local model inventory."""
        if not approved:
            raise PermissionError("explicit model baseline approval is required")
        if self._baseline_path.exists() and not self._load_baseline():
            if self._baseline_status in {"invalid", "unreadable"}:
                raise ModelIntegrityError(
                    "refusing to overwrite invalid model baseline evidence"
                )
        key = self._baseline_key()
        if key is None:
            raise ModelIntegrityError("model baseline authority is unavailable")
        files, root = self._snapshot_inventory()
        document: dict[str, object] = {
            "schema": _BASELINE_SCHEMA,
            "approved_at": time.time(),
            "authority": "operator-explicit",
            "root": root,
            "files": files,
        }
        document[_BASELINE_HMAC] = hmac.new(
            key, self._baseline_body(document), hashlib.sha256
        ).hexdigest()
        with self.state_lock:
            self._write_baseline(document)
        if not self._load_baseline():
            raise ModelIntegrityError("written model baseline failed authentication")
        with _ATTESTATION_LOCK:
            _ATTESTATION_CACHE.clear()
        return len(files)

    # ── verification ─────────────────────────────────────────────────────────
    def _verify_pass(self) -> tuple[int, list[str]]:
        """Verify exact set/root/content; never enroll observations."""
        if not self._load_baseline():
            raise ModelIntegrityError(
                f"approved model baseline unavailable ({self._baseline_status})"
            )
        current, root = self._snapshot_inventory()
        mismatches: list[str] = []
        if root != self._baseline_root:
            mismatches.append("model root identity changed")
        for missing in sorted(set(self._baseline) - set(current)):
            mismatches.append(f"{missing} (missing)")
        for new in sorted(set(current) - set(self._baseline)):
            mismatches.append(f"{new} (unapproved-new)")
        for name in sorted(set(current) & set(self._baseline)):
            if not hmac.compare_digest(current[name], self._baseline[name]):
                mismatches.append(f"{name} (content≠baseline)")
        return len(current), mismatches

    # ── lifecycle ────────────────────────────────────────────────────────────
    def run(self) -> None:
        if self._models_root() is None:
            self.set_health(60, "no Ollama model directory found — nothing to attest")
            self.emit("AMIG: no local model directory found; attestation idle. "
                      "Set ANGERONA_OLLAMA_MODELS if models live elsewhere.",
                      Severity.LOW, idle=True)
            while not self.stopping:
                self.sleep(self._INTERVAL)
            return

        self.emit(
            "AMIG online — authenticated, explicit model attestation active.",
            Severity.INFO,
        )
        while not self.stopping:
            try:
                checked, mismatches = self._verify_pass()
                if mismatches:
                    self._mismatches += len(mismatches)
                    self.set_health(
                        0, f"{len(mismatches)} model inventory item(s) failed attestation"
                    )
                    signature = hashlib.sha256(
                        "\n".join(mismatches).encode("utf-8", "replace")
                    ).hexdigest()
                    if signature != self._last_alert_signature:
                        self._last_alert_signature = signature
                        self.emit(
                            "MODEL INTEGRITY FAILURE — approved local model inventory "
                            "changed; AI inference is blocked until reviewed.",
                            Severity.CRITICAL,
                            mismatches=mismatches[:20],
                            checked=checked,
                            baseline_status=self._baseline_status,
                            mitre="T1565.001 (Stored Data Manipulation)",
                        )
                else:
                    self._verified += checked
                    self._last_alert_signature = ""
                    self.set_health(
                        100,
                        f"{checked} approved model manifest/blob file(s) attested clean",
                    )
            except ModelIntegrityError as exc:
                self.last_error = str(exc)
                baseline_failure = self._baseline_status != "approved"
                health = 25 if baseline_failure else 0
                self.set_health(health, f"model attestation unavailable: {exc}")
                signature = f"unavailable:{self._baseline_status}:{exc}"
                if signature != self._last_alert_signature:
                    self._last_alert_signature = signature
                    self.emit(
                        "AI model attestation unavailable; model inference is blocked."
                        if baseline_failure
                        else "MODEL INTEGRITY FAILURE — approved inventory is missing, "
                        "unreadable, or structurally invalid; inference is blocked.",
                        Severity.MEDIUM if baseline_failure else Severity.CRITICAL,
                        baseline_status=self._baseline_status,
                        error=str(exc),
                    )
            self.sleep(self._INTERVAL)

    def self_test(self) -> tuple[bool, str]:
        """Offline: prove the hasher detects a single-byte change, and report
        whether any local models were discovered."""
        ok = True
        detail_bits = []
        try:
            with tempfile.NamedTemporaryFile(delete=False) as tf:
                tf.write(b"angerona-model-attestation-selftest")
                tmp = tf.name
            h1 = _hash_file(tmp)
            with open(tmp, "ab") as f:
                f.write(b"X")            # tamper by one byte
            h2 = _hash_file(tmp)
            os.unlink(tmp)
            ok = (len(h1) == 64 and h1 != h2)
            detail_bits.append("chunked SHA-256 tamper-detect verified" if ok
                               else f"hash mismatch-detect FAILED (h1={h1[:12]} h2={h2[:12]})")
        except Exception as exc:
            ok = False
            detail_bits.append(f"hash self-test error: {exc}")

        root = self._models_root()
        detail_bits.append(f"model dir: {root}" if root else "no local model dir (attestation idle)")
        return ok, "; ".join(detail_bits)


def require_fresh_model_attestation(
    model_ref: str,
    *,
    maximum_age_seconds: float = _ATTESTATION_TTL_SECONDS,
) -> ModelAttestationReceipt:
    """Return fresh evidence for one exact configured tag or fail closed.

    A small authenticated baseline is re-read on every call. The expensive full
    manifest/blob verification is cached only for a short monotonic interval;
    deletion or mutation of the authority file invalidates the cache at once.
    """
    from angerona.core.ollama_lifecycle import validate_model_ref

    maximum_age = float(maximum_age_seconds)
    if not 0 <= maximum_age <= _ATTESTATION_TTL_SECONDS:
        raise ValueError("model attestation age exceeds the security bound")
    normalized = validate_model_ref(model_ref)
    if "@" in normalized:
        raise ModelIntegrityError("AI triage requires a named model tag")
    name, separator, tag = normalized.partition(":")
    tag = tag if separator else "latest"
    manifest_relative = (
        PurePosixPath("manifests")
        / "registry.ollama.ai"
        / "library"
        / name
        / tag
    ).as_posix()

    with _ATTESTATION_LOCK:
        guard = AIModelIntegrityGuardModule()
        if not guard._load_baseline():
            raise ModelIntegrityError(
                f"approved model baseline unavailable ({guard._baseline_status})"
            )
        root, root_identity = guard._validated_root()
        if root_identity != guard._baseline_root:
            raise ModelIntegrityError("approved model root identity changed")
        now = time.monotonic()
        cached = _ATTESTATION_CACHE.get(normalized)
        if (
            cached is not None
            and cached.baseline_sha256 == guard._baseline_sha256
            and now <= cached.expires_monotonic
            and now - cached.issued_monotonic <= maximum_age
        ):
            return cached

        checked, mismatches = guard._verify_pass()
        if checked < 1 or mismatches:
            summary = "; ".join(mismatches[:5]) or "empty verification"
            raise ModelIntegrityError(f"approved model inventory changed: {summary}")
        manifest_hex = guard._baseline.get(manifest_relative)
        if manifest_hex is None:
            raise ModelIntegrityError(
                "configured model tag is not present in the approved baseline"
            )
        verification = verify_ollama_model_files(
            normalized,
            f"sha256:{manifest_hex}",
            models_root=root,
        )
        issued = time.monotonic()
        receipt = ModelAttestationReceipt(
            model_ref=normalized,
            manifest_digest=verification.manifest_digest,
            baseline_sha256=guard._baseline_sha256,
            blob_count=verification.blob_count,
            bytes_verified=verification.bytes_verified,
            issued_monotonic=issued,
            expires_monotonic=issued + _ATTESTATION_TTL_SECONDS,
        )
        _ATTESTATION_CACHE[normalized] = receipt
        return receipt


def register() -> AIModelIntegrityGuardModule:
    return AIModelIntegrityGuardModule()
