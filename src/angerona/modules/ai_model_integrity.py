"""ai_model_integrity.py — AI Model Integrity Guard (Code: AMIG).

Purpose
    Local LLM weights (e.g. Ollama blobs) are loaded into RAM and trusted by the
    triage engine. If an attacker tampers with or poisons a model file on disk,
    every downstream AI decision is compromised. AMIG computes cryptographic
    SHA-256 hashes of the local model blobs and compares them against a recorded
    baseline, raising a CRITICAL alert on any mismatch BEFORE the suite trusts a
    model for inference.

Trust-on-first-use baseline
    On first run (no baseline recorded) AMIG hashes the discovered model blobs
    and records them as the known-good baseline, then emits an INFO event naming
    what it pinned. On every subsequent pass it re-hashes and compares. This is
    TOFU: it detects post-baseline tampering. Re-pin deliberately by deleting the
    baseline file (or calling ``rebaseline()``) after an intentional model update.

Discovery
    Ollama blob directory, in priority order:
      1. ``ANGERONA_OLLAMA_MODELS`` (env)   2. ``OLLAMA_MODELS`` (env)
      3. ``%USERPROFILE%\\.ollama\\models`` (Windows) / ``~/.ollama/models``
    Hashes the ``blobs/sha256-*`` files. (An Ollama blob is content-addressed by
    its own sha256, so AMIG also flags a blob whose *content* no longer matches
    the sha256 embedded in its filename — a strong, self-describing check.)

Safety
    Read-only. Hashes files in 4 MB chunks (no whole-file load). Never modifies,
    deletes, or loads a model; on mismatch it only alerts — enforcement (refusing
    to load) is left to the AI triage layer / SOAR.

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from angerona.core.module_base import BaseModule, Severity


_SHA256_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_MAX_MANIFEST_BYTES = 16 * 1024 * 1024
_MAX_MANIFEST_BLOBS = 10_000


class ModelIntegrityError(RuntimeError):
    """Raised when a local Ollama model cannot be verified from disk."""


@dataclass(frozen=True)
class LocalModelVerification:
    """Bounded evidence from an on-disk Ollama manifest and its blobs."""

    manifest_digest: str
    blob_count: int
    bytes_verified: int
    manifest_path: str


def _repo_root() -> Path:
    from angerona.core.data_paths import data_dir
    return data_dir()


def _hash_file(filepath: str | os.PathLike, chunk: int = 4096 * 1024) -> str:
    """SHA-256 a (potentially multi-GB) file in chunks — no whole-file load."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for block in iter(lambda: f.read(chunk), b""):
                h.update(block)
        return h.hexdigest()
    except FileNotFoundError:
        return "FILE_NOT_FOUND"
    except Exception as exc:  # permission / IO
        return f"ERROR:{exc}"


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
    version = "1.0.0"

    _INTERVAL = 30 * 60.0     # re-attest every 30 min

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._baseline_path = _repo_root() / "shared_logs" / "model_baselines.json"
        self._baseline: dict[str, str] = {}
        self._verified = 0
        self._mismatches = 0

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

    def _discover_blobs(self) -> dict[str, str]:
        """Return {blob_relpath: absolute_path} for every model blob found."""
        root = self._models_root()
        out: dict[str, str] = {}
        if not root:
            return out
        blobs = root / "blobs"
        search = blobs if blobs.exists() else root
        for p in search.rglob("sha256-*"):
            if p.is_file():
                out[p.name] = str(p)
        return out

    # ── baseline persistence ─────────────────────────────────────────────────
    def _load_baseline(self) -> None:
        try:
            if self._baseline_path.exists():
                self._baseline = json.loads(self._baseline_path.read_text("utf-8"))
        except Exception as exc:
            self.last_error = str(exc)
            self._baseline = {}

    def _save_baseline(self) -> None:
        try:
            self._baseline_path.parent.mkdir(parents=True, exist_ok=True)
            with self.state_lock:
                self._baseline_path.write_text(json.dumps(self._baseline, indent=2), "utf-8")
        except Exception as exc:
            self.last_error = str(exc)

    def rebaseline(self) -> int:
        """Re-pin the current on-disk blobs as the new known-good baseline.
        Call after an intentional model update. Returns number of blobs pinned."""
        blobs = self._discover_blobs()
        self._baseline = {name: _hash_file(path) for name, path in blobs.items()}
        self._save_baseline()
        return len(self._baseline)

    # ── verification ─────────────────────────────────────────────────────────
    def _verify_pass(self) -> tuple[int, list[str]]:
        """Hash every discovered blob; return (checked, mismatched_names)."""
        blobs = self._discover_blobs()
        mismatches: list[str] = []
        checked = 0
        for name, path in blobs.items():
            if self.stopping:
                break
            current = _hash_file(path)
            checked += 1

            # 1) Content-address self-check: Ollama names a blob sha256-<hex>.
            expected_self = name.split("sha256-", 1)[-1].lower() if "sha256-" in name else ""
            if expected_self and current and not current.startswith("ERROR") \
                    and current != "FILE_NOT_FOUND" and current.lower() != expected_self:
                mismatches.append(f"{name} (content≠self-address)")
                continue

            # 2) Baseline comparison (TOFU).
            base = self._baseline.get(name)
            if base is None:
                self._baseline[name] = current     # pin newly-seen blob
            elif base != current:
                mismatches.append(f"{name} (content≠baseline)")
        return checked, mismatches

    # ── lifecycle ────────────────────────────────────────────────────────────
    def run(self) -> None:
        self._load_baseline()
        first = not self._baseline
        if self._models_root() is None:
            self.set_health(60, "no Ollama model directory found — nothing to attest")
            self.emit("AMIG: no local model directory found; attestation idle. "
                      "Set ANGERONA_OLLAMA_MODELS if models live elsewhere.",
                      Severity.LOW, idle=True)
            while not self.stopping:
                self.sleep(self._INTERVAL)
            return

        if first:
            n = self.rebaseline()
            self.emit(f"AMIG: pinned baseline for {n} local model blob(s) (trust-on-first-use).",
                      Severity.INFO, pinned=n)

        self.emit("AMIG online — cryptographic model attestation active.", Severity.INFO)
        while not self.stopping:
            try:
                checked, mismatches = self._verify_pass()
                if mismatches:
                    self._mismatches += len(mismatches)
                    self.set_health(0, f"{len(mismatches)} model blob(s) failed attestation")
                    self.emit(
                        f"⚠ MODEL INTEGRITY FAILURE — {len(mismatches)} blob(s) do not match "
                        f"their known-good hash (possible poisoning/tampering): "
                        f"{', '.join(mismatches[:5])}. Do NOT trust affected model(s) until reviewed.",
                        Severity.CRITICAL, mismatches=mismatches[:20], checked=checked,
                        mitre="T1565.001 (Stored Data Manipulation)")
                else:
                    self._verified += checked
                    self._save_baseline()   # persist any newly-pinned blobs
                    self.set_health(100, f"{checked} model blob(s) attested clean")
            except Exception as exc:
                self.last_error = str(exc)
                self.set_health(50, f"attestation error: {exc}")
            self.sleep(self._INTERVAL)

    def self_test(self) -> tuple[bool, str]:
        """Offline: prove the hasher detects a single-byte change, and report
        whether any local models were discovered."""
        import tempfile
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


def register() -> AIModelIntegrityGuardModule:
    return AIModelIntegrityGuardModule()
