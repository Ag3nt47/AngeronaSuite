"""Offline lifecycle registry for verified detection packages.

The registry owns immutable, digest-named package copies and a small atomic
manifest.  Activation and rollback never modify package content; they only
replace the manifest after re-running all loader validation gates.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from angerona.core.detection_packages import (
    MAX_PACKAGE_BYTES,
    DetectionPackage,
    PackageValidationError,
    load_package,
)

STATES = {"staged", "active", "retired", "quarantined"}
DEFAULT_LOCK_TIMEOUT = 5.0


@dataclass(frozen=True)
class ValidationReport:
    ok: bool
    action: str
    state: str
    package_id: str | None
    digest: str | None
    errors: tuple[str, ...] = ()
    previous_digest: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["errors"] = list(self.errors)
        return result


class DetectionPackageRegistry:
    """A single-host, local package registry with atomic state transitions."""

    def __init__(
        self,
        root: str | Path,
        *,
        trusted_keys: str | Path | None = None,
        require_signed: bool = True,
        lock_timeout: float = DEFAULT_LOCK_TIMEOUT,
    ) -> None:
        self.root = Path(root).resolve()
        self.packages = self.root / "packages"
        self.quarantine = self.root / "quarantine"
        self.manifest_path = self.root / "registry.json"
        self.lock_path = self.root / "registry.lock"
        self.trusted_keys = Path(trusted_keys).resolve() if trusted_keys else None
        self.require_signed = bool(require_signed)
        self.lock_timeout = max(0.05, min(float(lock_timeout), 60.0))
        self.packages.mkdir(parents=True, exist_ok=True)
        self.quarantine.mkdir(parents=True, exist_ok=True)
        with self._locked():
            if not self.manifest_path.exists():
                self._write_manifest({
                    "schema_version": 1, "packages": {},
                    "activation_policy": (
                        "signed_only" if self.require_signed
                        else "development_unsigned_override"
                    ),
                })
            else:
                manifest = self._manifest()
                policy = (
                    "signed_only" if self.require_signed
                    else "development_unsigned_override"
                )
                if manifest.get("activation_policy") != policy:
                    manifest["activation_policy"] = policy
                    self._write_manifest(manifest)

    @contextmanager
    def _locked(self):
        """Acquire a bounded OS lock; timeout raises instead of racing onward."""
        self.lock_path.touch(exist_ok=True)
        stream = self.lock_path.open("r+b")
        deadline = time.monotonic() + self.lock_timeout
        acquired = False
        try:
            while not acquired:
                try:
                    if os.name == "nt":
                        import msvcrt
                        stream.seek(0)
                        if stream.read(1) == b"":
                            stream.seek(0)
                            stream.write(b"\0")
                            stream.flush()
                        stream.seek(0)
                        msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                except (BlockingIOError, OSError):
                    if time.monotonic() >= deadline:
                        raise PackageValidationError("registry lock acquisition timed out")
                    time.sleep(0.025)
            yield
        finally:
            if acquired:
                try:
                    if os.name == "nt":
                        import msvcrt
                        stream.seek(0)
                        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
            stream.close()

    def _manifest(self) -> dict[str, Any]:
        try:
            data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            if data.get("schema_version") != 1 or not isinstance(data.get("packages"), dict):
                raise ValueError("invalid registry manifest")
            return data
        except Exception as exc:
            raise PackageValidationError(f"registry manifest is invalid: {exc}") from exc

    def _write_manifest(self, data: dict[str, Any]) -> None:
        payload = json.dumps(
            data, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        fd, name = tempfile.mkstemp(prefix=".registry-", suffix=".tmp", dir=self.root)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.manifest_path)
        finally:
            try:
                os.unlink(name)
            except FileNotFoundError:
                pass

    @staticmethod
    def _filename(digest: str) -> str:
        return digest.removeprefix("sha256:") + ".json"

    def _record(self, manifest: dict[str, Any], package_id: str, digest: str) -> dict[str, Any]:
        versions = manifest["packages"].setdefault(package_id, {})
        return versions.setdefault(
            digest,
            {"state": "staged", "previous_digest": None, "trusted": False, "signer": None},
        )

    def _quarantine_bytes(self, raw: bytes, hint: str) -> None:
        import hashlib
        name = hashlib.sha256(raw).hexdigest() + ".json"
        target = self.quarantine / name
        if not target.exists():
            target.write_bytes(raw[:MAX_PACKAGE_BYTES])

    def _signature_path(self, digest: str) -> Path:
        return self.packages / (digest.removeprefix("sha256:") + ".sig.json")

    def _verify_signature(self, package_path: Path, signature_path: Path) -> tuple[bool, str | None]:
        """Verify a detached Ed25519 signature against the explicit local store."""
        if self.trusted_keys is None or not signature_path.is_file():
            return False, None
        try:
            import base64
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            store = json.loads(self.trusted_keys.read_text(encoding="utf-8"))
            signature = json.loads(signature_path.read_text(encoding="utf-8"))
            if set(signature) != {"key_id", "signature"}:
                raise ValueError("signature metadata fields are invalid")
            key_id = signature["key_id"]
            keys = store.get("keys")
            if not isinstance(key_id, str) or not isinstance(keys, dict) or key_id not in keys:
                raise ValueError("publisher key is not trusted")
            key_entry = keys[key_id]
            if not isinstance(key_entry, dict) or set(key_entry) != {"public_key"}:
                raise ValueError("trusted key entry is invalid")
            public_raw = base64.b64decode(key_entry["public_key"], validate=True)
            signature_raw = base64.b64decode(signature["signature"], validate=True)
            if len(public_raw) != 32 or len(signature_raw) != 64:
                raise ValueError("Ed25519 key or signature length is invalid")
            Ed25519PublicKey.from_public_bytes(public_raw).verify(
                signature_raw, package_path.read_bytes()
            )
            return True, key_id
        except ImportError:
            return False, None
        except Exception as exc:
            raise PackageValidationError(f"publisher signature verification failed: {exc}") from exc

    def stage(
        self,
        source: str | Path,
        *,
        signature: str | Path | None = None,
        now: datetime | None = None,
    ) -> ValidationReport:
        """Validate and retain an immutable package, or quarantine invalid input."""
        path = Path(source)
        try:
            raw = path.read_bytes()
            package = load_package(path, now=now)
            document = package.document
            digest, package_id = str(document["digest"]), package.package_id
            supplied_signature = Path(signature) if signature else None
            trusted, signer = self._verify_signature(path, supplied_signature) if supplied_signature else (False, None)
            with self._locked():
                target = self.packages / self._filename(digest)
                if target.exists() and target.read_bytes() != raw:
                    raise PackageValidationError("digest collision with different package bytes")
                if not target.exists():
                    fd, name = tempfile.mkstemp(prefix=".package-", suffix=".tmp", dir=self.packages)
                    try:
                        with os.fdopen(fd, "wb") as stream:
                            stream.write(raw)
                            stream.flush()
                            os.fsync(stream.fileno())
                        os.replace(name, target)
                    finally:
                        try:
                            os.unlink(name)
                        except FileNotFoundError:
                            pass
                if trusted and supplied_signature:
                    signature_target = self._signature_path(digest)
                    signature_target.write_bytes(supplied_signature.read_bytes())
                manifest = self._manifest()
                record = self._record(manifest, package_id, digest)
                if record["state"] != "active":
                    record["state"] = "staged"
                record["trusted"], record["signer"] = trusted, signer
                self._write_manifest(manifest)
            return ValidationReport(True, "stage", record["state"], package_id, digest)
        except Exception as exc:
            try:
                self._quarantine_bytes(raw if "raw" in locals() else b"", path.name)
            except Exception:
                pass
            return ValidationReport(False, "stage", "quarantined", None, None, (str(exc),))

    def activate(self, package_id: str, digest: str, *, now: datetime | None = None) -> ValidationReport:
        """Atomically make a staged digest active after re-validating all gates."""
        try:
            with self._locked():
                return self._activate_locked(package_id, digest, now=now)
        except PackageValidationError as exc:
            return ValidationReport(False, "activate", "quarantined", package_id, digest, (str(exc),))

    def _activate_locked(
        self, package_id: str, digest: str, *, now: datetime | None = None
    ) -> ValidationReport:
        manifest = self._manifest()
        versions = manifest["packages"].get(package_id, {})
        record = versions.get(digest)
        if not record or record.get("state") not in {"staged", "retired", "active"}:
            return ValidationReport(False, "activate", "quarantined", package_id, digest,
                                    ("digest is not staged or retained",))
        try:
            package_path = self.packages / self._filename(digest)
            package = load_package(package_path, now=now)
            if package.package_id != package_id or package.document["digest"] != digest:
                raise PackageValidationError("package identity does not match registry request")
            trusted, signer = self._verify_signature(package_path, self._signature_path(digest))
            if trusted != bool(record.get("trusted")) or signer != record.get("signer"):
                raise PackageValidationError("publisher trust metadata changed")
            if self.require_signed and not trusted:
                raise PackageValidationError("activation policy requires a trusted publisher signature")
        except Exception as exc:
            record["state"] = "quarantined"
            self._write_manifest(manifest)
            return ValidationReport(False, "activate", "quarantined", package_id, digest, (str(exc),))
        prior = next((d for d, item in versions.items() if item.get("state") == "active" and d != digest), None)
        for other_digest, item in versions.items():
            if item.get("state") == "active" and other_digest != digest:
                item["state"] = "retired"
        record["state"] = "active"
        record["previous_digest"] = prior
        self._write_manifest(manifest)
        return ValidationReport(True, "activate", "active", package_id, digest,
                                previous_digest=prior)

    def rollback(self, package_id: str, *, now: datetime | None = None) -> ValidationReport:
        """Return atomically to the active version's recorded predecessor."""
        try:
            with self._locked():
                manifest = self._manifest()
                versions = manifest["packages"].get(package_id, {})
                active = next(((d, r) for d, r in versions.items() if r.get("state") == "active"), None)
                if not active or not active[1].get("previous_digest"):
                    return ValidationReport(False, "rollback", "quarantined", package_id, None,
                                            ("no rollback target is recorded",))
                return self._activate_locked(package_id, active[1]["previous_digest"], now=now)
        except PackageValidationError as exc:
            return ValidationReport(False, "rollback", "quarantined", package_id, None, (str(exc),))

    def retire(self, package_id: str, digest: str) -> ValidationReport:
        try:
            with self._locked():
                manifest = self._manifest()
                record = manifest["packages"].get(package_id, {}).get(digest)
                if not record:
                    return ValidationReport(False, "retire", "quarantined", package_id, digest,
                                            ("unknown package digest",))
                record["state"] = "retired"
                self._write_manifest(manifest)
                return ValidationReport(True, "retire", "retired", package_id, digest)
        except PackageValidationError as exc:
            return ValidationReport(False, "retire", "quarantined", package_id, digest, (str(exc),))

    def active(self, package_id: str, *, now: datetime | None = None) -> DetectionPackage | None:
        """Return only a currently valid and currently trusted active package.

        Trust is re-evaluated on every read so key revocation, detached
        signature removal, package tampering, or expiry cannot leave a stale
        active object usable after activation.
        """
        try:
            with self._locked():
                manifest = self._manifest()
                for digest, record in manifest["packages"].get(
                    package_id, {}
                ).items():
                    if record.get("state") != "active":
                        continue
                    try:
                        package_path = self.packages / self._filename(digest)
                        package = load_package(package_path, now=now)
                        trusted, signer = self._verify_signature(
                            package_path, self._signature_path(digest)
                        )
                        if (
                            package.package_id != package_id
                            or package.document["digest"] != digest
                            or trusted != bool(record.get("trusted"))
                            or signer != record.get("signer")
                            or (self.require_signed and not trusted)
                        ):
                            raise PackageValidationError(
                                "active package trust validation failed"
                            )
                        return package
                    except Exception:
                        record["state"] = "quarantined"
                        self._write_manifest(manifest)
                        return None
        except PackageValidationError:
            return None
        return None

    def inventory(self) -> dict[str, Any]:
        """Return a detached, structured view suitable for a local UI/report."""
        return json.loads(json.dumps(self._manifest()["packages"]))
