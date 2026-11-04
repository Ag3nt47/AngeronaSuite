"""Observe-only threshold release authorization and rollback-floor guard."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import stat
import sys
import time
from dataclasses import asdict, replace
from pathlib import Path
from typing import Mapping

from angerona import __version__
from angerona.core.module_base import BaseModule, Severity
from angerona.core.update_authority import (
    SCHEMA,
    AuthenticatedReleaseFloor,
    ReleaseAuthorizationStatement,
    UpdateAuthorityPolicy,
    file_sha256,
    verify_payload_manifest,
    verify_release_authorization,
)


SUPPORTED_PLATFORMS = ("windows", "macos", "linux")
_RELEASE_FLOOR = Path("update-authority") / "release-floor.json"


class _SourceReleaseEvidenceUnprovisioned(ValueError):
    """A default source run has not observed any release sidecar or floor."""


def _read_bounded(path: Path, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("release evidence is not a bounded regular file")
    return path.read_bytes()


def load_update_trust_store(path: Path) -> dict[str, bytes]:
    raw = json.loads(_read_bounded(path, 64 * 1024))
    if not isinstance(raw, dict) or not 1 <= len(raw) <= 32:
        raise ValueError("release trust store has an invalid schema")
    trust: dict[str, bytes] = {}
    key_digests: set[bytes] = set()
    for identity, value in raw.items():
        if not isinstance(identity, str) or not isinstance(value, str):
            raise ValueError("release trust store entry is invalid")
        try:
            public = base64.b64decode(
                value + "=" * (-len(value) % 4), altchars=b"-_", validate=True,
            )
        except Exception as exc:
            raise ValueError("release trust store key encoding is invalid") from exc
        if len(public) != 32:
            raise ValueError("release trust store requires Ed25519 public keys")
        if public in key_digests:
            raise ValueError("release trust store aliases one publisher key")
        key_digests.add(public)
        trust[identity] = public
    return trust


class ReleaseTransparencyGuardModule(BaseModule):
    CODE = "RTAG"
    NAME = "Release Transparency / Anti-Rollback Guard"
    name = NAME
    description = (
        "Verifies threshold publisher authorization binding the executable, complete "
        "payload manifest/catalog, SBOM, provenance, builder, and rollback sequence."
    )
    category = "Supply Chain"
    version = "1.14.0"
    supported_platforms = frozenset(SUPPORTED_PLATFORMS)
    capability_mode = "observe"
    platform_requirements = (
        "Externally pinned Ed25519 publisher keys",
        "release-authorization.json shipped by the release pipeline",
        "Independent witness for rollback resistance beyond the local administrator",
    )
    _INTERVAL = 1800.0

    def __init__(
        self,
        *,
        authorization_path: Path | None = None,
        trust_store_path: Path | None = None,
        artifact_path: Path | None = None,
        sbom_path: Path | None = None,
        payload_manifest_path: Path | None = None,
        payload_catalog_path: Path | None = None,
        payload_root: Path | None = None,
        provenance_path: Path | None = None,
        floor_path: Path | None = None,
        floor_key: bytes | None = None,
        trust_store: Mapping[str, bytes] | None = None,
        platform: str | None = None,
        clock=time.time,
    ) -> None:
        super().__init__()
        base = Path(sys.executable).resolve().parent
        self._authorization = authorization_path or base / "release-authorization.json"
        self._trust_path = trust_store_path
        self._artifact = artifact_path or Path(sys.executable)
        self._sbom = sbom_path or base / "Angerona-SBOM.json"
        self._payload_manifest = (
            payload_manifest_path or base / "release-payload-manifest.json"
        )
        self._payload_catalog = payload_catalog_path or base / "release-payload.cat"
        self._payload_root = payload_root or base
        self._provenance = provenance_path or base / "release-build-provenance.json"
        self._floor_path = floor_path
        self._floor_key = bytes(floor_key) if floor_key is not None else None
        if self._floor_key is not None and len(self._floor_key) != 32:
            raise ValueError("release floor key override must contain exactly 32 bytes")
        self._trust = dict(trust_store) if trust_store is not None else None
        self._platform = platform or (
            "windows-x64" if sys.platform.startswith("win")
            else "macos-arm64" if sys.platform == "darwin"
            else "linux-x86_64"
        )
        self._clock = clock
        self._last_state = ""
        self._source_bundle_unseen = not getattr(sys, "frozen", False) and all(
            value is None for value in (
                authorization_path, trust_store_path, artifact_path, sbom_path,
                payload_manifest_path, payload_catalog_path, payload_root,
                provenance_path, floor_path, floor_key, trust_store,
            )
        )

    def _source_bundle_unprovisioned(self) -> bool:
        if not self._source_bundle_unseen:
            return False
        parent = self._authorization.parent
        try:
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                self._source_bundle_unseen = False
                return False
            for path in (
                self._authorization, self._sbom, self._payload_manifest,
                self._payload_catalog, self._provenance, parent / "release-trust.json",
            ):
                try:
                    path.lstat()
                except FileNotFoundError:
                    continue
                self._source_bundle_unseen = False
                return False
            from angerona.core.data_paths import resolve_data_dir

            root = resolve_data_dir()
            floor = root / _RELEASE_FLOOR
            try:
                for directory in (root, floor.parent):
                    info = directory.lstat()
                    if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                        self._source_bundle_unseen = False
                        return False
                floor.lstat()
            except FileNotFoundError:
                return True
            # Any object at the exact floor path is evidence of possible prior
            # provisioning. Its contents do not grant source-run classification.
            self._source_bundle_unseen = False
            return False
        except Exception:
            self._source_bundle_unseen = False
            raise

    def _floor_store(self) -> AuthenticatedReleaseFloor:
        from angerona.core.data_paths import data_dir

        root = data_dir()
        key = self._floor_key
        if key is None:
            bus_key = root / "bus.key"
            if bus_key.is_symlink() or not bus_key.is_file() or bus_key.stat().st_size > 128:
                raise ValueError("release floor authority is unavailable")
            try:
                master = bytes.fromhex(bus_key.read_text(encoding="ascii").strip())
            except (OSError, UnicodeError, ValueError) as exc:
                raise ValueError("release floor authority is unavailable") from exc
            if len(master) != 32:
                raise ValueError("release floor authority is unavailable")
            key = hmac.new(
                master, b"Angerona-Release-Floor-v1\x00", hashlib.sha256,
            ).digest()
        return AuthenticatedReleaseFloor(
            self._floor_path or root / _RELEASE_FLOOR,
            key,
        )

    def _trust_store(self) -> dict[str, bytes]:
        if self._trust is not None:
            return dict(self._trust)
        if self._trust_path is not None:
            return load_update_trust_store(self._trust_path)
        return load_update_trust_store(
            Path(sys.executable).resolve().parent / "release-trust.json"
        )

    def observe_once(self):
        if self._source_bundle_unprovisioned():
            raise _SourceReleaseEvidenceUnprovisioned
        raw = _read_bounded(self._authorization, 256 * 1024)
        payload_manifest_raw = _read_bounded(
            self._payload_manifest, 2 * 1024 * 1024,
        )
        digest = file_sha256(self._artifact)
        floor_store = self._floor_store()
        floor = floor_store.load()
        result = verify_release_authorization(
            raw, self._trust_store(), UpdateAuthorityPolicy(),
            now=float(self._clock()), expected_platform=self._platform,
            expected_artifact_sha256=digest, installed_version=__version__,
            expected_sbom_sha256=file_sha256(self._sbom),
            expected_payload_manifest_sha256=file_sha256(self._payload_manifest),
            expected_payload_catalog_sha256=file_sha256(self._payload_catalog),
            expected_provenance_sha256=file_sha256(self._provenance),
            highest_sequence=floor.highest_sequence if floor else 0,
            highest_version=floor.highest_version if floor else "0.0.0",
            floor_statement_sha256=floor.statement_sha256 if floor else "",
        )
        payload_errors = verify_payload_manifest(
            payload_manifest_raw, self._payload_root,
        )
        if payload_errors:
            result = replace(
                result,
                valid=False,
                errors=result.errors + payload_errors,
            )
        if result.valid:
            floor_store.advance(result)
        return result

    def run(self) -> None:
        while not self.stopping:
            try:
                result = self.observe_once()
                self.set_health(
                    100 if result.valid else 20,
                    "threshold release authorization verified" if result.valid
                    else "; ".join(result.errors[:3]),
                )
                state = f"{result.statement_sha256}:{result.valid}:{'|'.join(result.errors)}"
                if state != self._last_state:
                    self._last_state = state
                    self.emit(
                        "Release authorization verified." if result.valid
                        else "Release authorization is missing or invalid.",
                        Severity.INFO if result.valid else Severity.CRITICAL,
                        authorization_sha256=result.statement_sha256,
                        verified_signers=list(result.verified_signers),
                        error_codes=list(result.errors[:8]),
                        threshold=UpdateAuthorityPolicy().signature_threshold,
                        observation_only=True,
                        local_trust_root_replaceable_by_admin=True,
                    )
            except _SourceReleaseEvidenceUnprovisioned:
                self.set_health(15, "installed release evidence is unprovisioned in this source run")
                if self._last_state != "source-bundle-unprovisioned":
                    self._last_state = "source-bundle-unprovisioned"
                    self.emit(
                        "Installed release evidence is unprovisioned in this source run.",
                        Severity.HIGH,
                        schema="angerona.release-transparency-status.v1",
                        finding_code="release-transparency.source-bundle-unprovisioned",
                        state="unavailable",
                        runtime="source",
                        observation_only=True,
                        response_authority="observe-only",
                        response_authorized=False,
                        automatic_install_authorized=False,
                    )
            except Exception as exc:
                self.set_health(15, "release authorization unavailable; update trust is unknown")
                state = f"missing:{type(exc).__name__}"
                if state != self._last_state:
                    self._last_state = state
                    self.emit(
                        "Release transparency evidence is unavailable.",
                        Severity.HIGH,
                        error_type=type(exc).__name__, observation_only=True,
                        automatic_install_authorized=False,
                    )
            self.sleep(self._INTERVAL)

    def self_test(self) -> tuple[bool, str]:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        policy = UpdateAuthorityPolicy(allowed_builders=("fixture-builder",))
        statement = ReleaseAuthorizationStatement(
            schema=SCHEMA, product="Angerona", version="1.0.0", sequence=2,
            platform="windows-x64", artifact_sha256="a" * 64, sbom_sha256="b" * 64,
            payload_manifest_sha256="d" * 64, payload_catalog_sha256="e" * 64,
            provenance_sha256="c" * 64, source_revision="f" * 40,
            builder_id="fixture-builder", issued_at=1, expires_at=120,
        )
        publishers = {name: Ed25519PrivateKey.generate() for name in ("fixture-a", "fixture-b")}
        trust = {name: key.public_key().public_bytes_raw() for name, key in publishers.items()}
        signed_bytes = statement.canonical()
        signatures = [{
            "signer_id": name,
            "signature": base64.urlsafe_b64encode(key.sign(signed_bytes)).decode("ascii").rstrip("="),
        } for name, key in publishers.items()]

        def verify(evidence, signer_rows, *, now=60, floor=0):
            envelope = json.dumps({"statement": asdict(evidence), "signatures": signer_rows}).encode("utf-8")
            return verify_release_authorization(
                envelope, trust, policy, now=now,
                expected_platform="windows-x64", expected_artifact_sha256="a" * 64,
                expected_sbom_sha256="b" * 64, expected_payload_manifest_sha256="d" * 64,
                expected_payload_catalog_sha256="e" * 64, expected_provenance_sha256="c" * 64,
                installed_version="1.0.0", highest_sequence=floor,
            )

        valid = verify(statement, signatures)
        if not valid.valid or valid.verified_signers != tuple(trust):
            return False, "Release authorization rejected the valid two-publisher sample"
        forged = [signatures[0], {**signatures[1],
                  "signature": base64.urlsafe_b64encode(bytes(64)).decode("ascii").rstrip("=")}]
        if (verify(statement, signatures[:1]).valid
                or verify(statement, forged).valid
                or verify(replace(statement, source_revision="1" * 40), signatures).valid
                or verify(statement, signatures, now=120).valid
                or verify(statement, signatures, floor=3).valid):
            return False, "Release authorization admitted an invalid threshold, signature, metadata, expiry or rollback sample"
        return True, ("Offline release sample accepted two independent publishers; below-threshold, forged, altered, "
                      "expired and rollback samples fail closed. Installed release evidence was not exercised.")


def register() -> ReleaseTransparencyGuardModule:
    return ReleaseTransparencyGuardModule()
