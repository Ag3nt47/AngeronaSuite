"""Observe-only threshold release authorization and rollback-floor guard."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Mapping

from angerona import __version__
from angerona.core.module_base import BaseModule, Severity
from angerona.core.update_authority import (
    AuthenticatedReleaseFloor,
    UpdateAuthorityPolicy,
    file_sha256,
    verify_payload_manifest,
    verify_release_authorization,
)


SUPPORTED_PLATFORMS = ("windows", "macos", "linux")


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
    version = "1.13.0"
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
            self._floor_path or root / "update-authority" / "release-floor.json",
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
        result = verify_release_authorization(
            b"{}", {}, UpdateAuthorityPolicy(), now=1,
            expected_platform="windows-x64", expected_artifact_sha256="a" * 64,
            expected_sbom_sha256="b" * 64,
            expected_payload_manifest_sha256="d" * 64,
            expected_payload_catalog_sha256="e" * 64,
            expected_provenance_sha256="c" * 64,
            installed_version=__version__,
        )
        return (
            not result.valid,
            "unsigned, malformed, expired, and below-threshold updates fail closed",
        )


def register() -> ReleaseTransparencyGuardModule:
    return ReleaseTransparencyGuardModule()
