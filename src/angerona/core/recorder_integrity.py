"""Explicit independent-witness enrollment and lazy runtime composition.

Only public enrollment settings are stored in settings.json. The host request
key belongs to the OS credential store, while the authority signing key stays
on the independently administered witness. Constructing a provider performs no
key-store/file/network access; consumers resolve it on their own workers.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path
import re
import threading
from types import MappingProxyType


KEY_NAME = "ANGERONA_RECORDER_WITNESS_PRIVATE_KEY"
CLIENT_KEY_ID = "sentinel-client-ed25519-v1"
AUTHORITY_KEY_ID = "sentinel-authority-ed25519-v1"
DEFAULTS = {
    "recorder_witness_enabled": False,
    "recorder_witness_independent_host": False,
    "recorder_witness_endpoint": "",
    "recorder_witness_certificate_sha256": "",
    "recorder_witness_authority_public_key": "",
    "recorder_witness_installation_id": "",
    "recorder_witness_client_id": "",
    "recorder_witness_client_certificate_path": "",
    "recorder_witness_client_key_path": "",
    "recorder_witness_ca_bundle_path": "",
    "recorder_witness_archive_mib": 16,
}
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class RecorderEnrollmentError(ValueError):
    """Sanitized enrollment failure; protection does not depend on this option."""


def validate_settings(values: dict, *, parse_public_key=True) -> dict:
    if type(values) is not dict or set(values) != set(DEFAULTS):
        raise RecorderEnrollmentError("Independent recorder enrollment schema is invalid")
    result = dict(values)
    for name in ("recorder_witness_enabled", "recorder_witness_independent_host"):
        if type(result[name]) is not bool:
            raise RecorderEnrollmentError("Independent recorder switches must be booleans")
    limit = result["recorder_witness_archive_mib"]
    if type(limit) is not int or not 4 <= limit <= 64:
        raise RecorderEnrollmentError("Recorder receipt storage must be between 4 and 64 MiB")
    for name, value in result.items():
        if name in {"recorder_witness_enabled", "recorder_witness_independent_host", "recorder_witness_archive_mib"}:
            continue
        maximum = 2048 if name.endswith("public_key") else 4096 if name.endswith("path") else 512
        if (type(value) is not str or len(value) > maximum
                or any((ord(char) < 32 and not (name.endswith("public_key") and char in "\r\n"))
                       or ord(char) == 127 for char in value)):
            raise RecorderEnrollmentError("Independent recorder enrollment text is invalid")
    endpoint = result["recorder_witness_endpoint"]
    if endpoint:
        from .personal_sentinel_gateway import _parse_enrolled_endpoint
        try:
            parsed, host = _parse_enrolled_endpoint(endpoint)
            if parsed.path != "/v1/authority" or host == "localhost" or ipaddress.ip_address(host).is_loopback:
                raise ValueError("A separately administered remote endpoint is required")
        except ValueError as exc:
            raise RecorderEnrollmentError("Use a private HTTPS witness address on another machine with /v1/authority") from exc
    for name in ("recorder_witness_installation_id", "recorder_witness_client_id"):
        if result[name] and not _HEX32.fullmatch(result[name]):
            raise RecorderEnrollmentError("Witness installation and client IDs need 32 lowercase hexadecimal characters")
    pin = result["recorder_witness_certificate_sha256"]
    if pin and not _HEX64.fullmatch(pin):
        raise RecorderEnrollmentError("Witness TLS certificate pin needs 64 lowercase hexadecimal characters")
    public = result["recorder_witness_authority_public_key"]
    if public and parse_public_key:
        from .personal_sentinel_authority import Ed25519PublicVerifier
        try:
            Ed25519PublicVerifier.from_pem(public.encode("ascii"), key_id=AUTHORITY_KEY_ID)
        except Exception as exc:
            raise RecorderEnrollmentError("Witness authority needs an Ed25519 public PEM key") from exc
    for name in ("recorder_witness_client_certificate_path", "recorder_witness_client_key_path",
                 "recorder_witness_ca_bundle_path"):
        value = result[name]
        if value and (not Path(value).is_absolute() or value.startswith(("\\\\", "//"))
                      or ".." in Path(value).parts):
            raise RecorderEnrollmentError("Witness TLS files must use fixed absolute local paths")
    if result["recorder_witness_enabled"]:
        required = ("recorder_witness_endpoint", "recorder_witness_certificate_sha256",
                    "recorder_witness_authority_public_key", "recorder_witness_installation_id",
                    "recorder_witness_client_id", "recorder_witness_client_certificate_path",
                    "recorder_witness_client_key_path")
        if not result["recorder_witness_independent_host"] or any(not result[name] for name in required):
            raise RecorderEnrollmentError("Complete the remote witness enrollment and confirm its independent custody before enabling")
    return result


def load_settings(values: dict) -> dict:
    """Bound malformed saved fields without silently disabling requested checks."""
    result = {}
    for name, default in DEFAULTS.items():
        value = values.get(name, default)
        if type(default) is bool:
            result[name] = value if type(value) is bool else default
        elif type(default) is int:
            result[name] = value if type(value) is int and 4 <= value <= 64 else default
        else:
            maximum = 2048 if name.endswith("public_key") else 4096 if name.endswith("path") else 512
            result[name] = value if type(value) is str and len(value) <= maximum else default
    return result


def settings_from_config(config) -> dict:
    return {name: getattr(config, name, default) for name, default in DEFAULTS.items()}


def provision_host_identity(data_root: Path) -> str:
    """Explicit worker action; return only the public enrollment key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from .personal_sentinel_authority import Ed25519PrivateSigner
    from .secure_store import get_or_create_secret

    def create_pem():
        private = Ed25519PrivateKey.generate()
        return private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()).decode("ascii")

    pem = get_or_create_secret(KEY_NAME, create_pem, Path(data_root))
    signer = Ed25519PrivateSigner.from_pem(pem.encode("ascii"), key_id=CLIENT_KEY_ID)
    return signer.public_verifier()._public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")


def client_from_settings(values: dict, data_root: Path):
    """Worker-only key resolution and one enrolled transport; no request yet."""
    from .personal_sentinel_authority import (
        Ed25519PrivateSigner, Ed25519PublicVerifier, PersonalSentinelAuthorityClient, PinnedHttpsSentinelTransport,
    )
    from .sentinel_remote_floor import RawSignedFloorClient
    from .secure_store import read_secret_values

    settings = validate_settings(values)
    if not settings["recorder_witness_enabled"]:
        raise RecorderEnrollmentError("Independent recorder witness is disabled")
    pem = read_secret_values((KEY_NAME,), Path(data_root), strict=True).get(KEY_NAME)
    if not pem:
        raise RecorderEnrollmentError("Generate and enroll this host's public request identity first")
    signer = Ed25519PrivateSigner.from_pem(pem.encode("ascii"), key_id=CLIENT_KEY_ID)
    verifier = Ed25519PublicVerifier.from_pem(
        settings["recorder_witness_authority_public_key"].encode("ascii"), key_id=AUTHORITY_KEY_ID)
    transport = PinnedHttpsSentinelTransport(settings["recorder_witness_endpoint"],
        settings["recorder_witness_certificate_sha256"],
        client_certificate_path=settings["recorder_witness_client_certificate_path"],
        client_key_path=settings["recorder_witness_client_key_path"],
        ca_bundle_path=settings["recorder_witness_ca_bundle_path"])
    floor = RawSignedFloorClient(installation_id=settings["recorder_witness_installation_id"],
        client_instance_id=settings["recorder_witness_client_id"], request_signer=signer,
        response_verifier=verifier, transport=transport,
        independently_administered=settings["recorder_witness_independent_host"])
    return PersonalSentinelAuthorityClient(installation_id=settings["recorder_witness_installation_id"],
        client_instance_id=settings["recorder_witness_client_id"], request_signer=signer,
        response_verifier=verifier, response_floor=floor, transport=transport)


@dataclass(frozen=True)
class EnrollmentStatus:
    state: str
    reason: str


class ConfiguredWitnessProvider:
    """Lazy known composition for integrity constructors and the epoch worker."""
    def __init__(self, values: dict, data_root: Path):
        self._values = MappingProxyType(load_settings(values))
        self._data_root = Path(data_root)
        self._client = None
        self._lock = threading.Lock()
        self._status = EnrollmentStatus("not-checked", "No witness connection has been attempted")

    @property
    def installation_id(self):
        return self._values["recorder_witness_installation_id"]

    @property
    def client_instance_id(self):
        return self._values["recorder_witness_client_id"]

    @property
    def response_verifier(self):
        return self._resolve().response_verifier

    def latest_status(self):
        return self._status

    def _resolve(self):
        with self._lock:
            if self._client is None:
                try:
                    self._client = client_from_settings(dict(self._values), self._data_root)
                except Exception:
                    self._status = EnrollmentStatus("enrollment-held", "Witness enrollment or protected credentials are unavailable; local records are preserved")
                    raise
                self._status = EnrollmentStatus("configured", "Client configured; a fresh authenticated authority observation is still required")
            return self._client

    def read_head(self, domain):
        return self._resolve().read_head(domain)

    def compare_and_advance(self, transition):
        return self._resolve().compare_and_advance(transition)

    def read_recorder_head(self):
        return self._resolve().read_recorder_head()

    def append_recorder_epoch(self, claim):
        return self._resolve().append_recorder_epoch(claim)


def provider_from_config(config):
    values = settings_from_config(config)
    if values["recorder_witness_enabled"] is not True:
        return None
    return ConfiguredWitnessProvider(values, config.data_dir)
