"""Local endpoint identity and signed fleet-connection contracts.

This module does not implement a server, transport, or mTLS. It only creates
and verifies artifacts that a future authenticated transport may carry.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import secrets
import stat
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    _CRYPTO_ERROR: Exception | None = None
except Exception as exc:  # pragma: no cover - fail-closed path
    Ed25519PrivateKey = Ed25519PublicKey = None  # type: ignore
    serialization = None  # type: ignore
    _CRYPTO_ERROR = exc

MAX_LEDGER_ENTRIES = 10_000
MAX_STATE_BYTES = 2 * 1024 * 1024
MAX_ENVELOPE_BYTES = 64 * 1024
IDENTITY_STATE_VERSION = 2
_ENDPOINT = re.compile(r"^[A-Za-z0-9.-]{1,253}:[1-9][0-9]{0,4}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
_DEVICE_ID = re.compile(r"^device-[0-9a-f]{32}$")


def _require_crypto() -> None:
    if _CRYPTO_ERROR is not None:
        raise RuntimeError("Ed25519 cryptography support is required") from _CRYPTO_ERROR


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("identity data must use finite JSON-safe types") from exc


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _strict_unb64(value: Any, expected_size: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError("invalid bounded base64url value")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("invalid base64url alphabet")
    raw = _unb64(value)
    if len(raw) != expected_size or _b64(raw) != value:
        raise ValueError("invalid base64url size or encoding")
    return raw


def _device_id(public_key: bytes) -> str:
    return "device-" + hashlib.sha256(public_key).hexdigest()[:32]


def _reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate identity state field: {key}")
        value[key] = item
    return value


def _read_json_object(path: Path, *, max_bytes: int = MAX_STATE_BYTES) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        raise
    attributes = getattr(metadata, "st_file_attributes", 0)
    if path.is_symlink() or attributes & getattr(
        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
    ):
        raise ValueError("identity state must not be redirected")
    if metadata.st_size <= 0 or metadata.st_size > max_bytes:
        raise ValueError("identity state has an invalid bounded size")
    try:
        value = json.loads(
            path.read_bytes().decode("utf-8"),
            object_pairs_hook=_reject_duplicate_fields,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON value: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("identity state is not strict UTF-8 JSON") from exc
    if type(value) is not dict:
        raise ValueError("identity state must be a JSON object")
    return value


def _atomic_json(path: Path, value: Any) -> None:
    encoded = _canonical(value)
    if len(encoded) > MAX_STATE_BYTES:
        raise ValueError("identity state exceeds bounded size")
    if path.exists() or path.is_symlink():
        metadata = path.lstat()
        attributes = getattr(metadata, "st_file_attributes", 0)
        if path.is_symlink() or attributes & getattr(
            stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
        ):
            raise ValueError("identity state must not be redirected")
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    try:
        with open(temp, "xb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


@contextmanager
def _exclusive_lock(path: Path, timeout: float = 5.0):
    """Bounded cross-process one-byte lock used by replay/high-water state."""
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.touch(exist_ok=True)
    stream = lock_path.open("r+b")
    deadline = time.monotonic() + max(0.05, min(float(timeout), 30.0))
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
                    raise TimeoutError("identity state lock timed out")
                time.sleep(0.01)
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


@dataclass(frozen=True)
class SignedEnrollmentRequest:
    device_id: str
    public_key: str
    nonce: str
    endpoint: str
    expires_at: float
    signature: str

    def unsigned(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("signature")
        return value


@dataclass(frozen=True)
class RotationProof:
    device_id: str
    old_public_key: str
    new_public_key: str
    rotated_at: float
    old_key_signature: str
    new_key_signature: str

    def unsigned(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("old_key_signature")
        value.pop("new_key_signature")
        return value


@dataclass(frozen=True)
class ConnectionEnvelope:
    device_id: str
    sequence: int
    sent_at: float
    kind: str
    payload: Mapping[str, Any]
    signature: str

    def unsigned(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("signature")
        return value


class ReplayLedger:
    def __init__(self, path: Path, *, max_entries: int = MAX_LEDGER_ENTRIES) -> None:
        self.path = Path(path)
        if type(max_entries) is not int or not 1 <= max_entries <= MAX_LEDGER_ENTRIES:
            raise ValueError("replay ledger entry bound is invalid")
        self.max_entries = max_entries

    def _read(self) -> list[str]:
        if not self.path.exists():
            return []
        value = _read_json_object(self.path)
        if set(value) != {"version", "nonces"} or value["version"] != 1:
            raise ValueError("replay ledger schema is invalid")
        entries = value["nonces"]
        if (
            type(entries) is not list
            or len(entries) > self.max_entries
            or len(set(entries)) != len(entries)
            or any(type(item) is not str or not _NONCE.fullmatch(item) for item in entries)
        ):
            raise ValueError("invalid or oversized replay ledger")
        return entries

    def consume(self, nonce: str) -> bool:
        if type(nonce) is not str or not _NONCE.fullmatch(nonce):
            raise ValueError("invalid replay nonce")
        with _exclusive_lock(self.path):
            entries = self._read()
            if nonce in entries:
                return False
            entries.append(nonce)
            _atomic_json(
                self.path,
                {"version": 1, "nonces": entries[-self.max_entries :]},
            )
            return True


class EndpointIdentity:
    def __init__(self, directory: Path) -> None:
        _require_crypto()
        self.directory = Path(directory)
        self.key_path = self.directory / "device-ed25519.key"
        self.state_path = self.directory / "device-identity.json"
        self._private = self._load_or_create_key()
        public = self.public_key
        expected_device_id = _device_id(public)
        if self.state_path.exists():
            try:
                state = _read_json_object(self.state_path)
                expected_fields = {
                    "version",
                    "device_id",
                    "revoked",
                    "quarantined",
                    "public_fingerprint",
                    "state_signature",
                }
                if (
                    type(state) is not dict
                    or set(state) != expected_fields
                    or state["version"] != IDENTITY_STATE_VERSION
                    or not isinstance(state["device_id"], str)
                    or not _DEVICE_ID.fullmatch(state["device_id"])
                    or type(state["revoked"]) is not bool
                    or type(state["quarantined"]) is not bool
                    or state["public_fingerprint"] != self.public_fingerprint
                ):
                    raise ValueError("identity state does not match its private key")
                body = dict(state)
                signature = _strict_unb64(body.pop("state_signature"), 64)
                self._private.public_key().verify(signature, _canonical(body))
            except Exception as exc:
                raise RuntimeError("endpoint identity state is invalid") from exc
            self.device_id = state["device_id"]
            self.revoked = state["revoked"]
            self.quarantined = state["quarantined"]
        else:
            self.device_id = expected_device_id
            self.revoked = False
            self.quarantined = False
            self._save_state()

    def _load_or_create_key(self):
        from angerona.core.hardening import (
            ensure_sensitive_parent,
            key_acl_required,
            secure_sensitive_file,
        )

        required = key_acl_required()
        self.directory.mkdir(parents=True, exist_ok=True)
        ensure_sensitive_parent(self.key_path, required=required)
        try:
            raw = self.key_path.read_bytes()
        except FileNotFoundError:
            private = Ed25519PrivateKey.generate()
            raw = private.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            try:
                descriptor = os.open(
                    str(self.key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                )
            except FileExistsError:
                raw = self.key_path.read_bytes()
            else:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
        if len(raw) != 32:
            raise RuntimeError("endpoint identity key is malformed")
        secure_sensitive_file(self.key_path, required=required)
        return Ed25519PrivateKey.from_private_bytes(raw)

    @property
    def public_key(self) -> bytes:
        return self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def public_fingerprint(self) -> str:
        return "sha256:" + hashlib.sha256(self.public_key).hexdigest()

    def _save_state(self) -> None:
        body = {
            "version": IDENTITY_STATE_VERSION,
            "device_id": self.device_id,
            "revoked": self.revoked,
            "quarantined": self.quarantined,
            "public_fingerprint": self.public_fingerprint,
        }
        _atomic_json(
            self.state_path,
            {
                **body,
                "state_signature": _b64(self._private.sign(_canonical(body))),
            },
        )

    def set_access_state(
        self, *, revoked: bool | None = None, quarantined: bool | None = None
    ) -> None:
        if revoked is not None and type(revoked) is not bool:
            raise TypeError("revoked must be a boolean or None")
        if quarantined is not None and type(quarantined) is not bool:
            raise TypeError("quarantined must be a boolean or None")
        if revoked is not None:
            self.revoked = revoked
        if quarantined is not None:
            self.quarantined = quarantined
        self._save_state()

    def enrollment_request(
        self,
        endpoint: str,
        *,
        nonce: str | None = None,
        expires_at: float | None = None,
        now: float | None = None,
    ) -> SignedEnrollmentRequest:
        stamp = time.time() if now is None else float(now)
        expiry = stamp + 300 if expires_at is None else float(expires_at)
        nonce = nonce or _b64(secrets.token_bytes(24))
        if not math.isfinite(stamp) or not math.isfinite(expiry):
            raise ValueError("enrollment timestamps must be finite")
        if not isinstance(endpoint, str) or not _ENDPOINT.fullmatch(endpoint):
            raise ValueError("endpoint must be a host:port authority")
        if int(endpoint.rsplit(":", 1)[1]) > 65535:
            raise ValueError("endpoint port is out of range")
        if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
            raise ValueError("invalid enrollment nonce")
        if not stamp < expiry <= stamp + 900:
            raise ValueError("enrollment expiry must be within 15 minutes")
        unsigned = {
            "device_id": self.device_id,
            "public_key": _b64(self.public_key),
            "nonce": nonce,
            "endpoint": endpoint,
            "expires_at": expiry,
        }
        return SignedEnrollmentRequest(
            **unsigned, signature=_b64(self._private.sign(_canonical(unsigned)))
        )

    @staticmethod
    def verify_enrollment(
        request: SignedEnrollmentRequest,
        ledger: ReplayLedger,
        *,
        now: float | None = None,
    ) -> bool:
        _require_crypto()
        try:
            if not isinstance(request, SignedEnrollmentRequest):
                return False
            stamp = time.time() if now is None else float(now)
            if (
                not math.isfinite(stamp)
                or type(request.expires_at) not in (int, float)
                or not math.isfinite(float(request.expires_at))
                or request.expires_at <= stamp
                or request.expires_at > stamp + 900
                or not isinstance(request.endpoint, str)
                or not _ENDPOINT.fullmatch(request.endpoint)
                or int(request.endpoint.rsplit(":", 1)[1]) > 65535
                or not isinstance(request.nonce, str)
                or not _NONCE.fullmatch(request.nonce)
                or not isinstance(request.device_id, str)
                or not _DEVICE_ID.fullmatch(request.device_id)
            ):
                return False
            public_bytes = _strict_unb64(request.public_key, 32)
            if request.device_id != _device_id(public_bytes):
                return False
            signature = _strict_unb64(request.signature, 64)
            public = Ed25519PublicKey.from_public_bytes(public_bytes)
            public.verify(signature, _canonical(request.unsigned()))
        except Exception:
            return False
        try:
            return ledger.consume(request.nonce)
        except Exception:
            return False

    def rotate(self, *, now: float | None = None) -> RotationProof:
        stamp = time.time() if now is None else float(now)
        if not math.isfinite(stamp):
            raise ValueError("rotation timestamp must be finite")
        old = self._private
        old_public = self.public_key
        new = Ed25519PrivateKey.generate()
        new_public = new.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        unsigned = {
            "device_id": self.device_id,
            "old_public_key": _b64(old_public),
            "new_public_key": _b64(new_public),
            "rotated_at": stamp,
        }
        proof = RotationProof(
            **unsigned,
            old_key_signature=_b64(old.sign(_canonical(unsigned))),
            new_key_signature=_b64(new.sign(_canonical(unsigned))),
        )
        raw = new.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        temp = self.key_path.with_suffix(".rotate.tmp")
        try:
            with open(temp, "xb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, self.key_path)
        finally:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass
        from angerona.core.hardening import key_acl_required, secure_sensitive_file

        secure_sensitive_file(self.key_path, required=key_acl_required())
        self._private = new
        self._save_state()
        return proof

    @staticmethod
    def verify_rotation(
        proof: RotationProof,
        *,
        expected_device_id: str,
        expected_old_public_key: bytes,
    ) -> bool:
        _require_crypto()
        try:
            if (
                not isinstance(proof, RotationProof)
                or not isinstance(proof.device_id, str)
                or not _DEVICE_ID.fullmatch(proof.device_id)
                or type(proof.rotated_at) not in (int, float)
                or not math.isfinite(float(proof.rotated_at))
            ):
                return False
            old_public = _strict_unb64(proof.old_public_key, 32)
            new_public = _strict_unb64(proof.new_public_key, 32)
            if (
                not isinstance(expected_device_id, str)
                or proof.device_id != expected_device_id
                or not isinstance(expected_old_public_key, bytes)
                or old_public != expected_old_public_key
                or old_public == new_public
            ):
                return False
            body = _canonical(proof.unsigned())
            Ed25519PublicKey.from_public_bytes(old_public).verify(
                _strict_unb64(proof.old_key_signature, 64), body
            )
            Ed25519PublicKey.from_public_bytes(new_public).verify(
                _strict_unb64(proof.new_key_signature, 64), body
            )
            return True
        except Exception:
            return False

    def sign_connection(
        self,
        sequence: int,
        kind: str,
        payload: Mapping[str, Any],
        *,
        sent_at: float | None = None,
    ) -> ConnectionEnvelope:
        if self.revoked or self.quarantined:
            raise PermissionError("device is revoked or quarantined")
        if (
            type(sequence) is not int
            or sequence < 1
            or not isinstance(kind, str)
            or not kind
            or len(kind) > 80
            or type(payload) is not dict
        ):
            raise ValueError("invalid connection envelope")
        stamp = time.time() if sent_at is None else float(sent_at)
        if not math.isfinite(stamp):
            raise ValueError("connection timestamp must be finite")
        unsigned = {
            "device_id": self.device_id,
            "sequence": int(sequence),
            "sent_at": stamp,
            "kind": kind,
            "payload": dict(payload),
        }
        if len(_canonical(unsigned)) > MAX_ENVELOPE_BYTES:
            raise ValueError("connection envelope exceeds 64 KiB")
        return ConnectionEnvelope(
            **unsigned, signature=_b64(self._private.sign(_canonical(unsigned)))
        )


class ConnectionVerifier:
    def __init__(
        self,
        device_id: str,
        public_key: bytes,
        *,
        state_path: Path,
        clock_skew_seconds: float = 120,
    ) -> None:
        _require_crypto()
        if (
            not isinstance(device_id, str)
            or not _DEVICE_ID.fullmatch(device_id)
            or not isinstance(public_key, bytes)
            or len(public_key) != 32
            or type(clock_skew_seconds) not in (int, float)
            or not math.isfinite(float(clock_skew_seconds))
        ):
            raise ValueError("connection identity, key, or clock bound is invalid")
        self.device_id = device_id
        self.public_key = Ed25519PublicKey.from_public_bytes(public_key)
        self.clock_skew_seconds = max(1.0, min(float(clock_skew_seconds), 900.0))
        self.state_path = Path(state_path)
        self._thread_lock = threading.Lock()

    def _read_sequence(self) -> int:
        if not self.state_path.exists():
            return 0
        state = _read_json_object(self.state_path)
        if (
            set(state) != {"version", "device_id", "last_sequence"}
            or state["version"] != 1
            or state["device_id"] != self.device_id
            or type(state["last_sequence"]) is not int
            or state["last_sequence"] < 0
        ):
            raise ValueError("connection replay state is invalid")
        return int(state["last_sequence"])

    def verify(self, envelope: ConnectionEnvelope, *, now: float | None = None) -> bool:
        try:
            stamp = time.time() if now is None else float(now)
            if (
                not isinstance(envelope, ConnectionEnvelope)
                or not math.isfinite(stamp)
                or envelope.device_id != self.device_id
                or type(envelope.sequence) is not int
                or envelope.sequence < 1
                or type(envelope.sent_at) not in (int, float)
                or not math.isfinite(float(envelope.sent_at))
                or abs(envelope.sent_at - stamp) > self.clock_skew_seconds
                or not isinstance(envelope.kind, str)
                or not envelope.kind
                or len(envelope.kind) > 80
                or type(envelope.payload) is not dict
                or len(_canonical(envelope.unsigned())) > MAX_ENVELOPE_BYTES
            ):
                return False
            self.public_key.verify(
                _strict_unb64(envelope.signature, 64),
                _canonical(envelope.unsigned()),
            )
        except Exception:
            return False
        try:
            with self._thread_lock, _exclusive_lock(self.state_path):
                last_sequence = self._read_sequence()
                if envelope.sequence <= last_sequence:
                    return False
                _atomic_json(
                    self.state_path,
                    {
                        "version": 1,
                        "device_id": self.device_id,
                        "last_sequence": envelope.sequence,
                    },
                )
            return True
        except Exception:
            return False
