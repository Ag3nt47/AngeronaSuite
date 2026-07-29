"""Local endpoint identity and signed fleet-connection contracts.

This module does not implement a server, transport, or mTLS. It only creates
and verifies artifacts that a future authenticated transport may carry.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey,
    )
    _CRYPTO_ERROR: Exception | None = None
except Exception as exc:  # pragma: no cover - fail-closed path
    Ed25519PrivateKey = Ed25519PublicKey = None  # type: ignore
    serialization = None  # type: ignore
    _CRYPTO_ERROR = exc

MAX_LEDGER_ENTRIES = 10_000
MAX_STATE_BYTES = 2 * 1024 * 1024
MAX_ENVELOPE_BYTES = 64 * 1024
_ENDPOINT = re.compile(r"^[A-Za-z0-9.-]{1,253}:[1-9][0-9]{0,4}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")


def _require_crypto() -> None:
    if _CRYPTO_ERROR is not None:
        raise RuntimeError("Ed25519 cryptography support is required") from _CRYPTO_ERROR


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _atomic_json(path: Path, value: Any) -> None:
    encoded = _canonical(value)
    if len(encoded) > MAX_STATE_BYTES:
        raise ValueError("identity state exceeds bounded size")
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
                    fcntl.flock(
                        stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB
                    )
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
        self.max_entries = max(1, min(int(max_entries), MAX_LEDGER_ENTRIES))

    def _read(self) -> list[str]:
        if not self.path.exists():
            return []
        value = json.loads(self.path.read_text(encoding="utf-8"))
        entries = value.get("nonces", [])
        if not isinstance(entries, list) or len(entries) > self.max_entries:
            raise ValueError("invalid or oversized replay ledger")
        return [str(item) for item in entries]

    def consume(self, nonce: str) -> bool:
        with _exclusive_lock(self.path):
            entries = self._read()
            if nonce in entries:
                return False
            entries.append(nonce)
            _atomic_json(
                self.path,
                {"version": 1, "nonces": entries[-self.max_entries:]},
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
        if self.state_path.exists():
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
            self.device_id = str(state["device_id"])
            self.revoked = bool(state.get("revoked", False))
            self.quarantined = bool(state.get("quarantined", False))
        else:
            self.device_id = "device-" + hashlib.sha256(public).hexdigest()[:32]
            self.revoked = False
            self.quarantined = False
            self._save_state()

    def _load_or_create_key(self):
        from angerona.core.hardening import (
            ensure_sensitive_parent, key_acl_required, secure_sensitive_file,
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
        _atomic_json(self.state_path, {
            "version": 1, "device_id": self.device_id,
            "revoked": self.revoked, "quarantined": self.quarantined,
            "public_fingerprint": self.public_fingerprint,
        })

    def set_access_state(
        self, *, revoked: bool | None = None, quarantined: bool | None = None
    ) -> None:
        if revoked is not None:
            self.revoked = bool(revoked)
        if quarantined is not None:
            self.quarantined = bool(quarantined)
        self._save_state()

    def enrollment_request(
        self, endpoint: str, *, nonce: str | None = None,
        expires_at: float | None = None, now: float | None = None,
    ) -> SignedEnrollmentRequest:
        stamp = time.time() if now is None else float(now)
        expiry = stamp + 300 if expires_at is None else float(expires_at)
        nonce = nonce or _b64(secrets.token_bytes(24))
        if not _ENDPOINT.fullmatch(endpoint):
            raise ValueError("endpoint must be a host:port authority")
        if int(endpoint.rsplit(":", 1)[1]) > 65535:
            raise ValueError("endpoint port is out of range")
        if not _NONCE.fullmatch(nonce):
            raise ValueError("invalid enrollment nonce")
        if not stamp < expiry <= stamp + 900:
            raise ValueError("enrollment expiry must be within 15 minutes")
        unsigned = {
            "device_id": self.device_id, "public_key": _b64(self.public_key),
            "nonce": nonce, "endpoint": endpoint, "expires_at": expiry,
        }
        return SignedEnrollmentRequest(
            **unsigned, signature=_b64(self._private.sign(_canonical(unsigned)))
        )

    @staticmethod
    def verify_enrollment(
        request: SignedEnrollmentRequest, ledger: ReplayLedger, *,
        now: float | None = None,
    ) -> bool:
        _require_crypto()
        stamp = time.time() if now is None else float(now)
        if request.expires_at < stamp or request.expires_at > stamp + 900:
            return False
        if (not _ENDPOINT.fullmatch(request.endpoint)
                or int(request.endpoint.rsplit(":", 1)[1]) > 65535
                or not _NONCE.fullmatch(request.nonce)
                or not request.device_id.startswith("device-")):
            return False
        try:
            public = Ed25519PublicKey.from_public_bytes(_unb64(request.public_key))
            public.verify(_unb64(request.signature), _canonical(request.unsigned()))
        except Exception:
            return False
        try:
            return ledger.consume(request.nonce)
        except Exception:
            return False

    def rotate(self, *, now: float | None = None) -> RotationProof:
        stamp = time.time() if now is None else float(now)
        old = self._private
        old_public = self.public_key
        new = Ed25519PrivateKey.generate()
        new_public = new.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        unsigned = {
            "device_id": self.device_id, "old_public_key": _b64(old_public),
            "new_public_key": _b64(new_public), "rotated_at": stamp,
        }
        proof = RotationProof(
            **unsigned,
            old_key_signature=_b64(old.sign(_canonical(unsigned))),
            new_key_signature=_b64(new.sign(_canonical(unsigned))),
        )
        raw = new.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
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
    def verify_rotation(proof: RotationProof) -> bool:
        _require_crypto()
        body = _canonical(proof.unsigned())
        try:
            Ed25519PublicKey.from_public_bytes(_unb64(proof.old_public_key)).verify(
                _unb64(proof.old_key_signature), body
            )
            Ed25519PublicKey.from_public_bytes(_unb64(proof.new_public_key)).verify(
                _unb64(proof.new_key_signature), body
            )
            return True
        except Exception:
            return False

    def sign_connection(
        self, sequence: int, kind: str, payload: Mapping[str, Any],
        *, sent_at: float | None = None,
    ) -> ConnectionEnvelope:
        if self.revoked or self.quarantined:
            raise PermissionError("device is revoked or quarantined")
        if sequence < 1 or not kind or len(kind) > 80:
            raise ValueError("invalid connection envelope")
        unsigned = {
            "device_id": self.device_id, "sequence": int(sequence),
            "sent_at": time.time() if sent_at is None else float(sent_at),
            "kind": kind, "payload": dict(payload),
        }
        if len(_canonical(unsigned)) > MAX_ENVELOPE_BYTES:
            raise ValueError("connection envelope exceeds 64 KiB")
        return ConnectionEnvelope(
            **unsigned, signature=_b64(self._private.sign(_canonical(unsigned)))
        )


class ConnectionVerifier:
    def __init__(
        self, device_id: str, public_key: bytes, *,
        state_path: Path,
        clock_skew_seconds: float = 120,
    ) -> None:
        _require_crypto()
        self.device_id = device_id
        self.public_key = Ed25519PublicKey.from_public_bytes(public_key)
        self.clock_skew_seconds = max(1.0, min(float(clock_skew_seconds), 900.0))
        self.state_path = Path(state_path)
        self._thread_lock = threading.Lock()

    def _read_sequence(self) -> int:
        if not self.state_path.exists():
            return 0
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        if (
            state.get("version") != 1
            or state.get("device_id") != self.device_id
            or not isinstance(state.get("last_sequence"), int)
            or state["last_sequence"] < 0
        ):
            raise ValueError("connection replay state is invalid")
        return int(state["last_sequence"])

    def verify(self, envelope: ConnectionEnvelope, *, now: float | None = None) -> bool:
        stamp = time.time() if now is None else float(now)
        if envelope.device_id != self.device_id:
            return False
        if abs(envelope.sent_at - stamp) > self.clock_skew_seconds:
            return False
        if len(_canonical(envelope.unsigned())) > MAX_ENVELOPE_BYTES:
            return False
        try:
            self.public_key.verify(
                _unb64(envelope.signature), _canonical(envelope.unsigned())
            )
        except Exception:
            return False
        try:
            with self._thread_lock, _exclusive_lock(self.state_path):
                last_sequence = self._read_sequence()
                if envelope.sequence <= last_sequence:
                    return False
                _atomic_json(self.state_path, {
                    "version": 1, "device_id": self.device_id,
                    "last_sequence": envelope.sequence,
                })
            return True
        except Exception:
            return False
