"""Credential-backed operator identity for an independently hosted broker.

Trusted credential bindings belong to the broker's protected policy backend;
they are never taken from an approval request. A label is presentation only.
This library does not enroll users, create private keys, run an identity
provider, or provide same-process/admin resistance. Production isolation still
requires the signed service and an OS-authenticated operator transport.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import math
import os
import re
import threading
import time
from types import MappingProxyType

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,159}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_NONCE = re.compile(r"[0-9a-f]{32}\Z")
_DOMAIN = b"Angerona-Authenticated-Operator-Approval-v1\x00"
_SEAL = object()
MAX_PROOF_TTL = 1800.0


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _text(value, label):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("Invalid " + label)
    return value


@dataclass(frozen=True)
class NativeOperatorIdentity:
    issuer: str
    subject: str
    mechanism: str

    @property
    def principal_id(self) -> str:
        return principal_id(self.issuer, self.subject)


def current_os_identity() -> NativeOperatorIdentity:
    """Read the current OS token; environment usernames are never identity."""
    if os.name == "nt":
        import win32api
        import win32security
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), 8)
        try:
            sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
            subject = win32security.ConvertSidToStringSid(sid)
        finally:
            token.Close()
        return NativeOperatorIdentity("windows-token", subject, "GetTokenInformation(TokenUser)")
    # UID is local to this host. This local source is useful for display and
    # protected enrollment; remote peer identity must come from SO_PEERCRED.
    import socket
    host = hashlib.sha256(socket.gethostname().encode("utf-8")).hexdigest()
    return NativeOperatorIdentity("posix-local-" + host, "uid:" + str(os.geteuid()), "geteuid")


def principal_id(issuer: str, subject: str) -> str:
    _text(issuer, "credential issuer")
    _text(subject, "credential subject")
    return "principal:" + hashlib.sha256(canonical([issuer, subject])).hexdigest()


@dataclass(frozen=True)
class PrincipalCredential:
    """Public binding provisioned by trusted backend policy, never by a peer.

    The caller installing this record must verify the issuer-to-subject binding
    through its OS/IdP enrollment boundary. Merely constructing this object is
    not evidence that an external identity provider has been configured.
    """
    credential_id: str
    issuer: str
    subject: str
    public_key: bytes
    enabled: bool = True
    expires_at: float = 0.0

    def __post_init__(self):
        _text(self.credential_id, "credential ID")
        principal_id(self.issuer, self.subject)
        if not isinstance(self.public_key, bytes) or len(self.public_key) != 32:
            raise ValueError("Ed25519 public credential must contain 32 bytes")
        if type(self.enabled) is not bool:
            raise ValueError("Credential enabled must be a boolean")
        if type(self.expires_at) not in (int, float) or not math.isfinite(self.expires_at) or self.expires_at < 0:
            raise ValueError("Invalid credential expiry")
        # Collapse alternate SID spellings before they could become identities.
        if self.issuer == "windows-token":
            parts = self.subject.split("-")
            if (len(parts) < 4 or parts[:2] != ["S", "1"]
                    or any(not part.isascii() or not part.isdecimal() or str(int(part)) != part
                           for part in parts[2:])):
                raise ValueError("Windows subject must be a canonical SID")

    @property
    def principal_id(self):
        return principal_id(self.issuer, self.subject)

    @property
    def key_fingerprint(self):
        return hashlib.sha256(self.public_key).hexdigest()


def bind_current_os_credential(credential_id: str, public_key: bytes) -> PrincipalCredential:
    """Enrollment input from the real current OS user, not a supplied SID.

    The protected backend must still authorize enrollment and verify possession
    before installing this public binding. No signing key is created here.
    """
    native = current_os_identity()
    return PrincipalCredential(credential_id, native.issuer, native.subject, public_key)


@dataclass(frozen=True)
class SignedPrincipalProof:
    credential_id: str
    issuer: str
    subject: str
    key_fingerprint: str
    purpose_digest: str
    issued_at: float
    expires_at: float
    nonce: str
    signature: str

    @classmethod
    def unsigned(cls, credential, purpose_digest, issued_at, expires_at, nonce):
        if not isinstance(credential, PrincipalCredential):
            raise TypeError("A provisioned public credential binding is required")
        return cls(credential.credential_id, credential.issuer, credential.subject,
                   credential.key_fingerprint, purpose_digest, issued_at, expires_at, nonce, "")

    def signing_bytes(self):
        _text(self.credential_id, "credential ID")
        principal_id(self.issuer, self.subject)
        if not isinstance(self.key_fingerprint, str) or not _HEX.fullmatch(self.key_fingerprint):
            raise ValueError("Invalid credential fingerprint")
        if not isinstance(self.purpose_digest, str) or not _HEX.fullmatch(self.purpose_digest):
            raise ValueError("Approval must bind an exact operation digest")
        if not isinstance(self.nonce, str) or not _NONCE.fullmatch(self.nonce):
            raise ValueError("Invalid approval nonce")
        if (type(self.issued_at) not in (int, float) or type(self.expires_at) not in (int, float)
                or not math.isfinite(self.issued_at) or not math.isfinite(self.expires_at)
                or not 0 <= self.issued_at < self.expires_at <= self.issued_at + MAX_PROOF_TTL):
            raise ValueError("Approval expiry exceeds its bounded lifetime")
        return _DOMAIN + canonical(dict(credential_id=self.credential_id,
            issuer=self.issuer, subject=self.subject, key_fingerprint=self.key_fingerprint,
            purpose_digest=self.purpose_digest, issued_at=self.issued_at,
            expires_at=self.expires_at, nonce=self.nonce))


@dataclass(frozen=True, init=False)
class VerifiedPrincipal:
    principal_id: str
    issuer: str
    subject: str
    credential_id: str
    key_fingerprint: str
    expires_at: float

    def __init__(self, credential, expires_at, *, _seal=None):
        if _seal is not _SEAL:
            raise TypeError("Verified identity is issued only by the trusted verifier")
        for key, value in dict(principal_id=credential.principal_id, issuer=credential.issuer,
                              subject=credential.subject, credential_id=credential.credential_id,
                              key_fingerprint=credential.key_fingerprint, expires_at=expires_at).items():
            object.__setattr__(self, key, value)


class ApprovalIdentityVerifier:
    """Verify real signatures against host-provisioned public identity bindings.

    Revocations are part of backend policy and must be persisted by its owner.
    A response broker also persists its own per-proposal revocations. Key and
    subject identities are both checked: rotation is not another person.
    """
    def __init__(self, credentials=(), *, clock=time.time):
        if not callable(clock):
            raise ValueError("Identity verification clock must be callable")
        records = tuple(credentials)
        if len(records) > 5000 or any(not isinstance(record, PrincipalCredential) for record in records):
            raise ValueError("Trusted credentials must use the bounded public binding schema")
        mapping = {record.credential_id: record for record in records}
        if len(mapping) != len(records):
            raise ValueError("Duplicate trusted credential alias")
        self.credentials = MappingProxyType(mapping)
        self._clock = clock
        self._revoked = set()
        self._lock = threading.RLock()

    def revoke(self, credential_id):
        if credential_id not in self.credentials:
            raise ValueError("Unknown credential")
        with self._lock:
            self._revoked.add(self.credentials[credential_id].key_fingerprint)

    def status(self):
        stamp = self._clock()
        valid_clock = type(stamp) in (int, float) and math.isfinite(stamp) and stamp >= 0
        with self._lock:
            active = [record for record in self.credentials.values()
                      if valid_clock and record.enabled and record.key_fingerprint not in self._revoked
                      and (not record.expires_at or stamp < record.expires_at)]
        return dict(state="configured" if active else "unavailable",
                    credential_count=len(self.credentials),
                    active_credential_count=len(active),
                    enrolled_subject_count=len({record.principal_id for record in active}),
                    reason="Identity verification clock unavailable" if not valid_clock else
                    "Trusted backend credential bindings provisioned" if active else
                    "No OS/issuer-authenticated operator credential bindings provisioned",
                    os_transport_available=False)

    def resolve_principal(self, identity):
        record = self.credentials.get(identity)
        if record is not None:
            return record.principal_id
        if any(record.principal_id == identity for record in self.credentials.values()):
            return identity
        raise PermissionError("Requester identity is not bound to trusted backend credentials")

    def verify(self, proof, purpose_digest, *, now=None):
        if not isinstance(proof, SignedPrincipalProof):
            raise PermissionError("Authenticated credential proof required; labels are advisory only")
        stamp = self._clock() if now is None else now
        if type(stamp) not in (int, float) or not math.isfinite(stamp):
            raise ValueError("Invalid identity verification clock")
        record = self.credentials.get(proof.credential_id)
        with self._lock:
            revoked = record is not None and record.key_fingerprint in self._revoked
        if record is None or not record.enabled or revoked or (record.expires_at and stamp >= record.expires_at):
            raise PermissionError("Operator credential is unknown, disabled, expired or revoked")
        try:
            body = proof.signing_bytes()
            if (proof.purpose_digest != purpose_digest or not proof.issued_at <= stamp < proof.expires_at
                    or (proof.issuer, proof.subject, proof.key_fingerprint)
                    != (record.issuer, record.subject, record.key_fingerprint)):
                raise ValueError("Wrong operation or expired approval")
            if not isinstance(proof.signature, str) or len(proof.signature) != 86:
                raise ValueError("Invalid approval signature encoding")
            raw = base64.urlsafe_b64decode(proof.signature + "==")
            if len(raw) != 64 or base64.urlsafe_b64encode(raw).decode().rstrip("=") != proof.signature:
                raise ValueError("Invalid approval signature encoding")
            Ed25519PublicKey.from_public_bytes(record.public_key).verify(raw, body)
        except Exception as exc:
            raise PermissionError("Approval signature, lifetime or exact-operation binding is invalid") from exc
        return VerifiedPrincipal(record, min(proof.expires_at, record.expires_at or proof.expires_at), _seal=_SEAL)


def independent_principals(principals):
    """Maximum matching of verified subjects to keys; aliases add no vote."""
    records = tuple(principals)
    if len(records) > 128:
        raise ValueError("Approval identity bound exceeded")
    by_subject = {}
    for principal in records:
        if not isinstance(principal, VerifiedPrincipal):
            raise TypeError("Only verified principals may count toward approval")
        by_subject.setdefault(principal.principal_id, {})[principal.key_fingerprint] = principal
    assigned = {}
    def assign(subject, seen):
        for key, principal in sorted(by_subject[subject].items()):
            if key in seen:
                continue
            seen.add(key)
            if key not in assigned or assign(assigned[key].principal_id, seen):
                assigned[key] = principal
                return True
        return False
    for subject in sorted(by_subject):
        assign(subject, set())
    return tuple(sorted(assigned.values(), key=lambda item: item.principal_id))
