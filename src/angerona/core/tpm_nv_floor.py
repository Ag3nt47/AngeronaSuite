"""Enrolled TPM2 NV checkpoint observations; no provisioning or NV write API.

This is an optional hardware adapter, not an IndependentHighWater digest CAS.
The accepted external enrollment authority must establish a physical TPM, AK
credential activation, platform-created NV policy and a protected policy writer.
Software cannot distinguish a snapshot-capable vTPM clone with the same keys.
Counter and extend writes are separate: a crash can leave a pending binding.
Neither that state nor a rate limit is permission to reset/re-enroll a device.
Enrollment review dates use host wall time; they are not a trusted time or
online revocation oracle. The installed issuer pin is a deployment trust root.

The native observer only sends ReadPublic, NV_ReadPublic and NV_Certify. Pure
write plans describe constraints for a separately accepted TPM policy authorizer
and writer; they do not execute commands, grant authority or produce tickets.
No normal source composition enrolls or enables this adapter automatically.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
import re
import secrets
import struct
import threading
import time
from typing import Callable, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


SHA256 = 0x000B
NULL = 0x0010
RSASSA = 0x0014
RSAPSS = 0x0016
ECDSA = 0x0018
READ_PUBLIC = 0x00000173
NV_READ_PUBLIC = 0x00000169
NV_CERTIFY = 0x00000184
NV_INCREMENT = 0x00000134
NV_EXTEND = 0x00000136
POLICY_NV = 0x00000149
POLICY_AUTHORIZE = 0x0000016A
POLICY_COMMAND_CODE = 0x0000016C
POLICY_CP_HASH = 0x0000016E
NO_SESSIONS = 0x8001
SESSIONS = 0x8002
PW = 0x40000009
MAX_WIRE = 8192
MAX_DOCUMENT = 32768
MAX_COUNTER = (1 << 64) - 1
NV_BASE = 0x62040408  # PLATFORMCREATE, WRITTEN, NO_DA, AUTHREAD, POLICY_DELETE, POLICYWRITE
AK_REQUIRED = 0x00050072  # restricted sign, fixedTPM/parent, sensitiveDataOrigin, userWithAuth
FORMAT = "angerona-tpm-nv-floor-enrollment-v1"
ASSURANCE = "physical-tpm2-platform-nv-policy-v1"
_ENROLL_DOMAIN = b"Angerona-TPM-NV-enrollment-v1\x00"
_BIND_DOMAIN = b"Angerona-TPM-NV-checkpoint-v1\x00"
_CHALLENGE_DOMAIN = b"Angerona-TPM-NV-certify-v1\x00"
_SEAL = object()
_HEX = re.compile(r"^[0-9a-f]+$")


class TpmFloorError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> None:
    raise TpmFloorError(code, message)


def _hash(raw: bytes) -> bytes:
    return hashlib.sha256(raw).digest()


def _u16(value: int) -> bytes:
    return struct.pack(">H", value)


def _u32(value: int) -> bytes:
    return struct.pack(">I", value)


def _u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def _b2(raw: bytes) -> bytes:
    return _u16(len(raw)) + raw


def _bytes(raw: object, size: int | None = None, *, maximum: int = MAX_WIRE) -> bytes:
    if type(raw) is not bytes or len(raw) > maximum or (size is not None and len(raw) != size):
        _fail("shape", "A bounded immutable byte string was required.")
    return raw


def _number(value: object, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        _fail("shape", "An integer is outside the accepted range.")
    return value


def _hex(value: object, *, size: int | None = None, maximum: int = MAX_WIRE) -> bytes:
    if type(value) is not str or len(value) > maximum * 2 or not _HEX.fullmatch(value) or len(value) % 2:
        _fail("shape", "A canonical bounded hexadecimal field was required.")
    return _bytes(bytes.fromhex(value), size, maximum=maximum)


class _Reader:
    def __init__(self, raw: bytes):
        self.raw = _bytes(raw)
        self.pos = 0

    def take(self, size: int) -> bytes:
        if size < 0 or self.pos + size > len(self.raw):
            _fail("wire", "Truncated TPM structure.")
        value = self.raw[self.pos:self.pos + size]
        self.pos += size
        return value

    def n(self, size: int) -> int:
        return int.from_bytes(self.take(size), "big")

    def b2(self, maximum: int = MAX_WIRE) -> bytes:
        size = self.n(2)
        if size > maximum:
            _fail("wire", "Oversized TPM2B structure.")
        return self.take(size)

    def end(self) -> None:
        if self.pos != len(self.raw):
            _fail("wire", "Unexpected trailing TPM structure data.")


@dataclass(frozen=True)
class AkPublic:
    public: bytes
    name: bytes
    scheme: int
    key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey = field(repr=False, compare=False)


def parse_ak_public(raw: bytes) -> AkPublic:
    outer = _Reader(raw)
    inner = outer.b2(2048)
    outer.end()
    r = _Reader(inner)
    kind, name_alg, attrs = r.n(2), r.n(2), r.n(4)
    r.b2(64)  # authPolicy is included in the pinned public area.
    if name_alg != SHA256 or attrs & AK_REQUIRED != AK_REQUIRED or attrs & ~(AK_REQUIRED | 0x480):
        _fail("ak-profile", "AK must be a fixed, restricted TPM signing key in the accepted profile.")
    if r.n(2) != NULL:
        _fail("ak-profile", "Restricted signing AK must have null symmetric parameters.")
    scheme = r.n(2)
    if scheme not in ({RSASSA, RSAPSS} if kind == 1 else {ECDSA} if kind == 0x23 else set()):
        _fail("ak-profile", "AK scheme is outside the RSA/ECC SHA256 profile.")
    if r.n(2) != SHA256:
        _fail("ak-profile", "AK signing hash must be SHA256.")
    try:
        if kind == 1:
            bits, exponent = r.n(2), r.n(4)
            modulus = r.b2(512)
            if bits not in {2048, 3072, 4096} or len(modulus) * 8 != bits:
                _fail("ak-profile", "Unsupported RSA modulus size.")
            n = int.from_bytes(modulus, "big")
            if n.bit_length() != bits or not n & 1 or exponent not in {0, 65537}:
                _fail("ak-profile", "Invalid RSA AK public parameters.")
            key = rsa.RSAPublicNumbers(exponent or 65537, n).public_key()
        else:
            if r.n(2) != 3 or r.n(2) != NULL:
                _fail("ak-profile", "Only NIST P256 with null KDF is accepted.")
            x, y = r.b2(32), r.b2(32)
            if not x or not y:
                _fail("ak-profile", "Empty ECC point coordinate.")
            key = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
    except ValueError as exc:
        if isinstance(exc, TpmFloorError):
            raise
        raise TpmFloorError("ak-profile", "Invalid AK public key.") from exc
    r.end()
    return AkPublic(raw, _u16(SHA256) + _hash(inner), scheme, key)


def policy_authorize_digest(authorizer_name: bytes, policy_ref: bytes) -> bytes:
    """TCG PolicyUpdate's two hashes exclude TPM2B size fields."""
    _bytes(authorizer_name, 34)
    if authorizer_name[:2] != _u16(SHA256):
        _fail("policy", "A SHA256 policy authorizer Name is required.")
    _bytes(policy_ref, 32)
    return _hash(_hash(bytes(32) + _u32(POLICY_AUTHORIZE) + authorizer_name) + policy_ref)


@dataclass(frozen=True)
class NvPublic:
    public: bytes
    index: int
    name: bytes
    size: int
    attributes: int


def parse_nv_public(raw: bytes, *, counter: bool, auth_policy: bytes) -> NvPublic:
    outer = _Reader(raw)
    inner = outer.b2(128)
    outer.end()
    r = _Reader(inner)
    index, alg, attrs, policy, size = r.n(4), r.n(2), r.n(4), r.b2(64), r.n(2)
    r.end()
    if not 0x01000000 <= index <= 0x01FFFFFF or alg != SHA256:
        _fail("nv-profile", "Invalid NV index or name algorithm.")
    expected = NV_BASE | (0x10 if counter else 0x40)
    if attrs != expected or size != (8 if counter else 32) or policy != _bytes(auth_policy, 32):
        _fail("nv-profile", "NV must be initialized, non-ORDERLY, platform-created and policy-write/delete protected.")
    return NvPublic(raw, index, _u16(SHA256) + _hash(inner), size, attrs)


def _json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("enrollment", "Duplicate enrollment JSON key.")
        result[key] = value
    return result


@dataclass(frozen=True, init=False)
class TpmEnrollment:
    enrollment_id: bytes
    installation_id: bytes
    ak_handle: int
    ak: AkPublic
    qualified_name: bytes
    counter: NvPublic
    extend: NvPublic
    authorizer_name: bytes
    counter_policy_ref: bytes
    extend_policy_ref: bytes
    review_sha256: bytes
    not_before: int
    not_after: int
    document_sha256: bytes
    _seal: object = field(repr=False, compare=False)

    @classmethod
    def from_signed_document(cls, raw: bytes, issuer: ed25519.Ed25519PublicKey, *, now: int | None = None) -> TpmEnrollment:
        """Issuer key comes from accepted deployment, never from this document."""
        _bytes(raw, maximum=MAX_DOCUMENT)
        if not isinstance(issuer, ed25519.Ed25519PublicKey):
            _fail("enrollment", "An externally pinned enrollment issuer is required.")
        try:
            wrapper = json.loads(raw.decode("utf-8"), object_pairs_hook=_json_pairs)
            if type(wrapper) is not dict or set(wrapper) != {"payload", "signature"}:
                _fail("enrollment", "Invalid signed enrollment wrapper.")
            p = wrapper["payload"]
            fields = {"format", "assurance", "enrollment_id", "installation_id", "ak_handle", "ak_public",
                      "qualified_name", "counter_public", "extend_public", "authorizer_name", "counter_policy_ref",
                      "extend_policy_ref", "review_sha256", "not_before", "not_after"}
            if type(p) is not dict or set(p) != fields or p["format"] != FORMAT or p["assurance"] != ASSURANCE:
                _fail("enrollment", "Enrollment profile or fields are not accepted.")
            canonical = json.dumps(p, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            issuer.verify(_hex(wrapper["signature"], size=64), _ENROLL_DOMAIN + canonical)
            before, after = _number(p["not_before"], 0, MAX_COUNTER), _number(p["not_after"], 0, MAX_COUNTER)
            current = int(time.time()) if now is None else _number(now, 0, MAX_COUNTER)
            if not before <= current < after or after - before > 366 * 86400:
                _fail("enrollment-expired", "Enrollment is not currently within its bounded review period.")
            authorizer = _hex(p["authorizer_name"], size=34)
            cref, eref = _hex(p["counter_policy_ref"], size=32), _hex(p["extend_policy_ref"], size=32)
            if cref == eref:
                _fail("policy", "Counter and extend policy references must be distinct.")
            counter = parse_nv_public(_hex(p["counter_public"]), counter=True, auth_policy=policy_authorize_digest(authorizer, cref))
            extend = parse_nv_public(_hex(p["extend_public"]), counter=False, auth_policy=policy_authorize_digest(authorizer, eref))
            if counter.index == extend.index:
                _fail("nv-profile", "Distinct NV counter and extend indices are required.")
            values = dict(enrollment_id=_hex(p["enrollment_id"], size=16), installation_id=_hex(p["installation_id"], size=16),
                          ak_handle=_number(p["ak_handle"], 0x81000000, 0x81FFFFFF), ak=parse_ak_public(_hex(p["ak_public"])),
                          qualified_name=_hex(p["qualified_name"], size=34), counter=counter, extend=extend,
                          authorizer_name=authorizer, counter_policy_ref=cref, extend_policy_ref=eref,
                          review_sha256=_hex(p["review_sha256"], size=32), not_before=before, not_after=after,
                          document_sha256=_hash(raw), _seal=_SEAL)
            if values["qualified_name"][:2] != _u16(SHA256):
                _fail("ak-profile", "AK qualified Name must use SHA256.")
            result = object.__new__(cls)
            for key, value in values.items():
                object.__setattr__(result, key, value)
            return result
        except (InvalidSignature, UnicodeError, json.JSONDecodeError, TypeError, KeyError) as exc:
            raise TpmFloorError("enrollment", "Enrollment signature or encoding was rejected.") from exc


def _enrolled(value: TpmEnrollment) -> None:
    if type(value) is not TpmEnrollment or value._seal is not _SEAL:
        _fail("enrollment", "An issuer-verified enrollment is required.")


@dataclass(frozen=True)
class CheckpointCandidate:
    """Local candidate; its contents are independently checked against certified NV."""
    counter: int
    previous_extend: bytes
    epoch_id: bytes
    checkpoint_sha256: bytes

    def __post_init__(self):
        _number(self.counter, 1, MAX_COUNTER)
        _bytes(self.previous_extend, 32)
        _bytes(self.epoch_id, 16)
        _bytes(self.checkpoint_sha256, 32)

    def extend_input(self, enrollment: TpmEnrollment) -> bytes:
        _enrolled(enrollment)
        return _hash(_BIND_DOMAIN + enrollment.installation_id + enrollment.enrollment_id + _u64(self.counter)
                     + self.epoch_id + self.checkpoint_sha256)

    def expected_extend(self, enrollment: TpmEnrollment) -> bytes:
        return _hash(self.previous_extend + self.extend_input(enrollment))


@dataclass(frozen=True)
class FloorChallenge:
    challenge_id: str
    qualifying_data: tuple[bytes, bytes, bytes]


@dataclass(frozen=True)
class Certification:
    attestation: bytes  # TPMS_ATTEST, without the TPM2B size prefix
    signature: bytes   # TPMT_SIGNATURE


@dataclass(frozen=True)
class FloorSample:
    ak_public: bytes
    ak_name: bytes
    ak_qualified_name: bytes
    counter_public: bytes
    counter_name: bytes
    extend_public: bytes
    extend_name: bytes
    certifications: tuple[Certification, Certification, Certification]


@dataclass(frozen=True)
class FloorResult:
    state: str
    counter: int
    extend_digest: bytes
    clock_safe: bool
    detail: str


def _certify(cert: Certification, enrollment: TpmEnrollment, nv: NvPublic, nonce: bytes) -> tuple[bytes, bool]:
    if type(cert) is not Certification:
        _fail("attestation", "A typed NV certification is required.")
    raw = _bytes(cert.attestation, maximum=2048)
    r = _Reader(raw)
    if r.n(4) != 0xFF544347 or r.n(2) != 0x8014:
        _fail("attestation", "Only TPM-generated NV-content attestation is accepted.")
    if r.b2(68) != enrollment.qualified_name or r.b2(64) != nonce:
        _fail("attestation", "AK qualified Name or fresh phase nonce did not match.")
    r.n(8)  # TPM clock is not an OS build/version or calibrated wall clock.
    r.n(4)
    r.n(4)
    safe = r.n(1)
    r.n(8)  # firmwareVersion can be hierarchy-obfuscated; never an OS rollback claim.
    if safe not in {0, 1} or r.b2(68) != nv.name or r.n(2) != 0:
        _fail("attestation", "NV identity, offset or clock encoding was rejected.")
    contents = r.b2(32)
    r.end()
    if len(contents) != nv.size:
        _fail("attestation", "The full enrolled NV contents must be certified.")
    s = _Reader(cert.signature)
    scheme, alg = s.n(2), s.n(2)
    if scheme != enrollment.ak.scheme or alg != SHA256:
        _fail("signature", "Attestation signature scheme did not match the enrolled AK.")
    key = enrollment.ak.key
    try:
        if isinstance(key, rsa.RSAPublicKey):
            signature = s.b2(512)
            if len(signature) != key.key_size // 8:
                _fail("signature", "Invalid RSA signature size.")
            pad = padding.PKCS1v15() if scheme == RSASSA else padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
            key.verify(signature, raw, pad, hashes.SHA256())
        else:
            a, b = s.b2(32), s.b2(32)
            if not a or not b:
                _fail("signature", "Empty ECDSA signature scalar.")
            key.verify(encode_dss_signature(int.from_bytes(a, "big"), int.from_bytes(b, "big")), raw, ec.ECDSA(hashes.SHA256()))
        s.end()
    except (InvalidSignature, ValueError) as exc:
        if isinstance(exc, TpmFloorError):
            raise
        raise TpmFloorError("signature", "AK attestation signature was rejected.") from exc
    return contents, bool(safe)


class TpmFloorVerifier:
    """Bounded single-use challenges, never trusting caller-supplied extraData alone."""
    def __init__(self, enrollment: TpmEnrollment, *, clock: Callable[[], float] = time.monotonic,
                 wall_clock: Callable[[], float] = time.time):
        _enrolled(enrollment)
        self.enrollment = enrollment
        self._clock, self._wall_clock = clock, wall_clock
        self._pending: dict[str, tuple[FloorChallenge, CheckpointCandidate, float]] = {}
        self._lock = threading.Lock()

    def challenge(self, candidate: CheckpointCandidate) -> FloorChallenge:
        if type(candidate) is not CheckpointCandidate:
            _fail("shape", "A typed checkpoint candidate is required.")
        now = self._clock()
        with self._lock:
            self._pending = {key: value for key, value in self._pending.items() if value[2] > now}
            if len(self._pending) >= 8:
                _fail("capacity", "Outstanding hardware observations must retire before replacement.")
            if not self.enrollment.not_before <= self._wall_clock() < self.enrollment.not_after:
                _fail("enrollment-expired", "Enrollment review has expired.")
            nonce = secrets.token_bytes(32)
            identity = secrets.token_hex(16)
            e = self.enrollment
            data = tuple(_hash(_CHALLENGE_DOMAIN + nonce + e.enrollment_id + name + bytes([phase]))
                         for phase, name in enumerate((e.counter.name, e.extend.name, e.counter.name)))
            result = FloorChallenge(identity, data)
            self._pending[identity] = (result, candidate, now + 15)
            return result

    def verify(self, challenge: FloorChallenge, sample: FloorSample) -> FloorResult:
        with self._lock:
            pending = self._pending.pop(challenge.challenge_id, None) if type(challenge) is FloorChallenge else None
        if pending is None or pending[0] != challenge or self._clock() >= pending[2]:
            _fail("freshness", "Observation challenge is unknown, consumed or expired.")
        e, candidate = self.enrollment, pending[1]
        if not e.not_before <= self._wall_clock() < e.not_after:
            _fail("enrollment-expired", "Enrollment expired during observation.")
        if type(sample) is not FloorSample or (sample.ak_public, sample.ak_name, sample.ak_qualified_name,
                sample.counter_public, sample.counter_name, sample.extend_public, sample.extend_name) != (
                e.ak.public, e.ak.name, e.qualified_name, e.counter.public, e.counter.name, e.extend.public, e.extend.name):
            _fail("identity", "Freshly read AK/NV public identities do not match enrollment; no automatic re-enrollment.")
        if type(sample.certifications) is not tuple or len(sample.certifications) != 3:
            _fail("attestation", "Counter/extend/counter certifications are required.")
        values = [_certify(cert, e, nv, nonce) for cert, nv, nonce in zip(sample.certifications,
                  (e.counter, e.extend, e.counter), challenge.qualifying_data, strict=True)]
        before, digest, after = values[0][0], values[1][0], values[2][0]
        count = int.from_bytes(after, "big")
        safe = all(value[1] for value in values)
        if before != after:
            return FloorResult("concurrent-or-pending", count, digest, safe, "NV counter changed during observation; retry with a new challenge after the writer retires.")
        if count > candidate.counter:
            return FloorResult("hardware-ahead", count, digest, safe, "Local candidate is older than hardware, or a commit crashed; preserve evidence and reconcile externally.")
        if count < candidate.counter:
            return FloorResult("hardware-behind", count, digest, safe, "Candidate is ahead of enrolled hardware; replacement, clear, clone or an uncommitted candidate needs review.")
        if digest != candidate.expected_extend(e):
            return FloorResult("binding-mismatch", count, digest, safe, "Matching counter alone does not bind this checkpoint; pending writes or tampering require review.")
        return FloorResult("checkpoint-bound", count, digest, safe,
                           "Fresh enrolled NV observations bind this candidate under the external physical-device/writer policy; this is not OS version or sensor-health attestation.")


@dataclass(frozen=True)
class PolicyWriteStep:
    command_code: int
    target_index: int
    expected_counter: int
    expected_extend: bytes
    operand: bytes
    cp_hash: bytes
    approved_policy: bytes
    policy_ref: bytes


@dataclass(frozen=True)
class AnchorPlan:
    enrollment_document_sha256: bytes
    candidate: CheckpointCandidate
    steps: tuple[PolicyWriteStep, PolicyWriteStep]
    required_external_action: str = ("Separate platform enrollment and serialized protected TPM PolicyAuthorize writer with single-use permits; "
                                     "no atomic CAS, command execution or signing ticket is provided.")


def _approved_policy(e: TpmEnrollment, counter: int, extend: bytes, command: int, cp_hash: bytes) -> bytes:
    digest = bytes(32)
    for nv, operand in ((e.counter, _u64(counter)), (e.extend, extend)):
        args = _hash(operand + _u16(0) + _u16(0))  # offset=0, TPM_EO_EQ
        digest = _hash(digest + _u32(POLICY_NV) + args + nv.name)
    digest = _hash(digest + _u32(POLICY_COMMAND_CODE) + _u32(command))
    return _hash(digest + _u32(POLICY_CP_HASH) + cp_hash)


def prepare_anchor_plan(enrollment: TpmEnrollment, *, current_counter: int, current_extend: bytes,
                        epoch_id: bytes, checkpoint_sha256: bytes) -> AnchorPlan:
    """Pure two-command plan, including explicit state and command constraints.

    Both PolicyNV comparisons precede PolicyCommandCode/PolicyCpHash and then
    PolicyAuthorize. The external authorizer must verify this exact plan and the
    predecessor checkpoint; approving arbitrary host requests defeats custody.
    PolicyNV checks happen while preparing a session, not atomically at the
    later write. Concurrent prebuilt sessions/reusable tickets are not a CAS;
    the accepted writer must serialize sessions and retain single-use permits.
    NV_Increment then NV_Extend is not atomic. Never blindly resume/reissue on
    reply loss: observe hardware and reconcile this same candidate first.
    """
    _enrolled(enrollment)
    _number(current_counter, 1, MAX_COUNTER - 1)
    _bytes(current_extend, 32)
    candidate = CheckpointCandidate(current_counter + 1, current_extend, epoch_id, checkpoint_sha256)
    operand = candidate.extend_input(enrollment)
    increment_cp = _hash(_u32(NV_INCREMENT) + enrollment.counter.name * 2)
    extend_cp = _hash(_u32(NV_EXTEND) + enrollment.extend.name * 2 + _b2(operand))
    steps = (
        PolicyWriteStep(NV_INCREMENT, enrollment.counter.index, current_counter, current_extend, b"", increment_cp,
                        _approved_policy(enrollment, current_counter, current_extend, NV_INCREMENT, increment_cp), enrollment.counter_policy_ref),
        PolicyWriteStep(NV_EXTEND, enrollment.extend.index, current_counter + 1, current_extend, operand, extend_cp,
                        _approved_policy(enrollment, current_counter + 1, current_extend, NV_EXTEND, extend_cp), enrollment.extend_policy_ref),
    )
    return AnchorPlan(enrollment.document_sha256, candidate, steps)


class ReadonlyTpmTransport(Protocol):
    def submit(self, command: bytes) -> bytes: ...


def _command(code: int, handles: bytes, parameters: bytes = b"", auth: bytes | None = None) -> bytes:
    body = handles + (b"" if auth is None else _u32(len(auth)) + auth) + parameters
    return _u16(NO_SESSIONS if auth is None else SESSIONS) + _u32(10 + len(body)) + _u32(code) + body


def _response(raw: bytes, *, sessions: bool) -> bytes:
    r = _Reader(raw)
    tag, size, code = r.n(2), r.n(4), r.n(4)
    if size != len(raw) or tag not in {NO_SESSIONS, SESSIONS}:
        _fail("wire", "Invalid TPM response header.")
    if code:
        if tag != NO_SESSIONS or len(raw) != 10:
            _fail("wire", "Malformed TPM error response.")
        _fail("nv-rate" if code == 0x920 else "tpm-unavailable", f"TPM returned 0x{code:08x}; no automatic retry/reset is authorized.")
    if tag != (SESSIONS if sessions else NO_SESSIONS):
        _fail("wire", "TPM response session tag did not match.")
    if not sessions:
        return r.take(len(raw) - r.pos)
    parameters = r.take(r.n(4))
    for _ in range(2):
        if r.b2(64) != b"" or r.n(1) != 1 or r.b2(64) != b"":
            _fail("wire", "Unexpected password-session response authorization.")
    r.end()
    return parameters


class NativeTbsObserver:
    """Wire-level observer. Passwords are injected, not discovered or logged.

    A synchronous TBS call has no invented hard deadline. Run on a retained
    service worker; challenge expiry rejects late evidence. close() must retire
    that worker before closing its transport. This class never owns threads.
    """
    def __init__(self, transport: ReadonlyTpmTransport):
        self._transport = transport

    def sample(self, enrollment: TpmEnrollment, challenge: FloorChallenge, *, ak_auth: bytes = b"",
               nv_read_auth: bytes = b"") -> FloorSample:
        _enrolled(enrollment)
        _bytes(ak_auth, maximum=32)
        _bytes(nv_read_auth, maximum=32)
        if type(challenge) is not FloorChallenge or len(challenge.qualifying_data) != 3:
            _fail("shape", "A verifier-issued observation challenge is required.")
        for data in challenge.qualifying_data:
            _bytes(data, 32)
        raw = _response(self._transport.submit(_command(READ_PUBLIC, _u32(enrollment.ak_handle))), sessions=False)
        r = _Reader(raw)
        ak_public, ak_name, qualified = _b2(r.b2(2048)), r.b2(68), r.b2(68)
        r.end()
        nv_public = []
        for nv in (enrollment.counter, enrollment.extend):
            r = _Reader(_response(self._transport.submit(_command(NV_READ_PUBLIC, _u32(nv.index))), sessions=False))
            nv_public.append((_b2(r.b2(128)), r.b2(68)))
            r.end()
        if (ak_public, ak_name, qualified, *nv_public[0], *nv_public[1]) != (
                enrollment.ak.public, enrollment.ak.name, enrollment.qualified_name, enrollment.counter.public,
                enrollment.counter.name, enrollment.extend.public, enrollment.extend.name):
            _fail("identity", "Observed public identities changed; no secret-bearing certification was dispatched.")
        certs = []
        auth = _u32(PW) + _b2(b"") + b"\x00" + _b2(ak_auth)
        auth += _u32(PW) + _b2(b"") + b"\x00" + _b2(nv_read_auth)
        for nv, nonce in zip((enrollment.counter, enrollment.extend, enrollment.counter), challenge.qualifying_data, strict=True):
            parameters = _b2(nonce) + _u16(enrollment.ak.scheme) + _u16(SHA256) + _u16(nv.size) + _u16(0)
            command = _command(NV_CERTIFY, _u32(enrollment.ak_handle) + _u32(nv.index) * 2, parameters, auth)
            r = _Reader(_response(self._transport.submit(command), sessions=True))
            attestation = r.b2(2048)
            signature = r.take(len(r.raw) - r.pos)
            certs.append(Certification(attestation, signature))
        return FloorSample(ak_public, ak_name, qualified, *nv_public[0], *nv_public[1], tuple(certs))


_NATIVE_HOLD_LOCK = threading.Lock()
_NATIVE_HOLDS: list[object] = []
_NATIVE_OWNERS: list[object] = []
_NATIVE_CREATE_LOCK = threading.Lock()


class WindowsTbsReadonlyTransport:
    """Accepted installed composition only; no host writes/provisioning API.

    A failed/overlapping native close retains the exact context owner forever
    in this process and fences replacement. No numeric-handle retry or close
    while Submit_Command is pending. Tests inject a simulated API explicitly.
    """
    def __init__(self, installed_guard: Callable[[], bool], *, _api=None):
        self._guard = installed_guard
        self._lock = threading.Lock()
        self._poisoned = False
        self._closed = False
        self._context = None
        self._close_attempt_context = None
        self._api = _api
        self._admit()
        if not _NATIVE_CREATE_LOCK.acquire(blocking=False):
            _fail("busy", "A native TBS context is already being admitted.")
        try:
            self._admit()
            with _NATIVE_HOLD_LOCK:
                if _NATIVE_OWNERS:
                    _fail("capacity", "Retire the existing owned TBS observer before replacement.")
            if _api is None:
                if os.name != "nt":
                    _fail("platform", "Windows TBS is unavailable on this platform.")
                self._api = _WindowsTbsApi()
            # Retain before entering FFI. Collection of a Python wrapper is not
            # native context retirement, including ambiguous creation.
            with _NATIVE_HOLD_LOCK:
                _NATIVE_OWNERS.append(self)
            try:
                self._context = self._api.create_context()
                if not self._context:
                    _fail("native-cleanup", "Native TBS context creation did not establish ownership.")
            except BaseException:
                self._hold()
                raise
        finally:
            _NATIVE_CREATE_LOCK.release()

    def _admit(self):
        with _NATIVE_HOLD_LOCK:
            held = bool(_NATIVE_HOLDS)
        if held or self._poisoned or self._closed:
            _fail("native-cleanup", "Unproven native TBS custody prevents replacement or reuse.")
        if self._guard() is not True:
            _fail("installed-authority", "Enrolled installed service custody is required for TBS access.")

    def _hold(self):
        with _NATIVE_HOLD_LOCK:
            self._poisoned = True
            if not any(value is self for value in _NATIVE_HOLDS):
                _NATIVE_HOLDS.append(self)

    @property
    def cleanup_proven(self) -> bool:
        return self._closed and not self._poisoned

    def submit(self, command: bytes) -> bytes:
        r = _Reader(command)
        tag, size, code = r.n(2), r.n(4), r.n(4)
        if size != len(command) or code not in {READ_PUBLIC, NV_READ_PUBLIC, NV_CERTIFY}:
            _fail("readonly", "Only the closed read/certify command catalog is available.")
        if tag != (SESSIONS if code == NV_CERTIFY else NO_SESSIONS):
            _fail("readonly", "Read-only command tag did not match.")
        if not self._lock.acquire(blocking=False):
            _fail("busy", "The exact TBS worker must retire before another call.")
        try:
            self._admit()
            try:
                result = _bytes(self._api.submit(self._context, command), maximum=MAX_WIRE)
            except TpmFloorError:
                raise  # a typed completed native failure is not a pending call
            except BaseException:
                self._hold()
                raise
            self._admit()  # a concurrent close/authority loss may have fenced this exact call
            return result
        finally:
            self._lock.release()

    def close(self) -> bool:
        if self.cleanup_proven:
            return True
        if not self._lock.acquire(blocking=False):
            with _NATIVE_HOLD_LOCK:
                if self._closed and not self._poisoned:
                    return True  # the first closer already established native retirement
                self._poisoned = True
                if not any(value is self for value in _NATIVE_HOLDS):
                    _NATIVE_HOLDS.append(self)
                return False
        try:
            if self._poisoned:
                return False
            context, self._context = self._context, None  # one native attempt, never retry a reused number
            self._close_attempt_context = context
            try:
                self._api.close(context)
            except BaseException:
                self._hold()
                return False
            with _NATIVE_HOLD_LOCK:
                self._closed = True
                if self._poisoned:
                    return False  # an overlapping close made retirement sticky while native close ran
                self._close_attempt_context = None
                _NATIVE_OWNERS[:] = [value for value in _NATIVE_OWNERS if value is not self]
            return True
        finally:
            self._lock.release()


class _WindowsTbsApi:
    def __init__(self):
        import ctypes
        from ctypes import wintypes

        self._ctypes = ctypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetSystemDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
        kernel.GetSystemDirectoryW.restype = wintypes.UINT
        path = ctypes.create_unicode_buffer(32768)
        length = kernel.GetSystemDirectoryW(path, len(path))
        if not 0 < length < len(path):
            _fail("native-path", "The native Windows system directory is unavailable.")
        self._dll = ctypes.WinDLL(os.path.join(path.value, "tbs.dll"), winmode=0x800)
        self._dll.Tbsi_Context_Create.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        self._dll.Tbsi_Context_Create.restype = ctypes.c_uint32
        self._dll.Tbsip_Submit_Command.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                                                   ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
                                                   ctypes.POINTER(ctypes.c_uint32)]
        self._dll.Tbsip_Submit_Command.restype = ctypes.c_uint32
        self._dll.Tbsip_Context_Close.argtypes = [ctypes.c_void_p]
        self._dll.Tbsip_Context_Close.restype = ctypes.c_uint32
        self._creating_context = None

    def create_context(self):
        c = self._ctypes
        params = (c.c_uint32 * 2)(2, 4)  # TBS_CONTEXT_VERSION_TWO; includeTpm20 only
        context = c.c_void_p()
        self._creating_context = context  # retains even an ambiguous failing FFI result
        code = self._dll.Tbsi_Context_Create(c.byref(params), c.byref(context))
        if code or not context.value:
            _fail("tbs-unavailable", f"TBS context creation failed (0x{code:08x}); no TPM1.2 fallback.")
        self._creating_context = None
        return context

    def submit(self, context, command: bytes) -> bytes:
        c = self._ctypes
        source = c.create_string_buffer(command)
        target = c.create_string_buffer(MAX_WIRE)
        size = c.c_uint32(MAX_WIRE)
        code = self._dll.Tbsip_Submit_Command(context, 0, 200, source, len(command), target, c.byref(size))
        if code:
            _fail("tbs-unavailable", f"TBS submit failed (0x{code:08x}); no automatic retry.")
        if not 10 <= size.value <= MAX_WIRE:
            _fail("wire", "TBS returned an invalid bounded response size.")
        return target.raw[:size.value]

    def close(self, context):
        code = self._dll.Tbsip_Context_Close(context)
        if code:
            _fail("native-cleanup", f"TBS context retirement is unproven (0x{code:08x}).")
