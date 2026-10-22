"""Ephemeral authenticated local messaging, with an explicit attestation gate.

Ed25519 peer certificates and packet signatures authenticate each boot/session.
Fresh X25519 private keys are exchanged every ten seconds, HKDF-SHA256 derives
direction/purpose-specific AES-256-GCM keys, and counters make nonces unique.
The cross-process channel uses a signed four-message rekey handshake. MeshPipe
pumps that handshake on background threads while an application worker is busy.

These are process-held capabilities, not OS enclaves or protection from a
compromised interpreter/root account. Source digests are enrollment bindings,
not independently measured attestation. Key buffers are overwritten best effort;
Python and cryptography can retain immutable/native copies. No perfect erasure
or remote hardware attestation is claimed. Private subprocess bootstrap material
must travel only through an inherited anonymous pipe, never logs/CLI/disk.

Primary crypto contracts:
https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x25519/
https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/
https://cryptography.io/en/latest/hazmat/primitives/aead/
https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#hkdf
"""
from __future__ import annotations

import base64
from collections import OrderedDict, deque
from contextlib import contextmanager
import hashlib
import json
import math
import queue
import re
import secrets
import threading
import time

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

LOCAL_MAX_PAYLOAD = 256 * 1024
MAX_PAYLOAD = 4 * 1024 * 1024
MAX_WIRE = 6 * 1024 * 1024
_MAX_QUEUED_BYTES = 8 * 1024 * 1024
MAX_PEERS = 128
ROTATION_SECONDS = 10.0
_SESSION_MS = 60 * 60 * 1000
_PACKET_MS = 3000
_LABEL = re.compile(r"[A-Za-z][A-Za-z0-9_. -]{0,79}\Z")
_PURPOSE = re.compile(r"[a-zA-Z][a-zA-Z0-9_.-]{0,63}\Z")
_ID = re.compile(r"[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"(?:[0-9a-f]{64})?\Z")
_CERT_FIELDS = frozenset({"version", "kind", "boot", "session", "peer", "label",
                          "source_digest", "epoch", "issued", "expires", "ed25519",
                          "x25519", "nonce_prefix"})
_HEADER_FIELDS = frozenset({"version", "kind", "boot", "session", "sender", "receiver",
                            "purpose", "epoch", "seq", "issued", "expires", "nonce", "certificate"})
_CONTROL_FIELDS = frozenset({"version", "kind", "boot", "session", "sender", "receiver",
                             "seq", "issued", "expires", "type", "epoch", "data"})
_CERT_DOMAIN = b"Angerona/EnclaveMesh/certificate/v1\0"
_PACKET_DOMAIN = b"Angerona/EnclaveMesh/packet/v1\0"
_CONTROL_DOMAIN = b"Angerona/EnclaveMesh/control/v1\0"


class MeshError(RuntimeError):
    pass


class MeshFrozen(MeshError):
    pass


class MeshHandshakeRequired(MeshError):
    pass


def canonical(value) -> bytes:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                         allow_nan=False).encode("ascii")
        if len(raw) > MAX_WIRE:
            raise MeshError("Mesh frame exceeds its byte limit")
        return raw
    except (TypeError, ValueError, RecursionError) as exc:
        raise MeshError("Invalid mesh frame") from exc


def decode_frame(raw: bytes) -> dict:
    if type(raw) is not bytes or len(raw) > MAX_WIRE:
        raise MeshError("Invalid mesh frame size")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise MeshError("Duplicate mesh frame field")
            result[key] = value
        return result
    try:
        result = json.loads(raw, object_pairs_hook=unique,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise MeshError("Invalid mesh JSON") from exc
    if not isinstance(result, dict):
        raise MeshError("Mesh frame must be an object")
    return result


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value, *, size=None, maximum=MAX_PAYLOAD + 16) -> bytes:
    if not isinstance(value, str) or len(value) > (maximum + 2) // 3 * 4:
        raise MeshError("Invalid mesh binary encoding")
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError) as exc:
        raise MeshError("Invalid mesh binary encoding") from exc
    if len(result) > maximum or (size is not None and len(result) != size):
        raise MeshError("Invalid mesh binary length")
    return result


def _wipe(value) -> None:
    if isinstance(value, bytearray):
        value[:] = b"\0" * len(value)


def _private(kind) -> bytearray:
    return bytearray(kind.generate().private_bytes_raw())


def _ed_public(raw) -> bytes:
    return ed25519.Ed25519PrivateKey.from_private_bytes(bytes(raw)).public_key().public_bytes_raw()


def _x_public(raw) -> bytes:
    return x25519.X25519PrivateKey.from_private_bytes(bytes(raw)).public_key().public_bytes_raw()


def _sign(raw, domain, body) -> str:
    return _b64(ed25519.Ed25519PrivateKey.from_private_bytes(bytes(raw)).sign(domain + canonical(body)))


def _verify(public, domain, body, signature) -> None:
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public).verify(
            _unb64(signature, size=64, maximum=64), domain + canonical(body))
    except (InvalidSignature, ValueError) as exc:
        raise MeshError("Mesh signature verification failed") from exc


def _issue(ca, *, kind, boot, session, peer, label, source_digest, epoch, issued, expires,
           signing, exchange, prefix) -> dict:
    body = {"version": 1, "kind": kind, "boot": boot, "session": session, "peer": peer,
            "label": label, "source_digest": source_digest, "epoch": epoch,
            "issued": issued, "expires": expires, "ed25519": _b64(signing),
            "x25519": _b64(exchange), "nonce_prefix": _b64(prefix)}
    return {"body": body, "signature": _sign(ca, _CERT_DOMAIN, body)}


def _certificate(cert, ca, *, boot, session, now, kind, expected=None) -> dict:
    if (not isinstance(cert, dict) or set(cert) != {"body", "signature"}
            or not isinstance(cert.get("body"), dict) or set(cert["body"]) != _CERT_FIELDS):
        raise MeshError("Invalid mesh certificate")
    body = cert["body"]
    if (type(body["version"]) is not int or body["version"] != 1 or body["kind"] != kind
            or body["boot"] != boot or body["session"] != session
            or not isinstance(body["peer"], str) or not _ID.fullmatch(body["peer"])
            or not isinstance(body["label"], str) or not _LABEL.fullmatch(body["label"])
            or not isinstance(body["source_digest"], str) or not _DIGEST.fullmatch(body["source_digest"])
            or type(body["epoch"]) is not int or not 0 <= body["epoch"] < 2**63
            or type(body["issued"]) is not int or type(body["expires"]) is not int
            or not body["issued"] <= now < body["expires"]
            or body["expires"] - body["issued"] > _SESSION_MS):
        raise MeshError("Mesh certificate identity, epoch, or lifetime is invalid")
    _unb64(body["ed25519"], size=32, maximum=32)
    _unb64(body["x25519"], size=32, maximum=32)
    _unb64(body["nonce_prefix"], size=4, maximum=4)
    _verify(ca, _CERT_DOMAIN, body, cert["signature"])
    if expected is not None:
        for field in ("peer", "label", "source_digest", "ed25519"):
            if body[field] != expected[field]:
                raise MeshError("Mesh certificate changed its enrolled identity")
    return body


def _derived(local_x, remote_cert, local_cert, *, sender, receiver, purpose) -> bytearray:
    remote = remote_cert["body"]
    local = local_cert["body"]
    try:
        shared = bytearray(x25519.X25519PrivateKey.from_private_bytes(bytes(local_x)).exchange(
            x25519.X25519PublicKey.from_public_bytes(_unb64(remote["x25519"], size=32, maximum=32))))
    except ValueError as exc:
        raise MeshError("Invalid mesh X25519 exchange") from exc
    try:
        ordered = sorted((local_cert, remote_cert), key=lambda cert: cert["body"]["peer"])
        salt = hashlib.sha256(canonical(ordered)).digest()
        context = canonical([local["boot"], local["session"], local["epoch"], sender, receiver, purpose])
        return bytearray(HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                              info=b"Angerona/EnclaveMesh/AES256GCM/v1\0" + context).derive(bytes(shared)))
    finally:
        _wipe(shared)


class _Endpoint:
    def _setup(self, *, ca_public, signing, exchange, local_identity, remote_identity,
               local_cert, remote_cert, boot, session, clock, gate, verified, rotation_ms):
        self._lock = threading.RLock()
        self._ca_public = ca_public
        self._ed = signing
        self._x = exchange
        self._local_identity = local_identity
        self._remote_identity = remote_identity
        self._local_cert = local_cert
        self._remote_cert = remote_cert
        self.boot, self.session = boot, session
        self._clock = clock
        self._gate = gate
        self._verified = verified is True
        self._closed = False
        self._frozen = not self._verified
        self._last_now = -1
        self._epoch = local_cert["body"]["epoch"]
        self._expires = local_cert["body"]["expires"]
        self._rotation_ms = rotation_ms
        self._sequence = 0
        self._received = {}
        self._keys = OrderedDict()
        self._payload_limit = LOCAL_MAX_PAYLOAD

    def _now(self):
        value = self._clock()
        if type(value) not in {int, float} or not math.isfinite(value):
            raise MeshError("Invalid mesh clock")
        now = int(value * 1000)
        if now < self._last_now:
            self._erase()
            self._frozen = True
            raise MeshFrozen("Mesh clock moved backwards")
        self._last_now = now
        return now

    def _require(self):
        if self._closed or self._frozen or not self._verified:
            raise MeshFrozen("Mesh is closed or awaiting verified authorization")
        if self._gate is not None:
            try:
                approved = self._gate() is True
            except Exception:
                approved = False
            if not approved:
                self._erase()
                self._frozen = True
                raise MeshFrozen("Mesh authorization was revoked")

    def _erase(self):
        for key in self._keys.values():
            _wipe(key)
        self._keys.clear()

    def _key(self, remote, sender, receiver, purpose):
        key_id = (remote["body"]["peer"], sender, receiver, purpose, self._epoch)
        if key_id not in self._keys:
            self._keys[key_id] = _derived(self._x, remote, self._local_cert,
                                          sender=sender, receiver=receiver, purpose=purpose)
            if len(self._keys) > 64:
                _old, key = self._keys.popitem(last=False)
                _wipe(key)
        return self._keys[key_id]

    def _seal(self, payload, remote, purpose):
        self._require()
        now = self._now()
        if now >= self._expires:
            raise MeshHandshakeRequired("Mesh epoch renewal is required")
        if type(payload) is not bytes or len(payload) > self._payload_limit:
            raise MeshError("Mesh payload must be bounded bytes")
        if not isinstance(purpose, str) or not _PURPOSE.fullmatch(purpose):
            raise MeshError("Invalid mesh purpose")
        if self._sequence >= 2**63 - 1:
            raise MeshError("Mesh sequence limit reached")
        self._sequence += 1
        local = self._local_cert["body"]
        sender, receiver = local["peer"], remote["body"]["peer"]
        nonce = _unb64(local["nonce_prefix"], size=4, maximum=4) + self._sequence.to_bytes(8, "big")
        header = {"version": 1, "kind": "data", "boot": self.boot, "session": self.session,
                  "sender": sender, "receiver": receiver, "purpose": purpose, "epoch": self._epoch,
                  "seq": self._sequence, "issued": now, "expires": min(now + _PACKET_MS, self._expires),
                  "nonce": _b64(nonce), "certificate": decode_frame(canonical(self._local_cert))}
        ciphertext = _b64(AESGCM(bytes(self._key(remote, sender, receiver, purpose))).encrypt(
            nonce, payload, canonical(header)))
        signed = {"header": header, "ciphertext": ciphertext}
        return {**signed, "signature": _sign(self._ed, _PACKET_DOMAIN, signed)}

    def _open(self, envelope, remote, purpose):
        self._require()
        now = self._now()
        if now >= self._expires:
            raise MeshHandshakeRequired("Mesh epoch renewal is required")
        if (not isinstance(envelope, dict) or set(envelope) != {"header", "ciphertext", "signature"}
                or not isinstance(envelope.get("header"), dict) or set(envelope["header"]) != _HEADER_FIELDS):
            raise MeshError("Invalid mesh packet")
        canonical(envelope)
        header = envelope["header"]
        if (type(header["version"]) is not int or header["version"] != 1 or header["kind"] != "data"
                or header["boot"] != self.boot or header["session"] != self.session
                or header["sender"] != remote["body"]["peer"]
                or header["receiver"] != self._local_cert["body"]["peer"]
                or not isinstance(purpose, str) or not _PURPOSE.fullmatch(purpose)
                or header["purpose"] != purpose or type(header["epoch"]) is not int
                or header["epoch"] != self._epoch
                or type(header["seq"]) is not int or not 0 < header["seq"] < 2**63
                or type(header["issued"]) is not int or type(header["expires"]) is not int
                or not header["issued"] <= now < header["expires"] <= self._expires
                or header["expires"] - header["issued"] > _PACKET_MS):
            raise MeshError("Mesh packet identity, purpose, epoch, or lifetime is invalid")
        cert = _certificate(header["certificate"], self._ca_public, boot=self.boot, session=self.session,
                            now=now, kind="epoch", expected=remote["body"])
        if header["certificate"] != remote or cert["epoch"] != self._epoch:
            raise MeshError("Mesh packet uses an unnegotiated epoch certificate")
        nonce = _unb64(header["nonce"], size=12, maximum=12)
        if nonce != _unb64(cert["nonce_prefix"], size=4, maximum=4) + header["seq"].to_bytes(8, "big"):
            raise MeshError("Mesh nonce is inconsistent with its signed sequence")
        previous = self._received.get(header["sender"], 0)
        if header["seq"] <= previous:
            raise MeshError("Mesh packet is replayed or out of order")
        ciphertext = _unb64(envelope["ciphertext"], maximum=self._payload_limit + 16)
        _verify(_unb64(cert["ed25519"], size=32, maximum=32), _PACKET_DOMAIN,
                {"header": header, "ciphertext": envelope["ciphertext"]}, envelope["signature"])
        try:
            payload = AESGCM(bytes(self._key(remote, header["sender"], header["receiver"], purpose))).decrypt(
                nonce, ciphertext, canonical(header))
        except InvalidTag as exc:
            raise MeshError("Mesh AEAD authentication failed") from exc
        self._received[header["sender"]] = header["seq"]
        return payload

    def close(self):
        with self._lock:
            self._closed = True
            self._frozen = True
            self._erase()
            _wipe(self._ed)
            _wipe(self._x)

    def snapshot(self):
        with self._lock:
            return {"epoch": self._epoch, "frozen": self._frozen, "closed": self._closed,
                    "verified": self._verified, "sent": self._sequence,
                    "cached_keys": len(self._keys)}


class MeshPeer(_Endpoint):
    def seal(self, payload: bytes, receiver, purpose="telemetry.event") -> dict:
        authority = self._authority
        with authority._lock:
            if not authority._transaction_depth:
                authority.tick()
            authority._member(self)
            authority._member(receiver)
            return self._seal(payload, receiver._local_cert, purpose)

    send = seal

    def open(self, envelope: dict, purpose="telemetry.event", *, expected_sender=None) -> bytes:
        authority = self._authority
        with authority._lock:
            if not authority._transaction_depth:
                authority.tick()
            authority._member(self)
            try:
                sender_id = envelope["header"]["sender"]
                sender = authority._peers[sender_id]
            except (KeyError, TypeError):
                raise MeshError("Mesh packet sender is not enrolled") from None
            if expected_sender is not None and sender is not expected_sender:
                raise MeshError("Mesh packet sender differs from its bound capability")
            return self._open(envelope, sender._local_cert, purpose)

    receive = open

    @property
    def label(self):
        return self._local_identity["body"]["label"]

    @property
    def peer_id(self):
        return self._local_identity["body"]["peer"]


class MeshAuthority:
    def __init__(self, *, verified=False, gate=None, clock=time.monotonic,
                 rotation_seconds=ROTATION_SECONDS):
        if type(rotation_seconds) not in {int, float} or not 0.1 <= rotation_seconds <= 10:
            raise ValueError("Mesh rotation must be between 0.1 and 10 seconds")
        self._lock = threading.RLock()
        self._clock, self._gate = clock, gate
        self._ca = _private(ed25519.Ed25519PrivateKey)
        self._ca_public = _ed_public(self._ca)
        self.boot, self.session = secrets.token_hex(16), secrets.token_hex(16)
        self._peers = {}
        self._labels = set()
        self._epoch = 0
        self._issued = int(clock() * 1000)
        self._session_expires = self._issued + _SESSION_MS
        self._rotation_ms = int(rotation_seconds * 1000)
        self._expires = self._issued + self._rotation_ms
        self._verified = verified is True
        self._closed = False
        self._stop = threading.Event()
        self._transaction_depth = 0

    def _member(self, peer):
        if not isinstance(peer, MeshPeer) or self._peers.get(peer.peer_id) is not peer or peer._closed:
            raise MeshError("Mesh sender/receiver capability is not enrolled here")

    def enroll(self, label: str, source_digest="") -> MeshPeer:
        if not isinstance(label, str) or not _LABEL.fullmatch(label):
            raise ValueError("Invalid mesh peer label")
        if not isinstance(source_digest, str) or not _DIGEST.fullmatch(source_digest):
            raise ValueError("Mesh source digest must be empty or SHA-256")
        with self._lock:
            self.tick()
            if self._closed or len(self._peers) >= MAX_PEERS or label in self._labels:
                raise MeshError("Mesh enrollment is closed, full, or already named")
            peer = MeshPeer()
            signing, exchange = _private(ed25519.Ed25519PrivateKey), _private(x25519.X25519PrivateKey)
            fields = dict(boot=self.boot, session=self.session, peer=secrets.token_hex(16), label=label,
                          source_digest=source_digest, epoch=self._epoch, issued=self._issued,
                          signing=_ed_public(signing), exchange=_x_public(exchange), prefix=secrets.token_bytes(4))
            identity = _issue(self._ca, kind="identity", expires=self._session_expires, **fields)
            certificate = _issue(self._ca, kind="epoch", expires=self._expires, **fields)
            peer._setup(ca_public=self._ca_public, signing=signing, exchange=exchange,
                        local_identity=identity, remote_identity=None, local_cert=certificate, remote_cert=None,
                        boot=self.boot, session=self.session, clock=self._clock, gate=self._gate,
                        verified=self._verified, rotation_ms=self._rotation_ms)
            peer._authority = self
            self._peers[peer.peer_id] = peer
            self._labels.add(label)
            return peer

    def _rotate(self, now):
        self._epoch += 1
        self._issued, self._expires = now, min(now + self._rotation_ms, self._session_expires)
        for peer in self._peers.values():
            peer._erase()
            _wipe(peer._x)
            peer._x = _private(x25519.X25519PrivateKey)
            identity = peer._local_identity["body"]
            peer._local_cert = _issue(self._ca, kind="epoch", boot=self.boot, session=self.session,
                                      peer=identity["peer"], label=identity["label"], source_digest=identity["source_digest"],
                                      epoch=self._epoch, issued=now, expires=self._expires,
                                      signing=_ed_public(peer._ed), exchange=_x_public(peer._x), prefix=secrets.token_bytes(4))
            peer._epoch, peer._expires = self._epoch, self._expires
            peer._sequence = 0
            peer._received.clear()

    def tick(self):
        with self._lock:
            if self._closed:
                return
            now = int(self._clock() * 1000)
            if now < self._issued:
                self.freeze()
                raise MeshFrozen("Mesh session clock or lifetime is invalid")
            if self._gate is not None:
                try:
                    authorized = self._gate() is True
                except Exception:
                    authorized = False
                if not authorized:
                    self.freeze()
            if self._verified and now >= self._session_expires - 2 * self._rotation_ms:
                self.renew_session()
                return
            if now >= self._session_expires:
                raise MeshFrozen("Mesh session expired while frozen")
            if self._verified and now >= self._expires:
                self._rotate(now)

    def renew_session(self):
        """Renew only while the caller's live attestation gate remains approved."""
        with self._lock:
            if self._closed or not self._verified:
                raise MeshFrozen("Verified mesh authorization is required for renewal")
            if self._gate is not None and self._gate() is not True:
                self.freeze()
                raise MeshFrozen("Mesh renewal gate is not approved")
            now = int(self._clock() * 1000)
            _wipe(self._ca)
            self._ca = _private(ed25519.Ed25519PrivateKey)
            self._ca_public = _ed_public(self._ca)
            self.session = secrets.token_hex(16)
            self._session_expires = now + _SESSION_MS
            for peer in self._peers.values():
                old = peer._local_identity["body"]
                _wipe(peer._ed)
                peer._ed = _private(ed25519.Ed25519PrivateKey)
                _wipe(peer._x)
                peer._x = _private(x25519.X25519PrivateKey)
                peer._ca_public = self._ca_public
                peer.session = self.session
                peer._local_identity = _issue(self._ca, kind="identity", boot=self.boot,
                    session=self.session, peer=old["peer"], label=old["label"], source_digest=old["source_digest"],
                    epoch=self._epoch + 1, issued=now, expires=self._session_expires,
                    signing=_ed_public(peer._ed), exchange=_x_public(peer._x), prefix=secrets.token_bytes(4))
            self._rotate(now)

    @contextmanager
    def transaction(self):
        """Keep local seal/open together across the authority's rotation lock."""
        with self._lock:
            self.tick()
            now = int(self._clock() * 1000)
            if self._verified and now + min(1000, self._rotation_ms // 4) >= self._expires:
                self._rotate(now)
            self._transaction_depth += 1
            try:
                yield self
            finally:
                self._transaction_depth -= 1

    def set_verified(self, value: bool):
        with self._lock:
            if self._closed:
                raise MeshFrozen("Mesh is closed")
            if value is not True:
                self.freeze()
                return
            if self._gate is not None and self._gate() is not True:
                raise MeshFrozen("Mesh verification gate is not approved")
            self._verified = True
            if int(self._clock() * 1000) >= self._session_expires:
                self.renew_session()
            else:
                self._rotate(int(self._clock() * 1000))
            for peer in self._peers.values():
                peer._verified = True
                peer._frozen = False

    def freeze(self):
        with self._lock:
            self._verified = False
            for peer in self._peers.values():
                peer._verified = False
                peer._frozen = True
                peer._erase()
                _wipe(peer._x)

    def start_rotator(self):
        def rotate():
            while not self._stop.wait(self._rotation_ms / 1000):
                try:
                    self.tick()
                except MeshError:
                    return
        with self._lock:
            if not hasattr(self, "_rotator"):
                self._rotator = threading.Thread(target=rotate, name="EnclaveMesh-rotate", daemon=True)
                self._rotator.start()

    def close(self):
        with self._lock:
            self._closed = True
            self._stop.set()
            for peer in self._peers.values():
                peer.close()
            _wipe(self._ca)

    def snapshot(self):
        with self._lock:
            return {"verified": self._verified, "frozen": not self._verified,
                    "closed": self._closed, "epoch": self._epoch, "peers": len(self._peers),
                    "session_expires": self._session_expires / 1000,
                    "rotation_seconds": self._rotation_ms / 1000}


EnclaveMesh = MeshAuthority


class CrossProcessMeshChannel(_Endpoint):
    @classmethod
    def create_pair(cls, *, parent_label="ugcap.parent", child_label="ugcap.worker",
                    verified=False, gate=None, clock=time.monotonic, rotation_seconds=ROTATION_SECONDS):
        authority = MeshAuthority(verified=True, clock=clock, rotation_seconds=rotation_seconds)
        parent, child = authority.enroll(parent_label), authority.enroll(child_label)
        endpoint = cls()
        endpoint._setup(ca_public=authority._ca_public, signing=bytearray(parent._ed), exchange=bytearray(parent._x),
                        local_identity=parent._local_identity, remote_identity=child._local_identity,
                        local_cert=parent._local_cert, remote_cert=child._local_cert,
                        boot=authority.boot, session=authority.session, clock=clock, gate=gate,
                        verified=verified, rotation_ms=authority._rotation_ms)
        endpoint._ca = bytearray(authority._ca)
        endpoint._payload_limit = MAX_PAYLOAD
        endpoint._is_parent = True
        endpoint._control_send = endpoint._control_received = 0
        endpoint._pending = None
        endpoint._requested = False
        bootstrap = {"version": 1, "boot": authority.boot, "session": authority.session,
                     "ca_public": _b64(authority._ca_public), "signing_private": _b64(bytes(child._ed)),
                     "exchange_private": _b64(bytes(child._x)), "local_identity": child._local_identity,
                     "remote_identity": parent._local_identity, "local_cert": child._local_cert,
                     "remote_cert": parent._local_cert, "rotation_ms": authority._rotation_ms}
        authority.close()
        return endpoint, decode_frame(canonical(bootstrap))

    @classmethod
    def from_bootstrap(cls, bootstrap: dict, *, verified=False, gate=None, clock=time.monotonic):
        expected = {"version", "boot", "session", "ca_public", "signing_private", "exchange_private",
                    "local_identity", "remote_identity", "local_cert", "remote_cert", "rotation_ms"}
        if (not isinstance(bootstrap, dict) or set(bootstrap) != expected
                or type(bootstrap["version"]) is not int or bootstrap["version"] != 1
                or not isinstance(bootstrap["boot"], str) or not _ID.fullmatch(bootstrap["boot"])
                or not isinstance(bootstrap["session"], str) or not _ID.fullmatch(bootstrap["session"])
                or type(bootstrap["rotation_ms"]) is not int or not 100 <= bootstrap["rotation_ms"] <= 10000):
            raise MeshError("Invalid private mesh bootstrap")
        canonical(bootstrap)
        bootstrap = decode_frame(canonical(bootstrap))
        ca = _unb64(bootstrap["ca_public"], size=32, maximum=32)
        now = int(clock() * 1000)
        common = dict(ca=ca, boot=bootstrap["boot"], session=bootstrap["session"], now=now)
        local_id = _certificate(bootstrap["local_identity"], kind="identity", **common)
        remote_id = _certificate(bootstrap["remote_identity"], kind="identity", **common)
        local = _certificate(bootstrap["local_cert"], kind="epoch", expected=local_id, **common)
        remote = _certificate(bootstrap["remote_cert"], kind="epoch", expected=remote_id, **common)
        signing = bytearray(_unb64(bootstrap["signing_private"], size=32, maximum=32))
        exchange = bytearray(_unb64(bootstrap["exchange_private"], size=32, maximum=32))
        if (local_id["peer"] == remote_id["peer"] or local["epoch"] != remote["epoch"]
                or local["expires"] != remote["expires"]
                or _b64(_ed_public(signing)) != local["ed25519"]
                or _b64(_x_public(exchange)) != local["x25519"]):
            _wipe(signing)
            _wipe(exchange)
            raise MeshError("Mesh bootstrap private keys do not match certified identities")
        endpoint = cls()
        endpoint._setup(ca_public=ca, signing=signing, exchange=exchange,
                        local_identity=bootstrap["local_identity"], remote_identity=bootstrap["remote_identity"],
                        local_cert=bootstrap["local_cert"], remote_cert=bootstrap["remote_cert"],
                        boot=bootstrap["boot"], session=bootstrap["session"], clock=clock,
                        gate=gate, verified=verified, rotation_ms=bootstrap["rotation_ms"])
        endpoint._ca = None
        endpoint._payload_limit = MAX_PAYLOAD
        endpoint._is_parent = False
        endpoint._control_send = endpoint._control_received = 0
        endpoint._pending = None
        endpoint._requested = False
        return endpoint

    def seal(self, payload: bytes, purpose: str) -> dict:
        with self._lock:
            if self._pending is not None or self._now() + min(1000, self._rotation_ms // 4) >= self._expires:
                raise MeshHandshakeRequired("Mesh is quiescing for a fresh epoch")
            return self._seal(payload, self._remote_cert, purpose)

    def open(self, envelope: dict, purpose: str) -> bytes:
        with self._lock:
            return self._open(envelope, self._remote_cert, purpose)

    def _control(self, kind, epoch, data):
        if self._control_send >= 2**63 - 1:
            raise MeshError("Mesh control sequence limit reached")
        self._control_send += 1
        now = self._now()
        body = {"version": 1, "kind": "control", "boot": self.boot, "session": self.session,
                "sender": self._local_identity["body"]["peer"], "receiver": self._remote_identity["body"]["peer"],
                "seq": self._control_send, "issued": now, "expires": min(now + 5000, self._local_identity["body"]["expires"]),
                "type": kind, "epoch": epoch, "data": data}
        return {"body": body, "signature": _sign(self._ed, _CONTROL_DOMAIN, body)}

    def _epoch_cert(self, identity, exchange, prefix, epoch, issued, expires):
        body = identity["body"]
        return _issue(self._ca, kind="epoch", boot=self.boot, session=self.session, peer=body["peer"],
                      label=body["label"], source_digest=body["source_digest"], epoch=epoch, issued=issued,
                      expires=expires, signing=_unb64(body["ed25519"], size=32, maximum=32),
                      exchange=exchange, prefix=prefix)

    def _begin(self):
        now = self._now()
        exchange = _private(x25519.X25519PrivateKey)
        epoch = self._epoch + 1
        cert = self._epoch_cert(self._local_identity, _x_public(exchange), secrets.token_bytes(4),
                                epoch, now, min(now + self._rotation_ms, self._local_identity["body"]["expires"]))
        self._pending = {"stage": "proposal", "epoch": epoch, "exchange": exchange,
                         "local_cert": cert, "challenge": secrets.token_hex(16), "deadline": now + 5000}
        return self._control("proposal", epoch, {"certificate": cert, "challenge": self._pending["challenge"]})

    def control_frames(self) -> list[dict]:
        with self._lock:
            self._require()
            now = self._now()
            if now >= self._local_identity["body"]["expires"]:
                raise MeshFrozen("Mesh session expired")
            if self._pending is not None and now >= self._pending["deadline"]:
                self.close()
                raise MeshFrozen("Mesh epoch handshake expired")
            if now + min(1000, self._rotation_ms // 4) < self._expires or self._pending is not None:
                return []
            if self._is_parent:
                return [self._begin()]
            if not self._requested:
                self._requested = True
                return [self._control("request", self._epoch + 1, {})]
            return []

    tick = control_frames

    def _install(self, pending):
        self._erase()
        _wipe(self._x)
        self._x = pending["exchange"]
        self._local_cert, self._remote_cert = pending["local_cert"], pending["remote_cert"]
        self._epoch, self._expires = pending["epoch"], pending["local_cert"]["body"]["expires"]
        self._sequence = 0
        self._received.clear()
        self._requested = False

    def accept_control(self, frame: dict) -> list[dict]:
        with self._lock:
            self._require()
            now = self._now()
            if (not isinstance(frame, dict) or set(frame) != {"body", "signature"}
                    or not isinstance(frame.get("body"), dict) or set(frame["body"]) != _CONTROL_FIELDS):
                raise MeshError("Invalid mesh control frame")
            canonical(frame)
            body = frame["body"]
            if (type(body["version"]) is not int or body["version"] != 1 or body["kind"] != "control"
                    or body["boot"] != self.boot or body["session"] != self.session
                    or body["sender"] != self._remote_identity["body"]["peer"]
                    or body["receiver"] != self._local_identity["body"]["peer"]
                    or type(body["seq"]) is not int or not self._control_received < body["seq"] < 2**63
                    or type(body["epoch"]) is not int or not 0 <= body["epoch"] < 2**63
                    or type(body["issued"]) is not int or type(body["expires"]) is not int
                    or not body["issued"] <= now < body["expires"] <= self._remote_identity["body"]["expires"]
                    or body["expires"] - body["issued"] > 5000 or not isinstance(body["data"], dict)):
                raise MeshError("Mesh control identity, sequence, or lifetime is invalid")
            _verify(_unb64(self._remote_identity["body"]["ed25519"], size=32, maximum=32),
                    _CONTROL_DOMAIN, body, frame["signature"])
            self._control_received = body["seq"]
            kind, data, epoch = body["type"], body["data"], body["epoch"]
            if kind == "request" and self._is_parent and data == {} and epoch == self._epoch + 1:
                return [] if self._pending is not None else [self._begin()]
            if kind == "proposal" and not self._is_parent and self._pending is None and epoch == self._epoch + 1:
                if set(data) != {"certificate", "challenge"} or not isinstance(data["challenge"], str) or not _ID.fullmatch(data["challenge"]):
                    raise MeshError("Invalid mesh rekey proposal")
                parent = _certificate(data["certificate"], self._ca_public, boot=self.boot, session=self.session,
                                      now=now, kind="epoch", expected=self._remote_identity["body"])
                if parent["epoch"] != epoch or parent["expires"] - parent["issued"] > self._rotation_ms:
                    raise MeshError("Mesh rekey proposal has an invalid epoch")
                if parent["x25519"] == self._remote_cert["body"]["x25519"]:
                    raise MeshError("Mesh rekey proposal reused its previous exchange key")
                exchange = _private(x25519.X25519PrivateKey)
                self._pending = {"stage": "reply", "epoch": epoch, "exchange": exchange,
                                 "remote_cert": data["certificate"], "prefix": secrets.token_bytes(4),
                                 "challenge": data["challenge"], "deadline": now + 5000}
                return [self._control("reply", epoch, {"challenge": data["challenge"],
                                                       "x25519": _b64(_x_public(exchange)),
                                                       "nonce_prefix": _b64(self._pending["prefix"])})]
            pending = self._pending
            if pending is None or epoch != pending["epoch"] or now >= pending["deadline"]:
                raise MeshError("Unsolicited or expired mesh rekey frame")
            if kind == "reply" and self._is_parent and pending["stage"] == "proposal":
                if set(data) != {"challenge", "x25519", "nonce_prefix"} or data["challenge"] != pending["challenge"]:
                    raise MeshError("Mesh rekey response challenge is invalid")
                if data["x25519"] == self._remote_cert["body"]["x25519"]:
                    raise MeshError("Mesh rekey response reused its previous exchange key")
                remote_cert = self._epoch_cert(self._remote_identity,
                                               _unb64(data["x25519"], size=32, maximum=32),
                                               _unb64(data["nonce_prefix"], size=4, maximum=4), epoch,
                                               pending["local_cert"]["body"]["issued"], pending["local_cert"]["body"]["expires"])
                pending.update(stage="commit", remote_cert=remote_cert)
                return [self._control("commit", epoch, {"challenge": pending["challenge"],
                                                        "parent_certificate": pending["local_cert"],
                                                        "child_certificate": remote_cert})]
            if kind == "commit" and not self._is_parent and pending["stage"] == "reply":
                if (set(data) != {"challenge", "parent_certificate", "child_certificate"}
                        or data["challenge"] != pending["challenge"] or data["parent_certificate"] != pending["remote_cert"]):
                    raise MeshError("Mesh rekey commit does not match its proposal")
                local = _certificate(data["child_certificate"], self._ca_public, boot=self.boot, session=self.session,
                                     now=now, kind="epoch", expected=self._local_identity["body"])
                if (local["epoch"] != epoch or local["x25519"] != _b64(_x_public(pending["exchange"]))
                        or local["nonce_prefix"] != _b64(pending["prefix"])
                        or local["expires"] != pending["remote_cert"]["body"]["expires"]):
                    raise MeshError("Mesh rekey commit changed the child's fresh key")
                pending["local_cert"] = data["child_certificate"]
                self._install(pending)
                pending["stage"] = "ack"
                self._pending = pending
                return [self._control("ack", epoch, {"challenge": pending["challenge"]})]
            if kind == "ack" and self._is_parent and pending["stage"] == "commit":
                if data != {"challenge": pending["challenge"]}:
                    raise MeshError("Mesh rekey acknowledgement is invalid")
                self._install(pending)
                self._pending = None
                return []
            raise MeshError("Unexpected mesh control transition")

    def control_sent(self, frame):
        """Release child application sends only after its ack entered the pipe."""
        with self._lock:
            if (not self._is_parent and self._pending is not None and self._pending["stage"] == "ack"
                    and frame.get("body", {}).get("type") == "ack"):
                self._pending = None

    def snapshot(self):
        result = super().snapshot()
        result["session_expires"] = self._local_identity["body"]["expires"] / 1000
        return result

    def close(self):
        with self._lock:
            if self._pending is not None:
                _wipe(self._pending.get("exchange"))
                self._pending = None
            _wipe(self._ca)
            super().close()


class MeshPipe:
    """Bounded duplex inherited-pipe transport; receive returns plaintext bytes.

    The caller owns the supplied streams and closes them/processes after close.
    Reader threads are daemons; EOF ends their blocking read. No listener,
    network socket, Qt object, raw application message, or fallback protocol is
    used. A pipe failure freezes the channel and wakes pending receivers.
    """

    def __init__(self, endpoint: CrossProcessMeshChannel, reader, writer, *, allowed_purposes):
        purposes = frozenset(allowed_purposes)
        if not purposes or len(purposes) > 16 or any(not isinstance(p, str) or not _PURPOSE.fullmatch(p) for p in purposes):
            raise ValueError("Mesh pipe needs a bounded purpose allowlist")
        self.endpoint, self.reader, self.writer = endpoint, reader, writer
        self._purposes = purposes
        self._condition = threading.Condition()
        self._write_lock = threading.RLock()
        self._inbox = {purpose: deque() for purpose in purposes}
        self._count = 0
        self._queued_bytes = 0
        self._write_bytes = 0
        self._tickets = []
        self._write_queue = queue.Queue(maxsize=16)
        self._error = ""
        self._stop = threading.Event()
        self._reader_thread = threading.Thread(target=self._read_loop, name="EnclaveMesh-pipe-read", daemon=True)
        self._maintenance_thread = threading.Thread(target=self._maintenance, name="EnclaveMesh-pipe-rekey", daemon=True)
        self._writer_thread = threading.Thread(target=self._write_loop, name="EnclaveMesh-pipe-write", daemon=True)
        self._writer_thread.start()
        self._reader_thread.start()
        self._maintenance_thread.start()

    def _fail(self, reason):
        with self._condition:
            if not self._error:
                self._error = reason
            self._stop.set()
            self.endpoint.close()
            for messages in self._inbox.values():
                messages.clear()
            self._count = self._queued_bytes = 0
            for ticket in self._tickets:
                ticket["error"] = True
                ticket["event"].set()
            self._condition.notify_all()

    def _write(self, frame, timeout=5.0):
        deadline = time.monotonic() + max(0.01, timeout)
        if not self._write_lock.acquire(timeout=max(0.01, timeout)):
            self._fail("Mesh pipe writer deadline expired")
            raise TimeoutError("Mesh write timed out")
        try:
            wire = canonical(frame) + b"\n"
            ticket = {"event": threading.Event(), "error": False, "wire": wire, "frame": frame}
            with self._condition:
                if self._stop.is_set():
                    raise MeshFrozen("Mesh pipe is closed")
                if self._write_bytes + len(wire) > _MAX_QUEUED_BYTES:
                    raise MeshError("Mesh writer queue exceeds its byte limit")
                self._tickets.append(ticket)
                self._write_bytes += len(wire)
                self._write_queue.put_nowait(ticket)
            if not ticket["event"].wait(max(0, deadline - time.monotonic())):
                self._fail("Mesh pipe writer deadline expired")
                raise TimeoutError("Mesh write timed out")
            if ticket["error"]:
                raise MeshFrozen("Mesh pipe writer failed or closed")
        finally:
            self._write_lock.release()

    def _write_loop(self):
        while not self._stop.is_set():
            try:
                ticket = self._write_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                self.writer.write(ticket["wire"])
                self.writer.flush()
                self.endpoint.control_sent(ticket["frame"])
            except Exception:
                ticket["error"] = True
                self._fail("Mesh pipe transport write failed")
            finally:
                with self._condition:
                    self._write_bytes = max(0, self._write_bytes - len(ticket["wire"]))
                    self._tickets = [value for value in self._tickets if value is not ticket]
                ticket["event"].set()

    def _maintenance(self):
        while not self._stop.wait(0.05):
            try:
                for frame in self.endpoint.control_frames():
                    self._write(frame)
            except Exception:
                self._fail("Mesh pipe renewal or authorization failed")
                return

    def _read_loop(self):
        try:
            while not self._stop.is_set():
                raw = self.reader.readline(MAX_WIRE + 1)
                if not raw:
                    self._fail("Mesh pipe reached EOF")
                    return
                if len(raw) > MAX_WIRE or not raw.endswith(b"\n"):
                    raise MeshError("Invalid mesh pipe framing")
                frame = decode_frame(raw)
                if set(frame) == {"body", "signature"}:
                    for reply in self.endpoint.accept_control(frame):
                        self._write(reply)
                    with self._condition:
                        if self._stop.is_set():
                            return
                        self._condition.notify_all()
                else:
                    purpose = frame.get("header", {}).get("purpose")
                    if purpose not in self._purposes:
                        raise MeshError("Mesh pipe purpose is not allowed")
                    payload = self.endpoint.open(frame, purpose)
                    with self._condition:
                        if self._stop.is_set():
                            return
                        if self._count >= 64 or self._queued_bytes + len(payload) > _MAX_QUEUED_BYTES:
                            raise MeshError("Mesh pipe receive queue is full")
                        self._inbox[purpose].append((payload, frame["header"]["expires"], frame["header"]["epoch"]))
                        self._count += 1
                        self._queued_bytes += len(payload)
                        self._condition.notify_all()
        except Exception:
            self._fail("Mesh pipe authentication, framing, or transport failed")

    def send(self, payload: bytes, purpose: str, timeout=5.0):
        if purpose not in self._purposes:
            raise MeshError("Mesh pipe purpose is not allowed")
        deadline = time.monotonic() + max(0.1, min(float(timeout), 120.0))
        while True:
            with self._condition:
                if self._error or self._stop.is_set():
                    raise MeshFrozen(self._error or "Mesh pipe is closed")
            try:
                if not self._write_lock.acquire(timeout=max(0, deadline - time.monotonic())):
                    raise TimeoutError("Mesh writer timed out")
                try:
                    frame = self.endpoint.seal(payload, purpose)
                    self._write(frame, timeout=max(0.01, deadline - time.monotonic()))
                finally:
                    self._write_lock.release()
                return
            except MeshHandshakeRequired:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Mesh epoch negotiation timed out") from None
                with self._condition:
                    self._condition.wait(min(remaining, 0.1))

    def receive(self, purpose: str, timeout=120.0) -> bytes:
        if purpose not in self._purposes:
            raise MeshError("Mesh pipe purpose is not allowed")
        deadline = time.monotonic() + max(0.0, min(float(timeout), 3600.0))
        with self._condition:
            while True:
                with self.endpoint._lock:
                    self.endpoint._require()
                    now = self.endpoint._now()
                    if now >= self.endpoint._local_identity["body"]["expires"]:
                        raise MeshFrozen("Mesh session expired")
                if self._error or self._stop.is_set():
                    raise MeshFrozen(self._error or "Mesh pipe is closed")
                if self._inbox[purpose]:
                    self._count -= 1
                    payload, expires, epoch = self._inbox[purpose].popleft()
                    self._queued_bytes -= len(payload)
                    if now < expires and epoch == self.endpoint._epoch:
                        return payload
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Mesh receive timed out")
                self._condition.wait(remaining)

    def close(self):
        self._fail("Mesh pipe is closed")
        with self._condition:
            for messages in self._inbox.values():
                messages.clear()
            self._count = 0
        # Cancel only this object's own synchronous pipe I/O, then let its
        # threads finish before a Windows helper interpreter tears crypto down.
        # No process/thread termination or external handle authority is used.
        self._cancel_io_threads()
        current = threading.current_thread()
        for worker in (self._maintenance_thread, self._writer_thread, self._reader_thread):
            if worker is not current:
                worker.join(timeout=0.5)

    def _cancel_io_threads(self):
        import os
        if os.name != "nt":
            return
        try:
            import ctypes
            kernel = ctypes.WinDLL("kernel32", winmode=0x800)
            open_thread = kernel.OpenThread
            open_thread.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
            open_thread.restype = ctypes.c_void_p
            cancel = kernel.CancelSynchronousIo
            cancel.argtypes = [ctypes.c_void_p]
            cancel.restype = ctypes.c_int
            close = kernel.CloseHandle
            close.argtypes = [ctypes.c_void_p]
            close.restype = ctypes.c_int
            for worker in (self._reader_thread, self._writer_thread):
                if worker.is_alive() and worker.native_id is not None:
                    handle = open_thread(1, False, worker.native_id)  # THREAD_TERMINATE required by API.
                    if handle:
                        try:
                            cancel(handle)
                        finally:
                            close(handle)
        except (OSError, AttributeError):
            pass

    def snapshot(self):
        with self._condition:
            return {"closed": self._stop.is_set(), "queued": self._count,
                    "queued_bytes": self._queued_bytes, "writer_bytes": self._write_bytes,
                    "state": "closed" if self._stop.is_set() else "active",
                    "channel": self.endpoint.snapshot()}
