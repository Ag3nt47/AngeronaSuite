"""Optional Windows TPM key continuity for the UGCAP vault.

Only ``provision()`` creates a persistent current-user RSA key. Every other
operation opens an existing nonexportable key through the exact Microsoft
Platform Crypto Provider and requires its hardware implementation flag. There
is no DPAPI, software-provider, password, or device-serial substitute.

This proves local TPM-key possession, not remote attestation, measured boot, or
physical uniqueness. In particular, clonable virtual-TPM snapshots require a
separate attestation/deployment policy. FIDO/YubiKey support is not implemented.

Native contracts are documented by Microsoft:
https://learn.microsoft.com/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey
https://learn.microsoft.com/windows/win32/api/ncrypt/nf-ncrypt-ncryptdecrypt
https://learn.microsoft.com/windows/win32/api/ncrypt/nf-ncrypt-ncryptsignhash
https://learn.microsoft.com/windows/win32/seccng/key-storage-property-identifiers
https://learn.microsoft.com/windows/win32/api/tbs/nf-tbs-tbsi_getdeviceinfo
"""
from __future__ import annotations

import base64
from collections import OrderedDict
from contextlib import contextmanager
import ctypes
import hashlib
import hmac
import json
import re
import secrets
import struct
import sys
import threading


PROVIDER = "Microsoft Platform Crypto Provider"
_WRAP_LABEL = b"Angerona/UGCAP/TPM/OAEP/v1"
_PROOF_DOMAIN = b"Angerona/UGCAP/TPM/proof/v1\0"
_SCHEMA = frozenset({"version", "provider", "key_name", "public_key_sha256",
                     "key_bits", "algorithm", "wrapped_secret"})
_NAME = re.compile(r"Angerona\.UGCAP\.[A-Za-z0-9_-]{1,96}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_SILENT = 0x40
_PAD_PKCS1 = 0x2
_PAD_OAEP = 0x4
_BUFFER_TOO_SMALL = 0x80090028
_MACHINE_KEY = 0x20
_UINT32 = ctypes.c_uint32
_HANDLE = ctypes.c_size_t


class HardwareBindingError(RuntimeError):
    """The hardware operation failed closed; the message contains no secrets."""


class HardwareUnavailable(HardwareBindingError):
    """The selected provider, TPM, or existing key is unavailable."""


class HardwareIntegrityError(HardwareBindingError):
    """A descriptor or key-possession proof did not match the enrolled key."""


class _OAEPInfo(ctypes.Structure):
    _fields_ = [("pszAlgId", ctypes.c_wchar_p), ("pbLabel", ctypes.c_void_p),
                ("cbLabel", _UINT32)]


class _PKCS1Info(ctypes.Structure):
    _fields_ = [("pszAlgId", ctypes.c_wchar_p)]


class _TPMDeviceInfo(ctypes.Structure):
    _fields_ = [("structVersion", _UINT32), ("tpmVersion", _UINT32),
                ("tpmInterfaceType", _UINT32), ("tpmImpRevision", _UINT32)]


def _check(status, operation: str) -> None:
    value = int(status) & 0xFFFFFFFF
    if value:
        raise HardwareUnavailable(f"TPM {operation} failed (0x{value:08x})")


def _output(call, *, limit: int = 8192) -> bytes:
    """Bound both stages of a CNG caller-allocated output buffer."""
    size = _UINT32()
    status = int(call(None, 0, ctypes.byref(size))) & 0xFFFFFFFF
    if status not in {0, _BUFFER_TOO_SMALL}:
        _check(status, "output sizing")
    if not 0 < size.value <= limit:
        raise HardwareIntegrityError("TPM returned an invalid output length")
    capacity = size.value
    result = (ctypes.c_ubyte * capacity)()
    _check(call(result, capacity, ctypes.byref(size)), "output operation")
    if not 0 < size.value <= capacity:
        raise HardwareIntegrityError("TPM output length changed beyond its buffer")
    return bytes(result[:size.value])


def _public_from_blob(blob: bytes):
    """Parse only bounded RSA public blobs; private blobs are never requested."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    if not isinstance(blob, bytes) or not 24 <= len(blob) <= 1024:
        raise HardwareIntegrityError("TPM public key blob is invalid")
    magic, bits, exponent_len, modulus_len, prime1, prime2 = struct.unpack("<6I", blob[:24])
    if (magic != 0x31415352 or bits not in {2048, 3072}
            or not 1 <= exponent_len <= 8 or modulus_len != bits // 8
            or prime1 or prime2 or len(blob) != 24 + exponent_len + modulus_len):
        raise HardwareIntegrityError("TPM public key blob is invalid")
    exponent = int.from_bytes(blob[24:24 + exponent_len], "big")
    modulus = int.from_bytes(blob[24 + exponent_len:], "big")
    if exponent != 65537 or modulus.bit_length() != bits or not modulus & 1:
        raise HardwareIntegrityError("TPM RSA public parameters are invalid")
    try:
        return rsa.RSAPublicNumbers(exponent, modulus).public_key()
    except ValueError as exc:
        raise HardwareIntegrityError("TPM RSA public parameters are invalid") from exc


def _fingerprint(public) -> str:
    from cryptography.hazmat.primitives import serialization
    encoded = public.public_bytes(serialization.Encoding.DER,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(encoded).hexdigest()


class _CNGKey:
    def __init__(self, native, handle: int, metadata: dict) -> None:
        self.native = native
        self.handle = handle
        self.metadata = metadata

    def public_key(self):
        blob = _output(lambda out, size, used: self.native.dll.NCryptExportKey(
            self.handle, 0, "RSAPUBLICBLOB", None, out, size, used, _SILENT), limit=1024)
        return _public_from_blob(blob)

    def sign_digest(self, digest: bytes) -> bytes:
        if type(digest) is not bytes or len(digest) != 32:
            raise HardwareIntegrityError("TPM proof digest must be SHA-256")
        value = (ctypes.c_ubyte * len(digest)).from_buffer_copy(digest)
        padding = _PKCS1Info("SHA256")
        return _output(lambda out, size, used: self.native.dll.NCryptSignHash(
            self.handle, ctypes.byref(padding), value, len(digest), out, size, used,
            _PAD_PKCS1 | _SILENT), limit=384)

    def decrypt(self, wrapped: bytes) -> bytes:
        if type(wrapped) is not bytes or len(wrapped) not in {256, 384}:
            raise HardwareIntegrityError("TPM wrapped key length is invalid")
        value = (ctypes.c_ubyte * len(wrapped)).from_buffer_copy(wrapped)
        label = (ctypes.c_ubyte * len(_WRAP_LABEL)).from_buffer_copy(_WRAP_LABEL)
        padding = _OAEPInfo("SHA256", ctypes.cast(label, ctypes.c_void_p), len(_WRAP_LABEL))
        return _output(lambda out, size, used: self.native.dll.NCryptDecrypt(
            self.handle, value, len(wrapped), ctypes.byref(padding), out, size, used,
            _PAD_OAEP | _SILENT), limit=384)


class _WindowsCNG:
    """Narrow native adapter. Constructing it never opens or creates a key."""

    def __init__(self, *, loader=None) -> None:
        if sys.platform != "win32":
            raise HardwareUnavailable("Windows TPM binding is unavailable on this platform")
        try:
            load = loader or ctypes.WinDLL
            self.dll = load("ncrypt.dll", winmode=0x800)  # SYSTEM32 only
            self._configure_api()
            try:
                self.tbs = load("tbs.dll", winmode=0x800)
                self.tbs.Tbsi_GetDeviceInfo.argtypes = [_UINT32, ctypes.c_void_p]
                self.tbs.Tbsi_GetDeviceInfo.restype = _UINT32
            except (OSError, AttributeError):
                self.tbs = None
        except (OSError, AttributeError) as exc:
            raise HardwareUnavailable("Windows CNG TPM APIs are unavailable") from exc

    def _configure_api(self) -> None:
        pointer = ctypes.c_void_p
        dword_ptr = ctypes.POINTER(_UINT32)
        signatures = {
            "NCryptOpenStorageProvider": [ctypes.POINTER(_HANDLE), ctypes.c_wchar_p, _UINT32],
            "NCryptOpenKey": [_HANDLE, ctypes.POINTER(_HANDLE), ctypes.c_wchar_p, _UINT32, _UINT32],
            "NCryptCreatePersistedKey": [_HANDLE, ctypes.POINTER(_HANDLE), ctypes.c_wchar_p,
                                          ctypes.c_wchar_p, _UINT32, _UINT32],
            "NCryptSetProperty": [_HANDLE, ctypes.c_wchar_p, pointer, _UINT32, _UINT32],
            "NCryptGetProperty": [_HANDLE, ctypes.c_wchar_p, pointer, _UINT32, dword_ptr, _UINT32],
            "NCryptFinalizeKey": [_HANDLE, _UINT32],
            "NCryptExportKey": [_HANDLE, _HANDLE, ctypes.c_wchar_p, pointer, pointer,
                                  _UINT32, dword_ptr, _UINT32],
            "NCryptSignHash": [_HANDLE, pointer, pointer, _UINT32, pointer, _UINT32,
                                 dword_ptr, _UINT32],
            "NCryptDecrypt": [_HANDLE, pointer, _UINT32, pointer, pointer, _UINT32,
                                dword_ptr, _UINT32],
            "NCryptFreeObject": [_HANDLE],
            "NCryptDeleteKey": [_HANDLE, _UINT32],
        }
        for name, args in signatures.items():
            fn = getattr(self.dll, name)
            fn.argtypes = args
            fn.restype = ctypes.c_int32

    def _property(self, handle: int, name: str) -> bytes:
        return _output(lambda out, size, used: self.dll.NCryptGetProperty(
            handle, name, out, size, used, 0), limit=4096)

    def _dword(self, handle: int, name: str) -> int:
        value = self._property(handle, name)
        if len(value) != 4:
            raise HardwareIntegrityError("TPM property has an invalid length")
        return struct.unpack("<I", value)[0]

    def _tpm_version(self) -> str:
        if self.tbs is None:
            return "unavailable"
        info = _TPMDeviceInfo(2, 0, 0, 0)
        status = int(self.tbs.Tbsi_GetDeviceInfo(ctypes.sizeof(info), ctypes.byref(info)))
        if status == 0x8028400F:  # TBS_E_TPM_NOT_FOUND
            raise HardwareUnavailable("No compatible TPM is present")
        if status:
            return "unavailable"
        if info.tpmVersion != 2:
            raise HardwareUnavailable("UGCAP requires a TPM 2.0 device")
        return "2.0"

    @contextmanager
    def _provider(self):
        handle = _HANDLE()
        _check(self.dll.NCryptOpenStorageProvider(ctypes.byref(handle), PROVIDER, 0), "provider open")
        if not handle.value:
            raise HardwareUnavailable("TPM provider returned no handle")
        try:
            implementation = self._dword(handle.value, "Impl Type")
            if not implementation & 1 or implementation & 2:
                raise HardwareUnavailable("The selected provider is not exclusively hardware backed")
            metadata = {"provider": PROVIDER, "hardware_backed": True,
                        "tpm_version": self._tpm_version(), "physical_attestation": False}
            yield handle.value, metadata
        finally:
            self.dll.NCryptFreeObject(handle.value)

    def probe(self) -> dict:
        with self._provider() as (_provider, metadata):
            return dict(metadata)

    @contextmanager
    def open(self, key_name: str, *, create: bool = False):
        with self._provider() as (provider, metadata):
            key = _HANDLE()
            deleted = False
            created = False
            try:
                if create:
                    # Flags 0: current-user key, no overwrite, no software/VBS
                    # fallback. Never request a machine-wide administrative key.
                    status = self.dll.NCryptCreatePersistedKey(provider, ctypes.byref(key), "RSA",
                                                               key_name, 0, 0)
                    if int(status) & 0xFFFFFFFF:
                        # A failed native call grants no custody of its output
                        # handle, including a name collision with an old key.
                        key.value = 0
                        _check(status, "key enrollment")
                    created = True
                    for prop, value in (("Length", 2048), ("Key Usage", 3), ("Export Policy", 0)):
                        encoded = _UINT32(value)
                        _check(self.dll.NCryptSetProperty(key.value, prop, ctypes.byref(encoded),
                                                         ctypes.sizeof(encoded), 0), "key policy")
                    _check(self.dll.NCryptFinalizeKey(key.value, _SILENT), "key finalization")
                else:
                    status = self.dll.NCryptOpenKey(provider, ctypes.byref(key), key_name, 0, _SILENT)
                    if int(status) & 0xFFFFFFFF:
                        key.value = 0
                        _check(status, "existing key open")
                if not key.value:
                    raise HardwareUnavailable("TPM key handle is unavailable")
                if (self._dword(key.value, "Length") not in {2048, 3072}
                        or self._dword(key.value, "Key Type") & _MACHINE_KEY
                        or self._dword(key.value, "Export Policy") != 0
                        or self._dword(key.value, "Key Usage") & 3 != 3):
                    raise HardwareIntegrityError("TPM key policy does not match UGCAP enrollment")
                yield _CNGKey(self, key.value, metadata)
            except BaseException:
                if created and key.value:
                    # Only this newly created key may be removed on enrollment
                    # failure. Existing/opened keys are never deleted or reset.
                    deleted = int(self.dll.NCryptDeleteKey(key.value, _SILENT)) == 0
                raise
            finally:
                if key.value and not deleted:
                    self.dll.NCryptFreeObject(key.value)


class WindowsTPMHardware:
    """TPM-bound wrapping of 16–64-byte vault keys, with live possession proof.

    The injectable native factory is for offline tests; production always uses
    the fixed CNG provider. A descriptor selects no provider or executable.
    Call provision only in response to the operator's explicit enrollment.
    """

    def __init__(self, key_name: str = "Angerona.UGCAP.v1", *, native_factory=None) -> None:
        if not isinstance(key_name, str) or not _NAME.fullmatch(key_name):
            raise ValueError("UGCAP TPM key name is invalid")
        self.key_name = key_name
        self._native_factory = native_factory or _WindowsCNG
        self._lock = threading.RLock()
        self._challenges: OrderedDict[bytes, None] = OrderedDict()

    def _identity(self, key) -> dict:
        public = key.public_key()
        metadata = key.metadata
        if metadata.get("provider") != PROVIDER or metadata.get("hardware_backed") is not True:
            raise HardwareIntegrityError("TPM hardware-provider identity is unverified")
        return {"backend": "windows_tpm", "provider": PROVIDER, "key_name": self.key_name,
                "public_key_sha256": _fingerprint(public), "key_bits": public.key_size,
                "hardware_backed": True, "nonexportable": True, "scope": "current-user",
                "tpm_version": metadata.get("tpm_version", "unavailable"),
                "physical_attestation": False}

    def identity(self) -> dict:
        with self._lock, self._native_factory().open(self.key_name) as key:
            return self._identity(key)

    def status(self) -> dict:
        try:
            native = self._native_factory()
            metadata = native.probe()
            if metadata.get("provider") != PROVIDER or metadata.get("hardware_backed") is not True:
                raise HardwareIntegrityError("TPM hardware-provider identity is unverified")
            try:
                with native.open(self.key_name) as key:
                    return {"available": True, "enrolled": True, "state": "ready", **self._identity(key)}
            except HardwareBindingError:
                return {"available": True, "enrolled": False, "state": "enrollment_required",
                        "provider": PROVIDER, "reason": "A matching usable TPM key is not enrolled"}
        except HardwareBindingError as exc:
            return {"available": False, "enrolled": False, "state": "unavailable", "reason": str(exc)}

    def available(self) -> bool:
        return self.status()["available"]

    @staticmethod
    def _proof(key, public, context: bytes) -> None:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, utils
        digest = hashlib.sha256(_PROOF_DOMAIN + secrets.token_bytes(32) + context).digest()
        signature = key.sign_digest(digest)
        if type(signature) is not bytes or len(signature) != public.key_size // 8:
            raise HardwareIntegrityError("TPM possession proof has an invalid length")
        try:
            public.verify(signature, digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
        except (InvalidSignature, ValueError) as exc:
            raise HardwareIntegrityError("TPM possession proof did not verify") from exc

    def provision(self) -> dict:
        """Explicit enrollment only; an existing key is never overwritten."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        with self._lock, self._native_factory().open(self.key_name, create=True) as key:
            identity = self._identity(key)
            public = key.public_key()
            self._proof(key, public, secrets.token_bytes(32))
            probe = secrets.token_bytes(32)
            wrapped = public.encrypt(probe, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                        algorithm=hashes.SHA256(), label=_WRAP_LABEL))
            if not hmac.compare_digest(key.decrypt(wrapped), probe):
                raise HardwareIntegrityError("TPM enrollment unwrap self-check failed")
            return identity

    def seal(self, secret: bytes) -> dict:
        if type(secret) is not bytes or not 16 <= len(secret) <= 64:
            raise ValueError("UGCAP TPM sealing requires a 16–64-byte secret")
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        with self._lock, self._native_factory().open(self.key_name) as key:
            identity = self._identity(key)
            wrapped = key.public_key().encrypt(secret, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                                  algorithm=hashes.SHA256(), label=_WRAP_LABEL))
            return {"version": 1, "provider": PROVIDER, "key_name": self.key_name,
                    "public_key_sha256": identity["public_key_sha256"],
                    "key_bits": identity["key_bits"], "algorithm": "RSA-OAEP-SHA256",
                    "wrapped_secret": base64.b64encode(wrapped).decode("ascii")}

    def unseal(self, descriptor: dict, challenge: bytes) -> bytes:
        if type(challenge) is not bytes or not 32 <= len(challenge) <= 1024:
            raise HardwareIntegrityError("UGCAP requires a fresh 32–1024-byte challenge")
        if (not isinstance(descriptor, dict) or set(descriptor) != _SCHEMA
                or type(descriptor.get("version")) is not int or descriptor["version"] != 1
                or descriptor.get("provider") != PROVIDER or descriptor.get("key_name") != self.key_name
                or descriptor.get("algorithm") != "RSA-OAEP-SHA256"
                or type(descriptor.get("key_bits")) is not int or descriptor["key_bits"] not in {2048, 3072}
                or not isinstance(descriptor.get("public_key_sha256"), str)
                or not _HASH.fullmatch(descriptor["public_key_sha256"])
                or not isinstance(descriptor.get("wrapped_secret"), str)
                or len(descriptor["wrapped_secret"]) > 1024):
            raise HardwareIntegrityError("UGCAP TPM descriptor is invalid")
        try:
            wrapped = base64.b64decode(descriptor["wrapped_secret"], validate=True)
        except (ValueError, UnicodeError) as exc:
            raise HardwareIntegrityError("UGCAP TPM ciphertext encoding is invalid") from exc
        if len(wrapped) != descriptor["key_bits"] // 8:
            raise HardwareIntegrityError("UGCAP TPM ciphertext length is invalid")
        with self._lock:
            challenge_id = hashlib.sha256(challenge).digest()
            if challenge_id in self._challenges:
                raise HardwareIntegrityError("UGCAP hardware challenge was already used")
            self._challenges[challenge_id] = None
            while len(self._challenges) > 256:
                self._challenges.popitem(last=False)
            with self._native_factory().open(self.key_name) as key:
                identity = self._identity(key)
                if (identity["key_bits"] != descriptor["key_bits"]
                        or not hmac.compare_digest(identity["public_key_sha256"], descriptor["public_key_sha256"])):
                    raise HardwareIntegrityError("The enrolled TPM key does not match this vault")
                public = key.public_key()
                context = challenge + json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode("ascii")
                self._proof(key, public, context)
                secret = key.decrypt(wrapped)
                if type(secret) is not bytes or not 16 <= len(secret) <= 64:
                    raise HardwareIntegrityError("TPM unwrapped an invalid vault key")
                return secret
