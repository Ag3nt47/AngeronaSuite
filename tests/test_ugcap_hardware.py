"""Offline CNG contract tests. No native DLL or real TPM is opened/provisioned."""
from __future__ import annotations

import base64
import ctypes
import json
import secrets
import struct

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

from angerona.core import ugcap_hardware as hardware


@pytest.fixture(scope="module")
def private_keys():
    return [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(2)]


class Function:
    def __init__(self, callback):
        self.callback = callback
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self.callback(*args)


def _put(pointer, value, ctype=hardware._UINT32):
    ctypes.cast(pointer, ctypes.POINTER(ctype)).contents.value = value


def _write_output(data, output, capacity, used):
    _put(used, len(data))
    if output is None:
        return 0
    if capacity < len(data):
        return hardware._BUFFER_TOO_SMALL
    ctypes.memmove(output, data, len(data))
    return 0


class MockCNG:
    """ctypes-shaped Microsoft API fake backed by test-only software RSA."""

    def __init__(self, private, *, enrolled=True):
        self.private = private
        self.enrolled = enrolled
        self.hardware_flags = 1
        self.export_policy = 0
        self.key_type = 0
        self.usage = 3
        self.create_flags = []
        self.open_flags = []
        self.properties = []
        self.freed = []
        self.deleted = []
        self.sign_digests = []
        self.decrypt_calls = 0
        self.bad_signature = False
        self.bad_secret = False
        self.policy_failure = False
        self.version = 2
        self.tbs_error = 0
        for name, callback in {
            "NCryptOpenStorageProvider": self.open_provider,
            "NCryptOpenKey": self.open_key,
            "NCryptCreatePersistedKey": self.create,
            "NCryptSetProperty": self.set_property,
            "NCryptGetProperty": self.get_property,
            "NCryptFinalizeKey": lambda *_args: 0,
            "NCryptExportKey": self.export,
            "NCryptSignHash": self.sign,
            "NCryptDecrypt": self.decrypt,
            "NCryptFreeObject": self.free,
            "NCryptDeleteKey": self.delete,
            "Tbsi_GetDeviceInfo": self.tpm_info,
        }.items():
            setattr(self, name, Function(callback))

    def loader(self, name, **kwargs):
        assert name in {"ncrypt.dll", "tbs.dll"}
        assert kwargs == {"winmode": 0x800}
        return self

    def open_provider(self, output, name, flags):
        assert name == hardware.PROVIDER and flags == 0
        _put(output, 101, hardware._HANDLE)
        return 0

    def open_key(self, _provider, output, _name, spec, flags):
        self.open_flags.append(flags)
        assert spec == 0 and flags == hardware._SILENT
        if not self.enrolled:
            return 0x80090016
        _put(output, 202, hardware._HANDLE)
        return 0

    def create(self, _provider, output, algorithm, name, spec, flags):
        assert algorithm == "RSA" and name.startswith("Angerona.UGCAP.") and spec == 0
        self.create_flags.append(flags)
        if self.enrolled:
            _put(output, 202, hardware._HANDLE)  # Failure grants no ownership.
            return 0x8009000F
        self.enrolled = True
        _put(output, 202, hardware._HANDLE)
        return 0

    def set_property(self, _key, name, value, size, flags):
        assert size == 4 and flags == 0
        self.properties.append((name, ctypes.cast(value, ctypes.POINTER(hardware._UINT32)).contents.value))
        return 0x80090029 if self.policy_failure else 0

    def get_property(self, _handle, name, output, capacity, used, flags):
        assert flags == 0
        values = {"Impl Type": self.hardware_flags, "Length": 2048,
                  "Key Type": self.key_type, "Export Policy": self.export_policy,
                  "Key Usage": self.usage}
        return _write_output(struct.pack("<I", values[name]), output, capacity, used)

    def export(self, _key, export_key, kind, parameters, output, capacity, used, flags):
        assert export_key == 0 and kind == "RSAPUBLICBLOB" and parameters is None
        assert flags == hardware._SILENT
        numbers = self.private.public_key().public_numbers()
        exponent = numbers.e.to_bytes(3, "big")
        modulus = numbers.n.to_bytes(256, "big")
        blob = struct.pack("<6I", 0x31415352, 2048, len(exponent), len(modulus), 0, 0) + exponent + modulus
        return _write_output(blob, output, capacity, used)

    def sign(self, _key, info, digest, size, output, capacity, used, flags):
        parsed = ctypes.cast(info, ctypes.POINTER(hardware._PKCS1Info)).contents
        assert parsed.pszAlgId == "SHA256"
        assert flags == hardware._SILENT | hardware._PAD_PKCS1
        value = ctypes.string_at(digest, size)
        if output is not None:
            self.sign_digests.append(value)
        result = (b"x" * 256 if self.bad_signature else self.private.sign(
            value, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())))
        return _write_output(result, output, capacity, used)

    def decrypt(self, _key, wrapped, size, info, output, capacity, used, flags):
        parsed = ctypes.cast(info, ctypes.POINTER(hardware._OAEPInfo)).contents
        assert parsed.pszAlgId == "SHA256"
        assert ctypes.string_at(parsed.pbLabel, parsed.cbLabel) == hardware._WRAP_LABEL
        assert flags == hardware._SILENT | hardware._PAD_OAEP
        try:
            result = self.private.decrypt(ctypes.string_at(wrapped, size), padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=hardware._WRAP_LABEL))
        except ValueError:
            return 0x80090005
        if self.bad_secret:
            result = b"short"
        if output is not None:
            self.decrypt_calls += 1
        return _write_output(result, output, capacity, used)

    def free(self, value):
        self.freed.append(value)
        return 0

    def delete(self, value, flags):
        assert flags == hardware._SILENT
        self.deleted.append(value)
        self.enrolled = False
        return 0

    def tpm_info(self, size, pointer):
        assert size == 16
        info = ctypes.cast(pointer, ctypes.POINTER(hardware._TPMDeviceInfo)).contents
        assert info.structVersion == 2
        info.tpmVersion = self.version
        return self.tbs_error


@pytest.fixture
def setup_native(private_keys, monkeypatch):
    monkeypatch.setattr(hardware.sys, "platform", "win32")
    mock = MockCNG(private_keys[0])
    factory = lambda: hardware._WindowsCNG(loader=mock.loader)
    return hardware.WindowsTPMHardware(native_factory=factory), mock


def test_nonwindows_backend_has_no_fallback_or_creation(monkeypatch):
    monkeypatch.setattr(hardware.sys, "platform", "linux")
    instance = hardware.WindowsTPMHardware()
    assert instance.status()["available"] is False
    for operation in (instance.identity, instance.provision,
                      lambda: instance.seal(b"s" * 32)):
        with pytest.raises(hardware.HardwareUnavailable, match="unavailable on this platform"):
            operation()


def test_identity_is_hardware_key_continuity_without_attestation_claim(setup_native):
    instance, mock = setup_native
    result = instance.identity()
    assert result["provider"] == hardware.PROVIDER
    assert result["hardware_backed"] is True and result["nonexportable"] is True
    assert result["tpm_version"] == "2.0" and result["scope"] == "current-user"
    assert result["physical_attestation"] is False
    assert len(result["public_key_sha256"]) == 64
    assert mock.create_flags == [] and mock.deleted == []
    assert mock.freed == [202, 101]


def test_missing_key_never_provisions_during_probe_identity_or_seal(setup_native):
    instance, mock = setup_native
    mock.enrolled = False
    assert instance.available() is True
    assert instance.status()["enrolled"] is False
    for operation in (instance.identity, lambda: instance.seal(b"s" * 32)):
        with pytest.raises(hardware.HardwareUnavailable):
            operation()
    assert mock.create_flags == [] and mock.deleted == []


def test_explicit_provision_creates_nonexportable_user_key_and_selfchecks(setup_native):
    instance, mock = setup_native
    mock.enrolled = False
    result = instance.provision()
    assert result["hardware_backed"] is True
    assert mock.create_flags == [0]
    assert mock.properties == [("Length", 2048), ("Key Usage", 3), ("Export Policy", 0)]
    assert len(mock.sign_digests) == 1 and mock.decrypt_calls == 1
    assert mock.deleted == [] and mock.enrolled


def test_provision_collision_never_overwrites_or_deletes_existing_key(setup_native):
    instance, mock = setup_native
    with pytest.raises(hardware.HardwareUnavailable):
        instance.provision()
    assert mock.create_flags == [0] and mock.deleted == [] and mock.enrolled


@pytest.mark.parametrize("failure", ["bad_signature", "policy_failure"])
def test_failed_new_enrollment_removes_only_its_new_key(setup_native, failure):
    instance, mock = setup_native
    mock.enrolled = False
    setattr(mock, failure, True)
    with pytest.raises(hardware.HardwareBindingError):
        instance.provision()
    assert mock.deleted == [202] and not mock.enrolled
    assert 202 not in mock.freed  # NCryptDeleteKey already frees its handle.


def test_seal_unseal_requires_pinned_key_fresh_proof_and_native_unwrap(setup_native):
    instance, mock = setup_native
    secret = secrets.token_bytes(32)
    descriptor = instance.seal(secret)
    encoded = json.dumps(descriptor)
    assert set(descriptor) == hardware._SCHEMA
    assert secret.hex() not in encoded and base64.b64encode(secret).decode() not in encoded
    assert mock.sign_digests == [] and mock.decrypt_calls == 0
    assert instance.unseal(descriptor, secrets.token_bytes(32)) == secret
    assert len(mock.sign_digests) == 1 and mock.decrypt_calls == 1
    assert mock.create_flags == []


def test_challenge_replay_rejected_and_distinct_challenges_have_distinct_proofs(setup_native):
    instance, mock = setup_native
    descriptor = instance.seal(b"k" * 32)
    challenge = secrets.token_bytes(32)
    assert instance.unseal(descriptor, challenge) == b"k" * 32
    with pytest.raises(hardware.HardwareIntegrityError, match="already used"):
        instance.unseal(descriptor, challenge)
    assert instance.unseal(descriptor, secrets.token_bytes(32)) == b"k" * 32
    assert len(set(mock.sign_digests)) == 2 and mock.decrypt_calls == 2


def test_replaced_or_cloned_key_rejected_before_private_operation(setup_native, private_keys):
    instance, mock = setup_native
    descriptor = instance.seal(b"k" * 32)
    mock.private = private_keys[1]
    with pytest.raises(hardware.HardwareIntegrityError, match="does not match"):
        instance.unseal(descriptor, secrets.token_bytes(32))
    assert not mock.sign_digests and mock.decrypt_calls == 0 and mock.create_flags == []


def test_clone_without_original_tpm_key_fails_without_reenrollment(setup_native):
    instance, mock = setup_native
    descriptor = instance.seal(b"k" * 32)
    mock.enrolled = False
    with pytest.raises(hardware.HardwareUnavailable):
        instance.unseal(descriptor, secrets.token_bytes(32))
    assert mock.create_flags == []


def test_failed_private_key_possession_proof_never_unwraps(setup_native):
    instance, mock = setup_native
    descriptor = instance.seal(b"k" * 32)
    mock.bad_signature = True
    with pytest.raises(hardware.HardwareIntegrityError, match="proof did not verify"):
        instance.unseal(descriptor, secrets.token_bytes(32))
    assert mock.decrypt_calls == 0 and mock.deleted == []


@pytest.mark.parametrize("change", [
    {"version": True}, {"version": 2}, {"provider": "Microsoft Software Key Storage Provider"},
    {"key_name": "Angerona.UGCAP.other"}, {"public_key_sha256": "0" * 63},
    {"wrapped_secret": "%%%"}, {"key_bits": 4096}, {"algorithm": "RSA-PKCS1"},
    {"extra": "injected"},
])
def test_malformed_descriptor_rejected_before_native_open(setup_native, change):
    instance, mock = setup_native
    descriptor = {**instance.seal(b"k" * 32), **change}
    opened = len(mock.open_flags)
    with pytest.raises(hardware.HardwareIntegrityError):
        instance.unseal(descriptor, secrets.token_bytes(32))
    assert len(mock.open_flags) == opened and mock.decrypt_calls == 0


@pytest.mark.parametrize("flags", [0, 2, 3, 0x20])
def test_software_or_unproven_provider_is_rejected(setup_native, flags):
    instance, mock = setup_native
    mock.hardware_flags = flags
    assert not instance.available()
    with pytest.raises(hardware.HardwareUnavailable, match="not exclusively hardware"):
        instance.identity()
    assert mock.open_flags == [] and mock.create_flags == []


@pytest.mark.parametrize("field,value", [("export_policy", 1), ("key_type", 0x20), ("usage", 1)])
def test_exportable_machine_or_decryptonly_key_rejected(setup_native, field, value):
    instance, mock = setup_native
    setattr(mock, field, value)
    with pytest.raises(hardware.HardwareIntegrityError, match="key policy"):
        instance.identity()
    assert mock.create_flags == [] and mock.deleted == []


def test_no_tpm_or_tpm12_is_rejected(setup_native):
    instance, mock = setup_native
    mock.tbs_error = 0x8028400F
    assert not instance.available()
    mock.tbs_error, mock.version = 0, 1
    assert not instance.available()
    assert mock.open_flags == []


def test_unavailable_version_is_reported_without_claiming_tpm20(setup_native):
    instance, mock = setup_native
    mock.tbs_error = 0x80284002
    assert instance.identity()["tpm_version"] == "unavailable"


def test_modified_ciphertext_and_bad_unwrapped_length_fail_closed(setup_native):
    instance, mock = setup_native
    descriptor = instance.seal(b"k" * 32)
    ciphertext = bytearray(base64.b64decode(descriptor["wrapped_secret"]))
    ciphertext[0] ^= 1
    descriptor["wrapped_secret"] = base64.b64encode(ciphertext).decode()
    with pytest.raises(hardware.HardwareBindingError):
        instance.unseal(descriptor, secrets.token_bytes(32))
    valid = instance.seal(b"k" * 32)
    mock.bad_secret = True
    with pytest.raises(hardware.HardwareIntegrityError, match="invalid vault key"):
        instance.unseal(valid, secrets.token_bytes(32))


def test_native_output_limits_and_public_blob_validation():
    def oversized(_output, _size, used):
        _put(used, 2**30)
        return 0
    with pytest.raises(hardware.HardwareIntegrityError, match="output length"):
        hardware._output(oversized)
    with pytest.raises(hardware.HardwareIntegrityError, match="blob is invalid"):
        hardware._public_from_blob(struct.pack("<6I", 0x32415352, 2048, 3, 256, 128, 128))


@pytest.mark.parametrize("name", ["", "generic", "Angerona.UGCAP...", "Angerona.UGCAP.x\x00y"])
def test_key_names_are_bounded_and_namespaced(name):
    with pytest.raises(ValueError, match="key name is invalid"):
        hardware.WindowsTPMHardware(name)
