from __future__ import annotations

import json
import os
import struct
import time

import pytest

from angerona.core import forensic_vault as vault

TICKS = 116444736000000000 + 100 * 10_000_000


def wrap(key, _entropy):
    return b"offline-key-fixture:" + key


def unwrap(blob, _entropy):
    return blob[len(b"offline-key-fixture:"):]


def write(path, *, complete=True, **options):
    with vault.ForensicVaultWriter(path, pid=4242, birth_ticks=TICKS, deadline=time.monotonic() + 10,
                                   _protect=wrap, _unprotect=unwrap, **options) as writer:
        writer.append("memory", b"SECRET-ONLY-IN-MEMORY\n")
        writer.append("sockets", b'{"remote_ip":"192.0.2.1"}\n')
        writer.finish({"complete": complete, "not_full_memory_dump": True})


def test_ciphertext_only_and_authenticated_complete_or_partial_receipts(tmp_path):
    for complete in (True, False):
        path = tmp_path / f"{complete}.afv"
        write(path, complete=complete)
        raw = path.read_bytes()
        assert b"SECRET-ONLY-IN-MEMORY" not in raw
        assert b"192.0.2.1" not in raw
        verified = vault.read_vault(path, _unprotect=unwrap)
        assert verified["records"]["memory"] == b"SECRET-ONLY-IN-MEMORY\n"
        assert verified["receipt"]["capture"]["complete"] is complete
        assert verified["header"]["not_full_memory_dump"] is True
    assert sorted(path.suffix for path in tmp_path.iterdir()) == [".afv", ".afv"]


@pytest.mark.parametrize("attack", ["header", "bitflip", "truncated", "missing-terminal", "trailing", "reorder"])
def test_header_content_order_truncation_and_trailing_tampering_refuse(tmp_path, attack):
    path = tmp_path / "case.afv"
    write(path)
    raw = bytearray(path.read_bytes())
    offset = len(vault.MAGIC)
    length = struct.unpack_from(">I", raw, offset)[0]
    start = offset + 4 + length
    first_size = 4 + struct.unpack_from(">I", raw, start)[0]
    second = start + first_size
    second_size = 4 + struct.unpack_from(">I", raw, second)[0]
    if attack == "header":
        raw = raw.replace(b'"pid":4242', b'"pid":4342')
    elif attack == "bitflip":
        raw[start + 8] ^= 1
    elif attack == "truncated":
        raw = raw[:-2]
    elif attack == "missing-terminal":
        raw = raw[:second + second_size]
    elif attack == "trailing":
        raw += b"unexpected"
    else:
        raw[start:second + second_size] = raw[second:second + second_size] + raw[start:second]
    path.write_bytes(raw)
    with pytest.raises(vault.ForensicVaultError):
        vault.read_vault(path, _unprotect=unwrap)


def test_wrong_key_and_missing_dpapi_never_create_plaintext(tmp_path):
    path = tmp_path / "case.afv"
    with pytest.raises(vault.ForensicVaultError, match="wrapping unavailable"):
        vault.ForensicVaultWriter(path, pid=4242, birth_ticks=TICKS, deadline=time.monotonic() + 5,
                                  _protect=lambda *_a: None, _unprotect=unwrap)
    assert not path.exists()
    write(path)
    with pytest.raises(vault.ForensicVaultError):
        vault.read_vault(path, _unprotect=lambda *_a: b"z" * 32)
    assert list(tmp_path.iterdir()) == [path]


def test_keys_and_nonce_prefixes_are_fresh_per_case(tmp_path):
    headers = []
    for index in range(3):
        path = tmp_path / f"case-{index}.afv"
        write(path)
        headers.append(vault.read_vault(path, _unprotect=unwrap)["header"])
    assert len({header["wrapped_key"] for header in headers}) == 3
    assert len({header["nonce_prefix"] for header in headers}) == 3


def test_existing_original_is_preserved_and_hardlinked_reader_is_refused(tmp_path):
    path = tmp_path / "original.afv"
    write(path)
    original = path.read_bytes()
    with pytest.raises(FileExistsError):
        write(path)
    assert path.read_bytes() == original
    linked = tmp_path / "linked.afv"
    os.link(path, linked)
    with pytest.raises(vault.ForensicVaultError, match="unsafe"):
        vault.read_vault(linked, _unprotect=unwrap)
    assert path.read_bytes() == original


def test_unfinalized_stream_cannot_be_exported_as_complete(tmp_path):
    path = tmp_path / "partial.afv"
    with vault.ForensicVaultWriter(path, pid=4242, birth_ticks=TICKS, deadline=time.monotonic() + 5,
                                   _protect=wrap, _unprotect=unwrap) as writer:
        writer.append("memory", b"SECRET-ONLY-IN-MEMORY")
    with pytest.raises(vault.ForensicVaultError, match="terminal receipt"):
        vault.read_vault(path, _unprotect=unwrap)
    assert b"SECRET-ONLY-IN-MEMORY" not in path.read_bytes()


def test_plaintext_and_frame_budget_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(vault, "MAX_PLAINTEXT", 16)
    path = tmp_path / "case.afv"
    with vault.ForensicVaultWriter(path, pid=4242, birth_ticks=TICKS, deadline=time.monotonic() + 5,
                                   _protect=wrap, _unprotect=unwrap) as writer:
        with pytest.raises(vault.ForensicVaultError, match="budget"):
            writer.append("memory", b"a" * 17)
        writer.finish({"complete": False, "reason": "budget"})
    assert vault.read_vault(path, _unprotect=unwrap)["receipt"]["capture"]["complete"] is False


def test_low_space_and_expired_clock_hold_before_file_creation(tmp_path, monkeypatch):
    from types import SimpleNamespace
    path = tmp_path / "case.afv"
    monkeypatch.setattr(vault.shutil, "disk_usage", lambda _p: SimpleNamespace(free=0))
    with pytest.raises(vault.ForensicVaultError, match="free-space"):
        write(path)
    assert not path.exists()


@pytest.mark.parametrize("initial, deadline", [
    (None, 5.0), (True, 5.0), (float("nan"), 5.0), (float("inf"), 5.0), (-1.0, 5.0),
    (1.0, None), (1.0, True), (1.0, float("nan")), (1.0, float("inf")), (1.0, 1.0),
])
def test_initial_bad_clock_cannot_be_recovered_by_a_later_sample_before_open(tmp_path, monkeypatch, initial, deadline):
    samples = iter((initial, 2.0))
    monkeypatch.setattr(vault, "DirectoryPins", lambda *_a: pytest.fail("invalid initial clock must not acquire pins"))
    monkeypatch.setattr(vault, "_protected_key", lambda *_a: pytest.fail("invalid initial clock must not wrap keys"))
    path = tmp_path / "invalid-clock.afv"
    with pytest.raises(vault.ForensicVaultError, match="clock or deadline"):
        vault.ForensicVaultWriter(path, pid=4242, birth_ticks=TICKS, deadline=deadline,
                                  _clock=lambda: next(samples))
    assert not path.exists()


def test_writer_expiry_and_clock_regression_never_write_late_plaintext(tmp_path):
    clock = [1.0]
    path = tmp_path / "clock.afv"
    with vault.ForensicVaultWriter(path, pid=4242, birth_ticks=TICKS, deadline=5.0,
                                   _protect=wrap, _unprotect=unwrap, _clock=lambda: clock[0]) as writer:
        initial = path.read_bytes()
        clock[0] = 0.5
        with pytest.raises(vault.ForensicVaultError, match="clock regressed"):
            writer.append("memory", b"SECRET-ONLY-IN-MEMORY")
        assert path.read_bytes() == initial
        clock[0] = 6.0
        # The earlier failed frame attempt consumed its nonce even though the
        # write guard rejected it. Later terminal encryption must stay held.
        with pytest.raises(vault.ForensicVaultError, match="poisoned"):
            writer.finish({"complete": False})
    assert b"SECRET-ONLY-IN-MEMORY" not in path.read_bytes()


def test_directory_native_pin_prevents_rename_until_retirement(tmp_path):
    if os.name != "nt":
        pytest.skip("Windows deny-delete directory handle semantics")
    original, renamed = tmp_path / "pinned", tmp_path / "renamed"
    original.mkdir()
    with vault.DirectoryPins(original) as pins:
        pins.check()
        with pytest.raises(OSError):
            original.rename(renamed)
    original.rename(renamed)
    assert renamed.is_dir()


def test_export_requires_explicit_choice_new_target_and_full_authentication(tmp_path, monkeypatch):
    from angerona.modules import hardware_crypto
    monkeypatch.setattr(hardware_crypto, "unprotect", unwrap)
    path = tmp_path / "case.afv"
    write(path, complete=False)
    destination = tmp_path / "operator-export"
    with pytest.raises(vault.ForensicVaultError, match="explicit confirmation"):
        vault.export_vault(path, destination)
    assert not destination.exists()
    result = vault.export_vault(path, destination, operator_confirmed=True)
    assert result["exported"] and not result["complete_capture"]
    assert (destination / "memory-strings.txt").read_bytes() == b"SECRET-ONLY-IN-MEMORY\n"
    assert json.loads((destination / "capture-receipt.json").read_bytes())["capture"]["complete"] is False
    with pytest.raises(FileExistsError):
        vault.export_vault(path, destination, operator_confirmed=True)
    bad = tmp_path / "bad.afv"
    bad.write_bytes(path.read_bytes()[:-1])
    with pytest.raises(vault.ForensicVaultError):
        vault.export_vault(bad, tmp_path / "must-not-exist", operator_confirmed=True)
    assert not (tmp_path / "must-not-exist").exists()


def test_current_user_dpapi_roundtrip_uses_only_our_inert_data(tmp_path):
    if os.name != "nt":
        pytest.skip("current-user DPAPI requires Windows")
    path = tmp_path / "native-dpapi.afv"
    with vault.ForensicVaultWriter(path, pid=4242, birth_ticks=TICKS, deadline=time.monotonic() + 10) as writer:
        writer.append("memory", b"native-dpapi-inert-fixture")
        writer.finish({"complete": False, "fixture": True})
    assert vault.read_vault(path)["records"]["memory"] == b"native-dpapi-inert-fixture"


def test_directory_close_failure_preserves_owner_and_never_retries_alias(monkeypatch):
    monkeypatch.setattr(vault, "_RETIREMENT_HOLDS", {})
    calls = []
    class Kernel:
        @staticmethod
        def CloseHandle(handle):
            calls.append(handle)
            return handle != 101
    pins = vault.DirectoryPins.__new__(vault.DirectoryPins)
    pins._kernel, pins._held = Kernel(), [101, 102]
    pins._close_failed, pins._ambiguous_handles = False, ()
    with pytest.raises(vault.ForensicVaultError, match="retirement unavailable"):
        pins.close()
    assert calls == [102, 101]
    assert pins._ambiguous_handles == (101,)
    assert vault.retirement_snapshot()["resource_kinds"] == ("directory",)
    with pytest.raises(vault.ForensicVaultError, match="remains unverified"):
        pins.close()
    assert calls == [102, 101]


def test_artifact_close_uncertainty_retains_stream_and_clears_key_references(monkeypatch):
    monkeypatch.setattr(vault, "_RETIREMENT_HOLDS", {})
    calls = []
    class Stream:
        def close(self):
            calls.append("close")
            raise OSError("fixture stream uncertainty")
    writer = vault.ForensicVaultWriter.__new__(vault.ForensicVaultWriter)
    writer._file, writer._pins = Stream(), None
    writer._close_attempted, writer._ambiguous_stream = False, None
    writer._key, writer._cipher = b"fixture", object()
    with pytest.raises(vault.ForensicVaultError, match="retirement unavailable"):
        writer.close()
    assert writer._ambiguous_stream is not None
    assert writer._key == b"" and writer._cipher is None
    assert vault.retirement_snapshot()["resource_kinds"] == ("artifact",)
    with pytest.raises(vault.ForensicVaultError, match="remains unverified"):
        writer.close()
    assert calls == ["close"]


def test_sensitive_export_short_write_is_not_reported_as_success(tmp_path, monkeypatch):
    from angerona.modules import hardware_crypto
    monkeypatch.setattr(hardware_crypto, "unprotect", unwrap)
    path = tmp_path / "case.afv"
    write(path)
    original = vault.os.fdopen
    class ShortWriter:
        def __init__(self, stream):
            self.stream = stream
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return self.stream.__exit__(*args)
        def write(self, data):
            return self.stream.write(data[:-1])
    def fdopen(descriptor, mode, *args, **kwargs):
        stream = original(descriptor, mode, *args, **kwargs)
        return ShortWriter(stream) if mode == "wb" else stream
    monkeypatch.setattr(vault.os, "fdopen", fdopen)
    destination = tmp_path / "explicit-export"
    with pytest.raises(vault.ForensicVaultError, match="write was incomplete"):
        vault.export_vault(path, destination, operator_confirmed=True)
    assert (destination / "memory-strings.txt").exists()  # explicit partial evidence is preserved
    assert not (destination / "capture-receipt.json").exists()
