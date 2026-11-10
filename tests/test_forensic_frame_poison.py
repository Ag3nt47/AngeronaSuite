"""Failed frame attempts cannot reuse an AEAD nonce for a later receipt."""
from __future__ import annotations

import time

import pytest

from angerona.core import forensic_vault as vault


TICKS = 116444736000000000 + 100 * 10_000_000


@pytest.mark.parametrize("failure", ["short-write", "write-error", "encrypt-error"])
def test_failed_frame_poison_refuses_later_append_and_terminal_before_any_encryption(tmp_path, failure):
    path = tmp_path / "partial.afv"
    wrap = lambda key, _entropy: b"inert-wrap:" + key
    unwrap = lambda blob, _entropy: blob[len(b"inert-wrap:"):]
    calls = []
    with vault.ForensicVaultWriter(path, pid=4242, birth_ticks=TICKS, deadline=time.monotonic() + 10,
                                   _protect=wrap, _unprotect=unwrap) as writer:
        cipher = writer._cipher
        class CipherSpy:
            def encrypt(self, nonce, plaintext, aad):
                calls.append((nonce, plaintext))
                if failure == "encrypt-error":
                    raise ValueError("inert provider error")
                return cipher.encrypt(nonce, plaintext, aad)
        writer._cipher = CipherSpy()
        stream = writer._file
        class FailedWrite:
            def __getattr__(self, name):
                return getattr(stream, name)
            def write(self, raw):
                # Preserve actual partial ciphertext; no original is deleted.
                written = stream.write(raw[:11])
                if failure == "write-error":
                    raise OSError("inert partial write failure")
                return written
        if failure != "encrypt-error":
            writer._file = FailedWrite()
        with pytest.raises((vault.ForensicVaultError, OSError, ValueError)):
            writer.append("memory", b"inert partial captured fixture")
        partial = path.read_bytes()
        assert writer._poisoned is True and writer._count == 0
        assert len(calls) == 1
        for later in (lambda: writer.append("memory", b"different retry plaintext"),
                      lambda: writer.append("memory", b""),
                      lambda: writer.finish({"complete": False}),
                      lambda: writer.finish({"complete": True})):
            with pytest.raises(vault.ForensicVaultError, match="poisoned"):
                later()
        assert len(calls) == 1 and path.read_bytes() == partial
        assert writer._finished is False
    assert path.read_bytes() == partial
    with pytest.raises(vault.ForensicVaultError):
        vault.read_vault(path, _unprotect=unwrap)


def test_successful_frames_advance_distinct_nonces_and_terminal_remains_authenticated(tmp_path):
    path = tmp_path / "complete.afv"
    wrap = lambda key, _entropy: b"inert-wrap:" + key
    unwrap = lambda blob, _entropy: blob[len(b"inert-wrap:"):]
    calls = []
    with vault.ForensicVaultWriter(path, pid=4242, birth_ticks=TICKS, deadline=time.monotonic() + 10,
                                   _protect=wrap, _unprotect=unwrap) as writer:
        cipher = writer._cipher
        class CipherSpy:
            def encrypt(self, nonce, plaintext, aad):
                calls.append(nonce)
                return cipher.encrypt(nonce, plaintext, aad)
        writer._cipher = CipherSpy()
        writer.append("memory", b"inert first")
        writer.append("sockets", b"inert second")
        writer.finish({"complete": True})
        assert writer._poisoned is False and writer._finished is True
    assert len(calls) == len(set(calls)) == 3
    assert vault.read_vault(path, _unprotect=unwrap)["receipt"]["capture"]["complete"] is True
