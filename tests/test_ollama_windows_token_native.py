"""Native Windows token regressions; no process, daemon, UAC or privilege changes.

Only the test process's own token is duplicated. The identity checks also work
on elevated Windows CI runners, without changing the authority of any process.
These checks do not replace elevated-to-medium process-creation acceptance.
"""
from __future__ import annotations

import ctypes
import os
from contextlib import ExitStack
from dataclasses import replace

import pytest

from angerona.core import ollama_windows_token as token_launch


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Actual Windows token APIs required")


@pytest.mark.parametrize("source_level", [1, 2], ids=["identification_rejected", "impersonation_converted"])
def test_native_own_token_conversion_preserves_authority(source_level, monkeypatch):
    from ctypes import wintypes

    # Missing dependencies may skip; API/access failures must remain failures.
    pytest.importorskip("win32api", exc_type=ImportError)
    pytest.importorskip("win32process", exc_type=ImportError)
    pytest.importorskip("win32security", exc_type=ImportError)
    native = token_launch._Native()

    def no_process(*_args, **_kwargs):
        pytest.fail("Token-only regression attempted process creation or resume")

    monkeypatch.setattr(native, "create_suspended", no_process)
    monkeypatch.setattr(native, "resume", no_process)
    duplicate = ctypes.WinDLL("advapi32", use_last_error=True).DuplicateTokenEx
    duplicate.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID,
                          ctypes.c_int, ctypes.c_int, ctypes.POINTER(wintypes.HANDLE)]
    duplicate.restype = wintypes.BOOL

    with ExitStack() as handles:
        current = native.security.OpenProcessToken(native.api.GetCurrentProcess(), 0xA)
        handles.callback(native.close, current)
        original = native.identity(current)
        assert original.token_type == 1
        source_handle = wintypes.HANDLE()
        # QUERY | DUPLICATE only; a non-inheritable impersonation token copied
        # from this process, with the test's explicit impersonation level.
        if not duplicate(int(current), 0xA, None, source_level, 2, ctypes.byref(source_handle)):
            raise OSError(ctypes.get_last_error(), "Native test token duplication failed")
        source = int(source_handle.value)
        handles.callback(native.close, source)
        assert native.identity(source) == replace(original, token_type=2)
        assert native.security.GetTokenInformation(
            source, native.security.TokenImpersonationLevel,
        ) == source_level

        if source_level == 1:
            with pytest.raises(OSError) as failure:
                unexpected = native.primary_token(source)
                # Close an unexpected success before the test assertion fails.
                handles.callback(native.close, unexpected)
            assert failure.value.errno == 1346  # ERROR_BAD_IMPERSONATION_LEVEL
        else:
            primary = native.primary_token(source)
            handles.callback(native.close, primary)
            assert native.identity(primary) == original
