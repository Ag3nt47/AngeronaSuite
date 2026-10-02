"""Real Windows sharing locks at authenticated and proposal persistence boundaries."""
from __future__ import annotations

import os

import pytest

from angerona.core import cve_fix_advisor, device_security_lab, temporal_tradecraft
from angerona.core.atomic_io import replace_with_retry


@pytest.mark.skipif(os.name != "nt", reason="Native Windows deny-delete reader")
@pytest.mark.parametrize("component", ["device", "temporal", "cve"])
@pytest.mark.parametrize("release", [True, False])
def test_state_writer_handles_native_sharing_lock(tmp_path, monkeypatch, component, release):
    import ctypes
    from ctypes import wintypes

    if component == "device":
        module = device_security_lab
        authority = b"disposable-device-state-test" * 2
        lab = module.DeviceSecurityLab(tmp_path, authority=authority, clock=lambda: 1000)
        first, _ = lab.create_enrollment("First device", True, evidence_source="local")
        lab.confirm_local_enrollment(first.enrollment_id, owner_attested=True)
        pending, _ = lab.create_enrollment("Second device", True, evidence_source="local")
        path = lab._state_path

        def save():
            return lab.confirm_local_enrollment(pending.enrollment_id, owner_attested=True)

        def verify():
            restored = module.DeviceSecurityLab(tmp_path, authority=authority, clock=lambda: 1000)
            assert {r.enrollment_id for r in restored.list_enrollments()} == {
                first.enrollment_id, pending.enrollment_id,
            }

    elif component == "temporal":
        module = temporal_tradecraft
        state_key, privacy_key = module.derive_temporal_keys(b"T" * 32)
        path = tmp_path / "temporal.json"
        engine = module.TemporalTradecraftEngine(
            path, state_key=state_key, privacy_key=privacy_key, clock=lambda: 1000,
        )
        engine.mark_missing("initial-gap")

        def save():
            return engine.mark_missing("second-gap")

        def verify():
            restored = module.TemporalTradecraftEngine(
                path, state_key=state_key, privacy_key=privacy_key, clock=lambda: 1000,
            )
            assert restored.persistence_status == "authenticated"
            assert engine.persistence_status == "authenticated"

    else:
        module = cve_fix_advisor
        monkeypatch.setattr(module, "_repo_root", lambda: tmp_path)
        module._save_applied({"old": {"status": "review"}})
        path = module._applied_path()

        def save():
            module._save_applied({"old": {"status": "review"}, "new": {"status": "review"}})

        def verify():
            assert set(module._load_applied()) == {"old", "new"}

    before = path.read_bytes()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    )
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.CreateFileW(str(path), 0x80000000, 3, None, 3, 0, None)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    observed = []

    def attempt(source, destination):
        nonlocal handle
        try:
            os.replace(source, destination)
        except PermissionError as exc:
            observed.append(exc.winerror)
            assert exc.winerror in {5, 32, 33}
            if release and handle is not None:
                assert kernel.CloseHandle(handle)
                handle = None
            raise

    monkeypatch.setattr(module, "replace_with_retry", lambda src, dst: replace_with_retry(
        src, dst, replace=attempt,
    ))
    try:
        if release:
            save()
            assert observed
            assert path.read_bytes() != before
            verify()
        else:
            if component == "temporal":
                result = save()
                assert result.state == "blind" and result.persistence_status == "unavailable"
            else:
                with pytest.raises(PermissionError):
                    save()
            assert len(observed) == 7
            assert path.read_bytes() == before
        assert not list(path.parent.glob(f".{path.name}*.tmp*"))
    finally:
        if handle is not None:
            kernel.CloseHandle(handle)
