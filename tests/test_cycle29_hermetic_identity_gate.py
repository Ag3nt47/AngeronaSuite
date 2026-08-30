from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from angerona.core import executable_trust, windows_package_identity
from angerona.modules import hermetic_packager


def test_frozen_health_uses_os_image_and_exact_package_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    current = tmp_path / "Angerona.exe"
    current.write_bytes(b"current image")
    unrelated = tmp_path / "angerona.exe"
    unrelated.write_bytes(b"unrelated substitute")
    monkeypatch.setattr(hermetic_packager, "_is_frozen", lambda: True)
    monkeypatch.setattr(hermetic_packager, "_current_process_image", lambda: current)
    monkeypatch.setattr(hermetic_packager, "_find_binary", lambda: unrelated)
    monkeypatch.setattr(hermetic_packager, "_image_path_protected", lambda _path: True)
    monkeypatch.setattr(
        hermetic_packager,
        "_check_signature",
        lambda _path: (True, "Valid", "CN=Angerona Release", "A1B2"),
    )
    monkeypatch.setattr(
        windows_package_identity,
        "verify_current_msix_authority",
        lambda: windows_package_identity.PackageAuthority(False, "pin unavailable"),
    )

    module = hermetic_packager.HermeticPackagerModule()
    pct, note = module._assess()
    assert pct == 75
    assert module._binary == current
    assert "package=pin unavailable" in note

    monkeypatch.setattr(
        windows_package_identity,
        "verify_current_msix_authority",
        lambda: windows_package_identity.PackageAuthority(True, "exact package"),
    )
    pct, note = module._assess()
    assert pct == 100
    assert "exact MSIX authority" in note


def test_frozen_metadata_cannot_hide_unprotected_current_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    current = tmp_path / "Angerona.exe"
    current.write_bytes(b"current image")
    monkeypatch.setattr(hermetic_packager, "_is_frozen", lambda: True)
    monkeypatch.setattr(hermetic_packager, "_current_process_image", lambda: current)
    monkeypatch.setattr(hermetic_packager, "_image_path_protected", lambda _path: False)
    monkeypatch.setattr(
        hermetic_packager,
        "_check_signature",
        lambda _path: (True, "Valid", "CN=Some Signer", "BAD"),
    )
    monkeypatch.setattr(
        windows_package_identity,
        "verify_current_msix_authority",
        lambda: windows_package_identity.PackageAuthority(True, "exact package"),
    )

    pct, note = hermetic_packager.HermeticPackagerModule()._assess()
    assert pct == 40
    assert "lacks protected image custody" in note


def test_build_launch_requires_exact_reviewed_digest_and_retains_custody(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = tmp_path / "build-hermetic.bat"
    script.write_bytes(b"@echo off\r\necho reviewed\r\n")
    system = tmp_path / "Windows" / "System32"
    system.mkdir(parents=True)
    command = system / "cmd.exe"
    command.write_bytes(b"trusted command fixture")
    monkeypatch.setattr(hermetic_packager, "_BUILD_BAT", script)
    monkeypatch.setattr(executable_trust, "_protected_path", lambda _path: True)
    monkeypatch.setattr(
        "angerona.core.privilege.trusted_windows_directories",
        lambda: (system.parent, system),
    )
    monkeypatch.setattr(
        "angerona.core.privilege.sanitized_child_environment",
        lambda **_kwargs: {"SystemRoot": str(system.parent), "PYTHONNOUSERSITE": "1"},
    )

    launches: list[tuple[list[str], dict]] = []

    class Process:
        pid = 9127

        def __init__(self):
            self.running = True

        def poll(self):
            return None if self.running else 0

        def terminate(self):
            self.running = False

        def wait(self, timeout=None):
            self.running = False
            return 0

        def kill(self):
            self.running = False

    def fake_popen(argv, **kwargs):
        launches.append((argv, kwargs))
        return Process()

    monkeypatch.setattr(hermetic_packager.subprocess, "Popen", fake_popen)
    module = hermetic_packager.HermeticPackagerModule()
    review = module.build_review()
    digest = hashlib.sha256(script.read_bytes()).hexdigest()
    assert review == {
        "ready": True,
        "path": str(script.resolve()),
        "sha256": digest,
        "size": script.stat().st_size,
    }

    assert not module.trigger_build()
    assert not module.trigger_build(approved=True, expected_sha256="0" * 64)
    assert launches == []

    assert module.trigger_build(approved=True, expected_sha256=digest)
    assert len(launches) == 1
    argv, kwargs = launches[0]
    assert argv[:4] == [str(command.resolve()), "/d", "/q", "/k"]
    assert argv[4] == str(script.resolve())
    assert kwargs["close_fds"] is True
    assert kwargs["env"] == {
        "SystemRoot": str(system.parent),
        "PYTHONNOUSERSITE": "1",
    }
    assert len(module._build_jobs) == 1
    assert not module._build_jobs[0][1].closed

    module._reap_build_jobs(stop=True)
    assert module._build_jobs == []
    script.write_bytes(b"@echo safely writable after custody closes\r\n")
