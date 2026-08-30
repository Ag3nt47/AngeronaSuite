from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from angerona.core import executable_trust
from angerona.modules import frz_heartbeat


def _acquire_fixture(monkeypatch: pytest.MonkeyPatch, path: Path):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(executable_trust, "_protected_path", lambda _path: True)
    monkeypatch.setattr(
        executable_trust,
        "_authenticode_identity",
        lambda _path: ("Valid", "CN=Angerona Release", "A1B2"),
    )
    return executable_trust.acquire_pinned_executable(
        path,
        expected_sha256=digest,
        expected_publisher="CN=Angerona Release",
    )


def test_native_trust_requires_both_independent_pins(tmp_path: Path) -> None:
    candidate = tmp_path / "frz_watchdog_v2.exe"
    candidate.write_bytes(b"reviewed watchdog")

    with pytest.raises(executable_trust.ExecutableTrustError, match="SHA-256 pin"):
        executable_trust.acquire_pinned_executable(
            candidate, expected_sha256="", expected_publisher="CN=Angerona"
        )
    with pytest.raises(executable_trust.ExecutableTrustError, match="publisher pin"):
        executable_trust.acquire_pinned_executable(
            candidate,
            expected_sha256=hashlib.sha256(candidate.read_bytes()).hexdigest(),
            expected_publisher="",
        )
    assert not executable_trust.executable_is_trusted(candidate)


def test_native_trust_binds_digest_publisher_and_held_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = tmp_path / "frz_watchdog_v2.exe"
    candidate.write_bytes(b"reviewed watchdog")

    receipt = _acquire_fixture(monkeypatch, candidate)
    try:
        assert receipt.path == candidate.resolve()
        assert receipt.sha256 == hashlib.sha256(b"reviewed watchdog").hexdigest()
        assert receipt.publisher == "CN=Angerona Release"
        assert receipt.still_valid(rehash=True)
    finally:
        receipt.close()

    candidate.write_bytes(b"substitute")
    with pytest.raises(executable_trust.ExecutableTrustError, match="does not match"):
        executable_trust.acquire_pinned_executable(
            candidate,
            expected_sha256=hashlib.sha256(b"reviewed watchdog").hexdigest(),
            expected_publisher="CN=Angerona Release",
        )


def test_wrong_authenticode_publisher_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = tmp_path / "frz_watchdog_v2.exe"
    candidate.write_bytes(b"reviewed watchdog")
    digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
    monkeypatch.setattr(executable_trust, "_protected_path", lambda _path: True)
    monkeypatch.setattr(
        executable_trust,
        "_authenticode_identity",
        lambda _path: ("Valid", "CN=Unrelated Vendor", "BAD"),
    )

    with pytest.raises(executable_trust.ExecutableTrustError, match="publisher"):
        executable_trust.acquire_pinned_executable(
            candidate,
            expected_sha256=digest,
            expected_publisher="CN=Angerona Release",
        )


def test_frz_launch_retains_custody_and_uses_minimal_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = tmp_path / "frz_watchdog_v2.exe"
    candidate.write_bytes(b"stub")

    class Custody:
        path = candidate
        sha256 = "a" * 64
        publisher = "CN=Angerona Release"
        thumbprint = "A1B2"
        object_identity = (1, 2, 4, 5, 1)
        closed = False

        def still_valid(self, *, rehash: bool = False) -> bool:
            return not self.closed

        def close(self) -> None:
            self.closed = True

    custody = Custody()
    launched: dict[str, object] = {}

    class Process:
        pid = 7712

        def poll(self):
            return None

        def terminate(self):
            return None

        def wait(self, timeout=None):
            return 0

        def kill(self):
            return None

    def fake_popen(argv, **kwargs):
        launched["argv"] = argv
        launched.update(kwargs)
        return Process()

    monkeypatch.setattr(frz_heartbeat, "_acquire_trusted_watchdog", lambda: custody)
    monkeypatch.setattr(frz_heartbeat, "_mmap_path", lambda: tmp_path / "beat.mmap")
    monkeypatch.setattr(frz_heartbeat.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        "angerona.core.privilege.sanitized_child_environment",
        lambda **_kwargs: {"SystemRoot": r"C:\Windows", "PYTHONNOUSERSITE": "1"},
    )

    module = frz_heartbeat.FrzHeartbeatModule()
    module._launch_watchdog()
    assert module._watchdog_custody is custody
    assert launched["env"] == {
        "SystemRoot": r"C:\Windows",
        "PYTHONNOUSERSITE": "1",
    }
    assert launched["cwd"] == str(candidate.parent)
    assert launched["close_fds"] is True
    assert module._watchdog_identity["sha256"] == "a" * 64

    module._watchdog_proc = None
    module._release_watchdog_custody()
    assert custody.closed
