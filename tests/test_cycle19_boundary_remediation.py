from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import data_paths, privilege


pytestmark = pytest.mark.skipif(
    os.name != "nt", reason="Windows privileged-bootstrap regression"
)


def _patch_windows_paths(monkeypatch, tmp_path: Path) -> tuple[Path, Path]:
    windows = tmp_path / "TrustedWindows"
    system = windows / "System32"
    system.mkdir(parents=True)
    monkeypatch.setattr(
        privilege, "trusted_windows_directories", lambda: (windows, system)
    )
    monkeypatch.setattr(
        privilege, "trusted_program_data_path", lambda: tmp_path / "ProgramData"
    )
    monkeypatch.setattr(
        privilege, "_windows_known_folder", lambda _csidl: tmp_path / "ProgramFiles"
    )
    return windows, system


def test_child_environment_is_allowlisted_and_secret_free(tmp_path, monkeypatch):
    windows, system = _patch_windows_paths(monkeypatch, tmp_path)
    source = {
        "SystemRoot": str(tmp_path / "hostile-root"),
        "PATH": str(tmp_path / "hostile-bin"),
        "PYTHONPATH": str(tmp_path / "hostile-python"),
        "HTTP_PROXY": "http://credential-bearing-proxy.invalid",
        "OPENAI_API_KEY": "provider-sentinel",
        "ARIA_IMAP_PASSWORD": "mail-sentinel",
        "ANGERONA_FLEET_SERVICE_KEY": "fleet-sentinel",
        "ANGERONA_WATCHDOG_TOKEN": "watchdog-sentinel",
        "ANGERONA_DATA": str(tmp_path / "runtime"),
        "ANGERONA_DIAG_DIR": str(tmp_path / "runtime" / "diagnostics"),
        "USERPROFILE": str(tmp_path / "profile"),
    }

    environment = privilege.sanitized_child_environment(source=source)

    assert environment["SystemRoot"] == str(windows)
    assert environment["ComSpec"] == str(system / "cmd.exe")
    assert environment["ANGERONA_DATA"] == source["ANGERONA_DATA"]
    assert environment["ANGERONA_DIAG_DIR"] == source["ANGERONA_DIAG_DIR"]
    for key in (
        "OPENAI_API_KEY",
        "ARIA_IMAP_PASSWORD",
        "ANGERONA_FLEET_SERVICE_KEY",
        "ANGERONA_WATCHDOG_TOKEN",
        "HTTP_PROXY",
        "PYTHONPATH",
    ):
        assert key not in environment
    assert str(tmp_path / "hostile-bin") not in environment["PATH"]


@pytest.mark.parametrize("name", ("OPENAI_API_KEY", "PATH", "LD_PRELOAD"))
def test_child_environment_rejects_explicit_sensitive_override(
    tmp_path, monkeypatch, name
):
    _patch_windows_paths(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="refusing"):
        privilege.sanitized_child_environment(
            {name: "must-not-cross"}, source={}
        )


def test_uac_relaunch_scrubs_hostile_inputs_and_preserves_setup(
    tmp_path, monkeypatch
):
    _patch_windows_paths(monkeypatch, tmp_path)
    captured = {}

    class FakeShellExecute:
        argtypes = None
        restype = None

        def __call__(self, _hwnd, verb, target, params, workdir, show):
            captured.update({
                "verb": verb,
                "target": target,
                "params": params,
                "workdir": workdir,
                "show": show,
                "environment": dict(os.environ),
            })
            return 42

    monkeypatch.setattr(privilege, "is_admin", lambda: False)
    monkeypatch.setattr(
        privilege.ctypes,
        "windll",
        SimpleNamespace(shell32=SimpleNamespace(ShellExecuteW=FakeShellExecute())),
    )
    monkeypatch.setattr(privilege.sys, "argv", ["angerona", "--setup"])
    monkeypatch.setattr(privilege.sys, "frozen", False, raising=False)
    original = dict(os.environ)
    startup_ready = (
        Path(privilege.__file__).resolve().parents[3].parent
        / "AngeronaData" / "logs" / "dashboard-ready.signal"
    ).resolve()
    try:
        os.environ.update({
            "SystemRoot": str(tmp_path / "hostile-root"),
            "PATH": str(tmp_path / "hostile-bin"),
            "PYTHONPATH": str(tmp_path / "hostile-python"),
            "ANGERONA_RESILIENCE": "0",
            "ANGERONA_CORE_CMD": str(tmp_path / "hostile-core.exe"),
            "ANGERONA_FLEET_SERVICE_KEY": "attacker-authority",
            "OPENAI_API_KEY": "provider-secret",
            "ANGERONA_STARTUP_READY": str(startup_ready),
        })
        with pytest.raises(SystemExit):
            privilege.ensure_admin()
    finally:
        os.environ.clear()
        os.environ.update(original)

    assert captured["verb"] == "runas"
    assert captured["params"] == "-m angerona --setup"
    assert Path(captured["workdir"]).name == "src"
    elevated = captured["environment"]
    assert elevated["ANGERONA_STARTUP_READY"] == str(startup_ready)
    assert next(
        value for key, value in elevated.items()
        if key.casefold() == "systemroot"
    ).endswith("TrustedWindows")
    for key in (
        "PYTHONPATH",
        "ANGERONA_RESILIENCE",
        "ANGERONA_CORE_CMD",
        "ANGERONA_FLEET_SERVICE_KEY",
        "OPENAI_API_KEY",
    ):
        assert key not in elevated


def test_uac_scrub_rejects_noncanonical_startup_ready_path(
    tmp_path, monkeypatch,
):
    _patch_windows_paths(monkeypatch, tmp_path)
    original = dict(os.environ)
    try:
        os.environ["ANGERONA_STARTUP_READY"] = str(
            tmp_path / "attacker" / "dashboard-ready.signal"
        )
        privilege.sanitize_privileged_bootstrap_environment()
        assert "ANGERONA_STARTUP_READY" not in os.environ
    finally:
        os.environ.clear()
        os.environ.update(original)


def test_signed_parent_watchdog_context_is_narrowly_preserved(
    tmp_path, monkeypatch
):
    _patch_windows_paths(monkeypatch, tmp_path)
    watchdog = tmp_path / "angerona_watchdog.exe"
    watchdog.write_bytes(b"signed-watchdog-fixture")
    token = bytes(range(32))
    counter = 17
    proof = int.from_bytes(
        hashlib.sha256(token + struct.pack("<I", counter)).digest()[:8],
        "little",
    )
    heartbeat = tmp_path / "frz_watchdog.mmap"
    heartbeat.write_bytes(struct.pack(
        "<IQIQII",
        0x41574447,
        int(__import__("time").time() * 1e9),
        os.getppid(),
        proof,
        counter,
        1,
    ))
    monkeypatch.setattr(privilege, "_expected_watchdog_path", lambda: watchdog)
    monkeypatch.setattr(privilege, "_process_image_path", lambda _pid: watchdog)
    monkeypatch.setattr(privilege, "_authenticode_valid", lambda _path: True)
    original = dict(os.environ)
    try:
        os.environ.update({
            "ANGERONA_EXTERNAL_WATCHDOG": "1",
            "ANGERONA_WATCHDOG_MMAP": str(heartbeat),
            "ANGERONA_WATCHDOG_TOKEN": token.hex(),
            "ANGERONA_WD_DATADIR": str(tmp_path),
            "OPENAI_API_KEY": "provider-secret",
        })
        privilege.sanitize_privileged_bootstrap_environment()
        assert os.environ["ANGERONA_EXTERNAL_WATCHDOG"] == "1"
        assert os.environ["ANGERONA_WATCHDOG_TOKEN"] == token.hex()
        child = privilege.sanitized_child_environment()
        assert "ANGERONA_WATCHDOG_TOKEN" not in child
        assert "OPENAI_API_KEY" not in child
    finally:
        os.environ.clear()
        os.environ.update(original)


def test_acl_verifier_uses_trusted_powershell_and_clean_environment(
    tmp_path, monkeypatch
):
    _windows, _system = _patch_windows_paths(monkeypatch, tmp_path)
    powershell = tmp_path / "trusted-powershell.exe"
    powershell.write_bytes(b"fixture")
    monkeypatch.setattr(privilege, "trusted_powershell_path", lambda: powershell)
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["environment"] = kwargs["env"]
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(data_paths.subprocess, "run", fake_run)
    monkeypatch.setenv("SystemRoot", str(tmp_path / "hostile-root"))
    monkeypatch.setenv("OPENAI_API_KEY", "provider-secret")

    target = tmp_path / "runtime"
    assert data_paths._admin_acl_valid(target)
    assert captured["argv"][0] == str(powershell)
    assert captured["environment"]["ANGERONA_ACL_PATH"] == str(target)
    assert "OPENAI_API_KEY" not in captured["environment"]


def test_supervisor_sidecar_receives_runtime_coordinates_not_credentials(
    tmp_path, monkeypatch
):
    from angerona.resilience import supervisor

    _patch_windows_paths(monkeypatch, tmp_path)
    monkeypatch.setenv("ANGERONA_DATA", str(tmp_path / "runtime"))
    monkeypatch.setenv("ANGERONA_DIAG_DIR", str(tmp_path / "runtime" / "diag"))
    monkeypatch.setenv("OPENAI_API_KEY", "provider-secret")
    monkeypatch.setenv("ANGERONA_FLEET_SERVICE_KEY", "fleet-secret")
    monkeypatch.setenv("ANGERONA_WATCHDOG_TOKEN", "watchdog-secret")
    captured = {}
    sentinel = object()

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        captured["environment"] = kwargs["env"]
        return sentinel

    monkeypatch.setattr(supervisor.subprocess, "Popen", fake_popen)
    result = supervisor.spawn_detached(
        [str(Path(os.sys.executable).resolve()), "-m", "angerona.resilience.scanner"],
        window="hidden",
    )

    assert result is sentinel
    environment = captured["environment"]
    assert environment["ANGERONA_DATA"] == str(tmp_path / "runtime")
    assert environment["ANGERONA_DIAG_DIR"].endswith("diag")
    assert "OPENAI_API_KEY" not in environment
    assert "ANGERONA_FLEET_SERVICE_KEY" not in environment
    assert "ANGERONA_WATCHDOG_TOKEN" not in environment


def test_unprotected_fleet_argument_cannot_become_durable_authority(
    tmp_path, monkeypatch
):
    from angerona.core import secure_store
    from angerona.core.fleet_credentials import load_or_migrate_local_credentials

    writes = []
    monkeypatch.setattr(secure_store, "read_secret_map", lambda _root: {})
    monkeypatch.setattr(
        secure_store,
        "write_secret_map",
        lambda updates, _root: writes.append(dict(updates)),
    )

    with pytest.raises(RuntimeError, match="unprotected legacy"):
        load_or_migrate_local_credentials(
            tmp_path,
            "tenant-acme",
            "device-123",
            legacy_secret="attacker-selected-value" * 3,
        )
    assert writes == []
