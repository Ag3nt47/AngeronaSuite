from __future__ import annotations

import base64
import contextlib
import io
import os
import re
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import analysis_vmware_setup as setup


@pytest.fixture
def installer(tmp_path, monkeypatch):
    path = tmp_path / "VMware-workstation-full-25H2-24995812.exe"
    path.write_bytes(b"inert installer fixture, never executable")
    monkeypatch.setattr(setup, "_require_windows", lambda: None)
    monkeypatch.setattr(setup, "_installer_identity", lambda _path: ("Valid", "VMware, Inc.", "VMware Workstation"))
    return path


@pytest.mark.parametrize("identity", [
    ("NotSigned", "VMware, Inc.", "VMware Workstation"),
    ("HashMismatch", "VMware, Inc.", "VMware Workstation"),
    ("Valid", "Other VMware, Inc.", "VMware Workstation"),
    ("Valid", "VMware, Inc.", "Unrelated signed utility"),
])
def test_installer_rejects_untrusted_or_unrelated_signed_file(installer, monkeypatch, identity):
    monkeypatch.setattr(setup, "_installer_identity", lambda _path: identity)
    monkeypatch.setattr(setup, "_powershell", lambda *_a, **_k: pytest.fail("untrusted installer launched"))
    with pytest.raises(ValueError):
        setup.install_selected(installer)


def test_installer_handoff_preserves_file_custody(installer, monkeypatch):
    progress = []

    def launch(script, *, installer, timeout=None):
        assert script == setup._INSTALL_SCRIPT
        assert timeout is None
        if os.name == "nt":
            with pytest.raises(OSError):
                installer.write_bytes(b"replacement")
            with pytest.raises(OSError):
                installer.rename(installer.with_suffix(".swapped"))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(setup, "_powershell", launch)
    message = setup.install_selected(installer, progress.append)
    assert "exited successfully" in message
    assert "ready" not in message.lower()
    assert len(progress) == 2
    # Custody is released after the fake installer exits.
    installer.write_bytes(b"safe to replace after exit")


def test_installer_rejects_hardlink_before_signature(installer, monkeypatch):
    other = installer.with_name("other.exe")
    os.link(installer, other)
    monkeypatch.setattr(setup, "_installer_identity", lambda *_a: pytest.fail("hardlink admitted"))
    with pytest.raises(ValueError, match="one bounded"):
        with setup.verified_installer(installer):
            pytest.fail("hardlink admitted")


def test_installer_rejects_path_identity_change(installer, monkeypatch):
    original = setup._identity
    calls = 0

    def changed_identity(info):
        nonlocal calls
        calls += 1
        value = original(info)
        return (*value[:1], value[1] + 1, *value[2:]) if calls >= 3 else value

    monkeypatch.setattr(setup, "_identity", changed_identity)
    with pytest.raises(ValueError, match="changed"):
        with setup.verified_installer(installer):
            pytest.fail("path swap admitted")


@pytest.mark.parametrize("code", [1, 1223, 1603])
def test_cancelled_or_failed_installer_never_claims_success(installer, monkeypatch, code):
    monkeypatch.setattr(setup, "_powershell", lambda *_a, **_k: SimpleNamespace(returncode=code))
    with pytest.raises(ValueError, match="cancelled or failed"):
        setup.install_selected(installer)


def test_restart_exit_is_reported_without_configuring(installer, monkeypatch):
    monkeypatch.setattr(setup, "_powershell", lambda *_a, **_k: SimpleNamespace(returncode=3010))
    assert "restart" in setup.install_selected(installer).lower()


def test_powershell_receives_path_as_data_in_sanitized_environment(tmp_path, monkeypatch):
    from angerona.core import privilege

    engine = tmp_path / "powershell.exe"
    selected = tmp_path / "directory with 'quotes; $env:SECRET" / "VMware-workstation-full-25H2.exe"
    monkeypatch.setattr(privilege, "trusted_powershell_path", lambda: engine)
    monkeypatch.setattr(privilege, "trusted_windows_directories", lambda: (tmp_path, tmp_path))
    monkeypatch.setattr(privilege, "sanitized_child_environment", lambda *, source: {"SAFE": "yes"} if source == {} else pytest.fail("inherited secrets"))
    monkeypatch.setattr(setup, "_hold_plain_directories", lambda *_a: contextlib.nullcontext())
    monkeypatch.setattr(setup, "_open_sealed", lambda *_a: io.BytesIO(b"engine fixture"))
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout=b"")

    monkeypatch.setattr(setup.subprocess, "run", run)
    setup._powershell(setup._INSTALL_SCRIPT, installer=selected)
    argv, kwargs = calls[0]
    assert argv[0] == str(engine)
    assert base64.b64decode(argv[-1]).decode("utf-16-le") == setup._INSTALL_SCRIPT
    assert str(selected) not in " ".join(argv)
    assert kwargs["env"] == {"SAFE": "yes", "ANGERONA_VMWARE_INSTALLER": str(selected)}
    assert kwargs["cwd"] == str(tmp_path)
    assert "shell" not in kwargs
    assert kwargs["stdin"] == subprocess.DEVNULL


def test_signature_parser_rejects_malformed_or_unbounded_output(monkeypatch):
    for output in (b"not JSON", b"[]", b"{}", b"x" * 4097):
        monkeypatch.setattr(setup, "_powershell", lambda *_a, data=output, **_k: SimpleNamespace(returncode=0, stdout=data))
        with pytest.raises(ValueError):
            setup._installer_identity(Path("unused.exe"))


def test_configure_only_elevates_fixed_service_script_after_trust(monkeypatch):
    from angerona.core import analysis_vmware

    order = []

    @contextlib.contextmanager
    def installed():
        order.append("trusted")
        yield Path("D:/trusted-vmware")
        order.append("released")

    def powershell(script, *, expected_directory):
        order.append("elevate")
        assert expected_directory == Path("D:/trusted-vmware")
        encoded = re.search(r"'-EncodedCommand','([A-Za-z0-9+/=]+)'", script)[1]
        assert base64.b64decode(encoded).decode("utf-16-le") == setup._CONFIGURE_SCRIPT
        assert "-Verb RunAs" in script and "-WindowStyle Hidden" in script
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(setup, "_require_windows", lambda: None)
    monkeypatch.setattr(analysis_vmware, "trusted_installation", installed)
    monkeypatch.setattr(analysis_vmware, "service_ready", lambda: order.append("checked"))
    monkeypatch.setattr(setup, "_powershell", powershell)
    message = setup.configure_service()
    assert order == ["trusted", "elevate", "checked", "released"]
    assert "Manual" in message and "check readiness" in message


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell directory-custody fixture")
def test_service_program_rejects_other_directory_and_denies_ancestor_rename(tmp_path):
    """Run only fixture overrides: service/signature commands cannot touch host."""
    from angerona.core.privilege import (
        sanitized_child_environment, trusted_powershell_path, trusted_windows_directories,
    )

    expected = tmp_path / "installed" / "Workstation"
    expected.mkdir(parents=True)
    image = expected / "vmware-authd.exe"
    image.write_bytes(b"inert fixture")
    foreign = tmp_path / "foreign" / "vmware-authd.exe"
    foreign.parent.mkdir()
    foreign.write_bytes(b"inert fixture")
    prelude = r'''
function Get-CimInstance { [pscustomobject]@{PathName=$env:FIXTURE_SERVICE_IMAGE} }
function Set-Service { throw 'Fixture forbids any host service modification' }
function Start-Service { throw 'Fixture forbids any host service startup' }
function Get-AuthenticodeSignature {
    try { [IO.Directory]::Move($env:FIXTURE_PARENT, $env:FIXTURE_PARENT + '-moved'); exit 87 }
    catch [IO.IOException] { exit 88 }
    catch [UnauthorizedAccessException] { exit 88 }
}
'''
    environment = sanitized_child_environment(source={})
    environment.update({
        "ANGERONA_VMWARE_EXPECTED_DIRECTORY": str(expected),
        "FIXTURE_PARENT": str(expected.parent),
    })
    argv = [str(trusted_powershell_path()), "-NoProfile", "-NonInteractive", "-EncodedCommand",
            setup._encoded(prelude + setup._CONFIGURE_SCRIPT)]
    for target, expected_code in ((foreign, 1), (image, 88)):
        environment["FIXTURE_SERVICE_IMAGE"] = str(target)
        result = subprocess.run(
            argv, cwd=str(trusted_windows_directories()[1]), env=environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, check=False, creationflags=subprocess.CREATE_NO_WINDOW,
        )
        assert result.returncode == expected_code, result.stderr.decode(errors="replace")
        assert expected.parent.is_dir()


def test_standalone_service_program_matches_guarded_immutable_body():
    script = (Path(__file__).resolve().parents[1] / "tools/enable_analysis_lab_vmware.ps1").read_text(encoding="utf-8")
    assert script.endswith(setup._CONFIGURE_SCRIPT)
    assert "OpenBaseKey" in script and "RegistryHive]::LocalMachine" in script
    assert "$env:ANGERONA_VMWARE_EXPECTED_DIRECTORY = ''" in script


def test_untrusted_installation_prevents_configuration_elevation(monkeypatch):
    from angerona.core import analysis_vmware

    monkeypatch.setattr(setup, "_require_windows", lambda: None)
    def reject():
        raise ValueError("not trusted")
    monkeypatch.setattr(analysis_vmware, "trusted_installation", reject)
    monkeypatch.setattr(setup, "_powershell", lambda *_a, **_k: pytest.fail("untrusted service configured"))
    with pytest.raises(ValueError, match="not trusted"):
        setup.configure_service()


def test_unsupported_host_never_installs_or_configures(monkeypatch):
    monkeypatch.setattr(setup.sys, "platform", "linux")
    monkeypatch.setattr(setup, "_powershell", lambda *_a, **_k: pytest.fail("Windows setup launched"))
    with pytest.raises(ValueError, match="supports Windows"):
        setup.install_selected("unused.exe")
    with pytest.raises(ValueError, match="supports Windows"):
        setup.configure_service()


def test_wizard_step_is_optional_platform_gated_and_explains_purpose():
    from angerona.gui.setup_wizard import STEPS, field_supported

    step = next(step for step in STEPS if step.title == "Optional Analysis Lab")
    assert "autonomous defense" in step.intro and "Ollama" in step.intro
    assert "RAM" in step.intro and "only when you start" in step.intro
    assert len(step.fields) == 1 and step.fields[0].kind == "action"
    assert field_supported(step.fields[0], "win32")
    assert not field_supported(step.fields[0], "darwin")
    assert not field_supported(step.fields[0], "linux")


def test_setup_dialog_is_idle_until_explicit_action(monkeypatch):
    pytest.importorskip("PySide6")
    from angerona.gui.analysis_vmware_setup import VMwareSetupDialog

    monkeypatch.setattr(setup, "install_selected", lambda *_a: pytest.fail("silent install"))
    monkeypatch.setattr(setup, "configure_service", lambda *_a: pytest.fail("silent service change"))
    dialog = VMwareSetupDialog()
    try:
        assert not dialog._busy and not dialog._timer.isActive()
        assert dialog.close_button.isDefault()
        assert not dialog.install_button.autoDefault()
        assert "idle" in dialog.status.text()
    finally:
        dialog.close()
        dialog.deleteLater()


def test_nonwindows_dialog_disables_all_vmware_actions(monkeypatch):
    pytest.importorskip("PySide6")
    from angerona.gui.analysis_vmware_setup import VMwareSetupDialog

    monkeypatch.setattr(setup.sys, "platform", "darwin")
    dialog = VMwareSetupDialog()
    try:
        assert all(not button.isEnabled() for button in dialog._actions)
        assert dialog.close_button.isEnabled()
        assert "skip" in dialog.status.text().lower()
    finally:
        dialog.close()
        dialog.deleteLater()


def test_wizard_analysis_lab_page_defaults_to_skip(monkeypatch):
    pytest.importorskip("PySide6")
    from angerona.core.config import Config
    from angerona.gui.setup_wizard import STEPS, SetupWizard

    monkeypatch.setattr(setup, "install_selected", lambda *_a: pytest.fail("silent install"))
    monkeypatch.setattr(setup, "configure_service", lambda *_a: pytest.fail("silent configure"))
    wizard = SetupWizard(Config())
    try:
        index = next(index for index, step in enumerate(STEPS) if step.title == "Optional Analysis Lab")
        wizard._stack.setCurrentIndex(index)
        wizard._sync()
        assert wizard._skip.isDefault()
        assert not wizard._next.isDefault()
        wizard._skip.click()
        assert wizard._stack.currentIndex() == index + 1
    finally:
        wizard.close()
        wizard.deleteLater()


def test_worker_keeps_gui_responsive_and_completion_survives_full_progress():
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication
    from angerona.gui.analysis_vmware_setup import VMwareSetupDialog

    dialog = VMwareSetupDialog()
    entered, finish = threading.Event(), threading.Event()
    def work(progress):
        entered.set()
        for _ in range(30):
            progress("progress")
        assert finish.wait(3)
        return "Fixture completed"

    try:
        dialog._start(work)
        assert entered.wait(1)
        assert dialog._busy and not dialog.close_button.isEnabled()
        dialog.reject()
        assert dialog._busy
        QApplication.processEvents()
        finish.set()
        deadline = time.monotonic() + 3
        while dialog._busy and time.monotonic() < deadline:
            QApplication.processEvents()
            dialog._poll()
            time.sleep(0.01)
        assert not dialog._busy
        assert dialog.status.text().startswith("Fixture completed")
        assert "currently blocked" in dialog.status.text()
    finally:
        finish.set()
        dialog.close()
        dialog.deleteLater()
