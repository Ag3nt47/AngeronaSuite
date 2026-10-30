"""Enrollment does no credential I/O until explicit action on a retained reader."""
from __future__ import annotations

from dataclasses import replace
import threading
import time
from types import SimpleNamespace

from PySide6.QtWidgets import QApplication
from shiboken6 import delete

from angerona.core.config import Config
from angerona.core import recorder_integrity as enrollment
from angerona.core.recorder_integrity_runtime import RecorderIntegrityRuntime
from angerona.core.eventbus import EventBus
from angerona.core.recorder_epoch_worker import RecorderEpochStatus
from angerona.gui import recorder_integrity_controls as gui


def public_fixture():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")


def test_status_is_cached_and_settings_do_not_resolve_private_credentials(tmp_path, monkeypatch):
    monkeypatch.setattr(enrollment, "provision_host_identity", lambda *_args: (_ for _ in ()).throw(AssertionError("credential read")))
    status = RecorderEpochStatus(state="storage-held", reason="Archive limit reached", archive_bytes=4096)
    view = SimpleNamespace(latest_status=lambda: status)
    controls = gui.RecorderIntegrityControls(Config(data_dir=tmp_path), SimpleNamespace(recorder_integrity_runtime=view))
    try:
        assert "storage-held" in controls.status.text()
        assert controls._enrollment is None
        controls._archive_mib.setValue(8)
        candidate = Config(data_dir=tmp_path)
        controls.write_candidate(candidate)
        assert candidate.recorder_witness_archive_mib == 8 and not candidate.recorder_witness_enabled
        status = replace(status, reason="<b>untrusted-looking text remains plain</b>")
        controls.refresh_status()
        assert "<b>" in controls.status.text()
        assert controls._enrollment is None
    finally:
        controls.shutdown_reader()
        delete(controls)


def test_explicit_identity_action_runs_off_qt_and_close_discards_late_result(tmp_path, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    qt_thread = threading.get_ident()
    owners = []
    public = public_fixture()
    def public_key(root):
        assert root == tmp_path
        owners.append(threading.get_ident())
        entered.set()
        assert release.wait(3)
        return public
    monkeypatch.setattr(enrollment, "provision_host_identity", public_key)
    config = Config(data_dir=tmp_path)
    runtime = RecorderIntegrityRuntime(config, EventBus(), None)
    controls = gui.RecorderIntegrityControls(config, SimpleNamespace(recorder_integrity_runtime=runtime))
    try:
        controls._identity_button.click()
        assert entered.wait(2)
        assert owners[0] != qt_thread and not controls._identity_button.isEnabled()
        controls.shutdown_reader()
        # Closing only detaches the view. Production STOP retains and drains
        # this exact owner, instead of this test manually joining a UI thread.
        assert runtime.stop(timeout=0.01) is False
        release.set()
        assert runtime.stop(timeout=3) is True
        QApplication.processEvents()
        assert controls._public_identity.toPlainText() == ""
    finally:
        release.set()
        controls.shutdown_reader()
        assert runtime.stop(timeout=3) is True
        delete(controls)


def test_public_key_and_generated_ids_are_presented_without_saving_or_enabling(tmp_path, monkeypatch):
    public = public_fixture()
    monkeypatch.setattr(enrollment, "provision_host_identity", lambda _root: public)
    config = Config(data_dir=tmp_path)
    runtime = RecorderIntegrityRuntime(config, EventBus(), None)
    controls = gui.RecorderIntegrityControls(config, SimpleNamespace(recorder_integrity_runtime=runtime))
    try:
        controls._identity_button.click()
        deadline = time.monotonic() + 3
        while runtime.enrollment.latest_status().state == "running" and time.monotonic() < deadline:
            QApplication.processEvents()
            time.sleep(0.01)
        controls.refresh_status()
        assert controls._public_identity.toPlainText() == public
        assert len(controls._fields["recorder_witness_installation_id"].text()) == 32
        assert len(controls._fields["recorder_witness_client_id"].text()) == 32
        assert not controls._enabled.isChecked() and not controls._config.settings_path.exists()
    finally:
        controls.shutdown_reader()
        assert runtime.stop(timeout=3) is True
        delete(controls)
