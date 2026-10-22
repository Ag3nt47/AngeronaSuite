from __future__ import annotations

import copy
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, Qt
from PySide6.QtWidgets import QApplication, QLineEdit

from angerona.gui.ugcap_page import UGCAPPage


class FakeModule:
    def __init__(self, vault_path):
        self.calls = []
        self.challenge_refs = []
        self.challenge_copies = []
        self.reads = 0
        self.accept = True
        self.snapshot = {
            "status": "challenge required", "workspace_locked": False,
            "settings": {"ugcap_enabled": False, "ugcap_cadence_hours": 168,
                         "ugcap_vault_path": str(vault_path), "ugcap_key_name": "Angerona.UGCAP.v1",
                         "ugcap_lockdown": True},
            "report": {},
            "hardware": {"provider": "Windows TPM", "available": False, "status": "not provisioned"},
            "coverage": {"blake3_available": False, "platform": "Windows", "complete": False},
            "recovery": {"challenge_required": True}, "result": {}, "error": "",
        }

    def dashboard_snapshot(self):
        self.reads += 1
        return copy.deepcopy(self.snapshot)

    def _challenge(self, method, path, challenge, *rest):
        assert isinstance(challenge, bytearray)
        self.challenge_refs.append(challenge)
        self.challenge_copies.append(bytearray(challenge))
        self.calls.append((method, path, *rest))
        return self.accept

    def queue_initialize(self, path, challenge):
        return self._challenge("initialize", path, challenge)

    def queue_verify(self, path, challenge):
        return self._challenge("verify", path, challenge)

    def queue_restore(self, path, challenge, paths, report_id):
        return self._challenge("restore", path, challenge, paths, report_id)

    def queue_lock(self):
        self.calls.append(("lock",))
        return self.accept

    def queue_provision_hardware(self, name):
        self.calls.append(("provision", name))
        return self.accept

    def configure_settings(self, **kwargs):
        self.calls.append(("settings", kwargs))
        return {"queued": self.accept}


def make_page(tmp_path, *, show=False, paused=False):
    path = tmp_path / "attached-medium" / "angerona.ugcap"
    module = FakeModule(path)
    config = SimpleNamespace(**module.snapshot["settings"])
    manager = SimpleNamespace(modules={"UGCAP Integrity Guard": module}, ugcap_paused=paused)
    page = UGCAPPage(manager, config, None)
    if show:
        page.show()
        QApplication.instance().processEvents()
    return page, module


def drift_report(module, **kwargs):
    report = {"report_id": "a" * 32, "generation": "b" * 32,
              "vault_path": module.snapshot["settings"]["ugcap_vault_path"],
              "status": "drift", "coverage": {"complete": True, "files_scanned": 25},
              "changes": {"modified": ["src/angerona/example.py", "native/helper.dll"],
                          "missing": ["tests/test_example.py"], "added": ["unexpected.py"], "read_errors": []}}
    report.update(kwargs)
    module.snapshot["report"] = report
    return report


def check_path(page, index=0):
    page.diff_table.item(index, 0).setCheckState(Qt.CheckState.Checked)


def test_construction_and_opening_never_provision_or_touch_vault(tmp_path):
    page, module = make_page(tmp_path)
    try:
        assert module.calls == [] and module.reads == 0
        assert not page._timer.isActive()
        assert page.passcode.echoMode() == QLineEdit.EchoMode.Password
        assert page.passcode.text() == ""
        page.show()
        QApplication.instance().processEvents()
        assert module.reads >= 1 and module.calls == []
        assert page._timer.isActive() and page._timer.interval() == 3000
        assert not (tmp_path / "attached-medium").exists()
    finally:
        page.close()


@pytest.mark.parametrize("operation", ["verify", "initialize"])
def test_explicit_challenge_is_copied_then_ui_buffer_is_wiped(tmp_path, operation):
    page, module = make_page(tmp_path, show=True)
    try:
        secret = "unit-test-only-passphrase"
        page.passcode.setText(secret)
        getattr(page, operation + "_button").click()
        assert page.passcode.text() == ""
        assert module.challenge_refs == [bytearray()]
        assert module.challenge_copies == [bytearray(secret, "utf-8")]
        assert module.calls == [(operation, page.vault_path.text())]
        assert secret not in page.status.text()
        assert secret not in page.details.toPlainText()
        assert not any(key for key in page.__dict__ if "secret" in key or "challenge_copy" in key)
    finally:
        page.close()


def test_queue_failure_and_secret_bearing_exception_never_reveal_or_retain_challenge(tmp_path):
    page, module = make_page(tmp_path, show=True)
    try:
        module.accept = False
        page.passcode.setText("first-secret")
        page.verify_button.click()
        assert not page.passcode.text() and not module.challenge_refs[-1]
        def fail(path, challenge):
            module.challenge_refs.append(challenge)
            raise RuntimeError(bytes(challenge).decode())
        module.queue_verify = fail
        page.passcode.setText("never-show-this-secret")
        page.verify_button.click()
        assert not page.passcode.text() and not module.challenge_refs[-1]
        assert "never-show-this-secret" not in page.status.text()
        assert "not queued" in page.status.text()
    finally:
        page.close()


def test_restore_requires_current_complete_diff_and_individual_selection(tmp_path):
    page, module = make_page(tmp_path, show=True)
    try:
        page.passcode.setText("secret")
        page.restore_button.clicked.emit()
        assert module.calls == [] and page.passcode.text() == ""
        report = drift_report(module)
        page.refresh()
        assert page.diff_table.rowCount() == 4
        assert not page.restore_button.isEnabled()
        check_path(page)
        assert page.restore_button.isEnabled()
        page.passcode.setText("recovery-secret")
        page.restore_button.click()
        assert module.calls == [("restore", page.vault_path.text(), ["src/angerona/example.py"], report["report_id"])]
        assert page.passcode.text() == "" and module.challenge_refs[-1] == bytearray()
        assert not page.restore_button.isEnabled()
        page.refresh()  # A prior diff cannot approve a second restore.
        assert not page.restore_button.isEnabled()
    finally:
        page.close()


def test_added_read_errors_incomplete_and_wrong_vault_do_not_authorize_restore(tmp_path):
    page, module = make_page(tmp_path, show=True)
    try:
        report = drift_report(module)
        report["changes"]["read_errors"] = [{"path": "locked.py", "error": "Access denied"}]
        page.refresh()
        assert not page.diff_table.item(3, 0).flags() & Qt.ItemFlag.ItemIsUserCheckable
        assert not page.diff_table.item(4, 0).flags() & Qt.ItemFlag.ItemIsUserCheckable
        assert "Access denied" in page.diff_table.item(4, 3).text()
        check_path(page)
        report["status"] = "incomplete"
        report["coverage"]["complete"] = False
        page.refresh()
        check_path(page)
        assert not page.restore_button.isEnabled()
        report["status"] = "drift"
        report["coverage"]["complete"] = True
        report["vault_path"] = str(tmp_path / "another.ugcap")
        page.refresh()
        check_path(page)
        assert not page.restore_button.isEnabled()
        page._restore()
        assert module.calls == []
    finally:
        page.close()


def test_new_report_clears_checks_but_identical_snapshot_preserves_review(tmp_path):
    page, module = make_page(tmp_path, show=True)
    try:
        report = drift_report(module)
        page.refresh()
        check_path(page)
        page.refresh()
        assert page.diff_table.item(0, 0).checkState() == Qt.CheckState.Checked
        report["report_id"] = "c" * 32
        page.refresh()
        assert page.diff_table.item(0, 0).checkState() == Qt.CheckState.Unchecked
        check_path(page)
        page.passcode.setText("verification-secret")
        page.verify_button.click()
        page.refresh()
        assert not page.restore_button.isEnabled()
        report["report_id"] = "d" * 32
        page.refresh()
        assert page._awaiting_report is None
        assert not page.restore_button.isEnabled()  # Fresh checks are required.
    finally:
        page.close()


def test_binary_deferral_and_restart_requirement_remain_visible(tmp_path):
    page, module = make_page(tmp_path, show=True)
    try:
        drift_report(module)
        page.refresh()
        assert "offline recovery" in page.diff_table.item(1, 3).text()
        check_path(page, 1)
        page.passcode.setText("binary-secret")
        page.restore_button.click()
        assert module.calls[-1][2] == ["native/helper.dll"]
        module.snapshot["result"] = {"status": "deferred", "deferred": ["native/helper.dll"], "restart_required": True}
        page.refresh()
        assert '"restart_required": true' in page.details.toPlainText()
        assert '"status": "deferred"' in page.details.toPlainText()
    finally:
        page.close()


def test_diff_rendering_and_selection_batches_are_bounded_plaintext(tmp_path):
    page, module = make_page(tmp_path, show=True)
    try:
        hostile = '<img src="https://example.com/track">.py'
        report = drift_report(module)
        report["changes"] = {"modified": [hostile] + [f"src/item-{i}.py" for i in range(700)]}
        page.refresh()
        assert page.diff_table.rowCount() == 500
        assert page.diff_table.item(0, 2).text() == hostile
        assert "701 change" in page.report_summary.text()
        assert page.report_summary.textFormat() == Qt.TextFormat.PlainText
        for index in range(129):
            check_path(page, index)
        assert not page.restore_button.isEnabled()
        assert "at most 128" in page.selection_status.text()
        page.passcode.setText("batch-secret")
        page._restore()
        assert module.calls == [] and page.passcode.text() == ""
    finally:
        page.close()


def test_path_dialogs_only_select_file_and_clear_entered_challenge(tmp_path, monkeypatch):
    from angerona.gui import ugcap_page as ui
    page, module = make_page(tmp_path, show=True)
    path = str(tmp_path / "new-vault.ugcap")
    monkeypatch.setattr(ui.QFileDialog, "getSaveFileName", lambda *_a, **_k: (path, "UGCAP vault"))
    monkeypatch.setattr(ui.QFileDialog, "getOpenFileName", lambda *_a, **_k: (path, "UGCAP vault"))
    try:
        page.passcode.setText("path-secret")
        page.new_vault_button.click()
        assert page.vault_path.text() == path and not page.passcode.text()
        page.open_vault_button.click()
        assert module.calls == [] and not (tmp_path / "new-vault.ugcap").exists()
    finally:
        page.close()


def test_invalid_relative_and_network_paths_do_not_reach_queue(tmp_path):
    page, module = make_page(tmp_path, show=True)
    try:
        for path in ("relative.ugcap", "\\\\server\\share\\vault.ugcap", "//server/share/vault.ugcap"):
            page.vault_path.setText(path)
            page.passcode.setText("never-send")
            page.verify_button.click()
            assert page.passcode.text() == ""
        assert module.calls == []
    finally:
        page.close()


def test_settings_and_hardware_are_explicit_and_never_store_passcode(tmp_path):
    page, module = make_page(tmp_path, show=True)
    try:
        page.enabled.setChecked(True)
        page.cadence.setValue(24)
        page.key_name.setText("Angerona.UGCAP.testing")
        page.refresh()
        assert page.enabled.isChecked() and page.cadence.value() == 24
        assert module.calls == []
        page.passcode.setText("settings-secret")
        page.apply_settings_button.click()
        kind, settings = module.calls[-1]
        assert kind == "settings" and settings["ugcap_cadence_hours"] == 24
        assert "settings-secret" not in repr(settings)
        assert not page.passcode.text()
        module.snapshot["settings"].update(settings)
        page.refresh()
        assert page._pending_settings is None and not page._settings_dirty
        page.provision_button.click()
        assert module.calls[-1] == ("provision", "Angerona.UGCAP.testing")
        assert "blake3_available" in page.details.toPlainText()
        assert '"available": false' in page.details.toPlainText()
    finally:
        page.close()


def test_workspace_gate_signal_only_emits_on_change_and_initial_paused_is_visible(tmp_path):
    page, module = make_page(tmp_path, paused=True)
    transitions = []
    page.lock_state_changed.connect(transitions.append)
    try:
        assert "Workspace locked" in page.gate_status.text()
        module.snapshot["workspace_locked"] = True
        page.show()
        QApplication.instance().processEvents()
        assert transitions == []
        module.snapshot["workspace_locked"] = False
        page.refresh()
        page.refresh()
        assert transitions == [False]
        module.snapshot["workspace_locked"] = True
        page.refresh()
        assert transitions == [False, True]
        page.passcode.setText("lock-secret")
        page.lock_button.click()
        assert module.calls == [("lock",)] and page.passcode.text() == ""
    finally:
        page.close()


def test_hidden_closed_and_deleted_page_stops_polling_and_clears_password(tmp_path):
    page, module = make_page(tmp_path, show=True)
    page.passcode.setText("hidden-secret")
    page.hide()
    assert not page._timer.isActive() and not page.passcode.text()
    reads = module.reads
    page.refresh()
    assert module.reads == reads
    page.show()
    assert page._timer.isActive()
    page.passcode.setText("close-secret")
    page.close()
    assert not page._timer.isActive() and not page.passcode.text()
    page.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def test_missing_engine_keeps_limits_accessible_and_actions_disabled(tmp_path):
    page = UGCAPPage(SimpleNamespace(modules={}), SimpleNamespace())
    try:
        page.show()
        assert not page.verify_button.isEnabled()
        assert not page.provision_button.isEnabled()
        assert not page.restore_button.isEnabled()
        assert "unavailable" in page.status.text()
        limits = page.tabs.widget(3).toPlainText()
        assert "best effort" in limits and "no software-key fallback" in limits
        assert "does not guarantee rootkit prevention" in limits
    finally:
        page.close()


def test_panel_can_share_a_small_dashboard_without_forcing_large_minimum(tmp_path):
    page, _module = make_page(tmp_path, show=True)
    try:
        page.resize(600, 300)
        QApplication.instance().processEvents()
        assert page.minimumSizeHint().height() < 300
        assert page.minimumSizeHint().width() < 600
        assert page.tabs.widget(0).widgetResizable()
    finally:
        page.close()
