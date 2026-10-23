"""Real Qt ownership and reentrant-delivery contracts; all producers are inert."""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QElapsedTimer, QTimer, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QCheckBox, QComboBox, QLabel, QMessageBox, QPushButton, QWidget
from shiboken6 import delete, isValid

from angerona.core.config import Config
from angerona.gui import setup_wizard
from angerona.gui import update_controller as updates
from angerona.gui.main_window import MainWindow
from angerona.gui.pages import SettingsDialog
from angerona.updater.github_updater import UpdateReport

BASE, TARGET = "a" * 40, "b" * 40


def _until(predicate):
    clock = QElapsedTimer()
    clock.start()
    while not predicate() and clock.elapsed() < 3000:
        QTest.qWait(10)
    assert predicate()


@pytest.fixture
def owned():
    app = QApplication.instance()
    owns = app is None
    if owns:
        app = QApplication([])
    previous = app.quitOnLastWindowClosed()
    app.setQuitOnLastWindowClosed(False)
    state = SimpleNamespace(app=app, owners=[], controllers=[], releases=[])
    try:
        yield state
    finally:
        for event in state.releases:
            event.set()
        workers = []
        for controller in state.controllers:
            workers.extend(reader.thread for reader in (controller._check, controller._download) if reader.thread is not None)
            controller.close()
        for worker in workers:
            worker.join(2)
            assert not worker.is_alive()
        for owner in reversed(state.owners):
            if isValid(owner):
                delete(owner)
        if owns:
            app.shutdown()
            assert QApplication.instance() is None
        else:
            app.setQuitOnLastWindowClosed(previous)


def _producer(owned, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    owned.releases.append(release)
    calls = []
    report = UpdateReport("checked", 10, "1.14.0", BASE, TARGET, "", "none", "different")

    def check(state, root, *, force):
        calls.append((threading.get_ident(), force))
        entered.set()
        assert release.wait(10), "inert producer was not released"
        return report

    monkeypatch.setattr(updates, "check_installed_updates", check)
    return entered, release, calls, report


def _owner(owned, tmp_path, *, enabled=False):
    class Owner(QWidget):
        _on_daily_update_report = MainWindow._on_daily_update_report
        _open_setup = MainWindow._open_setup

        def _update_message(self, title, text, *, question=False):
            self.prompts.append((title, text, question))
            return False

    owner = Owner()
    owner.config = SimpleNamespace(data_dir=tmp_path, github_daily_check_enabled=enabled)
    owner.prompts = []
    owner._update_prompt_revision = ""
    controller = updates.UpdateController(owner.config, tmp_path / "source", owner)
    controller._timer.stop()
    controller._initial.stop()
    owner._update_controller = controller
    controller.update_available.connect(owner._on_daily_update_report)
    owned.owners.append(owner)
    owned.controllers.append(controller)
    return owner, controller


def test_manual_settings_check_uses_one_fetch_visible_status_and_the_real_prompt_path(owned, tmp_path, monkeypatch):
    entered, release, calls, _ = _producer(owned, monkeypatch)
    owner, controller = _owner(owned, tmp_path)

    class Settings(QWidget):
        _on_check_updates = SettingsDialog._on_check_updates
        _shared_update_status = SettingsDialog._shared_update_status
        _apply_update_check = SettingsDialog._apply_update_check

    settings = Settings(owner)
    settings._shared_update_controller = controller
    settings._accept_async_results = True
    settings._update_status = QLabel(settings)
    settings._update_status.setTextFormat(Qt.PlainText)
    settings._btn_check = QPushButton(settings)
    controller.status_changed.connect(settings._shared_update_status)
    controller.report_ready.connect(settings._apply_update_check)
    ticks = []
    heartbeat = QTimer(owner)
    heartbeat.setInterval(10)
    heartbeat.timeout.connect(lambda: ticks.append(1))
    heartbeat.start()
    settings._on_check_updates()
    _until(lambda: entered.is_set() and len(ticks) >= 2)
    assert not settings._btn_check.isEnabled() and not owner.prompts
    release.set()
    _until(lambda: len(owner.prompts) == 1)
    assert len(calls) == 1 and calls[0][0] != threading.get_ident() and calls[0][1] is True
    assert "GitHub main differs" in settings._update_status.text()
    assert settings._btn_check.isEnabled() and settings._update_status.textFormat() == Qt.PlainText


@pytest.mark.parametrize("pending", [False, True])
def test_opt_out_revokes_active_or_queued_automatic_delivery(owned, tmp_path, monkeypatch, pending):
    entered, release, calls, _ = _producer(owned, monkeypatch)
    owner, controller = _owner(owned, tmp_path, enabled=True)
    reports = []
    controller.report_ready.connect(reports.append)
    controller.check_daily()
    _until(entered.is_set)
    if pending:
        controller._check._timer.stop()
        release.set()
        deadline = time.monotonic() + 2
        while controller._check._results.empty() and time.monotonic() < deadline:
            time.sleep(0.001)
        assert not controller._check._results.empty()
    controller.set_daily_preference(False)
    owner.config.github_daily_check_enabled = False
    release.set()
    if pending:
        controller._check._poll()
    _until(lambda: not controller._check.busy)
    assert len(calls) == 1 and not reports and not owner.prompts


def test_manual_intent_claims_active_daily_fetch_even_after_opt_out(owned, tmp_path, monkeypatch):
    entered, release, calls, _ = _producer(owned, monkeypatch)
    owner, controller = _owner(owned, tmp_path, enabled=True)
    controller.check_daily()
    _until(entered.is_set)
    controller.set_daily_preference(False)
    owner.config.github_daily_check_enabled = False
    controller.check_now()
    release.set()
    _until(lambda: len(owner.prompts) == 1)
    assert len(calls) == 1


def test_deleting_parent_revokes_plain_fetch_state_and_retires_the_worker(owned, tmp_path, monkeypatch):
    entered, release, _, _ = _producer(owned, monkeypatch)
    owner, controller = _owner(owned, tmp_path)
    controller.check_now()
    _until(entered.is_set)
    worker, cancelled = controller._check.thread, controller._cancelled
    delete(owner)
    assert cancelled.is_set() and not controller.alive()
    release.set()
    worker.join(2)
    assert not worker.is_alive() and not owner.prompts


def test_deleting_parent_revokes_detached_stage_cancellation_without_late_delivery(owned, tmp_path, monkeypatch):
    owner, controller = _owner(owned, tmp_path)
    entered, release, cancellation_seen = threading.Event(), threading.Event(), threading.Event()
    owned.releases.append(release)
    callbacks = []

    def prepare(root, state, revision, *, cancelled):
        entered.set()
        assert release.wait(10)
        if cancelled():
            cancellation_seen.set()
        return SimpleNamespace(status="cancelled")

    monkeypatch.setattr(updates, "prepare_source_update", prepare)
    controller._last_report = UpdateReport("checked", 10, "1.14.0", BASE, TARGET, "", "none", "different")
    controller._last_origin = "manual"
    controller._last_serial = controller._serial
    controller.candidate_ready.connect(callbacks.append)
    controller.download_source_candidate(TARGET)
    _until(entered.is_set)
    worker = controller._download.thread
    delete(owner)
    release.set()
    worker.join(2)
    assert cancellation_seen.is_set() and not worker.is_alive() and callbacks == []


@pytest.mark.parametrize("signal", ["status", "report"])
@pytest.mark.parametrize("action", ["close", "delete"])
def test_reentrant_receiver_cannot_cause_late_prompt_or_invalid_signal_emit(owned, tmp_path, monkeypatch, signal, action):
    entered, release, _, _ = _producer(owned, monkeypatch)
    owner, controller = _owner(owned, tmp_path)
    revoked = []

    def revoke(value):
        if signal == "status" and value.startswith("Checking"):
            return
        revoked.append(True)
        controller.close() if action == "close" else delete(controller)

    (controller.status_changed if signal == "status" else controller.report_ready).connect(revoke)
    controller.check_now()
    _until(entered.is_set)
    release.set()
    _until(lambda: bool(revoked))
    assert not controller.alive() and not owner.prompts


@pytest.mark.parametrize("action", ["close", "delete_parent"])
def test_modal_prompt_continuation_rechecks_authority_and_owner(owned, tmp_path, monkeypatch, action):
    entered, release, _, _ = _producer(owned, monkeypatch)
    owner, controller = _owner(owned, tmp_path)
    prepared = []
    monkeypatch.setattr(updates, "prepare_source_update", lambda *args, **kwargs: prepared.append(True))

    def prompt(title, text, *, question=False):
        owner.prompts.append((title, text, question))
        controller.close() if action == "close" else delete(owner)
        return True

    owner._update_message = prompt
    controller.check_now()
    _until(entered.is_set)
    release.set()
    _until(lambda: bool(owner.prompts))
    assert not prepared and not controller.alive()


def test_privacy_defaults_and_local_profile_explicitly_reset_an_existing_opt_in(owned, tmp_path):
    class Privacy(QWidget):
        _restore_privacy_defaults = SettingsDialog._restore_privacy_defaults
        def _select_tab(self, value):
            return True

    privacy = Privacy()
    owned.owners.append(privacy)
    privacy._github_daily_check = QCheckBox(privacy)
    privacy._github_daily_check.setChecked(True)
    privacy._aria_test_status = QLabel(privacy)
    privacy._restore_privacy_defaults()
    assert privacy._github_daily_check.isChecked() is False
    for profile in setup_wizard.SETUP_PROFILES.values():
        assert profile["github_daily_check_enabled"] is False
    class Profile(QWidget):
        _do_action = setup_wizard.SetupWizard._do_action
        _set_widget = setup_wizard.SetupWizard._set_widget

    profile = Profile()
    owned.owners.append(profile)
    profile._profile_combo = QComboBox(profile)
    profile._profile_combo.addItems(list(setup_wizard.SETUP_PROFILES))
    profile._progress = QLabel(profile)
    checkbox = QCheckBox(profile)
    profile._widgets = [{"github_daily_check_enabled": checkbox}]
    for index in range(profile._profile_combo.count()):
        checkbox.setChecked(True)
        profile._profile_combo.setCurrentIndex(index)
        profile._do_action("apply_profile")
        assert checkbox.isChecked() is False


def test_declined_setup_network_consent_leaves_configuration_unchanged(owned, tmp_path, monkeypatch):
    config = Config(data_dir=tmp_path)
    values = {field.key: getattr(config, field.key) for step in setup_wizard.STEPS for field in step.fields if field.kind in setup_wizard.CONFIG_KINDS}
    values["github_daily_check_enabled"] = True

    class Wizard(QWidget):
        _finish = setup_wizard.SetupWizard._finish
        def _staged(self):
            return values, {}, {}

    wizard = Wizard()
    owned.owners.append(wizard)
    wizard._cfg = config
    before = dict(vars(config))
    monkeypatch.setattr(setup_wizard.QMessageBox, "question", lambda *args, **kwargs: QMessageBox.No)
    wizard._finish()
    assert vars(config) == before and not config.settings_path.exists()


def test_accepted_setup_enabling_daily_checks_starts_the_owned_due_path(owned, tmp_path, monkeypatch):
    entered, release, calls, _ = _producer(owned, monkeypatch)
    owner, controller = _owner(owned, tmp_path)

    class AcceptedSetup:
        def __init__(self, config, **kwargs):
            self.config = config
        def exec(self):
            self.config.github_daily_check_enabled = True
            return 1

    monkeypatch.setattr(setup_wizard, "SetupWizard", AcceptedSetup)
    owner._open_setup()
    _until(entered.is_set)
    assert calls[0][1] is False
    release.set()
    _until(lambda: not controller._check.busy)


def test_daily_off_has_no_owned_periodic_or_initial_wakeup(owned, tmp_path):
    owner = QWidget()
    config = SimpleNamespace(data_dir=tmp_path, github_daily_check_enabled=False)
    controller = updates.UpdateController(config, tmp_path / "source", owner)
    owned.owners.append(owner)
    owned.controllers.append(controller)
    assert not controller._timer.isActive() and not controller._initial.isActive()
    controller.check_daily()
    assert controller._check.thread is None


def test_packaged_release_with_unknown_source_only_opens_release_review(owned, tmp_path, monkeypatch):
    report = UpdateReport("checked", 10, "1.14.0", "", TARGET, "v1.15.0", "newer", "unknown")
    monkeypatch.setattr(updates, "check_installed_updates", lambda *args, **kwargs: report)
    monkeypatch.setattr(updates, "prepare_source_update", lambda *args, **kwargs: pytest.fail("packaged release must not enter source staging"))
    owner, controller = _owner(owned, tmp_path)
    controller.check_now()
    _until(lambda: bool(owner.prompts))
    title, text, question = owner.prompts[0]
    assert title == "Angerona release available" and question is False
    assert "https://github.com/Ag3nt47/AngeronaSuite/releases/tag/v1.15.0" in text
    assert "signed-release" in text and "cannot be established" in text
    assert controller._download.thread is None


@pytest.mark.parametrize("manual_status", ["checked", "not_due"])
def test_manual_claim_of_an_automatic_not_due_result_issues_only_one_force_attempt(owned, tmp_path, monkeypatch, manual_status):
    owner, controller = _owner(owned, tmp_path, enabled=True)
    entered, release = threading.Event(), threading.Event()
    owned.releases.append(release)
    calls = []
    fetched = []
    report = UpdateReport("checked", 10, "1.14.0", BASE, TARGET, "", "none", "different")

    def check(state, root, *, force):
        calls.append(force)
        if not force:
            entered.set()
            assert release.wait(10)
            return UpdateReport("not_due", 10, "1.14.0", message="Daily interval not elapsed.")
        if manual_status == "checked":
            fetched.append(True)
            return report
        return UpdateReport("not_due", 10, "1.14.0", message="The 60-second manual retry floor is active.")

    monkeypatch.setattr(updates, "check_installed_updates", check)
    controller.check_daily()
    _until(entered.is_set)
    controller.set_daily_preference(False)
    owner.config.github_daily_check_enabled = False
    controller.check_now()
    release.set()
    _until(lambda: len(calls) == 2 and not controller._check.busy)
    assert calls == [False, True]
    assert len(fetched) == (1 if manual_status == "checked" else 0)
    assert len(owner.prompts) == (1 if manual_status == "checked" else 0)
