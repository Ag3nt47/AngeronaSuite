"""Real offscreen Qt presentation recovery; no Core, transport or host action."""
from __future__ import annotations

import json
from types import MethodType, SimpleNamespace

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QRect, Qt
from PySide6.QtGui import QRegion
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QLabel, QMainWindow, QPushButton, QVBoxLayout, QWidget
from shiboken6 import delete, isValid

from angerona.gui import display_recovery, holographic_orb
from angerona.gui.display_recovery import DisplayRecovery, DisplayRecoveryNotice
from angerona.gui.header_controls import PanelRevealOverlay
from angerona.gui.holographic_orb import HolographicOrbController
from angerona.gui.main_window import MainWindow


@pytest.fixture
def scene(monkeypatch):
    app = QApplication.instance()
    logs = []
    monkeypatch.setattr("angerona.core.crashlog._write", lambda kind, text: logs.append((kind, text)))
    owner = QMainWindow()
    owner.resize(640, 420)
    central = QWidget()
    central.setStyleSheet("background:#112233")
    layout = QVBoxLayout(central)
    layout.addWidget(QLabel("Synthetic dashboard · no sensors or host actions"))
    owner.setCentralWidget(central)
    owner._termination_started = False
    owner._restore_dashboard_display = MethodType(MainWindow._restore_dashboard_display, owner)
    owner._request_display_restore = MethodType(MainWindow._request_display_restore, owner)
    failures = []
    owner._display_restore_failed = failures.append
    state = SimpleNamespace(app=app, owner=owner, central=central, logs=logs, failures=failures)
    try:
        yield state
    finally:
        controller = getattr(owner, "_holographic_orb", None)
        if controller is not None and isValid(controller):
            controller.shutdown()
        if isValid(owner):
            owner._termination_started = True
            display = getattr(owner, "_display_recovery", None)
            if display is not None:
                display.cancel()
            delete(owner)
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        app.processEvents()


def wait_until(predicate, timeout=1000):
    for _ in range(timeout // 5):
        if predicate():
            return
        QTest.qWait(5)
    assert predicate()


def coordinator(scene, normal, plain, monkeypatch):
    monkeypatch.setattr(DisplayRecovery, "ATTEMPT_MS", 25)
    result = DisplayRecovery(
        scene.owner, normal=normal, plain=plain, failed=scene.failures.append,
        terminating=lambda: scene.owner._termination_started,
    )
    scene.owner._display_recovery = result
    return result


def test_supported_restore_delivers_real_central_paint_and_private_record(scene):
    scene.owner._request_display_restore()
    display = scene.owner._display_recovery
    wait_until(lambda: not display._active)
    assert scene.owner.isVisible() and scene.central.isVisible()
    assert display.records[-1]["outcome"] == "paint-observed"
    assert display.records[-1]["attempt"] == 1
    assert scene.central.grab().toImage().pixelColor(2, 2).name() == "#112233"
    assert not scene.failures
    assert [kind for kind, _text in scene.logs] == ["DISPLAY_RECOVERY"] * 2
    assert json.loads(scene.logs[-1][1]) == display.records[-1]


def test_normal_restore_exception_falls_forward_once_without_leaking_text(scene, monkeypatch):
    calls = []

    def normal():
        calls.append("normal")
        raise RuntimeError("private path or secret must never reach diagnostic text")

    def plain():
        calls.append("plain")
        scene.owner.showNormal()

    display = coordinator(scene, normal, plain, monkeypatch)
    assert display.request()
    wait_until(lambda: not display._active)
    assert calls == ["normal", "plain"]
    assert display.records[-1]["outcome"] == "paint-observed"
    assert display.records[-1]["attempt"] == 2
    assert any(row["error_type"] == "RuntimeError" for row in display.records)
    assert "private path" not in json.dumps(list(display.records))
    assert "secret" not in str(scene.logs)


def test_two_unpainted_attempts_end_at_notice_without_background_retry(scene, monkeypatch):
    calls = []
    display = coordinator(scene, lambda: calls.append("normal"), lambda: calls.append("plain"), monkeypatch)
    display.request()
    wait_until(lambda: bool(scene.failures))
    QTest.qWait(100)
    assert calls == ["normal", "plain"]
    assert len(scene.failures) == 1
    assert not display._active and not display._timer.isActive()
    assert display.records[-1] == {
        "schema": 1, "phase": "notice", "outcome": "failed", "attempt": 2, "error_type": ""}


@pytest.mark.parametrize("stop", [False, True])
def test_operator_hide_or_stop_fences_pending_retry(scene, monkeypatch, stop):
    calls = []
    display = coordinator(scene, scene.owner.showNormal, lambda: calls.append("plain"), monkeypatch)
    display.request()
    if stop:
        scene.owner._termination_started = True
    else:
        scene.owner.hide()
    QTest.qWait(100)
    assert not calls and not scene.failures
    assert not display._active
    if stop:
        assert display.request() is False


def test_new_request_replaces_old_deadline_and_history_is_bounded(scene, monkeypatch):
    calls = []
    display = coordinator(scene, lambda: calls.append("normal"), lambda: calls.append("plain"), monkeypatch)
    for _ in range(20):
        display.request()
    wait_until(lambda: bool(scene.failures))
    assert calls.count("normal") == 20 and calls.count("plain") == 1
    assert len(scene.failures) == 1 and len(display.records) == 16


@pytest.mark.parametrize("clock_failure", ["raises", "nan", "infinity", "verify-raises", "frozen", "regressed"])
def test_optional_clock_failure_cannot_block_normal_restore_or_cause_infinite_retry(scene, monkeypatch, clock_failure):
    calls = []
    samples = []

    def clock():
        samples.append(True)
        if clock_failure == "verify-raises" and len(samples) == 1:
            return 1.0
        if clock_failure in {"raises", "verify-raises"}:
            raise OSError("Private clock detail must not be logged")
        if clock_failure == "frozen":
            return 1.0
        if clock_failure == "regressed":
            return 2.0 if len(samples) == 1 else 1.0
        return float("nan") if clock_failure == "nan" else float("inf")

    monkeypatch.setattr(display_recovery, "time", SimpleNamespace(monotonic=clock))
    display = coordinator(scene, lambda: calls.append("normal"), lambda: calls.append("plain"), monkeypatch)
    display.request()
    wait_until(lambda: bool(scene.failures))
    QTest.qWait(75)
    assert calls == ["normal", "plain"]
    assert len(scene.failures) == 1
    if clock_failure != "frozen":
        assert any(row["phase"] == "clock" and row["outcome"] == "unavailable" for row in display.records)
    assert "Private clock detail" not in str(scene.logs)


def test_clock_failure_still_allows_first_attempt_real_qt_paint(scene, monkeypatch):
    def unavailable():
        raise RuntimeError("optional clock unavailable")

    monkeypatch.setattr(display_recovery, "time", SimpleNamespace(monotonic=unavailable))
    display = coordinator(scene, scene.owner.showNormal, lambda: pytest.fail("Plain retry was not needed"), monkeypatch)
    display.request()
    wait_until(lambda: not display._active)
    assert display.records[-1]["outcome"] == "paint-observed"
    assert display.records[-1]["attempt"] == 1


def test_retired_request_and_attempt_callbacks_cannot_consume_new_request(scene, monkeypatch):
    calls = []
    display = coordinator(scene, lambda: calls.append("normal"), lambda: calls.append("plain"), monkeypatch)
    display.request()
    stale_epoch = display._epoch
    display.request()
    display._verify(stale_epoch, 1)
    display._verify(display._epoch, 0)
    assert calls == ["normal", "normal"] and display._attempt == 1
    display.cancel()


def test_plain_retry_restores_only_owned_masks_and_preserves_disabled_controls(scene):
    overlay = PanelRevealOverlay(scene.central)
    scene.owner._panel_reveal = overlay
    other = QWidget(scene.owner, Qt.Window)
    original = QRegion(QRect(0, 0, 240, 180))
    other.setMask(original)
    other._angerona_reveal_original_mask = QRegion(original)
    overlay._captured_windows.add(other)
    other.setMask(QRegion(QRect(0, 0, 5, 5)))
    unrelated = QRegion(QRect(0, 0, 100, 90))
    scene.owner.setMask(unrelated)
    label = scene.central.findChild(QLabel)
    label.setEnabled(False)
    label.setUpdatesEnabled(False)
    MainWindow._restore_dashboard_display(scene.owner, plain=True)
    assert other.mask() == original
    assert scene.owner.mask() == unrelated
    assert not label.isEnabled() and label.updatesEnabled()
    assert overlay._shut_down


def test_failed_optional_cleanup_and_orb_cannot_block_direct_plain_qt_show(scene):
    failures = []

    def broken():
        raise RuntimeError("optional decoration was deleted")

    scene.owner._panel_reveal = SimpleNamespace(shutdown=broken)
    scene.owner._holographic_orb = SimpleNamespace(disable_display_motion=broken, show_main_now=broken)
    scene.owner._display_recovery = SimpleNamespace(decoration_failed=failures.append, cancel=lambda: None)
    try:
        MainWindow._restore_dashboard_display(scene.owner, plain=True)
        assert scene.owner.isVisible() and scene.central.updatesEnabled()
        assert len(failures) == 3
    finally:
        # This inert stand-in is not a native controller owned by the fixture.
        del scene.owner._holographic_orb


def test_notice_is_nonmodal_and_has_original_retry_and_stop_actions(scene):
    calls = []
    notice = DisplayRecoveryNotice(scene.owner, retry=lambda: calls.append("retry"), stop=lambda: calls.append("stop"))
    try:
        notice.show_records([{"phase": "notice", "outcome": "failed"}])
        assert notice.windowModality() == Qt.NonModal
        assert notice.property("_angerona_no_reveal") is True
        assert notice.property("_angerona_orb_ignore") is True
        assert scene.app.activeModalWidget() is None
        buttons = {button.text(): button for button in notice.findChildren(QPushButton)}
        buttons["Retry display"].click()
        assert calls == ["retry"] and not notice.isVisible()
        notice.show()
        buttons["Safe STOP"].click()
        assert calls == ["retry", "stop"]
        assert "protection" in notice.findChild(QLabel).text().lower()
    finally:
        delete(notice)


@pytest.mark.parametrize("trail_failure", [False, True])
def test_orb_restore_shows_qt_owner_before_optional_trail(scene, monkeypatch, trail_failure):
    monkeypatch.setattr(holographic_orb, "motion_allowed", lambda _config: True)
    controller = HolographicOrbController(scene.owner, SimpleNamespace(holographic_orb_enabled=True))
    scene.owner._holographic_orb = controller
    controller._normal_geometries[scene.owner] = QRect(10, 10, 640, 420)
    controller._add_collapsed(scene.owner)
    observations = []

    def trail(*_args, **_kwargs):
        observations.append(scene.owner.isVisible())
        if trail_failure:
            raise RuntimeError("optional presentation failure")
        # No completed signal is delivered at all.

    monkeypatch.setattr(controller, "_start_trail", trail)
    controller.show_main_now()
    assert observations == [True]
    assert scene.owner.isVisible() and not controller.is_collapsed(scene.owner)
    assert controller._display_motion_disabled is trail_failure


def test_late_collapse_token_and_restore_after_stop_cannot_reopen(scene, monkeypatch):
    monkeypatch.setattr(holographic_orb, "motion_allowed", lambda _config: True)
    controller = HolographicOrbController(scene.owner, SimpleNamespace(holographic_orb_enabled=True))
    scene.owner._holographic_orb = controller
    monkeypatch.setattr(controller, "_start_trail", lambda *_args, **_kwargs: None)
    scene.owner.showNormal()
    controller.collapse_window(scene.owner)
    controller.show_main_now()
    QTest.qWait(300)
    assert scene.owner.isVisible() and not controller.orb.isVisible()
    scene.owner.hide()
    scene.owner._termination_started = True
    controller.restore_main()
    controller.restore_window(scene.owner)
    assert not scene.owner.isVisible()


def test_orb_core_route_uses_first_party_display_coordinator(scene):
    controller = HolographicOrbController(scene.owner, SimpleNamespace(holographic_orb_enabled=True))
    scene.owner._holographic_orb = controller
    scene.owner._restore_from_background = scene.owner._request_display_restore
    controller.restore_main()
    wait_until(lambda: not scene.owner._display_recovery._active)
    assert scene.owner._display_recovery.records[-1]["outcome"] == "paint-observed"


@pytest.mark.parametrize("immediate", [False, True])
def test_restore_all_main_uses_coordinator_except_explicit_immediate_path(scene, monkeypatch, immediate):
    controller = HolographicOrbController(scene.owner, SimpleNamespace(holographic_orb_enabled=True))
    scene.owner._holographic_orb = controller
    calls = []
    scene.owner._restore_from_background = lambda: calls.append("coordinator")
    controller._add_collapsed(scene.owner)
    monkeypatch.setattr(controller, "restore_window", lambda window, **kwargs: calls.append((window, kwargs)))
    controller.restore_all(immediate=immediate)
    assert calls == ([(scene.owner, {"immediate": True})] if immediate else ["coordinator"])


@pytest.mark.parametrize("width", [640, 800, 1280, 1920])
def test_chill_caption_explains_live_selected_without_clipping_or_selection_changes(scene, monkeypatch, width):
    from angerona.gui import pages

    monkeypatch.setattr(pages, "AsyncSnapshot", lambda *_args, **_kwargs:
                        SimpleNamespace(busy=False, request=lambda: None, close=lambda: None))
    deep = SimpleNamespace(name="YARA Scanner", status="stopped", _chill_paused=True)
    live = SimpleNamespace(name="Network Monitor", status="running")
    manager = SimpleNamespace(modules={deep.name: deep, live.name: live},
                              config=SimpleNamespace(runtime_chill_active=True), is_enabled=lambda _name: True)
    cards = pages.DashboardCards(SimpleNamespace(), SimpleNamespace(revision=lambda: 1), manager)
    cards.resize(width, 160)
    cards.show()
    try:
        cards.refresh()
        scene.app.processEvents()
        card = cards.c_modules
        assert card.value.text() == "1/2"
        assert card._caption.text() == "Chill:\n1 held"
        assert "in-flight checks may finish" in card.toolTip()
        assert "Checked means selected" in card.toolTip()
        assert manager.is_enabled(deep.name) and deep.status == "stopped"
        expected = card._caption.fontMetrics().boundingRect(
            QRect(0, 0, card._caption.width(), 1000), Qt.TextWordWrap, card._caption.text()).height()
        assert card._caption.height() >= expected
        manager.config.runtime_chill_active = False
        deep._chill_paused = False
        cards.refresh()
        assert card._caption.text() == "Modules running"
    finally:
        cards.close()
        delete(cards)
