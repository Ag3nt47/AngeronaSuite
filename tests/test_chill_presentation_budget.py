"""Chill budgets lower optional GUI work while manual and security paths stay live."""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QPushButton, QVBoxLayout, QWidget

from angerona.core.background_pacing import BackgroundPacingController
from angerona.core.chill_mode import chill_ai_blocked, set_chill_ai_blocked
from angerona.gui import presentation_timer
from angerona.gui.main_window import MainWindow
from angerona.gui.pages import StatusStrip
from angerona.gui.presentation_timer import PresentationTimer, set_chill_presentation
from angerona.gui.system_pulse import SystemPulseCard


@pytest.fixture
def controller(monkeypatch):
    value = BackgroundPacingController()
    monkeypatch.setattr(presentation_timer, "get_pacing_controller", lambda: value)
    monkeypatch.setattr("angerona.core.background_pacing.get_pacing_controller", lambda: value)
    yield value
    set_chill_presentation(False)


def test_chill_stops_cosmetic_callbacks_and_slows_views_without_blocking_manual_work(controller):
    window = QWidget()
    window.show()
    window.isActiveWindow = lambda: True
    ordinary = PresentationTimer(window)
    cosmetic = PresentationTimer(window, cosmetic=True)
    counts = {"ordinary": 0, "cosmetic": 0, "manual": 0}

    def count(key):
        counts[key] += 1

    ordinary.timeout.connect(lambda: count("ordinary"))
    cosmetic.timeout.connect(lambda: count("cosmetic"))
    button = QPushButton("Refresh now", window)
    button.clicked.connect(lambda: count("manual"))
    ordinary.start(40)
    cosmetic.start(40)
    try:
        QTest.qWait(160)
        assert counts["ordinary"] >= 1 and counts["cosmetic"] >= 1
        set_chill_presentation(True)
        assert ordinary.isActive() and ordinary.interval() == 15000
        assert not cosmetic.isActive() and cosmetic._requested
        before = counts.copy()
        button.click()
        # A one-shot first read/manual operation keeps its requested latency.
        initial = PresentationTimer(window)
        initial.setSingleShot(True)
        initial.timeout.connect(lambda: count("manual"))
        initial.start(20)
        QTest.qWait(100)
        assert counts == {"ordinary": before["ordinary"], "cosmetic": before["cosmetic"],
                          "manual": 2}
        window.isActiveWindow = lambda: False
        ordinary.refresh()
        assert ordinary.interval() == 30000
        set_chill_presentation(False)
        assert ordinary.interval() == 40 and cosmetic.isActive()
    finally:
        ordinary.stop()
        cosmetic.stop()
        window.close()
        window.deleteLater()


def test_pulse_chill_sampling_budget_visibility_and_manual_request(monkeypatch, controller):
    sampled = threading.Event()

    def sample(_collector):
        sampled.set()

    monkeypatch.setattr("angerona.gui.system_pulse._SystemPulseCollector.__call__", sample)
    window = QWidget()
    card = SystemPulseCard(window)
    QVBoxLayout(window).addWidget(card)
    window.show()
    QApplication.instance().processEvents()
    try:
        assert card._timer.interval() == 2000 and card._timer.isActive()
        card.set_chill_mode(True, active=True)
        assert card._timer.interval() == 30000
        card.set_chill_mode(True, active=False)
        assert card._timer.interval() == 60000
        card.request_sample()
        assert sampled.wait(1)  # Manual request does not wait for the minute timer.
        window.hide()
        QApplication.instance().processEvents()
        assert not card._timer.isActive()
        window.show()
        QApplication.instance().processEvents()
        assert card._timer.isActive()
        card.hide()
        assert not card._timer.isActive()
        card.set_external_view_active(True)
        assert card._timer.isActive()  # visible footer can share a hidden card's sampler
        window.showMinimized()
        QApplication.instance().processEvents()
        assert not card._timer.isActive()
        window.showNormal()
        card.set_chill_mode(False)
        assert card._timer.interval() == 2000
    finally:
        card.shutdown()
        card._sample_worker.join(2)
        window.close()
        window.deleteLater()


def test_chill_ribbon_has_no_autopan_timer_but_keyboard_and_scrollbar_still_work(controller):
    modules = {f"Fixture {index:02d}": SimpleNamespace(
        name=f"Fixture {index:02d}", CODE=f"T{index:04d}", status="running", health=100,
        health_state="ok", health_note="ready",
    ) for index in range(40)}
    manager = SimpleNamespace(modules=modules, is_enabled=lambda _name: True)
    window = QWidget()
    window.resize(600, 160)
    strip = StatusStrip(manager)
    QVBoxLayout(window).addWidget(strip)
    window.show()
    QApplication.instance().processEvents()
    try:
        set_chill_presentation(True)
        strip.refresh()
        assert not strip._pan_timer.isActive()
        bar = strip._scroll.horizontalScrollBar()
        assert bar.maximum() > 0
        bar.setValue(bar.maximum())
        last = list(strip._chips.values())[-1]
        clicked = []
        last.clicked.connect(clicked.append)
        last.setFocus()
        QTest.keyClick(last, Qt.Key_Return)
        assert clicked == [last._name]
        assert bar.value() == bar.maximum()
        assert not strip._pan_timer.isActive()
    finally:
        window.close()
        window.deleteLater()


def test_auto_escalation_preserves_ai_block_and_manual_full_is_the_only_clear(monkeypatch):
    monkeypatch.setenv("ANGERONA_CHILL_AI_BLOCKED", "0")
    config = SimpleNamespace()
    set_chill_ai_blocked(config, True)
    button = SimpleNamespace(set_full_label=lambda _v: None, setStyleSheet=lambda _v: None,
                             setToolTip=lambda _v: None)
    ai = SimpleNamespace(_chill_paused=True)
    harness = SimpleNamespace(
        config=config, _eco_on=True, _apply_chill_throttles=lambda _v: None,
        _set_chill_runtime=lambda _v: None, eco_btn=button,
        _ECO_HEAVY_MODULES=("AI Triage (Ollama)",),
        _CHILL_USER_ONLY_MODULES=MainWindow._CHILL_USER_ONLY_MODULES,
        manager=SimpleNamespace(modules={"AI Triage (Ollama)": ai}, is_enabled=lambda _n: True),
        _chill_policy=SimpleNamespace(disable=lambda: None),
    )
    assert not MainWindow._wake_chill_modules(harness, auto=True)
    assert chill_ai_blocked(config) and ai._chill_paused
    called = []
    harness._wake_chill_modules = lambda **kwargs: called.append(kwargs)
    MainWindow._toggle_eco_mode(harness)
    assert not chill_ai_blocked(config)
    assert called == [{"auto": False}]


def test_hidden_chill_flow_write_does_not_depend_on_even_panel_tick():
    calls = []
    harness = SimpleNamespace(
        _usage_reconciler=SimpleNamespace(request=lambda: None),
        _quiet_chill_active=lambda: True, _current_refresh_plan=lambda: (60000, 99, 2, 2, 5),
        timer=SimpleNamespace(interval=lambda: 60000), _tick_count=5,
        red_swords=SimpleNamespace(set_active=lambda _v: None),
        shark_engine=SimpleNamespace(is_running=False), red_team_engine=SimpleNamespace(is_running=False),
        _check_threat_animation=lambda: None,
        _write_flow_metrics_async=lambda: calls.append("flow"),
    )
    MainWindow._refresh_body(harness)
    assert calls == ["flow"]


@pytest.mark.parametrize("cloud_enabled", [False, True])
def test_aria_keeps_chill_explanation_and_uses_cloud_only_when_configured(monkeypatch, cloud_enabled):
    reason = "Local AI is off while Chill is enabled. Switch Chill off manually to enable Ollama."
    monkeypatch.setattr("angerona.engines.ollama_client.call", lambda *_a, **_k: {
        "error": reason, "error_type": "ChillMode",
    })
    cloud_calls = []
    monkeypatch.setattr("angerona.engines.ai_consult.consult_ai", lambda *_a, **_k:
                        cloud_calls.append(1) or {"text": "explicit cloud reply", "provider": "fixture"})
    owner = SimpleNamespace(
        config=SimpleNamespace(aria_cloud_fallback=cloud_enabled),
        _ARIA_ARCH="architecture", _ARIA_COACH="coach", _aria_context=lambda: "",
        _looks_like_lookup=lambda _q: False,
    )
    answer = MainWindow._aria_converse(owner, "Explain this situation")
    assert reason in answer
    assert len(cloud_calls) == int(cloud_enabled)
    assert ("explicit cloud reply" in answer) is cloud_enabled


def test_blocked_ollama_panel_shows_manual_full_requirement_and_disables_retry(monkeypatch):
    from angerona.core import ollama_lifecycle
    from angerona.gui.ollama_status import OllamaStatusPanel

    reason = "Local AI is off while Chill is enabled. Switch Chill off manually to enable Ollama."
    monkeypatch.setattr(ollama_lifecycle, "startup_snapshot", lambda _host:
                        ollama_lifecycle.OllamaStartupStatus("blocked", "Chill Mode", 0, reason))
    calls = []
    monkeypatch.setattr(ollama_lifecycle, "request_ollama_start", lambda *_a: calls.append(1))
    panel = OllamaStatusPanel(lambda: "http://127.0.0.1:11434", retry=True)
    try:
        assert panel.progress.value() == 0
        assert reason in panel.label.text()
        assert not panel.retry_button.isEnabled()
        panel.retry_button.click()
        assert calls == []
    finally:
        panel.close()
        panel.deleteLater()


def test_floating_orb_stops_idle_frames_in_chill_but_manual_services_stay_live(monkeypatch, controller):
    from angerona.gui.holographic_orb import HolographicOrb

    monkeypatch.setattr("angerona.gui.holographic_orb.motion_allowed", lambda _cfg: True)
    orb = HolographicOrb(SimpleNamespace(holographic_orb_x=-1, holographic_orb_y=-1))
    ticks, selected = [], []
    orb._tick.timeout.connect(lambda: ticks.append(1))
    orb.serviceTriggered.connect(selected.append)
    orb.show_token()
    try:
        QTest.qWait(160)
        assert orb._tick.isActive() and ticks
        set_chill_presentation(True)
        before = len(ticks)
        phase = orb._phase
        assert not orb._tick.isActive() and orb._tick._requested
        orb.set_menu_expanded(True, animated=False)
        QApplication.instance().processEvents()
        QTest.mouseClick(orb, Qt.LeftButton, pos=orb._node_rects["core"].center().toPoint())
        QTest.qWait(100)
        assert selected == ["core"]
        assert len(ticks) == before and orb._phase == phase
        set_chill_presentation(False)
        assert orb._tick.isActive()
        QTest.qWait(100)
        assert len(ticks) > before
    finally:
        orb.hide_token()
        orb.deleteLater()
