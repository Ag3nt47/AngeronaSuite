"""The FPS meter measures completed paints and never invents hidden frames."""
from __future__ import annotations

from unittest.mock import Mock

from PySide6.QtCore import QCoreApplication, QEvent, QRect
from PySide6.QtWidgets import QApplication, QWidget

from angerona.gui.dashboard_footer import DashboardFooter
from angerona.gui.responsiveness_monitor import FrameSampler, ResponsivenessMonitor


class Clock:
    now = 10.0

    def __call__(self):
        return self.now


def _fixture():
    owner = QWidget()
    owner.resize(800, 100)
    footer = DashboardFooter(owner)
    footer.resize(780, footer.height())
    controller = Mock()
    controller.snapshot.return_value = {
        "enabled": True, "multiplier": 1, "level": "normal", "reason": "Normal responsiveness",
    }
    clock = Clock()
    monitor = ResponsivenessMonitor(footer, owner, controller=controller, clock=clock)
    monitor.sample_ready.connect(footer.update_responsiveness)
    owner.show()
    QApplication.instance().processEvents()
    monitor.set_active(True)
    monitor._timer.stop()  # deterministic clock/ticks, without real waits
    return owner, footer, controller, clock, monitor


def _dispose(owner, monitor):
    monitor.close()
    owner.close()
    owner.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


def test_frame_sampler_counts_real_paints_and_expires_history():
    sampler = FrameSampler()
    sampler.reset(10.0)
    assert sampler.snapshot(10.5)["fps"] is None
    for index in range(1, 61):
        sampler.record(10.0 + index / 30.0, 0.0)
    sample = sampler.snapshot(12.0)
    assert sample["fps"] == 30.0
    assert sample["percent"] == 100.0
    sampler.record(15.0, 2_000.0)
    sample = sampler.snapshot(15.0)
    assert sample["fps"] == 0.5
    assert sample["worst_lag_ms"] == 2_000.0
    assert sampler.snapshot(18.0)["fps"] == 0.0
    for index in range(1000):
        sampler.record(20 + index / 30.0, 0.0)
    assert len(sampler._frames) <= 120


def test_heartbeat_requests_only_small_region_and_counts_delivered_paint(monkeypatch):
    owner, footer, controller, clock, monitor = _fixture()
    try:
        update = Mock(wraps=footer.update)
        monkeypatch.setattr(footer, "update", update)
        clock.now += 0.034
        monitor._tick()
        assert update.call_args.args == (footer.heartbeat_rect(),)
        assert isinstance(update.call_args.args[0], QRect)
        assert len(monitor._sampler._frames) == 0
        clock.now += 0.1
        QApplication.instance().processEvents()
        assert len(monitor._sampler._frames) == 1
        assert monitor._sampler._frames[-1][1] >= 99
        footer.grab()  # incidental paints do not fabricate more heartbeat frames
        assert len(monitor._sampler._frames) == 1
    finally:
        _dispose(owner, monitor)


def test_stall_reports_delayed_frames_and_pause_clears_visible_lease():
    owner, footer, controller, clock, monitor = _fixture()
    try:
        controller.begin_ui_monitoring.assert_called_once_with()
        controller.report_ui.assert_not_called()
        assert footer._fps == "FPS measuring…"
        clock.now += 4.0
        monitor._tick()
        report = controller.report_ui.call_args
        assert report.args == (0.0,)
        assert report.kwargs["worst_lag_ms"] >= 3_900
        assert "FPS 0 (0%)" == footer._fps
        monitor.set_active(False)
        assert not monitor._timer.isActive()
        assert footer._fps == "FPS paused"
        assert controller.report_ui.call_args.kwargs == {"active": False}
        assert not monitor._sampler._frames
        clock.now += 60
        monitor.set_active(True)
        monitor._timer.stop()
        assert footer._fps == "FPS measuring…"
        assert monitor._sampler.snapshot(clock.now)["fps"] is None
    finally:
        _dispose(owner, monitor)


def test_hidden_minimized_disabled_and_destroyed_monitor_clear_pressure():
    owner, footer, controller, clock, monitor = _fixture()
    try:
        owner.hide()
        monitor._tick()
        assert not monitor._active
        assert controller.report_ui.call_args.kwargs == {"active": False}
        owner.showMinimized()
        monitor.set_active(True)
        monitor._tick()
        assert not monitor._active
        owner.showNormal()
        monitor.set_active(True)
        monitor._timer.stop()
        monitor.set_enabled(False)
        controller.report_ui.reset_mock()
        clock.now += 3
        monitor._tick()
        assert not controller.report_ui.called
        assert monitor._active  # disabling pacing preserves the truthful meter
        owner.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        assert monitor._closed
        assert controller.report_ui.call_args.kwargs == {"active": False}
    finally:
        if not monitor._closed:
            _dispose(owner, monitor)


def test_host_samples_reused_without_new_sampling_or_invalid_pressure():
    owner, _footer, controller, _clock, monitor = _fixture()
    try:
        for sample in ({"error": "unavailable", "cpu": 99}, {}, {"cpu": float("nan")}, {"cpu": 101}):
            monitor.update_host_sample(sample)
        controller.report_host.assert_not_called()
        monitor.update_host_sample({"cpu": 93.5})
        controller.report_host.assert_called_once_with(93.5)
    finally:
        _dispose(owner, monitor)
