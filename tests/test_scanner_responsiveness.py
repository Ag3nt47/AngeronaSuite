import threading
from types import SimpleNamespace

import pytest

from angerona.resilience import scanner
from angerona.modules.yara_scanner import YaraScannerModule


@pytest.fixture
def host_factory(monkeypatch):
    monkeypatch.setattr(scanner.diag, "write_status", lambda *a, **kw: None)
    monkeypatch.setattr(scanner.tok, "is_standdown_requested", lambda: False)
    monkeypatch.setattr(scanner.ScannerHost, "_read_ping", lambda self: "")
    def make(interval=1):
        closed, tick = [], threading.Event()
        ring = SimpleNamespace(backpressure=False, drops=0,
                               close=lambda: closed.append("ring"), write=lambda *a, **kw: True)
        beat = SimpleNamespace(beat=tick.set, close=lambda: closed.append("beat"))
        monkeypatch.setattr(scanner.ipc_ring, "RingWriter", lambda *a, **kw: ring)
        monkeypatch.setattr(scanner.hb, "HeartbeatWriter", lambda *a, **kw: beat)
        host = scanner.ScannerHost(interval=interval)
        host.sensors = [SimpleNamespace(poll=lambda: [], sensor_id=1)]
        return host, closed, tick
    return make


def test_scanner_stop_interrupts_long_interval_and_closes_handles(host_factory):
    host, closed, tick = host_factory(3600)
    thread = threading.Thread(target=host.run)
    thread.start()
    try:
        assert tick.wait(3)
        host.stop()
        thread.join(2)
        assert not thread.is_alive()
        assert closed == ["beat", "ring"]
    finally:
        host.stop()
        thread.join(2)


def test_scanner_failure_still_releases_handles(host_factory):
    host, closed, _ = host_factory()
    def failed():
        raise OSError("sensor failed")
    host.sensors[0].poll = failed
    with pytest.raises(OSError, match="sensor failed"):
        host.run()
    assert closed == ["beat", "ring"]
    with pytest.raises(RuntimeError, match="only run once"):
        host.run()
    assert closed == ["beat", "ring"]


def test_scanner_rejects_duplicate_loop_while_first_is_active(host_factory):
    host, closed, _ = host_factory()
    entered, release = threading.Event(), threading.Event()
    def blocked():
        entered.set()
        assert release.wait(5)
        return []
    host.sensors[0].poll = blocked
    thread = threading.Thread(target=host.run)
    thread.start()
    try:
        assert entered.wait(3)
        with pytest.raises(RuntimeError, match="only run once"):
            host.run()
        assert closed == []
    finally:
        host.stop()
        release.set()
        thread.join(3)
    assert not thread.is_alive()
    assert closed == ["beat", "ring"]


@pytest.mark.parametrize("value", [0, -1, float("nan"), float("inf"), -float("inf")])
def test_invalid_interval_rejected_before_resources(monkeypatch, value):
    monkeypatch.setattr(scanner.ipc_ring, "RingWriter", lambda *a: pytest.fail("opened ring"))
    with pytest.raises(ValueError, match="finite positive"):
        scanner.ScannerHost(interval=value)


def test_tiny_interval_is_bounded(host_factory):
    host, _, _ = host_factory(0.000001)
    assert host.interval == 0.05
    host._shutdown()


def test_backpressure_avoids_enrichment_and_keeps_baseline(monkeypatch):
    import psutil
    rows = []
    monkeypatch.setattr(psutil, "process_iter", lambda *a, **kw: rows)
    sensor = scanner.RawProcessSensor()
    assert list(sensor.poll()) == []
    rows.append(SimpleNamespace(info={"pid": 123}))
    # This process deliberately has no exe/cmdline/oneshot methods.
    assert len(list(sensor.poll(enrich=False))) == 1
    assert list(sensor.poll()) == []


def test_yara_inventory_yields_during_discovery_without_changing_selection(tmp_path):
    for number in range(20):
        (tmp_path / f"f{number:02d}").write_bytes(b"inert")
    normal = YaraScannerModule._fair_batch(tmp_path, "")
    checks = []
    paced = YaraScannerModule._fair_batch(tmp_path, "", checkpoint=lambda n: checks.append(n) or True)
    assert paced == normal
    assert checks == list(range(1, 41))


def test_yara_cancelled_inventory_is_explicitly_incomplete(tmp_path):
    for number in range(20):
        (tmp_path / f"f{number:02d}").write_bytes(b"inert")
    batch = YaraScannerModule._fair_batch(tmp_path, "", checkpoint=lambda n: n < 8)
    assert batch.incomplete and batch.discovery_truncated
    assert batch.discovered < 20


def test_scan_center_checks_cancel_after_pressure_yield(monkeypatch, tmp_path):
    from angerona.core import background_pacing
    from angerona.core.security_scan_center import ScanCancellationToken, SecurityScanCenter

    for number in range(10):
        (tmp_path / f"f{number}").write_bytes(b"inert")
    center = SecurityScanCenter()
    monkeypatch.setattr(center, "_validated_local_target", lambda value: tmp_path)
    monkeypatch.setattr(center, "_make_yara_scanner", lambda: (None, "unavailable"))
    monkeypatch.setattr(background_pacing, "get_pacing_controller",
                        lambda: SimpleNamespace(batch_delay=lambda: 0.05))
    token, waits = ScanCancellationToken(), []
    def wait(delay):
        waits.append(delay)
        token.cancel()
        return True
    monkeypatch.setattr(token, "wait", wait)
    result = center.scan_path(tmp_path, cancellation=token)
    assert result.status == "cancelled"
    assert waits == [0.05]
    assert result.metrics["files_scanned"] == 8


def test_scan_center_directory_discovery_paces_and_stops(monkeypatch, tmp_path):
    from angerona.core import background_pacing
    from angerona.core.security_scan_center import ScanCancellationToken, SecurityScanCenter, _TraversalState

    for number in range(270):
        (tmp_path / f"f{number}").write_bytes(b"inert")
    monkeypatch.setattr(background_pacing, "get_pacing_controller",
                        lambda: SimpleNamespace(batch_delay=lambda: 0.05))
    token, state = ScanCancellationToken(), _TraversalState()
    monkeypatch.setattr(token, "wait", lambda delay: token.cancel())
    files = list(SecurityScanCenter()._iter_local_files(tmp_path, cancellation=token, traversal=state))
    assert len(files) == 255
    assert state.cancelled and state.entries_seen == 256


def test_scan_center_thread_start_failure_releases_busy_state(monkeypatch):
    from PySide6.QtWidgets import QApplication
    from angerona.gui import scan_center

    app = QApplication.instance() or QApplication([])
    panel = scan_center.ScanCenterPanel()
    def failed_start(self):
        raise RuntimeError("no thread")
    monkeypatch.setattr(threading.Thread, "start", failed_start)
    try:
        panel._start("Test scan", lambda *args: pytest.fail("worker executed"))
        assert not panel._busy and panel._loading_token is None
        assert not panel.stop_button.isEnabled()
        assert "Could not start scan worker" in panel.log.toPlainText()
    finally:
        panel.close()
        app.processEvents()
