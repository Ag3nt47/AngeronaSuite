from __future__ import annotations

import os
import sys
import threading
import time
from types import ModuleType, SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from angerona.gui import top_talkers
from angerona.modules.arp_watchdog import ARPWatchdogModule


def _fake_scapy_module(monkeypatch, async_sniffer=None, sniff=None) -> ModuleType:
    package = ModuleType("scapy")
    package.__path__ = []  # type: ignore[attr-defined]
    all_module = ModuleType("scapy.all")
    if async_sniffer is not None:
        all_module.AsyncSniffer = async_sniffer  # type: ignore[attr-defined]
    if sniff is not None:
        all_module.sniff = sniff  # type: ignore[attr-defined]
    package.all = all_module  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "scapy", package)
    monkeypatch.setitem(sys.modules, "scapy.all", all_module)
    return all_module


def test_top_talkers_collection_includes_process_interface_and_ptr(monkeypatch) -> None:
    established = SimpleNamespace(
        status="ESTABLISHED",
        pid=42,
        raddr=SimpleNamespace(ip="203.0.113.8", port=443),
        laddr=SimpleNamespace(ip="192.0.2.2", port=50123),
    )

    class FakeProcess:
        def __init__(self, pid: int) -> None:
            assert pid == 42

        def name(self) -> str:
            return "browser.exe"

        def create_time(self) -> float:
            return 1234.5

        def exe(self) -> str:
            return r"C:\Apps\browser.exe"

    fake_psutil = SimpleNamespace(
        CONN_ESTABLISHED="ESTABLISHED",
        net_connections=lambda kind: [established],
        Process=FakeProcess,
    )
    monkeypatch.setattr(top_talkers, "psutil", fake_psutil)
    monkeypatch.setattr(top_talkers, "is_untrusted_external", lambda _ip: True)
    monkeypatch.setattr(
        top_talkers,
        "interface_type_for_local_ip",
        lambda ip: "Physical" if ip == "192.0.2.2" else "",
    )
    monkeypatch.setattr(top_talkers.socket, "gethostbyaddr", lambda _ip: ("example.test", [], []))

    snapshot = top_talkers._collect_top_talkers(resolve_hostnames=True)

    assert snapshot["process_count"] == 1
    assert snapshot["total_ext"] == 1
    assert snapshot["rows"] == [{
        "pid": 42,
        "name": "browser.exe",
        "conns": 1,
        "ext": 1,
        "top": "203.0.113.8:443  (example.test)",
        "remote_ip": "203.0.113.8",
        "iface": "Physical",
        "create_time": 1234.5,
        "exe": r"C:\Apps\browser.exe",
    }]


def test_top_talker_combat_submission_revalidates_exact_identity(monkeypatch) -> None:
    established = SimpleNamespace(
        status="ESTABLISHED",
        pid=42,
        raddr=SimpleNamespace(ip="203.0.113.8", port=443),
    )

    class FakeProcess:
        def __init__(self, pid: int) -> None:
            assert pid == 42

        @staticmethod
        def create_time() -> float:
            return 1234.5

        @staticmethod
        def exe() -> str:
            return r"C:\Apps\browser.exe"

    fake_psutil = SimpleNamespace(
        CONN_ESTABLISHED="ESTABLISHED",
        Process=FakeProcess,
        net_connections=lambda kind: [established],
    )
    published = []
    combat = SimpleNamespace(
        status="running",
        _bus=SimpleNamespace(publish=published.append),
        policy=lambda: SimpleNamespace(enabled=True),
    )
    harness = SimpleNamespace(_combat_module=lambda: combat)
    monkeypatch.setattr(top_talkers, "psutil", fake_psutil)
    snapshot = {
        "pid": 42,
        "name": "browser.exe",
        "create_time": 1234.5,
        "exe": r"C:\Apps\browser.exe",
        "remote_ip": "203.0.113.8",
    }

    submitted, _message = top_talkers.TopTalkersDialog._submit_combat_containment(
        harness, snapshot
    )
    assert submitted is True
    contract = published[-1].details["response_contract"]
    assert contract["targets"] == {
        "pid": 42,
        "process_create_time": 1234.5,
        "remote_ips": ["203.0.113.8"],
        "deception": "Smart Deception",
    }
    assert "isolate_program" in contract["actions"]

    snapshot["create_time"] = 1000.0
    submitted, message = top_talkers.TopTalkersDialog._submit_combat_containment(
        harness, snapshot
    )
    assert submitted is False
    assert "different process" in message
    assert len(published) == 1


def test_top_talkers_refresh_drops_overlapping_worker(monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(top_talkers, "psutil", None)
    dialog = top_talkers.TopTalkersDialog()

    class RecordingPool:
        def __init__(self) -> None:
            self.workers = []

        def start(self, worker) -> None:
            self.workers.append(worker)

    pool = RecordingPool()
    dialog._pool = pool
    monkeypatch.setattr(top_talkers, "psutil", object())

    dialog.refresh()
    dialog.refresh()
    assert len(pool.workers) == 1
    assert dialog._refresh_in_flight is True

    dialog._apply_snapshot({"rows": [], "process_count": 0, "total_ext": 0})
    dialog.refresh()
    assert len(pool.workers) == 2

    dialog.reject()
    app.processEvents()
    assert dialog._timer.isActive() is False


def test_top_talkers_worker_collects_on_calling_background_thread(monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    called_from = []
    result = []

    def collect(resolve: bool) -> dict:
        called_from.append(threading.current_thread())
        return {"resolve": resolve}

    monkeypatch.setattr(top_talkers, "_collect_top_talkers", collect)
    worker = top_talkers._TopTalkersWorker(True)
    worker.signals.finished.connect(result.append)
    thread = threading.Thread(target=worker.run)
    thread.start()
    thread.join(timeout=1.0)
    app.processEvents()

    assert not thread.is_alive()
    assert called_from == [thread]
    assert result == [{"resolve": True}]


def test_top_talkers_worker_reports_collection_failure(monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    result = []

    def fail(_resolve: bool) -> dict:
        raise RuntimeError("snapshot failed")

    monkeypatch.setattr(top_talkers, "_collect_top_talkers", fail)
    worker = top_talkers._TopTalkersWorker(False)
    worker.signals.finished.connect(result.append)
    thread = threading.Thread(target=worker.run)
    thread.start()
    thread.join(timeout=1.0)
    app.processEvents()

    assert result == [{"error": "Could not collect connections: snapshot failed"}]


def test_arp_watchdog_uses_one_async_capture_and_stops_it(monkeypatch) -> None:
    instances = []

    class FakeAsyncSniffer:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs
            self.running = False
            self.stop_calls = []
            self.join_calls = []
            instances.append(self)

        def start(self) -> None:
            self.running = True

        def stop(self, join: bool = True) -> None:
            self.stop_calls.append(join)
            self.running = False

        def join(self, timeout=None) -> None:
            self.join_calls.append(timeout)

    _fake_scapy_module(monkeypatch, async_sniffer=FakeAsyncSniffer)
    module = ARPWatchdogModule()

    module._try_start_scapy()
    module._try_start_scapy()
    assert len(instances) == 1
    assert module._scapy_ok is True

    capture_stop = module._scapy_stop_event
    module.stop()

    assert capture_stop is not None and capture_stop.is_set()
    assert instances[0].stop_calls == [False]
    assert instances[0].join_calls == [1.5]
    assert module._scapy_helper is None
    assert module._scapy_ok is False


def test_arp_watchdog_restart_never_overlaps_stubborn_capture(monkeypatch) -> None:
    instances = []

    class StubbornAsyncSniffer:
        def __init__(self, **_kwargs) -> None:
            self.running = False
            instances.append(self)

        def start(self) -> None:
            self.running = True

        def stop(self, join: bool = True) -> None:
            assert join is False
            # Simulate a capture API that cannot promptly unblock.

        def join(self, timeout=None) -> None:
            assert timeout == 1.5

    _fake_scapy_module(monkeypatch, async_sniffer=StubbornAsyncSniffer)
    module = ARPWatchdogModule()
    module._try_start_scapy()
    old_stop = module._scapy_stop_event

    module.stop()
    module._stop.clear()  # model a later BaseModule restart
    module._try_start_scapy()

    assert old_stop is not None and old_stop.is_set()
    assert len(instances) == 1
    assert module._scapy_helper is instances[0]
    assert module._scapy_ok is False


def test_arp_watchdog_fallback_sniff_has_bounded_idle_stop(monkeypatch) -> None:
    entered = threading.Event()
    calls = []

    def sniff(**kwargs) -> None:
        calls.append(kwargs)
        entered.set()
        time.sleep(0.01)

    _fake_scapy_module(monkeypatch, sniff=sniff)
    module = ARPWatchdogModule()
    module._try_start_scapy()
    assert entered.wait(timeout=1.0)

    module.stop()

    assert calls
    assert all(call["timeout"] == 0.5 for call in calls)
    assert module._scapy_helper is None
    assert module._scapy_ok is False
