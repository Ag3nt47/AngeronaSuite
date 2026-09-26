from __future__ import annotations

import json
import threading
import subprocess
import time

import pytest

from angerona.modules import packet_sniffer as module
from angerona.modules.packet_sniffer_worker import _token_kind


class _FakeWorker:
    def __init__(self, returncode: int, output: str = "") -> None:
        self.returncode = returncode
        self._output = output
        self.terminated = False

    def poll(self):
        return self.returncode

    def communicate(self, timeout=None):
        return self._output, ""

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.returncode = -9


def _wait_until(predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return predicate()


class _GatedWorker(_FakeWorker):
    def __init__(self):
        super().__init__(returncode=None)  # type: ignore[arg-type]
        self.wait_entered = threading.Event()
        self.release_wait = threading.Event()
        self.killed = False

    def wait(self, timeout=None):
        self.wait_entered.set()
        if not self.release_wait.wait(2.0):
            raise subprocess.TimeoutExpired("fixture", timeout)
        if self.returncode is None:
            raise subprocess.TimeoutExpired("fixture", timeout)
        return self.returncode

    def kill(self):
        self.killed = True
        super().kill()


def test_worker_protocol_redacts_secret_values():
    secret = "password=do-not-log-this"
    assert _token_kind(secret.encode()) == "password"

    decoded = module._decode_records(
        json.dumps(
            {
                "type": "detection",
                "src": "10.0.0.4",
                "dst": "10.0.0.8",
                "token_kind": "password",
                "payload": secret,
            }
        )
    )

    assert decoded == (
        {
            "type": "detection",
            "src": "10.0.0.4",
            "dst": "10.0.0.8",
            "token_kind": "password",
        },
    )
    assert secret not in repr(decoded)


def test_native_worker_fault_is_returned_as_data(monkeypatch):
    native_access_violation = -1073741819
    worker = _FakeWorker(native_access_violation)
    sniffer = module.PacketSnifferModule()
    monkeypatch.setattr(sniffer, "_launch_worker", lambda: worker)

    result = sniffer._capture_once()

    assert result is not None
    assert result.returncode == native_access_violation
    assert module._returncode_label(result.returncode) == "0xC0000005"


def test_stop_terminates_capture_worker():
    worker = _FakeWorker(returncode=None)  # type: ignore[arg-type]
    sniffer = module.PacketSnifferModule()
    with sniffer._worker_lock:
        sniffer._worker = worker  # type: ignore[assignment]

    sniffer.stop()

    assert _wait_until(lambda: sniffer._worker is None)
    assert worker.terminated


def test_stop_keeps_qt_timer_responsive_while_reaping_hung_worker(monkeypatch):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6.QtCore")
    pytest.importorskip("PySide6.QtWidgets")
    from PySide6.QtCore import QEventLoop, QTimer
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    loop = QEventLoop()
    worker = _GatedWorker()
    sniffer = module.PacketSnifferModule()
    with sniffer._worker_lock:
        sniffer._worker = worker  # type: ignore[assignment]
    observed = {}

    def stop():
        observed["start"] = time.monotonic()
        sniffer.stop()
        observed["return"] = time.monotonic()

    def tick():
        observed["tick"] = time.monotonic()
        loop.quit()

    QTimer.singleShot(0, stop)
    QTimer.singleShot(10, tick)
    QTimer.singleShot(1000, loop.quit)
    try:
        loop.exec()
    finally:
        worker.release_wait.set()
    assert _wait_until(lambda: sniffer._worker is None)
    assert observed["return"] - observed["start"] < 0.2
    assert observed["tick"] - observed["start"] < 0.25
    assert worker.wait_entered.is_set()
    assert worker.terminated and worker.killed
    assert app is not None


def test_rapid_stop_start_waits_for_old_capture_cleanup(monkeypatch):
    workers = [_GatedWorker(), _GatedWorker()]
    launched = []
    sniffer = module.PacketSnifferModule()
    monkeypatch.setattr(module.importlib.util, "find_spec", lambda _name: object())

    def launch():
        worker = workers[len(launched)]
        launched.append(worker)
        return worker

    monkeypatch.setattr(sniffer, "_launch_worker", launch)
    sniffer.start()
    assert _wait_until(lambda: len(launched) == 1)
    sniffer.stop()
    assert workers[0].wait_entered.wait(1.0)
    sniffer.start()
    assert len(launched) == 1  # old capture still owns its generation
    workers[0].release_wait.set()
    assert _wait_until(lambda: len(launched) == 2)
    assert workers[0].terminated and workers[0].killed
    # A late cleanup of the retired process cannot erase the new pointer.
    sniffer._terminate_worker(workers[0])
    assert sniffer._worker is workers[1]
    sniffer.stop()
    workers[1].release_wait.set()
    assert _wait_until(lambda: sniffer._worker is None)
    assert workers[1].terminated and workers[1].killed


def test_reaper_force_kills_when_terminate_fails():
    class DeniedTerminate(_FakeWorker):
        killed = False

        def terminate(self):
            raise OSError("fixture refused terminate")

        def kill(self):
            self.killed = True
            super().kill()

    worker = DeniedTerminate(returncode=None)  # type: ignore[arg-type]
    sniffer = module.PacketSnifferModule()
    with sniffer._worker_lock:
        sniffer._worker = worker  # type: ignore[assignment]

    sniffer.stop()

    assert _wait_until(lambda: sniffer._worker is None)
    assert worker.killed and worker.returncode == -9


def test_decode_rejects_non_json_and_bounds_untrusted_fields():
    output = "\n".join(
        (
            "not-json",
            json.dumps(
                {
                    "type": "error",
                    "message": "x" * 500,
                }
            ),
        )
    )
    records = module._decode_records(output)
    assert len(records) == 1
    assert records[0]["type"] == "error"
    assert len(records[0]["message"]) == 240
