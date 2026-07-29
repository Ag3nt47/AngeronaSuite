from __future__ import annotations

import os
import threading

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from angerona.core.eventbus import Event, Severity
from angerona.gui.main_window import MainWindow
from angerona.gui.system_pulse import SystemPulseCard
from angerona.gui.telemetry_worker import (
    _SEEN_ID_LIMIT,
    _SIGNAL_BATCH_LIMIT,
    _UI_QUEUE_LIMIT,
    _UI_RENDER_BATCH_LIMIT,
    _WORKER_PENDING_LIMIT,
    TelemetryWorker,
    UIBatchFlusher,
)
from angerona.modules.canary_drill import CanaryDrillModule, _ECHO_QUEUE_LIMIT


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def test_telemetry_worker_dedup_and_pending_memory_are_bounded():
    worker = TelemetryWorker()
    for event_id in range(_SEEN_ID_LIMIT + 200):
        assert worker._remember_event_id(event_id)
    assert len(worker._seen_ids) == _SEEN_ID_LIMIT
    assert len(worker._seen_order) == _SEEN_ID_LIMIT
    assert (0, 0.0) not in worker._seen_ids
    assert (_SEEN_ID_LIMIT + 199, 0.0) in worker._seen_ids
    assert not worker._remember_event_id(_SEEN_ID_LIMIT + 199)
    assert worker._remember_event_id(_SEEN_ID_LIMIT + 199, 1.0)

    events = [{"id": index} for index in range(_WORKER_PENDING_LIMIT + 300)]
    worker._enqueue_pending(events)
    snapshot = worker.backpressure_snapshot()
    assert snapshot["pending"] == _WORKER_PENDING_LIMIT
    assert snapshot["dropped"] == 300
    assert worker._pending[0]["id"] == 300


def test_telemetry_worker_shutdown_flush_is_capped_and_accounts_for_drop():
    worker = TelemetryWorker()
    batches: list[list[dict]] = []
    worker.batch_ready.connect(batches.append)
    worker._enqueue_pending(
        [{"id": index} for index in range(_SIGNAL_BATCH_LIMIT + 25)]
    )
    worker._maybe_flush(force=True)
    assert len(batches) == 1
    assert len(batches[0]) == _SIGNAL_BATCH_LIMIT
    assert batches[0][0]["id"] == 25
    assert worker.backpressure_snapshot()["dropped"] == 25
    assert not worker._pending


def test_ui_flusher_bounds_bursts_and_discards_stale_results_after_stop():
    _app()
    rendered: list[list[dict]] = []
    flusher = UIBatchFlusher(rendered.append)
    flusher._timer.stop()
    flusher.enqueue([{"id": index} for index in range(_UI_QUEUE_LIMIT + 100)])
    snapshot = flusher.backpressure_snapshot()
    assert snapshot["queued"] == _UI_QUEUE_LIMIT
    assert snapshot["dropped"] == 100

    flusher._flush()
    assert len(rendered[0]) == _UI_RENDER_BATCH_LIMIT
    assert flusher.backpressure_snapshot()["queued"] == (
        _UI_QUEUE_LIMIT - _UI_RENDER_BATCH_LIMIT
    )

    flusher.stop()
    flusher.enqueue([{"id": "late"}])
    stopped = flusher.backpressure_snapshot()
    assert stopped["queued"] == 0
    assert stopped["accepting"] is False
    assert stopped["dropped"] == 100 + (
        _UI_QUEUE_LIMIT - _UI_RENDER_BATCH_LIMIT
    ) + 1


def test_system_pulse_ignores_late_completion_after_shutdown():
    _app()
    card = SystemPulseCard(interval_ms=60_000)
    card._timer.stop()
    card.shutdown()
    card._apply_sample({
        "cpu": 99.0,
        "ram": 99.0,
        "available": 1.0,
        "wifi": 1,
        "down": 1.0,
        "up": 1.0,
    })
    assert card.snapshot()["history"] == []
    assert card._timer.isActive() is False
    card.close()


class _VoiceHarness:
    _voice_loop_entry = MainWindow._voice_loop_entry
    _ensure_voice_loop = MainWindow._ensure_voice_loop
    _voice_loop_in_flight = MainWindow._voice_loop_in_flight

    def __init__(self) -> None:
        self._voice_loop_lock = threading.Lock()
        self._voice_loop_thread = None
        self._aria_voice_stop = True
        self.entered = threading.Event()
        self.release = threading.Event()
        self.calls = 0

    def _aria_voice_loop(self) -> None:
        self.calls += 1
        self.entered.set()
        self.release.wait(timeout=2.0)


def test_voice_start_is_single_flight_across_concurrent_callers():
    voice = _VoiceHarness()
    results: list[bool] = []
    callers = [
        threading.Thread(target=lambda: results.append(voice._ensure_voice_loop()))
        for _index in range(20)
    ]
    for caller in callers:
        caller.start()
    for caller in callers:
        caller.join(timeout=1.0)
    assert voice.entered.wait(timeout=1.0)
    assert results.count(True) == 1
    assert results.count(False) == 19
    assert voice.calls == 1
    assert voice._voice_loop_in_flight()
    voice.release.set()
    worker = voice._voice_loop_thread
    if worker is not None:
        worker.join(timeout=1.0)
    assert not voice._voice_loop_in_flight()


def test_self_test_claim_is_single_flight_until_completion():
    class Harness:
        _claim_self_test = MainWindow._claim_self_test

        def __init__(self) -> None:
            self._selftest_active = threading.Event()

    harness = Harness()
    assert harness._claim_self_test()
    assert not harness._claim_self_test()
    harness._selftest_active.clear()
    assert harness._claim_self_test()


def test_canary_echo_saturation_keeps_newest_records_without_blocking():
    module = CanaryDrillModule()
    for index in range(_ECHO_QUEUE_LIMIT + 10):
        tag = f"DRILLCANARY_{index:016X}"
        module._on_event(Event(
            module="ETWG",
            message=f"Process created: {tag}",
            severity=Severity.INFO,
            details={"eid": 4688, "raw": [tag]},
        ))
    assert module._echo_queue.qsize() == _ECHO_QUEUE_LIMIT
    assert module._echo_queue_dropped == 10
    first, _observed_at = module._echo_queue.get_nowait()
    assert first == "DRILLCANARY_000000000000000A"
