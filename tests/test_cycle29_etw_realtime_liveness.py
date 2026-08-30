from __future__ import annotations

from types import SimpleNamespace

from angerona.modules import etw_realtime_sensor


class _Thread:
    def __init__(self, alive: bool = True) -> None:
        self.alive = alive

    def is_alive(self) -> bool:
        return self.alive


class _EndCapture:
    def __init__(self, ended: bool = False) -> None:
        self.ended = ended

    def is_set(self) -> bool:
        return self.ended


class _Job:
    def __init__(self) -> None:
        self.running = True
        self.consumer = SimpleNamespace(
            process_thread=_Thread(), end_capture=_EndCapture()
        )
        self.properties = SimpleNamespace(
            EventsLost=0, LogBuffersLost=0, RealTimeBuffersLost=0
        )
        self.query_error: Exception | None = None
        self.stopped = False

    def query(self):
        if self.query_error is not None:
            raise self.query_error
        return self.properties

    def stop(self) -> None:
        self.stopped = True
        self.running = False


def _attached_sensor(callback=lambda _event: None):
    sensor = etw_realtime_sensor.ETWProcessSensor(callback)
    sensor._job = _Job()
    sensor._running = True
    return sensor


def test_etw_idle_health_requires_live_consumer_and_kernel_query() -> None:
    sensor = _attached_sensor()
    receipt = sensor.status_receipt()

    assert receipt.live is True
    assert receipt.state == "idle-proven"
    assert receipt.loss_count == 0
    assert "kernel session query succeeded" in receipt.reason


def test_etw_consumer_death_clears_running_instead_of_sticking_green() -> None:
    sensor = _attached_sensor()
    sensor._job.consumer.process_thread.alive = False

    receipt = sensor.status_receipt()
    assert receipt.live is False
    assert receipt.state == "ended"
    assert sensor._running is False
    assert sensor.running is False


def test_etw_kernel_query_error_and_buffer_loss_are_explicit() -> None:
    sensor = _attached_sensor()
    sensor._job.properties.EventsLost = 3
    sensor._job.properties.RealTimeBuffersLost = 2

    receipt = sensor.status_receipt()
    assert receipt.live is True
    assert receipt.state == "lossy"
    assert receipt.loss_count == 5

    sensor = _attached_sensor()
    sensor._job.query_error = OSError("session missing")
    receipt = sensor.status_receipt()
    assert receipt.live is False
    assert receipt.state == "error"
    assert "session missing" in receipt.reason
    assert sensor._running is False


def test_etw_callback_delivery_failure_degrades_session_receipt() -> None:
    def reject(_event: dict) -> None:
        raise RuntimeError("downstream rejected")

    sensor = _attached_sensor(reject)
    sensor._callback(
        (
            etw_realtime_sensor.PROCESS_START_EVENT_ID,
            {
                "ProcessID": 4242,
                "ParentProcessID": 1,
                "ImageName": r"C:\Windows\System32\cmd.exe",
            },
        )
    )

    receipt = sensor.status_receipt()
    assert sensor.events_seen == 1
    assert receipt.live is True
    assert receipt.state == "callback-error"
    assert receipt.callback_failures == 1
    assert "callback_failures=1" in receipt.reason


def test_stop_releases_job_even_after_liveness_was_lost() -> None:
    sensor = _attached_sensor()
    job = sensor._job
    sensor._running = False

    sensor.stop()
    assert job.stopped is True
    assert sensor._job is None
