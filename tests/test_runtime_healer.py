from types import SimpleNamespace
import threading

from angerona.core.eventbus import Event, EventBus
from angerona.core.runtime_healer import RuntimeHealer


class Service:
    def __init__(self, healthy=True):
        self.healthy = healthy
        self.stopping = False
        self.repairs = 0

    def recovery_snapshot(self):
        return {"healthy": self.healthy, "stopping": self.stopping}

    def recover(self):
        self.repairs += 1
        return True


def setup(healthy=False):
    reporter, recorder = Service(healthy), Service()
    now = [100.0]
    bus = EventBus()
    healer = RuntimeHealer(
        reporter, recorder, bus, SimpleNamespace(runtime_chill_active=False),
        clock=lambda: now[0],
    )
    return healer, reporter, recorder, now, bus


def state(healer):
    return healer.snapshot()["components"]["status_reporter"]


def test_confirms_failure_then_verifies_repair_on_later_observation():
    healer, reporter, recorder, now, _ = setup()
    healer.run_once()
    assert state(healer)["state"] == "confirming"
    assert reporter.repairs == 0
    now[0] += 15
    healer.run_once()
    assert reporter.repairs == 1
    assert recorder.repairs == 0
    assert state(healer)["state"] == "verifying"
    reporter.healthy = True
    now[0] += 15
    healer.run_once()
    assert state(healer)["state"] == "stabilizing"
    assert state(healer)["attempts"] == 1
    now[0] += 300
    healer.run_once()
    assert state(healer)["state"] == "healthy"
    assert state(healer)["attempts"] == 0


def test_backoff_and_exhaustion_do_not_hide_or_retry_persistent_failure():
    healer, reporter, _, now, _ = setup()
    healer.run_once()
    healer.run_once()
    for _ in range(20):
        healer.run_once()
    assert reporter.repairs == 1
    now[0] += 15
    healer.run_once()
    assert reporter.repairs == 2
    now[0] += 59
    healer.run_once()
    assert reporter.repairs == 2
    now[0] += 1
    healer.run_once()
    assert reporter.repairs == 3
    now[0] += 100_000
    healer.run_once()
    assert reporter.repairs == 3
    assert state(healer)["state"] == "attention_required"


def test_brief_health_and_clock_rollback_do_not_reset_incident_budget():
    healer, reporter, _, now, _ = setup()
    healer.run_once()
    healer.run_once()
    reporter.healthy = True
    healer.run_once()
    now[0] -= 50
    healer.run_once()
    assert state(healer)["attempts"] == 1
    reporter.healthy = False
    now[0] += 65
    healer.run_once()
    healer.run_once()
    assert reporter.repairs == 2


def test_probe_failure_is_unknown_and_does_not_authorize_repair():
    healer, reporter, _, _, _ = setup()

    def broken():
        raise OSError("secret private path")

    reporter.recovery_snapshot = broken
    for _ in range(4):
        healer.run_once()
    assert reporter.repairs == 0
    assert state(healer)["state"] == "unknown"
    assert state(healer)["error_type"] == "OSError"
    assert "private" not in str(healer.snapshot())
    reporter.recovery_snapshot = lambda: {"healthy": "False"}
    healer.run_once()
    assert state(healer)["state"] == "unknown"


def test_exception_is_charged_and_shutdown_never_revives_stopped_service():
    healer, reporter, _, _, _ = setup()

    def broken():
        reporter.repairs += 1
        raise RuntimeError("secret private path")

    reporter.recover = broken
    healer.run_once()
    healer.run_once()
    assert reporter.repairs == 1
    assert state(healer)["attempts"] == 1
    assert state(healer)["last_result"] == "failed"
    assert "secret" not in str(healer.snapshot())
    reporter.stopping = True
    healer.run_once()
    assert state(healer)["state"] == "stopped"
    assert healer.stop()
    assert not healer.start()
    healer.run_once()
    assert reporter.repairs == 1


def test_quiet_bus_and_callback_history_are_advisory_only():
    healer, reporter, recorder, _, bus = setup(healthy=True)

    def broken(_event):
        raise ValueError("sensitive")

    bus.subscribe(broken)
    bus.publish(Event("fixture", "test"))
    for _ in range(5):
        healer.run_once()
    snapshot = healer.snapshot()
    assert reporter.repairs == recorder.repairs == 0
    assert snapshot["bus_advisory"]["failures"] == 1
    assert snapshot["bus_advisory"]["action"] == "diagnostic_only"
    assert len(bus.subscriber_metrics()) == 1
    assert bus.revision() == 1
    assert healer.snapshot() == snapshot
    snapshot["components"]["status_reporter"]["state"] = "tampered"
    assert state(healer)["state"] == "healthy"


def test_concurrent_sweep_and_shutdown_cannot_admit_an_action_after_stop():
    healer, reporter, _, _, _ = setup()
    entered, release = threading.Event(), threading.Event()
    healer.run_once()

    def probe():
        entered.set()
        assert release.wait(2)
        return {"healthy": False}

    reporter.recovery_snapshot = probe
    worker = threading.Thread(target=healer.run_once)
    worker.start()
    try:
        assert entered.wait(2)
        healer.run_once()  # another sweep cannot multiply the confirmation
        healer.stop()
    finally:
        release.set()
        worker.join(2)
    assert not worker.is_alive()
    assert reporter.repairs == 0


def test_application_wires_healer_and_teardown_stops_it_first(monkeypatch):
    from angerona.app import AngeronaApp

    calls = []

    class Healer:
        def __init__(self, *args):
            calls.append("constructed")

        def start(self):
            calls.append("started")

        def stop(self):
            calls.append("stopped")

    monkeypatch.setattr("angerona.core.runtime_healer.RuntimeHealer", Healer)
    app = AngeronaApp.__new__(AngeronaApp)
    app._shutdown_requested = threading.Event()
    app.reporter = Service()
    app.flight_recorder_worker = Service()
    app.bus = EventBus()
    app.config = SimpleNamespace()
    app._start_runtime_healer()
    app._start_runtime_healer()
    assert calls == ["constructed", "started"]
    assert app.reporter.runtime_healer is app._runtime_healer
    app._shutdown_requested.set()
    app._start_runtime_healer()
    assert calls == ["constructed", "started"]
    app.reporter.stop = lambda: calls.append("reporter_stopped")
    # Stop the fixture at this boundary, proving ordering without full app setup.
    class EndOfFixture(Exception):
        pass

    def stop_reporter():
        calls.append("reporter_stopped")
        raise EndOfFixture

    app.reporter.stop = stop_reporter
    import pytest
    with pytest.raises(EndOfFixture):
        app._shutdown_owned()
    assert calls[-2:] == ["stopped", "reporter_stopped"]


def test_daemon_start_is_idempotent_and_stop_joins_without_more_repairs():
    healer, reporter, _, _, _ = setup()
    checked = threading.Event()
    original = reporter.recovery_snapshot

    def probe():
        checked.set()
        return original()

    reporter.recovery_snapshot = probe
    assert healer.start()
    try:
        assert checked.wait(2)
        assert not healer.start()
        worker = healer._thread
        assert healer.stop()
        assert not worker.is_alive()
        assert not healer.start()
        healer.run_once()
        assert reporter.repairs == 0
    finally:
        healer.stop()


def test_failed_daemon_start_can_be_retried_without_joining_unstarted_thread(monkeypatch):
    healer, _, _, _, _ = setup()
    original = threading.Thread.start

    def fail(_thread):
        raise RuntimeError("cannot create thread")

    monkeypatch.setattr(threading.Thread, "start", fail)
    import pytest
    with pytest.raises(RuntimeError):
        healer.start()
    assert healer._thread is None
    monkeypatch.setattr(threading.Thread, "start", original)
    assert healer.start()
    assert healer.stop()


def test_real_reporter_recovers_and_signed_pipeline_remains_available(tmp_path, monkeypatch):
    from angerona.core.eventbus import BusAuthority
    from angerona.core.status_report import StatusReporter
    from angerona.core.storage import AsyncFlightRecorder, FlightRecorder

    authority = BusAuthority(b"t" * 32)
    monkeypatch.setattr(
        "angerona.core.storage.BusAuthority.load", classmethod(lambda cls: authority),
    )
    storage = FlightRecorder(tmp_path / "events.db")
    recorder = AsyncFlightRecorder(storage, flush_interval=0.01)
    bus = EventBus()
    bus.arm(authority)
    bus.subscribe(recorder.submit)
    config = SimpleNamespace(
        data_dir=tmp_path, runtime_chill_active=False,
        ollama_host="local", ollama_model="fixture",
    )
    reporter = StatusReporter(bus, storage, SimpleNamespace(modules={}), config)
    healer = RuntimeHealer(reporter, recorder, bus, config)
    reporter.runtime_healer = healer
    completed = threading.Event()
    original = reporter._write

    def observe_write(*, force=False):
        result = original(force=force)
        if result:
            completed.set()
        return result

    monkeypatch.setattr(reporter, "_write", observe_write)
    try:
        recorder.start()
        # The normal start failed to leave a live reporter; direct service
        # probes authorize one worker replacement without trusting a log file.
        healer.run_once()
        healer.run_once()
        assert completed.wait(3)
        healer.run_once()
        assert state(healer)["state"] == "stabilizing"
        bus.publish(Event("recovery-test", "signed after repair"))
        healer.stop()
        reporter.stop()
        assert recorder.stop(3)
        events = storage.recent(10)
        assert len(events) == 1 and authority.verify(events[0])
        assert "RUNTIME RECOVERY" in (tmp_path / "diagnostics" / "status.txt").read_text()
    finally:
        healer.stop()
        reporter.stop()
        recorder.stop(3)
        storage.close()
