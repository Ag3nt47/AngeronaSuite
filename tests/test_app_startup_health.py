from __future__ import annotations

import json

from angerona.app import AngeronaApp
from angerona.core.eventbus import EventBus, Severity


def _app(*, ready: bool) -> AngeronaApp:
    app = AngeronaApp.__new__(AngeronaApp)
    app.bus = EventBus()
    app._startup_events_ready = ready
    app._startup_degradations = []
    return app


def test_startup_degradation_waits_for_recorder_and_redacts_exception() -> None:
    app = _app(ready=False)
    app._record_startup_degradation(
        "Optional Store",
        "structured hunting is unavailable",
        RuntimeError(r"secret=token path=C:\private\operator"),
    )

    assert app.bus.recent() == []
    assert len(app._startup_degradations) == 1

    app._startup_events_ready = True
    app._flush_startup_degradations()
    event = app.bus.recent(1)[0]
    encoded = json.dumps(event.details) + event.message

    assert event.module == "Startup Health"
    assert event.severity == Severity.MEDIUM
    assert event.details["error_type"] == "RuntimeError"
    assert "token" not in encoded
    assert "private" not in encoded


def test_module_loader_failure_becomes_critical_operator_evidence() -> None:
    app = _app(ready=True)
    notes: list[str] = []
    app._blackbox_note = notes.append

    def fail() -> None:
        raise LookupError("sensitive internal detail")

    app._load_modules = fail
    app._load_modules_guarded()

    event = app.bus.recent(1)[0]
    assert event.severity == Severity.CRITICAL
    assert event.details["service"] == "Protection Module Loader"
    assert event.details["error_type"] == "LookupError"
    assert "sensitive" not in event.message
    assert notes and "Startup Health" in notes[0]
