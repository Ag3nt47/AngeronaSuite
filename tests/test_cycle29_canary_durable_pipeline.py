from __future__ import annotations

import time

from angerona.core.eventbus import Event, EventBus
from angerona.core.module_base import Severity
from angerona.modules import canary_drill as drill


class _Recorder:
    def __init__(self, events=()) -> None:
        self.events = list(events)
        self.calls = []

    def bounded_events_in_window(self, start_ts, end_ts, *, limit):
        self.calls.append((start_ts, end_ts, limit))
        return list(self.events), len(self.events)


def _armed_module(recorder=None):
    module = drill.CanaryDrillModule()
    module.bind(EventBus())
    if recorder is not None:
        module.bind_recorder(recorder)
    tag = "DRILLCANARY_ABCDEF0123456789"
    now = time.monotonic()
    assert module._expectations.arm(tag, drill._PROCESS_CONTRACT, now=now)
    event = Event(
        module="ETWG",
        message=f"Process created: {tag}",
        severity=Severity.INFO,
        ts=time.time(),
        details={"eid": 4688, "raw": [tag]},
        hmac_sig="a" * 64,
    )
    return module, tag, event


def test_sensor_echo_is_not_counted_until_exact_signed_row_is_durable() -> None:
    recorder = _Recorder()
    module, tag, event = _armed_module(recorder)

    module._on_event(event)
    assert module._collect_echoes() == []
    assert module._sensor_echoes == 1
    assert module._drills_caught == 0
    assert tag in module._pending_durable

    recorder.events = [event]
    assert module._check_durable_receipts() == []
    assert module._drills_caught == 1
    assert tag not in module._pending_durable
    assert recorder.calls and recorder.calls[0][2] == 512


def test_same_timestamp_wrong_hmac_cannot_satisfy_recorder_leg() -> None:
    module, tag, event = _armed_module(_Recorder())
    wrong = Event(
        module="ETWG",
        message=event.message,
        severity=event.severity,
        ts=event.ts,
        details=event.details,
        hmac_sig="b" * 64,
    )
    module._recorder.events = [wrong]
    module._on_event(event)
    module._collect_echoes()
    event_ts, _deadline, signature = module._pending_durable[tag]
    module._pending_durable[tag] = (event_ts, 0.0, signature)

    assert module._check_durable_receipts() == [tag]
    assert module._drills_caught == 0
    assert module._durable_misses == 1


def test_missing_recorder_never_produces_full_pipeline_success() -> None:
    module, tag, event = _armed_module()

    module._on_event(event)
    assert module._collect_echoes() == []

    assert module._sensor_echoes == 1
    assert module._drills_caught == 0
    assert module._durable_misses == 1
    assert tag not in module._pending_durable


def test_integrity_failure_row_is_rejected_even_if_hmac_text_matches() -> None:
    module, tag, event = _armed_module(_Recorder())
    invalid = Event(
        module="ETWG",
        message=event.message,
        severity=event.severity,
        ts=event.ts,
        details={**event.details, "_ledger_integrity": "invalid"},
        hmac_sig=event.hmac_sig,
    )
    module._recorder.events = [invalid]
    module._on_event(event)
    module._collect_echoes()
    event_ts, _deadline, signature = module._pending_durable[tag]
    module._pending_durable[tag] = (event_ts, 0.0, signature)

    assert module._check_durable_receipts() == [tag]
    assert module._drills_caught == 0
