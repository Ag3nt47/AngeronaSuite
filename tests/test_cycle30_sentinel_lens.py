from __future__ import annotations

import itertools
import json
import os
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from PySide6.QtWidgets import QApplication, QFileDialog, QPushButton, QWidget

from angerona.core.sentinel_lens import (
    MAX_BUNDLE_BYTES,
    MAX_IMPORT_BYTES,
    SentinelLensInputError,
    SentinelLensService,
    analyze_events,
    build_sentinel_snapshot,
    parse_log_bundle,
    parse_netflow,
    parse_syslog,
    parse_windows_event,
    render_narrative,
)
from angerona.core.eventbus import Event, EventBus, Severity
from angerona.gui.flow_window import FlowWindow
from angerona.gui.sentinel_lens import SentinelLensDialog, _loopback_ollama_url


def _windows_process_event(*, stamp: str = "2026-08-28T12:00:00Z") -> bytes:
    return json.dumps({
        "System": {
            "EventID": 4688,
            "TimeCreated": {"SystemTime": stamp},
            "Computer": "VERY-SECRET-HOSTNAME",
            "Channel": "Security",
        },
        "EventData": {
            "Data": [
                {
                    "@Name": "NewProcessName",
                    "#text": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                },
                {
                    "@Name": "ParentProcessName",
                    "#text": r"C:\Program Files\Microsoft Office\winword.exe",
                },
                {"@Name": "NewProcessId", "#text": "1234"},
                {"@Name": "ParentProcessId", "#text": "900"},
                {"@Name": "CommandLine", "#text": "powershell -NoProfile"},
            ]
        },
    }, indent=2).encode("utf-8")


def _netflow(*, destination: str = "8.8.8.8", port: int = 4444) -> bytes:
    return json.dumps({
        "src_ip": "10.20.30.40",
        "dst_ip": destination,
        "src_port": 52_000,
        "dst_port": port,
        "protocol": "tcp",
        "bytes": 0,
        "packets": 0,
        "timestamp": 1_788_000_001,
        "exporter": "PRIVATE-FLOW-EXPORTER",
    }).encode("utf-8")


def test_standard_parsers_are_deterministic_bounded_and_privacy_minimized() -> None:
    syslog = parse_syslog(
        b"<34>1 2026-08-28T12:00:00Z host-a sshd 123 ID47 - failed login",
        observed_at=1_788_000_000,
    )
    assert syslog.message == "failed login"
    assert syslog.observed_at == 1_788_000_000
    assert "host-a" not in syslog.host_token
    assert len(syslog.host_token) == 64

    event = parse_windows_event(_windows_process_event())
    assert event.observed_at == 1_787_918_400
    assert event.details["eid"] == 4688
    assert event.details["pid"] == 1234
    assert event.details["parent_image"].endswith("winword.exe")
    assert event.details["command_line"] == "powershell -NoProfile"
    assert "VERY-SECRET-HOSTNAME" not in event.as_event().details.values()
    assert event.as_event().details["host_id"] == event.host_token

    flow = parse_netflow(_netflow(), observed_at=1_788_000_001)
    assert flow.details["bytes"] == 0
    assert flow.details["packets"] == 0
    assert flow.severity == 2

    with pytest.raises(SentinelLensInputError):
        parse_syslog(b"first\nsecond", observed_at=1.0)
    with pytest.raises(SentinelLensInputError):
        parse_netflow(_netflow().replace(b'"bytes": 0', b'"bytes": -1'))
    with pytest.raises(SentinelLensInputError):
        parse_windows_event(b"{" + b'"EventID":4688,' * 65 + b'"x":1}')


def test_bundle_ingestion_supports_pretty_json_arrays_jsonl_and_syslog() -> None:
    pretty = parse_log_bundle(_windows_process_event(), suffix=".json")
    assert len(pretty) == 1
    assert pretty[0].source_format == "windows-event"

    array = json.dumps([
        json.loads(_windows_process_event()),
        json.loads(_netflow()),
    ], indent=2).encode("utf-8")
    mixed = parse_log_bundle(array, source_format="auto", suffix=".json")
    assert [row.source_format for row in mixed] == ["windows-event", "netflow"]

    jsonl = _netflow() + b"\n" + _netflow(destination="1.1.1.1", port=8080)
    assert len(parse_log_bundle(jsonl, source_format="netflow")) == 2

    logs = (
        b"<13>1 2026-08-28T12:00:00Z host app 1 ID - one\n"
        b"<13>1 2026-08-28T12:00:01Z host app 1 ID - two\n"
    )
    assert len(parse_log_bundle(logs, suffix=".log")) == 2


@pytest.mark.parametrize(
    "payload",
    [
        b'{"EventID":4688,"EventID":4625,"EventData":{}}',
        b'[1,2,3]',
        b'{"unknown":"shape"}',
        b'{"src_ip":"10.0.0.1"}',
    ],
)
def test_bundle_ingestion_fails_closed_on_ambiguous_json(payload: bytes) -> None:
    with pytest.raises(SentinelLensInputError):
        parse_log_bundle(payload, source_format="auto", suffix=".json")


def test_bundle_and_record_byte_budgets_are_enforced() -> None:
    with pytest.raises(SentinelLensInputError):
        parse_log_bundle(b"x" * (MAX_BUNDLE_BYTES + 1), source_format="syslog")
    huge = json.dumps({
        "EventID": 4688,
        "EventData": {},
        "Message": "x" * MAX_IMPORT_BYTES,
    }).encode("utf-8")
    with pytest.raises(SentinelLensInputError):
        parse_log_bundle(huge, source_format="windows-event")


def test_snapshot_maps_attack_chain_anomalies_to_exact_clickable_evidence() -> None:
    process = parse_windows_event(_windows_process_event()).as_event()
    flow = parse_netflow(_netflow()).as_event()
    snapshot = build_sentinel_snapshot([process, flow])

    rules = {row["rule_id"] for row in snapshot["anomalies"]}
    assert rules == {"SL-OFFICE-SCRIPT", "SL-UNCOMMON-EGRESS"}
    assert snapshot["privacy"] == {
        "mode": "local-only",
        "external_model_calls": 0,
        "raw_telemetry_exported": False,
        "remediation_execution": False,
    }
    office = next(
        row for row in snapshot["anomalies"] if row["rule_id"] == "SL-OFFICE-SCRIPT"
    )
    node = next(row for row in snapshot["nodes"] if row["id"] == office["event_id"])
    exact = node["exact_evidence"]
    assert exact["details"]["image"].endswith("powershell.exe")
    assert exact["details"]["command_line"] == "powershell -NoProfile"
    assert office["evidence"] == [office["event_id"]]
    narrative = render_narrative(snapshot, office["event_id"])
    assert "Exact local evidence:" in narrative
    assert "parent-process" not in narrative  # only relations touching this event
    assert "detector-evidence" in narrative
    assert "proposal-only" in narrative


def test_authentication_burst_is_one_deterministic_bounded_finding() -> None:
    events = [
        SimpleNamespace(
            module="Auth",
            message="failed",
            severity=3,
            ts=1000.0 + index,
            hmac_sig=f"{index + 1:064x}",
            details={"eid": 4625, "event_type": "failed-logon", "user": "alice"},
        )
        for index in range(8)
    ]
    first = analyze_events(events)
    second = analyze_events(reversed(events))
    burst = [row for row in first if row.rule_id == "SL-AUTH-BURST"]
    assert len(burst) == 1
    assert len(burst[0].evidence) == 8
    assert all(value.startswith("EV:") for value in burst[0].evidence)
    assert {row.finding_id for row in first} == {row.finding_id for row in second}


def test_snapshot_stops_consuming_an_unbounded_source_and_rejects_bad_rows() -> None:
    good = SimpleNamespace(
        module="Sensor", message="ok", severity=0, ts=1.0,
        hmac_sig="a" * 64, details={},
    )
    bad = SimpleNamespace(
        module="Sensor", message="bad", severity=0, ts=2.0,
        hmac_sig="b" * 64, details={str(index): index for index in range(65)},
    )
    snapshot = build_sentinel_snapshot(itertools.chain((bad,), itertools.repeat(good)), max_events=2)
    assert snapshot["stats"]["source_records_examined"] == 2
    assert snapshot["stats"]["source_truncated"] is True
    assert snapshot["stats"]["rejected_records"] == 1
    assert snapshot["stats"]["retained_events"] == 1


def test_only_plain_loopback_ai_endpoints_are_admitted(monkeypatch) -> None:
    assert _loopback_ollama_url("http://localhost:11434") == "http://localhost:11434"
    assert _loopback_ollama_url("http://127.0.0.1:11434/") == "http://127.0.0.1:11434"
    assert _loopback_ollama_url("http://[::1]:11434") == "http://[::1]:11434"
    for endpoint in (
        "https://models.example.com",
        "http://localhost.example.com:11434",
        "http://user:password@localhost:11434",
        "http://localhost:11434/proxy",
    ):
        with pytest.raises(SentinelLensInputError):
            _loopback_ollama_url(endpoint)

    calls: list[dict] = []

    def fake_call(payload, path, *, host, timeout, neutralized_telemetry=None):
        calls.append({
            "payload": payload,
            "path": path,
            "host": host,
            "timeout": timeout,
            "neutralized_telemetry": neutralized_telemetry,
        })
        return {"response": "bounded local narrative"}

    from angerona.engines import ollama_client

    monkeypatch.setattr(ollama_client, "call", fake_call)
    remote = SentinelLensDialog(
        None, config=SimpleNamespace(ollama_host="https://models.example.com")
    )
    with pytest.raises(SentinelLensInputError):
        remote._ask_loopback_ai("private evidence")
    assert calls == []
    remote.close()

    local = SentinelLensDialog(
        None,
        config=SimpleNamespace(
            ollama_host="http://127.0.0.1:11434",
            ollama_model="local-model",
            ollama_keep_alive="5m",
        ),
    )
    assert local._ask_loopback_ai("private evidence") == "bounded local narrative"
    assert calls[0]["host"] == "http://127.0.0.1:11434"
    assert calls[0]["path"] == "/api/generate"
    assert calls[0]["neutralized_telemetry"] == "private evidence"
    assert "private evidence" not in calls[0]["payload"]["prompt"]
    local.close()


def test_safe_file_import_rejects_symlinks_and_accepts_stable_regular_files(
    tmp_path: Path,
) -> None:
    source = tmp_path / "events.json"
    source.write_bytes(_windows_process_event())
    assert SentinelLensDialog._safe_import_bytes(source) == source.read_bytes()
    assert len(SentinelLensDialog._parse_import(source.read_bytes(), "auto", ".json")) == 1

    link = tmp_path / "events-link.json"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("symlink creation is unavailable on this host")
    with pytest.raises(SentinelLensInputError):
        SentinelLensDialog._safe_import_bytes(link)


def test_dialog_import_validation_runs_off_the_gui_thread(
    tmp_path: Path, monkeypatch,
) -> None:
    app = QApplication.instance() or QApplication([])
    source = tmp_path / "pretty-event.json"
    source.write_bytes(_windows_process_event())
    monkeypatch.setattr(
        QFileDialog,
        "getOpenFileName",
        lambda *_args, **_kwargs: (os.fspath(source), ""),
    )
    dialog = SentinelLensDialog(None)
    assert dialog._snapshot_worker is not None
    assert dialog._snapshot_worker.wait(3_000)
    app.processEvents()
    dialog._import_logs()
    assert dialog.import_button.isEnabled() is False
    assert dialog._import_worker is not None
    assert dialog._import_worker.wait(3_000)
    app.processEvents()
    assert dialog.import_button.isEnabled() is True
    assert len(dialog._imported) == 1
    assert "memory-only" in dialog.status.text() or "Building bounded graph" in dialog.status.text()
    if dialog._snapshot_worker is not None and dialog._snapshot_worker.isRunning():
        assert dialog._snapshot_worker.wait(3_000)
        app.processEvents()
    dialog.close()
    app.processEvents()


class _Bus:
    def __init__(self, rows=()):
        self.rows = list(rows)

    def recent(self, limit):
        return self.rows[:limit]

    def event_count(self):
        return len(self.rows)


def test_dialog_rows_nodes_and_world_view_entry_are_clickable() -> None:
    app = QApplication.instance() or QApplication([])
    event = parse_windows_event(_windows_process_event()).as_event()
    dialog = SentinelLensDialog(_Bus((event,)))
    assert dialog._snapshot_worker is not None
    assert dialog._snapshot_worker.wait(3_000)
    app.processEvents()
    completed_worker = dialog._snapshot_worker
    dialog.refresh()
    assert dialog._snapshot_worker is completed_worker  # unchanged source is not rebuilt
    dialog.refresh(force=True)
    assert dialog._snapshot_worker is not completed_worker
    assert dialog._snapshot_worker.wait(3_000)
    app.processEvents()
    assert dialog.anomalies.rowCount() == 1
    evidence = dialog.anomalies.item(0, 4).text()
    dialog.select_node(evidence)
    assert "EXACT NODE EVIDENCE" in dialog.detail.toPlainText()
    assert "REMEDIATION PROPOSALS" in dialog.detail.toPlainText()
    assert evidence in dialog._items

    parent = QWidget()
    flow = FlowWindow(
        _Bus(),
        None,
        SimpleNamespace(modules={}),
        SimpleNamespace(
            ollama_host="http://localhost:11434",
            ollama_model="local",
            ollama_keep_alive="5m",
        ),
        parent,
    )
    buttons = {button.objectName(): button for button in flow.findChildren(QPushButton)}
    assert "SentinelLensButton" in buttons
    buttons["SentinelLensButton"].click()
    assert isinstance(flow._sentinel_lens, SentinelLensDialog)
    assert flow._sentinel_lens.config is flow.config
    opened = flow._sentinel_lens
    buttons["SentinelLensButton"].click()
    assert flow._sentinel_lens is opened
    if flow._sentinel_lens._snapshot_worker is not None:
        assert flow._sentinel_lens._snapshot_worker.wait(3_000)
    app.processEvents()
    flow._sentinel_lens.close()
    dialog.close()
    flow.close()
    parent.close()
    app.processEvents()


def test_live_view_reserves_a_fair_lane_for_explicit_imports() -> None:
    app = QApplication.instance() or QApplication([])
    dialog = SentinelLensDialog(_Bus())
    assert dialog._snapshot_worker is not None
    assert dialog._snapshot_worker.wait(3_000)
    app.processEvents()
    live = [
        SimpleNamespace(
            module="Live",
            message=f"event-{index}",
            severity=0,
            ts=float(index + 1),
            hmac_sig=f"{index + 1:064x}",
            details={},
        )
        for index in range(2_000)
    ]
    dialog.bus = _Bus(live)
    imported = parse_netflow(_netflow())
    dialog._imported.append(imported)
    selected = dialog._live_events()
    assert len(selected) == 2_000
    assert sum(
        str(getattr(row, "module", "")).startswith("SentinelLens/")
        for row in selected
    ) == 1
    assert sum(getattr(row, "module", "") == "Live" for row in selected) == 1_999
    dialog.close()
    app.processEvents()


def test_background_service_subscribes_and_continuously_builds_local_snapshot() -> None:
    bus = EventBus(ring_size=16)
    service = SentinelLensService(
        bus,
        queue_capacity=16,
        max_events=8,
        analysis_interval=0.01,
    )
    assert service.start() is True
    assert service.start() is False

    bus.publish(Event(
        module="Live Sensor",
        message="critical corroboration",
        severity=Severity.CRITICAL,
        ts=1_788_000_000,
        details={"event_type": "sensor-signal"},
    ))
    assert service.submit_windows_event(_windows_process_event()) is True
    assert service.submit_netflow(_netflow()) is True
    assert service.submit_syslog(
        b"<34>1 2026-08-28T12:00:00Z host-a sshd 1 ID47 - failed login"
    ) is True
    assert service.wait_for_revision(0, timeout=3.0)

    snapshot = service.snapshot()
    assert {row["rule_id"] for row in snapshot["anomalies"]} == {
        "SL-CRITICAL-SIGNAL",
        "SL-OFFICE-SCRIPT",
        "SL-UNCOMMON-EGRESS",
    }
    health = snapshot["service_health"]
    assert health["state"] == "running"
    assert health["callback_contract"] == "bounded-put_nowait-only"
    assert health["accepted"] == 4
    assert health["processed_records"] == 4
    assert health["queue_dropped"] == 0
    assert health["accepted_by_source"] == {
        "eventbus": 1,
        "syslog": 1,
        "windows-event": 1,
        "netflow": 1,
        "normalized": 0,
    }
    assert health["network_listener"] is False
    assert health["remediation_execution"] is False
    assert service.stop(timeout=3.0) is True
    assert service.stop(timeout=3.0) is True
    assert service.health()["clean_shutdown"] is True


def test_background_service_discloses_queue_drops_and_never_blocks_publishers(
    monkeypatch,
) -> None:
    import angerona.core.sentinel_lens as lens_core

    bus = EventBus(ring_size=8)
    service = SentinelLensService(
        bus,
        queue_capacity=1,
        max_events=2,
        analysis_interval=0.01,
        batch_size=1,
    )
    analysis_entered = threading.Event()
    release_analysis = threading.Event()
    real_build = lens_core.build_sentinel_snapshot

    def blocked_build(events, *, max_events=2_000):
        analysis_entered.set()
        assert release_analysis.wait(3.0)
        return real_build(events, max_events=max_events)

    monkeypatch.setattr(lens_core, "build_sentinel_snapshot", blocked_build)
    service.start()
    bus.publish(Event(module="one", message="one", ts=1.0))
    assert analysis_entered.wait(2.0)

    # Analysis is deliberately blocked, yet the inline EventBus callback only
    # offers to the queue: one pending item is accepted and the next is dropped.
    bus.publish(Event(module="two", message="two", ts=2.0))
    bus.publish(Event(module="three", message="three", ts=3.0))
    pressure = service.health()
    assert pressure["queue_depth"] == 1
    assert pressure["queue_capacity"] == 1
    assert pressure["queue_dropped"] == 1
    assert pressure["accepted"] == 2
    metric = next(
        row for row in bus.subscriber_metrics()
        if "SentinelLensService" in row.name
    )
    assert metric.deliveries == 3
    assert metric.failures == 0

    release_analysis.set()
    assert service.wait_for_revision(0, timeout=3.0)
    assert service.stop(timeout=3.0)
    final = service.health()
    assert final["state"] == "stopped"
    assert final["clean_shutdown"] is True
    assert final["processed_records"] == 2
    assert final["retained_events"] == 2


def test_service_admission_bounds_and_post_shutdown_rejections_are_honest() -> None:
    service = SentinelLensService(None, queue_capacity=4, analysis_interval=0.01)
    service.start()
    with pytest.raises(SentinelLensInputError):
        service.submit_netflow(b"x" * (MAX_IMPORT_BYTES + 1))
    with pytest.raises(SentinelLensInputError):
        service.submit_record(object())  # type: ignore[arg-type]
    assert service.health()["admission_rejections"] == 2
    assert service.stop(timeout=3.0)
    assert service.submit_syslog(b"<13>one") is False
    stopped = service.health()
    assert stopped["stopped_rejections"] == 1
    assert stopped["clean_shutdown"] is True


def test_dialog_consumes_app_owned_snapshot_and_discloses_service_health() -> None:
    app = QApplication.instance() or QApplication([])
    service = SentinelLensService(None, analysis_interval=0.01)
    service.start()
    assert service.submit_windows_event(_windows_process_event())
    assert service.wait_for_revision(0, timeout=3.0)

    dialog = SentinelLensDialog(None, service=service)
    app.processEvents()
    assert dialog._snapshot_worker is None
    assert dialog.anomalies.rowCount() == 1
    assert "hunt running" in dialog.status.text()
    assert "dropped 0" in dialog.status.text()
    evidence = dialog.anomalies.item(0, 4).text()
    dialog.select_node(evidence)
    assert "proposal-only" in dialog.detail.toPlainText()
    dialog.close()
    app.processEvents()
    assert service.stop(timeout=3.0)


def test_world_view_immediate_delete_cancels_owned_callbacks_and_preserves_lens() -> None:
    app = QApplication.instance() or QApplication([])
    parent = QWidget()
    manager = SimpleNamespace(sentinel_lens_service=None)
    flow = FlowWindow(
        _Bus(),
        None,
        manager,
        SimpleNamespace(
            modules={},
            ollama_host="http://localhost:11434",
            ollama_model="local",
            ollama_keep_alive="5m",
        ),
        parent,
    )
    buttons = {button.objectName(): button for button in flow.findChildren(QPushButton)}
    buttons["SentinelLensButton"].click()
    lens = flow._sentinel_lens
    assert lens.parentWidget() is parent

    # WA_DeleteOnClose removes FlowWindow before its former zero-delay fit
    # callback. A parented timer and no destroyed-signal capture make this safe.
    flow.close()
    app.processEvents()
    app.processEvents()
    assert lens.parentWidget() is parent
    if lens._snapshot_worker is not None and lens._snapshot_worker.isRunning():
        assert lens._snapshot_worker.wait(3_000)
        app.processEvents()
    lens.close()
    parent.close()
    app.processEvents()
