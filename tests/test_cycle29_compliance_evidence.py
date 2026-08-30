from __future__ import annotations

import json
import hashlib
import hmac

from angerona.core.eventbus import Event, EventBus
from angerona.core.module_base import Severity
from angerona.modules import compliance_mapper as cmap


class _Recorder:
    def __init__(self, rows, backlog=None, highwater=None) -> None:
        self.rows = list(rows)
        self.backlog = len(self.rows) if backlog is None else backlog
        self.highwater = (
            max((row[0] for row in self.rows), default=0)
            if highwater is None
            else highwater
        )
        self.cursors = []

    def bounded_events_after_id(self, cursor, *, limit):
        self.cursors.append((cursor, limit))
        return list(self.rows), self.backlog, self.highwater


def _module(tmp_path) -> cmap.ComplianceMapperModule:
    module = cmap.ComplianceMapperModule()
    module._out = tmp_path / "compliance_report.json"
    module._state_path_override = tmp_path / "compliance.state.json"
    module._state_key_override = b"C" * 32
    return module


def test_artifact_describes_relevance_not_enforcement(tmp_path) -> None:
    artifact_key = b"A" * 32
    report = cmap.generate_artifact(
        [{"mitre_id": "T1059.001", "module": "Sensor", "severity": 3}],
        tmp_path / "report.json",
        coverage={"complete": True, "source": "flight-recorder"},
        artifact_key=artifact_key,
    )

    item = report["mapped_incidents"][0]
    assert "nist_control_enforced" not in item
    assert "stig_baseline_enforced" not in item
    assert item["nist_control_mapped"].startswith("CM-5")
    assert item["claim_type"] == "control_relevance"
    assert item["implementation_status"] == "not_assessed"
    assert "not evidence" in report["claim_semantics"]
    assert report["coverage"]["complete"] is True
    signature = report["artifact_hmac_sha256"]
    unsigned = dict(report)
    unsigned["artifact_hmac_sha256"] = None
    assert hmac.compare_digest(
        signature,
        hmac.new(
            artifact_key,
            json.dumps(
                unsigned,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest(),
    )


def test_durable_recorder_cursor_advances_only_through_returned_rows(tmp_path) -> None:
    rows = [
        (
            41,
            Event(
                "Sensor",
                "PowerShell detection T1059.001",
                Severity.HIGH,
                details={"mitre": "T1059.001"},
            ),
        ),
        (
            42,
            Event(
                "Sensor",
                "Ransomware T1486",
                Severity.CRITICAL,
                details={"mitre": "T1486"},
            ),
        ),
    ]
    recorder = _Recorder(rows, backlog=5, highwater=45)
    module = _module(tmp_path)
    module.bind_recorder(recorder)

    coverage = module._drain_events()

    assert module._cursor_id == 42
    assert [item["recorder_id"] for item in module._incidents] == [41, 42]
    assert coverage["backlog_remaining"] == 3
    assert coverage["complete"] is False
    assert recorder.cursors == [(0, cmap._MAX_DURABLE_BATCH)]


def test_authenticated_state_survives_restart_and_rejects_tamper(tmp_path) -> None:
    module = _module(tmp_path)
    module._state_status = "new"
    module._cursor_id = 9
    module._append_event(
        Event("Sensor", "T1082", Severity.MEDIUM, details={"mitre": "T1082"}),
        recorder_id=9,
    )
    module._save_state()

    restarted = _module(tmp_path)
    assert restarted._load_state()
    assert restarted._cursor_id == 9
    assert restarted._incidents[0]["recorder_id"] == 9

    path = tmp_path / "compliance.state.json"
    document = json.loads(path.read_text("utf-8"))
    document["cursor_id"] = 99
    path.write_text(json.dumps(document), encoding="utf-8")
    tampered = _module(tmp_path)
    assert not tampered._load_state()
    assert tampered._state_status == "invalid"


def test_eventbus_fallback_and_overflow_are_explicitly_incomplete(tmp_path) -> None:
    module = _module(tmp_path)
    bus = EventBus(ring_size=2)
    module.bind(bus)
    for index in range(5):
        bus.publish(
            Event(
                "Sensor",
                f"T1059 event {index}",
                Severity.MEDIUM,
                details={"mitre": "T1059"},
            )
        )

    coverage = module._drain_events()

    assert coverage["source"] == "eventbus-fallback"
    assert coverage["complete"] is False
    assert module._bus_overflows >= 1


def test_retention_loss_is_counted_before_deque_eviction(tmp_path) -> None:
    module = _module(tmp_path)
    for index in range(2001):
        module._append_event(
            Event(
                "Sensor",
                f"T1059 event {index}",
                Severity.INFO,
                details={"mitre": "T1059"},
            ),
            recorder_id=index + 1,
        )

    assert len(module._incidents) == 2000
    assert module._retention_drops == 1
    assert module._incidents[0]["recorder_id"] == 2
