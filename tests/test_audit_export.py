import json
from dataclasses import replace

import pytest

from angerona.core.audit_export import (
    AuditEvent, AuditExportRequest, AuditExporter, SignedAuditExport,
    write_audit_export,
)


def _event(record_id, timestamp, **overrides):
    value = {
        "record_id": record_id,
        "tenant_id": "tenant-001",
        "scope": "response",
        "timestamp": timestamp,
        "action": "process.contain",
        "outcome": "success",
        "actor": "Agent47@example.com",
        "details": {
            "device_id": "device-001",
            "username": "Agent47",
            "path": r"C:\Users\Agent47\private.exe",
            "password": "super-secret",
            "message": "password=super-secret from 10.2.3.4",
        },
    }
    value.update(overrides)
    return AuditEvent(**value)


def _request(**overrides):
    value = {
        "request_id": "export-001",
        "tenant_id": "tenant-001",
        "scopes": ("response",),
        "start_time": 0,
        "end_time": 1000,
        "max_records": 100,
        "requested_by": "operator-001",
    }
    value.update(overrides)
    return AuditExportRequest(**value)


def test_audit_export_filters_redacts_chains_and_signs(tmp_path):
    exporter = AuditExporter(b"k" * 32, b"s" * 16, clock=lambda: 500)
    export = exporter.export((
        _event("event-002", 20),
        _event("event-001", 10),
        _event("event-003", 30, tenant_id="tenant-002"),
        _event("event-004", 40, scope="identity"),
    ), _request())
    assert exporter.verify(export)
    assert [item.record_id for item in export.records] == [
        "event-001", "event-002",
    ]
    assert export.records[1].previous_hash == export.records[0].record_hash
    path = tmp_path / "audit.json"
    write_audit_export(path, export)
    raw = path.read_text(encoding="utf-8")
    assert "Agent47" not in raw
    assert "super-secret" not in raw
    assert r"C:\\Users" not in raw
    assert "10.2.3.4" not in raw
    assert json.loads(raw)["manifest"]["privacy_policy"]


def test_audit_export_tampering_and_wrong_key_fail_verification():
    exporter = AuditExporter(b"k" * 32, b"s" * 16, clock=lambda: 500)
    export = exporter.export((_event("event-001", 10),), _request())
    changed = SignedAuditExport(
        export.manifest, (replace(export.records[0], outcome="failure"),)
    )
    assert not exporter.verify(changed)
    assert not AuditExporter(
        b"x" * 32, b"s" * 16, clock=lambda: 500
    ).verify(export)


def test_export_limit_is_explicit_and_duplicate_ids_fail_closed():
    exporter = AuditExporter(b"k" * 32, b"s" * 16, clock=lambda: 500)
    export = exporter.export((
        _event("event-001", 10), _event("event-002", 20),
    ), _request(max_records=1))
    assert export.manifest.truncated
    assert export.manifest.input_count == 2
    assert export.manifest.exported_count == 1
    with pytest.raises(ValueError, match="duplicate"):
        exporter.export((
            _event("event-001", 10), _event("event-001", 20),
        ), _request())


def test_request_scope_time_and_payload_bounds_are_validated():
    with pytest.raises(ValueError, match="time range"):
        _request(start_time=2, end_time=1)
    with pytest.raises(ValueError, match="scopes"):
        _request(scopes=())
    with pytest.raises(ValueError, match="64 KiB"):
        _event("event-001", 10, details={"message": "x" * (70 * 1024)})
