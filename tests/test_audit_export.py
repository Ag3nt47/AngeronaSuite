import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

import angerona.core.audit_export as audit_export
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
        "actor": "SampleUser@example.com",
        "details": {
            "device_id": "device-001",
            "username": "SampleUser",
            "path": r"C:\Users\SampleUser\private.exe",
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
    assert "SampleUser" not in raw
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


def test_input_record_and_byte_bounds_stop_generators_without_exhausting(monkeypatch):
    exporter = AuditExporter(b"k" * 32, b"s" * 16, clock=lambda: 500)
    yielded: list[int] = []

    def too_many_events():
        for index in range(4):
            yielded.append(index)
            if index == 3:
                raise AssertionError("exporter exhausted the untrusted iterable")
            yield _event(f"event-{index:03d}", index)

    monkeypatch.setattr(audit_export, "MAX_INPUT_RECORDS", 2)
    with pytest.raises(ValueError, match="100000 records"):
        exporter.export(too_many_events(), _request())
    assert yielded == [0, 1, 2]

    byte_yielded: list[int] = []

    def oversized_events():
        byte_yielded.append(1)
        yield _event("event-100", 100)
        raise AssertionError("exporter read beyond the byte budget")

    monkeypatch.setattr(audit_export, "MAX_INPUT_RECORDS", 100_000)
    monkeypatch.setattr(audit_export, "MAX_INPUT_BYTES", 1)
    with pytest.raises(ValueError, match="64 MiB"):
        exporter.export(oversized_events(), _request())
    assert byte_yielded == [1]


def test_privacy_bearing_mapping_keys_are_redacted_from_export():
    exporter = AuditExporter(b"k" * 32, b"s" * 16, clock=lambda: 500)
    details = {
        "contact=private.person@example.com": "contact record",
        "username=PrivatePerson": "account record",
        r"C:\Users\PrivatePerson\sensitive.txt": "file record",
        "secret=do-not-export": "credential record",
    }
    export = exporter.export(
        (_event("event-001", 10, details=details),),
        _request(),
    )
    raw = export.canonical().decode("utf-8")
    for private_value in (
        "private.person@example.com",
        "PrivatePerson",
        r"C:\\Users",
        "do-not-export",
    ):
        assert private_value not in raw
    assert exporter.verify(export)


@pytest.mark.parametrize(
    "details",
    (
        {"one@example.com": 1, "two@example.com": 2},
        {"x" * 128 + "a": 1, "x" * 128 + "b": 2},
    ),
)
def test_mapping_key_normalization_and_truncation_collisions_fail_closed(details):
    exporter = AuditExporter(b"k" * 32, b"s" * 16, clock=lambda: 500)
    with pytest.raises(ValueError, match="normalization collision"):
        exporter.export(
            (_event("event-001", 10, details=details),),
            _request(),
        )


def test_two_synchronized_writers_publish_whole_exports_without_temp_collision(
    tmp_path, monkeypatch,
):
    exporter = AuditExporter(b"k" * 32, b"s" * 16, clock=lambda: 500)
    first = exporter.export((_event("event-001", 10),), _request())
    second = exporter.export((_event("event-002", 20),), _request())
    target = tmp_path / "audit.json"
    start = threading.Barrier(2)
    first_replace = threading.Event()
    release_replace = threading.Event()
    call_guard = threading.Lock()
    replace_calls = 0
    original_replace = audit_export.replace_with_retry

    def slow_first_replace(source, destination):
        nonlocal replace_calls
        with call_guard:
            replace_calls += 1
            is_first = replace_calls == 1
        if is_first:
            first_replace.set()
            assert release_replace.wait(5)
        original_replace(source, destination)

    def writer(value):
        start.wait(timeout=5)
        write_audit_export(target, value)

    monkeypatch.setattr(audit_export, "replace_with_retry", slow_first_replace)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(writer, value) for value in (first, second)]
        assert first_replace.wait(5)
        time.sleep(0.05)
        release_replace.set()
        for future in futures:
            future.result(timeout=5)

    assert target.read_bytes() in {first.canonical(), second.canonical()}
    assert replace_calls == 2
    assert not list(tmp_path.glob(".audit.json.*.tmp"))
