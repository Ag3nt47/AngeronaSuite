"""The advisory Scan Center shares collector evidence without sharing mutation."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import threading
import time
from types import SimpleNamespace

import psutil
import pytest

from angerona.core.security_scan_center import MAX_CONNECTIONS, ScanCancellationToken, SecurityScanCenter
from angerona.telemetry import sensors


NOW = 1_700_000_000.0


def _row(host="::", port=445):
    return SimpleNamespace(pid=None, status="LISTEN", laddr=SimpleNamespace(ip=host, port=port), raddr=None)


def _center(**kwargs):
    return SecurityScanCenter(usb_authorizer=lambda _path: (None, "inert"), wall_clock=lambda: NOW + 0.1, **kwargs)


@pytest.fixture
def shared_collector(monkeypatch):
    monkeypatch.setattr(sensors, "_conn_cache", (0.0, None))
    monkeypatch.setattr(sensors, "_CACHE_TTL", 1.5)
    monkeypatch.setattr(sensors, "time", SimpleNamespace(monotonic=lambda: 100.0, time=lambda: NOW))
    calls = []

    def collect(**kwargs):
        calls.append(kwargs)
        time.sleep(0.02)  # inert model of an OS call that releases the GIL
        return [_row(), _row("::1", 8080)]

    monkeypatch.setattr(psutil, "net_connections", collect)
    return calls


def test_eight_detectors_and_eight_default_audits_share_one_collection(shared_collector):
    barrier = threading.Barrier(16)

    def run(kind):
        barrier.wait(timeout=5)
        return sensors.connection_snapshot() if kind == "sensor" else _center().audit_listening_exposure()

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(run, ["sensor"] * 8 + ["audit"] * 8))
    assert len(shared_collector) == 1
    assert all(receipt is results[0] for receipt in results[:8])
    for result in results[8:]:
        assert result.status == "completed"
        assert result.metrics["inventory_source"] == "shared-connection-snapshot"
        assert result.metrics["source_complete"] is True
        assert result.metrics["listeners_reviewed"] == 2
        assert result.metrics["all_interface_listeners"] == 1
        rendered = json.dumps(result.to_dict(), allow_nan=False)
        assert '"pid"' not in rendered and "::1" not in rendered


def test_cached_rows_are_read_only_and_public_exports_are_detached(shared_collector):
    receipt = sensors.connection_snapshot()
    with pytest.raises(TypeError):
        receipt.connections[0]["status"] = "poisoned"
    copied = sensors.list_connections()
    copied[0]["status"] = "private edit"
    exported = receipt.to_dict()
    exported["connections"][0]["status"] = "export edit"
    json.dumps(exported, allow_nan=False)
    assert sensors.connection_snapshot().connections[0]["status"] == "LISTEN"
    assert len(shared_collector) == 1
    original = {"pid": 1, "status": "LISTEN", "laddr": "127.0.0.1:1", "raddr": ""}
    detached = sensors.ConnectionSnapshot((original,), NOW, True, 1, 0)
    original["status"] = "changed after construction"
    assert detached.connections[0]["status"] == "LISTEN"


@pytest.mark.parametrize("endpoint,expected", [
    ("127.0.0.1:8080", ("127.0.0.1", 8080)),
    ("::1:8080", ("::1", 8080)),
    ("[::1]:8080", ("::1", 8080)),
    (":::445", ("::", 445)),
    ("[2001:db8::1]:443", ("2001:db8::1", 443)),
    ("[::1:8080", ("", 0)), ("::1]:8080", ("", 0)),
    ("[::1]:443:5", ("", 0)), ("127.0.0.1:65536", ("", 0)),
    ("127.0.0.1:-1", ("", 0)), ("127.0.0.1:１２", ("", 0)),
    (("::1", 8080), ("::1", 8080)),
])
def test_shared_ipv6_endpoints_preserve_listener_scope(endpoint, expected):
    assert SecurityScanCenter._endpoint(endpoint) == expected


@pytest.mark.parametrize("complete,rows,stamp,error,expected", [
    (False, (), NOW, "denied", "error"),
    (False, ({"status": "LISTEN", "laddr": ":::445"},), NOW, "row lost", "limited"),
    (True, (), NOW - 5, "", "error"),
    (True, (), NOW + 5, "", "error"),
    (True, (), float("nan"), "", "error"),
    (True, (), float("inf"), "", "error"),
    (True, (), NOW, "inconsistent failure", "error"),
])
def test_partial_denied_or_unverified_age_is_never_a_clean_audit(monkeypatch, complete, rows, stamp, error, expected):
    receipt = sensors.ConnectionSnapshot(rows, stamp, complete, len(rows), 0, error)
    monkeypatch.setattr(sensors, "connection_snapshot", lambda **kwargs: receipt)
    result = _center().audit_listening_exposure()
    assert result.status == expected and result.errors
    json.dumps(result.to_dict(), allow_nan=False)


def test_shared_audit_retains_row_cap_and_cooperative_cancel(monkeypatch):
    row = {"pid": None, "status": "LISTEN", "laddr": ":::445", "raddr": ""}
    receipt = sensors.ConnectionSnapshot((row,) * (MAX_CONNECTIONS + 1), NOW, True, MAX_CONNECTIONS + 1, 0)
    monkeypatch.setattr(sensors, "connection_snapshot", lambda **kwargs: receipt)
    result = _center().audit_listening_exposure()
    assert result.status == "limited" and result.metrics["connections_examined"] == MAX_CONNECTIONS
    token = ScanCancellationToken()
    canceled = _center().audit_listening_exposure(cancellation=token, progress=lambda _record: token.cancel())
    assert canceled.status == "cancelled" and canceled.metrics["listeners_reviewed"] == 1


def test_precanceled_audit_performs_no_collection(monkeypatch):
    def refused(**kwargs):
        raise AssertionError("pre-canceled audit reached the collector")
    monkeypatch.setattr(sensors, "connection_snapshot", refused)
    token = ScanCancellationToken()
    token.cancel()
    result = _center().audit_listening_exposure(cancellation=token)
    assert result.status == "cancelled" and result.executed is False


def test_late_native_collection_is_not_reported_completed(monkeypatch):
    elapsed = [0.0]
    def delayed(**kwargs):
        elapsed[0] = 2.0
        return sensors.ConnectionSnapshot((), NOW, True, 0, 0)
    monkeypatch.setattr(sensors, "connection_snapshot", delayed)
    result = _center(monotonic=lambda: elapsed[0], max_duration_seconds=1).audit_listening_exposure()
    assert result.status == "limited" and result.metrics["timed_out"] is True


def test_explicit_psutil_provider_stays_independent(monkeypatch):
    def refused(**kwargs):
        raise AssertionError("injected provider reached the shared collector")
    monkeypatch.setattr(sensors, "connection_snapshot", refused)
    provider = SimpleNamespace(net_connections=lambda **kwargs: [_row("::1", 8080)], CONN_LISTEN="LISTEN")
    result = _center(psutil_module=provider).audit_listening_exposure()
    assert result.status == "completed" and result.metrics["listeners_reviewed"] == 1
    assert "inventory_source" not in result.metrics
