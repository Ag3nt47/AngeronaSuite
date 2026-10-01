"""Coverage errors and retained worker tracebacks must remain honest and safe."""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

import angerona.core.security_scan_center as scan_module
from angerona.core.security_scan_center import SecurityScanCenter


@pytest.mark.parametrize("failure", ["read", "signature"])
def test_local_scan_failure_is_incomplete(tmp_path, monkeypatch, failure):
    target = tmp_path / "inert.txt"
    target.write_bytes(b"inert")
    center = SecurityScanCenter()

    class Scanner:
        def scan(self, _content):
            raise RuntimeError("signature engine failed")

    monkeypatch.setattr(center, "_make_yara_scanner", lambda: (Scanner(), "active"))
    if failure == "read":
        def unreadable(*_args, **_kwargs):
            raise PermissionError("read denied")
        monkeypatch.setattr(scan_module, "_read_scoped_file", unreadable)
    result = center.scan_path(target)
    assert result.status == "limited"
    assert result.errors


def test_retained_provider_traceback_releases_scanner_on_worker(tmp_path, monkeypatch):
    target = tmp_path / "inert.txt"
    target.write_bytes(b"inert")
    center = SecurityScanCenter()
    owners, finalized, retained = [], [], []

    class Scanner:
        def __init__(self):
            owners.append(threading.get_ident())

        def scan(self, _content):
            return SimpleNamespace(matching_rules=[])

        def __del__(self):
            finalized.append(threading.get_ident())

    def failed_result(*_args, **_kwargs):
        raise RuntimeError("result provider failed")

    monkeypatch.setattr(center, "_make_yara_scanner", lambda: (Scanner(), "active"))
    monkeypatch.setattr(center, "_result", failed_result)

    def worker():
        try:
            center.scan_path(target)
        except RuntimeError as exc:
            retained.append(exc)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(10)
    assert not thread.is_alive()
    assert retained and retained[0].__traceback__ is not None
    assert finalized == owners


def test_match_enumeration_stops_at_cap_and_reports_incomplete(tmp_path, monkeypatch):
    target = tmp_path / "inert.txt"
    target.write_bytes(b"inert")
    center = SecurityScanCenter()
    consumed = []

    def matches():
        for index in range(32):
            consumed.append(index)
            yield SimpleNamespace(identifier=f"Inert_{index}")
        raise AssertionError("must not consume the unbounded tail")

    class Scanner:
        def scan(self, _content):
            return SimpleNamespace(matching_rules=matches())

    monkeypatch.setattr(center, "_make_yara_scanner", lambda: (Scanner(), "active"))
    result = center.scan_path(target)
    assert result.status == "limited"
    assert result.metrics["signature_limit_reached"] is True
    assert len(result.findings) == len(consumed) == 32
    assert not result.errors


def test_interrupted_scanner_setup_detaches_retained_native_owner(tmp_path, monkeypatch):
    (tmp_path / "rules.yar").write_text("rule inert { condition: false }", encoding="utf-8")
    monkeypatch.setattr(scan_module, "resource_root", lambda: tmp_path)
    owners, finalized, retained = [], [], []

    class Compiler:
        def add_include_dir(self, _path):
            pass

        def add_source(self, _source, **_kwargs):
            pass

        def build(self):
            return object()

    class Scanner:
        def __init__(self, _rules):
            owners.append(threading.get_ident())

        def set_timeout(self, _timeout):
            # Rust methods have no Python self frame; model that boundary.
            self = None
            raise KeyboardInterrupt("setup interrupted")

        def __del__(self):
            finalized.append(threading.get_ident())

    center = SecurityScanCenter(yara_module=SimpleNamespace(Compiler=Compiler, Scanner=Scanner))

    def worker():
        try:
            center._make_yara_scanner()
        except KeyboardInterrupt as exc:
            retained.append(exc)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(10)
    assert not thread.is_alive()
    assert retained and retained[0].__traceback__ is not None
    assert finalized == owners


def test_unreadable_directory_is_incomplete_not_empty_success(tmp_path, monkeypatch):
    center = SecurityScanCenter()
    monkeypatch.setattr(center, "_make_yara_scanner", lambda: (None, "unavailable"))

    def denied(_path):
        raise PermissionError("directory listing denied")

    monkeypatch.setattr(scan_module.os, "scandir", denied)
    result = center.scan_path(tmp_path)
    assert result.status == "limited"
    assert result.metrics["files_scanned"] == 0
    assert result.metrics["unreadable_traversal_entries"] == 1
    assert result.errors == ("unreadable-traversal-entries:1",)
