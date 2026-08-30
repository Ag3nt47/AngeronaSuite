from __future__ import annotations

import json
import os

import pytest

from angerona.core.eventbus import EventBus
from angerona.modules import file_integrity as fim


def _module(tmp_path, monkeypatch, watch_root):
    monkeypatch.setattr(fim, "watch_roots", lambda: [str(watch_root)])
    module = fim.FileIntegrityModule()
    module._baseline_path_override = tmp_path / "fim-baseline.json"
    module._baseline_key_override = b"K" * 32
    return module


def test_baseline_requires_explicit_complete_review_and_is_authenticated(
    tmp_path, monkeypatch
) -> None:
    watched = tmp_path / "watched"
    watched.mkdir()
    target = watched / "policy.conf"
    target.write_text("allow=false\n", encoding="utf-8")
    module = _module(tmp_path, monkeypatch, watched)
    module._baseline = module._scan()
    module._driver_baseline = {"reviewed.sys"}

    with pytest.raises(PermissionError):
        module.approve_current_baseline()
    destination = module.approve_current_baseline(approved=True)

    loaded_module = _module(tmp_path, monkeypatch, watched)
    loaded = loaded_module._load_approved_baseline()
    assert loaded is not None
    files, drivers = loaded
    assert files == module._baseline
    assert drivers == {"reviewed.sys"}
    assert loaded_module._baseline_status == "approved"

    document = json.loads(destination.read_text("utf-8"))
    document["files"][str(target)] = "0" * 64
    destination.write_text(json.dumps(document), encoding="utf-8")
    tampered_module = _module(tmp_path, monkeypatch, watched)
    assert tampered_module._load_approved_baseline() is None
    assert tampered_module._baseline_status == "invalid"


def test_missing_approved_file_is_detected_on_first_complete_scan(
    tmp_path, monkeypatch
) -> None:
    watched = tmp_path / "watched"
    watched.mkdir()
    target = watched / "startup-target.bin"
    target.write_bytes(b"trusted")
    module = _module(tmp_path, monkeypatch, watched)
    module._baseline = module._scan()
    module._driver_baseline = set()
    module.approve_current_baseline(approved=True)

    restarted = _module(tmp_path, monkeypatch, watched)
    loaded = restarted._load_approved_baseline()
    assert loaded is not None
    restarted._baseline, restarted._driver_baseline = loaded
    bus = EventBus()
    restarted.bind(bus)
    target.unlink()

    current = restarted._scan()
    assert restarted._last_scan_receipt["complete"] is True
    restarted._evaluate_snapshot(current)

    events = bus.recent(20)
    assert any(
        event.details.get("path") == str(target) and "deleted" in event.message
        for event in events
    )


def test_metadata_preserving_rewrite_invalidates_windows_change_token_cache(
    tmp_path, monkeypatch
) -> None:
    watched = tmp_path / "watched"
    watched.mkdir()
    target = watched / "same-size.bin"
    target.write_bytes(b"AAAA")
    module = _module(tmp_path, monkeypatch, watched)
    first = module._scan()
    assert first, module._last_scan_receipt
    module._baseline = first
    before = target.stat()

    target.write_bytes(b"BBBB")
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
    second = module._scan()

    assert str(target) in first, (tuple(first), str(target))
    assert str(target) in second, module._last_scan_receipt
    assert first[str(target)] != second[str(target)]
    assert module._last_scan_receipt["files_hashed"] == 1
    assert module._last_scan_receipt["hashes_reused"] == 0


def test_incomplete_root_never_reports_green_or_allows_approval(
    tmp_path, monkeypatch
) -> None:
    missing = tmp_path / "missing"
    module = _module(tmp_path, monkeypatch, missing)
    module._baseline_status = "approved"
    module._driver_collection_ok = True
    module._baseline = module._scan()

    module._set_coverage_health()

    assert module._last_scan_receipt["complete"] is False
    assert module.health <= 35
    assert "unavailable" in module.health_note
    with pytest.raises(RuntimeError):
        module.approve_current_baseline(approved=True)
