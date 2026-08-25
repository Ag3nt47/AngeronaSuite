from __future__ import annotations

import json
import os
from pathlib import Path
from types import ModuleType, SimpleNamespace


def test_dashboard_ready_marker_is_canonical_atomic_and_pid_bound(
    tmp_path: Path, monkeypatch,
) -> None:
    from angerona.app import _mark_dashboard_ready

    marker = tmp_path / "logs" / "dashboard-ready.signal"
    monkeypatch.setenv("ANGERONA_STARTUP_READY", str(marker))

    assert _mark_dashboard_ready(SimpleNamespace(data_dir=tmp_path)) is True
    payload = json.loads(marker.read_text(encoding="utf-8"))
    assert payload["pid"] == os.getpid()
    assert isinstance(payload["ready_at"], float)
    assert not list(marker.parent.glob(".dashboard-ready.*.tmp"))


def test_dashboard_ready_marker_rejects_any_other_write_location(
    tmp_path: Path, monkeypatch,
) -> None:
    from angerona.app import _mark_dashboard_ready

    outside = tmp_path / "outside" / "dashboard-ready.signal"
    monkeypatch.setenv("ANGERONA_STARTUP_READY", str(outside))

    assert _mark_dashboard_ready(SimpleNamespace(data_dir=tmp_path / "runtime")) is False
    assert not outside.exists()


def test_fast_pyside_detection_uses_module_state_instead_of_source_reads(
    monkeypatch,
) -> None:
    from PySide6.QtCore import QObject
    import shibokensupport.feature as feature

    from angerona.__main__ import _install_fast_pyside_feature_detection

    monkeypatch.delattr(feature, "_angerona_fast_detection", raising=False)

    def source_read_must_not_run(_module):
        raise AssertionError("unexpected source inspection")

    monkeypatch.setattr(feature, "_mod_uses_pyside", source_read_must_not_run)
    assert _install_fast_pyside_feature_detection() is True

    angerona_module = ModuleType("angerona.startup_probe")
    assert feature._mod_uses_pyside(angerona_module) is True

    qt_module = ModuleType("third_party.qt_probe")
    qt_module.QObject = QObject
    assert feature._mod_uses_pyside(qt_module) is True

    plain_module = ModuleType("third_party.plain_probe")
    assert feature._mod_uses_pyside(plain_module) is False

