"""Crash hunter: read-only, bounded, rate-limited evidence sweep."""
from __future__ import annotations

import ast
import json
import os
import time
from pathlib import Path

from angerona.resilience import crash_hunter
from angerona.resilience.crash_hunter import CrashHunter

CORE_STOP = {"unexpected_stop": True, "component": "core"}


def test_sweep_reports_recent_temp_drops_and_is_marked_read_only(tmp_path):
    drop = tmp_path / "nested" / "payload.ps1"
    drop.parent.mkdir()
    drop.write_text("inert")
    (tmp_path / "notes.txt").write_text("ignored suffix")
    old = tmp_path / "old.exe"
    old.write_text("inert")
    os.utime(old, (time.time() - 7200, time.time() - 7200))
    report = crash_hunter.sweep(time.time() - 60, temp_root=tmp_path)
    assert report["read_only"] is True and report["schema"] == "angerona.crash-hunt.v1"
    assert [Path(row["path"]).name for row in report["temp_drops"]] == ["payload.ps1"]
    assert isinstance(report["processes"], list) and "autoruns" in report
    assert drop.read_text() == "inert" and old.exists()  # Nothing was changed.


def test_sweep_never_raises_and_records_collector_errors(monkeypatch, tmp_path):
    monkeypatch.setattr(crash_hunter, "_new_processes", lambda *_: (_ for _ in ()).throw(RuntimeError("x")))
    report = crash_hunter.sweep(temp_root=tmp_path)
    assert report["processes"] == [] and report["complete"] is False
    assert "processes:RuntimeError" in report["errors"]


def test_only_unexpected_core_stops_trigger_and_sweeps_are_rate_limited(tmp_path):
    clock = [1000.0]
    published, sweeps = [], []

    def sweeper():
        sweeps.append(1)
        return {"ts": 1.0, "processes": [{}], "connections": [], "temp_drops": [],
                "autoruns": {"sha256": "a"}, "complete": True}

    hunter = CrashHunter(lambda *a: published.append(a), report_dir=tmp_path,
                         clock=lambda: clock[0], sweeper=sweeper, background=False)
    assert not hunter.on_supervisor_event("HIGH", "x", {"component": "core"})
    assert not hunter.on_supervisor_event("HIGH", "x", {"unexpected_stop": True, "component": "scanner"})
    assert hunter.on_supervisor_event("HIGH", "x", CORE_STOP)
    assert not hunter.on_supervisor_event("HIGH", "x", CORE_STOP)  # Within 60 s.
    clock[0] += 61
    assert hunter.on_supervisor_event("HIGH", "x", CORE_STOP)
    assert len(sweeps) == 2 and [p[0] for p in published] == ["MEDIUM", "MEDIUM"]
    assert json.loads(next(tmp_path.glob("crash_hunt_*.json")).read_text())["complete"] is True


def test_remote_connections_drops_or_autorun_change_raise_severity(tmp_path):
    clock = [0.0]
    reports = iter([
        {"ts": 1.0, "processes": [], "connections": [], "temp_drops": [], "autoruns": {"sha256": "a"}},
        {"ts": 2.0, "processes": [], "connections": [], "temp_drops": [], "autoruns": {"sha256": "b"}},
        {"ts": 3.0, "processes": [], "connections": [{}], "temp_drops": [], "autoruns": {"sha256": "b"}},
    ])
    published = []
    hunter = CrashHunter(lambda *a: published.append(a), report_dir=tmp_path,
                         clock=lambda: clock[0], sweeper=lambda: next(reports), background=False)
    for _ in range(3):
        hunter.on_supervisor_event("HIGH", "x", CORE_STOP)
        clock[0] += 61
    assert [p[0] for p in published] == ["MEDIUM", "HIGH", "HIGH"]
    assert published[1][2]["autoruns_changed_since_last_sweep"] is True


def test_module_contains_no_host_mutation_calls():
    """Static guard: the hunter must stay observe-only."""
    source = Path(crash_hunter.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    called = {node.func.attr for node in ast.walk(tree)
              if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
    forbidden = {"kill", "terminate", "suspend", "Popen", "run", "system", "remove", "rmtree",
                 "SetValueEx", "DeleteValue", "DeleteKey", "CreateKey", "rename", "replace"}
    assert not (called & forbidden), called & forbidden
    assert "import subprocess" not in source
