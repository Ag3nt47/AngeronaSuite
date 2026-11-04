"""The observer must preserve failures and retain an isolated native fatal event."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from angerona.core.privilege import sanitized_child_environment


@pytest.mark.parametrize("fault", ["assertion", "qt-fatal", "mocked-functions"])
def test_trace_preserves_failure_and_last_test_identity(tmp_path, fault):
    if fault == "qt-fatal":
        pytest.importorskip("PySide6.QtCore")
    probe = tmp_path / "test_trace_probe.py"
    body = "    assert False, 'inert assertion probe'\n"
    if fault == "qt-fatal":
        body = (
            "    import os\n"
            "    if os.name == 'nt':\n"
            "        import ctypes\n"
            "        ctypes.windll.kernel32.SetErrorMode(0x8007)\n"
            "    from PySide6.QtCore import qFatal\n"
            "    qFatal('isolated fatal trace probe')\n"
        )
    if fault == "mocked-functions":
        body = (
            "    import time, json\n"
            "    clock = iter([1.0, 2.0])\n"
            "    monkeypatch.setattr(time, 'monotonic', lambda: next(clock))\n"
            "    monkeypatch.setattr(json, 'dumps', lambda *_args, **_kwargs: 'mocked serializer')\n"
            "    assert time.monotonic() == 1.0\n"
            "    assert json.dumps({}) == 'mocked serializer'\n"
            "    assert time.monotonic() == 2.0\n"
        )
    parameters = "monkeypatch" if fault == "mocked-functions" else ""
    probe.write_text(f"def test_inert_probe({parameters}):\n" + body, encoding="utf-8")
    trace = tmp_path / "execution.jsonl"
    environment = sanitized_child_environment(source={})
    # These child probes exercise only the explicitly selected observer.
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    environment["TEMP"] = str(tmp_path)
    environment["TMP"] = str(tmp_path)
    environment["QT_QPA_PLATFORM"] = "offscreen"
    environment["ANGERONA_PYTEST_TRACE_PATH"] = str(trace)
    # Keep the named observer importable from the repository, while collection
    # starts at this one disposable probe rather than scanning ancestor siblings.
    result = subprocess.run(
        [
            sys.executable, "-m", "pytest", "-q",
            "--confcutdir", str(tmp_path), "--rootdir", str(tmp_path),
            "-p", "tools.pytest_execution_trace", str(probe),
        ],
        cwd=Path(__file__).resolve().parents[1], env=environment,
        capture_output=True, timeout=60,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if fault == "mocked-functions":
        assert result.returncode == 0, result.stdout.decode(errors="replace")
    else:
        assert result.returncode != 0, "diagnostic observation must never turn failure into success"
    records = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    assert any(row["kind"] == "test-start" and row["nodeid"].endswith("test_inert_probe") for row in records), (
        result.returncode, result.stdout.decode(errors="replace"), result.stderr.decode(errors="replace"),
    )
    starts = [row for row in records if row["kind"] == "test-start"]
    assert [row["nodeid"] for row in starts] == ["test_trace_probe.py::test_inert_probe"]
    if fault != "qt-fatal":
        reports = [row for row in records
                   if row["kind"] == "test-report" and row.get("when") == "call"]
        assert len(reports) == 1 and reports[0]["nodeid"] == starts[0]["nodeid"]
        finishes = [row for row in records if row["kind"] == "session-finish"]
        assert len(finishes) == 1
        expected_status = 1 if fault == "assertion" else 0
        assert result.returncode == expected_status
        assert finishes[0]["exitstatus"] == expected_status
        assert finishes[0]["testsfailed"] == expected_status
        assert finishes[0]["testscollected"] == 1
        assert [(row["kind"], row.get("completed")) for row in records
                if row["kind"] in {"unconfigure-begin", "unconfigure-end", "session-end"}] == [
            ("unconfigure-begin", None), ("unconfigure-end", True), ("session-end", None),
        ]
        assert records[-1]["kind"] == "session-end"
    if fault == "assertion":
        assert any(row.get("outcome") == "failed" and row.get("when") == "call" for row in records)
        assert "inert assertion probe" in reports[0]["failure"]
    elif fault == "qt-fatal":
        assert any(
            row["kind"] == "qt-message" and row["severity"] == "QtFatalMsg"
            # PySide can normalize Python qFatal messages to its own text.
            and row["message"] and row["nodeid"].endswith("test_inert_probe")
            for row in records
        )
    else:
        assert any(row.get("outcome") == "passed" and row.get("when") == "call" for row in records)
