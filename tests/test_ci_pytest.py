"""The CI observer preserves pytest and native shutdown failures separately."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from angerona.core.privilege import sanitized_child_environment


ROOT = Path(__file__).resolve().parents[1]


def _run(tmp_path, arguments, *, fake_body=None, journal_initial=None, environment_updates=None):
    environment = sanitized_child_environment(source={})
    journal = tmp_path / "exit.jsonl"
    trace = tmp_path / "trace.jsonl"
    environment.update({
        "ANGERONA_PYTEST_EXIT_PATH": str(journal),
        "ANGERONA_PYTEST_TRACE_PATH": str(trace),
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "QT_QPA_PLATFORM": "offscreen",
        "TEMP": str(tmp_path), "TMP": str(tmp_path),
    })
    environment.update(environment_updates or {})
    if journal_initial is not None:
        journal.write_text(journal_initial, encoding="utf-8")
    if fake_body is not None:
        package = tmp_path / "pytest"
        package.mkdir()
        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "__main__.py").write_text(fake_body, encoding="utf-8")
        environment["PYTHONPATH"] = str(tmp_path)
    child_arguments = list(arguments)
    if fake_body is None:
        # An explicit file can still make pytest enumerate all ancestor
        # directories. Keep real inert probes inside their owned fixture;
        # accumulated repository scratch must not consume the 30s deadline.
        child_arguments[:0] = ["--confcutdir", str(tmp_path), "--rootdir", str(tmp_path)]
    result = subprocess.run(
        [sys.executable, "-X", "faulthandler", "-m", "tools.ci_pytest", *child_arguments],
        cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    records = [json.loads(line) for line in journal.read_text(encoding="utf-8").splitlines()]
    return result, records, trace


@pytest.mark.parametrize("outcome", [
    "exit-zero", "exit-one", "exception", "closed-stdout", "string-exit",
])
def test_module_arguments_and_original_failures_are_preserved(tmp_path, outcome):
    arguments = ["-q", "inert path with spaces", "--maxfail=1"]
    received = tmp_path / "arguments.json"
    endings = {
        "exit-zero": "raise SystemExit(0)",
        "exit-one": "raise SystemExit(1)",
        "exception": "raise RuntimeError('inert pytest exception probe')",
        "closed-stdout": "sys.stdout.close()\nraise SystemExit(1)",
        "string-exit": "raise SystemExit('inert-private-exit-value')",
    }
    body = (
        "import json, sys\nfrom pathlib import Path\n"
        f"Path({str(received)!r}).write_text(json.dumps(sys.argv[1:]), encoding='utf-8')\n"
        + endings[outcome] + "\n"
    )
    result, records, _trace = _run(tmp_path, arguments, fake_body=body)
    assert json.loads(received.read_text(encoding="utf-8")) == arguments
    assert result.returncode == (0 if outcome == "exit-zero" else 1), result.stderr
    if outcome == "exception":
        assert any(row["kind"] == "pytest-exception" and row["exception_type"] == "RuntimeError"
                   for row in records)
        assert "inert pytest exception probe" in result.stderr
    elif outcome == "string-exit":
        exit_record = next(row for row in records if row["kind"] == "pytest-system-exit")
        assert exit_record["exit_code_type"] == "str"
        assert "exit_code" not in exit_record
        assert "inert-private-exit-value" not in json.dumps(records)
    else:
        assert any(row["kind"] == "pytest-system-exit"
                   and row["exit_code"] == result.returncode for row in records)
    kinds = [row["kind"] for row in records]
    assert kinds[-3:] == ["pytest-entrypoint-finished", "python-atexit-begin", "python-atexit-end"]


def test_later_native_exit_cannot_be_replaced_by_passing_pytest_code(tmp_path):
    body = (
        "import atexit, os\n"
        "atexit.register(lambda: os._exit(7))\n"
        "raise SystemExit(0)\n"
    )
    result, records, _trace = _run(tmp_path, [], fake_body=body)
    assert result.returncode == 7
    assert any(row["kind"] == "pytest-system-exit" and row["exit_code"] == 0 for row in records)
    assert records[-1]["kind"] == "python-atexit-begin"
    assert not any(row["kind"] == "python-atexit-end" for row in records)


def test_existing_journal_is_preserved_without_changing_a_passing_exit(tmp_path):
    existing = '{"kind":"retained-evidence"}\n'
    result, records, _trace = _run(
        tmp_path, [], fake_body="raise SystemExit(0)\n", journal_initial=existing,
    )
    assert result.returncode == 0, result.stderr
    assert records == [{"kind": "retained-evidence"}]
    assert (tmp_path / "exit.jsonl").read_text(encoding="utf-8") == existing
    assert "exit journal could not be opened" in result.stderr


def test_broken_exit_journal_cannot_change_passing_pytest_exit(tmp_path):
    body = """import gc, io, os
owned = [stream for stream in gc.get_objects()
         if isinstance(stream, io.TextIOWrapper)
         and stream.name == os.environ['ANGERONA_PYTEST_EXIT_PATH']]
assert len(owned) == 1, 'exact owned diagnostic stream was not found'
owned[0].close()
raise SystemExit(0)
"""
    result, records, _trace = _run(tmp_path, [], fake_body=body)
    assert result.returncode == 0, result.stderr
    assert len(records) == 1
    assert records[0]["kind"] == "process-start"


@pytest.mark.parametrize("passes", [True, False])
def test_actual_pytest_records_final_session_and_unconfigure_status(tmp_path, passes):
    probe = tmp_path / "test_inert_probe.py"
    probe.write_text(f"def test_inert_probe():\n    assert {passes!r}\n", encoding="utf-8")
    result, records, trace = _run(
        tmp_path, ["-q", "-p", "tools.pytest_execution_trace", str(probe)],
    )
    expected = 0 if passes else 1
    assert result.returncode == expected, result.stdout + result.stderr
    assert any(row["kind"] == "pytest-system-exit" and row["exit_code"] == expected for row in records)
    phases = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    finish = next(row for row in phases if row["kind"] == "session-finish")
    assert finish["exitstatus"] == expected
    assert finish["testsfailed"] == expected
    assert finish["testscollected"] == 1
    assert [row["kind"] for row in phases][-3:] == [
        "unconfigure-begin", "unconfigure-end", "session-end",
    ]
    assert phases[-2]["completed"] is True


def test_real_probe_collection_never_visits_ancestor_scratch(tmp_path):
    visited = tmp_path / "visited.jsonl"
    (tmp_path / "boundary_plugin.py").write_text(
        "import json, os\nfrom pathlib import Path\nimport pytest\n"
        "@pytest.hookimpl(tryfirst=True)\n"
        "def pytest_collect_directory(path, parent):\n"
        "    expected = Path(os.environ['ANGERONA_PROBE_COLLECTION_ROOT'])\n"
        "    assert path == expected, 'inert probe escaped its owned collection root'\n"
        "    with (expected / 'visited.jsonl').open('a', encoding='utf-8') as stream:\n"
        "        stream.write(json.dumps({'owned': path == expected}) + '\\n')\n",
        encoding="utf-8",
    )
    probe = tmp_path / "test_inert_probe.py"
    probe.write_text("def test_inert_probe():\n    assert True\n", encoding="utf-8")
    result, records, trace = _run(
        tmp_path, ["-q", "-p", "tools.pytest_execution_trace", "-p", "boundary_plugin", str(probe)],
        environment_updates={"PYTHONPATH": str(tmp_path), "ANGERONA_PROBE_COLLECTION_ROOT": str(tmp_path)},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert [json.loads(line) for line in visited.read_text(encoding="utf-8").splitlines()] == [{"owned": True}]
    phases = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    finish = next(row for row in phases if row["kind"] == "session-finish")
    assert finish["testscollected"] == 1 and finish["exitstatus"] == 0
    assert any(row["kind"] == "pytest-system-exit" and row["exit_code"] == 0 for row in records)
    assert {"python-atexit-begin", "python-atexit-end"} <= {row["kind"] for row in records}


def test_broken_trace_write_and_close_preserve_original_unconfigure_exception(tmp_path):
    (tmp_path / "fault_plugin.py").write_text("""def pytest_unconfigure(config):
    from tools import pytest_execution_trace as observer
    observer._stream.close()
    class BrokenStream:
        def write(self, _value):
            raise OSError('inert observer write failure')
        def flush(self):
            raise OSError('inert observer flush failure')
        def close(self):
            raise OSError('inert observer close failure')
    observer._stream = BrokenStream()
    raise RuntimeError('inert original unconfigure failure')
""", encoding="utf-8")
    probe = tmp_path / "test_inert_probe.py"
    probe.write_text("def test_inert_probe():\n    assert True\n", encoding="utf-8")
    result, records, trace = _run(
        tmp_path, ["-q", "-p", "tools.pytest_execution_trace", "-p", "fault_plugin", str(probe)],
        environment_updates={"PYTHONPATH": str(tmp_path)},
    )
    assert result.returncode == 1
    assert "inert original unconfigure failure" in result.stderr
    assert any(row["kind"] == "pytest-exception" and row["exception_type"] == "RuntimeError"
               for row in records)
    phases = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    assert any(row["kind"] == "session-finish" and row["exitstatus"] == 0 for row in phases)
    assert phases[-1]["kind"] == "unconfigure-begin"


def test_collection_failure_remains_nonzero_and_retains_its_cause(tmp_path):
    probe = tmp_path / "test_inert_collection.py"
    probe.write_text("import missing_inert_ci_collection_probe\n", encoding="utf-8")
    result, records, trace = _run(
        tmp_path, ["-q", "-p", "tools.pytest_execution_trace", str(probe)],
    )
    assert result.returncode == 2, result.stdout + result.stderr
    assert any(row["kind"] == "pytest-system-exit" and row["exit_code"] == 2 for row in records)
    phases = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    failed_collection = next(row for row in phases if row["kind"] == "collection-report")
    assert failed_collection["outcome"] == "failed"
    assert "missing_inert_ci_collection_probe" in failed_collection["failure"]
    finish = next(row for row in phases if row["kind"] == "session-finish")
    assert finish["exitstatus"] == 2 and finish["testsfailed"] == 1 and finish["testscollected"] == 0
