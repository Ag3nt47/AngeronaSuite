from __future__ import annotations

import json
import os
from pathlib import Path
import time
from types import SimpleNamespace

import pytest

from angerona.core import sandbox_runner, source_sandbox


def workspace(tmp_path, source="VALUE = 1\n"):
    installed = tmp_path / "installed"
    installed.mkdir()
    (installed / "probe.py").write_text(source, encoding="utf-8")
    return source_sandbox.SourceSandboxWorkspace(
        "probe", ("probe.py",), source_root=installed,
        sandbox_root=tmp_path / "copies",
    )


def test_oversized_installed_source_is_refused_without_copy(tmp_path, monkeypatch):
    monkeypatch.setattr(source_sandbox, "MAX_SOURCE_BYTES", 64)
    current = workspace(tmp_path, "#" * 65)
    with pytest.raises(ValueError, match="source limit"):
        current.ensure()
    assert not current.file("probe.py").working_path.exists()


def test_oversized_candidate_is_refused_before_ast_or_overwrite(tmp_path, monkeypatch):
    current = workspace(tmp_path)
    current.ensure()
    monkeypatch.setattr(source_sandbox, "MAX_SOURCE_BYTES", 64)
    monkeypatch.setattr(source_sandbox.ast, "parse", lambda *_a, **_k: pytest.fail("oversized AST"))
    with pytest.raises(ValueError, match="source limit"):
        current.save("probe.py", "#" + "\u2603" * 30)
    assert current.reload("probe.py") == "VALUE = 1\n"
    assert current.file("probe.py").source_path.read_text() == "VALUE = 1\n"


def test_hardlinked_working_copy_is_not_read_as_sandbox_content(tmp_path):
    current = workspace(tmp_path)
    current.ensure()
    working = current.file("probe.py").working_path
    outside = tmp_path / "unrelated.txt"
    outside.write_text("not sandbox content")
    working.unlink()
    try:
        os.link(outside, working)
    except OSError as exc:
        pytest.skip(f"hardlink fixture unavailable: {exc}")
    with pytest.raises(ValueError, match="not regular"):
        current.reload("probe.py")
    assert outside.read_text() == "not sandbox content"


def test_working_copy_mutation_during_bounded_read_is_refused(tmp_path, monkeypatch):
    current = workspace(tmp_path)
    current.ensure()
    working = current.file("probe.py").working_path
    original_open = source_sandbox.os.fdopen
    read_limits = []

    class ChangedRead:
        def __init__(self, *args, **kwargs):
            self.handle = original_open(*args, **kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.handle.close()

        def read(self, limit):
            read_limits.append(limit)
            value = self.handle.read(limit)
            working.write_bytes(b"# changed content during read\n")
            return value

    scoped_os = SimpleNamespace(**vars(source_sandbox.os))
    scoped_os.fdopen = ChangedRead
    monkeypatch.setattr(source_sandbox, "os", scoped_os)
    with pytest.raises(ValueError, match="changed during its bounded read"):
        current.reload("probe.py")
    assert read_limits == [source_sandbox.MAX_SOURCE_BYTES + 1]


def probe(tmp_path, body):
    package = tmp_path / "bounded_probe"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "module.py").write_text(
        "class Probe:\n    name = 'Inert probe'\n    def self_test(self):\n"
        + "\n".join("        " + line for line in body.splitlines()) + "\n",
        encoding="utf-8",
    )


@pytest.mark.parametrize("write", ["print('X' * 4000)", "import os; os.write(1, b'X' * 65536)"])
def test_child_python_and_native_output_are_bounded(tmp_path, write):
    probe(tmp_path, write + "\nreturn True, 'must not pass with excessive output'")
    passed, output = sandbox_runner.run_isolated_self_test(
        "bounded_probe.module", "Probe", "Inert probe", source_root=tmp_path, timeout=10,
    )
    assert not passed
    assert "OUTPUT LIMIT" in output
    assert len(output) < 2000


def test_relative_probe_root_is_resolved_before_disposable_child_cwd(tmp_path, monkeypatch):
    target = tmp_path / "relative"
    target.mkdir()
    probe(target, "return True, 'relative target reached'")
    monkeypatch.chdir(tmp_path)
    passed, output = sandbox_runner.run_isolated_self_test(
        "bounded_probe.module", "Probe", "Inert probe", source_root=Path("relative"), timeout=10,
    )
    assert passed, output
    assert "relative target reached" in output


def test_success_also_retires_disposable_descendants(tmp_path):
    import psutil

    probe(tmp_path, """import json, subprocess, sys, psutil
p = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(20)'],
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
return True, json.dumps({'pid': p.pid, 'created': psutil.Process(p.pid).create_time()})""")
    passed, output = sandbox_runner.run_isolated_self_test(
        "bounded_probe.module", "Probe", "Inert probe", source_root=tmp_path, timeout=10,
    )
    assert passed, output
    child = json.loads(output.split("[self_test detail] ", 1)[1])
    deadline = time.monotonic() + 3
    try:
        while time.monotonic() < deadline:
            try:
                process = psutil.Process(child["pid"])
                if (process.create_time() != child["created"]
                        or process.status() == psutil.STATUS_ZOMBIE):
                    break
            except psutil.NoSuchProcess:
                break
            time.sleep(0.01)
        else:
            pytest.fail("completed self-test left its disposable descendant running")
    finally:
        # Only our exact disposable child identity can be cleaned up on failure.
        try:
            process = psutil.Process(child["pid"])
            if process.create_time() == child["created"]:
                process.kill()
        except psutil.NoSuchProcess:
            pass


@pytest.mark.skipif(os.name != "nt", reason="Windows suspended-child custody")
def test_failed_job_assignment_never_imports_target(tmp_path, monkeypatch):
    marker = tmp_path / "unexpected-execution.txt"
    probe(tmp_path, f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\nreturn True, 'bad'")

    def unavailable(_process):
        raise OSError("inert custody refusal")

    monkeypatch.setattr(sandbox_runner, "_assign_windows_kill_job", unavailable)
    passed, output = sandbox_runner.run_isolated_self_test(
        "bounded_probe.module", "Probe", "Inert probe", source_root=tmp_path, timeout=10,
    )
    assert not passed and "custody failed" in output
    assert not marker.exists()


@pytest.mark.parametrize("timeout", [float("inf"), float("nan"), 61])
def test_unbounded_deadline_is_refused(timeout):
    with pytest.raises(ValueError, match="at most 60"):
        sandbox_runner.run_isolated_self_test("unused", "Unused", "unused", timeout=timeout)
