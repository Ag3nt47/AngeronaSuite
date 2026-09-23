"""Exercise the harness phase without importing its whole Qt application."""
from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest


def live_phase(namespace):
    path = Path(__file__).parents[1] / "tools" / "selfcheck.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    phase = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and any(isinstance(decorator, ast.Call)
                and decorator.args
                and isinstance(decorator.args[0], ast.Constant)
                and str(decorator.args[0].value).startswith("Red Team drill — LIVE run")
                for decorator in node.decorator_list)
    )
    phase.decorator_list = []
    exec(compile(ast.Module(body=[phase], type_ignores=[]), str(path), "exec"), namespace)
    return namespace[phase.name]


@pytest.fixture
def drill(tmp_path, monkeypatch):
    from angerona.modules import purple_guard
    from angerona.shark import red_team
    import os
    import tempfile

    calls = []
    target = tmp_path / "target"
    target.mkdir()
    clock = [0.0]
    worker = SimpleNamespace(alive=False)
    worker.is_alive = lambda: worker.alive
    def join(timeout):
        calls.append(("join", timeout))
        worker.alive = False
    worker.join = join
    engine = SimpleNamespace(
        is_running=False, steps=[SimpleNamespace(ok=True, technique="custom")],
        _thread=worker, complete=True,
    )
    def start(**kwargs):
        calls.append("start")
        (target / "_redteam_custom_fixture.txt").write_text(
            "detect-me-xyz; never executed", encoding="utf-8")
        engine.is_running = not engine.complete
        worker.alive = engine.is_running
        return True
    def cleanup():
        calls.append("cleanup")
        engine.is_running = False
        (target / "_redteam_custom_fixture.txt").unlink(missing_ok=True)
    engine.start = start
    engine.stop_and_clean = cleanup
    lease = SimpleNamespace(release=lambda: calls.append("release"))
    monkeypatch.setattr(purple_guard, "acquire_redteam_validation_lease", lambda *a, **k: lease)
    monkeypatch.setattr(red_team, "RedTeamEngine", lambda *a: engine)
    monkeypatch.setattr(tempfile, "mkdtemp", lambda **k: str(target))
    def sleep(seconds):
        clock[0] += seconds
    namespace = {
        "os": os, "config": SimpleNamespace(data_dir=tmp_path),
        "manager": object(), "bus": object(), "storage": object(),
        "time": SimpleNamespace(monotonic=lambda: clock[0], sleep=sleep),
    }
    return live_phase(namespace), engine, worker, target, calls


def test_timeout_cancels_and_joins_before_releasing_artifact_custody(drill):
    run, engine, worker, target, calls = drill
    engine.complete = False
    with pytest.raises(AssertionError, match="did not finish within 30s"):
        run()
    assert calls == ["start", "cleanup", ("join", 5.0), "cleanup", "release"]
    assert not worker.alive and not target.exists()


def test_success_cleans_markers_before_releasing_lease(drill):
    run, _, _, target, calls = drill
    assert "custom marker inert + cleaned" in run()
    assert calls == ["start", "cleanup", "cleanup", "release"]
    assert not target.exists()


def test_failed_mandatory_step_cannot_be_reported_as_success(drill):
    run, engine, _, target, calls = drill
    engine.steps[0].ok = False
    with pytest.raises(AssertionError, match="mandatory drill steps failed"):
        run()
    assert calls[-1] == "release" and not target.exists()


def test_cleanup_error_still_releases_lease(drill):
    run, engine, _, _, calls = drill
    def failed_cleanup():
        calls.append("cleanup")
        raise OSError("cleanup refused")
    engine.stop_and_clean = failed_cleanup
    with pytest.raises(OSError, match="cleanup refused"):
        run()
    assert calls == ["start", "cleanup", "release"]


def test_stuck_worker_is_reported_and_custody_still_released(drill):
    run, engine, worker, _, calls = drill
    engine.complete = False
    worker.join = lambda timeout: calls.append(("stuck-join", timeout))
    with pytest.raises(AssertionError, match="worker did not stop within 5s"):
        run()
    assert calls[-1] == "release"
