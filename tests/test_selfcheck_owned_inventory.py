"""The offline drill fixture cannot become production inventory authority."""
from __future__ import annotations

import ast
import os
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace

import pytest


def fixture_decorator(tmp_path, monkeypatch, *, producer=None, data_dir=None):
    from angerona.modules import process_monitor
    source = Path(__file__).parents[1] / "tools/selfcheck.py"
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    function = next(node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_offline_owned_inventory_fixture")
    ticks = iter((100.0, 101.0, 102.0))
    namespace = {"Path": Path, "__file__": str(source),
        "config": SimpleNamespace(data_dir=data_dir or Path(os.environ["ANGERONA_DATA"])),
        "manager": SimpleNamespace(modules={"Process Monitor": producer}),
        "time": SimpleNamespace(time=lambda: next(ticks))}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), "exec"), namespace)
    original = lambda *a, **k: pytest.fail("real general inventory was collected")
    monkeypatch.setattr(process_monitor, "process_snapshot", original)
    return namespace[function.name], process_monitor, original


def test_fresh_immutable_inventory_is_scoped_to_only_the_owned_phase(tmp_path, monkeypatch):
    from angerona.telemetry.sensors import ProcessSnapshot
    decorate, producer, original = fixture_decorator(tmp_path, monkeypatch)
    observed = []
    @decorate
    def controlled_phase():
        observed.extend((producer.process_snapshot(), producer.process_snapshot()))
        return "owned controls complete"
    assert producer.process_snapshot is original
    assert controlled_phase() == "owned controls complete"
    assert producer.process_snapshot is original
    first, second = observed
    assert type(first) is type(second) is ProcessSnapshot and first is not second
    assert first.processes == second.processes == ()
    assert first.complete is second.complete is True
    assert first.enumeration_complete is second.enumeration_complete is True
    assert first.collected_at == 100.0 and second.collected_at == 101.0
    assert (first.enumerated, first.skipped, first.unreadable, first.identity_incomplete, first.error) == (0, 0, 0, 0, "")
    with pytest.raises(FrozenInstanceError):
        first.complete = False


def test_phase_exception_restores_exact_original_supplier(tmp_path, monkeypatch):
    decorate, producer, original = fixture_decorator(tmp_path, monkeypatch)
    @decorate
    def controlled_phase():
        assert producer.process_snapshot().complete is True
        raise RuntimeError("inert owned control failed")
    with pytest.raises(RuntimeError, match="owned control failed"):
        controlled_phase()
    assert producer.process_snapshot is original


def test_fixture_refuses_non_disposable_profile_before_patch(tmp_path, monkeypatch):
    outside = Path(__file__).parents[1] / "SourceData"
    decorate, producer, original = fixture_decorator(tmp_path, monkeypatch, data_dir=outside)
    with pytest.raises(AssertionError, match="disposable workspace"):
        decorate(lambda: pytest.fail("non-disposable profile reached fixture"))()
    assert producer.process_snapshot is original


@pytest.mark.parametrize("status,alive", [("running", False), ("stopped", True)])
def test_fixture_refuses_preexisting_running_or_alive_producer(tmp_path, monkeypatch, status, alive):
    sensor = SimpleNamespace(status=status, _thread=SimpleNamespace(is_alive=lambda: alive))
    decorate, producer, original = fixture_decorator(tmp_path, monkeypatch, producer=sensor)
    with pytest.raises(AssertionError, match="running Process Monitor"):
        decorate(lambda: pytest.fail("live producer reached fixture"))()
    assert producer.process_snapshot is original
