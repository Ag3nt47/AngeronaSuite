from __future__ import annotations

import json
import threading

import pytest

from angerona.modules import evolution_engine as evolution_module
from angerona.modules.evolution_engine import EvolutionEngine


def _engine(tmp_path, monkeypatch) -> EvolutionEngine:
    monkeypatch.setattr(evolution_module, "_repo_root", lambda: tmp_path)
    engine = EvolutionEngine()
    engine.status = "running"
    return engine


def test_concurrent_history_writers_preserve_every_receipt(tmp_path, monkeypatch) -> None:
    engine = _engine(tmp_path, monkeypatch)
    threads = [
        threading.Thread(
            target=engine._record_history,
            args=(f"T{1000 + index}", {"index": index}, [{"iteration": 1}], False),
        )
        for index in range(32)
    ]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5.0)

    assert all(not thread.is_alive() for thread in threads)
    history = json.loads(engine.history_path.read_text(encoding="utf-8"))
    assert len(history) == 32
    assert {item["technique"] for item in history} == {
        f"T{1000 + index}" for index in range(32)
    }
    assert not list(engine.shared_logs.glob("*.tmp"))


def test_corrupt_history_is_never_silently_replaced(tmp_path, monkeypatch) -> None:
    engine = _engine(tmp_path, monkeypatch)
    engine.shared_logs.mkdir(parents=True, exist_ok=True)
    original = b"not-json\n"
    engine.history_path.write_bytes(original)

    with pytest.raises(RuntimeError, match="refusing to overwrite"):
        engine._record_history("T1003", {}, [], False)

    assert engine.history_path.read_bytes() == original


def test_one_worker_cannot_report_green_while_another_is_active(
    tmp_path, monkeypatch
) -> None:
    engine = _engine(tmp_path, monkeypatch)
    engine._active.update({"T1001", "T1002"})
    monkeypatch.setattr(engine, "_latest_footprint", lambda technique: {"technique": technique})
    monkeypatch.setattr(engine, "_ollama_yara", lambda _footprint: "rule R { condition: true }")
    monkeypatch.setattr(engine, "_stage_proposal", lambda *_args: tmp_path / "proposal.json")
    monkeypatch.setattr(engine, "_record_history", lambda *_args: None)

    engine._evolve("T1001", engine.lifecycle_generation, threading.Event())

    assert engine.health == 70
    assert "1 review-only proposal worker" in engine.health_note


def test_history_failure_stays_degraded_after_worker_exit(tmp_path, monkeypatch) -> None:
    engine = _engine(tmp_path, monkeypatch)
    engine._active.add("T1003")
    monkeypatch.setattr(engine, "_latest_footprint", lambda technique: {"technique": technique})
    monkeypatch.setattr(engine, "_ollama_yara", lambda _footprint: "rule R { condition: true }")
    monkeypatch.setattr(engine, "_stage_proposal", lambda *_args: tmp_path / "proposal.json")
    monkeypatch.setattr(
        engine,
        "_record_history",
        lambda *_args: (_ for _ in ()).throw(OSError("disk full")),
    )

    engine._evolve("T1003", engine.lifecycle_generation, threading.Event())

    assert engine.health == 40
    assert "T1003" in engine.health_note
    assert "disk full" in engine.last_error
