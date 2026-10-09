"""Inert regressions for Shark launch retirement and repeated marker phases."""
from __future__ import annotations

import hashlib
import os
from dataclasses import asdict
from types import SimpleNamespace

import pytest

from angerona.core.practice_scope import provenance_for_event
from angerona.core.eventbus import Severity
from angerona.modules.file_integrity import FileIntegrityModule, _combat_file_contract
from angerona.modules.intel_sync import BYOVD_DRILL_MARKER, is_known_bad_driver
from angerona.shark import shark_attack
from angerona.shark.aar_report import _matches
from angerona.shark.run_manifest import (
    attest_run_history, build_run_history, preflight_run, verify_run_history,
)


@pytest.mark.parametrize("error", [RuntimeError, OSError])
@pytest.mark.parametrize("boundary", ["construct", "start"])
def test_shark_launch_failure_retires_practice_run_and_allows_retry(
    tmp_path, monkeypatch, error, boundary,
):
    messages = []
    engine = shark_attack.SharkAttackEngine(tmp_path, on_event=messages.append)
    attempts = []

    class InertThread:
        def __init__(self, **kwargs):
            attempts.append(kwargs)
            if len(attempts) == 1 and boundary == "construct":
                raise error("inert construction failure")

        def start(self):
            if len(attempts) == 1:
                raise error("inert start failure")

        def is_alive(self):
            return False

    monkeypatch.setattr(shark_attack, "threading", SimpleNamespace(
        Thread=InertThread, current_thread=shark_attack.threading.current_thread,
    ))
    assert engine.start() is False
    failed_run_id = engine.run_id
    assert not engine.is_running
    assert engine._thread is None
    assert engine._cancel.is_set()
    assert provenance_for_event(SimpleNamespace(details={"run_id": failed_run_id})) is None
    assert not engine.history_path.exists()
    assert engine.steps == []
    assert any("worker launch failed" in message for message in messages)

    try:
        assert engine.start() is True
        assert engine.is_running
        assert not engine._cancel.is_set()
        assert engine.run_id != failed_run_id
        assert provenance_for_event(SimpleNamespace(details={"run_id": engine.run_id}))
    finally:
        engine.stop_and_clean()


def _observed(path):
    info = path.stat()
    return {
        "path": str(path),
        "observed_file_identity": {
            "device": info.st_dev, "inode": info.st_ino,
            "birthtime_ns": int(getattr(info, "st_birthtime_ns", 0) or 0),
        },
        "observed_content_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def test_four_byovd_phases_retain_distinct_exact_evidence_and_signed_history(tmp_path):
    engine = shark_attack.SharkAttackEngine(tmp_path / "data", documents_dir=tmp_path / "markers")
    engine.run_id = "shark-four-phase-inert-test"
    engine.documents_dir.mkdir()
    legacy = engine.documents_dir / "angerona_byovd_drill.sys"
    legacy.write_bytes(b"operator-owned original")
    paths = []
    try:
        for _ in range(4):
            engine._step_simulated_byovd((0, 0))
        assert len(engine.steps) == 4 and all(step.ok for step in engine.steps)
        paths = [shark_attack.Path(step.artifact_paths[0]) for step in engine.steps]
        assert len(set(paths)) == 4
        assert len(engine._owned_artifacts) == 4
        for path in paths:
            assert BYOVD_DRILL_MARKER in path.read_text(encoding="utf-8")
            assert is_known_bad_driver(path.name)["drill"] is True
            severity, message = FileIntegrityModule._driver_alert(None, str(path))
            assert severity == Severity.CRITICAL
            assert "BYOVD drill marker" in message
            observation = _observed(path)
            assert provenance_for_event(SimpleNamespace(details=observation)).run_id == engine.run_id
            # Shark detection evidence does not gain Red Team response authority.
            assert _combat_file_contract(**observation) == {}

        history = build_run_history(
            kind="shark", run_id=engine.run_id, generated="2026-10-09 12:00:00",
            steps=[asdict(step) for step in engine.steps], status="completed",
            preflight=preflight_run(
                kind="shark", cycles=4, jitter_range=(0, 1), noise_chance=0,
                target_dir=engine.documents_dir,
            ),
        )
        key = bytes(range(32))
        signed = attest_run_history(history, key=key)
        assert verify_run_history(signed, key=key).valid
        assert [step["artifact_paths"] for step in signed["steps"]] == [[str(path)] for path in paths]
        # AAR attribution follows each exact manifest path, including when all
        # four observations arrive later in the same detector polling cycle.
        for index, path in enumerate(paths):
            observation = SimpleNamespace(details=_observed(path))
            assert [i for i, step in enumerate(signed["steps"]) if _matches(step, observation)] == [index]
    finally:
        engine.stop_and_clean()
    assert legacy.read_bytes() == b"operator-owned original"
    assert all(path.exists() is (os.name != "nt") for path in paths)
    assert all(provenance_for_event(SimpleNamespace(details={"path": str(path)})) is None for path in paths)


@pytest.mark.parametrize("suffix", ["", "a" * 31, "a" * 33, "g" * 32, "a" * 32 + ".bak"])
def test_byovd_generated_name_match_is_exact(suffix):
    assert is_known_bad_driver(f"angerona_byovd_drill_{suffix}.sys") is None


def test_generated_name_and_marker_bytes_alone_grant_no_practice_or_response_authority(tmp_path):
    marker = tmp_path / ("angerona_byovd_drill_" + "a" * 32 + ".sys")
    marker.write_text(BYOVD_DRILL_MARKER, encoding="ascii")
    observation = _observed(marker)
    assert is_known_bad_driver(str(marker))["drill"] is True
    assert provenance_for_event(SimpleNamespace(details=observation)) is None
    assert _combat_file_contract(**observation) == {}
