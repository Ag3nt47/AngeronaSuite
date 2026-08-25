from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from angerona.modules import purple_guard
from angerona.shark.red_team import RedTeamEngine, RedTeamStep


def test_complete_validation_pack_arms_all_techniques_without_rewriting_lineage(
    tmp_path: Path,
) -> None:
    purple_guard.install_policies([{"mitre": "T1003"}], "signed-prior-run", tmp_path)
    before = purple_guard._read_policy(tmp_path)["techniques"]["T1003"]

    result = purple_guard.ensure_redteam_validation_pack(tmp_path)
    policy = purple_guard._read_policy(tmp_path)["techniques"]

    assert result["simulation_only"] is True
    assert len(result["active"]) == 13
    assert set(result["active"]) == set(policy)
    assert result["unsupported"] == []
    assert policy["T1003"] == before
    assert policy["T1059"]["candidate_from_run"] == "builtin-redteam-validation-v1"

    second = purple_guard.ensure_redteam_validation_pack(tmp_path)
    assert second["installed"] == []
    assert len(second["already_active"]) == 13


def test_t1059_drill_uses_bounded_inert_python_sleeper(monkeypatch, tmp_path: Path) -> None:
    engine = RedTeamEngine(tmp_path / "data", documents_dir=tmp_path / "target")
    engine.run_id = "redteam-process-probe"
    engine._threat_level = 1
    engine._proc_mult = 1
    engine._jitter = lambda *_args, **_kwargs: None  # type: ignore[method-assign]
    calls: list[tuple[list[str], int]] = []

    class Probe:
        pid = 12345

        @staticmethod
        def poll():
            return None

        @staticmethod
        def terminate():
            return None

        @staticmethod
        def wait(timeout=None):
            return 0

        @staticmethod
        def kill():
            return None

    import subprocess
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda argv, creationflags=0: calls.append((list(argv), creationflags)) or Probe(),
    )

    engine._step_random_processes((0.0, 0.0))

    assert len(calls) == 3
    assert all(argv[0] == __import__("sys").executable for argv, _flags in calls)
    assert all(argv[1:3] == ["-c", "import time; time.sleep(30)"] for argv, _flags in calls)
    assert all(argv[-1].startswith("ANGERONA_REDTEAM_") for argv, _flags in calls)
    engine._cleanup_probe_processes()


def test_purple_guard_detects_registered_custom_target_only(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    custom_target = tmp_path / "operator-target"
    custom_target.mkdir()
    marker = custom_target / "_redteam_lsass_dump_custom.txt"
    marker.write_text("inert", encoding="utf-8")
    (custom_target / "redteam_lsass_dump_wrong.txt").write_text("inert", encoding="utf-8")
    (custom_target / "_redteam_benign_note_custom.txt").write_text(
        "ordinary note", encoding="utf-8"
    )
    emitted: list[dict] = []
    guard = purple_guard.PurpleGuard(data_root)
    guard.emit = lambda _message, severity=None, **details: emitted.append(details)

    registered = purple_guard.register_runtime_target(custom_target)
    try:
        assert registered == custom_target.resolve()
        assert guard.scan_once({"T1003": {"state": "CANDIDATE_READY"}}) == 1
        assert emitted == [
            {
                "path": str(marker),
                "artifact_path": str(marker),
                "mitre": "T1003",
                "drill_target": str(custom_target.resolve()),
                "detector_policy": "reviewed-redteam-candidate",
                "response_authorized": True,
                "response_contract": {
                    "version": 1,
                    "actions": ["quarantine_file"],
                    "targets": {"path": str(marker)},
                },
            }
        ]
    finally:
        assert purple_guard.unregister_runtime_target(custom_target)


def test_runtime_target_registration_allows_safe_preregistration_but_rejects_unsafe(
    tmp_path: Path,
) -> None:
    file_target = tmp_path / "not-a-directory.txt"
    file_target.write_text("x", encoding="utf-8")

    future = tmp_path / "missing"
    assert purple_guard.register_runtime_target(future) == future.resolve()
    assert purple_guard.unregister_runtime_target(future)
    with pytest.raises(ValueError, match="directory path"):
        purple_guard.register_runtime_target(file_target)
    with pytest.raises(ValueError, match="filesystem root"):
        purple_guard.register_runtime_target(Path(tmp_path.anchor))


def test_preregistered_target_is_scanned_after_bounded_drill_creates_it(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "data"
    future = tmp_path / "future-target"
    guard = purple_guard.PurpleGuard(data_root)
    emitted: list[dict] = []
    guard.emit = lambda _message, severity=None, **details: emitted.append(details)

    purple_guard.register_runtime_target(future)
    try:
        assert guard.scan_once({"T1003": {"state": "CANDIDATE_READY"}}) == 0
        future.mkdir()
        marker = future / "_redteam_lsass_dump_created_after_registration.txt"
        marker.write_text("inert", encoding="utf-8")
        assert guard.scan_once({"T1003": {"state": "CANDIDATE_READY"}}) == 1
        assert emitted[0]["artifact_path"] == str(marker)
    finally:
        purple_guard.unregister_runtime_target(future)


def test_purple_guard_propagates_safe_practice_and_process_lineage(
    tmp_path: Path,
) -> None:
    sandbox = tmp_path / "drill-sandbox"
    sandbox.mkdir()
    practice_id = "abc12345deadbeef"
    marker = sandbox / f"_redteam_lsass_dump_practice_{practice_id}.txt"
    marker.write_text("inert", encoding="utf-8")
    guard = purple_guard.PurpleGuard(tmp_path)
    emitted: list[dict] = []
    guard.emit = lambda _message, severity=None, **details: emitted.append(details)

    assert guard.scan_once({"T1003": {"state": "CANDIDATE_READY"}}) == 1
    assert emitted[0]["practice_verification_id"] == practice_id

    source = type(
        "ProcessEvent",
        (),
        {
            "ts": 10.0,
            "module": "Telemetry Scanner",
            "details": {
                "event_type": "process_creation",
                "pid": 42,
                "cmdline": "cmd /c rem ANGERONA_REDTEAM_deadbeef",
                "practice_verification_id": "practice-01234567",
                "run_id": "redteam-123-safe",
                "step_id": "DSTEP-ABC123",
            },
        },
    )()
    guard._bus = type("Bus", (), {"recent": lambda self, _limit: [source]})()
    assert guard.scan_process_once(
        {purple_guard._PROCESS_TECHNIQUE: {"state": "CANDIDATE_READY"}}
    ) == 1
    assert emitted[1]["practice_verification_id"] == "practice-01234567"
    assert emitted[1]["run_id"] == "redteam-123-safe"
    assert emitted[1]["step_id"] == "DSTEP-ABC123"


def test_rapid_rerun_cancels_stale_cleanup_before_new_markers(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    engine = RedTeamEngine(tmp_path / "data", documents_dir=target)
    old_marker = target / "_redteam_lsass_dump_old.txt"
    old_marker.write_text("old run", encoding="utf-8")
    engine.steps = [
        RedTeamStep(
            "Credential Access (simulated)",
            "T1003 marker",
            "old",
            time.time(),
            artifact_paths=[str(old_marker)],
        )
    ]
    engine._schedule_cleanup(0.08, target, (old_marker,))

    new_marker = target / "_redteam_wiper_new.txt"
    created = threading.Event()

    def fake_playbook(_jitter, _noise) -> None:
        new_marker.write_text("new run", encoding="utf-8")
        created.set()
        engine._running.clear()

    engine._run_playbook = fake_playbook  # type: ignore[method-assign]
    assert engine.start(jitter_range=(0.0, 0.0), noise_chance=0.0, complexity=1)
    assert created.wait(1.0)
    assert engine._thread is not None
    engine._thread.join(1.0)
    time.sleep(0.15)

    assert not old_marker.exists(), "the new-run pre-clean should remove prior markers"
    assert new_marker.exists(), "a prior run's delayed cleanup must not touch the new run"


def test_redteam_cleanup_never_deletes_name_only_lookalikes(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    legitimate = target / "_redteam_notes_for_project.txt"
    legitimate.write_text("user-owned", encoding="utf-8")
    tracked = target / "_redteam_lsass_dump_owned.txt"
    tracked.write_text("inert drill", encoding="utf-8")
    engine = RedTeamEngine(tmp_path / "data", documents_dir=target)
    engine._owned_artifacts.append(tracked)

    removed = engine._sweep_markers(
        target_dir=target,
        artifact_paths=engine._artifact_paths_snapshot(),
    )

    assert removed == 1
    assert not tracked.exists()
    assert legitimate.read_text(encoding="utf-8") == "user-owned"
