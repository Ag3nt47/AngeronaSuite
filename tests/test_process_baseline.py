from __future__ import annotations

import dataclasses
import json
import time
from pathlib import Path

import pytest

from angerona.core import process_allowlist
from angerona.core.eventbus import BusAuthority, Event, Severity
from angerona.core.process_baseline import (
    ExecutableAssessment,
    ProcessBaselineLearner,
)


def _assessment(path: str, *, signed: bool = True, trusted: bool = True):
    candidate = Path(path)
    info = candidate.stat()
    return ExecutableAssessment(
        name=candidate.name,
        path=str(candidate.resolve()),
        sha256=process_allowlist.executable_sha256(candidate),
        size=info.st_size,
        mtime_ns=info.st_mtime_ns,
        signature_status="Valid" if signed else "NotSigned",
        publisher="CN=Angerona Baseline Test" if signed else "",
        root_class="program_files" if trusted else "",
        trusted_root=trusted,
        reason="test assessment",
    )


def _signed_process_event(authority: BusAuthority, executable: Path) -> Event:
    event = Event(
        "Telemetry Scanner",
        f"process_creation: {executable.name}",
        Severity.INFO,
        details={
            "type": "process_creation",
            "name": executable.name,
            "pid": 1234,
            "ppid": 42,
            "ts": time.time(),
            "exe": str(executable.resolve()),
            "location_status": "resolved",
            "cmdline": f'"{executable}" --password=must-not-persist',
            "command_line_status": "resolved",
            "parent_name": "parent.exe",
            "source": "scanner",
            "sensor": "process_creation",
        },
    )
    return dataclasses.replace(event, hmac_sig=authority.sign(event))


def _wait_for(learner: ProcessBaselineLearner, accepted: int) -> dict:
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        snapshot = learner.snapshot()
        if snapshot["metrics"]["accepted"] >= accepted:
            return snapshot
        time.sleep(0.01)
    raise AssertionError(f"learner did not reach {accepted} observations")


def test_hash_bound_trust_fails_after_executable_replacement(tmp_path) -> None:
    executable = tmp_path / "vpn.exe"
    executable.write_bytes(b"trusted-v1")
    row = process_allowlist.add(path=str(executable), data_dir=tmp_path)
    assert len(row["sha256"]) == 64
    assert process_allowlist.is_allowed(
        executable.name, str(executable), data_dir=tmp_path
    )

    executable.write_bytes(b"replacement-with-different-bytes")
    assert not process_allowlist.is_allowed(
        executable.name, str(executable), data_dir=tmp_path
    )

    updated = process_allowlist.add(path=str(executable), data_dir=tmp_path)
    assert updated["sha256"] != row["sha256"]
    assert process_allowlist.is_allowed(
        executable.name, str(executable), data_dir=tmp_path
    )


def test_scanner_event_name_is_understood_by_trust_policy(tmp_path) -> None:
    executable = tmp_path / "scanner-name.exe"
    executable.write_bytes(b"scanner")
    process_allowlist.add(path=str(executable), data_dir=tmp_path)
    event = Event(
        "Telemetry Scanner",
        "process creation",
        details={"name": executable.name, "exe": str(executable)},
    )
    assert process_allowlist.event_process(event) == (
        executable.name,
        str(executable),
    )
    assert process_allowlist.is_event_allowed(event, tmp_path)


def test_learning_requires_signed_maturity_then_explicit_approval(tmp_path) -> None:
    authority = BusAuthority(b"k" * 32)
    executable = tmp_path / "ProtonVPN.Client.exe"
    executable.write_bytes(b"signed-proton-test")
    now = [1_735_689_600.0]
    learner = ProcessBaselineLearner(
        tmp_path,
        authority,
        enabled=True,
        clock=lambda: now[0],
        assessor=_assessment,
    )
    assert learner.start()

    event = _signed_process_event(authority, executable)
    assert learner.submit_event(event)
    assert learner.submit_event(event)
    snapshot = _wait_for(learner, 2)
    assert len(snapshot["candidates"]) == 1
    assert snapshot["candidates"][0]["eligible"] is False

    now[0] += 86400
    assert learner.submit_event(event)
    snapshot = _wait_for(learner, 3)
    candidate = snapshot["candidates"][0]
    assert candidate["eligible"] is True
    assert candidate["observations"] == 3
    assert len(candidate["days"]) == 2
    assert learner.stop()

    state_text = learner.path.read_text(encoding="utf-8")
    assert "must-not-persist" not in state_text
    assert "parent.exe" not in state_text
    approved = learner.approve(candidate["id"])
    assert approved["source"] == "baseline"
    assert approved["sha256"] == candidate["sha256"]
    assert process_allowlist.is_allowed(
        executable.name, str(executable), data_dir=tmp_path
    )
    assert learner.snapshot()["candidates"] == []

    reloaded = ProcessBaselineLearner(
        tmp_path,
        authority,
        assessor=_assessment,
    )
    assert not reloaded.snapshot()["integrity_error"]
    assert reloaded.snapshot()["candidates"] == []


def test_forged_event_and_queue_pressure_are_bounded(tmp_path) -> None:
    authority = BusAuthority(b"a" * 32)
    executable = tmp_path / "candidate.exe"
    executable.write_bytes(b"candidate")
    learner = ProcessBaselineLearner(
        tmp_path,
        authority,
        enabled=True,
        assessor=_assessment,
        queue_size=1,
    )
    forged = _signed_process_event(BusAuthority(b"b" * 32), executable)
    assert learner.submit_event(forged)
    assert not learner.submit_event(forged)
    assert learner.snapshot()["metrics"]["dropped"] == 1
    assert learner.start()
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        if learner.snapshot()["metrics"]["rejected"]:
            break
        time.sleep(0.01)
    assert learner.snapshot()["metrics"]["rejected"] == 1
    assert learner.snapshot()["candidates"] == []
    assert learner.stop()


def test_tampered_state_freezes_learning_until_explicit_reset(tmp_path) -> None:
    authority = BusAuthority(b"t" * 32)
    executable = tmp_path / "stable.exe"
    executable.write_bytes(b"stable")
    learner = ProcessBaselineLearner(
        tmp_path,
        authority,
        enabled=True,
        assessor=_assessment,
    )
    learner.start()
    assert learner.submit_event(_signed_process_event(authority, executable))
    _wait_for(learner, 1)
    assert learner.stop()

    raw = json.loads(learner.path.read_text(encoding="utf-8"))
    raw["candidates"][0]["observations"] = 999
    learner.path.write_text(json.dumps(raw), encoding="utf-8")

    locked = ProcessBaselineLearner(
        tmp_path,
        authority,
        enabled=True,
        assessor=_assessment,
    )
    assert "authentication" in locked.snapshot()["integrity_error"]
    locked.start()
    assert locked.submit_event(_signed_process_event(authority, executable))
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        if locked.snapshot()["metrics"]["rejected"]:
            break
        time.sleep(0.01)
    assert locked.snapshot()["candidates"] == []
    assert locked.stop()

    locked.reset_state()
    assert not locked.snapshot()["integrity_error"]
    assert locked.snapshot()["candidates"] == []
    assert list((tmp_path / "shared_logs").glob("process_baseline.json.quarantine.*"))
    assert locked.stop()


def test_unsigned_or_unprotected_candidate_never_becomes_eligible(tmp_path) -> None:
    authority = BusAuthority(b"u" * 32)
    executable = tmp_path / "unsigned.exe"
    executable.write_bytes(b"unsigned")
    now = [1_735_689_600.0]

    def untrusted(path: str) -> ExecutableAssessment:
        return _assessment(path, signed=False, trusted=False)

    learner = ProcessBaselineLearner(
        tmp_path,
        authority,
        enabled=True,
        clock=lambda: now[0],
        assessor=untrusted,
    )
    learner.start()
    event = _signed_process_event(authority, executable)
    for index in range(3):
        now[0] = 1_735_689_600.0 + index * 86400
        assert learner.submit_event(event)
        _wait_for(learner, index + 1)
    candidate = learner.snapshot()["candidates"][0]
    assert candidate["eligible"] is False
    with pytest.raises(ValueError, match="not mature"):
        learner.approve(candidate["id"])
    assert learner.stop()


def test_dismissal_suppresses_same_digest_but_not_forever(tmp_path) -> None:
    authority = BusAuthority(b"d" * 32)
    executable = tmp_path / "dismiss.exe"
    executable.write_bytes(b"dismiss")
    now = [1_735_689_600.0]
    learner = ProcessBaselineLearner(
        tmp_path,
        authority,
        enabled=True,
        clock=lambda: now[0],
        assessor=_assessment,
    )
    learner.start()
    event = _signed_process_event(authority, executable)
    assert learner.submit_event(event)
    candidate = _wait_for(learner, 1)["candidates"][0]
    assert learner.dismiss(candidate["id"], days=1)
    assert learner.snapshot()["candidates"] == []

    assert learner.submit_event(event)
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        if learner.snapshot()["metrics"]["dismissed"]:
            break
        time.sleep(0.01)
    assert learner.snapshot()["candidates"] == []

    now[0] += 86401
    assert learner.submit_event(event)
    _wait_for(learner, 2)
    assert len(learner.snapshot()["candidates"]) == 1
    assert learner.stop()


def test_approval_rechecks_current_executable_bytes(tmp_path) -> None:
    authority = BusAuthority(b"r" * 32)
    executable = tmp_path / "drift.exe"
    executable.write_bytes(b"first")
    now = [1_735_689_600.0]
    learner = ProcessBaselineLearner(
        tmp_path,
        authority,
        enabled=True,
        clock=lambda: now[0],
        assessor=_assessment,
    )
    learner.start()
    event = _signed_process_event(authority, executable)
    for index in range(3):
        now[0] = 1_735_689_600.0 + index * 86400
        assert learner.submit_event(event)
        _wait_for(learner, index + 1)
    candidate = learner.snapshot()["candidates"][0]
    assert candidate["eligible"]
    learner.stop()

    executable.write_bytes(b"changed after observation")
    with pytest.raises(ValueError, match="changed"):
        learner.approve(candidate["id"])
    assert not process_allowlist.is_allowed(
        executable.name, str(executable), data_dir=tmp_path
    )
