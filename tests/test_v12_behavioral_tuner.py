from __future__ import annotations

from types import SimpleNamespace

from angerona.core.module_base import Severity
from angerona.modules.behavioral_tuner import BehavioralTuner


HASH_A = "a" * 64
HASH_B = "b" * 64


def _tuner(tmp_path) -> BehavioralTuner:
    tuner = BehavioralTuner(learn_days=0)
    tuner._db_path = str(tmp_path / "tuner.sqlite3")
    tuner._connect()
    tuner._learn_seconds = 0
    return tuner


def _details(file_hash: str = HASH_A) -> dict:
    return {
        "name": "agent.exe",
        "parent_name": "services.exe",
        "file_hash": file_hash,
        "remote_ip": "203.0.113.19",
        "remote_port": 443,
    }


def test_real_module_names_normalize_to_stable_aliases(tmp_path) -> None:
    tuner = _tuner(tmp_path)
    tuner._learn("Process Monitor", _details())
    row = tuner._db.execute(
        "SELECT fingerprint, module FROM behavioral_baseline"
    ).fetchone()

    assert row == ("PROC|agent.exe|services.exe", "PROC")
    event = SimpleNamespace(module="Process Monitor", details=_details())
    assert tuner.is_known_good(event) is False


def test_candidate_requires_explicit_exact_hash_approval(tmp_path) -> None:
    tuner = _tuner(tmp_path)
    details = _details()
    tuner._learn("Process Monitor", details)
    identity = "PROC|agent.exe|services.exe"

    assert tuner.check_event("Process Monitor", details) is None
    assert tuner.approve_candidate(identity, HASH_B, "operator") is False
    assert tuner.approve_candidate(identity, HASH_A, "operator") is True
    assert tuner.check_event("Process Monitor", details) == Severity.INFO

    missing_hash = dict(details)
    missing_hash.pop("file_hash")
    assert tuner.check_event("Process Monitor", missing_hash) is None


def test_hash_drift_is_pending_until_exact_operator_approval(tmp_path) -> None:
    tuner = _tuner(tmp_path)
    identity = "PROC|agent.exe|services.exe"
    tuner._learn("PROC", _details(HASH_A))
    assert tuner.approve_candidate(identity, HASH_A, "operator") is True

    tuner._learn("Process Monitor", _details(HASH_B))
    stored = tuner._db.execute(
        "SELECT file_hash FROM behavioral_baseline WHERE fingerprint=?", (identity,)
    ).fetchone()[0]
    pending = tuner._db.execute(
        "SELECT status FROM tune_drift_proposals WHERE fingerprint=? AND candidate_hash=?",
        (identity, HASH_B),
    ).fetchone()[0]

    assert stored == HASH_A
    assert pending == "PENDING"
    assert tuner.check_event("PROC", _details(HASH_B)) is None
    assert tuner.check_event("PROC", _details(HASH_A)) == Severity.INFO

    assert tuner.approve_hash_drift(identity, HASH_A, HASH_B, "operator") is True
    assert tuner.check_event("PROC", _details(HASH_B)) == Severity.INFO
    assert tuner.check_event("PROC", _details(HASH_A)) is None


def test_learning_epoch_survives_reconstruction(tmp_path) -> None:
    path = str(tmp_path / "tuner.sqlite3")
    first = BehavioralTuner(learn_days=7)
    first._db_path = path
    first._first_launch_ts = 12345.0
    first._connect()
    persisted = first._first_launch_ts
    first._db.close()

    second = BehavioralTuner(learn_days=7)
    second._db_path = path
    second._connect()

    assert second._first_launch_ts == persisted
