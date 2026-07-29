import pytest

from angerona.core.case_management import CaseStore, EvidenceReference
from angerona.core.hunt_operations import HuntOperationsStore, HuntProgressEvent
from angerona.core.hunt_workspace import HuntResultReference, HuntWorkspace


DEVICE = "a" * 64


def _event(event_id, state, timestamp, **overrides):
    value = {
        "event_id": event_id,
        "hunt_id": "hunt-001",
        "device_token": DEVICE,
        "state": state,
        "timestamp": timestamp,
        "bytes_collected": 0,
    }
    value.update(overrides)
    return HuntProgressEvent(**value)


def _result(result_id="result-001", evidence_id="evidence-001"):
    return HuntResultReference(
        result_id, "hunt-001", "process.snapshot", DEVICE, evidence_id,
        "b" * 64, 500, "sensitive", 100, "signed collection receipt",
    )


def test_progress_is_idempotent_bounded_and_authenticated(tmp_path):
    store = HuntOperationsStore(
        tmp_path / "operations.db", b"k" * 32,
        max_hosts=1, max_total_bytes=2000,
    )
    queued = _event("progress-001", "queued", 1)
    assert store.record(queued)
    assert not store.record(queued)
    store.record(_event(
        "progress-002", "running", 2, bytes_collected=400,
    ))
    store.record(_event(
        "progress-003", "succeeded", 3, bytes_collected=800,
        result_ids=("result-001",),
    ))
    summary = store.summary("hunt-001")
    assert summary.state_counts["succeeded"] == 1
    assert summary.bytes_collected == 800
    assert store.verify_summary(summary)
    with pytest.raises(ValueError, match="transition"):
        store.record(_event("progress-004", "running", 4, bytes_collected=900))
    store.close()


def test_progress_failure_uses_codes_and_detects_database_tampering(tmp_path):
    store = HuntOperationsStore(tmp_path / "operations.db", b"k" * 32)
    store.record(_event(
        "progress-001", "failed", 1, error_code="collector.offline",
    ))
    assert store.summary("hunt-001").failure_codes == {"collector.offline": 1}
    store._db.execute(
        "UPDATE hunt_progress SET error_code='hidden.failure'"
    )
    store._db.commit()
    with pytest.raises(ValueError, match="authentication"):
        store.summary("hunt-001")
    store.close()


def test_workspace_results_promote_idempotently_to_authenticated_case(tmp_path):
    workspace = HuntWorkspace(tmp_path / "workspace.json", b"w" * 32)
    workspace.add_result(_result(), expected_revision=0)
    cases = CaseStore(tmp_path / "cases.db", b"c" * 32)
    operations = HuntOperationsStore(
        tmp_path / "operations.db", b"k" * 32, clock=lambda: 200,
    )
    first = operations.promote_to_case(
        "hunt-001", workspace, cases, actor="analyst-001",
        assignee="analyst-002",
    )
    second = operations.promote_to_case(
        "hunt-001", workspace, cases, actor="analyst-001",
        assignee="analyst-002",
    )
    assert first.case_id == second.case_id
    assert operations.verify_promotion(first)
    assert cases.get_case(first.case_id).status == "investigating"
    assert cases.evidence_owner("evidence-001") == first.case_id
    assert cases.verify_custody("evidence-001")
    operations.close()
    cases.close()


def test_case_promotion_rejects_empty_or_conflicting_evidence(tmp_path):
    workspace = HuntWorkspace(tmp_path / "workspace.json", b"w" * 32)
    cases = CaseStore(tmp_path / "cases.db", b"c" * 32)
    operations = HuntOperationsStore(tmp_path / "operations.db", b"k" * 32)
    with pytest.raises(ValueError, match="no evidence"):
        operations.promote_to_case(
            "hunt-001", workspace, cases, actor="analyst-001",
        )
    workspace.add_result(_result(), expected_revision=0)
    other = cases.create_case("Other")
    cases.add_evidence(
        other.case_id,
        EvidenceReference(
            "evidence-001", "x.reference", "b" * 64, 500,
            "other", "other receipt", 100, "sensitive",
        ),
        "analyst-003",
    )
    with pytest.raises(ValueError, match="another case"):
        operations.promote_to_case(
            "hunt-001", workspace, cases, actor="analyst-001",
        )
    operations.close()
    cases.close()
