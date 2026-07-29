import pytest

from angerona.core.fleet_hunts import HuntLifecycle, HuntSpec


def _spec(*, artifacts=("process.snapshot",), query=None):
    return HuntSpec(
        "hunt-001", artifacts, ("device-001",), (), query or {"name": "powershell"},
        10, 10_000_000, 300, 100, 200, "analyst-001",
    )


def test_hunt_has_no_arbitrary_command_or_path_and_requires_approval(tmp_path):
    with pytest.raises(ValueError, match="forbidden"):
        _spec(query={"command": "whoami"})
    lifecycle = HuntLifecycle(
        b"k" * 32, tmp_path / "hunts.json", clock=lambda: 110
    )
    spec = _spec()
    lifecycle.create(spec)
    with pytest.raises(PermissionError, match="independent"):
        lifecycle.approve(spec.hunt_id, spec.requested_by)
    assert lifecycle.approve(spec.hunt_id, "analyst-002") == 1
    lifecycle.transition(spec.hunt_id, "running")
    lifecycle.transition(spec.hunt_id, "completed")
    receipt = lifecycle.receipt(
        spec.hunt_id, hosts=1, bytes_collected=100,
        result_digest="a" * 64,
    )
    assert receipt.hunt_digest == spec.digest
    assert lifecycle.verify_receipt(receipt)
    restored = HuntLifecycle(
        b"k" * 32, tmp_path / "hunts.json", clock=lambda: 110
    )
    assert restored.receipt(
        spec.hunt_id, hosts=1, bytes_collected=100,
        result_digest="a" * 64,
    ).state == "completed"


def test_restricted_collection_needs_two_approvers_and_budgets_fail_closed(tmp_path):
    lifecycle = HuntLifecycle(
        b"k" * 32, tmp_path / "hunts.json", clock=lambda: 110
    )
    spec = _spec(artifacts=("security.events",))
    lifecycle.create(spec)
    assert lifecycle.approve(spec.hunt_id, "analyst-002") == 1
    with pytest.raises(ValueError, match="draft->running"):
        lifecycle.transition(spec.hunt_id, "running")
    assert lifecycle.approve(spec.hunt_id, "analyst-003") == 2
    lifecycle.transition(spec.hunt_id, "running")
    lifecycle.transition(spec.hunt_id, "completed")
    with pytest.raises(ValueError, match="budget"):
        lifecycle.receipt(
            spec.hunt_id, hosts=11, bytes_collected=1,
            result_digest="b" * 64,
        )


def test_persisted_hunt_state_tampering_fails_closed(tmp_path):
    path = tmp_path / "hunts.json"
    lifecycle = HuntLifecycle(b"k" * 32, path, clock=lambda: 110)
    lifecycle.create(_spec())
    path.write_text(
        path.read_text(encoding="utf-8").replace('"draft"', '"approved"'),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="authentication"):
        HuntLifecycle(b"k" * 32, path, clock=lambda: 110)
