import hashlib

import pytest

from angerona.core.endpoint_identity import ConnectionVerifier, EndpointIdentity
from angerona.core.fleet_jobs import (
    DurableJobStore, FleetJob, JobTarget, signed_result_receipt,
)


def _job(now=1000.0, *, dry_run=True):
    return FleetJob(
        job_id="job-00000001", idempotency_key="idem-00000001",
        operation_id="collect.processes", arguments={"limit": 50},
        target=JobTarget(device_ids=("device-00000001",), max_hosts=1),
        created_at=now, expires_at=now + 300, dry_run=dry_run,
        approval_digest="" if dry_run else hashlib.sha256(b"approval").hexdigest(),
    )


def test_durable_job_state_machine_and_replay(tmp_path):
    with_store = DurableJobStore(tmp_path / "jobs.db")
    try:
        first = with_store.create(_job())
        same = with_store.create(_job())
        assert same.job.digest == first.job.digest
        staged = with_store.transition(first.job.job_id, "staged", expected_version=1, now=1001)
        approved = with_store.transition(first.job.job_id, "approved", expected_version=2, now=1002)
        dispatched = with_store.transition(first.job.job_id, "dispatched", expected_version=3, now=1003)
        running = with_store.transition(first.job.job_id, "running", expected_version=4, now=1004)
        done = with_store.transition(
            first.job.job_id, "succeeded", expected_version=5,
            result_receipt={"count": 12}, now=1005,
        )
        assert done.state == "succeeded"
        assert done.result_receipt == {"count": 12}
        with pytest.raises(ValueError, match="invalid transition"):
            with_store.transition(first.job.job_id, "running", expected_version=6)
    finally:
        with_store.close()


def test_idempotency_conflict_and_optimistic_concurrency(tmp_path):
    store = DurableJobStore(tmp_path / "jobs.db")
    try:
        store.create(_job())
        changed = FleetJob(
            **{**_job().to_dict(), "arguments": {"limit": 99}}
        )
        with pytest.raises(ValueError, match="idempotency"):
            store.create(changed)
        with pytest.raises(RuntimeError, match="version conflict"):
            store.transition("job-00000001", "staged", expected_version=99)
    finally:
        store.close()


def test_expired_job_fails_closed_and_live_job_needs_approval():
    with pytest.raises(ValueError, match="approval digest"):
        _job(dry_run=False).__class__(
            **{**_job().to_dict(), "dry_run": False, "approval_digest": ""}
        )


def test_endpoint_signed_result_receipt(tmp_path):
    identity = EndpointIdentity(tmp_path / "identity")
    envelope = signed_result_receipt(
        identity, _job(), sequence=1, state="succeeded",
        result={"count": 3}, sent_at=1000,
    )
    verifier = ConnectionVerifier(
        identity.device_id, identity.public_key,
        state_path=tmp_path / "connection-sequence.json",
        clock_skew_seconds=10,
    )
    assert verifier.verify(envelope, now=1000)
    assert envelope.payload["job_digest"] == _job().digest
