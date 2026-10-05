"""Remote evidence must never acquire receiver-local response authority."""
import pytest

from angerona.core.eventbus import Event, EventBus, REMOTE_OBSERVE_AUTHORITY, Severity
from angerona.modules.evidence_lattice import EvidenceLattice, EvidenceLatticeModule


def _event(name, details):
    return Event(name, "inert independent detector evidence", Severity.MEDIUM, 1.0, details)


@pytest.mark.parametrize("remote_marker", [
    {"response_authority": REMOTE_OBSERVE_AUTHORITY},
    {"node_origin": "inert-peer"},
])
@pytest.mark.parametrize("pid_key", ["pid", "process_id", "target_pid", "child_pid"])
def test_remote_pid_alias_cannot_complete_local_corroboration(remote_marker, pid_key):
    module = EvidenceLatticeModule()
    module.bind(EventBus())
    local = {"pid": 4242, "process_create_time": 100.0}
    module._on_event(_event("File Integrity Monitor", local))
    module._on_event(_event("Network Monitor", local))
    prior_counts = module.lattice.counts()

    module._on_event(_event("Remote Telemetry Bridge", {
        pid_key: 4242, "process_create_time": 100.0, **remote_marker,
    }))

    assert module._bus.recent(10) == []
    assert module.lattice.counts() == prior_counts
    # Remote input did not consume the bucket or its cooldown: a real third
    # local detector can still corroborate and derive exact-target authority.
    module._on_event(_event("Process Monitor", local))
    event = module._bus.recent(1)[0]
    assert event.details["response_authorized"] is True
    assert event.details["response_contract"]["targets"]["pid"] == 4242
    assert event.details["response_contract"]["targets"]["process_create_time"] == 100.0
    assert event.details["modules"] == [
        "File Integrity Monitor", "Network Monitor", "Process Monitor",
    ]


@pytest.mark.parametrize("remote_marker", [
    {"response_authority": REMOTE_OBSERVE_AUTHORITY},
    {"node_origin": "inert-peer"},
])
def test_same_remote_ip_cannot_add_local_response_evidence(remote_marker):
    module = EvidenceLatticeModule()
    module.bind(EventBus())
    local = {"remote_ip": "8.8.8.8"}
    module._on_event(_event("Network Monitor", local))
    module._on_event(_event("Process Monitor", local))
    module._on_event(_event("Remote Telemetry Bridge", {**local, **remote_marker}))
    assert module._bus.recent(10) == []
    module._on_event(_event("File Integrity Monitor", local))
    event = module._bus.recent(1)[0]
    assert event.details["response_authorized"] is True
    assert event.details["response_contract"]["targets"]["remote_ips"] == ["8.8.8.8"]


def test_remote_evidence_is_rejected_before_allocating_entity_state():
    lattice = EvidenceLattice()
    for pid in range(1, 600):
        assert lattice.ingest(_event("Remote Telemetry Bridge", {
            "process_id": pid, "node_origin": "inert-peer",
        }), now=1.0) is None
    assert lattice.counts() == (0, 0)
