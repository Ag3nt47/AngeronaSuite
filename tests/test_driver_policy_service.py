"""Real durable installed composition with inert native policy boundary.

Only disposable fixture keys/artifacts are written. No CiTool/ConfigCI, SCM
installation, host policy query or mutation is performed by these tests.
"""
from __future__ import annotations

import base64
from dataclasses import asdict
import os
import threading
import time
from types import SimpleNamespace
import uuid

import pytest

from angerona.core import driver_policy_service as service
from angerona.core import native_pipe_custody
from angerona.core import native_broker_custody
from angerona.core import privileged_pipe as wire
from angerona.core.engine_transport import canonical, create_private_file, private_directory, verify_private
import test_windows_driver_policy as fixture


def write(path, raw):
    with os.fdopen(create_private_file(path), "wb") as stream:
        stream.write(raw)


def public_credential(index):
    record = fixture.credential(index)
    return dict(asdict(record), public_key=base64.b64encode(record.public_key).decode("ascii"))


def provision(root):
    private_directory(root)
    audit, enforce = fixture.material(), fixture.material("enforce")
    catalog = audit.catalog
    manifest = {"schema": service.SCHEMA, "policy_id": fixture.GUID, "minimum_audit_seconds": 300,
        "native_pins": {"citool_sha256": "a" * 64, "citool_publisher": "Inert fixture publisher",
            "powershell_sha256": "b" * 64, "powershell_publisher": "Inert fixture publisher", "configci_manifest_sha256": "c" * 64},
        "catalog": {"source_url": catalog.source_url, "revision": catalog.revision,
                    "review_reference": catalog.review_reference, "artifact_sha256": catalog.artifact_sha256},
        "materials": [{"mode": item.mode, "version": item.version, "xml_sha256": item.xml_sha256,
                       "compiled_sha256": item.compiled_sha256} for item in (audit, enforce)], "reviews": []}
    write(root / "catalog.bin", catalog.artifact)
    for item in (audit, enforce):
        write(root / (item.xml_sha256 + ".xml"), item.xml)
        write(root / (item.compiled_sha256 + ".cip"), fixture.compiled(item.mode))
    for index, name in enumerate(("broker", "journal", "capability", "transport")):
        write(root / (name + ".key"), bytes([index + 1]) * 32)
    write(root / "manifest.json", canonical(manifest))
    return manifest, audit, enforce


@pytest.fixture(autouse=True)
def no_operator_native_actions(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("A test attempted native policy composition")
    monkeypatch.setattr(service.policy, "WindowsNativeDriverPolicyApi", forbidden)
    monkeypatch.setattr(service, "_OWNERS", [])
    monkeypatch.setattr(service, "_HOLDS", [])
    monkeypatch.setattr(service, "_FILE_HOLD", [])
    monkeypatch.setattr(native_broker_custody, "_RETIREMENT_HOLDS", [])
    monkeypatch.setattr(native_pipe_custody, "_RETIREMENT_HOLDS", [])


@pytest.fixture
def state(tmp_path):
    root = tmp_path / "DriverPolicy"
    manifest, audit, enforce = provision(root)
    native, clock, accepted = fixture.Native(), [1000.0], [True]
    def construct():
        return service.DriverPolicyServiceRuntime(root, manifest_sha256=fixture.digest(canonical(manifest)),
            credentials=[fixture.credential(index) for index in (1, 2, 3)], installed_guard=lambda: accepted[0],
            read_artifact=service.ProtectedArtifactReader(verify_private),
            native_factory=lambda *_args, **_kwargs: native, clock=lambda: clock[0])
    owner = construct()
    value = SimpleNamespace(owner=owner, construct=construct, manifest=manifest, audit=audit, enforce=enforce,
                            native=native, root=root, clock=clock, accepted=accepted)
    owner.start()
    try:
        yield value
    finally:
        native.query_hook = native.before_update = native.after_update = None
        owner.stop(3)
        if value.owner is not owner:
            value.owner.stop(3)


def wait(owner, identity, peer=None):
    peer = fixture.peer() if peer is None else peer
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        result = owner.dispatch({"operation": "driver.poll", "job_id": identity}, peer)
        if result["state"] not in {"queued", "running"}:
            return result
        threading.Event().wait(.005)
    raise AssertionError("Owned inert policy operation did not complete")


def submit(owner, request, peer=None):
    peer = fixture.peer() if peer is None else peer
    queued = owner.dispatch(request, peer)
    return wait(owner, queued["job_id"], peer)


def prepare(state, action="audit", original_id="", review_id=""):
    item = state.audit if action == "audit" else state.enforce
    result = submit(state.owner, {"operation": "driver.prepare", "material_id": item.identity,
        "action": action, "original_id": original_id, "review_id": review_id})
    assert result["state"] == "completed", result
    return result["result"]


def approve(state, result, index):
    proposal = state.owner._plans[result["plan"]["plan_id"]]
    proof = asdict(fixture.proof(proposal, index, state.clock[0]))
    return submit(state.owner, {"operation": "driver.approve", "plan_id": result["plan"]["plan_id"], "proof": proof}, fixture.peer(index))


def execute(state, plan):
    return submit(state.owner, {"operation": "driver.execute", "plan_id": plan["plan"]["plan_id"]})


def test_actual_retained_composition_runs_real_broker_capability_service_and_readback(state):
    result = prepare(state)
    assert result["proposal_digest"] == state.owner._plans[result["plan"]["plan_id"]].digest
    assert not state.native.calls
    assert approve(state, result, 2)["state"] == "completed"
    assert approve(state, result, 3)["state"] == "completed"
    receipt = execute(state, result)
    assert receipt["state"] == "completed" and receipt["result"]["outcome"] == "completed"
    assert receipt["result"]["result"]["kernel_prevention_verified"] is False
    assert state.owner._authority.health().consumed_sequence == 1
    assert state.owner._journal.row(result["plan"]["plan_id"])["phase"] == "configured"
    assert state.native.calls == [("update", state.audit.identity)]
    assert state.owner._thread.daemon is False


def test_missing_independent_approvals_cannot_cross_native_boundary(state):
    result = prepare(state)
    assert approve(state, result, 1)["state"] == "held"  # requester cannot approve itself
    assert approve(state, result, 2)["state"] == "completed"
    assert execute(state, result)["state"] == "held"
    assert state.native.calls == [] and state.owner._authority.health().consumed_sequence == 0


@pytest.mark.parametrize("variation", ["wrong-peer", "wrong-purpose", "forged-signature", "same-person-new-label"])
def test_pipe_identity_and_exact_signed_purpose_required(state, variation):
    result = prepare(state)
    proposal = state.owner._plans[result["plan"]["plan_id"]]
    proof = asdict(fixture.proof(proposal, 2, state.clock[0]))
    peer = fixture.peer(3) if variation == "wrong-peer" else fixture.peer(2)
    if variation == "wrong-purpose":
        proof["purpose_digest"] = "0" * 64
    elif variation == "forged-signature":
        proof["signature"] = "A" * 86
    elif variation == "same-person-new-label":
        proof["credential_id"] = "requester-new-label"
    response = submit(state.owner, {"operation": "driver.approve", "plan_id": result["plan"]["plan_id"], "proof": proof}, peer)
    assert response["state"] == "held" and not state.native.calls


@pytest.mark.parametrize("wire_request", [
    {"operation": "execute", "command": "arbitrary"},
    {"operation": "driver.prepare", "material_id": "C:\\outside", "action": "audit", "original_id": "", "review_id": ""},
    {"operation": "driver.prepare", "material_id": "a" * 64, "action": "audit", "original_id": "", "review_id": "", "guard": True},
    {"operation": "driver.execute", "plan_id": "a" * 32, "proposal": {}},
    {"operation": "driver.approve", "plan_id": "a" * 32, "proof": {}, "peer": {"user_sid": "SYSTEM"}},
])
def test_wire_never_accepts_paths_code_peer_claims_guards_or_arbitrary_proposals(state, wire_request):
    with pytest.raises((PermissionError, TypeError)):
        state.owner.dispatch(wire_request, fixture.peer())
    assert not state.native.calls


def test_prepare_runs_off_request_thread_and_poll_is_memory_only(state):
    entered, finish = threading.Event(), threading.Event()
    observed = []
    def query():
        observed.append(threading.current_thread())
        entered.set()
        assert finish.wait(3)
    state.native.query_hook = query
    queued = state.owner.dispatch({"operation": "driver.prepare", "material_id": state.audit.identity,
        "action": "audit", "original_id": "", "review_id": ""}, fixture.peer())
    try:
        assert entered.wait(2)
        state.owner._read = lambda *_args: (_ for _ in ()).throw(AssertionError("Poll read a file"))
        assert state.owner.dispatch({"operation": "driver.poll", "job_id": queued["job_id"]}, fixture.peer())["state"] == "running"
        assert observed == [state.owner._thread]
    finally:
        state.owner._read = service.ProtectedArtifactReader(verify_private)
        finish.set()
    assert wait(state.owner, queued["job_id"])["state"] == "completed"


def test_jobs_are_peer_bound_and_requester_alone_can_execute(state):
    result = prepare(state)
    with pytest.raises(PermissionError):
        state.owner.dispatch({"operation": "driver.execute", "plan_id": result["plan"]["plan_id"]}, fixture.peer(2))
    identity = next(iter(state.owner._jobs))
    with pytest.raises(PermissionError):
        state.owner.dispatch({"operation": "driver.poll", "job_id": identity}, fixture.peer(2))


def test_profile_change_and_restoration_remain_sticky_held(state):
    state.accepted[0] = False
    with pytest.raises(PermissionError):
        prepare(state)
    state.accepted[0] = True
    assert state.owner.dispatch({"operation": "driver.status"}, fixture.peer())["state"] == "held"
    with pytest.raises(PermissionError):
        prepare(state)
    assert not state.native.calls


def test_cancel_before_native_commit_refuses_mutation_and_keeps_evidence(state):
    result = prepare(state)
    assert approve(state, result, 2)["state"] == approve(state, result, 3)["state"] == "completed"
    entered, finish = threading.Event(), threading.Event()
    def before():
        entered.set()
        assert finish.wait(3)
    state.native.before_update = before
    queued = state.owner.dispatch({"operation": "driver.execute", "plan_id": result["plan"]["plan_id"]}, fixture.peer())
    try:
        assert entered.wait(2)
        state.owner.dispatch({"operation": "driver.cancel", "job_id": queued["job_id"]}, fixture.peer())
    finally:
        finish.set()
    assert wait(state.owner, queued["job_id"])["state"] == "cancelled"
    assert not state.native.calls
    assert state.owner._journal.row(result["plan"]["plan_id"])["phase"] in {"uncertain", "cancelled"}


def test_stop_holds_exact_worker_and_leases_until_actual_native_boundary_retires(state):
    entered, finish = threading.Event(), threading.Event()
    state.native.query_hook = lambda: (entered.set(), finish.wait(3))
    state.owner.dispatch({"operation": "driver.prepare", "material_id": state.audit.identity,
        "action": "audit", "original_id": "", "review_id": ""}, fixture.peer())
    try:
        assert entered.wait(2)
        assert not state.owner.stop(0)
        assert service._OWNERS == service._HOLDS == [state.owner]
        assert state.owner._journal.ready()
        with pytest.raises(PermissionError):
            state.construct()
    finally:
        finish.set()
    assert state.owner.stop(3)
    assert not state.owner._journal.ready() and not service._OWNERS and not service._HOLDS


def test_restart_after_aged_audit_loads_fixed_compatibility_evidence_and_enforces_then_removes(state):
    audit = prepare(state)
    assert approve(state, audit, 2)["state"] == approve(state, audit, 3)["state"] == "completed"
    assert execute(state, audit)["result"]["outcome"] == "completed"
    assert state.owner.stop()
    state.clock[0] += 300
    report = b"Inert fixture boot recovery and driver compatibility review"
    report_pin = fixture.digest(report)
    row = {"audit_plan_id": audit["plan"]["plan_id"], "audit_material_id": state.audit.identity,
           "report_sha256": report_pin, "review_reference": "Explicit disposable fixture review"}
    state.manifest["reviews"] = [row]
    write(state.root / (report_pin + ".review"), report)
    # Simulate the independently accepted installer replacing public manifest.
    (state.root / "manifest.json").write_bytes(canonical(state.manifest))
    state.owner = state.construct()
    state.owner.start()
    review_id = next(iter(state.owner.backend.validator.reviews))
    enforce = prepare(state, "enforce", audit["plan"]["plan_id"], review_id)
    assert approve(state, enforce, 2)["state"] == approve(state, enforce, 3)["state"] == "completed"
    assert execute(state, enforce)["result"]["outcome"] == "completed"
    removal = prepare(state, "remove", enforce["plan"]["plan_id"])
    assert approve(state, removal, 2)["state"] == approve(state, removal, 3)["state"] == "completed"
    assert execute(state, removal)["result"]["outcome"] == "completed"
    assert not state.native.current.present


@pytest.mark.parametrize("file", ["catalog.bin", "broker.key", "manifest.json", "compiled"])
def test_bad_fixed_artifact_refuses_before_any_native_api(tmp_path, file):
    root = tmp_path / "DriverPolicy"
    manifest, audit, _ = provision(root)
    target = root / (audit.compiled_sha256 + ".cip") if file == "compiled" else root / file
    target.write_bytes(b"bad")
    native_called = []
    with pytest.raises((PermissionError, ValueError)):
        service.DriverPolicyServiceRuntime(root, manifest_sha256=fixture.digest(canonical(manifest)),
            credentials=[fixture.credential(index) for index in (1, 2, 3)], installed_guard=lambda: True,
            read_artifact=service.ProtectedArtifactReader(verify_private),
            native_factory=lambda *_args, **_kwargs: native_called.append(1))
    assert not native_called and not service._OWNERS and not service._HOLDS


def test_unenrolled_source_cannot_read_protected_keys_or_create_state(tmp_path):
    called = []
    with pytest.raises(PermissionError):
        service.DriverPolicyServiceRuntime(tmp_path, manifest_sha256="a" * 64, credentials=[], installed_guard=lambda: False,
            read_artifact=lambda *_args: called.append(1))
    assert not called and not list(tmp_path.iterdir())


def test_bounded_plan_and_job_cache_holds_new_work_without_native_dispatch(state, monkeypatch):
    monkeypatch.setattr(service, "MAX_JOBS", 1)
    prepare(state)
    with pytest.raises(PermissionError, match="capacity"):
        prepare(state)
    assert not state.native.calls


def test_revocation_during_native_prepare_prevents_os_mutation_and_plan_publication(state):
    state.native.query_hook = lambda: state.accepted.__setitem__(0, False)
    result = submit(state.owner, {"operation": "driver.prepare", "material_id": state.audit.identity,
        "action": "audit", "original_id": "", "review_id": ""})
    assert result["state"] == "held" and not state.owner._plans and not state.native.calls


def test_failed_start_keeps_unpublished_generation_and_never_releases_leases(state, monkeypatch):
    assert state.owner.stop()
    entered, finish = threading.Event(), threading.Event()
    real_thread = threading.Thread
    class LateThread:
        ident = None
        def __init__(self, *, target, **kwargs):
            def late():
                entered.set()
                assert finish.wait(3)
                target()
            self.actual = real_thread(target=late, **kwargs)
        def start(self):
            self.actual.start()
            assert entered.wait(2)
            raise RuntimeError("Unpublished native worker admission fixture")
        def is_alive(self):
            return False
    monkeypatch.setattr(service.threading, "Thread", LateThread)
    owner = state.construct()
    state.owner = owner
    try:
        with pytest.raises(RuntimeError):
            owner.start()
        assert not owner.stop(0) and owner._journal.ready()
        assert service._OWNERS == service._HOLDS == [owner]
        with pytest.raises(PermissionError):
            state.construct()
    finally:
        finish.set()
        owner._thread.actual.join(3)
        assert not owner._thread.actual.is_alive()
    assert owner._done.is_set() and not owner.stop(3) and owner._journal.ready()
    # No native worker remains. Release only fixture leases explicitly; the
    # product owner must remain sticky held after uncertain start.
    owner._broker.close()
    owner._journal.close()
    owner._authority.close()


def test_overlapping_stop_is_sticky_and_never_reports_clean_on_first_closer(state):
    entered, finish = threading.Event(), threading.Event()
    original_close = state.owner._journal.close
    def delayed_close():
        entered.set()
        assert finish.wait(3)
        original_close()
    state.owner._journal.close = delayed_close
    results = []
    thread = threading.Thread(target=lambda: results.append(state.owner.stop(3)))
    thread.start()
    try:
        assert entered.wait(2)
        assert not state.owner.stop(0)
    finally:
        finish.set()
        thread.join(3)
    assert not thread.is_alive() and results == [False]
    assert service._OWNERS == service._HOLDS == [state.owner]
    assert not state.owner.stop()


def test_protected_reader_denies_write_delete_and_detects_new_hardlink_during_read(tmp_path):
    path = tmp_path / "native-fixture.bin"
    alias = tmp_path / "native-alias.bin"
    path.write_bytes(b"bounded fixture artifact")
    validations = []
    def verify(_path):
        validations.append(1)
        if len(validations) == 2:
            with pytest.raises(OSError):
                path.write_bytes(b"replacement")
            with pytest.raises(OSError):
                path.unlink()
            os.link(path, alias)
    reader = service.ProtectedArtifactReader(verify)
    try:
        with pytest.raises(PermissionError, match="alias or link"):
            reader(path, 64)
    finally:
        if alias.exists():
            alias.unlink()
    assert path.read_bytes() == b"bounded fixture artifact" and not service._FILE_HOLD


@pytest.mark.parametrize("failure", ["close", "identity", "short-read"])
def test_protected_reader_native_uncertainty_never_returns_trusted_bytes_or_retries_handles(monkeypatch, tmp_path, failure):
    import win32file
    handles = []
    raw = b"simulated read artifact"
    class Handle:
        def __init__(self):
            self.close_count, self.detach_count = 0, 0
        def Close(self):
            self.close_count += 1
            if failure == "close" and self is handles[0]:
                raise RuntimeError("Simulated ambiguous CloseHandle")
        def Detach(self):
            self.detach_count += 1
            return 101
    def create(*_args):
        value = Handle()
        handles.append(value)
        return value
    monkeypatch.setattr(win32file, "CreateFile", create)
    monkeypatch.setattr(win32file, "ReadFile", lambda *_args: (0, raw[:-1] if failure == "short-read" else raw))
    monkeypatch.setattr(win32file, "GetFileInformationByHandle", lambda _handle: (0, 1, 2, 3, 4, 0, len(raw), 1, 5, 6))
    reader = service.ProtectedArtifactReader(lambda _path: None)
    monkeypatch.setattr(reader, "_identity", lambda handle: 2 if failure == "identity" and handle is not handles[0] else 1)
    with pytest.raises(PermissionError):
        reader(tmp_path / "modeled-artifact", 64)
    assert all(handle.close_count == 1 for handle in handles)
    if failure == "close":
        assert service._FILE_HOLD == [handles[0]] and handles[0].detach_count == 1
        with pytest.raises(PermissionError, match="retirement"):
            reader(tmp_path / "modeled-artifact", 64)
        assert len(handles) == 2 and all(handle.close_count == 1 for handle in handles)
    else:
        assert not service._FILE_HOLD


def test_ambiguous_state_close_is_retained_without_numeric_or_lease_retry(state):
    original = state.owner._journal.close
    calls = []
    def failed_close():
        calls.append(1)
        original()
        raise RuntimeError("Simulated close return uncertainty")
    state.owner._journal.close = failed_close
    assert not state.owner.stop() and not state.owner.stop()
    assert calls == [1] and service._OWNERS == service._HOLDS == [state.owner]


def test_real_owned_native_response_wire_uses_strict_pipe_and_captured_os_identity():
    from angerona.core.approval_identity import current_os_identity
    subject = current_os_identity().subject
    endpoint = r"\\.\pipe\Angerona.DriverPolicy.Test." + uuid.uuid4().hex
    server = service.DriverPolicyPipeServer(lambda request, peer: {"subject": peer.user_sid, "request": request},
        server_sid=subject, allowed_sids=[subject], endpoint=endpoint)
    client = wire.PrivilegedPipeClient(endpoint=endpoint, _server_verifier=lambda *_args: None)
    try:
        server.start()
        result = client.exchange({"operation": "fixture-status"})
        assert result == {"subject": subject, "request": {"operation": "fixture-status"}}
        assert all(type(pipe) is service.DriverPolicyPipe for pipe in server.pipes)
    finally:
        assert server.stop(3)
    assert all(pipe.close_proven for pipe in server.pipes)
    assert not native_broker_custody._RETIREMENT_HOLDS
