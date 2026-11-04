"""Real private source-update maintenance; no automatic deletion or fake trust.

The imported fixture uses actual staging, plans, source publication and native
file operations. Only its documented Git/process-query transports are modeled.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import zipfile

import pytest

from test_source_update_activation import (
    activation as activation, composition as composition, context as context,
    inert_child_factory as inert_child_factory, inert_owner as inert_owner,
    _FIRST, _SECOND, _Crash, _View, _approve, _encoded, _guard, _operation,
    _plan, _protected_unchanged, _run, _sha,
)
from angerona.core import source_activation as api
from angerona.core import source_activation_file as files
from angerona.core import source_activation_storage as storage
from angerona.core import startup_recovery


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Native source-update maintenance")


def _tree(path):
    return {item.relative_to(path).as_posix():
            (item.read_bytes(), item.stat().st_dev, item.stat().st_ino)
            for item in path.rglob("*") if item.is_file()}


def _review(sample):
    return storage.review_source_update_storage(sample.root, sample.state)


def _selected(review, identifier):
    return next(row for row in review["operations"] if row["activation_id"] == identifier)


@pytest.fixture
def inactive(activation):
    sample = activation
    plan = _plan(sample)
    review = _review(sample)
    row = _selected(review, plan["activation_id"])
    assert row["status"] == "inactive-candidate" and not row["protected"]
    assert row["export_allowed"] and row["delete_requires_confirmation"]
    return sample, plan, review


def test_real_inactive_candidate_export_verifies_every_zip_member_without_removal(inactive):
    sample, plan, review = inactive
    operation = _operation(sample, plan)
    stage = sample.state / "stages" / plan["stage_id"]
    before = {"activation/" + name: facts for name, facts in _tree(operation).items()}
    before.update({"stage/" + name: facts for name, facts in _tree(stage).items()})
    result = storage.export_source_update_backup(sample.root, sample.state,
        plan["activation_id"], review["review_sha256"], accepted=True)
    assert result["status"] == "exported" and result["activation_id"] == plan["activation_id"]
    archive = Path(result["path"])
    assert archive.parent == sample.state / "exports"
    assert _sha(archive.read_bytes()) == result["zip_sha256"]
    assert archive.stat().st_size == result["zip_bytes"]
    with zipfile.ZipFile(archive, "r") as exported:
        names = exported.namelist()
        assert len(names) == len(set(names)) == len(before) + 1
        assert set(names) == set(before) | {"verified-manifest.json"}
        manifest = json.loads(exported.read("verified-manifest.json"))
        assert manifest["source_scope_sha256"] == result["source_scope_sha256"]
        assert set(manifest["files"]) == set(before)
        for name, (raw, _device, _inode) in before.items():
            assert exported.read(name) == raw
            assert manifest["files"][name] == {"bytes": len(raw), "sha256": _sha(raw)}
    assert result["files"] == len(before)
    assert _tree(operation) == {name[11:]: value for name, value in before.items()
                                if name.startswith("activation/")}
    assert _tree(stage) == {name[6:]: value for name, value in before.items()
                            if name.startswith("stage/")}
    _protected_unchanged(sample)


@pytest.mark.parametrize("operation", ["export", "delete"])
def test_declining_maintenance_performs_no_payload_mutation(inactive, operation):
    sample, plan, review = inactive
    before = _tree(sample.state)
    if operation == "export":
        result = storage.export_source_update_backup(sample.root, sample.state,
            plan["activation_id"], review["review_sha256"], accepted=False)
    else:
        result = storage.delete_source_update_backup(sample.root, sample.state,
            plan["activation_id"], review["review_sha256"], accepted=True, permanent=False)
    assert result["status"] == "declined"
    assert _tree(sample.state) == before
    assert not sample.app._shutdown_requested.is_set()
    _protected_unchanged(sample)


def test_explicit_unexported_inactive_payload_delete_preserves_compact_audit(inactive):
    sample, plan, review = inactive
    operation = _operation(sample, plan)
    before_plan = (operation / "plan.json").read_bytes()
    assert not (sample.state / "exports").exists()
    result = storage.delete_source_update_backup(sample.root, sample.state,
        plan["activation_id"], review["review_sha256"], accepted=True, permanent=True)
    assert result["status"] == "deleted" and result["deleted_files"] > 0
    assert result["deleted_bytes"] > 0 and result["receipt_id"]
    assert (operation / "plan.json").read_bytes() == before_plan
    marker = json.loads((operation / "backup-retired.json").read_bytes())
    assert marker["activation_id"] == plan["activation_id"]
    assert marker["compact_metadata_preserved"] is True
    assert marker["consent_receipt"] == result["receipt_id"]
    assert not (operation / "broker").exists()
    assert not (sample.state / "stages" / plan["stage_id"]).exists()
    assert not (sample.state / "exports").exists()  # Export is not secretly forced.
    after = _review(sample)
    assert _selected(after, plan["activation_id"])["status"] == "retired-payload"
    assert not _selected(after, plan["activation_id"])["export_allowed"]
    assert not (sample.state / "activation-pending.json").exists()
    assert not sample.app._shutdown_requested.is_set()
    _protected_unchanged(sample)


@pytest.mark.parametrize("case", ["wrong-id", "wrong-review", "unknown-object"])
@pytest.mark.parametrize("operation", ["export", "delete"])
def test_wrong_confirmation_or_unknown_backup_objects_preserve_payloads(inactive, case, operation):
    sample, plan, review = inactive
    identifier, digest = plan["activation_id"], review["review_sha256"]
    if case == "wrong-id":
        identifier = "0" * 32
        assert identifier != plan["activation_id"]
    elif case == "wrong-review":
        digest = "0" * 64
    else:
        target = _operation(sample, plan) / "unknown-private-object.bin"
        target.write_bytes(b"must never be deleted by reviewed cleanup")
        review = _review(sample)
        digest = review["review_sha256"]  # Reach actual closed backup allowlist.
    before = _tree(_operation(sample, plan))
    with pytest.raises(storage.SourceActivationStorageHeld):
        if operation == "export":
            storage.export_source_update_backup(sample.root, sample.state, identifier,
                                                digest, accepted=True)
        else:
            storage.delete_source_update_backup(sample.root, sample.state, identifier,
                                                digest, accepted=True, permanent=True)
    assert _tree(_operation(sample, plan)) == before
    assert not (sample.state / "activation-pending.json").exists()
    _protected_unchanged(sample)


def test_actual_unknown_child_raced_into_retained_directory_is_not_deleted(inactive, monkeypatch):
    sample, plan, review = inactive
    operation = _operation(sample, plan)
    before = _tree(operation)
    actual_init = storage._OwnedDirectory.__init__
    raced = []

    def init(owner, path, stamp, *, delete_access=True):
        actual_init(owner, path, stamp, delete_access=delete_access)
        if Path(path) == operation and delete_access and not raced:
            new = operation / "raced-unowned.bin"
            new.write_bytes(b"unknown native child")
            raced.append((new, new.stat().st_ino))

    monkeypatch.setattr(storage._OwnedDirectory, "__init__", init)
    result = storage.delete_source_update_backup(sample.root, sample.state,
        plan["activation_id"], review["review_sha256"], accepted=True, permanent=True)
    assert raced and result["status"] == "held-partial"
    assert result["deleted_files"] == result["deleted_bytes"] == 0
    target, identity = raced[0]
    assert target.read_bytes() == b"unknown native child" and target.stat().st_ino == identity
    after = _tree(operation)
    assert {name: value for name, value in after.items() if name != target.name} == before
    assert (sample.state / "retention" / ("delete-" + result["receipt_id"] + ".json")).exists()
    _protected_unchanged(sample)


@pytest.mark.parametrize("kind", ["current", "request", "pending", "proposal"])
def test_real_current_or_inflight_activation_evidence_cannot_be_exported_or_deleted(activation, kind):
    sample = activation
    plan = _plan(sample)
    if kind == "proposal":
        api.queue_source_activation_proposal(sample.state, plan["activation_id"], plan["plan_sha256"])
    else:
        request = _approve(sample, plan)
        if kind == "current":
            assert _run(sample, plan, request)["status"] == "committed"
        elif kind == "pending":
            def crash(phase, _name):
                if phase == "prepared":
                    raise _Crash()
            with pytest.raises(_Crash):
                _run(sample, plan, request, checkpoint=crash)
    review = _review(sample)
    selected = _selected(review, plan["activation_id"])
    assert selected["protected"] and not selected["export_allowed"]
    assert not selected["delete_requires_confirmation"]
    before = _tree(_operation(sample, plan))
    for operation in ("export", "delete"):
        with pytest.raises(storage.SourceActivationStorageHeld, match="protected"):
            if operation == "export":
                storage.export_source_update_backup(sample.root, sample.state,
                    plan["activation_id"], review["review_sha256"], accepted=True)
            else:
                storage.delete_source_update_backup(sample.root, sample.state,
                    plan["activation_id"], review["review_sha256"], accepted=True, permanent=True)
    assert _tree(_operation(sample, plan)) == before
    _protected_unchanged(sample)


def test_two_real_updates_keep_current_lineage_when_old_completed_backup_is_deleted(activation):
    sample = activation
    plans = []
    for target in (_FIRST, _SECOND):
        plan = _plan(sample, target)
        request = _approve(sample, plan)
        assert _run(sample, plan, request)["status"] == "committed"
        plans.append(plan)
    current = api.applied_source_base(sample.root, sample.state)
    review = _review(sample)
    old, latest = plans
    assert _selected(review, old["activation_id"])["export_allowed"]
    assert _selected(review, latest["activation_id"])["protected_reason"] == "current-lineage"
    old_value = json.loads((_operation(sample, old) / "plan.json").read_bytes())
    latest_value = json.loads((_operation(sample, latest) / "plan.json").read_bytes())
    old_workspace = sample.root / ".tmp" / ("source-activation-" + old_value["plan_nonce"])
    latest_workspace = sample.root / ".tmp" / ("source-activation-" + latest_value["plan_nonce"])
    old_stage = sample.state / "stages" / old["stage_id"]
    assert old_workspace.is_dir() and old_stage.is_dir()
    latest_payload = _tree(latest_workspace)
    control_bytes = sum(path.stat().st_size for path in sample.state.rglob("*") if path.is_file())
    source_bytes = sum(path.stat().st_size for path in (sample.root / ".tmp").rglob("*") if path.is_file())
    assert review["retained_bytes"] == control_bytes + source_bytes
    result = storage.delete_source_update_backup(sample.root, sample.state,
        old["activation_id"], review["review_sha256"], accepted=True, permanent=True)
    assert result["status"] == "deleted"
    assert not old_workspace.exists() and not old_stage.exists()
    assert _tree(latest_workspace) == latest_payload
    after_review = _review(sample)
    assert _selected(after_review, old["activation_id"])["status"] == "retired-payload"
    assert after_review["retained_bytes"] < review["retained_bytes"]
    assert (_operation(sample, old) / "plan.json").exists()
    assert (_operation(sample, old) / "committed.json").exists()
    assert api.applied_source_base(sample.root, sample.state) == current
    assert (sample.root / "feature.py").read_bytes() == b"value=3\n"
    assert (sample.root / "new_upstream.py").read_bytes() == b"new=3\n"
    assert (sample.root / "custom.py").read_bytes() == b"my_local_preference=True\n"
    assert (sample.state / "applied-base.json").exists()
    assert (sample.state / "activations" / ("apply-" + latest["activation_id"]) / "committed.json").exists()
    _protected_unchanged(sample)


def test_storage_policy_decline_then_explicit_bounded_change_is_truthful(inactive):
    sample, _plan_value, review = inactive
    before = _tree(sample.state)
    declined = storage.set_source_update_storage_policy(sample.root, sample.state,
        review["review_sha256"], accepted=False, completed_backups=4, max_bytes=1024**3)
    assert declined == {"status": "declined", "budget": None}
    assert _tree(sample.state) == before
    result = storage.set_source_update_storage_policy(sample.root, sample.state,
        review["review_sha256"], accepted=True, completed_backups=4, max_bytes=1024**3)
    assert result == {"status": "changed", "budget": {"completed_backups": 4, "max_bytes": 1024**3}}
    after = _review(sample)
    assert after["policy_status"] == "ready" and after["budget"] == result["budget"]
    assert not (sample.state / "activation-storage-policy-pending.json").exists()
    assert not (sample.state / "activation-pending.json").exists()
    assert not sample.app._shutdown_requested.is_set()
    _protected_unchanged(sample)


def test_policy_native_publication_failure_retains_separate_hold_and_no_false_default(inactive, monkeypatch):
    sample, _plan_value, review = inactive
    target = sample.state / "activation-storage-policy.json"
    fault = OSError("inert native policy publication refusal")
    actual = files.RetainedFile.rename
    reached = []

    def rename(owner, path):
        if Path(path) == target:
            reached.append(owner.path)
            owner.check()
            raise fault
        return actual(owner, path)

    monkeypatch.setattr(files.RetainedFile, "rename", rename)
    with pytest.raises(OSError) as result:
        storage.set_source_update_storage_policy(sample.root, sample.state,
            review["review_sha256"], accepted=True, completed_backups=4, max_bytes=1024**3)
    assert result.value is fault and reached
    assert (sample.state / "activation-storage-policy-pending.json").exists()
    assert not (sample.state / "activation-pending.json").exists()
    after = _review(sample)
    assert after["policy_status"] == "held-incomplete-policy"
    assert after["startup_inhibited"] is False and after["automatic_deletion"] is False
    with pytest.raises(storage.SourceActivationStorageHeld, match="no default allowance"):
        storage.require_source_update_storage(sample.root, sample.state, additional_bytes=1)
    assert not sample.app._shutdown_requested.is_set()
    _protected_unchanged(sample)


def test_actual_streaming_digest_is_bounded_complete_and_rejects_early_eof(activation, monkeypatch):
    sample = activation
    path = sample.fixture_root / "digest-private.bin"
    raw = b"abcdef\0" * 10001
    files.write_new(path, raw)
    original_os = files.os
    with files.RetainedFile(path) as held:
        assert held.digest(len(raw)) == (hashlib.sha256(raw).hexdigest(), len(raw))
        counts = []

        def read(fd, limit):
            counts.append(limit)
            return original_os.read(fd, min(limit, 2)) if len(counts) == 1 else b""

        class View:
            def __getattr__(self, name):
                return read if name == "read" else getattr(original_os, name)

        with monkeypatch.context() as fault:
            fault.setattr(files, "os", View())
            with pytest.raises(files.ActivationFileError, match="incomplete"):
                held.digest(len(raw))
        assert counts and max(counts) <= 65536
        held.check()
        assert held.read(len(raw)) == raw
        def forbidden(*_args):
            raise AssertionError("Digest bound was checked after payload read")
        class NoRead:
            def __getattr__(self, name):
                return forbidden if name == "read" else getattr(original_os, name)
        with monkeypatch.context() as fault:
            fault.setattr(files, "os", NoRead())
            with pytest.raises(files.ActivationFileError, match="digest bound"):
                held.digest(len(raw) - 1)


@pytest.mark.parametrize("when", ["already-cancelled", "before-staged-policy"])
def test_policy_cancellation_before_durable_marker_preserves_budget_and_payloads(
    inactive, monkeypatch, when
):
    sample, _plan_value, review = inactive
    before = _tree(sample.state)
    cancelled = [when == "already-cancelled"]
    actual = storage._private_directory

    def directory(path):
        result = actual(path)
        if Path(path) == sample.state / "retention":
            cancelled[0] = True
        return result

    if when == "before-staged-policy":
        monkeypatch.setattr(storage, "_private_directory", directory)
        result = storage.set_source_update_storage_policy(sample.root, sample.state,
            review["review_sha256"], accepted=True, completed_backups=4,
            max_bytes=1024**3, cancelled=lambda: cancelled[0])
        assert result == {"status": "declined", "budget": None}
        assert list((sample.state / "retention").iterdir()) == []
    else:
        with pytest.raises(storage.SourceActivationStorageHeld, match="review was cancelled"):
            storage.set_source_update_storage_policy(sample.root, sample.state,
                review["review_sha256"], accepted=True, completed_backups=4,
                max_bytes=1024**3, cancelled=lambda: cancelled[0])
    assert _tree(sample.state) == before
    after = _review(sample)
    assert after["policy_status"] == "ready" and after["budget"] == review["budget"]
    assert not (sample.state / "activation-storage-policy-pending.json").exists()
    assert not (sample.state / "activation-pending.json").exists()
    assert not sample.app._shutdown_requested.is_set()
    _protected_unchanged(sample)


@pytest.mark.parametrize("reason", ["logical-bytes", "free-reserve"])
def test_backup_export_reserves_shared_quota_before_creating_zip_or_deleting(
    inactive, monkeypatch, reason
):
    sample, plan, original_review = inactive
    before = _tree(sample.state)
    if reason == "logical-bytes":
        monkeypatch.setattr(storage, "DEFAULT_MAX_BYTES", original_review["retained_bytes"])
    else:
        monkeypatch.setattr(storage, "shutil", _View(storage.shutil, disk_usage=lambda _path:
            SimpleNamespace(free=storage.MIN_FREE_BYTES - 1)))
    # Review the actual same payload under the modeled current capacity; a
    # stale review refusal must not substitute for real export admission.
    review = _review(sample)
    with pytest.raises(storage.SourceActivationStorageHeld) as result:
        storage.export_source_update_backup(sample.root, sample.state,
            plan["activation_id"], review["review_sha256"], accepted=True)
    assert ("byte limit" if reason == "logical-bytes" else "free-space reserve") in str(result.value)
    assert _tree(sample.state) == before
    assert not (sample.state / "exports").exists()
    assert not (sample.state / "activation-request.json").exists()
    assert not (sample.state / "activation-pending.json").exists()
    assert not (sample.data / "diagnostics/operator-stop.json").exists()
    assert not sample.app._shutdown_requested.is_set()
    assert _selected(_review(sample), plan["activation_id"])["status"] == "inactive-candidate"
    _protected_unchanged(sample)



def test_explicit_external_zip_is_verified_without_managed_payload_or_receipt(inactive):
    sample, plan, review = inactive
    destination = sample.fixture_root / "explicit-private-export.zip"
    before = _tree(sample.state)
    operation = _operation(sample, plan)
    stage = sample.state / "stages" / plan["stage_id"]
    members = {"activation/" + name: facts[0] for name, facts in _tree(operation).items()}
    members.update({"stage/" + name: facts[0] for name, facts in _tree(stage).items()})
    result = storage.export_source_update_backup(sample.root, sample.state,
        plan["activation_id"], review["review_sha256"], accepted=True, destination=destination)
    assert result["status"] == "exported" and result["location"] == "external"
    assert Path(result["path"]) == destination
    assert result["zip_sha256"] == _sha(destination.read_bytes())
    assert result["zip_bytes"] == destination.stat().st_size
    with zipfile.ZipFile(destination) as archive:
        names = archive.namelist()
        assert len(names) == len(set(names)) == len(members) + 1
        assert set(names) == set(members) | {"verified-manifest.json"}
        manifest = json.loads(archive.read("verified-manifest.json"))
        assert manifest["source_scope_sha256"] == result["source_scope_sha256"]
        assert set(manifest["files"]) == set(members)
        for name, raw in members.items():
            assert archive.read(name) == raw
            assert manifest["files"][name] == {"sha256": _sha(raw), "bytes": len(raw)}
    assert not list(sample.fixture_root.glob(".angerona-export-*"))
    assert _tree(sample.state) == before
    assert not (sample.state / "exports").exists()
    _protected_unchanged(sample)


@pytest.mark.parametrize("choice", ["source", "state", "relative", "not-zip", "existing"])
def test_external_destination_cannot_escape_approved_scope_or_overwrite(inactive, choice):
    sample, plan, review = inactive
    if choice == "source":
        destination = sample.root / "external.zip"
    elif choice == "state":
        destination = sample.state / "external.zip"
    elif choice == "relative":
        destination = Path("relative.zip")
    elif choice == "not-zip":
        destination = sample.fixture_root / "not-zip.txt"
    else:
        destination = sample.fixture_root / "keep-existing.zip"
        destination.write_bytes(b"unrelated exact destination")
    existing = ((destination.read_bytes(), destination.stat().st_ino)
                if choice == "existing" else None)
    before = _tree(sample.state)
    with pytest.raises(storage.SourceActivationStorageHeld):
        storage.export_source_update_backup(sample.root, sample.state,
            plan["activation_id"], review["review_sha256"], accepted=True, destination=destination)
    assert _tree(sample.state) == before
    if existing is not None:
        assert (destination.read_bytes(), destination.stat().st_ino) == existing
    else:
        assert not destination.exists()
    assert not list(sample.fixture_root.glob(".angerona-export-*"))
    _protected_unchanged(sample)


def test_external_private_directory_creation_race_refuses_without_adopting(inactive, monkeypatch):
    sample, plan, review = inactive
    destination = sample.fixture_root / "explicit-race.zip"
    before = _tree(sample.state)
    actual = startup_recovery.private_directory
    raced = []

    def create(path, *, create):
        path = Path(path)
        if create and path.parent == destination.parent and path.name.startswith(".angerona-export-"):
            assert not raced
            assert actual(path, create=True)
            evidence = path / "unrelated-owner.txt"
            evidence.write_bytes(b"must never become the exporter staging owner")
            raced.append((path, evidence.read_bytes(), evidence.stat().st_ino))
            # Genuine second exclusive native create must refuse; never return a
            # fabricated privacy result for the colliding real object.
        return actual(path, create=create)

    monkeypatch.setattr(startup_recovery, "private_directory", create)
    with pytest.raises(FileExistsError):
        storage.export_source_update_backup(sample.root, sample.state,
            plan["activation_id"], review["review_sha256"], accepted=True, destination=destination)
    assert len(raced) == 1
    path, raw, identity = raced[0]
    evidence = path / "unrelated-owner.txt"
    assert (evidence.read_bytes(), evidence.stat().st_ino) == (raw, identity)
    assert set(item.name for item in path.iterdir()) == {evidence.name}
    assert not destination.exists() and _tree(sample.state) == before
    _protected_unchanged(sample)



@pytest.fixture
def native_output(activation):
    """Actual rolled-back operation; parent output fields are unit DATA only.

    Approval, guard claim, journal, source effects, rollback and terminal record
    execute actual code under the documented process/Git transports. The native
    output envelope below is not a claim that an OS Job or PS observer ran.
    """
    sample = activation
    plan = _plan(sample)
    request = _approve(sample, plan)
    guard_path, guard_sha = _guard(sample, plan, request)

    def fail(phase, name):
        if phase == "new-published":
            raise RuntimeError("inert interruption for a genuine completed rollback")

    result = _run(sample, plan, request, guard=(guard_path, guard_sha), checkpoint=fail)
    assert result["status"] == "rolled_back"
    operation = _operation(sample, plan)
    plan_raw = (operation / "plan.json").read_bytes()
    value = json.loads(plan_raw)
    guard = json.loads(guard_path.read_bytes())
    nonce = guard["guard_nonce"]
    outcome = {"schema": "angerona.source-activation-outcome/v1", "status": result["status"],
        "activation_id": plan["activation_id"], "plan_sha256": plan["plan_sha256"],
        "request_sha256": request["request_sha256"], "guard_sha256": guard_sha,
        "snapshot_sha256": guard["snapshot_sha256"], "source_root": str(sample.root),
        "state_root": str(sample.state), "root_identity": value["root_identity"],
        "pending_present": False, "result": result}
    result_path = operation / ("result-" + nonce + ".json")
    files.write_new(result_path, _encoded(outcome))
    top = operation / "native-output"
    assert startup_recovery.private_directory(top, create=True)
    group = top / nonce
    assert startup_recovery.private_directory(group, create=True)
    log = group / "activation.log"
    raw = b"Unit parent output; no independent native attestation.\n"
    files.write_new(log, raw)
    receipt = {"schema": "angerona.source-activation-native-output/v1",
        "activation_id": plan["activation_id"], "guard_nonce": nonce,
        "guard_sha256": guard_sha, "plan_sha256": plan["plan_sha256"],
        "request_sha256": request["request_sha256"], "log_sha256": _sha(raw),
        "log_bytes": len(raw), "child_job_retired": True, "child_handles_closed": True,
        "inherited_descendants_retired": True, "independent_attestation": False,
        "observation_source": "parent-observed-owned-job"}
    receipt_path = group / "receipt.json"
    files.write_new(receipt_path, _encoded(receipt))
    review = _review(sample)
    assert _selected(review, plan["activation_id"])["export_allowed"]
    return SimpleNamespace(sample=sample, plan=plan, plan_value=value, plan_raw=plan_raw,
        request=request, operation=operation, guard_path=guard_path, guard=guard,
        nonce=nonce, result_path=result_path, outcome=outcome, group=group,
        log=log, receipt_path=receipt_path, receipt=receipt)


def _native_expected(item):
    selected_files, directories = storage._scope_tree(item.operation)
    return storage._native_output_expectations(item.sample.root, item.sample.state,
        item.operation, item.plan_value, item.plan_raw, selected_files, directories)


def _rewrite_json(path, value):
    raw = _encoded(value)
    with path.open("r+b") as stream:
        stream.write(raw)
        stream.truncate()
    return raw


def test_valid_native_output_group_retains_exact_data_exports_then_deletes_payload(native_output):
    item, sample = native_output, native_output.sample
    expected = _native_expected(item)
    prefix = "native-output/" + item.nonce + "/"
    assert set(expected) == {prefix + "activation.log", prefix + "receipt.json",
        item.guard_path.name, "guard-used-" + item.nonce + ".json", item.result_path.name}
    for name, digest in expected.items():
        assert digest == _sha((item.operation / name).read_bytes())
    before = _tree(item.operation)
    review = _review(sample)
    exported = storage.export_source_update_backup(sample.root, sample.state,
        item.plan["activation_id"], review["review_sha256"], accepted=True)
    assert exported["status"] == "exported" and _tree(item.operation) == before
    with zipfile.ZipFile(exported["path"]) as archive:
        manifest = json.loads(archive.read("verified-manifest.json"))
        for name, digest in expected.items():
            member = "activation/" + name
            assert archive.read(member) == before[name][0]
            assert manifest["files"][member]["sha256"] == digest
    review = _review(sample)
    result = storage.delete_source_update_backup(sample.root, sample.state,
        item.plan["activation_id"], review["review_sha256"], accepted=True, permanent=True)
    assert result["status"] == "deleted"
    assert not (item.operation / "native-output").exists()
    for path in (item.guard_path, item.result_path, item.operation / ("guard-used-" + item.nonce + ".json")):
        assert (path.read_bytes(), path.stat().st_dev, path.stat().st_ino) == before[path.name]
    assert _selected(_review(sample), item.plan["activation_id"])["status"] == "retired-payload"
    assert (sample.root / "feature.py").read_bytes() == b"value=1\n"
    _protected_unchanged(sample)


@pytest.mark.parametrize("change", [
    "missing-log", "missing-receipt", "missing-used", "missing-result", "unknown-extra",
    "log-hash", "guard-hash", "plan", "request", "nonce", "receipt-bool-int",
    "guard-schema-bool", "result-pending-int", "independent-claim", "log-oversize", "groups-129",
])
def test_invalid_native_output_data_holds_before_any_irreversible_delete(native_output, monkeypatch, change):
    item, sample = native_output, native_output.sample
    receipt = dict(item.receipt)
    if change.startswith("missing-"):
        path = {"missing-log": item.log, "missing-receipt": item.receipt_path,
            "missing-used": item.operation / ("guard-used-" + item.nonce + ".json"),
            "missing-result": item.result_path}[change]
        path.rename(sample.fixture_root / ("retained-" + path.name))
    elif change == "unknown-extra":
        (item.group / "unknown-user-data.txt").write_bytes(b"must remain untouched")
    elif change == "log-hash":
        raw = item.log.read_bytes()
        with item.log.open("r+b") as stream:
            stream.write(b"X" + raw[1:])
    elif change == "guard-hash":
        receipt["guard_sha256"] = "0" * 64
    elif change == "plan":
        receipt["plan_sha256"] = "0" * 64
    elif change == "request":
        receipt["request_sha256"] = "0" * 64
    elif change == "nonce":
        receipt["guard_nonce"] = "0" * 32
    elif change == "receipt-bool-int":
        receipt["child_handles_closed"] = 1
    elif change == "guard-schema-bool":
        guard = dict(item.guard, schema=True)
        guard_raw = _rewrite_json(item.guard_path, guard)
        receipt["guard_sha256"] = _sha(guard_raw)
        used_path = item.operation / ("guard-used-" + item.nonce + ".json")
        _rewrite_json(used_path, {"guard_sha256": receipt["guard_sha256"], "operation": guard["operation"]})
        _rewrite_json(item.result_path, {**item.outcome, "guard_sha256": receipt["guard_sha256"]})
    elif change == "result-pending-int":
        _rewrite_json(item.result_path, {**item.outcome, "pending_present": 0})
    elif change == "independent-claim":
        receipt["independent_attestation"] = True
    elif change == "log-oversize":
        raw = b"x" * (1024**2 + 1)
        with item.log.open("r+b") as stream:
            stream.write(raw)
            stream.truncate()
        receipt.update(log_bytes=len(raw), log_sha256=_sha(raw))
    else:
        nonces = [item.nonce]
        number = 0
        while len(nonces) < 129:
            nonce = format(number, "032x")
            number += 1
            if nonce in nonces:
                continue
            nonces.append(nonce)
            path = item.operation / "native-output" / nonce
            path.mkdir(mode=0o700)
            (path / "activation.log").write_bytes(b"bounded extra unit output")
            (path / "receipt.json").write_bytes(_encoded(receipt))
    if item.receipt_path.exists():
        _rewrite_json(item.receipt_path, receipt)
    # Exercise the actual closed validator directly so an unrelated public
    # admission refusal cannot satisfy the intended malformed-group negative.
    refusal = {
        "missing-log": "native output log/receipt pair is incomplete",
        "missing-receipt": "native output log/receipt pair is incomplete",
        "missing-used": "native output guard/result evidence is incomplete",
        "missing-result": "native output guard/result evidence is incomplete",
        "unknown-extra": "unknown native output object must be preserved",
        "log-hash": "native output log bytes changed",
        "guard-hash": "native output original guard or one-use marker changed",
        "plan": "native output receipt scope or parent observation is invalid",
        "request": "native output original guard or one-use marker changed",
        "nonce": "native output receipt scope or parent observation is invalid",
        "receipt-bool-int": "native output receipt scope or parent observation is invalid",
        "guard-schema-bool": "native output original guard or one-use marker changed",
        "result-pending-int": "native output result scope is not a terminal verified outcome",
        "independent-claim": "native output receipt scope or parent observation is invalid",
        "log-oversize": "native output receipt scope or parent observation is invalid",
        "groups-129": "native output directories are incomplete or unknown",
    }[change]
    before = _tree(sample.state)
    with pytest.raises(storage.SourceActivationStorageHeld) as held:
        _native_expected(item)
    assert type(held.value) is storage.SourceActivationStorageHeld
    assert str(held.value).startswith("Source-update storage held: " + refusal + ". ")
    assert _tree(sample.state) == before
    # Re-review the CURRENT namespace so a stale-review mismatch cannot stand
    # in for the real closed native-output validator.
    review = _review(sample)
    reached = []

    def delete(owner):
        reached.append(owner.path)
        pytest.fail("Invalid native-output group reached irreversible deletion")

    monkeypatch.setattr(files.RetainedFile, "delete", delete)
    with pytest.raises(storage.SourceActivationStorageHeld):
        storage.delete_source_update_backup(sample.root, sample.state,
            item.plan["activation_id"], review["review_sha256"], accepted=True, permanent=True)
    assert reached == [] and _tree(sample.state) == before
    assert (sample.root / "feature.py").read_bytes() == b"value=1\n"
    _protected_unchanged(sample)


def test_native_output_actual_reparse_log_is_held_before_delete(native_output, monkeypatch):
    item, sample = native_output, native_output.sample
    target = sample.fixture_root / "unrelated-output.txt"
    target.write_bytes(b"unrelated fixture data")
    original = target.read_bytes(), target.stat().st_ino
    item.log.rename(sample.fixture_root / "retained-original-native.log")
    try:
        item.log.symlink_to(target)
    except OSError as error:
        if os.name == "nt" and getattr(error, "winerror", None) == 1314:
            pytest.skip("Actual Windows symlink creation privilege unavailable")
        raise
    reached = []

    def delete(owner):
        reached.append(owner.path)
        pytest.fail("Redirected native-output log reached irreversible deletion")

    monkeypatch.setattr(files.RetainedFile, "delete", delete)
    with pytest.raises((storage.SourceActivationStorageHeld, files.ActivationFileError)):
        # A namespace reparse refusal during the fresh review is itself the
        # earlier real gate, never a fabricated cached review or authority.
        review = _review(sample)
        storage.delete_source_update_backup(sample.root, sample.state,
            item.plan["activation_id"], review["review_sha256"], accepted=True, permanent=True)
    assert reached == [] and item.log.is_symlink()
    assert (target.read_bytes(), target.stat().st_ino) == original
    _protected_unchanged(sample)


def _fixed_native_powershell_image():
    # The actual fixed system-directory API is transparent through the process
    # model; no synthetic process handle or environment hint chooses this path.
    from ctypes import wintypes as w
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetSystemDirectoryW.argtypes = (w.LPWSTR, w.UINT)
    kernel.GetSystemDirectoryW.restype = w.UINT
    text = ctypes.create_unicode_buffer(32768)
    length = kernel.GetSystemDirectoryW(text, len(text))
    assert 0 < length < len(text)
    return str(Path(text.value) / "WindowsPowerShell/v1.0/powershell.exe")


@pytest.fixture
def historical_handoff(native_output):
    """Known historical ACK storage DATA, never a live/retired-process proof."""
    item = native_output
    lock = item.operation / "resume-owner.lock"
    files.write_new(lock, b"\x00")
    top = item.operation / "handoffs"
    assert startup_recovery.private_directory(top, create=True)
    nonce = "9" * 32
    group = top / nonce
    assert startup_recovery.private_directory(group, create=True)
    request_path = item.operation / "requests" / (item.request["request_sha256"] + ".json")
    request_raw = request_path.read_bytes()
    assert _sha(request_raw) == item.request["request_sha256"]
    assert json.loads(request_raw)["accepted"] is True
    ready = {"schema": "angerona.source-activation-resume-ready/v1",
        "handoff_nonce": nonce, "activation_id": item.plan["activation_id"],
        "plan_sha256": item.plan["plan_sha256"], "request_sha256": item.request["request_sha256"],
        "gate_pid": 11001, "gate_birth": "133000000000011001",
        "cmd_pid": 11002, "cmd_birth": "133000000000011002",
        "resume_pid": 11003, "resume_birth": "133000000000011003",
        "resume_image": _fixed_native_powershell_image()}
    ready_path = group / "ready.json"
    files.write_new(ready_path, _encoded(ready))
    return SimpleNamespace(item=item, sample=item.sample, lock=lock, top=top,
        nonce=nonce, group=group, ready=ready, ready_path=ready_path,
        request_path=request_path, request_raw=request_raw)


def _handoff_expected(fixture):
    item = fixture.item
    selected_files, directories = storage._scope_tree(item.operation)
    return storage._handoff_expectations(item.sample.root, item.sample.state,
        item.operation, item.plan_value, item.plan_raw, selected_files, directories)


def _add_public_read_ace(path):
    # Actual ACL mutation of this test's private inert leaf only. The validator
    # must reject the extra principal; it must not rewrite it back to private.
    from ctypes import wintypes as w
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
        w.LPCWSTR, w.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(w.DWORD))
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = w.BOOL
    advapi.SetFileSecurityW.argtypes = (w.LPCWSTR, w.DWORD, ctypes.c_void_p)
    advapi.SetFileSecurityW.restype = w.BOOL
    kernel.LocalFree.argtypes, kernel.LocalFree.restype = (ctypes.c_void_p,), ctypes.c_void_p
    descriptor = ctypes.c_void_p()
    assert advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;FR;;;WD)", 1,
        ctypes.byref(descriptor), None), ctypes.get_last_error()
    try:
        assert advapi.SetFileSecurityW(str(path), 4, descriptor), ctypes.get_last_error()
    finally:
        assert kernel.LocalFree(descriptor) is None
    assert not startup_recovery.private_repair_file(path)


def test_known_historical_handoff_exports_and_deletes_only_reviewed_payload(historical_handoff):
    fixture, item = historical_handoff, historical_handoff.item
    sample = fixture.sample
    expected = _handoff_expected(fixture)
    ready_name = "handoffs/" + fixture.nonce + "/ready.json"
    request_name = "requests/" + item.request["request_sha256"] + ".json"
    assert set(expected) == {"resume-owner.lock", ready_name, request_name}
    before = _tree(item.operation)
    assert all(before[name][0] and _sha(before[name][0]) == digest
               for name, digest in expected.items())
    review = _review(sample)
    assert _selected(review, item.plan["activation_id"])["export_allowed"]
    result = storage.export_source_update_backup(sample.root, sample.state,
        item.plan["activation_id"], review["review_sha256"], accepted=True)
    assert result["status"] == "exported" and _tree(item.operation) == before
    with zipfile.ZipFile(result["path"]) as archive:
        manifest = json.loads(archive.read("verified-manifest.json"))
        for name, digest in expected.items():
            member = "activation/" + name
            assert archive.read(member) == before[name][0]
            assert manifest["files"][member]["sha256"] == digest
    review = _review(sample)
    result = storage.delete_source_update_backup(sample.root, sample.state,
        item.plan["activation_id"], review["review_sha256"], accepted=True, permanent=True)
    assert result["status"] == "deleted" and not fixture.top.exists()
    assert not (item.operation / "requests").exists()
    assert (fixture.lock.read_bytes(), fixture.lock.stat().st_dev, fixture.lock.stat().st_ino) == before["resume-owner.lock"]
    assert _selected(_review(sample), item.plan["activation_id"])["status"] == "retired-payload"
    assert (sample.root / "feature.py").read_bytes() == b"value=1\n"
    _protected_unchanged(sample)


@pytest.mark.parametrize("change", [
    "unknown-object", "ready-extra", "pid-bool", "relative-image", "nonce", "plan",
    "request-missing", "request-bytes", "request-state", "accepted-int",
    "ready-unprivate", "lock-unprivate", "missing-lock", "lock-value",
    "lock-oversize", "ready-oversize", "groups-33",
])
def test_unknown_historical_handoff_is_preserved_before_irreversible_delete(
        historical_handoff, monkeypatch, change):
    fixture, item = historical_handoff, historical_handoff.item
    sample, ready = fixture.sample, dict(fixture.ready)
    if change == "unknown-object":
        files.write_new(fixture.group / "unknown-private.json", b"{}")
    elif change == "ready-extra":
        ready["unapproved"] = True
    elif change == "pid-bool":
        ready["gate_pid"] = True
    elif change == "relative-image":
        ready["resume_image"] = "WindowsPowerShell/v1.0/powershell.exe"
    elif change == "nonce":
        ready["handoff_nonce"] = "0" * 32
    elif change == "plan":
        ready["plan_sha256"] = "0" * 64
    elif change == "request-missing":
        fixture.request_path.rename(sample.fixture_root / "retained-approved-request.json")
    elif change == "request-bytes":
        request = json.loads(fixture.request_raw)
        _rewrite_json(fixture.request_path, dict(request, accepted=False))
    elif change in {"request-state", "accepted-int"}:
        request = json.loads(fixture.request_raw)
        if change == "request-state":
            request["state_root"] = str(sample.fixture_root / "unapproved-profile")
        else:
            request["accepted"] = 1
        raw = _encoded(request)
        ready["request_sha256"] = _sha(raw)
        forged = fixture.request_path.parent / (ready["request_sha256"] + ".json")
        assert forged != fixture.request_path
        files.write_new(forged, raw)
    elif change == "ready-unprivate":
        _add_public_read_ace(fixture.ready_path)
    elif change == "lock-unprivate":
        _add_public_read_ace(fixture.lock)
    elif change == "missing-lock":
        fixture.lock.rename(sample.fixture_root / "retained-resume-owner.lock")
    elif change == "lock-value":
        with fixture.lock.open("r+b") as stream:
            stream.write(b"\x01")
    elif change == "lock-oversize":
        with fixture.lock.open("r+b") as stream:
            stream.write(b"\x00\x00")
    elif change == "ready-oversize":
        with fixture.ready_path.open("r+b") as stream:
            stream.write(b" " * 8193)
            stream.truncate()
    else:
        for number in range(32):
            nonce = format(number, "032x")
            if nonce == fixture.nonce:
                continue
            group = fixture.top / nonce
            assert startup_recovery.private_directory(group, create=True)
            files.write_new(group / "ready.json", _encoded(ready))
        # The original plus32 bounded extras exceeds the exact32-group limit.
    if change not in {"ready-unprivate", "ready-oversize"}:
        _rewrite_json(fixture.ready_path, ready)
    expected_error = {
        "unknown-object": "unknown recovery handoff must be preserved",
        "ready-extra": "recovery handoff ready metadata is outside its closed profile",
        "pid-bool": "recovery handoff ready metadata is outside its closed profile",
        "relative-image": "recovery handoff ready metadata is outside its closed profile",
        "nonce": "recovery handoff ready metadata is outside its closed profile",
        "plan": "recovery handoff ready metadata is outside its closed profile",
        "request-missing": "recovery handoff approved request evidence is absent",
        "request-bytes": "recovery handoff request scope or original bytes changed",
        "request-state": "recovery handoff request scope or original bytes changed",
        "accepted-int": "recovery handoff request scope or original bytes changed",
        "ready-unprivate": "native output evidence is not private",
        "lock-unprivate": "recovery owner lock is not private",
        "missing-lock": "recovery handoff directories or owner lock are incomplete",
        "lock-value": "recovery owner lock has an unknown value",
        "lock-oversize": "Source update file exceeds its byte bound",
        "ready-oversize": "Source update file exceeds its byte bound",
        "groups-33": "recovery handoff directories or owner lock are incomplete",
    }[change]
    before = _tree(sample.state)
    with pytest.raises((storage.SourceActivationStorageHeld, files.ActivationFileError)) as held:
        _handoff_expected(fixture)
    if change in {"lock-oversize", "ready-oversize"}:
        assert type(held.value) is files.ActivationFileError
        assert str(held.value) == expected_error
    else:
        assert type(held.value) is storage.SourceActivationStorageHeld
        assert str(held.value).startswith("Source-update storage held: " + expected_error + ". ")
    assert _tree(sample.state) == before
    reached = []

    def delete(owner):
        reached.append(owner.path)
        pytest.fail("Unknown historical handoff reached irreversible deletion")

    monkeypatch.setattr(files.RetainedFile, "delete", delete)
    # Current review only: never use a stale token as the intended refusal.
    with pytest.raises((storage.SourceActivationStorageHeld, files.ActivationFileError)):
        review = _review(sample)
        storage.delete_source_update_backup(sample.root, sample.state,
            item.plan["activation_id"], review["review_sha256"], accepted=True, permanent=True)
    assert reached == [] and _tree(sample.state) == before
    assert (sample.root / "feature.py").read_bytes() == b"value=1\n"
    _protected_unchanged(sample)
