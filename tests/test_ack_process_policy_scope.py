"""PW18 private policy fixtures; no host keys, live alerts or trust-store edits."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os

import pytest

from angerona.core import alert_ack as ack, process_allowlist as policy
from angerona.core.eventbus import BusAuthority, Event, Severity

KEY = bytes(range(32))


def _signed(event):
    return dataclasses.replace(event, hmac_sig=BusAuthority(KEY).sign(event))


@pytest.fixture
def ack_store(tmp_path, monkeypatch):
    path = tmp_path / "shared_logs" / "alert_acks.json"
    monkeypatch.setattr(ack, "_store_path", lambda: path)
    monkeypatch.setattr(ack, "_key_for_store", lambda _path: KEY)
    return path


def test_ack_binds_exact_signed_record_and_changed_generation_evidence_stays_active(ack_store):
    event = _signed(Event("scanner", "Suspicious process 100 nonce abc12345", Severity.HIGH,
                          details={"pid": 100, "process_create_time": 100.5, "image_sha256": "a" * 64}))
    ack.ack(event, "reviewed exact fixture")
    assert ack.is_acked(event)
    for changed in (dataclasses.replace(event, ts=event.ts + 1),
                    dataclasses.replace(event, message="Suspicious process 200 nonce abc12346"),
                    dataclasses.replace(event, details={**event.details, "process_create_time": 101.5}),
                    dataclasses.replace(event, details={**event.details, "image_sha256": "b" * 64})):
        assert not ack.is_acked(_signed(changed))
    ack.unack(event, "review reopened")
    assert not ack.is_acked(event)
    assert [row["action"] for row in ack.load()[ack.signature(event)]["history"]] == ["ack", "unack"]


def test_ack_receipt_expires_and_rejects_duration_outside_bound(ack_store, monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(ack.time, "time", lambda: now[0])
    event = _signed(Event("scanner", "inert", Severity.HIGH, ts=now[0]))
    ack.ack(event, ttl_s=60)
    assert ack.is_acked(event)
    now[0] += 61
    assert not ack.is_acked(event)
    for ttl in (0, True, float("nan"), ack.MAX_TTL_S + 1):
        with pytest.raises(ValueError, match="duration"):
            ack.ack(event, ttl_s=ttl)


def test_unsigned_or_missing_key_ack_never_creates_authority(ack_store, monkeypatch):
    event = Event("scanner", "unsigned", Severity.HIGH)
    with pytest.raises(ValueError, match="authenticated"):
        ack.ack(event)
    monkeypatch.setattr(ack, "_key_for_store", lambda _path: None)
    with pytest.raises(ValueError, match="authenticated"):
        ack.ack(_signed(event))
    assert not ack_store.exists()


def test_legacy_class_rows_remain_visible_but_cannot_be_promoted_during_migration(ack_store):
    event = _signed(Event("scanner", "inert", Severity.HIGH))
    ack_store.parent.mkdir()
    forged = {ack.signature(event): {"acked": True, "module": "scanner", "history": [],
               "scope": "exact-authenticated-record/v1", "acked_at": event.ts, "expires_at": event.ts + 3600}}
    original = json.dumps(forged).encode()
    ack_store.write_bytes(original)
    assert not ack.is_acked(event)
    assert ack.acked_records()[0]["review_required"]
    other = _signed(Event("other", "explicitly reviewed", Severity.HIGH))
    ack.ack(other)
    assert ack.is_acked(other) and not ack.is_acked(event)
    assert ack_store.with_name(ack_store.name + ".legacy-" + hashlib.sha256(original).hexdigest() + ".json").read_bytes() == original


def test_tampered_ack_document_is_not_cached_or_overwritten(ack_store):
    event = _signed(Event("scanner", "inert", Severity.HIGH))
    ack.ack(event)
    assert ack.is_acked(event)
    before_stat = ack_store.stat()
    doc = json.loads(ack_store.read_text())
    doc["records"][ack.signature(event)]["reason"] = "forged reason"
    encoded = json.dumps(doc).encode()
    ack_store.write_bytes(encoded)
    os.utime(ack_store, ns=(before_stat.st_atime_ns, before_stat.st_mtime_ns))
    assert not ack.is_acked(event)
    with pytest.raises(ValueError, match="integrity"):
        ack.unack(event)
    assert ack_store.read_bytes() == encoded


def test_ack_self_test_never_reads_or_swaps_live_store(monkeypatch):
    monkeypatch.setattr(ack, "_store_path", lambda: pytest.fail("live store read"))
    monkeypatch.setattr(ack, "_key_for_store", lambda *_: pytest.fail("live key read"))
    assert ack.self_test()[0]


@pytest.fixture
def process_store(tmp_path):
    (tmp_path / "bus.key").write_text(KEY.hex(), encoding="ascii")
    policy._CACHE.clear()
    return tmp_path


def test_only_authenticated_explicit_digest_approval_enters_active_policy(process_store):
    executable = process_store / "inert.exe"
    executable.write_bytes(b"inert executable bytes, not a PE")
    approved = policy.add(path=str(executable), data_dir=process_store)
    assert policy.is_allowed(executable.name, str(executable), process_store)
    policy.add(name="pathless.exe", data_dir=process_store)
    assert not policy.is_allowed("pathless.exe", data_dir=process_store)
    assert len(policy.entries(process_store)) == 2
    assert len(policy.policy_snapshot(process_store)) == 1
    assert json.loads(policy.policy_path(process_store).read_text())["version"] == 3
    executable.write_bytes(b"changed executable bytes")
    assert not policy.is_allowed(executable.name, str(executable), process_store)
    assert approved["sha256"] != policy.executable_sha256(executable)


def test_active_event_uses_authenticated_producer_digest_and_generation_without_disk_hash(process_store, monkeypatch):
    executable = process_store / "inert.exe"
    executable.write_bytes(b"inert fixture")
    approved = policy.add(path=str(executable), data_dir=process_store)
    snapshot = policy.policy_snapshot(process_store)
    event = _signed(Event("scanner", "inert", Severity.HIGH,
                          details={"name": executable.name, "exe": str(executable), "pid": 42,
                                   "process_create_time": 123.5, "image_sha256": approved["sha256"]}))
    monkeypatch.setattr(policy, "executable_sha256", lambda *_: pytest.fail("per-event file hashing"))
    assert policy.is_event_allowed(event, policy=snapshot)
    for fields in ({"image_sha256": ""}, {"image_sha256": "b" * 64},
                   {"process_create_time": None}, {"pid": 0}):
        assert not policy.is_event_allowed(_signed(dataclasses.replace(event, details={**event.details, **fields})), policy=snapshot)
    assert not policy.is_event_allowed(dataclasses.replace(event, message="tampered"), policy=snapshot)
    assert not policy.is_event_allowed(event, policy=tuple(snapshot))  # no batch authentication context


def test_unsigned_legacy_process_rows_preserved_until_specific_reapproval(process_store):
    executable = process_store / "inert.exe"
    executable.write_bytes(b"inert fixture")
    digest = policy.executable_sha256(executable)
    path = policy.policy_path(process_store)
    path.parent.mkdir()
    row = {"id": "a" * 32, "name": executable.name, "path": str(executable), "sha256": digest,
           "publisher": "", "source": "manual", "added_at": 1.0}
    original = json.dumps({"version": 2, "updated_at": 1.0, "entries": [row]}).encode()
    path.write_bytes(original)
    assert policy.entries(process_store)[0]["review_required"]
    assert not policy.is_allowed(executable.name, str(executable), process_store)
    policy.add(path=str(executable), data_dir=process_store)
    assert policy.is_allowed(executable.name, str(executable), process_store)
    archive = path.with_name(path.name + ".legacy-" + hashlib.sha256(original).hexdigest() + ".json")
    assert archive.read_bytes() == original


def test_bad_process_policy_hmac_cannot_expand_or_overwrite_authority(process_store):
    executable = process_store / "inert.exe"
    executable.write_bytes(b"inert fixture")
    row = policy.add(path=str(executable), data_dir=process_store)
    assert policy.is_allowed(executable.name, str(executable), process_store)
    path = policy.policy_path(process_store)
    metadata = path.stat()
    doc = json.loads(path.read_text())
    doc["entries"][0]["publisher"] = "forged publisher"
    forged = json.dumps(doc).encode()
    path.write_bytes(forged)
    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    assert not policy.is_allowed(executable.name, str(executable), process_store)
    with pytest.raises(ValueError, match="integrity"):
        policy.remove(row["id"], process_store)
    assert path.read_bytes() == forged


def test_missing_process_signing_key_is_not_created_by_policy_add(tmp_path):
    executable = tmp_path / "inert.exe"
    executable.write_bytes(b"inert fixture")
    with pytest.raises(ValueError, match="signing key"):
        policy.add(path=str(executable), data_dir=tmp_path)
    assert not (tmp_path / "bus.key").exists()
    assert not policy.policy_path(tmp_path).exists()


@pytest.mark.parametrize("module_name,helper", [
    ("alert_ack", "signature"), ("alert_ack", "acked_signatures"),
    ("alert_ack", "_load_at"), ("alert_ack", "_active"),
    ("process_allowlist", "is_event_allowed"), ("process_allowlist", "_policy_authentic"),
    ("process_allowlist", "_policy_key"),
])
def test_policy_filter_authentication_helpers_have_live_integrity_coverage(monkeypatch, module_name, helper):
    from angerona.modules.self_integrity import SelfIntegrityEngine
    engine = SelfIntegrityEngine()
    target = "angerona.core." + module_name + ":" + helper
    assert target in engine._targets
    assert engine.arm() == engine.expected_count
    module = ack if module_name == "alert_ack" else policy
    monkeypatch.setattr(module, helper, lambda *_a, **_k: True)
    assert any(target in finding for finding in engine.check())


def test_reapproving_one_legacy_process_preserves_all_other_visible_review_rows(process_store, monkeypatch):
    selected = process_store / "selected.exe"
    other = process_store / "other.exe"
    selected.write_bytes(b"selected inert fixture")
    other.write_bytes(b"other inert fixture")
    selected_digest = policy.executable_sha256(selected)
    other_digest = policy.executable_sha256(other)
    rows = [
        {"id": "a" * 32, "name": selected.name, "path": str(selected), "sha256": selected_digest,
         "publisher": "Selected legacy publisher", "source": "manual", "added_at": 1.0},
        {"id": "b" * 32, "name": other.name, "path": str(other), "sha256": other_digest,
         "publisher": "Other legacy publisher", "source": "manual", "added_at": 2.0},
        {"id": "c" * 32, "name": "pathless.exe", "path": "", "sha256": "",
         "publisher": "", "source": "manual", "added_at": 3.0},
    ]
    path = policy.policy_path(process_store)
    path.parent.mkdir()
    original = json.dumps({"version": 2, "updated_at": 3.0, "entries": rows}).encode()
    path.write_bytes(original)
    assert len(policy.entries(process_store)) == 3
    assert policy.policy_snapshot(process_store) == ()
    hashed = []
    real_hash = policy.executable_sha256

    def selected_only(candidate):
        hashed.append(str(candidate))
        assert str(candidate) == str(selected), "unselected executable was silently reapproved"
        return real_hash(candidate)

    monkeypatch.setattr(policy, "executable_sha256", selected_only)
    approved = policy.add(path=str(selected), data_dir=process_store)
    visible = {row["id"]: row for row in policy.entries(process_store)}
    assert set(visible) == {"a" * 32, "b" * 32, "c" * 32}
    assert approved["id"] == "a" * 32
    assert visible["a" * 32]["reviewed"] is True
    assert visible["a" * 32]["review_required"] is False
    for identifier in ("b" * 32, "c" * 32):
        assert visible[identifier]["reviewed"] is False
        assert visible[identifier]["review_required"] is True
    assert visible["b" * 32]["path"] == str(other)
    assert visible["b" * 32]["sha256"] == other_digest
    assert visible["b" * 32]["publisher"] == "Other legacy publisher"
    assert len(policy.policy_snapshot(process_store)) == 1
    assert hashed == [str(selected)]
    archive = path.with_name(path.name + ".legacy-" + hashlib.sha256(original).hexdigest() + ".json")
    assert archive.read_bytes() == original
