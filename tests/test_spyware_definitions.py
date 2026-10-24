"""Offline inert packs: durable local activation is separate from research."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path

import pytest

from angerona.core import spyware_definitions as definitions
from angerona.core.engine_transport import create_private_file, private_directory

NOW = 1800000000.0


def document(version="1.0", *, rows=None):
    return {"schema": definitions.SCHEMA, "version": version,
            "published_at": NOW - 60, "expires_at": NOW + 3600,
            "indicators": rows or [{"kind": "domain", "value": "inert.invalid"}]}


def write_pack(tmp_path, version="1.0", *, rows=None):
    path = tmp_path / "import.json"
    path.write_bytes(json.dumps(document(version, rows=rows)).encode())
    return path


def installation(tmp_path):
    root = private_directory(tmp_path / "installation")
    with os.fdopen(create_private_file(root / "bus.key"), "wb") as stream:
        stream.write((b"d" * 32).hex().encode())
    return root


def activate(store, path):
    snapshot = store.stage(path)
    return store.apply(snapshot["staged"]["review_identity"])


def test_canonical_identity_is_separate_from_source_bytes_and_publisher_authority():
    body = document(rows=[{"kind": "sha256", "value": "A" * 64},
                          {"kind": "domain", "value": "INERT[.]INVALID"}])
    first = definitions.parse_definition_bundle(json.dumps(body).encode(), now=NOW)
    body["indicators"].reverse()
    second = definitions.parse_definition_bundle(json.dumps(body, indent=2).encode(), now=NOW)
    assert first.sha256 == second.sha256 and first.source_sha256 != second.source_sha256
    assert first.indicators == (("domain", "inert.invalid"), ("sha256", "a" * 64))
    assert first.summary()["publisher_verified"] is False


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(schema="unknown"), lambda d: d.update(extra="code"),
    lambda d: d.update(version=True), lambda d: d.update(version="1."),
    lambda d: d.update(version="01"), lambda d: d.update(version="1000000000"),
    lambda d: d.update(version="1.2.3.4.5"), lambda d: d.update(published_at=True),
    lambda d: d.update(published_at=NOW + 1), lambda d: d.update(expires_at=NOW),
    lambda d: d.update(expires_at=NOW + 31 * 86400), lambda d: d.update(expires_at=float("inf")),
    lambda d: d.update(indicators=[]), lambda d: d.update(indicators={}),
    lambda d: d["indicators"].append(dict(d["indicators"][0])),
    lambda d: d["indicators"][0].update(response_authorized=True),
    lambda d: d["indicators"][0].update(kind="cve"),
    lambda d: d["indicators"][0].update(kind={}),
    lambda d: d["indicators"][0].update(value="*.inert.invalid"),
    lambda d: d["indicators"][0].update(value="https://inert.invalid/a"),
    lambda d: d["indicators"][0].update(kind="ip", value="192.0.2.0/24"),
    lambda d: d["indicators"][0].update(kind="sha256", value="a" * 63),
])
def test_untrusted_bundle_fields_types_patterns_and_time_are_refused(mutate):
    body = document()
    mutate(body)
    with pytest.raises(definitions.DefinitionError):
        definitions.parse_definition_bundle(json.dumps(body).encode(), now=NOW)


@pytest.mark.parametrize("raw", [
    b'{"schema":"one","schema":"two"}', b"[" * 100 + b"]" * 100,
    b"\xff", b"{}", b"x" * (definitions.MAX_BYTES + 1),
], ids=["duplicate", "deep", "non-utf8", "missing-fields", "oversized"])
def test_duplicate_deep_malformed_and_oversized_json_is_refused(raw):
    with pytest.raises(definitions.DefinitionError):
        definitions.parse_definition_bundle(raw, now=NOW)


def test_item_limit_refuses_whole_pack_without_truncation():
    body = document(rows=[{"kind": "domain", "value": f"h{i}.invalid"}
                          for i in range(definitions.MAX_ITEMS + 1)])
    with pytest.raises(definitions.DefinitionError, match="count"):
        definitions.parse_definition_bundle(json.dumps(body).encode(), now=NOW)


def test_activation_restart_rollback_and_highest_accepted_version(tmp_path):
    root = installation(tmp_path)
    store = definitions.DefinitionStore(root, clock=lambda: NOW)
    assert store.snapshot()["active"] is None and not store.path.exists()
    one = activate(store, write_pack(tmp_path))
    assert one["generation"] == 1 and one["active"]["version"] == "1.0"
    assert store.lookup("domain", "inert.invalid")["locally_activated"] is True
    assert not store.has_hashes()
    two = activate(store, write_pack(tmp_path, "2.0", rows=[{"kind": "sha256", "value": "a" * 64}]))
    assert two["active"]["version"] == "2.0" and two["previous"]["version"] == "1.0"
    assert store.has_hashes() and store.lookup("domain", "inert.invalid") is None
    reloaded = definitions.DefinitionStore(root, clock=lambda: NOW)
    assert reloaded.lookup("sha256", "a" * 64)["sha256"] == two["active"]["sha256"]
    before_key = (root / "bus.key").read_bytes()
    restored = reloaded.apply(reloaded.snapshot()["previous"]["review_identity"], action="rollback")
    assert restored["generation"] == 3 and restored["active"]["version"] == "1.0"
    assert restored["previous"]["version"] == "2.0" and restored["highest_version"] == "2.0"
    assert (root / "bus.key").read_bytes() == before_key
    assert reloaded.lookup("domain", "inert.invalid") and not reloaded.has_hashes()
    preview = reloaded.stage(write_pack(tmp_path, "2.0", rows=[{"kind": "domain", "value": "other.invalid"}]))
    before = reloaded.path.read_bytes()
    with pytest.raises(definitions.DefinitionError, match="highest accepted"):
        reloaded.apply(preview["staged"]["review_identity"])
    assert reloaded.path.read_bytes() == before


def test_stale_import_review_session_and_boolean_identity_never_activate(tmp_path):
    store = definitions.DefinitionStore(installation(tmp_path), clock=lambda: NOW)
    path = write_pack(tmp_path)
    first = store.stage(path)["staged"]["review_identity"]
    current = store.stage(path)["staged"]["review_identity"]
    assert first != current
    for bad in (first, {**current, "generation": False}, {**current, "staged_revision": True},
                {**current, "store_session": "0" * 32}, {**current, "candidate_sha256": "0" * 64}):
        with pytest.raises(definitions.DefinitionError, match="stale"):
            store.apply(bad)
    assert not store.path.exists() and store.snapshot()["active"] is None


def test_two_instances_cannot_overwrite_an_unobserved_committed_generation(tmp_path):
    root = installation(tmp_path)
    first = definitions.DefinitionStore(root, clock=lambda: NOW)
    second = definitions.DefinitionStore(root, clock=lambda: NOW)
    second_preview = second.stage(write_pack(tmp_path))["staged"]["review_identity"]
    activate(first, write_pack(tmp_path))
    before = first.path.read_bytes()
    with pytest.raises(definitions.DefinitionError, match="changed"):
        second.apply(second_preview)
    assert first.path.read_bytes() == before and second.snapshot()["active"] is None


@pytest.mark.parametrize("failure", ["replace", "key", "guard", "budget"])
def test_failed_prepublication_update_keeps_disk_and_prior_active(tmp_path, monkeypatch, failure):
    root = installation(tmp_path)
    store = definitions.DefinitionStore(root, clock=lambda: NOW)
    activate(store, write_pack(tmp_path))
    review = store.stage(write_pack(tmp_path, "2.0"))["staged"]["review_identity"]
    before, active = store.path.read_bytes(), store.lookup("domain", "inert.invalid")
    if failure == "replace":
        monkeypatch.setattr(definitions, "replace_with_retry", lambda *_: (_ for _ in ()).throw(PermissionError("inert")))
    elif failure == "key":
        (root / "bus.key").write_bytes((b"x" * 32).hex().encode())
    elif failure == "budget":
        monkeypatch.setattr(definitions, "MAX_STATE_BYTES", 1)

    @contextmanager
    def guard():
        if failure == "guard":
            raise definitions.DefinitionError("retired fixture generation")
        yield

    with pytest.raises((ValueError, OSError)):
        store.apply(review, commit_guard=guard)
    assert store.path.read_bytes() == before
    assert store.lookup("domain", "inert.invalid") == active
    assert not store.snapshot()["publication_uncertain"]


def test_postreplace_readback_failure_reports_uncertainty_without_rollback(tmp_path, monkeypatch):
    root = installation(tmp_path)
    store = definitions.DefinitionStore(root, clock=lambda: NOW)
    activate(store, write_pack(tmp_path))
    review = store.stage(write_pack(tmp_path, "2.0"))["staged"]["review_identity"]
    before = store.path.read_bytes()
    real_replace = definitions.replace_with_retry

    def replace_then_fail(source, target):
        real_replace(source, target)
        monkeypatch.setattr(store, "_read_state", lambda: (_ for _ in ()).throw(OSError("inert readback failure")))

    monkeypatch.setattr(definitions, "replace_with_retry", replace_then_fail)
    with pytest.raises(definitions.DefinitionError, match="uncertain"):
        store.apply(review)
    assert store.path.read_bytes() != before
    assert store.snapshot()["state"] == "unavailable"
    assert store.snapshot()["active"]["version"] == "1.0"  # retained advisory memory
    assert store.lookup("domain", "inert.invalid") is None
    with pytest.raises(definitions.DefinitionError, match="restart review"):
        store.apply(review)
    assert definitions.DefinitionStore(root, clock=lambda: NOW).snapshot()["active"]["version"] == "2.0"


def test_replace_publishes_then_raises_holds_old_matching_until_restart(tmp_path, monkeypatch):
    root = installation(tmp_path)
    store = definitions.DefinitionStore(root, clock=lambda: NOW)
    activate(store, write_pack(tmp_path, rows=[{"kind": "sha256", "value": "a" * 64},
                                             {"kind": "domain", "value": "old.invalid"}]))
    review = store.stage(write_pack(tmp_path, "2.0", rows=[
        {"kind": "domain", "value": "new.invalid"}]))["staged"]["review_identity"]
    key = (root / "bus.key").read_bytes()
    real_replace = definitions.replace_with_retry

    def replace_then_raise(source, target):
        real_replace(source, target)
        raise PermissionError("inert error after actual publication")

    monkeypatch.setattr(definitions, "replace_with_retry", replace_then_raise)
    with pytest.raises(definitions.DefinitionError, match="uncertain"):
        store.apply(review)
    disk = store.path.read_bytes()
    assert json.loads(disk)["active"]["bundle"]["version"] == "2.0"
    assert store.snapshot()["publication_uncertain"]
    assert store.lookup("domain", "old.invalid") is None
    assert store.lookup("domain", "new.invalid") is None
    assert not store.has_hashes()
    with pytest.raises(definitions.DefinitionError, match="restart review"):
        store.apply(review)
    assert store.path.read_bytes() == disk and (root / "bus.key").read_bytes() == key
    reloaded = definitions.DefinitionStore(root, clock=lambda: NOW)
    assert reloaded.lookup("domain", "new.invalid")
    assert reloaded.lookup("domain", "old.invalid") is None


@pytest.mark.parametrize("proof_error", [OSError, RuntimeError, Exception])
def test_failed_replace_with_unavailable_prior_state_proof_holds_matching(tmp_path, monkeypatch, proof_error):
    store = definitions.DefinitionStore(installation(tmp_path), clock=lambda: NOW)
    activate(store, write_pack(tmp_path))
    review = store.stage(write_pack(tmp_path, "2.0"))["staged"]["review_identity"]
    before = store.path.read_bytes()

    def fail_before_replace(*_):
        monkeypatch.setattr(store, "_read_state", lambda: (_ for _ in ()).throw(proof_error("unavailable")))
        raise PermissionError("inert prepublication failure")

    monkeypatch.setattr(definitions, "replace_with_retry", fail_before_replace)
    with pytest.raises(definitions.DefinitionError, match="uncertain"):
        store.apply(review)
    assert store.path.read_bytes() == before
    assert store.snapshot()["publication_uncertain"]
    assert store.lookup("domain", "inert.invalid") is None


def test_state_tampering_missing_and_malformed_keys_preserve_originals(tmp_path):
    root = installation(tmp_path)
    store = definitions.DefinitionStore(root, clock=lambda: NOW)
    activate(store, write_pack(tmp_path))
    raw = store.path.read_bytes().replace(b'"generation":1', b'"generation":2')
    store.path.write_bytes(raw)
    with pytest.raises(definitions.DefinitionError, match="authentication"):
        definitions.DefinitionStore(root, clock=lambda: NOW)
    assert store.path.read_bytes() == raw
    (root / "bus.key").unlink()
    with pytest.raises(OSError):
        definitions.DefinitionStore(root, clock=lambda: NOW)
    assert not (root / "bus.key").exists()
    (root / "bus.key").write_bytes(b"malformed")
    with pytest.raises((ValueError, RuntimeError)):
        definitions.DefinitionStore(root, clock=lambda: NOW)
    assert (root / "bus.key").read_bytes() == b"malformed" and store.path.read_bytes() == raw


def test_unsafe_import_paths_and_hardlinks_are_refused_before_activation(tmp_path):
    store = definitions.DefinitionStore(installation(tmp_path), clock=lambda: NOW)
    path = write_pack(tmp_path)
    alias = tmp_path / "hardlink.json"
    os.link(path, alias)
    for candidate in (alias, "relative.json", "//server/share/pack.json", "\\\\?\\UNC\\server\\pack.json"):
        with pytest.raises((ValueError, OSError)):
            store.stage(candidate)
    assert not store.path.exists()


def test_snapshot_and_matching_are_cached_without_disk_or_crypto(tmp_path, monkeypatch):
    store = definitions.DefinitionStore(installation(tmp_path), clock=lambda: NOW)
    activate(store, write_pack(tmp_path))
    monkeypatch.setattr(definitions, "read_definition_file", lambda *_: pytest.fail("cached read touched disk"))
    monkeypatch.setattr(definitions.hmac, "new", lambda *_: pytest.fail("cached read used crypto"))
    snapshot = store.snapshot()
    snapshot["active"]["counts"]["domain"] = 999
    assert store.snapshot()["active"]["counts"]["domain"] == 1
    assert store.lookup("domain", "inert.invalid") and not store.has_hashes()


def test_staged_preview_is_bounded_detached_and_expiry_does_not_rewrite_state(tmp_path):
    now = [NOW]
    store = definitions.DefinitionStore(installation(tmp_path), clock=lambda: now[0])
    path = write_pack(tmp_path, rows=[{"kind": "domain", "value": f"h{i}.invalid"} for i in range(30)])
    staged = store.stage(path)
    assert len(staged["staged"]["indicator_preview"]) == 25
    assert staged["staged"]["preview_truncated"] is True
    staged["staged"]["indicator_preview"][0]["value"] = "changed.invalid"
    assert store.snapshot()["staged"]["indicator_preview"][0]["value"] != "changed.invalid"
    store.apply(store.snapshot()["staged"]["review_identity"])
    raw = store.path.read_bytes()
    now[0] = NOW + 3600
    assert store.snapshot()["state"] == "expired" and store.lookup("domain", "h0.invalid") is None
    assert store.path.read_bytes() == raw
