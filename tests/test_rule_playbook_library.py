from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from angerona.core import rule_playbook_library as library
from angerona.core.github_tool_catalog import GitHubToolCatalog


@pytest.fixture
def service(tmp_path):
    return library.RulePlaybookLibrary(tmp_path / "rules", catalog=GitHubToolCatalog(tmp_path / "sources"))


def playbook():
    return json.loads(library._EXAMPLES["examples/request-containment.angerona-playbook.json"])


def add(service, document=None):
    return service.create_draft("soar", json.dumps(document or playbook()), name="My containment")


def test_bundled_discovery_batch_preserves_local_edits(service):
    listing = service.discover("builtin:angerona")
    assert len(listing["entries"]) == 3
    paths = [row["path"] for row in listing["entries"]]
    installed = service.install_batch(listing["source_id"], paths)
    row = next(row for row in installed if row["kind"] == "soar")
    updated = dict(playbook(), description="My preserved customization")
    service.save_draft(row["id"], json.dumps(updated))
    service.install_batch(listing["source_id"], paths)
    assert "My preserved customization" in service.read(row["id"])["text"]
    assert service.read(row["id"])["active_sha256"] == ""
    assert service.credits()


def test_batch_refuses_unknown_member_before_any_commit(service):
    with pytest.raises(ValueError):
        service.install_batch("builtin:angerona", ["examples/angerona-sample.yar", "absent.yar"])
    assert service.items() == []


def test_local_create_validate_activate_edit_disable_rollback(service):
    first = add(service)
    checked = service.sample_test(first["id"])
    assert checked["sample_passed"] is True
    assert checked["actions_executed"] is False
    active = service.activate(first["id"])
    original = active["active_sha256"]
    assert service.active_data("soar")[0]["active_sha256"] == original
    changed = playbook()
    changed["description"] = "A new local revision"
    service.save_draft(first["id"], json.dumps(changed))
    assert service.read(first["id"])["active_sha256"] == original
    assert "+" in service.diff(first["id"])
    second = service.activate(first["id"])
    assert second["active_sha256"] != original
    assert service.rollback(first["id"])["active_sha256"] == original
    service.disable(first["id"])
    assert service.active_data("soar") == []


@pytest.mark.parametrize("patch", [
    {"command": "arbitrary shell"}, {"target_pid": 123}, {"url": "https://example.org"},
    {"schema": "shuffle"}, {"id": "../escape"}, {"name": "<html>"},
    {"actions": [{"type": "exec", "command": "cmd"}]},
    {"actions": [{"type": "request_containment", "pid": 123}]},
    {"actions": [{"type": "notify", "message": "x", "elevate": True}]},
    {"trigger": {"minimum_severity": "LOW", "modules": []}},
    {"trigger": {"minimum_severity": "HIGH", "modules": ["X", "X"]}},
])
def test_foreign_or_executable_playbooks_refused(service, patch):
    document = dict(playbook(), **patch)
    row = add(service, document)
    assert service.validate(row["id"])["state"] == "invalid"
    with pytest.raises(ValueError):
        service.activate(row["id"])
    assert service.active_data("soar") == []


def test_duplicate_json_keys_refused():
    with pytest.raises(ValueError, match="Duplicate"):
        library.validate_playbook(b'{"schema":"angerona-playbook/v1","schema":"other"}')


@pytest.mark.parametrize("url", [
    "http://github.com/a/b", "https://github.com.evil/a/b", "https://u:p@github.com/a/b",
    "file:///c:/private", "https://127.0.0.1/", "https://github.com/a/b?token=secret",
    "https://github.com/a/b/blob/main/file.yar", "https://github.com/a/b/tree/" + "a" * 40 + "/../escape",
])
def test_source_url_never_fetches_unsupported_address(url):
    with pytest.raises(ValueError):
        library._source_url(url)


def test_pinned_member_url_and_repository_url():
    assert library._source_url("https://github.com/Owner/Repo") == ("https://github.com/owner/repo", "HEAD", "")
    assert library._source_url("https://github.com/a/b/blob/" + "a" * 40 + "/rules/a.yar") == (
        "https://github.com/a/b", "a" * 40, "rules/a.yar")


def test_active_content_corruption_is_not_accepted(service):
    row = add(service)
    active = service.activate(row["id"])
    (service.root / (active["active_sha256"] + ".txt")).write_bytes(b"changed")
    with pytest.raises(ValueError, match="consistency"):
        service.active_data("soar")


def test_native_yara_probe_must_retire_before_activation(service):
    observed = []
    def probe(root, sources, samples, operation):
        observed.append((root, sources, samples))
        return {"state": "completed", "worker_retired": False, "matches": []}
    service._probe = probe
    row = service.create_draft("yara", "rule harmless { condition: true }", name="Harmless")
    with pytest.raises(ValueError, match="retirement"):
        service.activate(row["id"])
    assert len(observed) == 1
    assert service.active_data("yara") == []


def test_draft_changed_during_native_probe_cannot_be_activated(service):
    row = service.create_draft("yara", "rule first { condition: true }", name="Changing")
    def probe(root, sources, samples, operation):
        service.save_draft(row["id"], "rule second { condition: false }")
        return {"state": "completed", "worker_retired": True, "matches": []}
    service._probe = probe
    with pytest.raises(ValueError, match="changed"):
        service.activate(row["id"])
    assert service.active_data("yara") == []


def test_successful_native_probe_receipt_bound_to_exact_draft(service):
    service._probe = lambda *args: {"state": "completed", "worker_retired": True, "matches": []}
    row = service.create_draft("yara", "rule harmless { condition: false }", name="Harmless")
    active = service.activate(row["id"])
    assert active["active_sha256"] == row["draft_sha256"]
    service.save_draft(row["id"], "invalid native rules")
    assert service.active_data("yara")[0]["text"] == "rule harmless { condition: false }"


def test_caller_deadline_is_not_renewed_between_download_phases(monkeypatch):
    outer = library.ImportOperation()
    outer.deadline = 123.0
    monkeypatch.setattr(library.time, "monotonic", lambda: 122.0)
    bridge = library._LibraryOperation(outer)
    bridge.next_phase()
    assert bridge.deadline == 123.0
    outer.cancelled.set()
    with pytest.raises(ValueError):
        bridge.check()


def test_plain_active_trigger_selection_never_promotes_advisory():
    document = playbook()
    event = SimpleNamespace(module="Detector", severity=4, details={"disposition": "active", "response_authorized": True})
    assert library.playbook_matches(document, event)
    for details in ({}, {"disposition": "practice", "response_authorized": True},
                    {"disposition": "active", "response_authorized": 1},
                    {"disposition": "observation", "response_authorized": False}):
        event.details = details
        assert not library.playbook_matches(document, event)
