import json

import pytest

from angerona.core.evidence_store import HuntPredicate, HuntQuery
from angerona.core.hunt_workspace import (
    HuntResultReference, HuntWorkspace, NotebookEntry,
)


def _entry(**overrides):
    value = {
        "entry_id": "entry-001",
        "hunt_id": "hunt-001",
        "kind": "query",
        "author": "analyst-001",
        "created_at": 100.0,
        "text": "Find matching process evidence",
        "query": HuntQuery((
            HuntPredicate("module", "eq", "Telemetry Scanner"),
        ), limit=25),
        "evidence_ids": (),
    }
    value.update(overrides)
    return NotebookEntry(**value)


def _result(**overrides):
    value = {
        "result_id": "result-001",
        "hunt_id": "hunt-001",
        "artifact_id": "process.snapshot",
        "device_token": "a" * 64,
        "evidence_id": "evidence-001",
        "sha256": "b" * 64,
        "size_bytes": 500,
        "privacy_class": "sensitive",
        "observed_at": 101.0,
        "provenance": "signed fleet collection receipt",
    }
    value.update(overrides)
    return HuntResultReference(**value)


def test_workspace_is_typed_non_executable_and_optimistically_versioned(tmp_path):
    workspace = HuntWorkspace(tmp_path / "workspace.json", b"k" * 32)
    assert workspace.append_entry(_entry(), expected_revision=0) == 1
    with pytest.raises(ValueError, match="revision conflict"):
        workspace.add_result(_result(), expected_revision=0)
    assert workspace.add_result(_result(), expected_revision=1) == 2
    snapshot = workspace.snapshot("hunt-001")
    assert workspace.verify_snapshot(snapshot)
    assert snapshot.entries[0].query.predicates[0].field == "module"

    with pytest.raises(ValueError, match="only query"):
        _entry(kind="note")
    with pytest.raises(ValueError, match="invalid hunt result digest"):
        _result(sha256="not-a-digest")


def test_workspace_persists_and_tampering_fails_closed(tmp_path):
    path = tmp_path / "workspace.json"
    HuntWorkspace(path, b"k" * 32).append_entry(_entry(), expected_revision=0)
    restored = HuntWorkspace(path, b"k" * 32)
    assert restored.snapshot("hunt-001").revision == 1

    raw = path.read_text(encoding="utf-8")
    path.write_text(raw.replace("Find matching", "Hide matching"), encoding="utf-8")
    with pytest.raises(ValueError, match="authentication"):
        HuntWorkspace(path, b"k" * 32)


def test_sanitized_export_redacts_and_excludes_restricted_results(tmp_path):
    workspace = HuntWorkspace(tmp_path / "workspace.json", b"k" * 32)
    note = NotebookEntry(
        "entry-002", "hunt-001", "note", "analyst@example.com", 100,
        r"password=secret C:\Users\SampleUser\private.txt", None, (),
    )
    workspace.append_entry(note, expected_revision=0)
    workspace.add_result(_result(), expected_revision=1)
    workspace.add_result(_result(
        result_id="result-002", evidence_id="evidence-002",
        artifact_id="security.events", privacy_class="restricted",
    ), expected_revision=2)

    exported = json.loads(workspace.export_sanitized("hunt-001"))
    encoded = json.dumps(exported)
    assert exported["raw_artifacts_included"] is False
    assert len(exported["result_references"]) == 1
    assert "SampleUser" not in encoded
    assert "secret" not in encoded.lower()
    assert "@" not in exported["entries"][0]["author"]


def test_result_artifact_budget_and_device_privacy_token_are_enforced():
    with pytest.raises(ValueError, match="privacy token"):
        _result(device_token="device-001")
    with pytest.raises(ValueError, match="artifact byte budget"):
        _result(size_bytes=6 * 1024 * 1024)
    with pytest.raises(ValueError, match="timestamp"):
        _result(observed_at=float("nan"))


def test_notebook_copies_mutable_query_values_before_persistence():
    values = ["Telemetry Scanner"]
    entry = _entry(query=HuntQuery((
        HuntPredicate("module", "in", values),
    )))
    values.append("Defense Monitor")
    assert entry.query.predicates[0].value == ["Telemetry Scanner"]
