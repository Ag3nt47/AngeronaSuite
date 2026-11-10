import json
import hashlib
import io
import zipfile
from types import SimpleNamespace

import pytest

from angerona.core import rule_playbook_library as library
from angerona.core.github_tool_catalog import GitHubToolCatalog
from angerona.core import github_tool_catalog


@pytest.fixture
def service(tmp_path):
    return library.RulePlaybookLibrary(tmp_path / "rules", catalog=GitHubToolCatalog(tmp_path / "sources"))


def document():
    return json.loads(library._EXAMPLES["examples/request-containment.angerona-playbook.json"])


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf"), 9.0, True, "10", 10**1000])
def test_cached_playbooks_are_not_selected_on_invalid_or_regressed_clock(bad):
    current = [10.0]
    cfg = SimpleNamespace(community_playbooks_enabled=True)
    data = document()
    provider = SimpleNamespace(active_data=lambda _kind: [{"text": json.dumps(data), "id": "fixture", "active_sha256": "a"*64}])
    runtime = library.CommunityPlaybookRuntime(cfg, library=provider, clock=lambda: current[0])
    event = SimpleNamespace(module="Detector", severity=4, details={"disposition": "active", "response_authorized": True})
    assert len(runtime.matching(event)) == 1
    current[0] = bad
    assert runtime.matching(event) == ()
    assert runtime.snapshot()["state"] == "community playbook clock unavailable"
    provider.active_data = lambda _kind: []  # policy was revoked while the clock was unavailable.
    current[0] = 11.0
    assert runtime.matching(event) == ()


def test_sample_test_rejects_intermediate_revision_even_if_old_sha_is_restored(service, monkeypatch):
    original = document()
    first = service.create_draft("soar", json.dumps(original), name="ABA fixture")
    real_read = service.read
    changed = dict(original, description="Different revision used for a sample")
    def swap_read(identity):
        service.save_draft(identity, json.dumps(changed))
        second = real_read(identity)
        service.save_draft(identity, json.dumps(original))
        assert real_read(identity)["draft_sha256"] == first["draft_sha256"]
        return second
    monkeypatch.setattr(service, "read", swap_read)
    with pytest.raises(ValueError, match="before sample testing"):
        service.sample_test(first["id"])
    assert real_read(first["id"])["validation"] == {}


@pytest.mark.parametrize("name", ["API Patch / Anti-Blinding Detector", "AI Triage (Ollama)", "Détection locale"])
def test_module_filters_allow_exact_real_module_names_without_interpretation(name):
    value = document()
    value["trigger"]["modules"] = [name]
    parsed = library.validate_playbook(json.dumps(value).encode())
    event = SimpleNamespace(module=name, severity=4, details={"disposition": "active", "response_authorized": True})
    assert library.playbook_matches(parsed, event)
    event.module += " different"
    assert not library.playbook_matches(parsed, event)


@pytest.mark.parametrize("name", ["", " leading", "trailing ", "hidden\x00name", "line\nbreak", "x"*161])
def test_module_filters_reject_ambiguous_or_unbounded_names(name):
    value = document()
    value["trigger"]["modules"] = [name]
    with pytest.raises(ValueError):
        library.validate_playbook(json.dumps(value).encode())


def accepted_probe(*_args):
    return {"state": "completed", "worker_retired": True, "matches": []}


def yara_draft(service, name, *, size=0):
    text = "rule " + name + " { condition: false }\n" + ("//" + "x"*size if size else "")
    return service.create_draft("yara", text, name=name)


def test_activation_compiles_selected_set_and_holds_failed_aggregate(service):
    service._probe = accepted_probe
    first = yara_draft(service, "first")
    service.activate(first["id"])
    second = yara_draft(service, "second")
    observed = []
    def probe(_root, sources, _samples, _op):
        observed.append(sources)
        return dict(accepted_probe(), state="invalid" if len(sources) == 2 else "completed")
    service._probe = probe
    with pytest.raises(ValueError, match="Combined native"):
        service.activate(second["id"])
    assert [len(rows) for rows in observed] == [1, 2]
    assert [row["id"] for row in service.active_data("yara")] == [first["id"]]


def test_activation_rechecks_whole_active_set_after_probe_without_holding_library_lock(service):
    service._probe = accepted_probe
    first = yara_draft(service, "first")
    service.activate(first["id"])
    second = yara_draft(service, "second")
    def probe(_root, sources, _samples, _op):
        if len(sources) == 2:
            service.disable(first["id"])
        return accepted_probe()
    service._probe = probe
    with pytest.raises(ValueError, match="selection changed"):
        service.activate(second["id"])
    assert service.active_data("yara") == []
    assert service.read(first["id"])["previous_sha256"] == first["draft_sha256"]


def test_rollback_cannot_overcommit_aggregate_and_preserves_previous_revision(service):
    service._probe = accepted_probe
    first = yara_draft(service, "first", size=40000)
    service.activate(first["id"])
    service.disable(first["id"])
    second = yara_draft(service, "second", size=40000)
    service.activate(second["id"])
    with pytest.raises(ValueError, match="32 sources / 64 KiB"):
        service.rollback(first["id"])
    assert service.read(first["id"])["previous_sha256"] == first["draft_sha256"]
    assert [row["id"] for row in service.active_data("yara")] == [second["id"]]


def test_rollback_requires_current_source_review(service, monkeypatch):
    monkeypatch.setattr(github_tool_catalog, "_require_unprivileged", lambda: None)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("root/rule.yar", "rule harmless { condition: false }")
    plan = github_tool_catalog.ImportPlan("fixture/rules", "a"*40, "a"*40, "MIT")
    source = service.catalog.store_source(plan, stream.getvalue(), github_tool_catalog.ImportOperation())
    service.catalog.set_review_state(source["id"], "reviewed", github_tool_catalog.ImportOperation())
    row = service.install_batch(source["id"], ["rule.yar"])[0]
    service._probe = accepted_probe
    service.activate(row["id"])
    service.disable(row["id"])
    service.catalog.set_review_state(source["id"], "revoked", github_tool_catalog.ImportOperation())
    with pytest.raises(ValueError, match="revoked"):
        service.rollback(row["id"])
    assert service.read(row["id"])["active_sha256"] == ""


def test_bom_rule_keeps_raw_provenance_and_exact_compile_input_digest(service):
    service._probe = accepted_probe
    text = "\ufeffrule harmless { condition: false }\r\n"
    row = service.create_draft("yara", text, name="BOM fixture")
    service.activate(row["id"])
    active = service.active_data("yara")[0]
    assert active["active_sha256"] == hashlib.sha256(text.encode()).hexdigest()
    assert active["text"] == "rule harmless { condition: false }\r\n"
    assert active["compile_input_sha256"] == hashlib.sha256(active["text"].encode()).hexdigest()
    assert active["compile_input_sha256"] != active["active_sha256"]


def test_known_sample_badge_requires_the_expected_rule_identifier(service):
    row = service.install_batch("builtin:angerona", ["examples/angerona-sample.yar"])[0]
    service._probe = lambda *_args: {"state": "completed", "worker_retired": True,
        "matches": [{"sample": 0, "rules": ["Wrong_Inert_Rule"]}, {"sample": 1, "rules": []}]}
    result = service.sample_test(row["id"])
    assert result["sample_passed"] is False
    assert result["sample_checks"] == {"known_positive": False, "known_negative": True}
