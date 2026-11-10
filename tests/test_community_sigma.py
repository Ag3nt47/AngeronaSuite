"""Host-independent semantic and refusal checks for the community adapter."""
from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

_staged = Path(__file__).with_name("community_sigma.py")
if _staged.is_file():
    _spec = importlib.util.spec_from_file_location("angerona_staged_community_sigma", _staged)
    sigma = importlib.util.module_from_spec(_spec)
    sys.modules[_spec.name] = sigma
    _spec.loader.exec_module(sigma)
else:
    from angerona.core import community_sigma as sigma


def document(category="process_creation", selection=None, condition="selection"):
    return {"title": "Reviewed benign fixture", "id": "89e0aca1-2a4c-47bb-ae08-59bed8d6bd9d",
            "author": "Fixture Author", "license": "DRL-1.1", "status": "test", "level": "high",
            "date": "2026-11-08", "tags": ["attack.execution", "attack.t1059.001"],
            "references": ["https://example.invalid/fixture-not-a-live-rule"],
            "logsource": {"category": category, "product": "windows"},
            "detection": {"selection": selection or {"Image|endswith": r"\fixture.exe"}, "condition": condition}}


def provenance(raw):
    return {"repository": "sigmahq/sigma", "commit": "a" * 40,
            "path": "rules/windows/process_creation/proc_creation_win_fixture.yml",
            "sha256": hashlib.sha256(raw).hexdigest(), "license": "DRL-1.1", "source_id": "sha256:" + "b" * 64}


def prepare(doc=None):
    raw = yaml.safe_dump(doc or document(), sort_keys=False).encode("utf-8")
    return sigma.prepare_sigma_document(raw, provenance(raw))


def event(eid=1, **fields):
    return {"module": "Sysmon Event Bridge", "sensor_source": "sysmon-native",
            "raw_sensor_evidence": True, "eid": eid, "image": r"C:\fixture.exe", **fields}


def evaluate(doc=None, candidate=None):
    prepared = prepare(doc)
    assert prepared["accepted"], prepared
    return sigma.evaluate_prepared(prepared, candidate or event())


def test_offline_self_check_has_actual_positive_negative_and_refusals():
    result = sigma.self_check()
    assert result["ok"]
    assert len(result["checks"]) >= 9
    assert {check["actual"] for check in result["checks"] if "actual" in check} >= {
        "MATCH", "NO_MATCH", "WRONG_SOURCE", "WRONG_EVENT_ID", "UNSUPPORTED_LOGSOURCE", "UNSUPPORTED_MODIFIER",
    }
    assert result["response_authorized"] is False


def test_metadata_logsource_and_license_are_preserved_in_findings():
    prepared = prepare()
    assert prepared["accepted"]
    assert prepared["sidecar"]["original_logsource"] == document()["logsource"]
    assert prepared["sidecar"]["metadata"]["author"] == "Fixture Author"
    assert prepared["sidecar"]["metadata"]["id"] == document()["id"]
    assert prepared["sidecar"]["license"] == "DRL-1.1"
    assert prepared["sidecar"]["attack"] == ["T1059.001"]
    result = sigma.evaluate_prepared(prepared, event())
    assert result["matched"]
    assert result["finding"]["source"]["commit"] == "a" * 40
    assert result["finding"]["author"] == "Fixture Author"
    assert result["finding"]["license"] == "DRL-1.1"
    assert result["finding"]["disposition"] == "review-required"
    assert result["response_authorized"] is False
    assert result["finding"]["response_authorized"] is False


@pytest.mark.parametrize("overrides,code", [
    ({"module": "Process Monitor"}, "WRONG_SOURCE"),
    ({"sensor_source": "psutil"}, "WRONG_SOURCE"),
    ({"raw_sensor_evidence": False}, "WRONG_SOURCE"),
    ({"raw_sensor_evidence": "True"}, "WRONG_SOURCE"),
    ({"fallback": True}, "WRONG_SOURCE"),
    ({"eid": 7}, "WRONG_EVENT_ID"),
    ({"eid": "1"}, "WRONG_EVENT_ID"),
    ({"eid": True}, "WRONG_EVENT_ID"),
    ({"image": r"C:\legitimate.exe"}, "NO_MATCH"),
])
def test_wrong_source_event_id_and_benign_controls(overrides, code):
    result = evaluate(candidate=event(**overrides))
    assert result["code"] == code
    assert not result["matched"]


def test_envelope_module_cannot_be_overridden_by_event_details():
    candidate = {"module": "Unrelated Sensor", "details": event()}
    assert evaluate(candidate=candidate)["code"] == "WRONG_SOURCE"
    obj = SimpleNamespace(module="Unrelated Sensor", details=event())
    assert evaluate(candidate=obj)["code"] == "WRONG_SOURCE"


@pytest.mark.parametrize("modifier,expected,actual,matched", [
    ("", "C:\\fixture.exe", "c:\\FIXTURE.exe", True),
    ("contains", "fixture", "C:\\fixture.exe", True),
    ("startswith", "C:\\", "c:\\fixture.exe", True),
    ("endswith", "\\fixture.exe", "C:\\fixture.exe", True),
    ("endswith", "\\fixture.exe", "C:\\fixture.exe.bak", False),
])
def test_supported_literal_modifier_semantics(modifier, expected, actual, matched):
    key = "Image" + ("|" + modifier if modifier else "")
    result = evaluate(document(selection={key: expected}), event(image=actual))
    assert result["matched"] is matched


def test_lists_maps_filters_prefixes_and_whitespace_preserve_meaning():
    doc = document()
    doc["detection"] = {
        "CandidateA": [{"Image|endswith": r"\fixture.exe"}, {"Image|endswith": r"\other.exe"}],
        "CandidateB": {"CommandLine|contains": ["--review", "--benign"]},
        "filter": {"ParentImage|endswith": r"\allowed-parent.exe"},
        "condition": "  all   of Candidate*  and not filter ",
    }
    prepared = prepare(doc)
    assert prepared["accepted"], prepared
    assert prepared["internal_rule"]["detection"]["condition"] == "candidatea and candidateb and not filter"
    good = event(command_line="fixture.exe --review", parent_image=r"C:\other-parent.exe")
    assert sigma.evaluate_prepared(prepared, good)["matched"]
    assert not sigma.evaluate_prepared(prepared, event(command_line="fixture.exe --noop"))["matched"]
    assert not sigma.evaluate_prepared(prepared, {**good, "parent_image": r"C:\allowed-parent.exe"})["matched"]
    for selection_name, selection in prepared["internal_rule"]["detection"].items():
        if selection_name == "condition":
            continue
        for branch in selection if isinstance(selection, list) else [selection]:
            assert branch["sensor_source"] == "sysmon-native"
            assert branch["eid"] == [1]


def test_explicit_or_followed_by_and_not_refuses_precedence_approximation():
    doc = document()
    doc["detection"] = {"a": {"Image|contains": "one"}, "b": {"Image|contains": "two"},
                        "filter": {"Image|contains": "ignore"}, "condition": "a or b and not filter"}
    result = prepare(doc)
    assert result["code"] == "UNSUPPORTED_CONDITION"


@pytest.mark.parametrize("category,eid,selection,fields", [
    ("process_creation", 1, {"ParentCommandLine|contains": "--fixture", "ProcessId": 42}, {"parent_cmdline": "p --fixture", "pid": "42"}),
    ("image_load", 7, {"ImageLoaded|endswith": r"\fixture.dll", "ProcessId": 42}, {"image_loaded": r"C:\fixture.dll", "process_id": "42"}),
    ("network_connection", 3, {"DestinationIp": "192.0.2.1", "DestinationPort": 443, "Initiated": True}, {"dest_ip": "192.0.2.1", "dest_port": "443", "initiated": True}),
    ("file_event", 11, {"TargetFilename|endswith": r"\fixture.txt"}, {"target_filename": r"C:\fixture.txt"}),
    ("registry_set", 13, {"TargetObject|contains": "Fixture", "Details|contains": "value"}, {"target_object": "HKCU\\Fixture", "details": "value"}),
    ("process_access", 10, {"GrantedAccess": "0x1fffff", "SourceProcessId": 42}, {"granted_access": "0x1fffff", "source_pid": "42"}),
    ("driver_load", 6, {"ImageLoaded|endswith": r"\fixture.sys"}, {"image_loaded": r"C:\fixture.sys"}),
    ("dns_query", 22, {"QueryName": "fixture.example", "ProcessId": 42}, {"query_name": "fixture.example", "process_id": "42"}),
    ("pipe_created", 18, {"PipeName|contains": "fixture"}, {"pipe_name": "fixture"}),
    ("file_delete", 26, {"TargetFilename|endswith": r"\fixture.txt"}, {"target_filename": r"C:\fixture.txt"}),
])
def test_bridge_field_mappings_are_specific_to_each_decoder(category, eid, selection, fields):
    result = evaluate(document(category, selection), event(eid=eid, **fields))
    assert result["matched"], result


def test_registry_create_delete_category_guards_do_not_confuse_operations():
    doc = document("registry_add", {"TargetObject|contains": "Fixture"})
    assert evaluate(doc, event(eid=12, target_object="HKCU\\Fixture", event_type="CreateKey"))["matched"]
    assert not evaluate(doc, event(eid=12, target_object="HKCU\\Fixture", event_type="DeleteKey"))["matched"]
    doc = document("registry_delete", {"TargetObject|contains": "Fixture"})
    assert evaluate(doc, event(eid=12, target_object="HKCU\\Fixture", event_type="DeleteValue"))["matched"]
    doc = document("registry_add", {"EventType": "DeleteKey"})
    assert prepare(doc)["code"] == "INCOMPATIBLE_EVENT_TYPE"


def test_explicit_event_id_is_intersection_not_overwritten_by_category_guard():
    doc = document("file_delete", {"EventID": 26, "TargetFilename|contains": "fixture"})
    prepared = prepare(doc)
    assert prepared["accepted"]
    assert prepared["internal_rule"]["detection"]["selection"]["eid"] == [26]
    assert sigma.evaluate_prepared(prepared, event(eid=26, target_filename="fixture"))["matched"]
    assert not sigma.evaluate_prepared(prepared, event(eid=23, target_filename="fixture"))["matched"]
    assert prepare(document(selection={"EventID": 7}))["code"] == "UNSUPPORTED_EVENT_ID"


@pytest.mark.parametrize("selection,code", [
    ({"OriginalFileName": "fixture.exe"}, "UNAVAILABLE_FIELD"),
    ({"Image|re": "(a+)+$"}, "UNSUPPORTED_MODIFIER"),
    ({"Image|contains|all": ["one", "two"]}, "UNSUPPORTED_MODIFIER"),
    ({"Image|cidr": "192.0.2.0/24"}, "UNSUPPORTED_MODIFIER"),
    ({"Image": "*fixture.exe"}, "UNSUPPORTED_WILDCARD"),
    ({"Image|contains": "fixture?"}, "UNSUPPORTED_WILDCARD"),
    ({"Image|contains": r"fixture\*"}, "UNSUPPORTED_WILDCARD"),
    ({"Image": None}, "UNSUPPORTED_VALUE"),
    ({"Image": ""}, "UNSUPPORTED_VALUE"),
    ({"Image|exists": True}, "UNSUPPORTED_MODIFIER"),
])
def test_unavailable_fields_and_unsupported_predicates_are_explicit(selection, code):
    result = prepare(document(selection=selection))
    assert not result["accepted"]
    assert result["code"] == code
    assert result["refusal"]["reason"]
    assert result["response_authorized"] is False


@pytest.mark.parametrize("change,code", [
    ({"logsource": {"product": "linux", "category": "process_creation"}}, "UNSUPPORTED_LOGSOURCE"),
    ({"logsource": {"product": "windows", "service": "security", "category": "process_creation"}}, "UNSUPPORTED_LOGSOURCE"),
    ({"logsource": {"product": "windows", "category": "process_creation", "channel": "Application"}}, "UNSUPPORTED_LOGSOURCE"),
    ({"taxonomy": "custom"}, "UNSUPPORTED_TAXONOMY"),
    ({"status": "deprecated"}, "UNSUPPORTED_STATUS"),
    ({"correlation": {"type": "event_count"}}, "UNSUPPORTED_CORRELATION"),
])
def test_logsource_taxonomy_and_correlation_refusals(change, code):
    result = prepare({**document(), **change})
    assert result["code"] == code
    assert not result["accepted"]


@pytest.mark.parametrize("raw", [
    b"title: one\ntitle: two\n",
    b"x: &x {one: two}\ny: *x\n",
    b"!!python/object/apply:os.system ['DO-NOT-EXECUTE']",
    b"title: one\n---\ntitle: two\n",
    b"x: .nan\n",
    b"x: " + b"[" * 40 + b"0" + b"]" * 40,
    b"x: " + b"a" * 4097,
    b"x: [" + b"0," * 5000 + b"0]",
    b"\xff\xfe\xfd",
])
def test_yaml_duplicates_aliases_unsafe_tags_multidoc_and_budgets_refuse(raw):
    result = sigma.prepare_sigma_document(raw, provenance(raw))
    assert not result["accepted"]
    assert result["errors"]


def test_canonical_unquoted_date_is_retained_as_text():
    raw = yaml.safe_dump(document()).replace("'2026-11-08'", "2026-11-08").encode()
    result = sigma.prepare_sigma_document(raw, provenance(raw))
    assert result["accepted"]
    assert result["sidecar"]["metadata"]["date"] == "2026-11-08"


@pytest.mark.parametrize("overrides,code", [
    ({"sha256": "0" * 64}, "SOURCE_DIGEST_MISMATCH"),
    ({"repository": "https://github.com/sigmahq/sigma"}, "INVALID_PROVENANCE"),
    ({"commit": "main"}, "INVALID_PROVENANCE"),
    ({"path": "../outside.yml"}, "INVALID_PROVENANCE"),
    ({"path": "C:\\outside.yml"}, "INVALID_PROVENANCE"),
    ({"license": ""}, "MISSING_LICENSE"),
])
def test_provenance_requires_exact_bytes_commit_and_safe_path(overrides, code):
    raw = yaml.safe_dump(document()).encode()
    result = sigma.prepare_sigma_document(raw, {**provenance(raw), **overrides})
    assert result["code"] == code
    assert not result["accepted"]


@pytest.mark.parametrize("target", ["rule", "source", "license"])
def test_prepared_plan_and_provenance_tampering_refuse(target):
    prepared = prepare()
    if target == "rule":
        prepared["internal_rule"]["detection"]["selection"]["image|endswith"] = "other.exe"
    elif target == "source":
        prepared["sidecar"]["source"]["commit"] = "b" * 40
    else:
        prepared["sidecar"]["license"] = "changed"
    result = sigma.evaluate_prepared(prepared, event())
    assert result["code"] == "PREPARED_DIGEST_MISMATCH"


def test_resealed_untrusted_plan_cannot_smuggle_regex_or_remove_guards():
    for kind in ("regex", "guard"):
        prepared = prepare()
        branch = prepared["internal_rule"]["detection"]["selection"]
        if kind == "regex":
            branch["image|re"] = "(a+)+$"
        else:
            del branch["sensor_source"]
        prepared["digest"] = sigma._digest(prepared["internal_rule"], prepared["sidecar"])
        assert sigma.evaluate_prepared(prepared, event())["code"] == "INVALID_PREPARED"


def test_event_runtime_objects_are_never_stringified():
    class Explosive:
        def __str__(self):
            pytest.fail("Untrusted runtime object must not be stringified")
    assert evaluate(candidate=event(image=Explosive()))["code"] == "INVALID_EVENT"
    assert evaluate(candidate=event(image="x" * 4097))["code"] == "EVENT_BUDGET_EXCEEDED"


def test_bridge_decoder_contract_uses_actual_native_mapping_without_starting_sensors():
    from defusedxml import ElementTree as ET
    from angerona.modules.sysmon_listener import _build_details

    for eid, mapping in sigma._FIELDS_BY_EID.items():
        xml = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventData>' + "".join(
            f'<Data Name="{field}">fixture</Data>' for field in mapping
        ) + "</EventData></Event>"
        details = _build_details(eid, ET.fromstring(xml), "offline-fixture", [])
        assert set(mapping.values()) <= set(details), (eid, set(mapping.values()) - set(details))
        assert details["eid"] == eid
        assert details["raw_sensor_evidence"] is True
        assert details["response_authorized"] is False


def test_translated_plan_fits_existing_closed_package_and_preserves_source_guards():
    from angerona.core.detection_packages import DetectionPackage, seal_package, validate_package

    prepared = prepare()
    package = seal_package({
        "schema_version": 1, "id": "community.fixture", "version": "1.0.0", "owner": "Fixture reviewer",
        "description": "Offline reviewed candidate; provenance sidecar " + prepared["digest"],
        "telemetry": ["sysmon-native"], "attack": ["T1059.001"], "severity": "high", "confidence": 70,
        "logic": {"type": "sigma-subset", "detection": prepared["internal_rule"]["detection"]},
        "fixtures": [{"name": "positive", "event": event(), "expected_match": True},
                     {"name": "negative", "event": event(image="other.exe"), "expected_match": False},
                     {"name": "source", "event": event(module="Other"), "expected_match": False},
                     {"name": "eid", "event": event(eid=7), "expected_match": False}],
        "performance": {"max_eval_ms": 50, "max_events_per_second": 1000},
        "rollback": {"previous_digest": None, "instructions": "Retire candidate through the existing registry."},
        "expires_at": "2099-01-01T00:00:00+00:00",
    })
    validate_package(package)
    detector = DetectionPackage(package)
    for fixture in package["fixtures"]:
        assert detector.evaluate(fixture["event"]) is fixture["expected_match"]
    assert "license" not in package  # closed schema unchanged; credits stay in bound sidecar
    assert not prepared["response_authorized"]
