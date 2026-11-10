import base64
import hashlib
import io
import json
from pathlib import Path
import threading
import zipfile

import pytest

from angerona.core import community_tool_adapters as adapter
from angerona.core import github_tool_catalog as catalog
from angerona.core import curated_tools as curated

REPOSITORY = next(path for path in Path(__file__).resolve().parents if (path / "pyproject.toml").is_file() and (path / "src/angerona/core/curated_tools.py").is_file())


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setattr(catalog, "_require_unprivileged", lambda: None)
    return adapter.CommunityToolService(tmp_path / "adapters", catalog=catalog.GitHubToolCatalog(tmp_path / "library"))


def imported(service, files, *, tool="sysmon-modular", review=True):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr("fixture-root/" + name, content)
    spec = next(row for row in adapter.tool_specs() if row["id"] == tool)
    plan = catalog.ImportPlan(spec["repository"], "a"*40, "a"*40, spec["license"])
    row = service.catalog.store_source(plan, stream.getvalue(), catalog.ImportOperation())
    if review:
        service.catalog.set_review_state(row["id"], "reviewed", catalog.ImportOperation())
    return row


XML = '<Sysmon><EventFiltering><ProcessCreate onmatch="include"/></EventFiltering></Sysmon>'


def test_constructor_and_specs_do_not_touch_files_or_network(tmp_path, monkeypatch):
    monkeypatch.setattr(catalog, "_download", lambda *_args: pytest.fail("network"))
    instance = adapter.CommunityToolService(tmp_path / "absent", catalog=catalog.GitHubToolCatalog(tmp_path / "absent-library"))
    rows = instance.tool_specs()
    assert len(rows) == 8 and not (tmp_path / "absent").exists()
    assert next(row for row in rows if row["id"] == "caldera")["repository"] == "apache/caldera"
    rows[0]["authors"].append("fixture mutation")
    assert "fixture mutation" not in instance.tool_specs()[0]["authors"]


def test_raw_member_preserves_bytes_and_requires_current_review(service):
    row = imported(service, {"license.md": b"MIT", "fixture.xml": b"\xff\x00\n"}, review=False)
    assert service.catalog.raw_member(row["id"], "fixture.xml") == b"\xff\x00\n"
    with pytest.raises(ValueError, match="not currently reviewed"):
        service.catalog.raw_member(row["id"], "fixture.xml", require_reviewed=True)
    service.catalog.set_review_state(row["id"], "reviewed", catalog.ImportOperation())
    assert service.catalog.raw_member(row["id"], "fixture.xml", require_reviewed=True) == b"\xff\x00\n"
    service.catalog.set_review_state(row["id"], "revoked", catalog.ImportOperation())
    with pytest.raises(ValueError, match="not currently reviewed"):
        service.catalog.raw_member(row["id"], "fixture.xml", require_reviewed=True)


@pytest.mark.parametrize("limit", [True, 0, -1, 4*1024*1024+1, float("nan"), "20"])
def test_raw_member_strict_byte_budget(service, limit):
    with pytest.raises(ValueError, match="raw member limit"):
        service.catalog.raw_member("a"*64, "fixture.xml", max_bytes=limit)


def test_raw_member_rejects_missing_member_oversize_and_tampered_archive(service):
    row = imported(service, {"license.md": "MIT", "fixture.xml": "fixture"})
    with pytest.raises(ValueError):
        service.catalog.raw_member(row["id"], "../fixture.xml")
    with pytest.raises(ValueError):
        service.catalog.raw_member(row["id"], "fixture.xml", max_bytes=2)
    (service.catalog.root / (row["id"] + ".zip")).write_bytes(b"modified archive")
    with pytest.raises(ValueError, match="SHA-256"):
        service.catalog.raw_member(row["id"], "fixture.xml")


def test_install_sysmon_preview_and_revoke_hold_without_service_install(service):
    row = imported(service, {"license.md": "MIT", "fixture.xml": XML, "archive.xml": '<Sysmon><FileDelete onmatch="include"/></Sysmon>'})
    progress = []
    result = service.install("sysmon-modular", progress=progress.append, source_id=row["id"])
    assert result["installed"] and result["commit"] == "a"*40 and progress[-1]["percent"] == 100
    evaluated = service.evaluate("sysmon-modular", [])
    assert evaluated["state"] == "completed" and evaluated["host_scan"] is False
    assert any(row["archives_deleted_files"] for row in evaluated["preview"])
    assert all(row["service_installed"] is False for row in evaluated["preview"])
    service.catalog.set_review_state(row["id"], "revoked", catalog.ImportOperation())
    assert service.status("sysmon-modular")["state"] == "needs-review"
    with pytest.raises(ValueError, match="reviewed"):
        service.evaluate("sysmon-modular", [])


def test_unreviewed_wrong_repository_or_missing_license_cannot_install(service):
    row = imported(service, {"license.md": "MIT", "fixture.xml": XML}, review=False)
    with pytest.raises(ValueError, match="reviewed"):
        service.install("sysmon-modular", source_id=row["id"])
    service.catalog.set_review_state(row["id"], "reviewed", catalog.ImportOperation())
    with pytest.raises(ValueError, match="canonical"):
        service.install("sigma", source_id=row["id"])
    missing = imported(service, {"fixture.xml": XML})
    with pytest.raises(ValueError, match="license"):
        service.install("sysmon-modular", source_id=missing["id"])


def test_xml_entities_and_invalid_data_are_explicit_gaps(service):
    row = imported(service, {"license.md": "MIT", "good.xml": XML, "bad.xml": '<!DOCTYPE a [<!ENTITY x SYSTEM "file:///outside">]><Sysmon>&x;</Sysmon>'})
    result = service.install("sysmon-modular", source_id=row["id"])
    assert result["coverage"]["supported"] == 1
    assert result["coverage"]["skipped"][0]["path"] == "bad.xml"


def test_atomic_commands_are_catalog_data_and_never_executed(service, tmp_path):
    sentinel = tmp_path / "must-not-exist"
    raw = 'attack_technique: T1059.001\natomic_tests:\n- auto_generated_guid: c62c08fd-114a-40b2-9376-53100946988d\n  name: inert fixture\n  supported_platforms: [windows]\n  executor:\n    name: powershell\n    command: |\n      New-Item ' + str(sentinel) + '\n'
    row = imported(service, {"LICENSE.txt": "MIT", "atomics/T1059.001/T1059.001.yaml": raw}, tool="atomic-red-team")
    assert service.install("atomic-red-team", source_id=row["id"])["installed"]
    result = service.evaluate("atomic-red-team", [])
    assert result["preview"][0]["mapped_control"] == "process-execution"
    assert not sentinel.exists() and result["response_authority"] is False


def test_cancel_and_per_tool_busy_do_not_block_other_adapter(service):
    operation = adapter.AdapterOperation()
    operation.cancel()
    with pytest.raises(adapter.AdapterCancelled):
        service.install("sysmon-modular", operation)
    with service._transaction("atomic-red-team", adapter.AdapterOperation()):
        with pytest.raises(ValueError, match="This tool is busy"):
            service.self_check("atomic-red-team")
        assert service.self_check("sysmon-modular")["state"] == "passed"


def test_sandbox_edited_copies_diff_revert_and_uninstall_preserve_upstream(service):
    row = imported(service, {"license.md": "MIT", "fixture.xml": XML})
    service.install("sysmon-modular", source_id=row["id"])
    sandbox = service.create_sandbox("sysmon-modular")
    identity = sandbox["sandbox_id"]
    before = service.catalog.raw_member(row["id"], "fixture.xml")
    changed = '<Sysmon><FileDelete onmatch="include"/></Sysmon>'
    service.sandbox_write("sysmon-modular", identity, "fixture.xml", changed)
    assert service.sandbox_files("sysmon-modular", identity)[0]["customized"] is True
    assert service.status("sysmon-modular")["customized"] is True
    assert "FileDelete" in service.sandbox_diff("sysmon-modular", identity, "fixture.xml")["diff"]
    analysis = service.sandbox_analysis("sysmon-modular", identity, "fixture.xml")
    assert analysis["details"]["archives_deleted_files"] and not analysis["activated"]
    assert service.catalog.raw_member(row["id"], "fixture.xml") == before
    result = service.uninstall("sysmon-modular")
    assert result["state"] == "uninstalled"
    assert service.sandbox_read("sysmon-modular", identity, "fixture.xml")["text"] == changed
    service.sandbox_revert("sysmon-modular", identity)
    assert service.sandbox_read("sysmon-modular", identity, "fixture.xml")["text"] == XML


def test_sandbox_rejects_path_escape_and_changed_baseline(service, tmp_path):
    row = imported(service, {"license.md": "MIT", "fixture.xml": XML})
    service.install("sysmon-modular", source_id=row["id"])
    sandbox = service.create_sandbox("sysmon-modular")
    identity = sandbox["sandbox_id"]
    with pytest.raises(ValueError):
        service.sandbox_write("sysmon-modular", identity, "../../outside", "inert")
    baseline = service.root / "sysmon-modular/sandboxes" / identity / "baseline/fixture.xml"
    baseline.write_text("changed baseline")
    with pytest.raises(ValueError, match="baseline changed"):
        service.sandbox_read("sysmon-modular", identity, "fixture.xml")
    assert not (tmp_path / "outside").exists()


@pytest.mark.parametrize("tool", ["sysmon-modular", "atomic-red-team"])
def test_actual_inert_positive_and_negative_self_checks(service, tool):
    result = service.self_check(tool)
    assert result["state"] == "passed" and result["positive"] and result["negative"]
    assert result["response_authority"] is False


def test_external_platforms_are_optional_advisory_only(service):
    for tool in ("caldera", "velociraptor", "wazuh"):
        assert service.install(tool)["state"] == "external-only"
        assert service.self_check(tool)["state"] == "unavailable"
        row = service.import_external_result(tool, {"origin": "https://fixture.invalid", "job_id": "inert", "findings": [{"title": "untrusted report data"}]})
        assert row["state"] == "imported-advisory" and row["response_authority"] is False


def test_zero_breach_uninstall_intent_survives_restart_and_preserves_reports(tmp_path):
    root = tmp_path / "managed-zero"
    bundle = REPOSITORY / "assets/integrations/zero_breach"
    instance = curated.CuratedToolService(root, bundle=bundle)
    instance.prepare(curated.ToolOperation(), allow_download=False)
    reports = root / "jobs/fixture"
    reports.mkdir(parents=True)
    (reports / "operator-report.txt").write_text("preserve me")
    engine = instance._engine(root)
    engine.write_bytes(engine.read_bytes() + b"\n# user edit\n")
    result = instance.uninstall(curated.ToolOperation())
    assert result["auto_prepare_blocked"] is True and not engine.exists()
    assert (reports / "operator-report.txt").read_text() == "preserve me"
    assert "preserved_path" in result
    restarted = curated.CuratedToolService(root, bundle=bundle)
    with pytest.raises(curated.ToolError, match="explicitly uninstalled"):
        restarted.prepare(curated.ToolOperation(), allow_download=False)
    assert restarted.prepare(curated.ToolOperation(), allow_download=False, restore_uninstalled=True)["verified"]
    assert restarted.status()["auto_prepare_blocked"] is False


def test_member_snapshot_validates_zip_once_and_retains_aggregate_budget(service, monkeypatch):
    row = imported(service, {"license.md": "MIT", "a.xml": XML, "b.xml": XML})
    original = service.catalog._archive
    calls = []
    def tracked(record):
        calls.append(record["id"])
        return original(record)
    monkeypatch.setattr(service.catalog, "_archive", tracked)
    members = service.catalog.raw_members(row["id"], ["a.xml", "b.xml"], require_reviewed=True)
    assert set(members) == {"a.xml", "b.xml"} and len(calls) == 1
    with pytest.raises(ValueError, match="byte budget"):
        service.catalog.raw_members(row["id"], ["a.xml", "b.xml"], total_bytes=len(XML), require_reviewed=True)


def test_sigma_service_delegates_native_source_eid_guard_and_preserves_authors(service):
    raw = b'''title: Inert adapter integration
id: a9e93e79-c044-4bb3-97a9-7ddf3ad41f87
author: Fixture Rule Author
license: DRL-1.1
date: 2026-11-08
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\inert-marker.exe'
  condition: selection
level: low
'''
    row = imported(service, {"LICENSE": "DRL-1.1", "rules/windows/process_creation/fixture.yml": raw,
                             "rules/windows/process_creation/unsupported.yml": raw.replace(b"Image|endswith", b"Image|re")}, tool="sigma")
    installed = service.install("sigma", source_id=row["id"])
    assert installed["coverage"]["supported"] == 1 and installed["coverage"]["skipped"]
    event = dict(module="Sysmon Event Bridge", sensor_source="sysmon-native", raw_sensor_evidence=True, eid=1, image="C:\\fixtures\\inert-marker.exe")
    result = service.evaluate("sigma", [event, dict(event, module="Process Monitor"), dict(event, eid=7), dict(event, image="C:\\fixtures\\ordinary.exe")])
    assert len(result["findings"]) == 1 and result["response_authority"] is False
    assert "Fixture Rule Author" in json.dumps(result["findings"])
    assert {row["code"] for row in result["gaps"]} == {"WRONG_SOURCE", "WRONG_EVENT_ID"}
    assert service.self_check("sigma")["state"] == "passed"


def test_zero_breach_bundled_source_sandbox_is_editable_and_never_replaces_engine(service, tmp_path):
    service.curated = curated.CuratedToolService(tmp_path / "managed", bundle=REPOSITORY / "assets/integrations/zero_breach")
    source = service.curated._bundle() / "engine.py"
    original = source.read_bytes()
    sandbox = service.create_sandbox("zero-breach")
    identity = sandbox["sandbox_id"]
    row = service.sandbox_read("zero-breach", identity, "engine.py")
    assert len(row["text"].encode()) > 256*1024
    service.sandbox_write("zero-breach", identity, "engine.py", row["text"] + "\n# inert operator experiment\n")
    assert service.status("zero-breach")["customized"]
    assert service.sandbox_analysis("zero-breach", identity, "engine.py")["details"]["execution"] == "never executed"
    assert source.read_bytes() == original
    assert not service.curated._engine(service.curated._root()).exists()


def test_sandbox_edits_share_aggregate_budget_and_preserve_previous_work(service):
    row = imported(service, {"license.md": "MIT", "a.xml": XML, "b.xml": XML, "c.xml": XML})
    service.install("sysmon-modular", source_id=row["id"])
    sandbox = service.create_sandbox("sysmon-modular")
    identity = sandbox["sandbox_id"]
    large = "<x>" + " "*(adapter.MAX_EDITOR_BYTES-7) + "</x>"
    service.sandbox_write("sysmon-modular", identity, "a.xml", large)
    with pytest.raises(ValueError, match="aggregate budget"):
        service.sandbox_write("sysmon-modular", identity, "b.xml", large)
    assert service.sandbox_read("sysmon-modular", identity, "a.xml")["text"] == large
    assert service.sandbox_read("sysmon-modular", identity, "b.xml")["text"] == XML


def test_pack_provenance_cannot_be_relabelled_to_a_different_commit(service):
    row = imported(service, {"license.md": "MIT", "fixture.xml": XML})
    service.install("sysmon-modular", source_id=row["id"])
    marker = service.root / "sysmon-modular/installed.json"
    document = json.loads(marker.read_text())
    document["commit"] = "b"*40
    marker.write_text(json.dumps(document))
    assert service.status("sysmon-modular")["state"] == "needs-review"
    with pytest.raises(ValueError, match="provenance differs"):
        service.evaluate("sysmon-modular", [])
    assert service.uninstall("sysmon-modular")["state"] == "uninstalled"
