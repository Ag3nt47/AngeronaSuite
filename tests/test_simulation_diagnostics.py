"""Real signed immutable AARs; diagnostic recommendations execute nothing."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil

import pytest

from angerona.core import report_attest, simulation_diagnostics as diagnostics
from angerona.core.eventbus import Event, Severity
from angerona.shark import aar_report as aar


@pytest.fixture
def report(tmp_path, monkeypatch):
    key = tmp_path / "bus.key"
    key.write_text((b"d" * 32).hex(), encoding="ascii")
    monkeypatch.setenv("ANGERONA_DATA", str(tmp_path))
    monkeypatch.setattr(report_attest, "_key_path", lambda: key)
    event = Event("YARA Scanner", "Inert native fixture", Severity.HIGH, 101.0, {})
    response = Event("Adversary Combat", "Inert response fixture", Severity.HIGH, 102.0, {})
    rows = [
        aar.StepVerdict("Verified fixture", "T1059 fixture", "No real attack", 100.0, True,
            catch=event, catch_latency=1.0, observation=event, observation_latency=1.0,
            native_catch=event, native_latency=1.0, remediation=response,
            response_action_reported=True, response_action_applied=True,
            target_containment_verified=True),
        aar.StepVerdict("Observation fixture", "T1046 fixture", "No attack", 100.0, True,
            observation=event, observation_latency=1.0),
        aar.StepVerdict("Held response", "T1112 fixture", "No registry changes", 100.0, True,
            catch=event, catch_latency=1.0, native_catch=event, native_latency=1.0,
            containment_reason="Exact durable action receipt not available"),
        aar.StepVerdict("Benign fixture", "noise fixture", "Unscored", 100.0, True, category="resilience"),
    ]
    history = {"run_id": "shark-diagnostics-fixture", "kind": "shark", "status": "completed"}
    handoff = aar._write_report(tmp_path, history, rows, "Bounded inert fixture report")
    return handoff, history, rows


def publish_payload(handoff, history, update):
    data = json.loads(handoff.report_bytes)
    update(data)
    signed = report_attest.attest(data)
    encoded = json.dumps(signed, indent=2)
    return aar._publish_report_bundle(handoff.report_directory, history, basename="shark_aar",
        text=handoff.text, encoded_payload=encoded,
        report_sha256=hashlib.sha256(encoded.encode()).hexdigest())


def test_real_current_handoff_loads_exact_identity_and_specific_nonexecuting_leads(report):
    handoff, _history, _rows = report
    original = {path.name: path.read_bytes() for path in handoff.report_directory.iterdir() if path.suffix in {".json", ".jsonl", ".txt"}}
    result = diagnostics.load_report_diagnostics(handoff.report_directory, report_kind="shark",
        expected_run_id=handoff.run_id, expected_report_sha256=handoff.report_sha256,
        expected_head_sha256=handoff.head_sha256, expected_sequence=handoff.sequence)
    assert result["authentication"] == "verified" and result["report_sha256"] == handoff.report_sha256
    assert result["overall_status"] == "failing" and result["counts"] == {"pass": 1, "fail": 2, "inconclusive": 0, "unscored": 1}
    assert [row["reason_code"] for row in result["rows"]] == ["verified.selected-evidence", "detection.observation-only", "response.not-reported", "category.unscored"]
    assert "src/angerona/modules/yara_scanner.py" in result["rows"][1]["source_areas"]
    assert all(row["fix_status"] in {"none", "not-applied"} for row in result["rows"])
    assert result["fixes_applied_by_this_view"] is result["response_authorized"] is False
    assert original == {path.name: path.read_bytes() for path in handoff.report_directory.iterdir() if path.suffix in {".json", ".jsonl", ".txt"}}


@pytest.mark.parametrize("pin", [{"expected_run_id": "other-run"}, {"expected_report_sha256": "a" * 64},
    {"expected_head_sha256": "b" * 64}, {"expected_sequence": 999}, {"expected_sequence": True}])
def test_wrong_expected_binding_cannot_follow_an_unrelated_saved_report(report, pin):
    handoff, _history, _rows = report
    with pytest.raises(ValueError):
        diagnostics.load_report_diagnostics(handoff.report_directory, report_kind="shark", **pin)


def test_signed_diagnostic_never_turns_planned_rows_into_failed_or_successful_checks(report):
    handoff, history, _rows = report
    changed = publish_payload(handoff, history, lambda value: value.update(diagnostic_only=True,
        coverage_score_eligible=False, outcome="inconclusive"))
    result = diagnostics.diagnostics_for_handoff(changed)
    assert result["report_state"] == "diagnostic" and result["overall_status"] == "inconclusive"
    assert all(row["status"] == "inconclusive" and row["reason_code"] == "coverage.incomplete-run" for row in result["rows"])


def test_mutation_and_supersession_do_not_revalidate_an_old_handoff(report):
    handoff, history, rows = report
    with pytest.raises(ValueError):
        diagnostics.diagnostics_for_handoff(replace(handoff, report_bytes=handoff.report_bytes + b" "))
    aar._write_report(handoff.report_directory, history, rows, "New exact report generation")
    with pytest.raises(ValueError):
        diagnostics.diagnostics_for_handoff(handoff)


def test_even_head_signed_shark_requires_its_own_json_authentication(report):
    handoff, history, _rows = report
    payload = json.loads(handoff.report_bytes)
    payload.pop(report_attest.SIG_FIELD)
    encoded = json.dumps(payload)
    changed = aar._publish_report_bundle(handoff.report_directory, history, basename="shark_aar",
        text=handoff.text, encoded_payload=encoded, report_sha256=hashlib.sha256(encoded.encode()).hexdigest())
    with pytest.raises(ValueError):
        diagnostics.diagnostics_for_handoff(changed)


def test_inconsistent_and_compatibility_only_credit_stays_inconclusive(report):
    handoff, history, _rows = report
    def change(value):
        value["verdicts"][0]["response_action_applied"] = False
        value["verdicts"][2]["native_analytic_detected"] = False
    changed = publish_payload(handoff, history, change)
    rows = diagnostics.diagnostics_for_handoff(changed)["rows"]
    assert rows[0]["status"] == rows[2]["status"] == "inconclusive"
    assert rows[0]["reason_code"] == "evidence.inconsistent"
    assert rows[2]["reason_code"] == "detection.compatibility-only"


def test_untrusted_text_is_plain_bounded_and_not_a_repair_command(report):
    handoff, history, _rows = report
    def change(value):
        value["verdicts"][1].update(containment_reason="<script>never execute</script>" + "x" * 4000,
                                     observed_by="unknown malicious producer")
    result = diagnostics.diagnostics_for_handoff(publish_payload(handoff, history, change))
    assert result["omitted_text_characters"] > 0
    row = result["rows"][1]
    assert any("<script>never execute</script>" in value for value in row["evidence"])
    assert all("<script>" not in value for value in row["next_steps"])
    assert "unknown malicious producer" not in row["source_areas"]
    summary = json.loads(diagnostics.live_debug_summary(result))
    assert summary["advisory_only"] is True and "rows" not in summary


def test_cli_reads_without_sensor_start_and_failure_never_looks_like_zero_misses(report, capsys):
    handoff, _history, _rows = report
    tool = Path(__file__).resolve().parents[1] / "tools/redteam_diagnostics.py"
    spec = importlib.util.spec_from_file_location("private_diagnostics_cli", tool)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.main(["--data-dir", str(handoff.report_directory), "--kind", "shark", "--summary"]) == 0
    assert json.loads(capsys.readouterr().out)["overall_status"] == "failing"
    def unavailable(*_args, **_kwargs):
        raise ValueError("Untrusted detail must not be an executable command")
    assert module.main(["--data-dir", str(handoff.report_directory)], reader=unavailable) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "unavailable" and "counts" not in result


@pytest.mark.parametrize("category", [None, "", "unknown", 1, False, [], "detection\0", "resil\0ience"])
def test_unknown_category_cannot_hide_an_unscored_failure_in_an_overall_pass(report, category):
    handoff, history, _rows = report
    def change(value):
        value["outcome"] = "verified"
        value["verdicts"] = [value["verdicts"][0], {"category": category}]
    result = diagnostics.diagnostics_for_handoff(publish_payload(handoff, history, change))
    assert result["overall_status"] == "inconclusive"
    assert result["rows"][1]["status"] == "inconclusive"
    assert result["rows"][1]["reason_code"] == "evidence.inconsistent"


@pytest.mark.parametrize("identity", [
    {"sequence": True}, {"sequence": 1.0}, {"sequence": "1"},
    {"run_id": 1}, {"run_id": ""}, {"report_kind": []},
    {"report_basename": "other"}, {"report_sha256": 1},
    {"head_sha256": "A" * 64}, {"journal_record_sha256": None},
])
def test_direct_handoff_requires_literal_report_identity_before_verification(report, identity):
    handoff, _history, _rows = report
    with pytest.raises(ValueError, match="literal fields"):
        diagnostics.diagnostics_for_handoff(replace(handoff, **identity))


@pytest.mark.parametrize("diagnostic_only", [None, 0, 1, "false", "true", {}, []])
def test_malformed_optional_diagnostic_marker_withholds_all_coverage_credit(report, diagnostic_only):
    handoff, history, _rows = report
    def change(value):
        value.update(outcome="verified", diagnostic_only=diagnostic_only)
        value["verdicts"] = [value["verdicts"][0]]
    result = diagnostics.diagnostics_for_handoff(publish_payload(handoff, history, change))
    assert result["coverage_score_eligible"] is False
    assert result["overall_status"] == "inconclusive"
    assert result["rows"][0]["reason_code"] == "coverage.incomplete-run"


def test_authentic_copied_report_directory_cannot_replace_the_active_profile(report, tmp_path):
    handoff, history, rows = report
    copied = tmp_path / "copied-profile"
    copied.mkdir()
    for path in handoff.report_directory.iterdir():
        if path.is_file():
            shutil.copyfile(path, copied / path.name)
    aar._write_report(handoff.report_directory, history, rows, "Superseding active report")
    with pytest.raises(ValueError, match="active verification profile"):
        diagnostics.diagnostics_for_handoff(replace(handoff, report_directory=copied))
    with pytest.raises(ValueError, match="active verification profile"):
        diagnostics.load_report_diagnostics(copied, report_kind="shark")


def test_existing_report_read_never_calls_profile_setup_or_creates_scratch(report, monkeypatch):
    handoff, _history, _rows = report
    from angerona.core import data_paths
    before_env = dict(os.environ)
    before_files = {path.name: (path.read_bytes(), path.stat().st_mtime_ns)
                    for path in handoff.report_directory.iterdir() if path.is_file()}
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Read-only verification called a profile writer")
    monkeypatch.setattr(report_attest, "_key_path", forbidden)
    monkeypatch.setattr(data_paths, "data_dir", forbidden)
    monkeypatch.setattr(Path, "mkdir", forbidden)
    result = diagnostics.load_report_diagnostics(handoff.report_directory, report_kind="shark")
    assert result["authentication"] == "verified"
    assert dict(os.environ) == before_env
    assert {path.name: (path.read_bytes(), path.stat().st_mtime_ns)
            for path in handoff.report_directory.iterdir() if path.is_file()} == before_files


def test_cold_default_cli_failure_never_initializes_a_profile(report, monkeypatch, capsys):
    handoff, _history, _rows = report
    from angerona.core import data_paths
    cold = handoff.report_directory / "absent-profile"
    monkeypatch.setenv("ANGERONA_DATA", str(cold))
    before_env = dict(os.environ)
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Read-only CLI called a profile writer")
    monkeypatch.setattr(report_attest, "_key_path", forbidden)
    monkeypatch.setattr(data_paths, "data_dir", forbidden)
    monkeypatch.setattr(Path, "mkdir", forbidden)
    tool = Path(__file__).resolve().parents[1] / "tools/redteam_diagnostics.py"
    spec = importlib.util.spec_from_file_location("private_cold_diagnostics_cli", tool)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.main(["--kind", "shark"]) == 1
    assert json.loads(capsys.readouterr().out)["state"] == "unavailable"
    assert not cold.exists() and dict(os.environ) == before_env


def test_default_cli_reports_profile_resolution_failure_as_unavailable(report, monkeypatch, capsys):
    from angerona.core import data_paths
    def unavailable():
        raise OSError("Unavailable profile discovery")
    monkeypatch.setattr(data_paths, "resolve_data_dir", unavailable)
    tool = Path(__file__).resolve().parents[1] / "tools/redteam_diagnostics.py"
    spec = importlib.util.spec_from_file_location("private_unavailable_diagnostics_cli", tool)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.main([]) == 1
    assert json.loads(capsys.readouterr().out)["state"] == "unavailable"
