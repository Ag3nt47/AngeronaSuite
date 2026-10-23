"""Offline evidence summaries preserve uncertainty and never alter source data."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path

import pytest


def load_summary():
    path = Path(__file__).resolve().parents[1] / "tools" / "summarize_live_debug.py"
    spec = importlib.util.spec_from_file_location("test_live_debug_summary_tool", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def summary():
    return load_summary()


def event(seq=1, message="Fixture issue", *, code="fixture.rule", severity="HIGH", **extra):
    return {"protocol": "angerona-live-debug-v1", "kind": "event", "run_id": "a" * 32,
        "seq": seq, "ts": float(seq), "module": "Fixture Detector", "severity": severity,
        "message": message, "details": {"finding_code": code, "disposition": "active"},
        "original_hmac": "b" * 64, "original_integrity_verified": True, **extra}


def capture(tmp_path, records, name="capture.jsonl"):
    path = tmp_path / name
    path.write_text("".join(json.dumps(row, ensure_ascii=True) + "\n" for row in records), encoding="ascii")
    return path


def test_groups_explicit_rule_with_severity_and_exact_source_metadata(summary, tmp_path):
    rows = [event(), event(2, "Updated evidence", severity="CRITICAL"),
        event(3, code="different.rule"), event(4, module="Other Detector")]
    before = copy.deepcopy(rows)
    path = capture(tmp_path, rows)
    original = path.read_bytes()
    report = summary.summarize([path])
    assert report["processing_complete"] is True
    assert len(report["cases"]) == 3
    case = next(case for case in report["cases"] if case["occurrences"] == 2)
    assert case["first_seen"] == 1.0 and case["last_seen"] == 2.0
    assert case["max_severity"] == "CRITICAL"
    assert case["producer_dispositions"] == {"active": 2}
    assert case["review_status"] == "needs-review"
    assert case["samples"][0]["original_hmac"] == "b" * 64
    assert case["samples"][0]["original_integrity_verified"] is True
    assert "not reverified offline" in case["verification_scope"]
    assert rows == before and path.read_bytes() == original
    assert report["automatic_response"] is False


def test_lexical_cases_do_not_merge_distinct_numeric_security_evidence(summary, tmp_path):
    rows = [event(1, "Failed authentication to port 22", code=""),
        event(2, "Failed authentication to port 443", code=""),
        event(3, "Failed authentication to port 22", code="")]
    report = summary.summarize([capture(tmp_path, rows)])
    assert sorted(case["occurrences"] for case in report["cases"]) == [1, 2]


def test_gap_and_inaccessible_coverage_are_independent_cases(summary, tmp_path):
    gap = event(1, "Coverage failure", kind="gap", source="diagnostics/crash.log", reason="retention", lost_records=4)
    coverage = event(2, "Coverage failure", kind="coverage", source="diagnostics/crash.log",
        state="unavailable", error_type="PermissionError")
    other_coverage = event(3, "Coverage failure", kind="coverage", source="logs/crash.log", state="not-created")
    report = summary.summarize([capture(tmp_path, [gap, coverage, other_coverage])])
    assert len(report["cases"]) == 3
    assert report["counts"]["gap_records"] == 1
    assert report["counts"]["reported_lost_records"] == 4
    assert report["counts"]["inaccessible_records"] == 1
    assert report["evidence_continuity_complete"] is False
    assert all(case["review_status"] == "needs-review" for case in report["cases"])


def test_only_previously_seen_exact_view_digest_binds_local_note(summary, tmp_path):
    target = event()
    annotation = {"protocol": "angerona-live-debug-v1", "kind": "annotation", "run_id": "a" * 32,
        "target_seq": 1, "target_view_sha256": summary.view_sha256(target),
        "verdict": "false-positive", "note": "Reviewed signed installer", "ts": 2.0}
    missing_hash = dict(annotation)
    del missing_hash["target_view_sha256"]
    wrong_hash = dict(annotation, target_view_sha256="c" * 64)
    empty_note = dict(annotation, note=" ")
    wrong_run = dict(annotation, run_id="c" * 32)
    report = summary.summarize([capture(tmp_path, [annotation, target, annotation,
        missing_hash, wrong_hash, empty_note, wrong_run])])
    assert report["counts"]["verified_local_annotations"] == 1
    assert report["counts"]["unverified_local_annotations"] == 5
    case, = report["cases"]
    assert case["review_status"] == "needs-review"
    assert case["local_reviews"][0]["verdict"] == "false-positive"
    assert case["local_reviews"][0]["binding_verified"] is True
    assert case["producer_dispositions"] == {"active": 1}
    assert all(note["binding_verified"] is False for note in report["unverified_local_notes"])


def test_duplicate_capture_does_not_inflate_occurrences_and_conflict_invalidates_note(summary, tmp_path):
    target = event()
    note = {"protocol": "angerona-live-debug-v1", "kind": "annotation", "run_id": "a" * 32,
        "target_seq": 1, "target_view_sha256": summary.view_sha256(target),
        "verdict": "false-positive", "note": "A local opinion", "ts": 2.0}
    path = capture(tmp_path, [target, target, note, dict(target, message="Conflicting contents")])
    report = summary.summarize([path])
    assert report["counts"]["duplicate_records"] == 1
    assert report["counts"]["identity_conflicts"] == 1
    assert report["processing_complete"] is False
    assert report["counts"]["verified_local_annotations"] == 0
    assert any(case["sources"] == ["offline-capture-integrity"] for case in report["cases"])


@pytest.mark.parametrize("raw", [
    b'{"protocol":"angerona-live-debug-v1","kind":"event","kind":"gap"}\n',
    b'{"protocol":"angerona-live-debug-v1","kind":"event","ts":NaN}\n',
    b'{"protocol":"angerona-live-debug-v1","kind":"event","ts":1e9999}\n',
    b'{"unclosed":\n',
    b'\xff\n',
])
def test_malformed_duplicate_or_nonfinite_json_is_explicit_unknown(summary, tmp_path, raw):
    path = tmp_path / "malformed.jsonl"
    path.write_bytes(raw)
    report = summary.summarize([path])
    assert report["counts"]["malformed_json"] == 1
    assert report["processing_complete"] is False
    assert report["cases"] == []
    assert "do not establish a clean host" in report["security_conclusion"]


def test_malicious_field_types_never_crash_or_create_trusted_verdict(summary, tmp_path):
    rows = [dict(event(), kind=[]), event(2, details={"disposition": []}),
        {"protocol": "angerona-live-debug-v1", "kind": "annotation", "run_id": {}, "target_seq": [],
         "verdict": {}, "note": ["malicious"]}]
    report = summary.summarize([capture(tmp_path, rows)])
    assert report["counts"]["invalid_records"] == 1
    assert report["counts"]["unverified_local_annotations"] == 1
    assert report["unverified_local_notes"][0]["verdict"] == "unknown"


def test_oversized_line_is_drained_and_truncated_tail_not_interpreted(summary, tmp_path):
    path = tmp_path / "bounded.jsonl"
    path.write_bytes(b"x" * (summary.MAX_FRAME_BYTES + 5) + b"\n" +
        (json.dumps(event()) + "\n").encode("ascii") + b'{"partial":')
    report = summary.summarize([path])
    assert report["counts"]["oversized_records"] == 1
    assert report["counts"]["truncated_records"] == 1
    assert report["counts"]["event_records"] == 1
    assert report["processing_complete"] is False


def test_input_record_time_and_case_budgets_are_explicit(summary, tmp_path):
    path = capture(tmp_path, [event(index, code=str(index)) for index in range(1, 10)])
    report = summary.summarize([path], max_bytes=50)
    assert report["counts"]["bytes_read"] == 50
    assert report["limits_reached"]["byte_budget_reached"]
    report = summary.summarize([path], max_records=2)
    assert report["counts"]["lines_read"] == 2
    assert report["limits_reached"]["record_budget_reached"]
    report = summary.summarize([path], max_cases=2)
    assert len(report["cases"]) == 2
    assert report["counts"]["case_overflow_records"] == 7
    clock = iter([0.0, 20.0])
    report = summary.summarize([path], monotonic=lambda: next(clock))
    assert report["limits_reached"]["time_budget_reached"]
    assert report["inputs"][0]["state"] == "not-read-budget"
    for seconds in (float("nan"), float("inf"), 0, -1):
        with pytest.raises(ValueError):
            summary.summarize([path], max_seconds=seconds)


def test_linked_or_unrelated_inputs_are_refused_without_reading(summary, tmp_path):
    source = capture(tmp_path, [event()])
    linked = tmp_path / "linked.jsonl"
    os.link(source, linked)
    report = summary.summarize([linked])
    assert report["inputs"][0]["state"] == "unavailable"
    assert report["counts"]["bytes_read"] == 0
    assert report["processing_complete"] is False
    config = tmp_path / "settings.json"
    config.write_text('{"password":"leave-intact"}')
    report = summary.summarize([config])
    assert report["counts"]["bytes_read"] == 0
    assert "leave-intact" not in json.dumps(report)


def test_parent_symlink_is_refused(summary, tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    capture(actual, [event()])
    alias = tmp_path / "alias"
    try:
        os.symlink(actual, alias, target_is_directory=True)
    except OSError:
        pytest.skip("Directory symlink creation unavailable")
    report = summary.summarize([alias / "capture.jsonl"])
    assert report["counts"]["bytes_read"] == 0
    assert report["inputs"][0]["state"] == "unavailable"


def test_samples_redact_secrets_and_have_fixed_bounds(summary, tmp_path):
    secret = "PlainSecretToRemove"
    rows = [event(seq, message=f"password={secret} " + "detail " * 1000) for seq in range(1, 10)]
    report = summary.summarize([capture(tmp_path, rows)])
    case, = report["cases"]
    assert len(case["samples"]) == 2
    assert all(len(sample["text"]) <= 512 for sample in case["samples"])
    assert secret not in json.dumps(report)


def test_explicit_rotated_cli_capture_files_are_supported(summary, tmp_path):
    older = capture(tmp_path, [event(1)], name="events.jsonl.1")
    current = capture(tmp_path, [event(2)], name="events.jsonl")
    report = summary.summarize([older, current])
    assert report["processing_complete"] is True
    assert report["counts"]["event_records"] == 2
    assert report["counts"]["input_files_read"] == 2
    assert report["cases"][0]["occurrences"] == 2


def test_cli_selected_output_is_exclusive_and_empty_capture_is_not_clean(summary, tmp_path, capsys):
    source = capture(tmp_path, [])
    assert summary.main([str(source)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["cases"] == []
    assert report["default_review_status"] == "needs-review"
    assert report["security_conclusion"].startswith("Unknown")
    output = tmp_path / "summary.json"
    assert summary.main([str(source), "--output", str(output)]) == 0
    previous = output.read_bytes()
    assert summary.main([str(source), "--output", str(output)]) == 2
    assert output.read_bytes() == previous
    assert "Summary failed" in capsys.readouterr().err
