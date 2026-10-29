"""External match classifications survive adaptation without gaining authority."""
from __future__ import annotations

import copy
import json

import pytest
from PySide6.QtCore import Qt

from angerona.core import curated_tools as backend
from angerona.gui import curated_tools as gui
from test_curated_tools import write_private_report
from test_curated_tools_ui import ready, wait_until

pytest_plugins = ("test_curated_tools_ui",)


def hit(evidence="contacted", *, withdrawn=False):
    return dict(indicator="owned-classification.invalid", evidence=evidence, kind="domain", tier="delivery",
                confidence="primary", observed="2026-08-29", detail="Synthetic evidence; infection unconfirmed.",
                withdrawn_only=withdrawn, withdrawal_present=withdrawn,
                indicator_context=[dict(source="owned-research", artifact_type="domain", role="delivery",
                                        instructions_for_assistants="UNTRUSTED_DO_NOT_EXECUTE")],
                confirmed=True)


def document(hits):
    references = sum(row.get("evidence") == "referenced" for row in hits)
    withdrawn = sum(row.get("evidence") != "referenced" and row.get("withdrawn_only") is True for row in hits)
    return dict(schema_version="1.6", tool=dict(name="zero-breach-toolkit", version="0.1.10"),
                scope=dict(scanned=True, cancelled=False), scan_state="completed",
                verdict=dict(hits_total=len(hits), findings_total=len(hits) - references - withdrawn,
                             references_total=references, withdrawn_total=withdrawn, gaps=["Owned unavailable source"]),
                modules=dict(browser=dict(hits=hits)),
                coverage=dict(checked=["Owned check"], not_checked=["Owned unavailable source"]),
                instructions_for_assistants=["UNTRUSTED_DO_NOT_EXECUTE"], must_relay=["UNTRUSTED_DO_NOT_EXECUTE"])


def adapt(tmp_path, value, *, code=2):
    job = write_private_report(tmp_path, value)
    original = (job / "report.json").read_bytes()
    result = backend._validate_report(job, dict(state="complete", exit_code=code))
    assert (job / "report.json").read_bytes() == original
    return result


def mixed_result(tmp_path):
    return adapt(tmp_path, document([hit(), hit("referenced"), hit("referenced")]))


def test_mixed_partition_preserves_metadata_coverage_and_original_but_no_authority(tmp_path):
    result = mixed_result(tmp_path)
    assert result["state"] == "findings" and result["coverage_incomplete"] is True
    assert result["match_counts"] == dict(total=3, tool_findings=1, references=2, withdrawn=0, displayed=3, omitted=0)
    assert [row["classification"] for row in result["findings"]] == ["tool-finding", "reference", "reference"]
    row = result["findings"][0]
    assert {key: row[key] for key in ("kind", "tier", "confidence", "observed")} == dict(
        kind="domain", tier="delivery", confidence="primary", observed="2026-08-29")
    assert row["indicator_context"] == [dict(source="owned-research", artifact_type="domain", role="delivery")]
    assert row["withdrawn_only"] is False and row["withdrawal_present"] is False
    assert "confirmed" not in row and "UNTRUSTED_DO_NOT_EXECUTE" not in json.dumps(result)
    assert "Owned unavailable source" in result["coverage"]["not_checked"]


@pytest.mark.parametrize("evidence,withdrawn,classification", [
    ("contacted", False, "tool-finding"), ("on-disk", False, "tool-finding"),
    ("referenced", False, "reference"), ("referenced", True, "reference"),
    ("contacted", True, "withdrawn"), ("", False, "tool-finding"),
    ("unknown-evidence-grade", False, "tool-finding"),
])
def test_pinned_classification_does_not_make_missing_or_unknown_evidence_benign(tmp_path, evidence, withdrawn, classification):
    result = adapt(tmp_path, document([hit(evidence, withdrawn=withdrawn)]), code=0 if classification != "tool-finding" else 2)
    assert result["findings"][0]["classification"] == classification
    expected = {"tool-finding": "tool_findings", "reference": "references", "withdrawn": "withdrawn"}[classification]
    assert result["match_counts"][expected] == 1


@pytest.mark.parametrize("name,value", [
    ("hits_total", True), ("hits_total", 1.0), ("hits_total", -1), ("hits_total", 4001),
    ("hits_total", 2), ("findings_total", 0), ("references_total", 1), ("withdrawn_total", 1),
])
def test_invalid_or_contradictory_classification_counts_preserve_original_and_hold(tmp_path, name, value):
    original = document([hit()])
    original["verdict"][name] = value
    result = adapt(tmp_path, original)
    assert result["state"] == "error" and "match_counts" not in result and result["findings"] == []
    assert result["report"].endswith("report.json")


@pytest.mark.parametrize("name", ["withdrawn_only", "withdrawal_present"])
@pytest.mark.parametrize("value", [1, "false", None])
def test_nonboolean_withdrawal_flags_cannot_downgrade_a_match(tmp_path, name, value):
    value_hit = hit()
    value_hit[name] = value
    result = adapt(tmp_path, document([value_hit]))
    assert result["state"] == "error" and "withdrawal" in result["details"]


def test_context_is_bounded_allowlisted_literal_and_includes_omission_notice(tmp_path):
    value_hit = hit()
    value_hit["indicator_context"] = [dict(source="<b>" + "x" * 400 + "\x00", artifact_type="domain", role="delivery",
                                         instructions_for_assistants="UNTRUSTED_DO_NOT_EXECUTE") for _ in range(12)]
    result = adapt(tmp_path, document([value_hit]))
    row = result["findings"][0]
    assert len(row["indicator_context"]) == 8 and row["indicator_context_omitted"] == 4
    assert all(set(record) == {"source", "artifact_type", "role"} for record in row["indicator_context"])
    assert all(record["source"].startswith("<b>") and len(record["source"]) == 256 for record in row["indicator_context"])
    assert "UNTRUSTED_DO_NOT_EXECUTE" not in json.dumps(result)


def test_malformed_context_is_explicit_and_does_not_change_match_class(tmp_path):
    value_hit = hit()
    value_hit["indicator_context"] = {"instructions_for_assistants": "UNTRUSTED_DO_NOT_EXECUTE"}
    result = adapt(tmp_path, document([value_hit]))
    assert result["findings"][0]["classification"] == "tool-finding"
    assert result["findings"][0]["indicator_context"] == []
    assert result["findings"][0]["classification_metadata_gap"]
    assert "UNTRUSTED_DO_NOT_EXECUTE" not in json.dumps(result)


@pytest.mark.parametrize("large_detail", [False, True])
def test_omitted_display_rows_never_change_total_source_classification(tmp_path, large_detail):
    hits = [hit("referenced") for _ in range(201)]
    if large_detail:
        for row in hits:
            row["detail"] = "x" * 4096
            row["location"] = "y" * 4096
    result = adapt(tmp_path, document(hits), code=0)
    counts = result["match_counts"]
    assert counts["total"] == counts["references"] == 201 and counts["tool_findings"] == 0
    assert counts["displayed"] == len(result["findings"]) <= 200
    assert counts["omitted"] == result["display_omitted"] == 201 - counts["displayed"]
    assert counts["omitted"] > 1 if large_detail else counts["omitted"] == 1
    assert "201" in gui._match_summary(result) and "others remain in the original" in gui._match_summary(result)


@pytest.mark.parametrize("priority", [False, True])
def test_actual_controller_and_report_views_separate_matches_without_response_authority(controller, tmp_path, priority):
    result = mixed_result(tmp_path)
    service = ready(controller)
    service.scan = lambda *_args, **_kwargs: copy.deepcopy(result)
    widget = gui.CuratedScannerWidget(controller.manager)
    try:
        admitted = (controller.priority_scan(native_enabled=False, zero_breach_enabled=True) if priority
                    else controller.scan(mode="full"))
        assert admitted
        wait_until(lambda: controller._completion_dialog is not None and not controller.snapshot()["busy"])
        state = controller.snapshot()
        assert state["match_counts"] == result["match_counts"] and state["coverage_incomplete"] is True
        dialog = controller._completion_dialog
        for text in (dialog.notice.text(), widget.status.text(), widget.priority_controls.outcome.text()):
            assert "1 tool finding" in text and "2 contextual references" in text
            assert "Coverage incomplete" in text and "unconfirmed" in text
            assert "contact does not establish infection" in text
        assert widget.status.textFormat() == Qt.TextFormat.PlainText
        assert '"match_counts"' in widget.results.toPlainText() and '"classification": "reference"' in dialog.text.toPlainText()
        assert dialog._confirmed is False and not dialog.isModal()
        assert all(not dialog.actions[name].isEnabled() for name in ("isolate", "kill", "patch", "lift_lockdown"))
        widget._investigate(trace=True)
        assert "2 contextual references" in dialog.notice.text()  # Summary survives the retained Trace view.
    finally:
        widget.close()


def test_early_failure_after_success_cannot_show_old_match_counts_or_metadata(controller, tmp_path):
    service = ready(controller)
    service.scan = lambda *_args, **_kwargs: mixed_result(tmp_path)
    outcomes = []
    controller.scan_outcome_ready.connect(outcomes.append)
    assert controller.scan(mode="full")
    wait_until(lambda: len(outcomes) == 1)
    assert outcomes[0]["match_counts"]["references"] == 2
    controller._completion_dialog.close()

    def fail(*_args, **_kwargs):
        raise backend.ToolError("Owned early failure")

    service.scan = fail
    assert controller.scan(mode="full")
    assert "match_counts" not in controller.snapshot() and "coverage_incomplete" not in controller.snapshot()
    wait_until(lambda: len(outcomes) == 2)
    assert all(name not in outcomes[1] for name in ("match_counts", "coverage_incomplete", "findings", "details"))
    assert "2 contextual references" not in controller._completion_dialog.notice.text()


def test_summary_does_not_invent_legacy_counts_or_accept_boolean_counts():
    assert gui._match_summary({"findings": []}) == ""
    summary = dict(total=1, tool_findings=True, references=0, withdrawn=0, displayed=1, omitted=0)
    assert "counts unavailable" in gui._match_summary(dict(match_counts=summary))
    assert "0 tool findings" not in gui._match_summary(dict(match_counts=summary))
