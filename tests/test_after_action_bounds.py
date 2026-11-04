"""Bounded after-action previews and complete explicit report exports."""
from copy import deepcopy
import json
import time
from types import SimpleNamespace

import pytest
from PySide6.QtWidgets import QApplication

from angerona.gui import breach_display as ui


@pytest.fixture(scope="module", autouse=True)
def _application():
    application = QApplication.instance() or QApplication([])
    yield application


def _large_report():
    # Noise intentionally precedes the real outcome to exercise prioritization.
    return dict(events=[dict(index=index, message="inert event " + "x" * 45) for index in range(5001)],
                state="completed", message="Selected workflow finished; review findings and coverage.",
                request_id="a" * 32,
                scan_progress=dict(stage="finished", finished=4, total=4,
                                   native_state="completed", tool_state="findings"),
                native=dict(state="completed", coverage={"not_checked": ["synthetic unsupported source"]}),
                details=dict(zero_breach=dict(state="findings", coverage_incomplete=True,
                                             match_counts=dict(confirmed=0, review=2),
                                             findings=[dict(message="inert lead", path="D:/synthetic/History")],
                                             evidence="quote:\" newline:\n null:\x00 non-BMP: \U0001f6e1 " + "z" * 120000)))


def _parse(text):
    def invalid_constant(value):
        pytest.fail("Invalid JSON constant in review: " + value)
    return json.loads(text, parse_constant=invalid_constant)


def test_large_projection_is_valid_bounded_explicit_and_keeps_actual_scanner_outcomes():
    report = _large_report()
    before = deepcopy(report)
    assert len(json.dumps(report, indent=2)) > ui._REVIEW_CHAR_LIMIT
    rendered = ui._render_review_json(report)
    value = _parse(rendered)
    assert len(rendered) <= ui._REVIEW_CHAR_LIMIT
    assert rendered.count("\n") + 1 < ui._REVIEW_BLOCK_LIMIT
    assert value["review_display"]["omission_counts"]
    assert value["review_display"]["omitted_locations"]
    access = value["review_display"]["original_access"]
    assert "Copy complete JSON (2 MiB limit)" in access
    assert "Export complete JSON (64 MiB limit)" in access
    assert "retained report is unchanged" in access
    assert value["overview"]["state"] == "completed"
    assert value["overview"]["workflow"] == dict(stage="finished", finished=4, total=4,
                                                  native_state="completed", tool_state="findings")
    assert value["overview"]["scanners"]["zero_breach"]["state"] == "findings"
    assert value["overview"]["scanners"]["zero_breach"]["coverage_incomplete"] is True
    assert value["overview"]["scanners"]["native"]["state"] == "completed"
    assert report == before  # preview omissions never mutate the retained source


def test_small_complete_report_keeps_literal_data_and_json_shape():
    report = dict(state="findings", text="<b>literal</b> \x00 \n \" \\ \U0001f6e1", rows=[1, 2, 3])
    assert _parse(ui._render_review_json(report)) == report


def test_projection_handles_cycles_depth_unsupported_values_and_nonfinite_numbers():
    cycle = []
    cycle.append(cycle)
    deep = []
    selected = deep
    for _ in range(100):
        child = []
        selected.append(child)
        selected = child

    class Unsupported:
        def __str__(self):
            pytest.fail("Projection must not call an untrusted representation")

    rendered = ui._render_review_json(dict(state="unavailable", cycle=cycle, deep=deep,
                                          unknown=Unsupported(), nan=float("nan")))
    parsed = _parse(rendered)
    assert parsed["overview"]["state"] == "unavailable"
    assert parsed["review_display"]["omission_counts"]
    assert len(rendered) <= ui._REVIEW_CHAR_LIMIT


def test_full_chunks_preserve_the_entire_report_not_the_projection():
    report = _large_report()
    encoded = b"".join(ui._complete_report_chunks(report, ui._REVIEW_COPY_LIMIT))
    assert _parse(encoded) == report
    assert len(encoded) > ui._REVIEW_CHAR_LIMIT
    assert _parse(encoded)["details"]["zero_breach"]["evidence"].endswith("z" * 120000)


def test_complete_chunks_fail_explicitly_at_size_cycle_and_depth_limits():
    with pytest.raises(ValueError):
        b"".join(ui._complete_report_chunks(_large_report(), 256))
    cycle = []
    cycle.append(cycle)
    with pytest.raises(ValueError, match="cyclic"):
        b"".join(ui._complete_report_chunks(cycle, ui._REVIEW_EXPORT_LIMIT))
    deep = []
    selected = deep
    for _ in range(100):
        child = []
        selected.append(child)
        selected = child
    with pytest.raises(ValueError, match="depth"):
        b"".join(ui._complete_report_chunks(deep, ui._REVIEW_EXPORT_LIMIT))


@pytest.mark.parametrize("report", [
    {1: "numeric key", "1": "string key"},
    {None: "null key", "null": "string key"},
    {False: "boolean key", "false": "string key"},
    {1.5: "float key", "1.5": "string key"},
])
def test_complete_json_refuses_non_string_key_coercion_and_projection_marks_omission(report):
    before = dict(report)
    with pytest.raises(ValueError, match="exact string object keys"):
        b"".join(ui._complete_report_chunks(report, ui._REVIEW_EXPORT_LIMIT))
    displayed = _parse(ui._render_review_json(report))
    assert displayed["review_display"]["omission_counts"]["object members"] == 1
    expected = {key: value for key, value in report.items() if type(key) is str}
    assert displayed["report_preview"] == expected
    assert report == before


def test_real_qt_large_and_over_4000_line_report_keep_json_prefix_and_suffix():
    report = _large_report()
    assert json.dumps(report, indent=2).count("\n") > 4000
    dialog = ui.AfterActionReportDialog(report)
    dialog.show()
    QApplication.processEvents()
    try:
        value = _parse(dialog.text.toPlainText())
        assert dialog.text.toPlainText().startswith("{")
        assert dialog.text.toPlainText().endswith("}")
        assert dialog.text.document().blockCount() < ui._REVIEW_BLOCK_LIMIT
        assert dialog.text.document().maximumBlockCount() == ui._REVIEW_BLOCK_LIMIT
        assert value["overview"]["workflow"]["tool_state"] == "findings"
        assert dialog._report is report and dialog._confirmed is False
        for name in ("isolate", "patch", "kill", "lift_lockdown", "review_resolved"):
            assert not dialog.actions[name].isEnabled()
    finally:
        dialog.close()
        dialog.deleteLater()


def test_update_keeps_selection_scroll_and_trace_mode(monkeypatch):
    details = [("record-" + str(index), "inert review " + "x" * 180) for index in range(60)]
    report = dict(state="held", request_id="a" * 32, details=details, sequence=1)
    dialog = ui.AfterActionReportDialog(report)
    dialog.show()
    QApplication.processEvents()
    try:
        cursor = dialog.text.document().find("record-35")
        assert cursor.hasSelection()
        dialog.text.setTextCursor(cursor)
        dialog.text.verticalScrollBar().setValue(dialog.text.verticalScrollBar().maximum() // 2)
        position = dialog.text.verticalScrollBar().value()
        selected = dialog.text.textCursor().selectedText()
        dialog.update_report(dict(report, sequence=2))
        assert _parse(dialog.text.toPlainText())["sequence"] == 2
        assert dialog.text.verticalScrollBar().value() == position
        assert dialog.text.textCursor().selectedText() == selected
        assert dialog.text.document().maximumBlockCount() == ui._REVIEW_BLOCK_LIMIT

        dialog.show_trace()
        dialog.update_report(dict(report, sequence=3))
        assert dialog._view == "trace"
        assert "does not contact a remote target" in _parse(dialog.text.toPlainText())["review"]

        from angerona.gui import component_heartbeat
        monkeypatch.setattr(component_heartbeat, "_update_details_text",
                            lambda *_args: pytest.fail("Unchanged JSON should not edit the document"))
        dialog.update_report(dict(report, sequence=4))  # trace does not include sequence
    finally:
        dialog.close()
        dialog.deleteLater()


def test_update_uses_finite_transient_bound_then_restores_4000(monkeypatch):
    from angerona.gui import component_heartbeat
    original = component_heartbeat._update_details_text
    seen = []

    def observed(view, rendered):
        seen.append(view.document().maximumBlockCount())
        return original(view, rendered)

    monkeypatch.setattr(component_heartbeat, "_update_details_text", observed)
    dialog = ui.AfterActionReportDialog(dict(state="held"))
    # A valid old document close to the previous widget limit. Updating it
    # must not discard its JSON prefix during reverse incremental edits.
    previous = '{"old": [\n' + ',\n'.join("0" for _ in range(3980)) + '\n]}'
    dialog.text.setPlainText(previous)
    try:
        dialog.update_report(_large_report())
        assert seen == [ui._REVIEW_BLOCK_LIMIT * 2]
        assert dialog.text.document().maximumBlockCount() == ui._REVIEW_BLOCK_LIMIT
        assert dialog.text.document().blockCount() < ui._REVIEW_BLOCK_LIMIT
        assert _parse(dialog.text.toPlainText())["overview"]["workflow"]["tool_state"] == "findings"
    finally:
        dialog.close()
        dialog.deleteLater()


def test_copy_complete_is_not_excerpt_and_failure_preserves_clipboard(monkeypatch):
    values = ["prior clipboard"]
    clipboard = SimpleNamespace(setText=lambda value: values.append(value))
    monkeypatch.setattr(ui.QApplication, "clipboard", lambda: clipboard)
    report = _large_report()
    dialog = ui.AfterActionReportDialog(report)
    try:
        assert dialog.copy_complete_report()
        assert _parse(values[-1]) == report
        monkeypatch.setattr(ui, "_REVIEW_COPY_LIMIT", 64)
        previous = values[-1]
        assert not dialog.copy_complete_report()
        assert values[-1] == previous
        assert "not copied" in dialog.review_status.text()
    finally:
        dialog.close()
        dialog.deleteLater()


def test_export_is_complete_atomic_and_limit_failure_preserves_existing_file(tmp_path, monkeypatch):
    target = tmp_path / "owned-after-action.json"
    monkeypatch.setattr(ui.QFileDialog, "getSaveFileName", lambda *_args: (str(target), "JSON reports (*.json)"))
    report = _large_report()
    dialog = ui.AfterActionReportDialog(report)
    requests = []
    dialog.action_requested.connect(requests.append)
    try:
        assert dialog.export_complete_report()
        deadline = time.monotonic() + 5
        while dialog._export_handles and time.monotonic() < deadline:
            QApplication.instance().processEvents()
            time.sleep(.005)
        assert not dialog._export_handles
        original = target.read_bytes()
        assert _parse(original) == report
        monkeypatch.setattr(ui, "_REVIEW_EXPORT_LIMIT", 64)
        assert not dialog.export_complete_report()
        assert target.read_bytes() == original
        assert "not exported" in dialog.review_status.text()
        assert not requests and dialog._report is report and not dialog._confirmed
        assert not [path for path in tmp_path.iterdir() if path != target]
    finally:
        dialog.close()
        dialog.deleteLater()


@pytest.mark.parametrize("report", [
    {1: "numeric key", "1": "string key"},
    {None: "null key", "null": "string key"},
    {False: "boolean key", "false": "string key"},
    {1.5: "float key", "1.5": "string key"},
])
def test_mixed_key_refusal_preserves_clipboard_prior_export_and_original(tmp_path, monkeypatch, report):
    values = ["preserved clipboard"]
    monkeypatch.setattr(ui.QApplication, "clipboard",
                        lambda: SimpleNamespace(setText=lambda value: values.append(value)))
    target = tmp_path / "owned-prior-report.json"
    prior = b'{"state":"preserved prior report"}'
    target.write_bytes(prior)
    monkeypatch.setattr(ui.QFileDialog, "getSaveFileName", lambda *_args: (str(target), "JSON reports (*.json)"))
    before = dict(report)
    dialog = ui.AfterActionReportDialog(report)
    requests = []
    dialog.action_requested.connect(requests.append)
    try:
        assert not dialog.copy_complete_report()
        assert values == ["preserved clipboard"]
        assert "exact string object keys" in dialog.review_status.text()
        assert not dialog.export_complete_report()
        assert target.read_bytes() == prior
        assert "exact string object keys" in dialog.review_status.text()
        assert not [path for path in tmp_path.iterdir() if path != target]
        assert dialog._report is report and report == before
        assert not requests and not dialog._confirmed
    finally:
        dialog.close()
        dialog.deleteLater()


def _scanner_review_fixture():
    return dict(
        state="incomplete", request_id="b" * 32,
        native=dict(state="completed", coverage_incomplete=True,
                    finding_counts=dict(advisory=2, omitted=1),
                    findings=[dict(classification="advisory", evidence_type="chromium-hsts",
                                   summary="Local browser record needs review.", response_authorized=False,
                                   source="https://example.invalid/technical-only")],
                    coverage=dict(processes=dict(complete=False),
                                  artifact_checks=dict(browser=dict(state="partial", checked=1, skipped=1)))),
        details=dict(zero_breach=dict(
            state="findings", coverage_incomplete=True,
            match_counts=dict(total=4, tool_findings=1, references=2, withdrawn=1, displayed=3, omitted=1),
            findings=[dict(classification="reference", indicator="contextual-match"),
                      dict(classification="tool-finding", indicator="reviewable-match"),
                      dict(classification="withdrawn", indicator="retired-match")],
            coverage=dict(not_checked=json.dumps([dict(check="Private browser profile", reason="Access denied")])))),
        technical_only="retained-marker", sequence=1,
    )


def test_spyware_report_starts_in_plain_english_and_keyboard_opens_technical_details():
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QLabel

    report = _scanner_review_fixture()
    sample_path = r"C:\Users\Fixture\AppData\Local\Temp\review-only.exe"
    report["native"]["finding_counts"]["advisory"] = 3
    report["native"]["findings"].append(dict(
        classification="advisory", evidence_type="windows-temp-file",
        summary=f"Review {sample_path}", path=sample_path, response_authorized=False,
    ))
    report["native"]["coverage"]["artifact_checks"]["windows-temp"] = dict(
        state="partial", checked=3, skipped=1, reason="directory-queue-limit",
    )
    dialog = ui.AfterActionReportDialog(report, scanner_review=True)
    dialog.show()
    QApplication.processEvents()
    try:
        summary = dialog.summary_text.toPlainText()
        assert dialog.summary_text.isVisible() and dialog.summary_text.isReadOnly()
        assert not dialog.text.isVisible()
        assert "Native Angerona advisories" in summary and "This scan recorded 3 native advisories" in summary
        assert "Browser security record" in summary and "Local browser record needs review" in summary
        assert "Windows temporary-file advisory" in summary
        assert summary.index("Zero-Breach toolkit findings and references") < summary.index("private scan folder")
        assert "It may miss your configured Windows temporary folder" in summary
        assert "1 finding, 2 contextual references, and 1 withdrawn entry." in summary
        assert summary.index("Finding — reviewable-match") < summary.index("Reference — contextual-match")
        assert "Withdrawn entry — retired-match" in summary
        assert "Coverage gaps" in summary and "Private browser profile" in summary and "Access denied" in summary
        assert "Process inventory was limited or unavailable" in summary
        assert "Native browser records had limits. Checked 1 and skipped 1." in summary
        assert ("Native Windows temporary-file sample was incomplete. Checked 3 files. "
                "The sample reached its limit for folders it could queue.") in summary
        assert "infection-free" in summary
        assert "technical-only" not in summary and "retained-marker" not in summary
        assert "review-only.exe" not in summary
        assert dialog._report is report
        assert not any(dialog.actions[name].isEnabled() for name in ("isolate", "patch", "kill", "lift_lockdown"))

        button = dialog.technical_details_button
        assert button.isCheckable() and button.accessibleName() == "Show technical details"
        button.setFocus()
        QTest.keyClick(button, Qt.Key.Key_Space)
        assert button.isChecked() and dialog.text.isVisible()
        assert button.accessibleName() == "Hide technical details"
        assert any(label.isVisible() and "A coverage gap is" in label.text() for label in dialog.findChildren(QLabel))
        assert _parse(dialog.text.toPlainText()) == report
        QTest.keyClick(button, Qt.Key.Key_Space)
        assert not button.isChecked() and not dialog.text.isVisible()
    finally:
        dialog.close()
        dialog.deleteLater()


def test_spyware_report_reuse_preserves_disclosure_and_original_copy(monkeypatch):
    values = []
    monkeypatch.setattr(ui.QApplication, "clipboard",
                        lambda: SimpleNamespace(setText=lambda value: values.append(value)))
    report = _scanner_review_fixture()
    dialog = ui.AfterActionReportDialog(report, scanner_review=True)
    dialog.show()
    QApplication.processEvents()
    try:
        dialog.technical_details_button.click()
        cursor = dialog.text.document().find("retained-marker")
        assert cursor.hasSelection()
        dialog.text.setTextCursor(cursor)

        refreshed = dict(report, sequence=2)
        dialog.update_report(refreshed, confirmed=False)
        dialog.show_investigation()  # Same view as an ordinary controller reopen.
        assert dialog.text.isVisible() and dialog.text.textCursor().selectedText() == "retained-marker"
        assert _parse(dialog.text.toPlainText()) == refreshed
        assert dialog.copy_complete_report() and _parse(values[-1]) == refreshed

        dialog.technical_details_button.click()
        assert not dialog.text.isVisible()
        dialog.show_trace()
        assert dialog.technical_details_button.isChecked() and dialog.text.isVisible()
        assert "does not contact a remote target" in _parse(dialog.text.toPlainText())["review"]
        dialog.update_report(dict(refreshed, sequence=3), confirmed=False)
        assert dialog._view == "trace" and dialog.text.isVisible()
        assert "does not contact a remote target" in _parse(dialog.text.toPlainText())["review"]
    finally:
        dialog.close()
        dialog.deleteLater()


def test_spyware_summary_bounds_literal_data_and_refuses_untyped_counts():
    class Unsupported:
        def __str__(self):
            pytest.fail("Plain summary must not call an unsupported representation")

        def __eq__(self, _other):
            pytest.fail("Plain summary must not compare an unsupported state or classification")

    bad = Unsupported()
    report = dict(state=bad, error="literal <b>not markup</b>\x00\u202e " + "x" * 10000,
                  native=dict(state=bad, finding_counts=dict(advisory=True, omitted=0),
                              findings=[dict(classification=bad, summary=bad)]),
                  details=dict(zero_breach=dict(
                      state=bad, match_counts=dict(total=True), findings=[dict(classification=bad)] * 1000,
                      coverage=dict(not_checked="[" * 8100))))
    summary = ui._plain_scan_summary(report)
    assert "Status was not recorded" in summary
    assert "A count of native advisories was not recorded" in summary
    assert "Toolkit classification counts were not recorded" in summary
    assert "<b>not markup</b>" in summary and "\x00" not in summary and "\u202e" not in summary
    assert "x" * 240 not in summary and len(summary) < 4096
    assert "cannot establish" in summary


@pytest.mark.parametrize(("sample", "count_text"), [
    (dict(state="completed", checked=1, skipped=0), "checked 1 file."),
    (dict(state="completed", checked=0, skipped=0), "checked 0 files."),
    (dict(state="completed", checked=64, skipped=0), "checked 64 files."),
    (dict(state="completed", checked=65, skipped=0), None),
    (dict(state="completed", checked=True, skipped=0), None),
    (dict(state="completed", checked=4, skipped=False), None),
    (None, None),
])
def test_spyware_summary_shows_only_recorded_windows_temp_sample_counts(sample, count_text):
    checks = {} if sample is None else {"windows-temp": sample}
    report = dict(native=dict(state="completed", coverage_incomplete=False,
                              coverage=dict(artifact_checks=checks)),
                  details=dict(zero_breach=dict(state="disabled")))

    summary = ui._plain_scan_summary(report)

    if count_text is None:
        assert "Windows temporary-file" not in summary
    else:
        assert f"The Windows temporary-file sample {count_text}" in summary
    assert "private scan folder" not in summary


@pytest.mark.parametrize(("checked", "count_text"), [(0, " Checked 0 files."), (True, ""), (65, "")])
def test_spyware_summary_keeps_unknown_windows_temp_diagnostics_in_technical_details(checked, count_text):
    report = _scanner_review_fixture()
    checks = report["native"]["coverage"]["artifact_checks"]
    checks["windows-temp"] = dict(state="partial", checked=checked, skipped=1, reason="C:/Private/Temp")
    checks["browser"]["reason"] = "directory-queue-limit"

    summary = ui._plain_scan_summary(report)

    line = next(line for line in summary.splitlines() if "Native Windows temporary-file sample" in line)
    assert line == f"• Native Windows temporary-file sample was incomplete.{count_text}"
    assert "C:/Private/Temp" not in summary
    assert "folders it could queue" not in summary
