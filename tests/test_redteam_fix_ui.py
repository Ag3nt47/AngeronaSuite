from __future__ import annotations

import hashlib
import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QWidget

from angerona.core import report_attest
from angerona.gui.pages import AARDialog


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _drain(app, dialog) -> None:
    # A completed result is not consumed until its exact retained worker exits.
    deadline = time.monotonic() + 5
    while dialog.has_active_work() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(.005)
    assert not dialog.has_active_work(), "Authenticated report reader did not retire"
    app.processEvents()


def _signed_dialog(tmp_path, monkeypatch, *, parent=None, diagnostic=False):
    # Real locally signed JSON/text/head; no authenticity/eligibility seam is mocked.
    key = tmp_path / "bus.key"
    key.write_text(bytes(range(32)).hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key)
    text = b"Inert fixture report: no host coverage is inferred.\n"
    (tmp_path / "redteam_aar.txt").write_bytes(text)
    report_path = tmp_path / "redteam_aar.json"
    report_attest.write_signed_json(report_path, {
        "run_id": "ui-fixture-run", "report_kind": "red_team",
        "report_basename": "redteam_aar", "coverage_score_eligible": not diagnostic,
        "diagnostic_only": diagnostic, "verdicts": [],
        "report_text_sha256": hashlib.sha256(text).hexdigest(),
    })
    report_digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
    head_path = tmp_path / "redteam_aar.head.json"
    report_attest.write_signed_json(head_path, {
        "schema": "angerona.aar-report-head.v2", "sequence": 1,
        "report_basename": "redteam_aar", "report_kind": "red_team",
        "run_id": "ui-fixture-run", "report_json_sha256": report_digest,
    })
    binding = {
        "run_id": "ui-fixture-run", "sha256": report_digest,
        "head_sha256": hashlib.sha256(head_path.read_bytes()).hexdigest(), "sequence": 1,
    }
    dialog = AARDialog(tmp_path, parent=parent, redteam=True,
                       report_binding=binding, on_attempt_fix=lambda _progress: "unused")
    dialog.refresh()
    _drain(_app(), dialog)
    assert dialog._saved_report_verified
    assert dialog._report_binding["coverage_score_eligible"] is (not diagnostic)
    assert dialog._report_binding["diagnostic_only"] is diagnostic
    return dialog


def test_practice_fix_controls_unlock_only_after_green_verification(tmp_path, monkeypatch) -> None:
    app = _app()
    dialog = _signed_dialog(tmp_path, monkeypatch)
    try:
        assert dialog._test_fix_btn.isHidden()
        assert dialog._source_btn.isHidden()

        dialog._on_fix_progress(63, "Testing detector response")
        assert dialog._fix_spinner._pct == 63
        assert "63%" in dialog._fix_spinner._label.text()

        dialog._show_fix_result("[PRACTICE FIX PARTIAL] 0/1 passed")
        assert dialog._test_fix_btn.isHidden()
        assert dialog._source_btn.isHidden()

        dialog._show_fix_result("[PRACTICE FIX VERIFIED] 1/1 passed")
        _drain(app, dialog)
        assert not dialog._test_fix_btn.isHidden()
        assert not dialog._source_btn.isHidden()
        assert dialog._fix_spinner._pct == 100
        assert dialog._fix_spinner._label.text().startswith("✓")
        assert not dialog._fix_spinner._ring._timer.isActive()

        dialog._show_fix_result("[PRACTICE FIX PARTIAL] retest failed")
        assert dialog._test_fix_btn.isHidden()
        assert dialog._source_btn.isHidden()
    finally:
        _drain(app, dialog)
        dialog.close()
        app.processEvents()


def test_green_practice_result_refreshes_score_before_showing_receipt(
    tmp_path, monkeypatch,
) -> None:
    app = _app()
    dialog = _signed_dialog(tmp_path, monkeypatch)
    refreshed: list[bool] = []
    real_refresh = dialog.refresh

    def refresh():
        refreshed.append(True)
        real_refresh()

    monkeypatch.setattr(dialog, "refresh", refresh)
    try:
        dialog._show_fix_result("[PRACTICE FIX VERIFIED] 1/1 passed")
        _drain(app, dialog)
        assert refreshed == [True]
        assert "PRACTICE FIX VERIFIED" in dialog.body.toPlainText()
        assert dialog._saved_report_verified
    finally:
        _drain(app, dialog)
        dialog.close()
        app.processEvents()


@pytest.mark.parametrize("scope", ["unverified", "diagnostic"])
def test_verified_result_text_cannot_unlock_without_authenticated_complete_source(
    tmp_path, monkeypatch, scope,
) -> None:
    app = _app()
    dialog = (_signed_dialog(tmp_path, monkeypatch, diagnostic=True)
              if scope == "diagnostic" else
              AARDialog(tmp_path, redteam=True, on_attempt_fix=lambda _progress: "unused"))
    try:
        dialog._show_fix_result("[PRACTICE FIX VERIFIED] 1/1 passed")
        assert dialog._test_fix_btn.isHidden()
        assert dialog._source_btn.isHidden()
        assert not dialog._fix_btn.isEnabled()
        assert not dialog.has_active_work()
    finally:
        _drain(app, dialog)
        dialog.close()
        app.processEvents()


def test_verified_source_button_opens_exact_detector_in_sandbox(
    tmp_path, monkeypatch,
) -> None:
    app = _app()

    class Parent(QWidget):
        def __init__(self) -> None:
            super().__init__()
            self.manager = object()
            self.bus = object()

    parent = Parent()
    calls = []
    sentinel = object()
    from angerona.gui import sandbox_editor

    monkeypatch.setattr(
        sandbox_editor,
        "launch_sandbox_editor",
        lambda manager, bus, **kwargs: calls.append((manager, bus, kwargs)) or sentinel,
    )
    dialog = _signed_dialog(tmp_path, monkeypatch, parent=parent)
    try:
        dialog._show_fix_result("[PRACTICE FIX VERIFIED] 1/1 passed")
        _drain(app, dialog)
        dialog._open_fix_source()
        assert dialog._sandbox is sentinel
        assert calls == [(
            parent.manager,
            parent.bus,
            {"parent": parent, "preselect": "Purple Remediation Guard"},
        )]
    finally:
        _drain(app, dialog)
        dialog.close()
        parent.close()
        app.processEvents()
