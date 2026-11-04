"""Inert offscreen diagnostics DTOs; no simulation, host report or response."""
from __future__ import annotations

import copy
import json
import sys
import threading
import time
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QThread, Qt
from PySide6.QtWidgets import QApplication
from shiboken6 import isValid

from angerona.gui import action_worker as actions
from angerona.gui import simulation_diagnostics as gui


def diagnostic(run_id="fixture-run", statuses=("pass", "fail", "inconclusive")):
    return {"schema": "angerona.simulation-diagnostics.v1", "run_id": run_id,
        "report_kind": "shark", "report_sha256": "1" * 64, "head_sha256": "2" * 64,
        "sequence": 7, "report_state": "complete", "overall_status": "failing",
        "coverage_score_eligible": True, "omitted_rows": 2, "omitted_text_characters": 17,
        "rows": [{"index": index, "stage": "fixture-stage", "technique": "T1059",
            "category": "fixture-category", "detection_status": "pass" if status == "pass" else "inconclusive",
            "response_status": "unscored", "status": status, "reason_code": "fixture-reason",
            "reason": "<b>Untrusted diagnostic text</b> " + "Evidence facts. " * 40,
            "evidence": ["Fixture observation; no response authority."],
            "next_steps": ["Review the bounded fixture and its producer contract."],
            "source_areas": ["src/angerona/modules/fixture.py"],
            "fix_kind": "engineering-review", "fix_status": "not-applied"}
            for index, status in enumerate(statuses)]}


def until(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        QApplication.instance().processEvents()
        time.sleep(.005)
    assert predicate()


@pytest.fixture
def owned(monkeypatch):
    assert not actions.active_finite_actions()
    monkeypatch.setattr(actions, "_CLOSING", False)
    panels, releases = [], []
    yield panels, releases
    for release in releases:
        release.set()
    for panel in panels:
        if isValid(panel):
            panel.close()
    for worker in actions.active_finite_actions():
        if hasattr(worker, "allow_native_proof"):
            worker.allow_native_proof.set()
        worker.requestInterruption()
        if not QThread.isRunning(worker) and not QThread.isFinished(worker):
            QThread.start(worker)  # Fixture-only uncertain-start resolution.
        assert QThread.wait(worker, 3000)
        actions.poll_finite_action_retirement(worker)
    until(lambda: not actions.active_finite_actions())
    for panel in panels:
        if isValid(panel):
            panel.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def panel_for(owned, monkeypatch, data=None, **kwargs):
    data = diagnostic() if data is None else data
    monkeypatch.setattr(gui, "_load_verified_diagnostics", lambda _source, _owner: gui._prepare_snapshot(data))
    panel = gui.SimulationDiagnosticsPanel(handoff="inert-fixture-handoff", **kwargs)
    owned[0].append(panel)
    until(lambda: panel._snapshot is not None and panel._worker is None)
    return panel


def test_inert_modeless_resizable_panel_distinguishes_facts_and_fix_review(owned, monkeypatch):
    original = diagnostic()
    panel = panel_for(owned, monkeypatch, original)
    assert not panel.isModal() and panel.windowModality() == Qt.WindowModality.NonModal
    assert panel.windowFlags() & Qt.WindowType.WindowMinimizeButtonHint
    assert panel.windowFlags() & Qt.WindowType.WindowMaximizeButtonHint
    assert panel.detail.isReadOnly() and panel.summary.textFormat() == Qt.TextFormat.PlainText
    assert panel.model.rowCount() == 3 and "Omitted rows: 2" in panel.summary.text()
    assert "eligible" in panel.summary.text() and "failing" in panel.summary.text()
    assert "characters omitted by producer: 17" in panel.summary.text()
    panel.table.selectRow(1)
    text = panel.detail.toPlainText()
    assert "FACTS FROM THE VERIFIED REPORT" in text and "NO FIX APPLIED BY THIS VIEW" in text
    assert "<b>Untrusted diagnostic text</b>" in text
    assert "fixture.py" in text and not panel.patch_button.isEnabled()
    original["rows"][1]["reason"] = "changed outside the panel"
    assert "changed outside" not in panel.detail.toPlainText()


def test_pass_fail_and_held_filters_never_change_report_verdict(owned, monkeypatch):
    panel = panel_for(owned, monkeypatch)
    for selection, expected in ((1, "pass"), (2, "fail"), (3, "inconclusive")):
        panel.filter.setCurrentIndex(selection)
        assert len(panel.model.rows) == 1 and panel.model.rows[0]["status"] == expected
        assert "failing" in panel.summary.text() and panel._snapshot.data["coverage_score_eligible"]
    panel.filter.setCurrentIndex(0)
    panel.search.setText("T1059")
    assert panel.model.rowCount() == 3
    panel.search.setText("not-a-fixture-term")
    assert panel.model.rowCount() == 0
    assert len(panel._snapshot.data["rows"]) == 3


def test_same_rows_update_keeps_selection_table_and_detail_scroll(owned, monkeypatch):
    payload = diagnostic(statuses=tuple("inconclusive" for _ in range(150)))
    panel = panel_for(owned, monkeypatch, payload)
    panel.show()
    QApplication.instance().processEvents()
    panel.table.selectRow(100)
    panel.table.scrollTo(panel.model.index(95, 0))
    panel.detail.verticalScrollBar().setValue(10)
    vertical = panel.table.verticalScrollBar().value()
    horizontal = panel.table.horizontalScrollBar().value()
    detail = panel.detail.verticalScrollBar().value()
    payload["rows"][100]["reason"] += " Additional verified fixture context."
    assert panel.refresh_diagnostics()
    until(lambda: panel._worker is None)
    assert panel._selected_row()["index"] == 100
    assert panel.table.verticalScrollBar().value() == vertical
    assert panel.table.horizontalScrollBar().value() == horizontal
    assert panel.detail.verticalScrollBar().value() == detail
    assert "Additional verified" in panel.detail.toPlainText()


def test_off_gui_authentication_coalesces_latest_handoff_and_rejects_stale_result(owned, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    owned[1].append(release)
    calls = []
    main_thread = threading.get_ident()

    def load(source, _worker):
        calls.append((source[1], threading.get_ident()))
        if source[1] == "old":
            entered.set()
            assert release.wait(2)
        return gui._prepare_snapshot(diagnostic(run_id=source[1]))

    monkeypatch.setattr(gui, "_load_verified_diagnostics", load)
    panel = gui.SimulationDiagnosticsPanel(handoff="old")
    owned[0].append(panel)
    assert entered.wait(1)
    assert panel.set_handoff("new") and panel.set_handoff("newest")
    assert panel._snapshot is None and panel._refresh_pending
    release.set()
    until(lambda: panel._snapshot is not None and panel._snapshot.data["run_id"] == "newest" and panel._worker is None)
    assert [call[0] for call in calls] == ["old", "newest"]
    assert all(call[1] != main_thread for call in calls)
    assert "old" not in panel.identity.text() and "newest" in panel.identity.text()


def test_load_failure_preserves_previous_verified_data_with_visible_failure(owned, monkeypatch):
    panel = panel_for(owned, monkeypatch)
    previous = panel._snapshot.json_text

    def rejected(_source, _worker):
        raise ValueError("fixture immutable report authentication rejected")

    monkeypatch.setattr(gui, "_load_verified_diagnostics", rejected)
    assert panel.refresh_diagnostics()
    until(lambda: panel._worker is None)
    assert panel._snapshot.json_text == previous
    assert "No new diagnostic result verified" in panel.message.text()
    assert "Previous verified data remains displayed" in panel.message.text()
    assert not panel._activities.snapshot()


def test_real_loader_routes_exact_identity_pins_off_gui_to_authenticator(owned, monkeypatch):
    calls = []
    expected = dict(report_kind="shark", expected_run_id="fixture-run",
        expected_report_sha256="1" * 64, expected_head_sha256="2" * 64, expected_sequence=7)

    def load(data_dir, **arguments):
        calls.append((data_dir, arguments, threading.get_ident()))
        return diagnostic()

    def wrong_route(_handoff):
        raise AssertionError("Handoff path was not selected")

    monkeypatch.setitem(sys.modules, "angerona.core.simulation_diagnostics",
        SimpleNamespace(diagnostics_for_handoff=wrong_route, load_report_diagnostics=load))
    panel = gui.SimulationDiagnosticsPanel(data_dir="inert-unused-data-dir", **expected)
    owned[0].append(panel)
    until(lambda: panel._snapshot is not None and panel._worker is None)
    assert calls == [("inert-unused-data-dir", expected, calls[0][2])]
    assert calls[0][2] != threading.get_ident()


def test_diagnostic_only_ineligible_view_cannot_show_scored_steps(owned, monkeypatch):
    value = diagnostic(statuses=("inconclusive", "unscored"))
    value.update(report_state="diagnostic", overall_status="inconclusive", coverage_score_eligible=False)
    panel = panel_for(owned, monkeypatch, value)
    assert "ineligible" in panel.summary.text() and "inconclusive" in panel.summary.text()
    for group in (1, 2):
        panel.filter.setCurrentIndex(group)
        assert panel.model.rowCount() == 0
    panel.filter.setCurrentIndex(3)
    assert panel.model.rowCount() == 2
    invalid = copy.deepcopy(value)
    invalid["rows"][0]["status"] = "pass"
    with pytest.raises(ValueError):
        gui._prepare_snapshot(invalid)


def test_copy_and_atomic_export_keep_full_json_including_filtered_rows(owned, monkeypatch, tmp_path):
    panel = panel_for(owned, monkeypatch)
    panel.filter.setCurrentIndex(1)
    assert panel.copy_json()
    assert json.loads(QApplication.clipboard().text()) == panel._snapshot.data
    target = tmp_path / "private-diagnostics.json"
    monkeypatch.setattr(gui.QFileDialog, "getSaveFileName", lambda *_args: (str(target), "JSON files (*.json)"))
    threads = []
    original = gui._export_snapshot

    def export(filename, payload, worker):
        threads.append(threading.get_ident())
        return original(filename, payload, worker)

    monkeypatch.setattr(gui, "_export_snapshot", export)
    assert panel.export_json()
    until(lambda: panel._worker is None)
    assert threads and threads[0] != threading.get_ident()
    assert target.read_bytes() == panel._snapshot.json_text.encode("ascii")
    assert len(json.loads(target.read_bytes())["rows"]) == 3
    assert "Complete diagnostics exported" in panel.message.text()
    assert not panel._activities.snapshot()


def test_patch_review_is_detached_plain_data_and_grants_no_panel_mutation(owned, monkeypatch):
    requests = []

    def review(request):
        requests.append(copy.deepcopy(request))
        request["row"]["next_steps"].append("mutated callback copy")

    panel = panel_for(owned, monkeypatch, patch_review=review)
    panel.table.selectRow(1)
    original = panel._snapshot.json_text
    assert panel.review_selected_fix()
    assert requests[0]["diagnostics_identity"]["report_sha256"] == "1" * 64
    assert requests[0]["row"]["index"] == 1
    assert "action_id" not in requests[0] and "saved_artifact" not in requests[0]
    assert panel._snapshot.json_text == original
    assert "mutated callback copy" not in panel._snapshot.data["rows"][1]["next_steps"]
    assert "No change has been applied" in panel.message.text()


def test_modeless_close_reuse_reauthenticates_new_handoff_before_patch_review(owned, monkeypatch):
    requests = []
    panel = panel_for(owned, monkeypatch, patch_review=requests.append)
    panel.table.selectRow(1)
    assert panel.patch_button.isEnabled()
    panel.close()
    assert panel._closed and panel.set_handoff("reopened-fixture")
    calls = []

    def load(source, _worker):
        calls.append(source[1])
        return gui._prepare_snapshot(diagnostic(run_id=source[1]))

    monkeypatch.setattr(gui, "_load_verified_diagnostics", load)
    assert not panel.review_selected_fix()
    panel.show()
    until(lambda: panel._worker is None and panel._snapshot.data["run_id"] == "reopened-fixture")
    assert not panel._closed and calls == ["reopened-fixture"]
    assert panel._snapshot_version == panel._source_version and panel.patch_button.isEnabled()
    assert panel.review_selected_fix()
    assert requests[0]["diagnostics_identity"]["run_id"] == "reopened-fixture"


def test_finished_without_native_wait_proof_does_not_publish_diagnostics(owned, monkeypatch):
    real = actions.FiniteActionWorker

    class HeldWait(real):
        def __init__(self, *args):
            super().__init__(*args)
            self.allow_native_proof = threading.Event()

        def wait(self, timeout=0):
            return super().wait(timeout) if self.allow_native_proof.is_set() else False

    monkeypatch.setattr(actions, "FiniteActionWorker", HeldWait)
    monkeypatch.setattr(gui, "_load_verified_diagnostics", lambda _source, _worker: gui._prepare_snapshot(diagnostic()))
    panel = gui.SimulationDiagnosticsPanel(handoff="fixture")
    owned[0].append(panel)
    worker = panel._worker
    assert QThread.wait(worker, 1500)
    QApplication.instance().processEvents()
    assert panel._snapshot is None and panel._activities.snapshot()
    assert worker in actions.active_finite_actions() and worker in panel._jobs
    assert not actions.poll_finite_action_retirement(worker)
    worker.allow_native_proof.set()
    assert actions.poll_finite_action_retirement(worker)
    assert panel._snapshot is not None and panel._worker is None and not panel._jobs
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert not isValid(worker) and actions.finite_action_retirement_proven(worker)


def test_close_cancels_without_wait_and_independent_registry_keeps_worker(owned, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    owned[1].append(release)

    def load(_source, owner):
        entered.set()
        assert release.wait(2)
        assert owner.isInterruptionRequested()
        return gui._prepare_snapshot(diagnostic())

    monkeypatch.setattr(gui, "_load_verified_diagnostics", load)
    panel = gui.SimulationDiagnosticsPanel(handoff="fixture")
    owned[0].append(panel)
    worker = panel._worker
    assert entered.wait(1)
    panel.close()
    assert worker.isInterruptionRequested() and worker in actions.active_finite_actions()
    assert panel._closed and not panel._activities.snapshot()
    panel.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert not isValid(panel) and isValid(worker)
    release.set()
    until(lambda: not actions.active_finite_actions())
    assert actions.finite_action_retirement_proven(worker)


def test_held_admission_does_not_start_a_cosmetic_only_action(owned, monkeypatch):
    monkeypatch.setattr(gui, "start_finite_action", lambda *_args, **_kwargs: None)
    panel = gui.SimulationDiagnosticsPanel(handoff="fixture", auto_load=False)
    owned[0].append(panel)
    assert not panel.refresh_diagnostics()
    assert panel._worker is None and not panel._jobs and not panel._activities.snapshot()
    assert "admission is held" in panel.message.text() and panel._snapshot is None


def test_raised_start_labels_unproved_native_retirement_and_keeps_exact_owner(owned, monkeypatch):
    real = actions.FiniteActionWorker

    class RaisedStart(real):
        def start(self, *_args, **_kwargs):
            self._start_attempted = True
            raise RuntimeError("fixture uncertain admission")

    monkeypatch.setattr(actions, "FiniteActionWorker", RaisedStart)
    panel = gui.SimulationDiagnosticsPanel(handoff="fixture")
    owned[0].append(panel)
    worker = panel._worker
    assert worker.admission_error and worker in actions.active_finite_actions()
    assert worker in panel._jobs and worker.wait(0) and not worker.isFinished()
    assert not panel._activities.snapshot() and panel._snapshot is None
    assert "retirement is unproved" in panel.message.text()
    assert not actions.poll_finite_action_retirement(worker)
    panel.close()
    QThread.start(worker)  # Test-only late native resolution; not a product retry.
    until(lambda: panel._worker is None and not actions.active_finite_actions())
    assert not panel._jobs and actions.finite_action_retirement_proven(worker)


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(schema="unknown"),
    lambda value: value.update(coverage_score_eligible="yes"),
    lambda value: value.update(omitted_rows=-1),
    lambda value: value.pop("omitted_text_characters"),
    lambda value: value.update(head_sha256="invalid"),
    lambda value: value["rows"].append(copy.deepcopy(value["rows"][0])),
    lambda value: value["rows"][0].update(next_steps="execute raw text"),
    lambda value: value["rows"][0].update(evidence=[{"unexpected": "structured data"}]),
    lambda value: value["rows"][0].update(fix_status="applied"),
])
def test_unexpected_dto_shape_is_rejected_without_partial_or_fictitious_result(mutation):
    value = diagnostic()
    mutation(value)
    with pytest.raises(ValueError):
        gui._prepare_snapshot(value)


def test_bounds_and_arbitrary_objects_are_rejected_without_copy_or_string_hooks(monkeypatch):
    class Untrusted:
        def __str__(self):
            raise AssertionError("arbitrary string hook was called")

        def __deepcopy__(self, _memo):
            raise AssertionError("arbitrary copy hook was called")

    value = diagnostic()
    value["rows"][0]["evidence"].append(Untrusted())
    with pytest.raises(ValueError):
        gui._prepare_snapshot(value)
    cycle = diagnostic()
    cycle["rows"][0]["evidence"].append(cycle)
    with pytest.raises(ValueError):
        gui._prepare_snapshot(cycle)
    monkeypatch.setattr(gui, "_MAX_BYTES", 4096)
    with pytest.raises(ValueError):
        gui._prepare_snapshot(diagnostic(statuses=tuple("inconclusive" for _ in range(20))))
