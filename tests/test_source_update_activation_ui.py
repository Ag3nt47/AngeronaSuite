"""Qt scheduling/consent custody only; no source publication/native efficacy grant."""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QMainWindow, QMessageBox

from angerona.core import source_activation as activation
from angerona.gui.main_window import MainWindow
from angerona.gui.shutdown_retirement import RetainedWorker, ShutdownRetirement
from angerona.gui.update_controller import UpdateController


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


def until(app, predicate, timeout=5):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        app.processEvents()
        if predicate():
            return
        time.sleep(.005)
    assert predicate(), "Exact source-update scheduling fixture did not settle"


def preview(root):
    return {"schema": 1, "status": "ready", "reason": "", "activation_id": "a" * 32,
        "plan_sha256": "b" * 64, "stage_id": "stage-fixture", "manifest_sha256": "c" * 64,
        "resolution_sha256": "d" * 64, "original_inventory_sha256": "e" * 64,
        "original_head": "1" * 40, "target_revision": "2" * 40, "base_revision": "1" * 40,
        "source_root": str(root), "changed_paths": ["src/example.py"], "preserved_changes": 3,
        "conflicts": 0, "dependencies_compatible": True}


def context(root, state):
    # Explicitly inert scheduling input; the REAL core API owns native proof.
    return {"schema": 1, "launch_id": "3" * 32, "source_root": str(root), "state_root": str(state),
        "supervisor_pid": 111, "supervisor_birth": "123", "supervisor_image": "fixed-system-host",
        "broker_pid": 222, "broker_birth": "124", "broker_image": "fixed-system-host",
        "core_pid": 333, "core_birth": "125", "core_image": "fixed-product-image",
        "token": "9" * 64, "owner_state": "bound"}


@pytest.fixture
def owner(app, tmp_path):
    window = QMainWindow()
    root = tmp_path / "source"
    config = SimpleNamespace(data_dir=tmp_path / "data", github_daily_check_enabled=False)
    controller = UpdateController(config, root, window)
    window._update_controller = controller
    controller._activation_initial.stop()  # This test explicitly admits each worker operation.
    yield SimpleNamespace(window=window, root=root, config=config, controller=controller)
    controller.close()
    until(app, lambda: all(not thread.is_alive() for thread in controller.owned_workers()))
    window.close()
    window.deleteLater()


def install_review(monkeypatch, owner, *, supervised=True, entered=None, release=None):
    calls = []
    expected = preview(owner.root)

    def prepare(root, state, stage, manifest, *, cancelled):
        assert threading.current_thread() is not threading.main_thread()
        calls.append((root, state, stage, manifest))
        if entered is not None:
            entered.set()
        if release is not None:
            assert release.wait(3)
        if cancelled():
            raise activation.SourceActivationError("cancelled fixture")
        return dict(expected, changed_paths=list(expected["changed_paths"]))

    monkeypatch.setattr(activation, "prepare_source_activation", prepare)
    monkeypatch.setattr(activation, "current_source_activation_context",
        lambda root, state: context(root, state) if supervised else None)
    return calls


def start_review(app, owner):
    delivered = []
    owner.controller.activation_ready.connect(delivered.append)
    assert owner.controller.review_source_candidate(SimpleNamespace(stage_id="stage-fixture", manifest_sha256="c" * 64))
    until(app, lambda: bool(delivered))
    return delivered[-1]


def test_real_detached_review_delivers_bounded_projection_without_private_context(app, owner, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    calls = install_review(monkeypatch, owner, entered=entered, release=release)
    delivered, ticks = [], []
    owner.controller.activation_ready.connect(delivered.append)
    timer = QTimer(owner.window)
    timer.setInterval(1)
    timer.timeout.connect(lambda: ticks.append(1))
    timer.start()
    try:
        assert owner.controller.review_source_candidate(SimpleNamespace(stage_id="stage-fixture", manifest_sha256="c" * 64))
        assert entered.wait(2)
        until(app, lambda: len(ticks) >= 3)
        assert delivered == [] and owner.controller._activation_review.thread.is_alive()
        release.set()
        until(app, lambda: bool(delivered))
        value = delivered[0]
        assert value["supervised"] is True and value["changed_paths"] == ("src/example.py",)
        assert "token" not in repr(value) and "9" * 64 not in repr(value)
        assert not any(key in value for key in ("context", "broker_pid", "core_birth"))
        assert calls == [(owner.root, owner.config.data_dir / "github-updates", "stage-fixture", "c" * 64)]
        value["changed_paths"] = ("different.py",)
        assert owner.controller._activation_preview["changed_paths"] == ["src/example.py"]
    finally:
        release.set()
        timer.stop()


def test_unsupervised_explicit_yes_queues_only_reconfirmation_and_never_handoff(app, owner, monkeypatch):
    install_review(monkeypatch, owner, supervised=False)
    queued, requests, handoffs = [], [], []
    monkeypatch.setattr(activation, "approve_source_activation", lambda *_a, **_k: requests.append("forbidden"))

    def queue(state, activation_id, plan_sha, *, cancelled):
        assert not cancelled() and threading.current_thread() is not threading.main_thread()
        queued.append((state, activation_id, plan_sha))
        return {"status": "queued-reconfirm", "activation_id": activation_id, "plan_sha256": plan_sha}

    monkeypatch.setattr(activation, "queue_source_activation_proposal", queue)
    owner.controller.activation_request_ready.connect(handoffs.append)
    value = start_review(app, owner)
    assert value["supervised"] is False
    assert owner.controller.approve_activation(value["serial"], accepted=True)
    until(app, lambda: bool(queued) and not owner.controller._activation_request.busy)
    assert requests == [] and handoffs == [] and owner.controller.activation_custody_released()


def test_close_during_durable_approval_revokes_exact_nonce_after_real_writer_retirement(app, owner, monkeypatch):
    install_review(monkeypatch, owner)
    entered, release = threading.Event(), threading.Event()
    durable, cancelled, handoffs = {}, [], []

    def approve(state, activation_id, plan_sha, launch_context, *, accepted, approval_id, cancelled):
        assert accepted is True and launch_context["token"] == "9" * 64
        durable[approval_id] = (activation_id, plan_sha)
        entered.set()
        assert release.wait(3)
        # The API may fail after publication. GUI already owns its nonce.
        raise OSError("inert post-publication fixture failure")

    def cancel(state, activation_id, plan_sha, approval_id):
        assert threading.current_thread() is not threading.main_thread()
        if approval_id not in durable:
            return {"status": "absent"}
        assert durable[approval_id] == (activation_id, plan_sha)
        cancelled.append(approval_id)
        durable.pop(approval_id)
        return {"status": "cancelled"}

    monkeypatch.setattr(activation, "approve_source_activation", approve)
    monkeypatch.setattr(activation, "cancel_source_activation_approval", cancel)
    owner.controller.activation_request_ready.connect(handoffs.append)
    value = start_review(app, owner)
    assert owner.controller.approve_activation(value["serial"], accepted=True)
    assert entered.wait(2)
    exact = owner.controller._activation_consent
    assert not exact.writer_done.is_set() and not exact.shutdown_ready()
    owner.window._shutdown_view_owners = lambda: (owner.window, owner.controller)
    owner.window._aar_report_threads = {}
    owner.window._shutdown_callback = None
    rows = MainWindow._retained_shutdown_workers(owner.window)
    writer = owner.controller._activation_request.thread
    assert any(row.worker is writer and row.before_cleanup is True for row in rows)
    # Real Main discovery must retain the specialized cancellation reader,
    # rather than generic-close it before the durable writer can return.
    assert not owner.controller._activation_cancel._closed
    owner.controller.close()
    assert exact.cancelled.is_set() and not owner.controller.activation_custody_released()
    release.set()
    until(app, lambda: bool(cancelled) and owner.controller.activation_custody_released())
    until(app, lambda: all(not thread.is_alive() for thread in owner.controller.owned_workers()))
    assert handoffs == [] and durable == {} and cancelled == [exact.approval_id]


def test_changed_request_or_unknown_cancel_remains_real_stop_custody(app, owner, monkeypatch):
    install_review(monkeypatch, owner)
    monkeypatch.setattr(activation, "approve_source_activation", lambda state, activation_id, plan_sha, ctx, **kw:
        {"status": "requested", "activation_id": activation_id, "plan_sha256": plan_sha, "request_sha256": "f" * 64})
    cancelled = threading.Event()

    def hold(*args):
        cancelled.set()
        return {"status": "held"}

    monkeypatch.setattr(activation, "cancel_source_activation_approval", hold)
    value = start_review(app, owner)
    assert owner.controller.approve_activation(value["serial"], accepted=True)
    until(app, cancelled.is_set)  # No synchronous receiver accepted the result.
    assert not owner.controller.activation_custody_released()
    exact = owner.controller._activation_consent
    assert exact.request["request_sha256"] == "f" * 64 and exact.cancellation_proven is False


def test_only_current_exact_durable_delivery_can_handoff(app, owner, monkeypatch):
    install_review(monkeypatch, owner)
    seen = []
    monkeypatch.setattr(activation, "approve_source_activation", lambda state, activation_id, plan_sha, ctx, **kw:
        {"status": "requested", "activation_id": activation_id, "plan_sha256": plan_sha, "request_sha256": "f" * 64})

    def receive(value):
        assert owner.controller.accept_activation_handoff(dict(value, serial=value["serial"] - 1)) is None
        assert owner.controller.accept_activation_handoff(dict(value, request_sha256="0" * 64)) is None
        seen.append(owner.controller.accept_activation_handoff(value))

    owner.controller.activation_request_ready.connect(receive)
    value = start_review(app, owner)
    assert owner.controller.approve_activation(value["serial"], accepted=False) is False
    assert owner.controller.approve_activation(value["serial"], accepted=True)
    until(app, lambda: bool(seen))
    assert seen == [{"launch_id": "3" * 32, "activation_id": "a" * 32,
        "request_sha256": "f" * 64, "core_pid": 333, "core_birth": "125"}]
    assert owner.controller._activation_consent.handoff is True
    assert owner.controller.activation_custody_released()


def test_reentrant_review_cannot_discard_exact_handoff_before_failed_stop_revokes_it(app, owner, monkeypatch):
    install_review(monkeypatch, owner)
    cancelled, received = [], []
    monkeypatch.setattr(activation, "approve_source_activation", lambda state, activation_id, plan_sha, ctx, **kw:
        {"status": "requested", "activation_id": activation_id, "plan_sha256": plan_sha, "request_sha256": "f" * 64})
    monkeypatch.setattr(activation, "cancel_source_activation_approval",
        lambda state, activation_id, plan_sha, nonce: (cancelled.append(nonce) or {"status": "cancelled"}))

    def failed_stop_modal(value):
        assert owner.controller.accept_activation_handoff(value) is not None
        exact = owner.controller._activation_consent
        # The real STOP preparation error dialog can dispatch other Qt slots.
        assert not owner.controller.review_source_candidate(SimpleNamespace(stage_id="new-stage", manifest_sha256="0" * 64))
        assert owner.controller._activation_consent is exact and exact in owner.controller._activation_states
        owner.controller.reject_activation_handoff(dict(value, request_sha256="0" * 64))
        assert exact.handoff is True
        owner.controller.reject_activation_handoff(value)
        assert exact.handoff is False and exact.cancelled.is_set()
        received.append(exact)

    owner.controller.activation_request_ready.connect(failed_stop_modal)
    value = start_review(app, owner)
    assert owner.controller.approve_activation(value["serial"], accepted=True)
    until(app, lambda: bool(received) and owner.controller.activation_custody_released())
    assert cancelled and set(cancelled) == {received[0].approval_id}


class QuestionOwner(QMainWindow):
    _on_source_activation_ready = MainWindow._on_source_activation_ready


@pytest.mark.parametrize("supervised", [False, True])
@pytest.mark.parametrize("answer", [QMessageBox.No, QMessageBox.Yes])
def test_actual_apply_question_defaults_no_escapes_no_and_never_reveals(app, tmp_path, supervised, answer):
    owner = QuestionOwner()
    approvals, declines = [], []
    owner._termination_started = False
    owner._update_controller = SimpleNamespace(alive=lambda: True, _activation_current=lambda serial: serial == 7,
        approve_activation=lambda serial, **kw: approvals.append((serial, kw)),
        decline_activation=declines.append)
    value = dict(preview(tmp_path), serial=7, supervised=supervised)
    inspected = []

    def respond():
        question = owner.findChild(QMessageBox, "SourceActivationConfirmation")
        assert question is not None
        assert question.defaultButton() is question.button(QMessageBox.No)
        assert question.escapeButton() is question.button(QMessageBox.No)
        assert question.property("_angerona_no_reveal") is True
        assert question.property("_angerona_security_prompt") is True
        inspected.append(question.text())
        question.button(answer).click()

    QTimer.singleShot(0, respond)
    try:
        owner._on_source_activation_ready(value)
        assert len(inspected) == 1
        text = inspected[0].lower()
        if supervised:
            assert "only after normal stop, exact native retirement" in text
            assert "exclusive maintenance checks" in text
            assert "a held stop leaves the update unapplied" in text
        else:
            assert "records a proposal only" in text
            assert "angerona stays running" in text
            assert "a later canonical launch must ask again" in text
        assert (approvals == [(7, {"accepted": True})]) is (answer == QMessageBox.Yes)
        assert (declines == [7]) is (answer == QMessageBox.No)
    finally:
        owner.close()
        owner.deleteLater()


def binding():
    return {"launch_id": "1" * 32, "activation_id": "2" * 32, "request_sha256": "3" * 64,
            "core_pid": 123, "core_birth": "134381000000000000"}


def test_actual_stop_receipt_detaches_binding_and_does_not_bypass_worker_drain(app, tmp_path):
    owner = QMainWindow()
    release, entered = threading.Event(), threading.Event()
    worker = threading.Thread(target=lambda: (entered.set(), release.wait(3)), name="inert-approval-writer")
    worker.start()
    assert entered.wait(1)
    supplied, finished, rows = binding(), [], []
    coordinator = ShutdownRetirement(owner, workers=lambda: (RetainedWorker("exact-writer", worker, True),),
        cleanup=lambda: None, finish=finished.append, data_root=tmp_path, activation_binding=supplied,
        diagnostic_writer=lambda root, row: rows.append(row))
    try:
        coordinator.start()
        supplied["request_sha256"] = "0" * 64
        assert coordinator._payload("stopping")["source_activation"] == binding()
        assert not finished and coordinator._payload("stopping")["pending_workers"] == ["exact-writer"]
        release.set()
        until(app, lambda: bool(finished))
        worker.join(2)
        assert not worker.is_alive()
        assert finished[0]["state"] == "retired" and finished[0]["forced"] is False
        assert rows[-1]["source_activation"] == binding()
    finally:
        release.set()
        worker.join(3)
        assert not worker.is_alive()
        owner.close()


@pytest.mark.parametrize("bad", [dict(binding(), core_pid=True), dict(binding(), core_birth="0"),
    dict(binding(), core_birth="١٢٣"), dict(binding(), core_birth="18446744073709551616"),
    dict(binding(), token="must-not-pass"), dict(binding(), activation_id="A" * 32)])
def test_malformed_stop_binding_is_rejected_before_start(app, tmp_path, bad):
    owner = QMainWindow()
    try:
        with pytest.raises(ValueError, match="binding|generation"):
            ShutdownRetirement(owner, workers=lambda: (), cleanup=lambda: None, finish=lambda row: None,
                               data_root=tmp_path, activation_binding=bad)
    finally:
        owner.close()


def test_forced_incomplete_never_becomes_clean_because_binding_exists(app, tmp_path):
    owner = QMainWindow()
    release = threading.Event()
    worker = threading.Thread(target=release.wait, name="inert-held-source-writer")
    worker.start()
    now, final, cleaned = [0.0], [], []
    coordinator = ShutdownRetirement(owner, workers=lambda: (RetainedWorker("held", worker, True),),
        cleanup=lambda: cleaned.append(True), finish=final.append, data_root=tmp_path, activation_binding=binding(),
        timeout=1, clock=lambda: now[0], diagnostic_writer=lambda root, row: None)
    try:
        coordinator.start()
        now[0] = 2
        coordinator.poll()
        until(app, lambda: bool(final))
        assert final[0]["state"] == "forced-incomplete" and final[0]["forced"] is True
        assert final[0]["source_activation"] == binding() and final[0]["pending_workers"] == ["held"]
        assert cleaned == []
    finally:
        release.set()
        worker.join(3)
        assert not worker.is_alive()
        owner.close()


def test_real_angerona_app_observer_composition_retains_sampler_after_cleanup(app, owner):
    from angerona.app import AngeronaApp
    from angerona.core.source_activation import SourceActivationController

    backend = AngeronaApp.__new__(AngeronaApp)  # No Config, services, sensors or App bootstrap.
    controller = SourceActivationController(owner.root, owner.config.data_dir / "github-updates", "1" * 32)
    backend._source_update_controller = controller
    entered, release = threading.Event(), threading.Event()

    def observe():
        controller.heartbeat_started(threading.current_thread())
        entered.set()
        try:
            assert release.wait(3)
        finally:
            controller.heartbeat_close()  # No cache was opened; memory-only close is actual.

    worker = threading.Thread(target=observe, name="inert-existing-component-observer")
    owner.window._shutdown_callback = backend.shutdown
    owner.window._shutdown_view_owners = lambda: (owner.window, owner.controller)
    owner.window._aar_report_threads = {}
    worker.start()
    try:
        assert entered.wait(1)
        rows = MainWindow._retained_shutdown_workers(owner.window)
        row = next(row for row in rows if row.worker is worker)
        assert row.before_cleanup is False
        assert row.retirement_proof.__self__ is backend
        assert row.retirement_proof.__func__ is AngeronaApp.source_update_observer_retirement_proven
        assert row.retirement_proof(worker) is False
        release.set()
        worker.join(2)
        assert not worker.is_alive() and row.retirement_proof(worker) is True
        backend._source_update_controller = None
        assert backend.source_update_observer_workers() == ()
    finally:
        release.set()
        worker.join(3)
        assert not worker.is_alive()


def test_saved_proposal_no_cancels_same_plan_without_restaging_or_stop(app, owner, monkeypatch):
    prepared, approved, cancelled = [], [], []
    monkeypatch.setattr(activation, "prepare_source_activation", lambda *a, **kw: prepared.append(a))
    monkeypatch.setattr(activation, "approve_source_activation", lambda *a, **kw: approved.append(a))

    def cancel(state, activation_id, plan_sha):
        assert threading.current_thread() is not threading.main_thread()
        cancelled.append((state, activation_id, plan_sha))
        return {"status": "cancelled"}

    monkeypatch.setattr(activation, "cancel_source_activation_proposal", cancel)
    result = dict(preview(owner.root), status="queued-reconfirm")
    delivered = []
    owner.controller.activation_ready.connect(delivered.append)
    owner.controller._apply_queued_activation({"snapshot": result,
        "context": context(owner.root, owner.config.data_dir / "github-updates")})
    assert len(delivered) == 1 and delivered[0]["activation_id"] == result["activation_id"]
    assert delivered[0]["plan_sha256"] == result["plan_sha256"]
    owner.controller.decline_activation(delivered[0]["serial"])
    until(app, lambda: bool(cancelled) and owner.controller.activation_custody_released())
    assert cancelled == [(owner.config.data_dir / "github-updates", "a" * 32, "b" * 64)]
    assert prepared == approved == []


def storage_review(owner, *, protected=False, policy_status="ready"):
    return {"schema": "angerona.source-activation-storage-review/v1", "source_root": str(owner.root),
        "state_root": str(owner.config.data_dir / "github-updates"), "retained_bytes": 4096,
        "completed_backups": 1, "free_bytes": 0, "source_free_bytes": 5 * 1024**3,
        "same_volume": False, "free_reserve_bytes": 2 * 1024**3,
        "budget": {"completed_backups": 2, "max_bytes": 2 * 1024**3},
        "policy_status": policy_status, "automatic_deletion": False, "startup_inhibited": False,
        "review_sha256": "4" * 64,
        "operations": [{"activation_id": "5" * 32, "status": "completed", "logical_bytes": 4096,
            "protected": protected, "protected_reason": "current-lineage" if protected else "",
            "export_allowed": not protected, "delete_requires_confirmation": not protected}]}


def admit_storage_review(app, owner, monkeypatch, **changes):
    from angerona.core import source_activation_storage as storage
    value = storage_review(owner, **changes)

    def review(root, state, *, cancelled):
        assert threading.current_thread() is not threading.main_thread()
        assert (root, state) == (owner.root, owner.config.data_dir / "github-updates")
        assert not cancelled()
        return value

    monkeypatch.setattr(storage, "review_source_update_storage", review)
    assert owner.controller.review_storage()
    until(app, lambda: owner.controller._last_storage_review is not None and not owner.controller.storage_busy())
    return storage, value


@pytest.mark.parametrize("answer", [QMessageBox.No, QMessageBox.Yes])
def test_export_saveas_keeps_exact_destination_review_and_default_no_off_gui(app, owner, monkeypatch, tmp_path, answer):
    from angerona.gui.update_controller import SourceUpdateStorageDialog, QFileDialog
    storage, reviewed = admit_storage_review(app, owner, monkeypatch)
    selected = str(tmp_path / "another-volume-selected.zip")
    chooser, exported = [], []

    def choose(*args, **kwargs):
        chooser.append((args, kwargs))
        return selected, "ZIP archives (*.zip)"

    def export(root, state, activation_id, review_sha, *, accepted, cancelled, destination):
        assert threading.current_thread() is not threading.main_thread()
        assert accepted is True and not cancelled()
        exported.append((root, state, activation_id, review_sha, destination))
        return {"schema": "angerona.source-activation-export/v1", "status": "exported",
                "path": destination, "location": "external"}

    monkeypatch.setattr(QFileDialog, "getSaveFileName", choose)
    monkeypatch.setattr(storage, "export_source_update_backup", export)
    dialog = SourceUpdateStorageDialog(owner.controller, owner.window)
    dialog._apply_review({"ok": True, "review": reviewed})
    inspected = []

    def respond():
        question = dialog.findChild(QMessageBox)
        assert question is not None and question.defaultButton() is question.button(QMessageBox.No)
        assert question.escapeButton() is question.button(QMessageBox.No)
        assert question.property("_angerona_no_reveal") is True
        assert selected in question.text() and "5" * 32 in question.text() and "4096" in question.text()
        inspected.append(question.text())
        question.button(answer).click()

    QTimer.singleShot(0, respond)
    try:
        dialog._export_selected()
        assert len(chooser) == len(inspected) == 1
        if answer == QMessageBox.Yes:
            until(app, lambda: bool(exported) and not owner.controller.storage_busy())
            assert exported == [(owner.root, owner.config.data_dir / "github-updates", "5" * 32, "4" * 64, selected)]
        else:
            app.processEvents()
            assert exported == [] and not owner.controller._storage_action_reader.busy
        # Zero control-volume free space is displayed honestly; the backend
        # receives the destination and decides its independent native budget.
        assert "Control volume free: 0" in dialog._totals.text()
    finally:
        dialog.close()
        dialog.deleteLater()


def test_saveas_cancel_and_protected_or_stale_review_never_admit_storage_effect(app, owner, monkeypatch):
    from angerona.gui.update_controller import SourceUpdateStorageDialog, QFileDialog
    storage, reviewed = admit_storage_review(app, owner, monkeypatch)
    effects = []
    monkeypatch.setattr(storage, "export_source_update_backup", lambda *a, **kw: effects.append((a, kw)))
    monkeypatch.setattr(storage, "delete_source_update_backup", lambda *a, **kw: effects.append((a, kw)))
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **kw: ("", ""))
    dialog = SourceUpdateStorageDialog(owner.controller, owner.window)
    try:
        dialog._apply_review({"ok": True, "review": reviewed})
        dialog._export_selected()
        assert not owner.controller.storage_action("delete", "0" * 64, "5" * 32, accepted=True)
        assert not owner.controller.storage_action("delete", "4" * 64, "5" * 32, accepted=False)
        owner.controller._apply_storage_review({"ok": True, "serial": owner.controller._storage_serial,
            "review": storage_review(owner, protected=True)})
        assert not owner.controller.storage_action("delete", "4" * 64, "5" * 32, accepted=True)
        assert not owner.controller.storage_action("export", "4" * 64, "5" * 32, accepted=True,
            destination=str(owner.root / "never.zip"))
        assert effects == [] and not owner.controller._storage_action_reader.busy
    finally:
        dialog.close()
        dialog.deleteLater()


def test_real_storage_worker_keeps_cancel_and_exact_policy_review_until_retired(app, owner, monkeypatch):
    storage, _reviewed = admit_storage_review(app, owner, monkeypatch)
    entered, release = threading.Event(), threading.Event()
    calls = []

    def policy(root, state, review_sha, *, completed_backups, max_bytes, accepted, cancelled):
        assert threading.current_thread() is not threading.main_thread()
        calls.append((root, state, review_sha, completed_backups, max_bytes, accepted))
        entered.set()
        assert release.wait(3)
        assert cancelled()
        return {"status": "declined", "budget": None}

    monkeypatch.setattr(storage, "set_source_update_storage_policy", policy)
    assert owner.controller.storage_action("policy", "4" * 64, accepted=True,
        completed_backups=3, max_bytes=1024**3)
    assert entered.wait(2)
    worker = owner.controller._storage_action_reader.thread
    assert worker in owner.controller.owned_workers() and worker.is_alive()
    owner.controller.close()
    assert worker in owner.controller.owned_workers() and worker.is_alive()
    release.set()
    until(app, lambda: not worker.is_alive())
    assert calls == [(owner.root, owner.config.data_dir / "github-updates", "4" * 64, 3, 1024**3, True)]


def test_incomplete_policy_never_projects_default_allowance_or_admits_policy(app, owner, monkeypatch):
    from angerona.gui.update_controller import SourceUpdateStorageDialog
    _storage, reviewed = admit_storage_review(app, owner, monkeypatch, policy_status="held-incomplete-policy")
    dialog = SourceUpdateStorageDialog(owner.controller, owner.window)
    try:
        dialog._apply_review({"ok": True, "review": reviewed})
        assert "incomplete policy" in dialog._status.text().lower() and not dialog._save.isEnabled()
        assert not owner.controller.storage_action("policy", "4" * 64, accepted=True,
            completed_backups=3, max_bytes=1024**3)
    finally:
        dialog.close()
        dialog.deleteLater()


def test_busy_cancel_drains_new_generation_after_close_without_retrying_old_hold(app, owner, monkeypatch):
    # Model two already-published nonce bindings at the cancellation API seam.
    # These are plain scheduling inputs, not native/source approval proofs.
    entered, release = threading.Event(), threading.Event()
    calls, states = [], []

    def model_request():
        state = owner.controller._new_activation_consent()
        assert state is not None
        with state.lock:
            state.approval_binding = {"activation_id": "a" * 32, "plan_sha256": "b" * 64}
            state.request = dict(state.approval_binding, request_sha256="f" * 64)
            state.cancellation_proven = False
        states.append(state)
        return state

    def cancel(state_root, activation_id, plan_sha, approval_id):
        assert threading.current_thread() is not threading.main_thread()
        assert (activation_id, plan_sha) == ("a" * 32, "b" * 64)
        calls.append(approval_id)
        if approval_id == states[0].approval_id:
            entered.set()
            assert release.wait(3)
            return {"status": "held"}  # This old uncertainty must never retry-loop.
        assert approval_id == states[1].approval_id
        return {"status": "cancelled"}

    monkeypatch.setattr(activation, "cancel_source_activation_approval", cancel)
    first = model_request()
    first.cancel()
    owner.controller._activation_cancel.request()
    assert entered.wait(2)
    second = model_request()  # The first worker already captured its state tuple.
    second.cancel()
    owner.controller._activation_cancel.request()
    owner.controller.close()
    try:
        release.set()
        until(app, lambda: second.cancellation_processed == second.cancellation_version
              and all(not worker.is_alive() for worker in owner.controller.owned_workers()))
        assert calls == [first.approval_id, second.approval_id]
        assert second.request is None and second.shutdown_ready()
        assert first.request is not None and first.cancellation_proven is False
        assert first.cancellation_processed == first.cancellation_version
        assert not owner.controller.activation_custody_released()
        assert owner.controller._activation_cancel._closed
    finally:
        release.set()
