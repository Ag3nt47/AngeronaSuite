"""UNEXECUTED inert GUI drafts; native backend calls are replaced in every test.

Do not run/import during the active canonical gate. Later offscreen execution
must remain separate from UAC, signed installation and native task acceptance.
"""
from functools import partial
import os
import threading
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QPoint, Qt
from PySide6.QtWidgets import QApplication, QDialog, QLabel, QMessageBox, QScrollArea, QVBoxLayout, QWidget
from PySide6.QtTest import QTest

from angerona.core.installed_autostart import InstalledAutostartStatus
from angerona.gui import installed_startup_controls as ui

_APP = None


class _ManualReader:
    """Inert single-slot adapter: no thread or backend operation is launched."""

    def __init__(self, owner, prepare, apply, *, name, status):
        self.prepare, self.apply, self.status = prepare, apply, status
        self.name = name
        self.busy = False
        self.closed = False
        self.requests = 0
        self.read = None

    def request(self):
        assert not self.busy and not self.closed
        self.read = self.prepare()
        self.requests += 1
        self.busy = True
        self.status("updating")

    def complete(self, view):
        job = self.read.args[0]
        self.busy = False
        self.apply(ui._Result(job.verb, job.sequence, job.generation, view))
        self.status("current")

    def close(self):
        self.closed = True


@pytest.fixture
def controls(monkeypatch):
    global _APP
    _APP = QApplication.instance() or QApplication([])
    monkeypatch.setattr(ui, "AsyncSnapshot", _ManualReader)
    monkeypatch.setattr(ui, "sys", SimpleNamespace(platform="win32", frozen=True))
    owner = QDialog()
    widget = ui.InstalledStartupControls(owner, parent=owner)
    try:
        yield widget, owner
    finally:
        widget.shutdown()
        owner.close()
        owner.deleteLater()
        _APP.processEvents()


def _verified(widget):
    widget.request_status()
    widget._reader.complete(ui._View("enrolled", enabled=True, requires_review=False))


def test_absent_task_cannot_be_enrolled_or_queue_consent(controls):
    widget, _owner = controls
    widget.request_status()
    widget._reader.complete(ui._View("not-enrolled", enabled=False, requires_review=False))
    assert widget.enrollment_info_button.isEnabled()
    widget._confirm("enroll")
    assert widget._start("enroll") is False
    assert widget._reader.requests == 1 and widget._confirmation is None


def test_constructor_and_render_never_probe_native_or_start_a_worker(controls, monkeypatch):
    widget, _owner = controls
    monkeypatch.setattr(ui, "_run_backend", lambda *_: pytest.fail("render started backend"))
    assert widget._reader.requests == 0
    widget._render()
    assert widget._reader.requests == 0
    assert widget.check_button.isEnabled()
    assert widget.enrollment_info_button.isEnabled() and not widget.revoke_button.isEnabled()


def test_source_observe_is_unavailable_and_cannot_queue_an_action(monkeypatch):
    global _APP
    _APP = QApplication.instance() or QApplication([])
    monkeypatch.setattr(ui, "AsyncSnapshot", _ManualReader)
    monkeypatch.setattr(ui, "sys", SimpleNamespace(platform="win32", frozen=False))
    owner = QDialog()
    widget = ui.InstalledStartupControls(owner, parent=owner)
    try:
        widget.request_status()
        widget._confirm("enroll")
        assert widget._reader.requests == 0 and widget._confirmation is None
        assert not widget.check_button.isEnabled() and not widget.revoke_button.isEnabled()
        assert "Source Observe" in widget.detail_label.text()
    finally:
        widget.shutdown()
        owner.close()


def test_one_reader_refuses_concurrent_and_coalesced_requests(controls):
    widget, _owner = controls
    widget.request_status()
    widget.request_status()
    widget._start("enroll")
    assert widget._reader.requests == 1
    assert widget._busy and widget._reader.busy
    assert isinstance(widget._reader.read, partial)
    assert widget._reader.read.func is ui._run_backend
    assert type(widget._reader.read.args[0]) is ui._Job
    assert not any(value is widget for value in widget._reader.read.args)


def test_confirmation_is_retained_modeless_and_defaults_to_no_cancel(controls):
    widget, _owner = controls
    _verified(widget)
    widget._confirm("revoke")
    dialog = widget._confirmation
    assert dialog is not None
    assert dialog.isModal() is False and dialog.windowModality() == Qt.NonModal
    assert dialog.defaultButton() is dialog.button(QMessageBox.No)
    assert dialog.escapeButton() is dialog.button(QMessageBox.Cancel)
    assert widget._reader.requests == 1
    dialog.done(QMessageBox.No)
    assert widget._confirmation is None and widget._reader.requests == 1


def test_confirmed_verb_is_immutable_and_never_inferred_from_button_text(controls):
    widget, _owner = controls
    _verified(widget)
    widget._confirm("revoke")
    dialog = widget._confirmation
    widget.revoke_button.setText("Enable something else")
    dialog.done(QMessageBox.Yes)
    assert widget._reader.requests == 2
    assert widget._active_job.verb == "revoke"


@pytest.mark.parametrize("change", ["lifecycle", "revision", "own-busy", "reader-busy"],
                         ids=["retired-lifecycle", "stale-status", "second-own-busy-check", "second-reader-busy-check"])
def test_confirmation_completion_rechecks_current_state_before_admission(controls, change):
    widget, _owner = controls
    _verified(widget)
    widget._confirm("revoke")
    dialog = widget._confirmation
    if change == "lifecycle":
        widget._generation += 1
    elif change == "revision":
        widget._revision += 1
    elif change == "own-busy":
        widget._busy = True
    else:
        widget._reader.busy = True
    dialog.done(QMessageBox.Yes)
    assert widget._reader.requests == 1 and widget._active_job is None


def test_legacy_conflict_has_specific_fixed_explanation_and_preserves_choice(controls):
    widget, _owner = controls
    widget.request_status()
    widget._reader.complete(ui._View("legacy-conflict", enabled=False, requires_review=True))
    assert "preserved" in widget.detail_label.text()
    assert widget.enrollment_info_button.isEnabled() and not widget.revoke_button.isEnabled()
    widget._confirm("enroll")
    assert widget._confirmation is None and widget._reader.requests == 1


def test_verified_task_does_not_claim_protection_health_and_can_be_revoked(controls):
    widget, _owner = controls
    widget.request_status()
    widget._reader.complete(ui._View("enrolled", enabled=True, requires_review=False))
    assert "verified at the last check" in widget.status_label.text()
    assert "holds its automatic administrator launch" in widget.detail_label.text()
    assert "healthy" not in widget.status_label.text().lower()
    assert widget.revoke_button.isEnabled()
    widget._confirm("revoke")
    widget._confirmation.done(QMessageBox.Yes)
    assert widget._active_job.verb == "revoke"


def test_verified_task_retains_required_legacy_review_warning(controls):
    widget, _owner = controls
    widget.request_status()
    widget._reader.complete(ui._View("enrolled-legacy-conflict", enabled=True, requires_review=True))
    assert "Review required" in widget.detail_label.text()
    assert "legacy startup entry" in widget.detail_label.text()
    assert "preserved" in widget.detail_label.text()
    assert widget._reader.requests == 1


def test_failed_mutation_is_unproved_without_automatic_cleanup_retry_or_refresh(controls):
    widget, _owner = controls
    _verified(widget)
    widget._confirm("revoke")
    widget._confirmation.done(QMessageBox.Yes)
    widget._reader.busy = False
    widget._reader.status("unavailable")
    assert widget._view.code == "operation-unproved" and widget._view.enabled is None
    assert "may have taken effect" in widget.detail_label.text()
    assert widget._reader.requests == 2
    assert widget.enrollment_info_button.isEnabled() and not widget.revoke_button.isEnabled()


def test_owner_finish_retires_confirmation_and_late_results(controls):
    widget, owner = controls
    _verified(widget)
    widget._confirm("revoke")
    owner.finished.emit(QDialog.Rejected)
    assert widget._closed and widget._stop.is_set() and widget._reader.closed
    assert widget._confirmation is None
    widget._apply(ui._Result("revoke", 2, 1, ui._View("revoked", False, True, False)))
    assert widget._reader.requests == 1 and widget._view.code == "enrolled"


@pytest.mark.parametrize("field,value", [
    ("enabled", 1), ("enabled", None), ("changed", True), ("requires_review", "yes"),
    ("code", "<img src=untrusted>"), ("code", "x" * 100000),
], ids=["literal-bool", "positive-needs-proof", "changed-code-consistency", "review-bool", "closed-reason", "bounded-code"])
def test_backend_dto_projection_rejects_malformed_or_inconsistent_fields(field, value):
    dto = InstalledAutostartStatus("enrolled", enabled=True, requires_review=False)
    object.__setattr__(dto, field, value)
    projected = ui.copy_installed_status(dto)
    assert projected.code == "status-unproved" and projected.enabled is None


def test_projection_does_not_call_untrusted_properties_or_retain_mutable_dto():
    class Untrusted:
        @property
        def code(self):
            pytest.fail("untrusted result property executed")
    assert ui.copy_installed_status(Untrusted()).code == "status-unproved"
    dto = InstalledAutostartStatus("enrolled", enabled=True, requires_review=False)
    projected = ui.copy_installed_status(dto)
    object.__setattr__(dto, "enabled", False)
    assert projected.enabled is True


def test_retired_prepared_job_never_calls_backend(controls, monkeypatch):
    widget, _owner = controls
    widget.request_status()
    read = widget._reader.read
    monkeypatch.setattr("angerona.core.autostart.installed_admin_status", lambda: pytest.fail("retired job called backend"))
    widget.shutdown()
    result = read()
    assert result.view.enabled is None and result.view.code == "status-unproved"


def test_worker_returns_closed_copy_and_suppresses_raw_backend_errors(monkeypatch):
    calls = []
    monkeypatch.setattr("angerona.core.autostart.installed_admin_status",
        lambda: calls.append("status") or InstalledAutostartStatus("not-enrolled", enabled=False))
    monkeypatch.setattr("angerona.core.autostart.revoke_installed_admin_autostart",
        lambda: (_ for _ in ()).throw(RuntimeError("untrusted password=never-display")))
    first = ui._run_backend(ui._Job("status", 1, 1, threading.Event()))
    assert first.view.code == "not-enrolled" and calls == ["status"]
    second = ui._run_backend(ui._Job("revoke", 2, 1, threading.Event()))
    assert second.view.code == "operation-unproved"
    assert "password" not in ui._REASONS[second.view.code]


def _responsive_startup_window(monkeypatch):
    global _APP
    _APP = QApplication.instance() or QApplication([])
    monkeypatch.setattr(ui, "AsyncSnapshot", _ManualReader)
    monkeypatch.setattr(ui, "sys", SimpleNamespace(platform="win32", frozen=True))
    owner = QDialog()
    font = owner.font()
    font.setPointSizeF(font.pointSizeF() * 1.35)
    owner.setFont(font)
    area = QScrollArea()
    area.setWidgetResizable(True)
    page = QWidget()
    layout = QVBoxLayout(page)
    controls = ui.InstalledStartupControls(owner, parent=page)
    layout.addWidget(controls)
    layout.addStretch()
    area.setWidget(page)
    QVBoxLayout(owner).addWidget(area)
    return owner, area, page, controls


def _settle_startup_layout():
    for _ in range(4):
        QApplication.processEvents()


def _assert_startup_content_fits(area, page, widget):
    viewport = area.viewport()
    assert area.horizontalScrollBar().maximum() == 0, (
        f"viewport={viewport.width()} page={page.width()} group={widget.width()} "
        f"group_min={widget.minimumSizeHint().width()} columns={widget._action_columns} "
        f"button_hints={[button.sizeHint().width() for button in widget._action_buttons]} "
        f"grid_min={widget._actions_grid.minimumSize().width()} "
        f"title_min={widget.fontMetrics().horizontalAdvance(widget.title())} "
        f"labels={[(label.minimumSizeHint().width(), label.minimumWidth()) for label in widget.findChildren(QLabel) if label.window() is widget.window()]}"
    )
    assert page.width() <= viewport.width()
    for child in (*widget._action_buttons, *widget.findChildren(QLabel)):
        if child.window() is not widget.window():
            continue  # A separate consent window is not scroll-page content.
        if not child.isVisibleTo(widget):
            continue  # Hidden ancestors do not paint their unlaid-out children.
        left = child.mapTo(viewport, QPoint(0, 0)).x()
        assert left >= 0 and left + child.width() <= viewport.width(), (
            f"visible {type(child).__name__}: left={left} width={child.width()} "
            f"viewport={viewport.width()} object={child.objectName()}"
        )
        if isinstance(child, QLabel):
            assert child.height() + 1 >= child.heightForWidth(child.width())
        else:
            assert child.width() >= child.sizeHint().width()
    for index, button in enumerate(widget._action_buttons):
        for other in widget._action_buttons[index + 1:]:
            assert not button.geometry().intersects(other.geometry())
    assert widget.fontMetrics().horizontalAdvance(widget.title()) + 12 <= widget.width()
    assert widget.accessibleName() == "Existing administrator sign-in task"
    assert widget.toolTip() == widget.accessibleName()
    assert widget.enrollment_info_button.accessibleName() == "Administrator sign-in enrollment information"
    assert widget.enrollment_info_button.toolTip() == widget.enrollment_info_button.accessibleName()
    assert widget.revoke_button.accessibleName() == "Remove administrator sign-in task…"
    assert widget.revoke_button.toolTip() == widget.revoke_button.accessibleName()


@pytest.mark.parametrize("width", [360, 480, 960])
def test_startup_actions_fit_real_viewport_at_large_font_and_keep_click_scope(monkeypatch, width):
    owner, area, page, widget = _responsive_startup_window(monkeypatch)
    try:
        owner.resize(width, 800)
        owner.show()
        _settle_startup_layout()
        assert owner.width() == width
        _assert_startup_content_fits(area, page, widget)
        QTest.mouseClick(widget.check_button, Qt.LeftButton)
        assert widget._active_job.verb == "status" and widget._reader.requests == 1
        widget._reader.complete(ui._View("enrolled-legacy-conflict", True, False, True))
        assert widget._enrollment_info.isHidden()
        QTest.mouseClick(widget.enrollment_info_button, Qt.LeftButton)
        _settle_startup_layout()
        assert widget._enrollment_info.isVisibleTo(widget)
        assert widget._enrollment_info.textFormat() == Qt.PlainText
        assert "enrollment is unavailable" in widget._enrollment_info.text()
        assert "current session" in widget._enrollment_info.text()
        assert "Windows asks for your approval each time" in widget._enrollment_info.text()
        assert widget._confirmation is None and widget._reader.requests == 1
        _assert_startup_content_fits(area, page, widget)
        QTest.mouseClick(widget.enrollment_info_button, Qt.LeftButton)
        _settle_startup_layout()
        assert widget._enrollment_info.isHidden()
        assert widget._confirmation is None and widget._reader.requests == 1
        assert "legacy startup entry" in widget.detail_label.text()
        _assert_startup_content_fits(area, page, widget)
        QTest.mouseClick(widget.revoke_button, Qt.LeftButton)
        consent = widget._confirmation
        assert consent is not None and "Remove only this verified installed sign-in task" in consent.text()
        assert consent.defaultButton() is consent.button(QMessageBox.No)
        consent.done(QMessageBox.No)
        assert widget._reader.requests == 1
        QTest.mouseClick(widget.revoke_button, Qt.LeftButton)
        widget._confirmation.done(QMessageBox.Yes)
        assert widget._active_job.verb == "revoke" and widget._reader.requests == 2
    finally:
        widget.shutdown()
        owner.close()
        owner.deleteLater()


def test_startup_grid_grows_and_shrinks_without_recreating_widgets_or_starting_work(monkeypatch):
    owner, area, page, widget = _responsive_startup_window(monkeypatch)
    buttons = widget._action_buttons
    columns = []
    try:
        owner.resize(960, 800)
        owner.show()
        _settle_startup_layout()
        # Fixed window sizes can still fit two columns with some Qt styles.
        # Measure a one-column case using the live controls and their chrome.
        widths = [button.sizeHint().width() for button in buttons]
        gap = max(0, widget._actions_grid.horizontalSpacing())
        two_columns = max(widths[::2]) + widths[1] + gap
        overhead = owner.width() - area.viewport().width()
        for margins in (page.layout().contentsMargins(), widget.contentsMargins(), widget.layout().contentsMargins()):
            overhead += margins.left() + margins.right()
        narrow_width = overhead + two_columns - 1
        for width in (960, 480, 360, 240, narrow_width, 960):
            owner.resize(width, 800)
            _settle_startup_layout()
            _assert_startup_content_fits(area, page, widget)
            columns.append(widget._action_columns)
            assert widget._action_buttons == buttons
            assert widget._reader.requests == 0 and widget._confirmation is None
        assert columns[0] == columns[-1] == 3
        assert columns[-2] == 1, (narrow_width, widths, columns)
    finally:
        widget.shutdown()
        owner.close()
        owner.deleteLater()

def test_startup_grid_counts_group_frame_at_the_exact_two_column_boundary(monkeypatch):
    owner, area, page, widget = _responsive_startup_window(monkeypatch)
    buttons = widget._action_buttons
    try:
        area.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        frame = widget.contentsMargins()
        widget.setContentsMargins(frame.left() + 11, frame.top(),
                                  frame.right() + 13, frame.bottom())
        owner.resize(960, 800)
        owner.show()
        _settle_startup_layout()
        widths = [button.sizeHint().width() for button in buttons]
        two_columns = max(widths[::2]) + widths[1] + max(0, widget._actions_grid.horizontalSpacing())
        page_margins = page.layout().contentsMargins()
        layout_margins = widget.layout().contentsMargins()
        window_chrome = owner.width() - area.viewport().width()
        # This width fits two columns plus layouts, but not the group's own
        # nonzero frame. It must reflow rather than force horizontal scrolling.
        boundary = (window_chrome + page_margins.left() + page_margins.right()
                    + layout_margins.left() + layout_margins.right() + two_columns)
        owner.resize(boundary, 800)
        _settle_startup_layout()
        assert owner.width() == boundary
        assert widget._action_columns == 1
        _assert_startup_content_fits(area, page, widget)
        assert widget._action_buttons == buttons
        assert widget._reader.requests == 0 and widget._active_job is None
        assert widget._confirmation is None
    finally:
        widget.shutdown()
        owner.close()
        owner.deleteLater()


def test_idle_hidden_activity_child_geometry_is_not_visible_page_overflow(monkeypatch):
    owner, area, page, widget = _responsive_startup_window(monkeypatch)
    try:
        owner.resize(360, 800)
        owner.show()
        _settle_startup_layout()
        assert widget.isVisibleTo(owner)
        assert widget.progress_view.isHidden()
        assert not widget.progress_view.caption.isVisibleTo(widget)
        # QWidget children of a hidden layout can keep their default geometry.
        # Force that geometry explicitly; it must not claim visible overflow.
        widget.progress_view.caption.resize(area.viewport().width() + 320, 80)
        assert widget.progress_view.caption.window() is widget.window()
        assert widget.progress_view.caption.width() > area.viewport().width()
        _assert_startup_content_fits(area, page, widget)
        assert widget._reader.requests == 0 and widget._active_job is None
    finally:
        widget.shutdown()
        owner.close()
        owner.deleteLater()


@pytest.mark.parametrize("width", [240, 360, 480])
def test_visible_admitted_activity_fits_narrow_large_font_viewport(monkeypatch, width):
    owner, area, page, widget = _responsive_startup_window(monkeypatch)
    try:
        owner.resize(width, 800)
        owner.show()
        _settle_startup_layout()
        widget.request_status()  # Existing admission; the reader is inert.
        _settle_startup_layout()
        assert widget._active_job.verb == "status" and widget._reader.requests == 1
        assert widget.progress_view.isVisibleTo(widget)
        assert widget.progress_view.caption.isVisibleTo(widget)
        assert "Installed startup: status" in widget.progress_view.caption.text()
        assert widget.progress_view.ring.busy and widget.progress_view.ring.percent is None
        _assert_startup_content_fits(area, page, widget)
        widget._reader.complete(ui._View("not-enrolled", False, False, False))
        _settle_startup_layout()
        assert widget.progress_view.isHidden() and not widget._activities.snapshot()
        _assert_startup_content_fits(area, page, widget)
    finally:
        widget.shutdown()
        owner.close()
        owner.deleteLater()


def test_running_activity_reflows_on_grow_shrink_without_restarting_action(monkeypatch):
    owner, area, page, widget = _responsive_startup_window(monkeypatch)
    try:
        owner.show()
        widget.request_status()
        job, handle = widget._active_job, widget._activity
        for width in (960, 480, 360, 240, 960):
            owner.resize(width, 800)
            _settle_startup_layout()
            assert widget.progress_view.caption.isVisibleTo(widget)
            _assert_startup_content_fits(area, page, widget)
            assert widget._reader.requests == 1 and widget._active_job is job
            assert widget._activity is handle and widget._activities.snapshot()
        widget._reader.complete(ui._View("not-enrolled", False, False, False))
        _settle_startup_layout()
        assert not widget._activities.snapshot()
    finally:
        widget.shutdown()
        owner.close()
        owner.deleteLater()


def test_width_assertion_still_rejects_an_actually_visible_activity_overflow(monkeypatch):
    owner, area, page, widget = _responsive_startup_window(monkeypatch)
    try:
        owner.resize(360, 800)
        owner.show()
        widget.request_status()
        _settle_startup_layout()
        caption = widget.progress_view.caption
        assert caption.isVisibleTo(widget)
        _assert_startup_content_fits(area, page, widget)
        prior = caption.size()
        caption.resize(area.viewport().width() + 100, prior.height())
        with pytest.raises(AssertionError, match="visible QLabel"):
            _assert_startup_content_fits(area, page, widget)
        caption.resize(prior)
        _settle_startup_layout()
        _assert_startup_content_fits(area, page, widget)
    finally:
        widget.shutdown()
        owner.close()
        owner.deleteLater()
