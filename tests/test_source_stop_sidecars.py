"""Standalone source presenters retire themselves without foreign controls."""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from angerona.resilience import source_stop, source_stop_peer, status_ui


@pytest.fixture
def source(tmp_path, monkeypatch):
    storage, root = tmp_path / "SourceData", tmp_path / "source"
    storage.mkdir()
    root.mkdir()
    identity = source_stop._Identity("S-1-5-21-11-22-33-1001", 2, 101,
                                    134000000000000001, str(tmp_path / "python.exe"))
    monkeypatch.setattr(source_stop, "_effective_identity", lambda: identity)
    monkeypatch.setattr(source_stop, "_source_root", lambda: root)
    monkeypatch.delenv(source_stop.SOURCE_SESSION_ENV, raising=False)
    context = source_stop.create_source_session(storage)
    assert context is not None
    return storage, context


@pytest.fixture
def qt_app():
    from PySide6.QtCore import QCoreApplication, QEvent
    from PySide6.QtWidgets import QApplication

    existing = QApplication.instance()
    app = existing or QApplication([])
    yield app
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    app.processEvents()
    if existing is None:
        app.shutdown()


def test_sidecar_admission_captures_exact_epoch_without_writes(source, monkeypatch):
    storage, context = source
    pointer = context._command_path().parent.parent / "current.json"
    before = pointer.read_bytes()
    observer = source_stop_peer.admit_source_sidecar(storage)
    assert observer is not None and observer._context.epoch == context.epoch
    assert source_stop_peer.os.environ[source_stop.SOURCE_SESSION_ENV] == context.epoch
    assert observer._thread is None and not observer.exit_requested()
    assert observer.stop()
    assert pointer.read_bytes() == before
    unknown = "0" * 32 if context.epoch != "0" * 32 else "1" * 32
    monkeypatch.setenv(source_stop.SOURCE_SESSION_ENV, unknown)
    with pytest.raises(source_stop_peer.SourceSidecarAdmissionError):
        source_stop_peer.admit_source_sidecar(storage)
    assert pointer.read_bytes() == before


def test_manual_no_reference_history_review_remains_independent_after_stop(source, monkeypatch):
    storage, context = source
    context.request_stop()
    monkeypatch.delenv(source_stop.SOURCE_SESSION_ENV, raising=False)
    assert source_stop_peer.admit_source_sidecar(storage) is None
    assert source_stop.SOURCE_SESSION_ENV not in source_stop_peer.os.environ
    # The same original epoch passed explicitly remains an owned sidecar and
    # cannot silently become an independent history viewer.
    monkeypatch.setenv(source_stop.SOURCE_SESSION_ENV, context.epoch)
    observer = source_stop_peer.admit_source_sidecar(storage)
    assert observer is not None and observer.exit_requested()


def test_manual_history_viewer_and_exact_superseded_sidecar_are_distinct(tmp_path, monkeypatch):
    context = SimpleNamespace(epoch="a" * 32, is_stop_requested=lambda: False,
                              is_superseded=lambda: True, respawn_allowed=lambda: False)
    monkeypatch.setattr(source_stop_peer, "join_source_session", lambda *_a, **_k: context)
    monkeypatch.delenv(source_stop.SOURCE_SESSION_ENV, raising=False)
    assert source_stop_peer.admit_source_sidecar(tmp_path) is None
    monkeypatch.setenv(source_stop.SOURCE_SESSION_ENV, context.epoch)
    observer = source_stop_peer.admit_source_sidecar(tmp_path)
    assert observer is not None and observer.exit_requested()
    assert observer.reason == "source-superseded"


def test_stopped_exact_epoch_is_cached_before_any_qt_or_worker(source, monkeypatch):
    storage, context = source
    context.request_stop()
    monkeypatch.setenv(source_stop.SOURCE_SESSION_ENV, context.epoch)
    observer = source_stop_peer.admit_source_sidecar(storage)
    assert observer is not None and observer.exit_requested()
    assert observer.reason == "source-stop" and observer._thread is None
    observer.start()
    assert observer._thread is None and observer.stop()


def test_non_source_scope_uses_no_source_observer_or_installed_command(tmp_path, monkeypatch):
    monkeypatch.setattr(source_stop, "_effective_identity", lambda: None)
    monkeypatch.delenv(source_stop.SOURCE_SESSION_ENV, raising=False)
    from angerona.resilience import shutdown_token

    monkeypatch.setattr(shutdown_token, "is_standdown_requested",
                        lambda: pytest.fail("presenter consulted installed control"))
    assert source_stop_peer.admit_source_sidecar(tmp_path) is None
    monkeypatch.setenv(source_stop.SOURCE_SESSION_ENV, "a" * 32)
    with pytest.raises(source_stop_peer.SourceSidecarAdmissionError):
        source_stop_peer.admit_source_sidecar(tmp_path)


@pytest.mark.parametrize("entry", ["status", "blackbox"])
def test_explicit_bad_reference_refuses_before_gui_or_singleton(source, monkeypatch, entry):
    storage, context = source
    monkeypatch.setenv(source_stop.SOURCE_SESSION_ENV,
                       "0" * 32 if context.epoch != "0" * 32 else "1" * 32)
    if entry == "status":
        monkeypatch.setattr(status_ui.hb, "_data_dir", lambda: storage)
        monkeypatch.setattr(status_ui, "run_window", lambda *_a, **_k: pytest.fail("invalid sidecar created Qt"))
        assert status_ui.main(["watchdog"]) == 2
    else:
        import blackbox_recorder as blackbox

        monkeypatch.setattr(blackbox, "DATA_DIR", storage)
        monkeypatch.setattr(blackbox.sys, "argv", ["blackbox_recorder.py"])
        monkeypatch.setattr(blackbox, "_acquire_single_instance",
                            lambda: pytest.fail("invalid sidecar acquired singleton"))
        monkeypatch.setattr(blackbox, "QApplication", lambda *_a: pytest.fail("invalid sidecar created Qt"))
        with pytest.raises(SystemExit) as result:
            blackbox.main()
        assert result.value.code == 2


@pytest.mark.parametrize("entry", ["status", "blackbox"])
def test_stopped_family_returns_before_presenter_entry(source, monkeypatch, entry):
    storage, context = source
    context.request_stop()
    monkeypatch.setenv(source_stop.SOURCE_SESSION_ENV, context.epoch)
    if entry == "status":
        monkeypatch.setattr(status_ui.hb, "_data_dir", lambda: storage)
        monkeypatch.setattr(status_ui, "run_window", lambda *_a, **_k: pytest.fail("stopped sidecar created Qt"))
        assert status_ui.main(["scanner"]) == 0
    else:
        import blackbox_recorder as blackbox

        monkeypatch.setattr(blackbox, "DATA_DIR", storage)
        monkeypatch.setattr(blackbox.sys, "argv", ["blackbox_recorder.py"])
        monkeypatch.setattr(blackbox, "_acquire_single_instance",
                            lambda: pytest.fail("stopped sidecar acquired singleton"))
        assert blackbox.main() is None


def _run_qt_observer(app, observer, trigger):
    from PySide6.QtCore import QTimer

    expired = []
    timer = source_stop_peer.install_qt_stop(app, observer)
    action = QTimer(app)
    action.setSingleShot(True)
    action.timeout.connect(trigger)
    guard = QTimer(app)
    guard.setSingleShot(True)
    guard.timeout.connect(lambda: expired.append(True) or app.quit())
    observer.start()
    action.start(25)
    guard.start(3000)
    try:
        app.exec()
    finally:
        timer.stop()
        action.stop()
        guard.stop()
        assert observer.stop(timeout=2.0)
        timer.deleteLater()
        action.deleteLater()
        guard.deleteLater()
    assert observer._thread is not None and observer._done.is_set()
    assert not observer._thread.is_alive()
    return expired


def test_real_qt_timer_retires_presenter_after_signed_stop_off_gui(source, monkeypatch, qt_app):
    storage, context = source
    monkeypatch.setenv(source_stop.SOURCE_SESSION_ENV, context.epoch)
    observer = source_stop_peer.admit_source_sidecar(storage)
    assert observer is not None
    observer._interval = 0.01
    gui_thread = threading.current_thread()
    reads = []
    actual_stop = source_stop.SourceStopContext.is_stop_requested
    actual_superseded = source_stop.SourceStopContext.is_superseded

    def off_gui(function):
        def checked(value):
            assert threading.current_thread() is not gui_thread, "source/native read reached Qt timer"
            reads.append(threading.current_thread().ident)
            return function(value)
        return checked

    monkeypatch.setattr(source_stop.SourceStopContext, "is_stop_requested", off_gui(actual_stop))
    monkeypatch.setattr(source_stop.SourceStopContext, "is_superseded", off_gui(actual_superseded))
    trigger, writer_done, errors = threading.Event(), threading.Event(), []

    def write_stop():
        try:
            assert trigger.wait(2)
            context.request_stop()
        except BaseException as error:
            errors.append(error)
        finally:
            writer_done.set()

    writer = threading.Thread(target=write_stop, name="PrivateSidecarStopIssuer")
    writer.start()
    try:
        assert not _run_qt_observer(qt_app, observer, trigger.set)
    finally:
        trigger.set()
        writer.join(timeout=2)
    assert not writer.is_alive() and writer_done.is_set() and not errors
    assert reads and observer.exit_requested() and observer.reason == "source-stop"


@pytest.mark.parametrize("intent", ["superseded", "unknown", "missing", "corrupt"])
def test_qt_supersession_is_self_retirement_and_unknown_does_not_quit(qt_app, intent):
    from PySide6.QtCore import QTimer

    current = threading.current_thread()
    state = {"ready": False}

    def check_stop():
        assert threading.current_thread() is not current
        return False

    def check_superseded():
        assert threading.current_thread() is not current
        if intent == "corrupt":
            raise ValueError("inert invalid signed fence")
        return state["ready"] if intent == "superseded" else "unknown"

    context = SimpleNamespace(is_stop_requested=check_stop)
    if intent != "missing":
        context.is_superseded = check_superseded
    observer = source_stop_peer.SourceSidecarStop(context, interval=0.01)
    if intent == "superseded":
        assert not _run_qt_observer(qt_app, observer, lambda: state.update(ready=True))
        assert observer.exit_requested() and observer.reason == "source-superseded"
    else:
        # An ordinary window close ends the test. Unknown/corrupt/missing
        # supersession must not cause an earlier self-quit or an exit flag.
        timer = source_stop_peer.install_qt_stop(qt_app, observer)
        close = QTimer(qt_app)
        close.setSingleShot(True)
        closed = []
        close.timeout.connect(lambda: closed.append(True) or qt_app.quit())
        observer.start()
        close.start(150)
        try:
            qt_app.exec()
        finally:
            close.stop()
            timer.stop()
            assert observer.stop(timeout=2)
            close.deleteLater()
            timer.deleteLater()
        assert closed == [True] and not observer.exit_requested() and observer.reason == ""
        assert observer._thread is not None and not observer._thread.is_alive()


def test_status_headless_mode_checks_only_cached_family_exit(monkeypatch):
    observer = source_stop_peer.SourceSidecarStop(SimpleNamespace(is_stop_requested=lambda: True))
    observer._observe_once()
    monkeypatch.setattr(status_ui, "_read_status", lambda *_a: pytest.fail("exited sidecar read status"))
    assert status_ui._run_headless("watchdog", source_stop_observer=observer) == 0
