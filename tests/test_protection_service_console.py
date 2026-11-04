"""Read-only console lifecycle with inert clients, never an installed service."""
from __future__ import annotations

import builtins
from dataclasses import replace
import sys
import threading
import time
from types import ModuleType, SimpleNamespace

import pytest

pytest.importorskip("PySide6")
from PySide6.QtCore import QProcess, QTimer, Qt
from PySide6.QtWidgets import QApplication, QPushButton

from angerona import __main__ as entry
from angerona.core import privilege, windows_package_identity
from angerona.gui import protection_service_console as console


@pytest.fixture(autouse=True)
def isolate_inert_retirement_owners(monkeypatch):
    # These tests use fake native clients only; no installed service is touched.
    monkeypatch.setattr(console, "_RETIREMENT_HOLD", None)


def payload(**changes):
    return dict(service="AngeronaProtection", protection_verified=False, authority=[], mutating_operations=[],
                event_text_available=False, storage_access_available=False, state="ready", mode="full",
                version="1.15.0", coverage_reason="Counts alone do not verify detector coverage.",
                modules=dict(discovered=86, sampled=86, truncated=False, enabled=75, running=75), **changes)


def spin_until(predicate, *, timeout=5):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        QApplication.processEvents()
        time.sleep(.005)
    assert predicate()


def retire(reader):
    reader.request_detach()
    assert reader.wait_retired(5), "exact owned status reader did not retire"


def test_reader_creates_client_off_qt_and_coalesces_requests_to_one_followup():
    entered, release = threading.Event(), threading.Event()
    qt_thread = threading.get_ident()
    calls, factories = [], []
    class Client:
        cleanup_proven = True
        def status(self):
            calls.append(threading.get_ident())
            if len(calls) == 1:
                entered.set()
                assert release.wait(5)
            return payload()
    def factory():
        factories.append(threading.get_ident())
        return Client()
    reader = console.ServiceStatusReader(client_factory=factory)
    try:
        reader.start()
        assert entered.wait(5)
        for _ in range(100):
            assert reader.request()
        assert len(calls) == 1
        release.set()
        spin_until(lambda: reader.snapshot.sequence == 2)
        assert len(calls) == 2 and len(factories) == 1
        assert all(value != qt_thread for value in calls + factories)
        assert reader.thread.daemon is False
    finally:
        release.set()
        retire(reader)


def test_detach_discards_pending_request_and_late_frame_without_stopping_service():
    entered, release = threading.Event(), threading.Event()
    calls = []
    class StatusOnlyClient:
        cleanup_proven = True
        def status(self):
            calls.append("status")
            entered.set()
            assert release.wait(5)
            return payload()
    reader = console.ServiceStatusReader(client_factory=StatusOnlyClient)
    try:
        reader.start()
        assert entered.wait(5)
        reader.request()
        reader.request_detach()
        assert reader.wait_retired() is False
        assert reader.request() is False
        release.set()
        assert reader.wait_retired(5)
        assert calls == ["status"] and reader.snapshot.sequence == 0
    finally:
        release.set()
        retire(reader)


def test_reader_error_keeps_prior_data_stale_and_does_not_export_native_error_text():
    calls = []
    class Client:
        cleanup_proven = True
        def status(self):
            calls.append("status")
            if len(calls) > 1:
                raise PermissionError("untrusted error with secret local path")
            return payload()
    reader = console.ServiceStatusReader(client_factory=Client, clock=lambda: 100.0)
    try:
        reader.start()
        spin_until(lambda: reader.snapshot.sequence == 1)
        first = reader.snapshot
        reader.request()
        spin_until(lambda: reader.snapshot.sequence == 2)
        assert reader.snapshot.error == "PermissionError"
        assert reader.snapshot.view is first.view and reader.snapshot.sampled_monotonic == 100.0
        assert "secret" not in repr(reader.snapshot)
    finally:
        retire(reader)


def test_unexpected_reader_exit_is_explicit_and_rejects_more_requests():
    class Client:
        cleanup_proven = True
        def status(self):
            raise SystemExit("no imported exception text may reach the view")
    reader = console.ServiceStatusReader(client_factory=Client)
    try:
        reader.start()
        spin_until(lambda: reader.wait_retired())
        assert reader.snapshot.error == "StatusReaderStopped" and reader.snapshot.view is None
        assert reader.request() is False
    finally:
        retire(reader)


def test_reader_start_failure_does_not_claim_retirement_or_replace_owner(monkeypatch):
    class UncertainThread:
        def __init__(self, **_kwargs):
            pass
        def start(self):
            raise RuntimeError("modeled thread admission failure")
        def join(self, _timeout):
            raise RuntimeError("cannot join a thread before it is started")
    with monkeypatch.context() as scoped:
        scoped.setattr(console.threading, "Thread", UncertainThread)
        reader = console.ServiceStatusReader()
        with pytest.raises(RuntimeError, match="admission failure"):
            reader.start()
        owner = reader.thread
        assert not reader.wait_retired() and reader.request() is False
        with pytest.raises(RuntimeError, match="cannot be restarted"):
            reader.start()
        assert reader.thread is owner


def test_window_close_waits_visibly_for_exact_reader_but_qt_keeps_dispatching():
    entered, release = threading.Event(), threading.Event()
    calls = []
    class Client:
        cleanup_proven = True
        def status(self):
            calls.append("status")
            entered.set()
            assert release.wait(5)
            return payload()
    reader = console.ServiceStatusReader(client_factory=Client)
    window = console.ProtectionServiceConsole(reader=reader)
    try:
        window.show()
        assert entered.wait(5)
        assert window.close() is False
        assert window.isVisible() and not window.refresh.isEnabled()
        assert "Waiting" in window.banner.text()
        probe = []
        QTimer.singleShot(0, lambda: probe.append(True))
        spin_until(lambda: bool(probe))
        assert not reader.wait_retired()
        release.set()
        spin_until(lambda: reader.wait_retired() and not window.isVisible())
        assert calls == ["status"]
    finally:
        release.set()
        retire(reader)
        window.close()


class InertReader:
    cleanup_proven = True
    def __init__(self, snapshot=None):
        self.snapshot = snapshot or console.ReaderSnapshot()
        self.requests = 0
        self.detached = False
    def request(self):
        self.requests += 1
        return True
    def request_detach(self):
        self.detached = True
    def wait_retired(self, timeout=0):
        return self.detached


def test_window_has_only_refresh_detach_and_never_promotes_counts_to_verified_coverage():
    reader = InertReader(console.ReaderSnapshot(1, console.StatusView.from_payload(payload()), 100.0))
    now = [100.0]
    window = console.ProtectionServiceConsole(reader=reader, start_reader=False, clock=lambda: now[0])
    try:
        window._tick()
        assert {button.text() for button in window.findChildren(QPushButton)} == {"Refresh status", "Close console"}
        assert window.counts["running"].text() == "75"
        assert "unverified" in window.banner.text() and "not establish" in window.scope.text()
        now[0] = 111.0
        window._tick()
        assert "stale" in window.banner.text() and "stale" in window.age.text()
        reader.snapshot = replace(reader.snapshot, sequence=2, error="PermissionError")
        window._tick()
        assert "unavailable" in window.banner.text() and window.counts["running"].text() == "75"
        assert window.version.text() == "1.15.0"
        assert all(label.textFormat() == Qt.TextFormat.PlainText for label in window.counts.values())
    finally:
        window.close()
    assert reader.detached


@pytest.mark.parametrize("raises", [False, True])
def test_native_cleanup_uncertainty_retains_exact_client_and_prevents_clean_retirement_or_replacement(raises):
    calls = []
    class Client:
        cleanup_proven = True
        def status(self):
            calls.append("status")
            self.cleanup_proven = False
            if raises:
                raise OSError("modeled ambiguous native close")
            return payload()
    client = Client()
    reader = console.ServiceStatusReader(client_factory=lambda: client)
    reader.start()
    assert reader.thread is not None
    reader.thread.join(5)
    assert not reader.thread.is_alive()
    assert reader.cleanup_proven is False and reader.wait_retired() is False
    assert reader.snapshot.error == "NativeCleanupUnproven" and reader.snapshot.view is None
    assert reader._held_client is client and console._RETIREMENT_HOLD is reader
    assert reader.request() is False and calls == ["status"]
    reader.request_detach()
    assert reader.wait_retired() is False  # Thread exit is not native cleanup.
    replacement = console.ServiceStatusReader(client_factory=lambda: pytest.fail("replacement touched native client"))
    with pytest.raises(RuntimeError, match="cannot be restarted"):
        replacement.start()


def test_window_reports_native_cleanup_hold_instead_of_waiting_for_an_exited_thread():
    reader = InertReader(console.ReaderSnapshot(1, error="NativeCleanupUnproven"))
    reader.cleanup_proven = False
    reader.wait_retired = lambda timeout=0: False
    window = console.ProtectionServiceConsole(reader=reader, start_reader=False)
    try:
        window.show()
        window._tick()
        assert not window.refresh.isEnabled()
        assert window.close() is False
        assert "native cleanup remains unverified" in window.banner.text()
        assert window.detach.text() == "Cleanup needs attention"
    finally:
        # The model has no native handles or worker; delete only its Qt view.
        window.timer.stop()
        window.hide()
        window.deleteLater()


def test_initial_failure_keeps_unavailable_counts_and_never_starts_an_engine(monkeypatch):
    from angerona.core import persistent_engine, config
    monkeypatch.setattr(persistent_engine, "ensure_engine", lambda **_k: pytest.fail("readonly console spawned an engine"))
    monkeypatch.setattr(config.Config, "load", lambda: pytest.fail("readonly console loaded preferences"))
    reader = InertReader(console.ReaderSnapshot(1, error="PeerAuthenticationError"))
    window = console.ProtectionServiceConsole(reader=reader, start_reader=False)
    try:
        window._tick()
        assert window.version.text() == "Unavailable"
        assert all(label.text() == "—" for label in window.counts.values())
        assert "No successful" in window.age.text() and "unavailable" in window.banner.text()
    finally:
        window.close()


@pytest.mark.parametrize("arguments", [
    ["--protection-console", "--chill"], ["--protection-console", "--automatic-start"],
    ["--automatic-start", "--protection-console"], ["--protection-console", "--engine-serve"],
    ["--protection-console=remote"], ["--protection-console-more"],
])
def test_protection_console_strict_cli_rejects_flags_before_startup_mutation(monkeypatch, arguments):
    monkeypatch.setattr(sys, "argv", ["angerona", *arguments])
    monkeypatch.setattr(entry, "_run_engine_mode", lambda *_a, **_k: pytest.fail("malformed console launched"))
    before = dict(entry.os.environ)
    assert entry.main() == 2
    assert dict(entry.os.environ) == before and sys.argv[1:] == arguments


@pytest.mark.parametrize("frozen,admin,trusted,expected", [
    (False, False, False, 123), (False, True, False, 2),
    (True, False, False, 2), (True, False, True, 123), (True, True, True, 2),
])
def test_console_reuses_package_and_ordinary_user_guards_without_uac(monkeypatch, frozen, admin, trusted, expected):
    monkeypatch.setattr(sys, "argv", ["angerona", "--protection-console"])
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "frozen", frozen, raising=False)
    monkeypatch.setattr(privilege, "is_admin", lambda: admin)
    monkeypatch.setattr(privilege, "ensure_admin", lambda: pytest.fail("status console requested UAC"))
    monkeypatch.setattr(windows_package_identity, "verify_current_msix_authority",
                        lambda: SimpleNamespace(trusted=trusted, reason="modeled package admission"))
    calls = []
    monkeypatch.setattr(entry, "_run_engine_mode", lambda mode: calls.append(mode) or 123)
    assert entry.main() == expected
    assert calls == (["--protection-console"] if expected == 123 else [])


def test_real_route_bypasses_config_singleton_and_ordinary_engine_creation(monkeypatch):
    from angerona.core import persistent_engine
    calls = []
    monkeypatch.setattr(persistent_engine, "_require_user", lambda: calls.append("user-guard"))
    monkeypatch.setattr(entry, "_install_fast_pyside_feature_detection", lambda: calls.append("pyside"))
    fake = ModuleType("angerona.gui.protection_service_console")
    fake.run_console = lambda: calls.append("status-window") or 123
    monkeypatch.setitem(sys.modules, fake.__name__, fake)
    original = builtins.__import__
    def guarded(name, *args, **kwargs):
        if name in {"angerona.core.config", "angerona.core.data_paths", "angerona.core.singleton", "angerona.app"}:
            pytest.fail("status-only route imported application state: " + name)
        return original(name, *args, **kwargs)
    with monkeypatch.context() as scoped:
        scoped.setattr(builtins, "__import__", guarded)
        assert entry._run_engine_mode("--protection-console") == 123
    assert calls == ["user-guard", "pyside", "status-window"]


def test_external_event_loop_exit_retains_unretired_reader_and_does_not_claim_clean_exit(monkeypatch):
    reader = SimpleNamespace(request_detach=lambda: None, start=lambda: None, wait_retired=lambda: False)
    app = SimpleNamespace(setApplicationName=lambda *_a: None, setQuitOnLastWindowClosed=lambda *_a: None,
                          aboutToQuit=SimpleNamespace(connect=lambda *_a: None), exec=lambda: 0)
    monkeypatch.setattr(console, "_RETIREMENT_HOLD", None)
    monkeypatch.setattr(console, "QApplication", lambda *_a: app)
    monkeypatch.setattr(
        console, "ProtectionServiceConsole",
        lambda **_k: SimpleNamespace(reader=reader, show=lambda: None, _pending_window_work=lambda: False),
    )
    with pytest.raises(RuntimeError, match="retirement remains unproven"):
        console.run_console()
    assert console._RETIREMENT_HOLD is reader


class InertElevationProcess(QProcess):
    """Configure an actual QProcess wrapper while keeping execution inert."""
    def __init__(self, parent):
        super().__init__(parent)
        self.test_state = QProcess.ProcessState.NotRunning

    def start(self):
        assert self.test_state == QProcess.ProcessState.NotRunning
        self.test_state = QProcess.ProcessState.Running

    def state(self):
        return self.test_state

    def complete(self, code, status=QProcess.ExitStatus.NormalExit):
        assert self.test_state == QProcess.ProcessState.Running
        self.test_state = QProcess.ProcessState.NotRunning
        self.finished.emit(code, status)


@pytest.fixture
def inert_elevation(tmp_path, monkeypatch):
    calls = []
    executable = tmp_path / "AngeronaStartup.exe"

    def prepare():
        calls.append(executable)
        return executable, {"SystemRoot": r"C:Windows"}

    monkeypatch.setattr(console, "_operator_elevation_available", lambda: True)
    monkeypatch.setattr(console, "_operator_elevation_launch", prepare)
    monkeypatch.setattr(console, "QProcess", InertElevationProcess)
    return calls


def test_elevation_defaults_off_and_shows_warning_directly_below_held_source(monkeypatch):
    monkeypatch.setattr(console.sys, "frozen", False, raising=False)
    monkeypatch.setattr(console, "_operator_elevation_launch", lambda: pytest.fail("held source requested UAC"))
    window = console.ProtectionServiceConsole(reader=InertReader(), start_reader=False)
    try:
        toggle = window.elevation_toggle
        assert not toggle.isChecked() and not toggle.isEnabled()
        settings = toggle.parentWidget()
        assert settings.title() == "Settings"
        assert settings.layout().itemAt(0).widget() is toggle
        assert settings.layout().itemAt(1).widget() is window.elevation_warning
        assert window.elevation_warning.wordWrap()
        assert "protected files and system settings" in window.elevation_warning.text()
        assert "held" in window.elevation_status.text()
        toggle.click()
        assert window._elevation_process is None
    finally:
        window.close()


def test_elevation_rechecks_authority_before_constructing_a_process(monkeypatch):
    def refuse():
        raise PermissionError("Private native diagnostic details")

    monkeypatch.setattr(console, "_operator_elevation_available", lambda: True)
    monkeypatch.setattr(console, "_operator_elevation_launch", refuse)
    monkeypatch.setattr(console, "QProcess", lambda *_: pytest.fail("held spec created a helper"))
    window = console.ProtectionServiceConsole(reader=InertReader(), start_reader=False)
    try:
        window.elevation_toggle.click()
        assert window._elevation_process is None
        assert not window.elevation_toggle.isChecked() and not window.elevation_toggle.isEnabled()
        assert "authority could not be verified" in window.elevation_status.text()
        assert "Private" not in window.elevation_status.text()
    finally:
        window.close()


@pytest.mark.parametrize("exit_code,exit_status", [
    (1223, QProcess.ExitStatus.NormalExit),
    (0, QProcess.ExitStatus.CrashExit),
])
def test_elevation_passes_only_fixed_argument_and_retains_console_if_unverified(
    inert_elevation, monkeypatch, exit_code, exit_status,
):
    monkeypatch.setenv("ANGERONA_TEST_INHERITED_SENTINEL", "must not propagate")
    window = console.ProtectionServiceConsole(reader=InertReader(), start_reader=False)
    try:
        window.show()
        window.elevation_toggle.click()
        process = window._elevation_process
        assert process.state() == QProcess.ProcessState.Running
        assert process.program() == str(inert_elevation[0])
        assert process.workingDirectory() == str(inert_elevation[0].parent)
        assert process.arguments() == ["--operator-elevation"]
        assert process.processEnvironment().keys() == ["SystemRoot"]
        assert process.processEnvironment().value("SystemRoot") == r"C:Windows"
        window.elevation_toggle.click()
        assert len(inert_elevation) == 1 and window._elevation_process is process
        process.complete(exit_code, exit_status)
        assert window.isVisible()
        assert "readiness was not verified" in window.elevation_status.text()
        assert not window.elevation_toggle.isChecked() and not window.elevation_toggle.isEnabled()
    finally:
        process = window._elevation_process
        if process is not None:
            process.complete(1223)
        window.close()


def test_explicit_close_waits_for_the_exact_running_elevation_helper(inert_elevation):
    window = console.ProtectionServiceConsole(reader=InertReader(), start_reader=False)
    try:
        window.show()
        window.elevation_toggle.click()
        process = window._elevation_process
        assert window.close() is False
        assert window.isVisible() and window._elevation_process is process
        assert "Waiting" in window.banner.text()
        process.complete(1223)
        spin_until(lambda: not window.isVisible())
    finally:
        process = window._elevation_process
        if process is not None:
            process.complete(1223)
        window.close()


def test_verified_elevation_waits_for_status_reader_retirement(inert_elevation):
    reader = InertReader()
    retired = threading.Event()
    reader.wait_retired = retired.is_set
    window = console.ProtectionServiceConsole(reader=reader, start_reader=False)
    try:
        window.show()
        window.elevation_toggle.click()
        window._elevation_process.complete(0)
        assert reader.detached and window.isVisible()
        assert "readiness verified" in window.elevation_status.text()
        retired.set()
        spin_until(lambda: not window.isVisible())
    finally:
        retired.set()
        process = window._elevation_process
        if process is not None:
            process.complete(1223)
        window.close()


def test_elevation_failed_to_start_releases_the_exact_process(inert_elevation):
    window = console.ProtectionServiceConsole(reader=InertReader(), start_reader=False)
    try:
        window.elevation_toggle.click()
        process = window._elevation_process
        process.test_state = QProcess.ProcessState.NotRunning
        process.errorOccurred.emit(QProcess.ProcessError.FailedToStart)
        assert window._elevation_process is None
        assert not window.elevation_toggle.isChecked() and window.elevation_toggle.isEnabled()
        assert "could not start" in window.elevation_status.text()
    finally:
        window.close()


def test_console_sends_one_bounded_startup_notice_after_visible_paint(monkeypatch):
    sent = []
    paints = []

    class ObservedConsole(console.ProtectionServiceConsole):
        def paintEvent(self, event):
            paints.append(True)
            super().paintEvent(event)

    def notify(endpoint):
        sent.append((endpoint, bool(paints), threading.get_ident()))

    monkeypatch.setattr(console, "notify_dashboard_ready", notify)
    endpoint = "49152:" + "a" * 64
    qt_thread = threading.get_ident()
    window = ObservedConsole(reader=InertReader(), start_reader=False, startup_endpoint=endpoint)
    try:
        QApplication.processEvents()
        assert not paints and not sent
        window.show()
        spin_until(lambda: len(sent) == 1 and not window._pending_window_work())
        assert sent[0][0] == endpoint and sent[0][1] is True and sent[0][2] != qt_thread
        prior_paints = len(paints)
        window.update()
        spin_until(lambda: len(paints) > prior_paints)
        assert len(sent) == 1
    finally:
        window.close()
