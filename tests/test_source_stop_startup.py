"""Desktop source STOP ownership precedes App construction and peer launch."""
from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace

import pytest

import angerona.__main__ as entry
from angerona.resilience import source_stop as stop


@pytest.fixture
def source(tmp_path, monkeypatch):
    storage, root = tmp_path / "SourceData", tmp_path / "source"
    storage.mkdir()
    root.mkdir()
    identity = stop._Identity("S-1-5-21-11-22-33-1001", 2, 101,
                              134000000000000001, str(tmp_path / "python.exe"))
    monkeypatch.setattr(stop, "_effective_identity", lambda: identity)
    monkeypatch.setattr(stop, "_source_root", lambda: root)
    monkeypatch.setattr(sys, "argv", ["angerona"])
    # main() writes the variable directly; record initial absence as well.
    monkeypatch.setenv(stop.SOURCE_SESSION_ENV, "")
    monkeypatch.delenv(stop.SOURCE_SESSION_ENV, raising=False)
    monkeypatch.delenv("ANGERONA_SUPERVISED_RECOVERY", raising=False)
    from angerona.core import data_paths
    monkeypatch.setattr(data_paths, "data_dir", lambda: storage)
    return storage


def _context(storage):
    result = stop.create_source_session(storage)
    assert result is not None
    return result


def test_explicit_singleton_owner_creates_epoch_and_publishes_own_reference(source):
    context = entry._source_stop_session_after_lock(object(), ordinary_source=True)
    assert context is not None and context.respawn_allowed()
    assert entry.os.environ[stop.SOURCE_SESSION_ENV] == context.epoch


def test_second_instance_does_not_create_rotate_or_retarget_epoch(source, monkeypatch):
    original = _context(source)
    monkeypatch.setenv(stop.SOURCE_SESSION_ENV, "invalid reference")
    def forbidden(*_args, **_kwargs):
        raise AssertionError("A second instance touched source session authority")
    monkeypatch.setattr(stop, "create_source_session", forbidden)
    monkeypatch.setattr(stop, "join_source_session", forbidden)
    assert entry._source_stop_session_after_lock(None, ordinary_source=True) is None
    assert entry.os.environ[stop.SOURCE_SESSION_ENV] == "invalid reference"
    assert original.respawn_allowed()


@pytest.mark.parametrize("epoch", ["", "bad", "A" * 32, "../current.json", "0" * 33])
def test_invalid_inherited_epoch_holds_instead_of_creating(source, monkeypatch, epoch):
    monkeypatch.setenv(stop.SOURCE_SESSION_ENV, epoch)
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Bad recovery reference became a fresh source epoch")
    monkeypatch.setattr(stop, "create_source_session", forbidden)
    with pytest.raises(entry._SourceStopStartupHeld):
        entry._source_stop_session_after_lock(object(), ordinary_source=True)
    assert list(source.iterdir()) == []


def test_supervised_source_recovery_requires_inherited_epoch(source, monkeypatch):
    original = _context(source)
    monkeypatch.setenv("ANGERONA_SUPERVISED_RECOVERY", "1")
    with pytest.raises(entry._SourceStopStartupHeld):
        entry._source_stop_session_after_lock(object(), ordinary_source=True)
    assert original.respawn_allowed()


@pytest.mark.parametrize("supervised", [False, True])
def test_valid_inherited_epoch_joins_exact_old_context_without_rotation(source, monkeypatch, supervised):
    original = _context(source)
    monkeypatch.setenv(stop.SOURCE_SESSION_ENV, original.epoch)
    if supervised:
        monkeypatch.setenv("ANGERONA_SUPERVISED_RECOVERY", "1")
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Inherited source recovery rotated the epoch")
    monkeypatch.setattr(stop, "create_source_session", forbidden)
    joined = entry._source_stop_session_after_lock(object(), ordinary_source=True)
    assert joined is not None and joined.epoch == original.epoch
    assert joined.respawn_allowed()


def test_stopped_or_missing_inherited_epoch_holds_without_retargeting(source, monkeypatch):
    original = _context(source)
    original.request_stop()
    monkeypatch.setenv(stop.SOURCE_SESSION_ENV, original.epoch)
    with pytest.raises(entry._SourceStopStartupHeld):
        entry._source_stop_session_after_lock(object(), ordinary_source=True)
    assert original.is_stop_requested()
    monkeypatch.setenv(stop.SOURCE_SESSION_ENV, "0" * 32)
    with pytest.raises(entry._SourceStopStartupHeld):
        entry._source_stop_session_after_lock(object(), ordinary_source=True)
    assert entry.os.environ[stop.SOURCE_SESSION_ENV] == "0" * 32


@pytest.mark.parametrize("headless,ordinary", [(False, False), (True, True)])
def test_protected_and_headless_paths_do_not_consult_source_authority(source, monkeypatch, headless, ordinary):
    if headless:
        monkeypatch.setattr(sys, "argv", ["angerona", "--headless"])
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Unintegrated/protected path consulted source authority")
    monkeypatch.setattr(stop, "create_source_session", forbidden)
    monkeypatch.setattr(stop, "join_source_session", forbidden)
    assert entry._source_stop_session_after_lock(object(), ordinary_source=ordinary) is None
    assert list(source.iterdir()) == []


@pytest.mark.parametrize("platform,frozen", [("linux", False), ("win32", True)])
def test_classification_does_not_probe_source_for_other_profiles(monkeypatch, platform, frozen):
    monkeypatch.setattr(sys, "platform", platform)
    monkeypatch.setattr(sys, "frozen", frozen, raising=False)
    def forbidden():
        raise AssertionError("Profile classification probed source identity")
    monkeypatch.setattr(stop, "source_runtime_admitted", forbidden)
    assert not entry._ordinary_source_stop_runtime()


def test_classification_uses_native_admission_and_holds_unknown(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setattr(stop, "source_runtime_admitted", lambda: True)
    assert entry._ordinary_source_stop_runtime()
    monkeypatch.setattr(stop, "source_runtime_admitted", lambda: False)
    assert not entry._ordinary_source_stop_runtime()
    def failed():
        raise OSError("unknown native identity")
    monkeypatch.setattr(stop, "source_runtime_admitted", failed)
    assert not entry._ordinary_source_stop_runtime()


def _module(monkeypatch, name, **attributes):
    module = ModuleType(name)
    module.__dict__.update(attributes)
    monkeypatch.setitem(sys.modules, name, module)
    return module


@pytest.fixture
def desktop(source, monkeypatch):
    """Inert main() graph: no Qt/native child, threads, inventory or sensors."""
    events, apps = [], []
    state = SimpleNamespace(ordinary=True, lock=None, apps=apps, events=events,
                            generic_stop=False, storage=source)
    class Lock:
        def close(self):
            events.append("lock-close")
    state.lock = Lock()
    def acquire():
        events.append("lock-acquired" if state.lock is not None else "lock-denied")
        return state.lock
    class Qt:
        @staticmethod
        def instance():
            # This graph creates no native QApplication. The repository's
            # deferred-deletion teardown must not treat this fake as one.
            return None

        def __init__(self, _args):
            events.append("qt")
        def setApplicationName(self, _name):
            pass
        def setQuitOnLastWindowClosed(self, _value):
            pass
        def exec(self):
            events.append("qt-exec")
            return 17
    class Inventory:
        def __init__(self):
            events.append("inventory")
        def request_stop(self):
            events.append("inventory-stop")
    class App:
        def __init__(self, _qt, **kwargs):
            events.append("app")
            self.kwargs = kwargs
            apps.append(self)
        def start(self):
            events.append("app-start")
            return True
        def shutdown(self):
            events.append("app-shutdown")
            self.kwargs["process_snapshot_lifecycle"].request_stop()
    def generic_stop():
        events.append("generic-admin-probe")
        return state.generic_stop
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setattr(entry, "_source_activation_pending_guard", lambda: False)
    monkeypatch.setattr(entry, "_install_fast_pyside_feature_detection", lambda: True)
    monkeypatch.setattr(entry, "_ordinary_source_stop_runtime", lambda: state.ordinary)
    _module(monkeypatch, "angerona.core.privilege", ElevationResult=type("Elevation", (), {}),
            OPERATOR_ELEVATION_ARGUMENT="--operator-elevation", ensure_admin=lambda: None,
            is_admin=lambda: False)
    _module(monkeypatch, "angerona.core.startup_protocol",
            parse_startup_arguments=lambda arguments: (list(arguments), None))
    _module(monkeypatch, "angerona.core.data_paths",
            configure_runtime_environment=lambda: events.append("configured"), data_dir=lambda: source)
    _module(monkeypatch, "angerona.core.win", install_no_window_default=lambda: None)
    _module(monkeypatch, "angerona.core.crashlog", install=lambda: None)
    _module(monkeypatch, "angerona.core.hardening", apply_process_mitigations=lambda: None)
    _module(monkeypatch, "angerona.core.singleton", acquire_single_instance=acquire)
    _module(monkeypatch, "angerona.branding", icon_path=lambda: None)
    _module(monkeypatch, "angerona.core.process_snapshot_lifecycle", ProcessSnapshotLifecycle=Inventory)
    _module(monkeypatch, "angerona.app", AngeronaApp=App)
    _module(monkeypatch, "angerona.resilience.shutdown_token", is_standdown_requested=generic_stop,
            signal_external_watchdog_stop=lambda: events.append("external-stop"))
    _module(monkeypatch, "PySide6.QtGui", QIcon=lambda value: value)
    _module(monkeypatch, "PySide6.QtWidgets", QApplication=Qt,
            QMessageBox=SimpleNamespace(information=lambda *_args: events.append("already-running")))
    return state


def test_main_creates_source_context_after_actual_lock_before_app(desktop, monkeypatch):
    real_create = stop.create_source_session
    def create(storage):
        assert storage == desktop.storage
        assert "lock-acquired" in desktop.events
        assert "qt" not in desktop.events and "app" not in desktop.events
        desktop.events.append("source-create")
        return real_create(storage)
    monkeypatch.setattr(stop, "create_source_session", create)
    assert entry.main() == 17
    context = desktop.apps[0].kwargs["source_stop_context"]
    assert type(context) is stop.SourceStopContext
    assert desktop.events.index("lock-acquired") < desktop.events.index("source-create")
    assert desktop.events.index("source-create") < desktop.events.index("inventory")
    assert desktop.events.index("source-create") < desktop.events.index("app")


def test_main_second_instance_never_rotates_source_session(desktop, monkeypatch):
    desktop.lock = None
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Second instance created source authority")
    monkeypatch.setattr(stop, "create_source_session", forbidden)
    assert entry.main() == 0
    assert desktop.apps == []
    assert "already-running" in desktop.events
    assert list(desktop.storage.iterdir()) == []


def test_source_recovery_skips_admin_namespace_and_missing_epoch_holds_before_app(desktop, monkeypatch):
    monkeypatch.setenv("ANGERONA_SUPERVISED_RECOVERY", "1")
    desktop.generic_stop = True
    assert entry.main() == 2
    assert "generic-admin-probe" not in desktop.events
    assert "lock-close" in desktop.events
    assert "qt" not in desktop.events and "inventory" not in desktop.events
    assert desktop.apps == []


def test_main_source_recovery_joins_exact_epoch_and_does_not_clear_it(desktop, monkeypatch):
    original = _context(desktop.storage)
    monkeypatch.setenv(stop.SOURCE_SESSION_ENV, original.epoch)
    monkeypatch.setenv("ANGERONA_SUPERVISED_RECOVERY", "1")
    assert entry.main() == 17
    assert desktop.apps[0].kwargs["source_stop_context"].epoch == original.epoch
    assert "generic-admin-probe" not in desktop.events


def test_main_held_source_session_never_constructs_app_or_inventory(desktop, monkeypatch):
    monkeypatch.setattr(stop, "create_source_session", lambda _storage: None)
    assert entry.main() == 2
    assert "lock-close" in desktop.events
    assert "qt" not in desktop.events and "inventory" not in desktop.events
    assert desktop.apps == []


def test_non_source_flow_adds_no_context_keyword_to_existing_app_fakes(desktop):
    desktop.ordinary = False
    assert entry.main() == 17
    assert "source_stop_context" not in desktop.apps[0].kwargs
    assert list(desktop.storage.iterdir()) == []


def test_protected_recovery_keeps_generic_stop_precedence(desktop, monkeypatch):
    desktop.ordinary, desktop.generic_stop = False, True
    monkeypatch.setenv("ANGERONA_SUPERVISED_RECOVERY", "1")
    assert entry.main() == 0
    assert desktop.events == ["configured", "generic-admin-probe", "external-stop"]
    assert desktop.apps == []
