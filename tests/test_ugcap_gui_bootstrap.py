"""A clean GUI import must leave ordinary detector code behind the UGCAP gate."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap


def test_fresh_gui_import_and_idle_drill_constructor_do_not_preload_detectors(tmp_path):
    root = Path(__file__).resolve().parents[1]
    source = root / "src"
    script = (
        "import sys,json\n"
        f"sys.path.insert(0,{str(source)!r})\n"
        "from angerona.__main__ import _install_fast_pyside_feature_detection\n"
        "_install_fast_pyside_feature_detection()\n"
        "import angerona.gui.main_window\n"
        "def ordinary():\n"
        "    return sorted(name for name in sys.modules if name.startswith('angerona.modules.')"
        " and name not in {'angerona.modules.ugcap_guard','angerona.modules.adversary_combat'})\n"
        "assert ordinary()==[], ordinary()\n"
        "from angerona.shark.red_team import RedTeamEngine\n"
        "from pathlib import Path\n"
        f"engine=RedTeamEngine(Path({str(tmp_path)!r}))\n"
        "assert ordinary()==[], ordinary()\n"
        "engine.stop_and_clean()\n"
        "assert ordinary()==[], ordinary()\n"
        "print(json.dumps({'ordinary':ordinary(),'constructed':True,'idle_cleanup':True}))\n"
    )
    environment = dict(os.environ)
    environment["QT_QPA_PLATFORM"] = "offscreen"
    result = subprocess.run([sys.executable, "-I", "-c", script], cwd=root, env=environment,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45, check=False)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")[-8000:]
    assert json.loads(result.stdout.decode().splitlines()[-1]) == {
        "ordinary": [], "constructed": True, "idle_cleanup": True}


def test_fresh_full_window_keeps_bootstrap_clean_and_locks_before_first_paint(tmp_path):
    """Build the real widget tree, without starting workers, sockets or services."""
    root = Path(__file__).resolve().parents[1]
    source = root / "src"
    script = textwrap.dedent(f"""\
        import sys, json, os, threading, subprocess, socket
        from pathlib import Path
        sys.path.insert(0, {str(source)!r})
        from angerona.core import data_paths
        data_paths._elevated_source_runtime = lambda: False
        data_paths.configure_runtime_environment()
        from angerona.__main__ import _install_fast_pyside_feature_detection
        _install_fast_pyside_feature_detection()
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication
        app = QApplication([])
        app.setQuitOnLastWindowClosed(False)
        from angerona.core import ollama_lifecycle
        forbidden = []
        def forbid(*args, **kwargs):
            forbidden.append('external operation')
            raise AssertionError('External launch/network/module start forbidden in GUI fixture')
        ollama_lifecycle.request_ollama_start = forbid
        ollama_lifecycle.ensure_ollama_service = forbid
        ollama_lifecycle._spawn_ollama_service = forbid
        subprocess.Popen = forbid
        socket.socket.connect = forbid
        socket.socket.connect_ex = forbid
        # UI helper threads are intentionally parked; no module or host worker
        # may run while we inspect the constructor and its gate synchronizer.
        parked_threads = []
        threading.Thread.start = lambda thread: parked_threads.append(thread.name)
        from angerona.core.config import Config
        from angerona.core.eventbus import EventBus
        from angerona.core.module_base import BaseModule
        from angerona.core.module_manager import ModuleManager
        from angerona.core.storage import FlightRecorder
        from angerona.gui.main_window import MainWindow
        BaseModule.start = forbid
        config = Config(data_dir=Path({str(tmp_path)!r}), ugcap_enabled=True,
                        dashboard_mode='flow')
        storage = FlightRecorder(config.db_path)
        bus = EventBus()
        bus.arm(storage.authority)
        manager = ModuleManager(bus, config, recorder=storage)
        manager.start_enabled = forbid
        manager.discover()
        assert set(manager.modules) == {{'UGCAP Integrity Guard', 'Adversary Combat'}}, manager.modules
        assert not manager.discovery_errors, manager.discovery_errors
        window = MainWindow(bus, storage, manager, config)
        def ordinary():
            return sorted(name for name in sys.modules
                if name.startswith('angerona.modules.') and name not in {{
                    'angerona.modules.ugcap_guard', 'angerona.modules.adversary_combat'}})
        def check_locked():
            assert manager.ugcap_paused is True
            assert window._ugcap_workspace_locked is True
            tabs = window._right_tabs
            assert tabs.currentWidget() is window.ugcap_page
            for index in range(tabs.count()):
                page = tabs.widget(index)
                assert tabs.isTabEnabled(index) is (page is window.ugcap_page)
                assert page.isEnabled() is (page is window.ugcap_page)
            assert not window.modules_panel.isEnabled()
            assert not window.console.isEnabled()
            for widget in window._header_primary_buttons:
                assert not widget.isEnabled()
            for widget in window._header_nav_buttons:
                if widget not in {{window._settings_btn, window._help_btn}}:
                    assert not widget.isEnabled()
            assert window._settings_btn.isEnabled() and window._help_btn.isEnabled()
        try:
            # This must hold immediately: there has been no timer/event-loop
            # dispatch that could apply a delayed first-refresh correction.
            check_locked()
            assert ordinary() == [], ordinary()
            assert manager.requires_ugcap_restart is False
            assert forbidden == [], forbidden
            assert len(threading.enumerate()) == 1
            assert all(module._thread is None for module in manager.modules.values())
            # Exercise the real GUI lock-state transitions without granting a
            # code-attestation lease or starting a detector in this fixture.
            manager._ugcap_paused = False
            window._sync_ugcap_gate()
            assert window._ugcap_workspace_locked is False
            assert window.modules_panel.isEnabled()
            assert window.console.isEnabled()
            assert all(window._right_tabs.isTabEnabled(i)
                       for i in range(window._right_tabs.count()))
            manager._ugcap_paused = True
            window._sync_ugcap_gate()
            check_locked()
            assert ordinary() == [] and not manager.requires_ugcap_restart
            print(json.dumps({{'constructed': True, 'initial_locked': True,
                  'gate_transitions': True, 'ordinary': ordinary(),
                  'restart_required': manager.requires_ugcap_restart,
                  'parked_threads': parked_threads}}), flush=True)
        finally:
            # Never call the product's whole-process termination/shutdown path
            # from a GUI fixture. Only dispose this child's UI resources.
            for timer in window.findChildren(QTimer):
                timer.stop()
            window._ui_watchdog.stop()
            window.system_pulse.shutdown()
            window._responsiveness_monitor.close()
            window._holographic_orb.shutdown()
            for name in ('_posture_reader', '_usage_reconciler', '_flow_writer',
                         '_security_reader'):
                getattr(window, name).close()
            window.tray.hide()
            storage.close()
            app.shutdown()
        """)
    environment = dict(os.environ)
    environment.update({"QT_QPA_PLATFORM": "offscreen", "ANGERONA_DATA": str(tmp_path),
                        "ANGERONA_DIAG_DIR": str(tmp_path / "diagnostics"),
                        "ANGERONA_BLACKBOX_ENABLED": "0"})
    result = subprocess.run([sys.executable, "-I", "-c", script], cwd=root, env=environment,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45, check=False)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")[-8000:]
    evidence = json.loads(result.stdout.decode().splitlines()[-1])
    assert evidence["constructed"] and evidence["initial_locked"] and evidence["gate_transitions"]
    assert evidence["ordinary"] == [] and evidence["restart_required"] is False
