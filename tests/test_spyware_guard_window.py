"""Native navigation/layout checks with every host worker forbidden or parked."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap


def test_dedicated_spyware_window_and_responsive_header_preserve_runtime_gates(tmp_path):
    root = Path(__file__).resolve().parents[1]
    script = textwrap.dedent(f"""\
        import sys, json, threading, subprocess, socket
        from pathlib import Path
        sys.path.insert(0, {str(root / 'src')!r})
        from angerona.__main__ import _install_fast_pyside_feature_detection
        _install_fast_pyside_feature_detection()
        from angerona.core import data_paths
        data_paths._elevated_source_runtime = lambda: False
        data_paths.configure_runtime_environment()
        from PySide6.QtCore import QPoint, QRect, Qt, QTimer
        from PySide6.QtTest import QTest
        from PySide6.QtWidgets import QApplication
        app = QApplication([])
        app.setQuitOnLastWindowClosed(False)
        forbidden = []
        def forbid(*args, **kwargs):
            forbidden.append('host operation')
            raise AssertionError('No process, network, or detector may start in this fixture')
        subprocess.Popen = forbid
        socket.socket.connect = forbid
        socket.socket.connect_ex = forbid
        parked = []
        threading.Thread.start = lambda thread: parked.append(thread.name)
        from angerona.core.config import Config
        from angerona.core.eventbus import EventBus
        from angerona.core.module_base import BaseModule
        from angerona.core.module_manager import ModuleManager
        from angerona.core.storage import FlightRecorder
        from angerona.gui.main_window import MainWindow
        from angerona.gui.header_controls import navigation_icon
        BaseModule.start = forbid
        config = Config(data_dir=Path({str(tmp_path)!r}), ui_motion_enabled=False,
                        ui_scale_mode='fixed', ui_scale_fixed=1.0)
        storage = FlightRecorder(config.db_path)
        bus = EventBus()
        bus.arm(storage.authority)
        manager = ModuleManager(bus, config, recorder=storage)
        manager.start_enabled = forbid
        window = MainWindow(bus, storage, manager, config)
        window._panel_reveal.enable_global_windows(False)
        window.show()
        widths, font_widths = [], []
        try:
            assert window.spyware_guard is None
            assert window.spyware_guard_page is None
            assert window._spyware_guard_dialog is None
            assert 'SpywareGuard' not in [window._right_tabs.tabText(i)
                                          for i in range(window._right_tabs.count())]
            spy = window._spyware_guard_btn
            assert spy.parentWidget() is window._header_groups[2]
            assert spy in window._header_nav_buttons
            assert spy.accessibleName().startswith('SpywareGuard')
            pixels = navigation_icon('spyware').pixmap(22, 22).toImage()
            opaque = [pixels.pixelColor(x, y) for x in range(pixels.width())
                      for y in range(pixels.height()) if pixels.pixelColor(x, y).alpha()]
            assert opaque and all(c.red() == c.green() == c.blue() == 0 for c in opaque)
            # Simultaneous startup and self-test publications remain
            # active through every width/font allocation; no host work runs.
            activity_text = 'Starting local protection and reading diagnostics ' * 18
            window.run_spinner.start(activity_text)
            window.loading_indicator._on_started('header-fixture', activity_text, 1, 4)
            window.loading_indicator._reveal_if_active()
            for scale in (1.0, 1.35):
                config.ui_scale_fixed = scale
                for width in (480, 640, 850, 1100, 1280, 1599, 1920, 2560, 3840):
                    window.resize(width, 900)
                    window._apply_dashboard_layout()
                    # Width constraints propagate through the nested header
                    # layouts on subsequent native event-loop turns.
                    QTest.qWait(30)
                    for timer in window.findChildren(QTimer):
                        timer.stop()
                    for group in window._header_groups[::2]:
                        buttons = [button for button in
                                   window._header_primary_buttons + window._header_nav_buttons
                                   + [window._header_stop_button] if button.parentWidget() is group]
                        for index, button in enumerate(buttons):
                            assert button.width() >= 32 and button.height() >= 32, (width, scale)
                            assert group.rect().contains(button.geometry()), (width, scale, button.accessibleName())
                            assert not any(button.geometry().intersects(other.geometry())
                                           for other in buttons[index + 1:]), (width, scale,
                                [(b.accessibleName(), b.geometry().getRect()) for b in buttons],
                                group.geometry().getRect(), group.minimumSizeHint().toTuple(),
                                group.layout().minimumSize().toTuple(), window._header_layout.minimumSize().toTuple())
                        # Groups belong to the horizontally scrollable content;
                        # the viewport, rather than all content, must fit the window.
                        assert window._header_action_strip._content.rect().contains(
                            QRect(group.mapTo(window._header_action_strip._content, QPoint()), group.size()))
                    strip = window._header_action_strip
                    viewport = window.centralWidget().viewport()
                    assert viewport.rect().contains(QRect(strip.mapTo(viewport, QPoint()), strip.size()))
                    stop = window._header_stop_button
                    assert stop.parentWidget() is window._header_control_row
                    assert stop.isVisible() and stop.text() == stop._full_label
                    assert viewport.rect().contains(QRect(stop.mapTo(viewport, QPoint()), stop.size()))
                    assert not strip.geometry().intersects(stop.geometry())
                    assert abs(stop.geometry().right() - window._header_control_row.rect().right()) <= 1
                    assert strip.verticalScrollBar().maximum() == 0
                    if strip._content.width() > strip.viewport().width():
                        assert strip.horizontalScrollBar().maximum() > 0
                    # Focus must reveal every off-screen control without invoking it.
                    controls = window._header_primary_buttons + window._header_nav_buttons
                    for button in controls:
                        assert button.accessibleName() and button.accessibleDescription() and button.toolTip()
                        button.setFocus(Qt.TabFocusReason)
                        app.processEvents()
                        assert app.focusWidget() is button
                        visible = strip.viewport().rect()
                        rect = QRect(button.mapTo(strip.viewport(), QPoint()), button.size())
                        if button.width() <= visible.width():
                            assert visible.contains(rect), (width, scale, button.accessibleName(), rect.getRect())
                        else:
                            # A large-font control may exceed the narrow viewport.
                            # Focus reveals its center and scrolling reaches both edges.
                            assert visible.contains(rect.center())
                            assert visible.intersected(rect).width() == visible.width()
                            bar = strip.horizontalScrollBar()
                            bar.setValue(bar.value() + rect.left())
                            assert button.mapTo(strip.viewport(), QPoint()).x() >= visible.left()
                            rect = QRect(button.mapTo(strip.viewport(), QPoint()), button.size())
                            bar.setValue(bar.value() + rect.right() - visible.right())
                            assert button.mapTo(strip.viewport(), QPoint()).x() + button.width() <= visible.right() + 1
                    for button in window._header_primary_buttons + [spy, stop]:
                        assert not button.is_compact()
                        if button.width() >= button.full_label_width():
                            assert button.text() == button._full_label
                        else:
                            # The explicit 400px safety cap still elides rather than clips.
                            assert button.text() and button.text() != button._full_label
                            assert '\u2026' in button.text()
                    # Tab across the actual focus chain keeps STOP reachable.
                    controls[0].setFocus(Qt.TabFocusReason)
                    seen = set()
                    for _ in range(len(controls) + 2):
                        focused = app.focusWidget()
                        seen.add(focused)
                        if focused is stop:
                            break
                        QTest.keyClick(focused, Qt.Key_Tab)
                        app.processEvents()
                    assert stop in seen and set(controls).issubset(seen)
                    lane = window._header_activity_box
                    assert lane.isVisible()
                    assert lane.parentWidget() is not window._header_groups[1]
                    indicators = (window.run_spinner, window.loading_indicator)
                    assert all(lane.rect().contains(activity.geometry()) for activity in indicators)
                    assert not indicators[0].geometry().intersects(indicators[1].geometry())
                    for activity in indicators:
                        assert activity_text in activity.current_text
                        assert activity.accessibleDescription() == activity.current_text
                        assert activity.toolTip() == activity.current_text
                        assert activity._label.fontMetrics().horizontalAdvance(activity._label.text()) <= activity._label.contentsRect().width()
                    assert spy.width() > window.threat_intel_btn.width(), (width, scale)
                    widths.append((scale, width, window._selftest_btn.width(),
                                   window.threat_intel_btn.width(), spy.width()))
            # Navigation peers keep their icon-only allocations even when a
            # stylesheet increases their natural text hint; Spyware keeps its
            # complete semantic caption.
            for pixels in (32, 10, 26):
                window.threat_intel_btn.setStyleSheet(
                    'font-size:%dpx; font-weight:700;' % pixels)
                window.resize(3840, 900)
                window._apply_dashboard_layout()
                peers = [button for button in window._header_nav_buttons if button is not spy]
                assert spy.minimumWidth() > max(button.minimumWidth() for button in peers)
                assert spy.maximumWidth() == spy.minimumWidth() <= 400
                assert all(button.maximumWidth() == button.minimumWidth() <= 380 for button in peers)
                QTest.qWait(30)
                assert spy.width() > max(button.width() for button in peers)
                right = window._header_groups[2]
                buttons = window._header_nav_buttons
                for index, button in enumerate(buttons):
                    assert right.rect().contains(button.geometry())
                    assert not any(button.geometry().intersects(other.geometry())
                                   for other in buttons[index + 1:])
                font_widths.append((pixels, spy.width(), window.threat_intel_btn.width()))
            window.loading_indicator._on_finished('header-fixture')
            window.run_spinner.stop()
            app.processEvents()
            assert window._header_activity_box.isHidden()
            # Window width changes scroll capacity, not readable label size.
            for scale in (1.0, 1.35):
                samples = [row for row in widths if row[0] == scale]
                assert len({{row[2:] for row in samples}}) == 1
            spy.click()
            app.processEvents()
            dialog, page = window._spyware_guard_dialog, window.spyware_guard_page
            assert dialog is not None and dialog.isVisible()
            QTest.qWait(30)
            assert dialog.screen().availableGeometry().contains(dialog.frameGeometry())
            assert page is window.spyware_guard and page._timer.isActive()
            page.setting_checks['spyware_memory_enabled'].setChecked(True)
            dialog.close()
            app.processEvents()
            assert not dialog.isVisible() and not page._timer.isActive()
            assert not page._closed
            assert window._open_spyware_guard() is dialog
            assert page._timer.isActive() and page.setting_checks['spyware_memory_enabled'].isChecked()
            manager._ugcap_paused = True
            window._sync_ugcap_gate()
            assert not spy.isEnabled() and not dialog.isEnabled() and not page.isEnabled()
            assert window._open_spyware_guard() is None
            manager._ugcap_paused = False
            window._sync_ugcap_gate()
            assert spy.isEnabled() and dialog.isEnabled() and page.isEnabled()
            window._close_spyware_guard_window()
            assert page._closed and not page._timer.isActive() and not dialog.isVisible()
            assert window._open_spyware_guard() is None
            assert forbidden == [] and manager.modules == {{}}
            print(json.dumps({{'widths': widths, 'font_widths': font_widths, 'reopen': True, 'lockdown': True,
                              'host_operations': forbidden}}), flush=True)
        finally:
            window._close_spyware_guard_window()
            for timer in window.findChildren(QTimer):
                timer.stop()
            if window._ui_watchdog is not None:
                window._ui_watchdog.stop()
            window.system_pulse.shutdown()
            window._responsiveness_monitor.close()
            window._holographic_orb.shutdown()
            for name in ('_posture_reader', '_usage_reconciler', '_flow_writer', '_security_reader'):
                getattr(window, name).close()
            window.tray.hide()
            storage.close()
            app.shutdown()
        """)
    environment = dict(os.environ)
    environment.update({
        "QT_QPA_PLATFORM": "offscreen", "ANGERONA_REDUCE_MOTION": "1",
        "ANGERONA_DATA": str(tmp_path), "ANGERONA_DIAG_DIR": str(tmp_path / "diagnostics"),
        "ANGERONA_BLACKBOX_ENABLED": "0",
    })
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", script], cwd=root, env=environment,
        input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90, check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")[-10000:]
    evidence = json.loads(result.stdout.decode().splitlines()[-1])
    assert len(evidence["widths"]) == 18
    assert len(evidence["font_widths"]) == 3
    assert evidence["reopen"] and evidence["lockdown"] and evidence["host_operations"] == []
