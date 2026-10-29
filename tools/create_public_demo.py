"""Capture real Qt widgets with inert fixtures, then encode a bounded public GIF.

Capture uses the repository Qt runtime. Encode uses the managed Python/Pillow
runtime, without importing Angerona or Qt. Every frame retains a visible DEMO
banner. No scan, response button, model, external service or cloud API is used.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


ROOT = Path(__file__).resolve().parents[1]
SCRATCH = ROOT / ".tmp" / "public-demo-20261028"
MAX_GIF = 12 * 1024 * 1024
CHAPTERS = 9
FRAMES_PER_CHAPTER = 10
FRAME_DURATION_MS = 500
FRAME_COUNT = CHAPTERS * FRAMES_PER_CHAPTER
MAX_FRAME_BYTES = 8 * 1024 * 1024
MAX_CAPTURE_BYTES = 64 * 1024 * 1024


def plain(path: Path, *, scratch: bool = False) -> Path:
    if not path.is_absolute():
        raise ValueError("demo paths must be absolute")
    path = Path(os.path.abspath(path))
    if scratch and (not path.is_relative_to(SCRATCH) or path == SCRATCH):
        raise ValueError("demo scratch must remain inside its explicit task directory")
    for item in (*reversed(path.parents), path):
        if item.exists():
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("demo refuses redirected paths")
            if item == path and not stat.S_ISDIR(info.st_mode) and info.st_nlink != 1:
                raise ValueError("demo refuses multiply linked files")
    return path


def identity() -> dict:
    class FileTime(ctypes.Structure):
        _fields_ = [("value", ctypes.c_ulonglong)]
    created, exited, kernel, user = FileTime(), FileTime(), FileTime(), FileTime()
    if not ctypes.windll.kernel32.GetProcessTimes(ctypes.c_void_p(-1), ctypes.byref(created),
            ctypes.byref(exited), ctypes.byref(kernel), ctypes.byref(user)):
        raise ctypes.WinError()
    return {"pid": os.getpid(), "creation_filetime": str(created.value)}


def publish_media(staged: Path, destination: Path, *, replace: bool) -> None:
    """Replace only the explicit reviewed demo asset, preserving raced edits."""
    staged, destination = plain(staged), plain(destination)
    prior = None
    if destination.exists():
        if not replace:
            raise ValueError("updating an existing public demo requires --replace-existing-demo")
        if destination.stat().st_size > MAX_GIF:
            raise ValueError("existing demo asset exceeds its bounded replacement read")
        prior = hashlib.sha256(destination.read_bytes()).digest()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if prior is None or hashlib.sha256(destination.read_bytes()).digest() != prior:
            raise ValueError("public demo asset changed during publication")
    elif prior is not None:
        raise ValueError("public demo asset disappeared during publication")
    os.replace(staged, destination)


def _settings_fixture(config, forbidden):
    """Install inert readers before constructing the real Settings dialog."""
    from angerona.connectors import hand_controls, voice
    from angerona.core import autostart, process_allowlist, provider_credentials, secure_store, usb_policy
    from angerona.gui.pages import SettingsDialog
    from types import SimpleNamespace

    autostart.is_enabled = lambda: False
    autostart.enable_autostart = autostart.disable_autostart = forbidden
    secure_store.read_secret_values = lambda *_args, **_kwargs: {}
    secure_store.read_secret_map = lambda *_args, **_kwargs: {}
    provider_credentials.provider_form_values = lambda: {
        provider.provider_id: "" for provider in provider_credentials.PROVIDER_CREDENTIALS}
    usb_policy.usb_pin_configured = lambda: False
    process_allowlist.entries = lambda *_args, **_kwargs: []
    voice.Voice.list_input_devices = staticmethod(lambda: [])
    voice.offline_model_status = lambda: (False, "DEMO - speech service and microphone not opened")
    hand_controls.HandControls = lambda *_args, **_kwargs: SimpleNamespace(
        status=lambda: "DEMO - camera and hand controls not opened")
    config.save = forbidden
    settings = SettingsDialog(config, forbidden, forbidden, initial_tab="General")
    if any(field.text() for field in settings._key_fields.values()):
        raise RuntimeError("the Settings fixture unexpectedly contains a provider credential")
    if settings._aria_imap_pass.text() or settings._teams_pw.text():
        raise RuntimeError("the Settings fixture unexpectedly contains a connector credential")
    return settings


def _attack_fixture(parent, forbidden):
    """Real MITRE widget, fixed technique samples, explicitly unavailable proof."""
    from types import SimpleNamespace
    from angerona.core import attack_coverage
    from angerona.gui import attack_heatmap

    matrix = {}
    for index, tid in enumerate(("T1059", "T1071", "T1547", "T1055", "T1003", "T1021")):
        meta = attack_heatmap._TID_TO_META.get(tid)
        if meta is None:
            continue
        matrix[tid] = {"label": meta[0], "fullname": meta[2], "tactic": meta[1],
                       "heat": .85 - index * .1, "count": 12 - index,
                       "last_seen": "DEMO fixed replay", "event_ids": [f"DEMO-{index:03d}"]}
    snapshot = {"generated": "DEMO - fixed synthetic replay", "matrix": matrix,
                "summary": {"techniques_active": len(matrix),
                            "tactics_active": len({row["tactic"] for row in matrix.values()}),
                            "highest_heat_tid": "T1059", "highest_heat_label": "Synthetic execution sample"}}
    attack_heatmap.get_tracker = lambda: SimpleNamespace(snapshot=lambda: snapshot, reset=forbidden)
    attack_coverage.readiness_snapshot = lambda *_args, **_kwargs: {
        "available": False, "reason": "DEMO - live detection/response readiness is not measured",
        "techniques": [{"tid": item.tid, "collecting": False, "stage": "declared",
                        "gaps": ["DEMO - no live readiness proof was produced"]}
                       for item in attack_coverage.COVERAGE]}
    dialog = attack_heatmap.AttackHeatmapWindow(parent)
    dialog._timer.stop()
    dialog._on_cell_clicked("T1059")
    return dialog


def capture(runtime_root: Path, frames_root: Path, poster: Path, *, replace: bool = False) -> None:
    runtime_root, frames_root = plain(runtime_root, scratch=True), plain(frames_root, scratch=True)
    poster = plain(poster)
    if poster != ROOT / "assets" / "screenshots" / "dashboard-demo.png" or (poster.exists() and not replace):
        raise ValueError("capture requires its explicit poster path and permission to replace an existing demo")
    frames_root.mkdir(parents=True, exist_ok=False)
    import faulthandler
    traceback_stream = (frames_root / "capture-stacks.log").open("x", encoding="utf-8")
    faulthandler.dump_traceback_later(45, file=traceback_stream)
    os.environ.update(ANGERONA_PUBLIC_DEMO_ROOT=str(runtime_root), QT_QPA_PLATFORM="offscreen",
                      QT_OPENGL="software", QT_QUICK_BACKEND="software",
                      TEMP=str(frames_root), TMP=str(frames_root), ANGERONA_STORAGE_AUTOMIGRATE="0")
    if str(ROOT / "tools") not in sys.path:
        sys.path.insert(0, str(ROOT / "tools"))
    # Explicitly prohibit accidental network or executable dispatch in this
    # disposable demo process, including any deferred UI callback.
    import socket
    import subprocess
    forbidden_attempts = []

    def forbidden(*_args, **_kwargs):
        forbidden_attempts.append("network/process dispatch refused")
        raise RuntimeError("external effects are forbidden in the public demo")

    socket.create_connection = forbidden
    socket.socket.connect = forbidden
    socket.socket.connect_ex = forbidden
    subprocess.Popen = forbidden
    import capture_public_dashboard as demo
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QDialog, QHeaderView, QLabel, QLineEdit, QPlainTextEdit, QProgressBar, QStackedWidget, QTextEdit, QVBoxLayout, QWidget
    from angerona import __version__
    from angerona.core.config import Config
    from angerona.core.eventbus import Event, Severity
    from angerona.gui.pages import AlertDetailDialog

    (frames_root / "capture-identity.json").write_text(json.dumps(identity()), encoding="ascii")
    app, window, storage = demo._build_demo_window()
    wrapper = QWidget()
    wrapper.setWindowTitle("Angerona public demonstration - synthetic fixtures only")
    wrapper.setStyleSheet(window.styleSheet())
    layout = QVBoxLayout(wrapper)
    layout.setContentsMargins(14, 12, 14, 12)
    layout.setSpacing(8)
    banner = QLabel(f"DEMO  |  ANGERONA {__version__}  |  REAL APPLICATION UI  |  SYNTHETIC DATA  |  NO HOST ACTIONS")
    banner.setStyleSheet("color:#fbbf24;background:#172033;font:700 16px 'Segoe UI';padding:10px;")
    layout.addWidget(banner)
    title = QLabel()
    title.setStyleSheet("font:700 23px 'Segoe UI';color:#f8fafc;")
    subtitle = QLabel()
    subtitle.setWordWrap(True)
    subtitle.setStyleSheet("font:14px 'Segoe UI';color:#cbd5e1;")
    layout.addWidget(title)
    layout.addWidget(subtitle)
    progress = QProgressBar()
    progress.setRange(0, FRAME_COUNT)
    progress.setTextVisible(False)
    progress.setFixedHeight(5)
    layout.addWidget(progress)
    stack = QStackedWidget()
    window.setParent(stack)
    window.setWindowFlags(Qt.Widget)
    stack.addWidget(window)
    layout.addWidget(stack, 1)
    wrapper.resize(1600, 1060)
    wrapper.show()
    demo._settle(app)
    # All scores and PASS strings in the existing fixture are illustrative.
    window.posture_lbl.setText("DEMO POSTURE 96 - synthetic illustration")
    window.console.out.setPlainText(
        "PUBLIC DEMO - fixed synthetic records, no host scan or response.\n"
        "Module health and posture below are illustrations, not test results.\n"
        "Evidence must satisfy separate policy and exact-target checks before response.\n"
        "Source Observe and signed installed Windows authority remain distinct.")
    window.system_pulse.shutdown()
    # The compact EKG consumes copied synthetic publications only. Its clock
    # advances by the GIF slot duration, never by a real host heartbeat.
    fixture_clock = [2000.0]
    fixture_missing_blackbox = [False]
    heartbeat_strip = window.component_heartbeat_strip
    heartbeat_strip._clock = lambda: fixture_clock[0]
    def heartbeat_publication():
        return tuple({"role": role, "generation_id": f"DEMO-{role}-001-synthetic",
                      "pid": 41001 + index, "deadline_seconds": 3.0,
                      "last_heartbeat_monotonic": None if role == "blackbox" and fixture_missing_blackbox[0] else fixture_clock[0] - .2,
                      "state": "unavailable" if role == "blackbox" and fixture_missing_blackbox[0] else "running",
                      "reason": "DEMO - synthetic missing heartbeat; no real process inspected" if role == "blackbox" and fixture_missing_blackbox[0]
                                else "DEMO - fixed synthetic heartbeat publication; no real process inspected"}
                     for index, role in enumerate(("core", "watchdog", "scanner", "blackbox")))
    window.set_component_heartbeat_source(heartbeat_publication)
    window._update_module_ribbon_summary()
    # Scan Center starts with the user's Downloads path even before any scan.
    # Replace that default input before inspecting/capturing any scene, including
    # scenes where the real Scan Center tab is currently hidden.
    window.scan_center.path_edit.setText("DEMO - synthetic findings; no path was scanned")
    frames = []
    chapter_names = []
    interactions = {"dashboard_panels_collapsed": {"console": [], "activity": [], "pulse": []},
                    "alerts": {"row_count": 0, "positions": []},
                    "settings_tabs": [], "attack_tabs": [], "attack_horizontal_positions": [],
                    "heartbeats": [], "heartbeat_details_steps": []}
    captured_bytes = 0
    detail = None
    settings = spyware = attack = None
    heartbeat_details = None

    def chapter(number, heading, description, widget, navigate=None):
        nonlocal captured_bytes
        chapter_names.append(heading)
        title.setText(f"{number}/{CHAPTERS}  {heading}")
        subtitle.setText(description)
        stack.setCurrentWidget(widget)
        demo._settle(app, .2)
        for step in range(FRAMES_PER_CHAPTER):
            fixture_clock[0] = 2000.0 + len(frames) * FRAME_DURATION_MS / 1000
            if navigate is not None:
                navigate(step)
                # Disclosure resize and tab/scroll layout are queued by Qt.
                # Capture their settled widgets rather than an in-flight paint.
                demo._settle(app, .35)
            progress.setValue((number - 1) * FRAMES_PER_CHAPTER + step + 1)
            app.processEvents()
            texts = [label.text() for label in wrapper.findChildren(QLabel)]
            texts += [field.text() for field in wrapper.findChildren(QLineEdit)]
            texts += [view.toPlainText() for view in wrapper.findChildren(QPlainTextEdit)]
            texts += [view.toPlainText() for view in wrapper.findChildren(QTextEdit)]
            visible = "\n".join(texts).casefold()
            for private in (str(Path.home()), os.environ.get("USERNAME", ""), os.environ.get("COMPUTERNAME", "")):
                if private and private.casefold() in visible:
                    raise RuntimeError("private host identity appeared in demo labels")
            destination = frames_root / f"frame-{len(frames):03d}.png"
            demo._save_widget(wrapper, destination)
            size = destination.stat().st_size
            captured_bytes += size
            if size > MAX_FRAME_BYTES or captured_bytes > MAX_CAPTURE_BYTES:
                raise RuntimeError("public demo capture reached its explicit frame/disk byte budget")
            frames.append(destination.name)
            if len(frames) == 1:
                print(json.dumps({"outcome": "first-dashboard-frame", "path": str(destination),
                                  "app_version": __version__, "capture": identity()}), flush=True)
    try:
        panel_controls = {"console": window._console_collapse, "activity": window._activity_collapse,
                          "pulse": window._pulse_collapse}
        ribbons = window._module_ribbons_disclosure
        if any(control.is_collapsed() for control in panel_controls.values()) or ribbons.is_expanded():
            raise RuntimeError("the demo requires panels open by default with only module health folded")

        def browse_dashboard(step):
            nonlocal heartbeat_details
            fixture_missing_blackbox[0] = step >= 4
            heartbeat_strip.refresh_snapshot()
            interactions["heartbeats"].append([
                {"role": row.role, "state": row.state, "fresh": row.fresh}
                for row in heartbeat_strip.snapshot()])
            # Exercise the real Console heading button, never the internal
            # grouping adapter. Other panels retain their open startup state.
            console = panel_controls["console"]
            if console.is_collapsed() != (step in (2, 3)):
                console._minimize_button.click()
            for name, control in panel_controls.items():
                interactions["dashboard_panels_collapsed"][name].append(control.is_collapsed())
            if step == 6:
                heartbeat_strip.click()
                heartbeat_details = heartbeat_strip._details_dialog
                for label in heartbeat_details.findChildren(QLabel):
                    label.setText("DEMO - synthetic heartbeat publications. No real process or sensor is being monitored; liveness does not establish protection.")
                heartbeat_details.setParent(stack)
                heartbeat_details.setWindowFlags(Qt.Widget)
                stack.addWidget(heartbeat_details)
            if 6 <= step <= 8:
                stack.setCurrentWidget(heartbeat_details)
                interactions["heartbeat_details_steps"].append(step)
            else:
                stack.setCurrentWidget(window)

        chapter(1, "One workbench for local security evidence",
                "Panels start open except module health. Synthetic EKG beats turn red when evidence is missing; click details for generations and reasons. No protection result is claimed.",
                window, browse_dashboard)
        selected = next(event for event in window.bus.recent(12) if event.module == "C2 Beacon Detector")

        # Extra rows are fixed inert observations, not simulated host collection.
        for index in range(72):
            window.bus.publish(Event(module="File Integrity Monitor" if index % 2 else "C2 Beacon Detector",
                severity=Severity.INFO if index % 3 else Severity.LOW, ts=1_785_240_300 + index,
                message=f"DEMO replay row {index + 1:02d} - synthetic evidence retained for analyst review",
                details={"public_demo": True, "synthetic": True, "training_only": True}))
        alerts = window.alerts_panel
        alerts._events = []
        alerts._newest_ts = 0.0
        alerts._accept_async_results = True
        alerts._apply_loaded_events(2, list(window.bus.recent(120)))
        alerts._accept_async_results = False
        if alerts.table.rowCount() < 72:
            raise RuntimeError("synthetic live-alert rows did not reach their bounded replay count")
        interactions["alerts"]["row_count"] = alerts.table.rowCount()
        alerts.setParent(stack)
        alerts.setWindowFlags(Qt.Widget)
        stack.addWidget(alerts)
        def scroll_alerts(step):
            bar = alerts.table.verticalScrollBar()
            if step and bar.maximum() <= 0:
                raise RuntimeError("the real alerts table did not expose a scrolling range")
            bar.setValue(round(bar.maximum() * step / (FRAMES_PER_CHAPTER - 1)))
            interactions["alerts"]["positions"].append({"value": bar.value(), "maximum": bar.maximum()})
        chapter(2, "Scroll the live-alert evidence stream",
                "The real alerts table scrolls through fixed synthetic rows. No host scan, allow/block action or alert dismissal is performed.",
                alerts, scroll_alerts)

        detail = AlertDetailDialog(selected, window, panel=window.alerts_panel)
        detail.setParent(stack)
        detail.setWindowFlags(Qt.Widget)
        stack.addWidget(detail)
        chapter(3, "Read the original alert and its limits",
                "Inspect record evidence and authenticity. An alert, fingerprint or AI explanation alone does not authorize containment.", detail)

        from types import SimpleNamespace
        from capture_spywareguard import DEMO_NOW, _SyntheticModule
        from angerona.gui import spyware_guard_page
        spyware_guard_page.time = SimpleNamespace(time=lambda: DEMO_NOW)
        spy_module = _SyntheticModule()
        # The real page probes this optional import capability during setup.
        # A public replay has no definition-import or mutation provider.
        spy_module.queue_definition_import = None
        spy_config = SimpleNamespace(**spy_module.dashboard_snapshot()["settings"], ui_motion_enabled=False)
        spyware = spyware_guard_page.SpywareGuardPage(
            SimpleNamespace(modules={"SpywareGuard": spy_module}), spy_config, None)
        stack.addWidget(spyware)
        spyware.refresh()
        spyware._timer.stop()
        spyware._news_rotation_timer.stop()
        spyware._news_scroll_timer.stop()
        spyware.hits_table.selectRow(0)
        chapter(4, "Inspect SpywareGuard's dedicated workspace",
                "Real SpywareGuard UI with fixed synthetic findings and explicit coverage. No scan, research fetch, beacon or containment is run.", spyware)

        settings_config = Config(data_dir=runtime_root, autostart_enabled=False,
                                 aria_enabled=False, aria_voice_enabled=False, ui_motion_enabled=False)
        settings = _settings_fixture(settings_config, forbidden)
        settings.setParent(stack)
        settings.setWindowFlags(Qt.Widget)
        stack.addWidget(settings)
        def browse_settings(step):
            if step < 5:
                settings._select_tab("General")
                area = settings.tabs.currentWidget()
                area.ensureWidgetVisible(settings._startup_recovery_enabled, 0, 60)
            else:
                settings._select_tab("System")
                area = settings.tabs.currentWidget()
                area.ensureWidgetVisible(settings._storage_controls, 0, 40)
            interactions["settings_tabs"].append(settings.tabs.tabText(settings.tabs.currentIndex()))
        chapter(5, "Review recovery and drive-space settings",
                "Demo-only configuration: General owns startup recovery; System owns storage limits. No credentials are read and no setting is saved.",
                settings, browse_settings)

        attack = _attack_fixture(window, forbidden)
        attack.setParent(stack)
        attack.setWindowFlags(Qt.Widget)
        stack.addWidget(attack)
        def browse_attack(step):
            if step < 6:
                attack._tabs.setCurrentIndex(0)
                bar = attack._view.horizontalScrollBar()
                bar.setValue(round(bar.maximum() * step / 5))
            else:
                attack._tabs.setCurrentIndex(1)
            interactions["attack_tabs"].append(attack._tabs.currentIndex())
            interactions["attack_horizontal_positions"].append(attack._view.horizontalScrollBar().value())
        chapter(6, "Explore the MITRE ATT&CK map and coverage limits",
                "Synthetic technique heat is shown separately from declared coverage. Live detection and response readiness are explicitly unavailable.",
                attack, browse_attack)

        window.soar_panel.table.clearSelection()
        window.soar_panel.table.setCurrentCell(-1, -1)
        window.soar_panel._sync_action_buttons()
        window.soar_panel.setParent(stack)
        window.soar_panel.setWindowFlags(Qt.Widget)
        stack.addWidget(window.soar_panel)
        header = window.soar_panel.table.horizontalHeader()
        for column in (0, 1, 2, 4):
            header.setSectionResizeMode(column, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        chapter(7, "Review proposed actions before policy admits them",
                "These review-only SOAR records are inert training fixtures. No approval, response, Undo or host-control button is activated.", window.soar_panel)

        window.scan_center.path_edit.setText("DEMO - synthetic findings; no path was scanned")
        window.scan_center._apply_result({"status": "completed", "findings": list(demo.SYNTHETIC_SCAN_FINDINGS),
                                         "summary": {"public_demo": True, "synthetic": True}})
        window.scan_center.status.setText("DEMO - no scan executed; findings are fixed synthetic examples")
        window.scan_center.progress.setFormat("DEMO")
        window.scan_center.setParent(stack)
        window.scan_center.setWindowFlags(Qt.Widget)
        stack.addWidget(window.scan_center)
        chapter(8, "Investigate findings with clear provenance",
                "Scan Center displays sample findings only. Real collection depends on platform, permissions and available providers.", window.scan_center)

        # Build the production Help dialog through its actual owner. Only its
        # modal event-loop entry is intercepted so the capture owns presentation.
        dialogs = []
        original_exec = QDialog.exec
        QDialog.exec = lambda dialog: dialogs.append(dialog) or 0
        try:
            window._open_help()
        finally:
            QDialog.exec = original_exec
        if len(dialogs) != 1:
            raise RuntimeError("the actual Help dialog was not constructed")
        help_dialog = dialogs[0]
        help_dialog.setParent(stack)
        help_dialog.setWindowFlags(Qt.Widget)
        stack.addWidget(help_dialog)
        chapter(9, "Find the implementation and honest operating limits",
                f"Angerona {__version__}: Help & Info documents source Observe mode, Ring 3 boundaries, evidence versus authority, storage choices and optional services.", help_dialog)
        demo._privacy_guard()
        if (not all(row["fresh"] for row in interactions["heartbeats"][0])
                or not any(row["role"] == "blackbox" and not row["fresh"]
                           for row in interactions["heartbeats"][-1])
                or interactions["heartbeat_details_steps"] != [6, 7, 8]):
            raise RuntimeError("synthetic EKG beat, flatline or actual details interaction was not captured")
        if forbidden_attempts:
            raise RuntimeError("a demo callback attempted an external effect; inspect the private failure")
        positions = interactions["alerts"]["positions"]
        if (positions[0]["value"] != 0 or positions[-1]["maximum"] <= 0
                or positions[-1]["value"] != positions[-1]["maximum"]
                or len({position["value"] for position in positions}) < 3):
            raise RuntimeError("the real alerts table did not complete its recorded scrolling demonstration")
        report = {"schema": 1, "frames": frames, "chapters": chapter_names,
                  "duration_ms": FRAME_DURATION_MS, "width": wrapper.width(),
                  "height": wrapper.height(), "synthetic": True, "host_actions": False,
                  "external_effect_attempts": 0, "app_version": __version__,
                  "interactions": interactions, "capture": identity()}
        (frames_root / "frames.json").write_text(json.dumps(report), encoding="ascii")
        staged_poster = frames_root / "poster.png"
        with (frames_root / frames[0]).open("rb") as source, staged_poster.open("xb") as target:
            target.write(source.read())
        publish_media(staged_poster, poster, replace=replace)
        print(json.dumps({"outcome": "captured", "frames": len(frames),
                          "seconds": FRAME_COUNT * FRAME_DURATION_MS / 1000,
                          "poster": str(poster), "capture": identity()}))
    finally:
        if detail is not None:
            detail.hide()
        for widget in (settings, spyware, attack, heartbeat_details):
            if widget is not None:
                widget.close()
        wrapper.hide()
        demo._close_demo(app, window, storage)
        app.processEvents()
        faulthandler.cancel_dump_traceback_later()
        traceback_stream.close()


def encode(frames_root: Path, output: Path, *, replace: bool = False) -> None:
    from PIL import Image, ImageChops
    frames_root, output = plain(frames_root, scratch=True), plain(output)
    if output != ROOT / "assets" / "demo" / "angerona-demo.gif" or (output.exists() and not replace):
        raise ValueError("encode requires its explicit GIF path and permission to replace an existing demo")
    manifest_path = plain(frames_root / "frames.json", scratch=True)
    if manifest_path.stat().st_size > 65536:
        raise ValueError("frame manifest exceeds its bound")
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    names = manifest.get("frames")
    if manifest.get("schema") != 1 or names != [f"frame-{index:03d}.png" for index in range(FRAME_COUNT)]:
        raise ValueError("frame manifest is invalid")
    if (manifest.get("duration_ms") != FRAME_DURATION_MS or not manifest.get("synthetic")
            or manifest.get("host_actions") is not False or len(manifest.get("chapters", [])) != CHAPTERS):
        raise ValueError("frame policy is invalid")
    images = []
    total_bytes = 0
    for name in names:
        if not isinstance(name, str) or not re.fullmatch(r"frame-\d{3}\.png", name):
            raise ValueError("invalid frame name")
        path = plain(frames_root / name, scratch=True)
        size = path.stat().st_size
        total_bytes += size
        if size > MAX_FRAME_BYTES or total_bytes > MAX_CAPTURE_BYTES:
            raise ValueError("frame exceeds its byte bound")
        with Image.open(path) as image:
            if (image.format != "PNG" or image.width > 1920 or image.height > 1200
                    or image.size != (manifest.get("width"), manifest.get("height"))):
                raise ValueError("frame geometry or type is invalid")
            images.append(image.convert("RGB"))
    palette_sample = Image.new("RGB", (800, 530 * CHAPTERS))
    for index in range(CHAPTERS):
        sample = images[index * FRAMES_PER_CHAPTER].copy()
        sample.thumbnail((800, 530))
        palette_sample.paste(sample, (0, index * 530))
    palette = palette_sample.quantize(colors=252)
    # Preserve the UI's liveness/absence colors; tiny EKG lanes must not lose
    # their meaning when a global chapter palette favors the blue dashboard.
    colors = palette.getpalette()[:252 * 3]
    colors.extend((40, 223, 148, 255, 83, 99, 47, 227, 138, 251, 191, 36))
    palette.putpalette(colors)
    quantized = [image.quantize(palette=palette, dither=Image.Dither.NONE) for image in images]
    staged = frames_root / "encoded-demo.gif"
    with staged.open("xb") as target:
        quantized[0].save(target, format="GIF", save_all=True, append_images=quantized[1:],
                          duration=FRAME_DURATION_MS, loop=0, optimize=False, disposal=2)
    if staged.stat().st_size > MAX_GIF:
        staged.unlink()  # Only this invocation's new, exact output is eligible.
        raise ValueError("new GIF exceeded its explicit 12 MiB budget")
    with Image.open(staged) as image:
        count = image.n_frames
        duration = 0
        slot = 0
        for index in range(count):
            image.seek(index)
            frame_duration = image.info.get("duration", 0)
            if frame_duration <= 0 or frame_duration % FRAME_DURATION_MS:
                raise ValueError("encoded GIF contains an unexpected frame duration")
            decoded = image.convert("RGB")
            for _ in range(frame_duration // FRAME_DURATION_MS):
                if slot >= len(quantized) or ImageChops.difference(
                        decoded, quantized[slot].convert("RGB")).getbbox() is not None:
                    raise ValueError(f"encoded GIF changed the reviewed pixels in frame slot {slot}")
                slot += 1
            duration += frame_duration
    if duration != FRAME_COUNT * FRAME_DURATION_MS or slot != FRAME_COUNT:
        raise ValueError("encoded GIF duration differs from the reviewed chapter plan")
    publish_media(staged, output, replace=replace)
    print(json.dumps({"outcome": "encoded", "bytes": output.stat().st_size, "frames": count,
                      "duration_ms": duration, "encoder": identity()}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--encode", action="store_true")
    parser.add_argument("--frames-root", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--replace-existing-demo", action="store_true",
                        help="Replace only the two explicit demo asset leaves after a successful capture/encode.")
    parser.add_argument("--poster", type=Path, default=ROOT / "assets" / "screenshots" / "dashboard-demo.png")
    parser.add_argument("--gif", type=Path, default=ROOT / "assets" / "demo" / "angerona-demo.gif")
    args = parser.parse_args()
    if args.encode:
        encode(args.frames_root, args.gif, replace=args.replace_existing_demo)
    elif args.runtime_root is not None:
        capture(args.runtime_root, args.frames_root, args.poster, replace=args.replace_existing_demo)
    else:
        parser.error("capture requires --runtime-root")


if __name__ == "__main__":
    main()
