"""Render privacy-safe public dashboard images from synthetic data only.

The default remains a single dashboard PNG for backwards compatibility.  Pass
``--gallery`` to capture the same real Qt dashboard plus its SOAR, Scan Center,
and ARIA surfaces.  Every displayed record is a fixed public-demo fixture; the
tool never starts defensive modules or reads host telemetry.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

DEMO_ROOT = ROOT / "diagnostics" / "public-demo-runtime"
os.environ["ANGERONA_DATA"] = str(DEMO_ROOT)
os.environ.setdefault("QT_QPA_PLATFORM", "windows")
os.environ.setdefault("QT_SCALE_FACTOR", "1")
os.environ.setdefault("QT_FONT_DPI", "96")
os.environ["ANGERONA_REDUCE_MOTION"] = "1"
os.environ["ANGERONA_PUBLIC_DEMO"] = "1"

from PySide6.QtCore import QModelIndex, QPoint, QItemSelectionModel, Qt  # noqa: E402
from PySide6.QtGui import QCursor  # noqa: E402
from PySide6.QtWidgets import QApplication, QAbstractItemView  # noqa: E402

from angerona.core.config import Config  # noqa: E402
from angerona.core.eventbus import Event, EventBus, Severity  # noqa: E402
from angerona.core.module_manager import ModuleManager  # noqa: E402
from angerona.core.storage import FlightRecorder  # noqa: E402
from angerona.gui.main_window import MainWindow  # noqa: E402


SYNTHETIC_EVENTS = (
    ("Telemetry Canary Drills", Severity.LOW,
     "Synthetic integrity canary acknowledged by the telemetry pipeline"),
    ("File Integrity Monitor", Severity.INFO,
     "Demo policy baseline verified; no unapproved file drift"),
    ("C2 Beacon Detector", Severity.MEDIUM,
     "Synthetic cadence marker isolated for analyst training"),
    ("Active Response SOAR", Severity.INFO,
     "Demo containment preview validated; no host action performed"),
    ("Network Protocol Deep Decoder", Severity.LOW,
     "Synthetic encrypted-flow metadata classified locally"),
    ("Data Provenance Graph", Severity.INFO,
     "Demo evidence chain linked to a signed training incident"),
    ("Purple Remediation Guard", Severity.INFO,
     "Synthetic detector proof accepted for a later drill run"),
    ("AI Model Integrity Guard", Severity.INFO,
     "Demo model digest matched the local trusted baseline"),
    ("Compliance Mapper", Severity.INFO,
     "Synthetic ATT&CK coverage mapped to defensive controls"),
    ("Watchdog Monitor", Severity.INFO,
     "Demo resilience heartbeat healthy across supervised services"),
    ("YARA Scanner", Severity.LOW,
     "Synthetic training sample matched an inert demonstration rule"),
    ("Zero-Trust Local IPC Guard", Severity.INFO,
     "Synthetic loopback authentication challenge verified"),
)

SYNTHETIC_SCAN_FINDINGS = (
    {
        "severity": "Medium",
        "title": "Externally reachable service requires review",
        "evidence": "Synthetic listener token; no address or process identity",
        "remediation": "Restrict ingress and require a process-bound egress lease",
        "patch_guidance": "Validate the service owner and current vendor guidance",
    },
    {
        "severity": "Low",
        "title": "Wireless link kept outside the trusted boundary",
        "evidence": "Synthetic untrusted-link posture; local identifiers withheld",
        "remediation": "Keep the endpoint-to-Sentinel authenticated path enforced",
        "patch_guidance": "Review gateway firmware and disable unused management paths",
    },
    {
        "severity": "Info",
        "title": "Personal Sentinel witness verified",
        "evidence": "Synthetic gateway receipt and trusted-time sample accepted",
        "remediation": "Continue independent monitoring and bounded re-attestation",
        "patch_guidance": "No patch action indicated by this synthetic observation",
    },
)

SYNTHETIC_SOAR_RECORDS = (
    {
        "request_id": "11111111111111111111111111111111",
        "ts": 1_785_240_120.0,
        "origin_module": "Temporal Tradecraft Correlator",
        "origin_ts": 1_785_240_119.0,
        "origin_hmac": "",
        "origin_severity": 3,
        "origin_message_sha256": "0" * 64,
        "severity": "High",
        "message": "Synthetic SSH-key-to-tunnel sequence queued for analyst review",
        "details": {"public_demo": True, "synthetic": True},
        "action": {"kind": "review_only", "reason": "synthetic training fixture"},
        "status": "PENDING REVIEW",
    },
    {
        "request_id": "22222222222222222222222222222222",
        "ts": 1_785_240_121.0,
        "origin_module": "Audit Log Integrity Guard",
        "origin_ts": 1_785_240_120.0,
        "origin_hmac": "",
        "origin_severity": 4,
        "origin_message_sha256": "0" * 64,
        "severity": "Critical",
        "message": "Synthetic audit-clear correlation preserved for containment review",
        "details": {"public_demo": True, "synthetic": True},
        "action": {"kind": "review_only", "reason": "synthetic training fixture"},
        "status": "PENDING REVIEW",
    },
    {
        "request_id": "33333333333333333333333333333333",
        "ts": 1_785_240_122.0,
        "origin_module": "Process Egress Lease Guard",
        "origin_ts": 1_785_240_121.0,
        "origin_hmac": "",
        "origin_severity": 2,
        "origin_message_sha256": "0" * 64,
        "severity": "Medium",
        "message": "Synthetic unleased egress attempt retained without host action",
        "details": {"public_demo": True, "synthetic": True},
        "action": {"kind": "review_only", "reason": "synthetic training fixture"},
        "status": "DISMISSED — no host action taken",
    },
)


def _stop_background_ui_helpers(window: MainWindow) -> None:
    for name in (
        "timer",
        "_timer",
        "_beat_timer",
        "_tray_timer",
        "_aria_timer",
        "_mic_timer",
        "_chill_maintenance_timer",
        "_adaptation_timer",
        "_sim_poll",
        "_shark_poll",
        "_rt_poll",
    ):
        timer = getattr(window, name, None)
        if timer is not None and hasattr(timer, "stop"):
            timer.stop()
    pulse = getattr(window, "system_pulse", None)
    if pulse is not None:
        pulse._timer.stop()
    hud = getattr(window, "aria_hud", None)
    orb = getattr(hud, "_orb", None)
    if orb is not None:
        # The orb owns a nested timer and its showEvent can restart it after the
        # first settle pass.  Freeze both timer and phase so gallery pixels do
        # not depend on capture scheduling.
        orb._timer.stop()
        orb._phase = 0.0
        orb.update()
    meter = getattr(hud, "mic_meter", None)
    meter_timer = getattr(meter, "_timer", None)
    if meter_timer is not None:
        meter_timer.stop()
    watchdog = getattr(window, "_ui_watchdog", None)
    if watchdog is not None:
        watchdog.stop()


def _settle(app: QApplication, seconds: float = 0.35) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.02)


def _save_widget(widget, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    image = widget.grab()
    if image.isNull() or not image.save(str(destination), "PNG"):
        raise RuntimeError(f"could not write public-demo image: {destination}")


def _build_demo_window():
    DEMO_ROOT.mkdir(parents=True, exist_ok=True)
    db_path = DEMO_ROOT / "synthetic-public-demo.db"
    if db_path.exists():
        db_path.unlink()
    for name in ("soar_queue.json", "soar_queue_state.json"):
        queue_path = DEMO_ROOT / "shared_logs" / name
        if queue_path.exists():
            queue_path.unlink()

    app = QApplication.instance() or QApplication([])
    app.setApplicationName("Angerona Public Demo")

    config = Config(
        data_dir=DEMO_ROOT,
        autostart_enabled=False,
        eco_mode=False,
        blackbox_enabled=False,
        aria_enabled=True,
        aria_voice_enabled=False,
        aria_cloud_fallback=False,
        alert_analysis_cloud_fallback=False,
        aria_push_enabled=False,
        aria_inbox_enabled=False,
        aria_research_egress=False,
        teams_bot_enabled=False,
        ui_motion_enabled=False,
    )
    bus = EventBus()
    storage = FlightRecorder(db_path)
    bus.subscribe(storage.record)
    manager = ModuleManager(bus, config)
    manager.discover()

    for index, module in enumerate(manager.modules.values()):
        module.status = "running"
        module.health = 100 if index % 7 else 94
        module.health_note = "Synthetic public-demo state"

    base = 1_785_240_000.0
    for index, (module, severity, message) in enumerate(SYNTHETIC_EVENTS):
        bus.publish(
            Event(
                module=module,
                message=message,
                severity=severity,
                ts=base + index,
                details={
                    "public_demo": True,
                    "synthetic": True,
                    "training_only": True,
                },
            )
        )

    window = MainWindow(bus, storage, manager, config)
    _stop_background_ui_helpers(window)
    # Suppress SystemPulseCard's constructor-scheduled first host sample. The
    # public image must be synthetic end to end, not merely overwritten later.
    window.system_pulse._busy.set()
    window.setWindowTitle("Angerona — Public Synthetic Demonstration")
    window.resize(1920, 1040)
    window.show()
    app.processEvents()
    _settle(app, 0.65)
    _stop_background_ui_helpers(window)
    window.system_pulse._busy.clear()
    window.system_pulse._timer.stop()

    window._last_posture = {
        "score": 96,
        "label": "Secure",
        "color": "#2fe38a",
        "factors": {
            "active_threats": 0,
            "critical_alerts": 0,
            "degraded_modules": 0,
        },
    }
    window.posture_lbl.setText("POSTURE 96 · Secure")
    window.posture_lbl.setStyleSheet(
        "color:#2fe38a; font-weight:800; font-size:11px; letter-spacing:1px;"
    )
    window.system_pulse._apply_sample(
        {
            "cpu": 18.0,
            "ram": 42.0,
            "available": 12 * 1024 ** 3,
            "wifi": 88,
            "down": 2.4 * 1024 ** 2,
            "up": 640 * 1024,
        }
    )
    window.console.out.setPlainText(
        "[PUBLIC DEMO] Synthetic telemetry only — no host data is displayed.\n"
        f"[PASS] {len(manager.modules)} defensive modules discovered\n"
        "[PASS] Event authenticity and bounded retention verified\n"
        "[PASS] Purple remediation proof chain ready\n"
        "[PASS] Local-first privacy controls enabled\n\n"
        "ARIA: Posture 96 · SECURE · no active synthetic threats"
    )
    window.cards.refresh()
    window.modules_panel.refresh()
    # Populate the real alert table synchronously from the fixed EventBus
    # fixture.  Waiting for the recorder's asynchronous reader made a gallery
    # capture depend on storage-thread scheduling and could yield an empty
    # panel after the deadline on a busy host.
    alerts = window.alerts_panel
    alerts._events_load_busy = False
    alerts._newest_ts = 0.0
    alerts._events = []
    alerts._apply_loaded_events(1, list(bus.recent(120)))
    alerts._accept_async_results = False
    window.status_strip.refresh()
    window.resource_strip.refresh()
    if getattr(window, "aria_hud", None) is not None:
        window.aria_hud.refresh()
        window.aria_hud._spark.setText("▁▂▃▅▇▆▅▃  bounded synthetic activity")
    if alerts.table.rowCount() != len(SYNTHETIC_EVENTS):
        raise RuntimeError("synthetic alert table did not reach its exact row count")
    app.processEvents()

    # Seed the *real* SOAR panel through its append-only review store, using
    # fixed review-only records that can never authorize a host response.
    from angerona.gui.pages import (  # noqa: PLC0415
        _append_soar_queue_record,
        _invalidate_soar_queue_cache,
    )

    _invalidate_soar_queue_cache()
    for record in SYNTHETIC_SOAR_RECORDS:
        if not _append_soar_queue_record(dict(record)):
            raise RuntimeError("could not seed the synthetic SOAR gallery")
    window.soar_panel.refresh()
    window.live_defense_activity.refresh()
    app.processEvents()

    return app, window, storage


def _privacy_guard() -> None:
    # PNG contains no camera/GPS metadata, and the only injected records are the
    # fixed synthetic strings above. This guard prevents accidental path reuse.
    forbidden = (
        str(Path.home()).casefold(),
        os.environ.get("USERNAME", "").casefold(),
        os.environ.get("COMPUTERNAME", "").casefold(),
        "c:\\users\\",
    )
    visible_text = "\n".join(
        [message for _, _, message in SYNTHETIC_EVENTS]
        + [str(value) for value in SYNTHETIC_SCAN_FINDINGS]
        + [str(value) for value in SYNTHETIC_SOAR_RECORDS]
    ).casefold()
    if any(value and value in visible_text for value in forbidden):
        raise RuntimeError("public-demo text failed the privacy guard")


def _close_demo(app: QApplication, window: MainWindow, storage: FlightRecorder) -> None:
    window.hide()
    _stop_background_ui_helpers(window)
    storage.close()
    app.processEvents()


def capture(destination: Path) -> None:
    """Capture the backwards-compatible single dashboard image."""

    app, window, storage = _build_demo_window()
    try:
        _save_widget(window, destination)
        _privacy_guard()
    finally:
        _close_demo(app, window, storage)


def capture_gallery(destination: Path) -> tuple[Path, ...]:
    """Capture four real GUI surfaces backed exclusively by demo fixtures."""

    from angerona.gui.dashboard_details import AriaDetailDialog  # noqa: PLC0415

    app, window, storage = _build_demo_window()
    outputs = (
        destination / "angerona-v1.11-dashboard.png",
        destination / "angerona-v1.11-soar-review.png",
        destination / "angerona-v1.11-scan-center.png",
        destination / "angerona-v1.11-aria-local-first.png",
    )
    dialog = None
    original_cursor_position = QCursor.pos()
    try:
        # Keep pointer hover state out of gallery pixels and restore the user's
        # cursor exactly when the bounded capture is complete.
        QCursor.setPos(window.mapToGlobal(QPoint(5, 5)))
        window._right_tabs.setCurrentWidget(window.alerts_panel)
        window.live_defense_activity.refresh()
        _settle(app)
        _save_widget(window, outputs[0])

        window._right_tabs.setCurrentWidget(window.soar_panel)
        window.soar_panel.refresh()
        # A public gallery should not imply that an operator has selected or
        # approved a live containment request.  Disable selection for this
        # static synthetic capture and clear both the selection and current
        # index before the widget is painted.
        window.soar_panel.table.setSelectionMode(QAbstractItemView.NoSelection)
        window.soar_panel.table.clearSelection()
        window.soar_panel.table.setCurrentItem(None)
        window.soar_panel.table.setCurrentCell(-1, -1)
        selection_model = window.soar_panel.table.selectionModel()
        selection_model.clear()
        selection_model.setCurrentIndex(QModelIndex(), QItemSelectionModel.Clear)
        window.soar_panel.table.setCurrentIndex(QModelIndex())
        window.soar_panel.table.setStyleSheet(
            "QTableWidget::item:hover { background: transparent; }"
            "QTableWidget::item:selected { background: transparent; }"
        )
        window.soar_panel.table.setFocusPolicy(Qt.NoFocus)
        window.soar_panel.table.clearFocus()
        window.soar_panel._sync_action_buttons()
        _settle(app)
        _save_widget(window, outputs[1])

        window.scan_center.path_edit.setText(
            "Synthetic local scope — no host path or identity"
        )
        window.scan_center._apply_result(
            {
                "status": "completed",
                "findings": list(SYNTHETIC_SCAN_FINDINGS),
                "summary": {
                    "public_demo": True,
                    "synthetic": True,
                    "scope": "Local defensive checks only; no remote scan",
                },
            }
        )
        window.scan_center.status.setText(
            "PUBLIC DEMO · synthetic findings only · no scan was executed"
        )
        window.scan_center.progress.setFormat("PUBLIC DEMO")
        window._right_tabs.setCurrentWidget(window.scan_center)
        _settle(app)
        # The dashboard splitter is operator-adjustable.  Give the feature view
        # enough room to show its actual findings table while retaining a small
        # slice of the live activity/ARIA boundary beneath it.
        window._body_splitter.setSizes([650, 160])
        _settle(app)
        _save_widget(window, outputs[2])

        hud = getattr(window, "aria_hud", None)
        if hud is None:
            raise RuntimeError("ARIA dashboard surface is unavailable")
        hud._status.setText(
            "PUBLIC DEMO · local-first posture assistance online · no host data"
        )
        hud._spark.setText("▁▂▃▅▇▆▅▃  bounded synthetic activity")
        dialog = AriaDetailDialog(window, window)
        dialog._timer.stop()
        dialog.resize(1100, 760)
        dialog.show()
        dialog.raise_()
        _settle(app)
        _save_widget(dialog, outputs[3])

        _privacy_guard()
    finally:
        QCursor.setPos(original_cursor_position)
        if dialog is not None:
            dialog.hide()
            dialog.deleteLater()
        _close_demo(app, window, storage)
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "destination",
        nargs="?",
        type=Path,
        default=ROOT / "diagnostics" / "dashboard-public-demo-cycle5.png",
        help="single dashboard PNG path (default mode)",
    )
    parser.add_argument(
        "--gallery",
        type=Path,
        help="directory for dashboard, SOAR, Scan Center, and ARIA PNGs",
    )
    args = parser.parse_args()
    if args.gallery is not None:
        for output in capture_gallery(args.gallery.resolve()):
            print(output)
    else:
        destination = args.destination.resolve()
        capture(destination)
        print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
