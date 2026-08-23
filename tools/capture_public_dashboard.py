"""Render a privacy-safe README dashboard image from synthetic data only."""
from __future__ import annotations

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

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

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


def _stop_background_ui_helpers(window: MainWindow) -> None:
    for name in (
        "_timer",
        "_beat_timer",
        "_tray_timer",
        "_aria_timer",
        "_mic_timer",
    ):
        timer = getattr(window, name, None)
        if timer is not None and hasattr(timer, "stop"):
            timer.stop()
    pulse = getattr(window, "system_pulse", None)
    if pulse is not None:
        pulse._timer.stop()
    watchdog = getattr(window, "_ui_watchdog", None)
    if watchdog is not None:
        watchdog.stop()


def capture(destination: Path) -> None:
    DEMO_ROOT.mkdir(parents=True, exist_ok=True)
    db_path = DEMO_ROOT / "synthetic-public-demo.db"
    if db_path.exists():
        db_path.unlink()

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
    settle_deadline = time.monotonic() + 0.65
    while time.monotonic() < settle_deadline:
        app.processEvents()
        time.sleep(0.02)
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
    window.alerts_panel.refresh()
    window.status_strip.refresh()
    window.resource_strip.refresh()
    if getattr(window, "aria_hud", None) is not None:
        window.aria_hud.refresh()
    alerts_deadline = time.monotonic() + 2.0
    while (
        window.alerts_panel.table.rowCount() < len(SYNTHETIC_EVENTS)
        and time.monotonic() < alerts_deadline
    ):
        app.processEvents()
        time.sleep(0.02)
    app.processEvents()

    image = window.grab()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not image.save(str(destination), "PNG"):
        raise RuntimeError(f"could not write dashboard image: {destination}")

    # PNG contains no camera/GPS metadata, and the only injected records are the
    # fixed synthetic strings above. This guard prevents accidental path reuse.
    forbidden = (
        str(Path.home()).casefold(),
        os.environ.get("USERNAME", "").casefold(),
        os.environ.get("COMPUTERNAME", "").casefold(),
        "c:\\users\\",
    )
    visible_text = "\n".join(
        message for _, _, message in SYNTHETIC_EVENTS
    ).casefold()
    if any(value and value in visible_text for value in forbidden):
        raise RuntimeError("public-demo text failed the privacy guard")

    window.hide()
    _stop_background_ui_helpers(window)
    storage.close()
    app.processEvents()


def main() -> int:
    destination = (
        Path(sys.argv[1]).resolve()
        if len(sys.argv) > 1
        else ROOT / "diagnostics" / "dashboard-public-demo-cycle5.png"
    )
    capture(destination)
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
