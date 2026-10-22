"""Capture the real SpywareGuard widget using fixed synthetic evidence only.

No modules are discovered or started. No host inventory, feed fetch, storage,
beacon, or response action is permitted by this fixture. The visible banner and
headline explicitly identify the image as a demonstration.
"""
from __future__ import annotations

import argparse
import copy
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QT_SCALE_FACTOR", "1")
os.environ.setdefault("QT_FONT_DPI", "96")
os.environ["ANGERONA_REDUCE_MOTION"] = "1"
os.environ["ANGERONA_PUBLIC_DEMO"] = "1"

from PySide6.QtCore import QCoreApplication, QEvent, Qt  # noqa: E402
from PySide6.QtGui import QFontDatabase  # noqa: E402
from PySide6.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget  # noqa: E402

from angerona.gui import spyware_guard_page as page_module  # noqa: E402
from angerona.gui.theme import build_qss  # noqa: E402


DEMO_NOW = datetime(2026, 10, 21, 12, tzinfo=timezone.utc).timestamp()


class _SyntheticModule:
    status = "SYNTHETIC PREVIEW · no live module or host actions"

    def dashboard_snapshot(self):
        settings = {
            "spyware_auto_contain": True, "spyware_network_enabled": True,
            "spyware_memory_enabled": False, "spyware_beacon_enabled": False,
            "spyware_beacon_channel": True, "spyware_beacon_signal": False,
        }
        rules = (
            ("renderer_shell_after_media", "demo-webview.exe", "HIGH", "Synthetic child-process transition after media rendering"),
            ("encrypted_egress_spike", "demo-uploader.exe", "HIGH", "Synthetic encrypted upload exceeded its process baseline"),
            ("dns_tunnel_pattern", "demo-network.exe", "MEDIUM", "Synthetic high-entropy DNS query pattern"),
            ("reviewed_sha256_indicator_match", "demo-artifact.exe", "HIGH", "Inert example digest matched a reviewed training indicator"),
            ("persistence_script_hook", "demo-startup.vbs", "MEDIUM", "Synthetic startup script requires investigation"),
        )
        hits = [{
            "id": f"synthetic-preview-{index}", "timestamp": f"DEMO 12:{15 - index:02}:00",
            "rule": rule, "process_name": process, "severity": severity,
            "summary": summary, "simulation": True, "actor_attribution": "none",
            "response_requested": False, "containment_performed": False,
            "evidence": {"source": "fixed-public-demo", "training_only": True},
        } for index, (rule, process, severity, summary) in enumerate(rules)]
        return copy.deepcopy({
            "status": self.status, "settings": settings, "hits": hits,
            "containments": [{"timestamp": "DEMO 12:15:01", "target": "demo-webview.exe",
                              "status": "simulation only", "details": "No host containment performed"}],
            "stats": {"findings": len(hits)},
            "indicators": [{"kind": "domain", "value": "training.example", "approved": True,
                            "source": "Synthetic fixture — never active"}],
            "sources": [],
            "coverage": {"mode": "synthetic demonstration", "host_scans": "not run",
                         "network_access": "not used", "memory_contents": "never acquired"},
            "beacon": {"enabled": False, "status": "demo — no destination or delivery"},
            "news": [{
                "title": "DEMO bulletin · spyware and exploit research headlines rotate here — synthetic preview",
                "url": "https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/",
                "source": "citizen_lab", "published": DEMO_NOW - 86400,
                "verified_at": DEMO_NOW - 60,
            }],
            "news_status": {"state": "current", "refreshing": False,
                            "synthetic": True, "last_refresh": DEMO_NOW - 60},
        })

    def __getattr__(self, name):
        raise RuntimeError("Synthetic screenshot fixture cannot queue actions: " + name)


def _register_fonts(app):
    if os.name == "nt" and app.platformName() == "offscreen":
        fonts = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"
        for name in ("segoeui.ttf", "segoeuib.ttf", "arial.ttf", "arialbd.ttf"):
            path = fonts / name
            if path.is_file():
                QFontDatabase.addApplicationFont(str(path))


def capture(destination: Path) -> Path:
    app = QApplication.instance() or QApplication([])
    app.setApplicationName("Angerona SpywareGuard — Synthetic Public Preview")
    _register_fonts(app)
    window = QWidget()
    window.setWindowTitle("Angerona SpywareGuard — Synthetic Public Preview")
    window.setStyleSheet(build_qss("slate"))
    layout = QVBoxLayout(window)
    layout.setContentsMargins(14, 12, 14, 12)
    banner = QLabel("SYNTHETIC DEMONSTRATION  ·  Fixed example dates and evidence  ·  No host scanned or network used")
    banner.setTextFormat(Qt.TextFormat.PlainText)
    banner.setWordWrap(True)
    banner.setStyleSheet("color:#fbbf24; border:1px solid #854d0e; padding:9px; border-radius:6px;")
    layout.addWidget(banner)
    module = _SyntheticModule()
    config = SimpleNamespace(**module.dashboard_snapshot()["settings"], ui_motion_enabled=False)
    original_clock = page_module.time
    page_module.time = SimpleNamespace(time=lambda: DEMO_NOW)
    page = None
    try:
        page = page_module.SpywareGuardPage(SimpleNamespace(modules={"SpywareGuard": module}), config, None)
        layout.addWidget(page, 1)
        window.resize(1260, 760)
        window.show()
        for _ in range(5):
            app.processEvents()
        page._timer.stop()
        page.hits_table.selectRow(0)
        app.processEvents()
        destination.parent.mkdir(parents=True, exist_ok=True)
        image = window.grab()
        if image.isNull() or not image.save(str(destination), "PNG"):
            raise RuntimeError("Could not save SpywareGuard preview: " + str(destination))
        return destination
    finally:
        if page is not None:
            page.close()
        window.close()
        window.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        page_module.time = original_clock


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        default=ROOT / "docs" / "screenshots" / "angerona-spywareguard-preview.png")
    args = parser.parse_args()
    destination = args.output if args.output.is_absolute() else ROOT / args.output
    print("PASS: wrote synthetic SpywareGuard preview " + str(capture(destination.resolve())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
