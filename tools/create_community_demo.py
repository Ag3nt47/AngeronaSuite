"""Render actual new Qt views with inert data, then encode reviewed demo frames.

Capture uses Angerona's Qt runtime. Encoding uses the managed Pillow runtime.
Every frame says DEMO. No application Core, scan, download or response starts.
Outputs stay in private staging until a maintainer reviews and promotes them.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / ".tmp" / "community-demo-20261109"
SOURCES = (
    "tools/create_community_demo.py", "src/angerona/gui/community_tools.py",
    "src/angerona/gui/rules_playbooks.py", "src/angerona/gui/suite_map.py",
    "src/angerona/gui/theme.py", "src/angerona/gui/dashboard_sections.py",
    "src/angerona/core/community_tool_adapters.py", "src/angerona/core/suite_topology.py",
    "src/angerona/core/rule_playbook_library.py",
)
NAMES = ("suggested-tools-demo", "community-source-sandbox-demo", "rules-playbooks-demo", "suite-map-3d-demo")


def fingerprints():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}


def forbidden(*_args, **_kwargs):
    raise AssertionError("Public demo cannot invoke a host, filesystem, network or response action")


def capture():
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    os.environ["ANGERONA_REDUCE_MOTION"] = "1"
    from types import SimpleNamespace
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont, QFontDatabase
    from PySide6.QtWidgets import QApplication, QDialog, QLabel, QVBoxLayout
    from angerona.core.community_tool_adapters import tool_specs as adapter_specs
    from angerona.core.eventbus import Event, EventBus
    from angerona.core.suite_topology import SuiteTopologyService
    from angerona.gui.community_tools import CommunityToolsPanel
    from angerona.gui.rules_playbooks import RulesPlaybooksPanel
    from angerona.gui.suite_map import SuiteMapDialog
    from angerona.gui.theme import build_qss

    initial = fingerprints()
    STAGE.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication([])
    font = Path("C:/Windows/Fonts/segoeui.ttf")
    if font.is_file():
        identifier = QFontDatabase.addApplicationFont(str(font))
        families = QFontDatabase.applicationFontFamilies(identifier)
        if families:
            app.setFont(QFont(families[0], 10))
    app.setStyleSheet(build_qss("cyber"))

    class Tools:
        root = STAGE / "inert-no-storage"
        catalog = SimpleNamespace(list_imports=lambda: [])
        tool_specs = staticmethod(adapter_specs)
        def status(self, tool):
            return {"tool_id": tool, "state": "DEMO · source review preview", "sandboxes": [],
                    "message": "Synthetic preview. Use Self-check in the application for an actual local result.",
                    "coverage": "Supported adapters have different scopes; upstream platforms are not all embedded.",
                    "safety": "Pinned source, reviewed data and separate editable copies. No downloaded commands execute here."}
        install = uninstall = self_check = create_sandbox = sandbox_files = sandbox_read = forbidden
        sandbox_write = sandbox_diff = sandbox_revert = sandbox_analysis = credits = forbidden

    class Library:
        def sources(self):
            return [{"name": "SigmaHQ Sigma", "url": "https://github.com/SigmaHQ/sigma"},
                    {"name": "YARA rules", "url": "https://github.com/Yara-Rules/rules"}]
        def items(self):
            return [{"id": "demo-not-a-runtime-rule", "name": "Example high-severity notification", "kind": "soar", "state": "draft"}]
        discover = install_batch = read = save_draft = create_draft = validate = sample_test = forbidden
        diff = activate = disable = rollback = credits = forbidden

    def settle(predicate=lambda: True):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            app.processEvents()
            if predicate():
                app.processEvents()
                return
            time.sleep(.01)
        raise RuntimeError("Inert demo worker did not finish")

    def shell(panel, title):
        window = QDialog()
        window.resize(1440, 920)
        layout = QVBoxLayout(window)
        banner = QLabel("DEMO   " + title + "   ·   Synthetic data   ·   No host actions")
        banner.setWordWrap(True)
        banner.setStyleSheet("color:#fbbf24;background:#302716;padding:12px;font-weight:700;font-size:16px;")
        layout.addWidget(banner)
        layout.addWidget(panel, 1)
        window.show()
        settle()
        return window

    def save(widget, name):
        destination = STAGE / (name + ".png")
        if not widget.grab().save(str(destination)):
            raise RuntimeError("Demo PNG capture failed")
        if not 0 < destination.stat().st_size <= 8 * 1024**2:
            raise RuntimeError("Demo PNG exceeded its bounded size")

    tools = CommunityToolsPanel(Tools(), open_source_review=forbidden)
    window = shell(tools, "Suggested tools and supported adapters")
    settle(lambda: not tools._operations and not any(thread.is_alive() for thread in tools._threads))
    tools.tools.setCurrentRow(2)
    tools.refresh()
    settle(lambda: not tools._operations and not any(thread.is_alive() for thread in tools._threads))
    save(window, NAMES[0])
    tools.tabs.setCurrentIndex(1)
    tools.editor.setPlainText("# DEMO working copy\n# Edits stay separate from installed source.\n\nrule review_example {\n    strings:\n        $marker = \"ANGERONA_INERT_DEMO\"\n    condition:\n        $marker\n}\n")
    tools.copy_notice.setText("DEMO · Separate editable copy. Save, compare, revert and analyze before any reviewed activation.")
    settle()
    save(window, NAMES[1])
    tools.request_shutdown()
    window.close()
    settle(lambda: not any(thread.is_alive() for thread in tools._threads))

    rules = RulesPlaybooksPanel(Library(), cfg=SimpleNamespace(community_rules_enabled=False, community_playbooks_enabled=False))
    window = shell(rules, "Build and review a defensive tactic")
    settle(lambda: rules._operation is None and (rules._thread is None or not rules._thread.is_alive()))
    rules.tabs.setCurrentIndex(2)
    rules.status.setText("DEMO · A plan and sample check do not grant response authority. Global community controls are OFF.")
    settle()
    save(window, NAMES[2])
    rules.request_shutdown()
    window.close()
    settle(lambda: rules._thread is None or not rules._thread.is_alive())

    class Module:
        description = "Demonstration component. Live view uses current cached module information."
        capability_outputs = ("observation",)
        def __init__(self, health=100):
            self._status, self.health, self.health_note = "running", health, "DEMO only"

    names = ["Process Monitor", "Network Monitor", "AMSI Bridge", "ETW Core Listener", "C2 Beacon Detector",
             "SpywareGuard", "YARA Scanner", "Adversary Combat", "SOAR Automation", "File Integrity Monitor",
             "Driver Provenance Guard", "Ransomware Heuristics", "Telemetry Canary Drills", "Self-Integrity Monitor",
             "Audit Log Integrity Guard", "Platform Attestation Guard", "Counter-Agentic Detection", "Watchdog Monitor"]
    modules = {name: Module(65 if index in {4, 13} else 100) for index, name in enumerate(names)}
    usb = Module()
    usb._known_local_mounts, usb._known = {"C:\\", "D:\\", "F:\\"}, {"F:\\"}
    modules["Removable-Media / USB Monitor"] = usb
    model = SuiteTopologyService(SimpleNamespace(modules=modules), EventBus())
    for name in names:
        model._observe(Event(name, "DEMO publication"))
    for port in (443, 53, 8080):
        model._observe(Event("Network Monitor", "DEMO endpoint", details={"remote_ip": "203.0.113.8", "remote_port": port}))
    snapshot = model._build()
    class Cache:
        def snapshot(self): return snapshot
        def start(self): return True
        def request_shutdown(self): pass
        def owned_workers(self): return ()
        def custody_released(self): return False
    view = SuiteMapDialog(None, None, service=Cache(), navigate=forbidden)
    view.resize(1440, 920)
    banner = QLabel("DEMO   Suite Map 3D   ·   Synthetic modules, drives and ports   ·   No scan or protection result")
    banner.setWordWrap(True)
    banner.setStyleSheet("color:#fbbf24;background:#302716;padding:12px;font-weight:700;font-size:16px;")
    view.layout().insertWidget(0, banner)
    view.show()
    settle()
    node = next(node for node in snapshot.nodes if node.kind == "external_drive")
    view._select(node)
    view.canvas._selected = node.id
    settle()
    save(view, NAMES[3])
    view.request_shutdown()
    view.close()
    settle()
    if fingerprints() != initial:
        raise RuntimeError("Demo source changed while it was being captured")
    manifest = {"schema": 1, "demo": True, "host_actions": False, "source_sha256": initial,
                "images": [{"name": name + ".png", "sha256": hashlib.sha256((STAGE / (name + ".png")).read_bytes()).hexdigest()} for name in NAMES]}
    (STAGE / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print("PASS: four real Qt views captured with synthetic data and no host actions")


def encode():
    from PIL import Image
    manifest = json.loads((STAGE / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("demo") is not True or manifest.get("host_actions") is not False or manifest.get("source_sha256") != fingerprints():
        raise ValueError("A current reviewed synthetic capture manifest is required")
    frames = []
    for row in manifest["images"]:
        if row["name"] not in {name + ".png" for name in NAMES}:
            raise ValueError("Unexpected demo frame")
        path = STAGE / row["name"]
        if hashlib.sha256(path.read_bytes()).hexdigest() != row["sha256"]:
            raise ValueError("Demo image changed after capture")
        with Image.open(path) as original:
            if original.size != (1440, 920):
                raise ValueError("Unexpected demo image dimensions")
            frames.append(original.convert("RGB").resize((1008, 644), Image.Resampling.LANCZOS))
    palette = Image.new("RGB", (1008, 644 * len(frames)))
    for index, frame in enumerate(frames):
        palette.paste(frame, (0, index * 644))
    palette = palette.quantize(colors=224)
    frames = [frame.quantize(palette=palette) for frame in frames]
    destination = STAGE / "community-suite-tour-demo.gif"
    frames[0].save(destination, save_all=True, append_images=frames[1:], duration=4500, loop=0, optimize=False, disposal=2)
    if not 0 < destination.stat().st_size <= 8 * 1024**2:
        raise ValueError("Demo GIF exceeded its public asset budget")
    print("PASS: four-chapter DEMO tour encoded")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("capture", "encode"))
    args = parser.parse_args()
    (capture if args.mode == "capture" else encode)()


if __name__ == "__main__":
    raise SystemExit(main())
