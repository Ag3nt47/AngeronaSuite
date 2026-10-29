"""One actual pinned-engine/Qt/native chain over private, inert evidence only."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import threading
import time
from types import SimpleNamespace

import pytest
from PySide6.QtWidgets import QApplication

from angerona.core import background_pacing, curated_tools as tools
from angerona.core.eventbus import EventBus
from angerona.core.module_base import BaseModule
from angerona.core.module_manager import ModuleManager
from angerona.gui.curated_tools import CuratedToolsController, SpywareScanControls
from test_spyware_native_progress import module_with, retire


def _until(predicate, timeout=35):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        QApplication.processEvents()
        if predicate():
            return
        time.sleep(.01)
    pytest.fail("Controlled scan chain did not reach the expected state before its test deadline")


class _InertBackground(BaseModule):
    name = "Owned integration pacing fixture"
    adaptive_throttle_allowed = True
    adaptive_throttle_max = 8.0


@pytest.mark.skipif(os.name != "nt", reason="Actual ordinary-user Windows scanner/Job integration")
def test_qt_priority_chain_actual_pinned_positive_report_and_inert_native_progress(tmp_path, monkeypatch):
    identity = tools._admin_state()
    if identity.get("verified") is not True or identity.get("elevated") is not False:
        pytest.skip("Actual managed engine requires a verified ordinary-user token; no elevation bypass")

    def no_network(*_args, **_kwargs):
        pytest.fail("Controlled integration attempted parent network access")

    for name in ("connect", "connect_ex", "sendto"):
        monkeypatch.setattr(socket.socket, name, no_network)
    for name in ("create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, no_network)

    root = tmp_path / "controlled-chain"
    tools._private(root)
    profile = root / "synthetic-profile"
    for directory in ("local", "roaming", "Downloads", "Desktop", "Documents", "config"):
        tools._private(profile / directory)
    evidence = root / "evidence"
    tools._private(evidence)
    original = evidence / "owned-ui-evidence.bin"
    # Larger than the pinned engine's 1 MiB read chunk, so the test observes
    # a genuine partial read rather than inventing a file percentage.
    inert = b"Controlled Angerona integration fixture. No executable content.\n" * 65536
    tools._atomic_bytes_write(original, inert, root=root)
    indicators = root / "private-indicators.txt"
    digest = hashlib.sha256(inert).hexdigest()
    tools._atomic_bytes_write(indicators, (digest + "\tsample\tprimary\tsynthetic fixture\n").encode(), root=root)

    cfg = SimpleNamespace(ugcap_enabled=False, github_tools_enabled=True,
                          github_tools_auto_prepare=False, github_tools_allow_download=False,
                          github_tools_timeout_seconds=30, github_tools_job_limit_mib=64,
                          github_tools_report_limit_mib=8, spyware_scan_native_enabled=True,
                          spyware_scan_zero_breach_enabled=True, spyware_scan_verify_admin=True,
                          spyware_scan_priority="above-normal", spyware_scan_cpu_percent=70,
                          spyware_scan_memory_mib=512, spyware_scan_background_percent=10,
                          ui_motion_enabled=False)
    bundle = Path(__file__).resolve().parents[1] / "assets/integrations/zero_breach"
    pinned = hashlib.sha256((bundle / "engine.py").read_bytes()).hexdigest()
    assert pinned == tools.ZERO_BREACH["sha256"]
    service = tools.CuratedToolService(root / "managed-tools", cfg=cfg, bundle=bundle)

    # The production sanitizer intentionally derives native Windows folders.
    # Route this controlled child's evidence fallbacks explicitly into our
    # owned tree rather than relying on parent environment overrides.
    environment = service._environment

    def isolated_environment(job, **kwargs):
        values = environment(job, **kwargs)
        values.update(HOME=str(profile), USERPROFILE=str(profile), APPDATA=str(profile / "roaming"),
                      LOCALAPPDATA=str(profile / "local"), ProgramData=str(profile / "local"),
                      XDG_CONFIG_HOME=str(profile / "config"))
        return values

    monkeypatch.setattr(service, "_environment", isolated_environment)
    command = service._command

    def observed_command(image, request_path):
        values = command(image, request_path)
        position = values.index("-c") + 1
        marker = ";from angerona.core.curated_tool_worker import main;"
        # Same controlled observer seam as the backend real-engine tests:
        # pinned scanner bytes and its returned reads remain unchanged.
        observer = """
import sys,time
def controlled_audit(event,args):
    if event.startswith('winreg.') or event in {'socket.connect','socket.bind','socket.getaddrinfo','socket.sendto','subprocess.Popen','os.system'}:
        print('CONTROLLED_CHAIN_FORBIDDEN_ACTION:'+event,file=sys.stderr,flush=True)
        raise PermissionError('Controlled chain forbids host inventory commands and network')
sys.addaudithook(controlled_audit)
from angerona.core.curated_tool_progress import ScannerProgress
actual_position=ScannerProgress.read_position
def observed_position(self,token,position):
    actual_position(self,token,position)
    if self.current_file.endswith('owned-ui-evidence.bin') and self.item_total and 0 < position < self.item_total and not getattr(self,'_controlled_pause',False):
        self._controlled_pause=True
        self.publish(force=True)
        time.sleep(1) # Bounded observation window after a genuine partial read.
ScannerProgress.read_position=observed_position
from angerona.core.curated_tool_worker import main
"""
        assert values[position].count(marker) == 1
        values[position] = values[position].replace(marker, "\n" + observer + "\n")
        return values

    monkeypatch.setattr(service, "_command", observed_command)
    entered, release = threading.Event(), threading.Event()
    native_calls = []

    def persistence(**kwargs):
        native_calls.append(kwargs)
        entered.set()
        assert release.wait(45)
        return {"findings": [], "coverage": {"controlled": "inert empty source"}}

    native = module_with(monkeypatch, persistence_collector=persistence)
    pacing = background_pacing.BackgroundPacingController()
    monkeypatch.setattr(background_pacing, "_CONTROLLER", pacing)
    manager = ModuleManager(EventBus(), cfg)
    native.bind(manager.bus)
    background = _InertBackground()
    background.set_throttle(2)
    manager.modules = {native.name: native, background.name: background}
    manager.module_trust = {name: {"origin": "builtin", "trust": "release"} for name in manager.modules}
    controller = CuratedToolsController(manager, QApplication.instance(), service_factory=lambda **_kw: service)
    panel = SpywareScanControls(manager, controller=controller)
    panel.resize(620, 720)
    panel.show()
    observations = []
    controller.status_changed.connect(lambda value: observations.append(value))
    native.start(initial_delay=30)
    try:
        assert controller.prepare()
        _until(lambda: not controller.snapshot()["busy"])
        assert controller.snapshot()["verified"] is True
        assert panel.start(mode="targeted", targets=(str(evidence),), iocs=(str(indicators),))
        _until(entered.is_set)
        assert manager.priority_scan_focus_snapshot()["active"] is True
        assert background._priority_throttle == 8
        _until(lambda: panel.item_progress.isVisible() and 0 < panel.item_progress.value() < 100)
        assert str(original) in panel.current_file.text()
        assert "bytes read" in panel.item_caption.text()
        assert panel.progress_ring.percent < 100 and panel.cancel_button.isEnabled()
        assert panel.activity.textFormat().name == "PlainText"
        _until(lambda: service.progress_snapshot().get("owner_retired") is True)
        assert controller.snapshot()["busy"] is True  # Exact native collector still owns its request.
        assert manager.priority_scan_focus_snapshot()["active"] is True
        assert native.priority_scan_snapshot()["request_finished"] is False
        release.set()
        _until(lambda: not controller.snapshot()["busy"])
        result = controller.snapshot()
        assert result["state"] == "completed" and result["findings"]
        tool = result["details"]["zero_breach"]
        assert tool["state"] == "findings" and tool["native_retired"] is True
        assert tool["native_generations"] and all(row["native_retired"] for row in tool["native_generations"])
        assert Path(result["report"]).is_relative_to(root) and Path(result["report"]).is_file()
        assert json.loads(Path(result["report"]).read_text(encoding="utf-8"))["schema_version"] == "1.6"
        status = native.priority_scan_snapshot()
        assert status["request_finished"] is True and status["collector_finished"] is True
        assert status["module_worker_alive"] is True
        assert manager.priority_scan_focus_snapshot() == {"active": False}
        assert background._priority_throttle == 1 and background._throttle == 2
        assert pacing.work_multiplier() == 1
        assert controller.wait_for_shutdown(3) and service.wait_for_shutdown(3)
        assert panel.progress_ring.percent == 100 and not panel.cancel_button.isEnabled()
        assert observations and any(value.get("scanner_progress", {}).get("native", {}).get("state") == "running"
                                    for value in observations)
        assert all(not value["busy"] or panel_value.get("finished", 0) < panel_value.get("total", 1)
                   for value in observations if (panel_value := value.get("scan_progress")))
        assert native_calls == [{"max_entries": 512}]
        assert original.read_bytes() == inert
        assert hashlib.sha256((bundle / "engine.py").read_bytes()).hexdigest() == pinned
        stderr = Path(result["report"]).with_name("stderr.log").read_text(encoding="utf-8")
        assert "CONTROLLED_CHAIN_FORBIDDEN_ACTION" not in stderr
        (tmp_path / "qt-chain-native-receipt.json").write_text(json.dumps({
            "state": result["state"], "report": result["report"], "native_request": status,
            "tool_native_generations": tool["native_generations"], "tool_native_retired": tool["native_retired"],
            "focus": manager.priority_scan_focus_snapshot(), "controlled_network_attempts": 0,
        }, indent=2), encoding="utf-8")
    finally:
        release.set()
        controller.shutdown()
        retire(native)
        assert controller.wait_for_shutdown(10)
        manager.stop_all()
        panel.close()
        controller.deleteLater()
