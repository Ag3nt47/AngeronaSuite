import ast
import os
import time
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def test_staged_cve_proposal_never_renders_as_executed_or_fixed():
    source = Path("src/angerona/gui/threat_intel_page.py").read_text(encoding="utf-8")
    assert "Proposal staged — not executed" in source
    assert "not verified as fixed" in source
    assert "ran successfully" not in source
    assert '"Fix applied"' not in source


def test_bulk_ignore_is_retired_and_no_longer_calls_the_ignore_store():
    source = Path("src/angerona/gui/threat_intel_page.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    method = next(
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "_mass_flag_ignore"
    )
    method_source = ast.get_source_segment(source, method) or ""
    assert ".ignore(" not in method_source
    assert "Bulk ignore is disabled" in method_source
    assert "remain active" in method_source


def test_cve_exclusion_requires_typed_evidence_approver_and_future_expiry(
    tmp_path, monkeypatch,
):
    from angerona.core import cve_ignore

    store = tmp_path / "cve_ignore.json"
    monkeypatch.setattr(cve_ignore, "_store_path", lambda: store)

    with pytest.raises(TypeError):
        cve_ignore.ignore("CVE-2099-0001", "no fix")
    with pytest.raises(ValueError, match="only not_applicable"):
        cve_ignore.ignore(
            "CVE-2099-0001", "risk accepted", classification="accepted_risk",
            expires_at=time.time() + 60, approver="analyst",
        )
    with pytest.raises(ValueError, match="future"):
        cve_ignore.ignore(
            "CVE-2099-0001", "product absent", classification="not_applicable",
            expires_at=time.time() - 1, approver="analyst",
        )

    cve_ignore.ignore(
        "CVE-2099-0001", "product package is not installed",
        classification="not_applicable", expires_at=time.time() + 60,
        approver="analyst-1",
    )
    assert cve_ignore.is_ignored("CVE-2099-0001")

    data = cve_ignore.load()
    data["CVE-2099-0001"]["expires_at"] = time.time() - 1
    cve_ignore._save(data)
    assert not cve_ignore.is_ignored("CVE-2099-0001")

    data["CVE-2099-0002"] = {
        "ignored": True, "reason": "legacy no-fix suppression", "history": [],
    }
    cve_ignore._save(data)
    assert not cve_ignore.is_ignored("CVE-2099-0002")


def test_opening_sandbox_does_not_stop_sensors_or_replace_eventbus():
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication
    from angerona.gui.sandbox_editor import SandboxEditor

    class Manager:
        modules = {}

        def __init__(self):
            self.stop_calls = 0

        def stop_all(self):
            self.stop_calls += 1

    class Bus:
        def publish(self, *_args, **_kwargs):
            return "live"

    app = QApplication.instance() or QApplication([])
    manager = Manager()
    bus = Bus()
    original_publish = bus.publish.__func__
    window = SandboxEditor(manager, bus)
    try:
        assert manager.stop_calls == 0
        assert bus.publish.__func__ is original_publish
    finally:
        window._close_confirmed = True
        window.close()
        app.processEvents()


def test_sandbox_editor_has_no_global_sensor_pause_or_bus_replacement():
    source = Path("src/angerona/gui/sandbox_editor.py").read_text(encoding="utf-8")

    assert ".stop_all(" not in source
    assert "bus.publish =" not in source
    assert "all sensors paused" not in source
    assert "run_isolated_self_test(" in source


def test_isolated_sandbox_self_test_has_a_hard_deadline(tmp_path):
    from angerona.core.sandbox_runner import run_isolated_self_test

    package = tmp_path / "probe_pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "probe.py").write_text(
        "import time\n"
        "class HangingProbe:\n"
        "    name = 'Hanging Probe'\n"
        "    def self_test(self):\n"
        "        time.sleep(30)\n"
        "        return True, 'unexpected'\n",
        encoding="utf-8",
    )

    started = time.monotonic()
    passed, output = run_isolated_self_test(
        "probe_pkg.probe", "HangingProbe", "Hanging Probe",
        timeout=0.25, source_root=Path(tmp_path),
    )
    elapsed = time.monotonic() - started

    assert passed is False
    assert "TIMEOUT" in output
    assert elapsed < 5


def test_isolated_sandbox_uses_disposable_data_and_offline_environment(tmp_path):
    from angerona.core.sandbox_runner import run_isolated_self_test

    package = tmp_path / "env_probe_pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "probe.py").write_text(
        "import os\n"
        "class EnvironmentProbe:\n"
        "    name = 'Environment Probe'\n"
        "    def self_test(self):\n"
        "        root = os.environ.get('ANGERONA_DATA', '')\n"
        "        ok = (os.environ.get('ANGERONA_OFFLINE') == '1' and "
        "'angerona-sandbox-' in root and os.environ.get('ANGERONA_REMOTE_BRIDGE') == '0')\n"
        "        return ok, root\n",
        encoding="utf-8",
    )

    passed, output = run_isolated_self_test(
        "env_probe_pkg.probe", "EnvironmentProbe", "Environment Probe",
        timeout=3, source_root=Path(tmp_path),
    )

    assert passed is True
    assert "angerona-sandbox-" in output


def test_inno_setup_delegates_rollback_and_mutation_to_installed_authority():
    script = Path("installer/Angerona.iss").read_text(encoding="utf-8")

    assert "function InitializeSetup(): Boolean;" in script
    assert "PrivilegesRequired=lowest" in script
    assert "CreateAppDir=no" in script
    assert "CreateUninstallRegKey=no" in script
    assert "CustodyPreflightOnly" in script
    assert "if not ShellExec(" in script
    assert "'runas', PowerShell" in script
    assert "Install-Angerona-Release.ps1" in script
    assert "RegWriteStringValue(" not in script
    assert "HighestInstalledVersion" not in script
    assert "uninsdelete" not in script.lower()
