from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest
from PySide6.QtCore import QCoreApplication, QEvent

import blackbox_recorder as blackbox


def test_bounded_query_preserves_success_output_and_retires_process(monkeypatch):
    original = subprocess.Popen
    children = []
    def start(*args, **kwargs):
        child = original(*args, **kwargs)
        children.append(child)
        return child
    monkeypatch.setattr(subprocess, "Popen", start)
    output = blackbox._read_firewall_command(
        [sys.executable, "-I", "-c", "print('inert snapshot')"], timeout=5,
    )
    assert output.strip() == "inert snapshot"
    assert children[0].poll() == 0
    assert children[0].stdout.closed


def test_output_overflow_refuses_partial_snapshot_and_retires_child(monkeypatch):
    monkeypatch.setattr(blackbox, "_MAX_FIREWALL_OUTPUT_BYTES", 1024)
    original = subprocess.Popen
    children = []
    def start(*args, **kwargs):
        child = original(*args, **kwargs)
        children.append(child)
        return child
    monkeypatch.setattr(subprocess, "Popen", start)
    with pytest.raises(ValueError, match="output limit"):
        blackbox._read_firewall_command(
            [sys.executable, "-I", "-c", "import os,time; os.write(1,b'x'*65536); time.sleep(20)"],
            timeout=5,
        )
    assert children[0].poll() is not None
    assert children[0].stdout.closed


def test_timeout_retires_only_query_child(monkeypatch):
    original = subprocess.Popen
    children = []
    def start(*args, **kwargs):
        child = original(*args, **kwargs)
        children.append(child)
        return child
    monkeypatch.setattr(subprocess, "Popen", start)
    with pytest.raises(TimeoutError, match="deadline"):
        blackbox._read_firewall_command(
            [sys.executable, "-I", "-c", "import time; time.sleep(20)"], timeout=0.1,
        )
    assert children[0].poll() is not None
    assert children[0].stdout.closed


@pytest.mark.skipif(os.name != "nt", reason="Windows system-query path")
def test_windows_query_uses_trusted_binary_and_never_searches_cwd(monkeypatch):
    from angerona.core.privilege import trusted_powershell_path, trusted_windows_directories
    commands = []
    def refused(command, **kwargs):
        commands.append((command, kwargs))
        raise OSError("inert launch refusal")
    monkeypatch.setattr(subprocess, "Popen", refused)
    with pytest.raises(OSError, match="inert launch refusal"):
        blackbox._read_firewall_command(["powershell", "-NoProfile"], timeout=5)
    assert commands[0][0][0] == str(trusted_powershell_path())
    assert commands[0][1]["cwd"] == str(trusted_windows_directories()[1])
    assert commands[0][1]["creationflags"] & subprocess.CREATE_NO_WINDOW
    assert commands[0][1]["creationflags"] & 0x00000004


def test_both_query_failures_keep_existing_ui_snapshot(monkeypatch):
    app = blackbox.QApplication.instance() or blackbox.QApplication([])
    calls = []
    def refused(command, **kwargs):
        calls.append(command[0])
        raise ValueError("inert output overflow")
    monkeypatch.setattr(blackbox, "_read_firewall_command", refused)
    tab = blackbox.FirewallTab()
    tab._apply_rules([dict(name="retained", rule_id="exact", direction="In",
                           action="Block", proto="", port="")])
    try:
        tab.refresh()
        deadline = time.monotonic() + 5
        while tab._reader.busy and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.005)
        assert not tab._reader.busy
        assert calls == ["powershell", "netsh"]
        assert tab.table.item(0, 0).text() == "retained"
        assert "previous snapshot retained" in tab.status.text()
    finally:
        tab.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


def test_netsh_fallback_bounds_fields_and_rule_count(monkeypatch):
    def output(command, **kwargs):
        if command[0] == "powershell":
            raise OSError("inert fallback")
        return "\n".join(
            "Rule Name: " + str(index) + "X" * 2050 + "\nDirection: " + "Y" * 2050
            for index in range(2001)
        )
    monkeypatch.setattr(blackbox, "_read_firewall_command", output)
    rules = blackbox.FirewallTab._read_rules()
    assert len(rules) == blackbox._MAX_FIREWALL_RULES
    assert all(len(rule["name"]) == len(rule["direction"]) == 2048 for rule in rules)


def test_status_describes_snapshot_and_filter_limits(monkeypatch):
    app = blackbox.QApplication.instance() or blackbox.QApplication([])
    tab = blackbox.FirewallTab()
    try:
        tab._apply_rules([dict(name=str(index), rule_id=str(index), direction="In",
                               action="Block", proto="", port="") for index in range(2001)])
        assert len(tab._all_rules) == 2000
        assert tab.table.rowCount() == 500
        assert "Showing 500 of 2000" in tab.status.text()
        assert "Snapshot limit: 2000; table limit: 500" in tab.status.text()
        tab.filter_edit.setText("1999")
        assert "Showing 1 of 1" in tab.status.text()
        assert "Filtering searches this snapshot only" in tab.status.text()
    finally:
        tab.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
