from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QPlainTextEdit

from angerona.gui.dashboard_details import (
    ConsoleDetailDialog,
    ModuleResourceDialog,
    SystemPulseDetailDialog,
)
from angerona.gui.system_pulse import SystemPulseCard
from angerona.gui.top_talkers import TopTalkersDialog
from angerona.modules import purple_guard


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def test_purple_guard_reuses_policy_until_atomic_file_change(tmp_path, monkeypatch) -> None:
    calls = 0
    original = purple_guard._read_policy

    def counted(root=None):
        nonlocal calls
        calls += 1
        return original(root)

    monkeypatch.setattr(purple_guard, "_read_policy", counted)
    purple_guard.install_policies([{"mitre": "T1003"}], "first", tmp_path)
    calls = 0
    module = purple_guard.PurpleGuard(tmp_path)

    assert "T1003" in module._policy_snapshot()
    for _index in range(50):
        assert "T1003" in module._policy_snapshot()
    assert calls == 1

    purple_guard.install_policies([{"mitre": "T1059"}], "second", tmp_path)
    calls_after_install = calls
    assert "T1059" in module._policy_snapshot()
    assert calls == calls_after_install + 1


def test_console_detail_skips_unchanged_full_transcript_copy() -> None:
    _app()

    class CountingOutput(QPlainTextEdit):
        def __init__(self) -> None:
            super().__init__()
            self.reads = 0

        def toPlainText(self) -> str:  # noqa: N802 - Qt signature
            self.reads += 1
            return super().toPlainText()

    class Console:
        def __init__(self) -> None:
            self.out = CountingOutput()
            self.out.setPlainText("ready\n" + ("x" * 80_000))
            self._busy = 0

        def run_command(self, _text: str) -> None:
            return None

    console = Console()
    detail = ConsoleDetailDialog(console)
    detail._timer.stop()
    initial_reads = console.out.reads
    for _index in range(20):
        detail._refresh()
    assert console.out.reads == initial_reads

    console.out.appendPlainText("changed")
    detail._refresh()
    assert console.out.reads == initial_reads + 1
    assert "changed" in detail.transcript.toPlainText()
    detail.close()


def test_pulse_detail_copies_history_only_for_new_sample(monkeypatch) -> None:
    _app()
    card = SystemPulseCard(interval_ms=60_000)
    card._timer.stop()
    card._apply_sample(
        {"cpu": 5.0, "ram": 10.0, "available": 1.0, "wifi": 20,
         "down": 30.0, "up": 40.0}
    )
    calls = 0
    original = card.snapshot

    def counted():
        nonlocal calls
        calls += 1
        return original()

    monkeypatch.setattr(card, "snapshot", counted)
    detail = SystemPulseDetailDialog(card)
    detail._timer.stop()
    initial_calls = calls
    for _index in range(20):
        detail._refresh()
    assert calls == initial_calls

    card._apply_sample(
        {"cpu": 6.0, "ram": 11.0, "available": 2.0, "wifi": 21,
         "down": 31.0, "up": 41.0}
    )
    detail._refresh()
    assert calls == initial_calls + 1
    assert detail.cpu.value.text() == "6%"
    detail.close()
    card.close()


def test_module_resource_table_rebuilds_only_when_events_change(monkeypatch) -> None:
    _app()
    event = type(
        "Event",
        (),
        {"ts": 1.0, "module": "Sensor", "severity": 2, "message": "one"},
    )()
    current = [event]

    def snapshot(_name):
        return {"intensity": 1, "health": 100, "status": "running", "events": current}

    detail = ModuleResourceDialog("Sensor", snapshot)
    detail._timer.stop()
    calls = 0
    original = detail.table.setRowCount

    def counted(rows):
        nonlocal calls
        calls += 1
        return original(rows)

    monkeypatch.setattr(detail.table, "setRowCount", counted)
    for _index in range(20):
        detail._refresh()
    assert calls == 0

    current.append(
        type(
            "Event",
            (),
            {"ts": 2.0, "module": "Sensor", "severity": 3, "message": "two"},
        )()
    )
    detail._refresh()
    assert calls == 1
    detail.close()


def test_top_talkers_skips_unchanged_table_rebuild(monkeypatch) -> None:
    _app()
    dialog = TopTalkersDialog()
    dialog._timer.stop()
    snapshot = {
        "rows": [{"name": "vpn", "pid": 7, "conns": 1, "ext": 0,
                  "top": "10.0.0.1:443", "iface": "VPN"}],
        "process_count": 1,
        "total_ext": 0,
    }
    dialog._apply_snapshot(snapshot)
    calls = 0
    original = dialog.table.setRowCount

    def counted(rows):
        nonlocal calls
        calls += 1
        return original(rows)

    monkeypatch.setattr(dialog.table, "setRowCount", counted)
    for _index in range(20):
        dialog._apply_snapshot(snapshot)
    assert calls == 0
    dialog.close()
