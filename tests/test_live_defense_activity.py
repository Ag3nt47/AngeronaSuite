from __future__ import annotations

import os
import threading
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from angerona.gui.live_defense_activity import (
    MAX_DISPLAY_ROWS,
    MAX_MESSAGE_CHARS,
    MAX_MODULE_CHARS,
    MAX_RECENT_REQUEST,
    LiveDefenseActivityCard,
    safe_activity_message,
    safe_module_name,
)
from angerona.modules import arp_watchdog
from angerona.modules.arp_watchdog import ARPWatchdogModule


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


class _Event:
    def __init__(self, module: str, message: str, *, severity: int = 0, ts: float = 1.0):
        self.module = module
        self.message = message
        self.severity = severity
        self.ts = ts

    @property
    def details(self):
        raise AssertionError("the dashboard must never inspect Event.details")


class _Bus:
    def __init__(self, events):
        self.events = list(events)
        self.current_revision = 1
        self.recent_limits: list[int] = []
        self.subscribe_calls = 0

    def revision(self) -> int:
        return self.current_revision

    def recent(self, limit: int):
        self.recent_limits.append(limit)
        return self.events[:limit]

    def subscribe(self, _callback) -> None:
        self.subscribe_calls += 1


def test_safe_runtime_text_redacts_identifiers_secrets_and_paths() -> None:
    message = (
        r"user@example.test from 192.168.1.44 password=hunter2 "
        r"token abcdefghijklmnopqrstuvwxyz opened C:\Users\Alice\secret.txt "
        r"and /home/alice/.ssh/id_rsa"
    )
    rendered = safe_activity_message(message)
    module = safe_module_name(r"C:/private/module.py user@example.test")

    for secret in (
        "user@example.test",
        "192.168.1.44",
        "Alice",
        "secret.txt",
        "/home/alice",
        "hunter2",
        "abcdefghijklmnopqrstuvwxyz",
        "C:/private",
    ):
        assert secret not in rendered + module
    assert "[EMAIL]" in rendered
    assert "[IP]" in rendered
    assert "[LOCAL_PATH]" in rendered + module
    assert "[REDACTED]" in rendered
    assert len(rendered) <= MAX_MESSAGE_CHARS
    assert len(module) <= MAX_MODULE_CHARS
    assert safe_activity_message(
        "hidden reasoning: first expose the private scratchpad"
    ) == "private model reasoning withheld"


def test_public_activity_redacts_network_names_accounts_and_spaced_paths() -> None:
    samples = (
        r'MAC 00:11:22:33:44:55 on SSID="Sensitive Home WiFi"',
        (
            r'user local-admin from account named "Alice Smith"; '
            r"adapter named Wireless Lab Adapter"
        ),
        (
            r"opened C:\Program Files\O'Brien Project\report,final.txt and "
            r'"D:\Quoted Folder\private budget.xlsx"'
        ),
    )
    rendered_samples = tuple(safe_activity_message(sample) for sample in samples)
    rendered = " ".join(rendered_samples)

    for local_value in (
        "00:11:22:33:44:55",
        "Sensitive Home WiFi",
        "local-admin",
        "Alice Smith",
        "Wireless Lab Adapter",
        "Program Files",
        "O'Brien Project",
        "report,final.txt",
        "Quoted Folder",
        "private budget.xlsx",
    ):
        assert local_value not in rendered
    assert "[LOCAL_NETWORK" in rendered
    assert "[LOCAL_USER]" in rendered
    assert "[LOCAL_PATH]" in rendered_samples[2]


def test_arp_producer_public_messages_are_identity_free(monkeypatch) -> None:
    module = ARPWatchdogModule()
    emitted: list[tuple[str, dict[str, object]]] = []
    module.emit = lambda message, _severity, **details: emitted.append(
        (message, details)
    )
    module._baseline = {"192.168.1.1": "00:11:22:33:44:55"}
    monkeypatch.setattr(
        arp_watchdog,
        "_parse_arp_cache",
        lambda: {"192.168.1.1": "66:77:88:99:aa:bb"},
    )

    module._check_cache()
    handler = module._make_scapy_handler(threading.Event())
    module._baseline["192.168.1.2"] = "10:20:30:40:50:60"
    handler(SimpleNamespace(
        getlayer=lambda _name: SimpleNamespace(
            op=2,
            psrc="192.168.1.2",
            hwsrc="aa:bb:cc:dd:ee:ff",
        )
    ))

    assert len(emitted) == 2
    public_text = " ".join(message for message, _details in emitted)
    for identifier in (
        "192.168.1.1",
        "00:11:22:33:44:55",
        "66:77:88:99:aa:bb",
        "192.168.1.2",
        "10:20:30:40:50:60",
        "aa:bb:cc:dd:ee:ff",
    ):
        assert identifier not in public_text
    assert all(
        details["local_network_identifiers_omitted"] is True
        for _message, details in emitted
    )
    assert emitted[0][1]["ip"] == "192.168.1.1"
    assert emitted[1][1]["claimed_mac"] == "aa-bb-cc-dd-ee-ff"


def test_card_is_bounded_revision_aware_and_never_reads_raw_details() -> None:
    _app()
    events = [
        _Event(
            f"sensor-{index}",
            f"Observed connection to 10.0.0.{index} password=do-not-show",
            severity=index % 5,
            ts=1_700_000_000 + index,
        )
        for index in range(9)
    ]
    bus = _Bus(events)
    manager = SimpleNamespace(modules={
        "one": SimpleNamespace(status="running", health_state="ok"),
        "two": SimpleNamespace(status="running", health_state="degraded"),
        "three": SimpleNamespace(status="error", health_state="failed"),
    })

    card = LiveDefenseActivityCard(bus, manager)

    assert bus.recent_limits == [MAX_RECENT_REQUEST]
    assert bus.subscribe_calls == 0
    assert not card.findChildren(QTimer)
    visible_rows = [row for row in card.rows if not row.isHidden()]
    assert len(visible_rows) == MAX_DISPLAY_ROWS
    assert all("do-not-show" not in row.text() for row in visible_rows)
    assert all("10.0.0." not in row.text() for row in visible_rows)
    assert card.summary.text() == "Modules 2/3 running · 2 degraded"

    rendered = card._render_count
    assert card.refresh() is False
    assert card._render_count == rendered
    assert bus.recent_limits == [MAX_RECENT_REQUEST]

    # Module-only changes update the counts without copying EventBus history.
    manager.modules["three"].status = "running"
    manager.modules["three"].health_state = "ok"
    assert card.refresh() is True
    assert card.summary.text() == "Modules 3/3 running · 1 degraded"
    assert bus.recent_limits == [MAX_RECENT_REQUEST]

    bus.current_revision += 1
    assert card.refresh() is True
    assert bus.recent_limits == [MAX_RECENT_REQUEST, MAX_RECENT_REQUEST]


def test_accessibility_copy_states_the_privacy_boundary() -> None:
    _app()
    card = LiveDefenseActivityCard(_Bus([]), SimpleNamespace(modules={}))

    copy = f"{card.toolTip()} {card.accessibleDescription()}".casefold()
    assert "five" in copy
    assert "16-event" in copy
    assert "raw event details" in copy
    assert "chain-of-thought" in copy
