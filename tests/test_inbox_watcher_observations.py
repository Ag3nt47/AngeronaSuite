from __future__ import annotations

import ast
import copy
import socket
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.connectors import inbox_triage, inbox_watcher
from angerona.core.eventbus import Event, Severity
from angerona.core.threat import event_disposition, is_active_threat


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refused(*_args, **_kwargs):
        raise AssertionError("Inbox watcher test attempted real network access")

    monkeypatch.setattr(socket, "socket", refused)
    monkeypatch.setattr(socket, "create_connection", refused)
    monkeypatch.setattr(socket, "getaddrinfo", refused)


def _phish(**changes):
    return {"from": "Security <security@paypa1-support.com>", "reply_to": "harvest@evil.ru",
            "subject": "URGENT verify your password", "body": "Confirm credentials immediately",
            "attachments": ["invoice.exe"], **changes}


def test_repeated_mail_polls_emit_once_as_nonactive_high_observations():
    events = []
    message = _phish(message_identity="1" * 64)

    def emit(text, severity, **details):
        events.append(Event("ARIA Inbox", text, getattr(Severity, severity), time.time(), details))

    watcher = inbox_watcher.InboxWatcher(host="imap.example", user="operator", emit=emit,
                                         fetch=lambda: [copy.deepcopy(message)])
    assert watcher.scan_once()["emitted"] == 1
    assert watcher.scan_once()["emitted"] == 0
    assert watcher.scan_once()["flagged"] == 1
    assert len(events) == 1
    event = events[0]
    assert event.severity == Severity.HIGH
    assert event.details["verdict"] == "PHISH_LIKELY"
    assert event.details["active_attack"] is False
    assert event.details["response_authorized"] is False
    assert event_disposition(event) == "observation"
    assert not is_active_threat(event)


def test_normalized_fetch_fallback_identity_is_stable_and_mailbox_scoped():
    emitted = []
    watcher = inbox_watcher.InboxWatcher(host="imap.example", user="operator",
        emit=lambda *args, **kwargs: emitted.append((args, kwargs)), fetch=lambda: [_phish()])
    assert watcher.scan_once()["emitted"] == 1
    assert watcher.scan_once()["emitted"] == 0
    watcher.folder = "Archive"
    assert watcher.scan_once()["emitted"] == 1
    assert len(emitted) == 2


def test_subject_sender_and_reasons_are_bounded_single_line_text():
    events = []
    message = _phish(subject="URGENT\r\npassword\x1b[31m\u202e spoof",
        **{"from": "IT\nsecurity@paypa1-support.com\x00"},
        attachments=["invoice\n.exe"])
    watcher = inbox_watcher.InboxWatcher(fetch=lambda: [message],
        emit=lambda text, severity, **details: events.append((text, severity, details)))
    watcher.scan_once()
    assert len(events) == 1
    text, severity, details = events[0]
    assert severity == "HIGH" and len(text) <= 512
    for value in [text, details["sender"], *details["reasons"]]:
        assert all(ord(char) >= 32 and char not in "\x7f\u202e" for char in value)


def test_unverified_authentication_alone_stays_quiet_and_reports_the_gap():
    raw = (b"From: staff@example.com\r\nSubject: Notes\r\n"
           b"Authentication-Results: receiving.example; spf=pass; dkim=pass; dmarc=pass\r\n\r\nordinary notes")
    message = inbox_triage._normalize_message(raw, size=len(raw))
    events = []
    watcher = inbox_watcher.InboxWatcher(fetch=lambda: [message],
        emit=lambda *args, **kwargs: events.append((args, kwargs)))

    summary = watcher.scan_once()

    assert summary["authentication_unverified"] == 1
    assert summary["flagged"] == summary["incomplete"] == summary["emitted"] == 0
    assert events == []
    assert any("authentication is unverified" in reason
               for reason in watcher._triage.score_message(message).reasons)


@pytest.mark.parametrize("failure", ["exception", "false"])
def test_failed_publication_does_not_consume_delivery_identity(failure):
    attempts = []

    def emit(*_args, **_kwargs):
        attempts.append(1)
        if len(attempts) == 1:
            if failure == "exception":
                raise RuntimeError("inert publication failure")
            return False
        return None

    watcher = inbox_watcher.InboxWatcher(fetch=lambda: [_phish()], emit=emit)
    assert watcher.scan_once()["emitted"] == 0
    assert watcher.scan_once()["emitted"] == 1
    assert watcher.scan_once()["emitted"] == 0
    assert len(attempts) == 2


def test_incomplete_content_and_advisories_are_deduplicated_low_observations():
    events = []
    incomplete = inbox_triage._incomplete_message("bounded content was unavailable")
    advisory = {"from": "psirt@example.com", "subject": "Security advisory CVE-2026-1234", "body": "Notes"}
    watcher = inbox_watcher.InboxWatcher(fetch=lambda: [incomplete, advisory],
        emit=lambda text, severity, **details: events.append((text, severity, details)))
    first = watcher.scan_once()
    assert first["incomplete"] == first["advisories"] == 1
    assert first["emitted"] == 2
    assert watcher.scan_once()["emitted"] == 0
    assert all(severity == "LOW" and details["observation_only"] is True
               for _, severity, details in events)


def test_delivery_cache_is_bounded_without_creating_persistent_trust_files(monkeypatch):
    monkeypatch.setattr(inbox_watcher, "_MAX_SEEN_ALERTS", 3)
    current = [_phish(message_identity="1" * 64)]
    watcher = inbox_watcher.InboxWatcher(fetch=lambda: current, emit=lambda *_args, **_kwargs: None)
    for value in "1234":
        current[0] = _phish(message_identity=value * 64)
        assert watcher.scan_once()["emitted"] == 1
    assert len(watcher._seen) == 3
    current[0] = _phish(message_identity="4" * 64)
    assert watcher.scan_once()["emitted"] == 0


def test_overlapping_scan_is_rejected_without_fetching_twice():
    attempts = []
    watcher = inbox_watcher.InboxWatcher(fetch=lambda: attempts.append(1) or [])
    watcher._scan_lock.acquire()
    try:
        with pytest.raises(RuntimeError, match="already running"):
            watcher.scan_once()
    finally:
        watcher._scan_lock.release()
    assert attempts == []


def test_watcher_selftest_uses_only_inert_observations():
    ok, detail = inbox_watcher.InboxWatcher().self_test()
    assert ok, detail


def test_real_gui_inbox_callback_reports_publication_failure_without_importing_gui():
    source = Path(__file__).resolve().parents[1] / "src/angerona/gui/main_window.py"
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    matches = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "_inbox_emit"]
    assert len(matches) == 1
    function = ast.Module(body=[copy.deepcopy(matches[0])], type_ignores=[])
    captured = []
    fail = [True]

    def publish(event):
        if fail[0]:
            raise RuntimeError("inert publication failure")
        captured.append(event)

    namespace = {"self": SimpleNamespace(bus=SimpleNamespace(publish=publish)),
                 "Event": Event, "Severity": Severity, "time": SimpleNamespace(time=lambda: 123.0)}
    # Compile only the reviewed nested callback, with fake dependencies. The GUI
    # module, application constructor and real EventBus are never imported/run.
    exec(compile(ast.fix_missing_locations(function), str(source), "exec"), namespace)
    watcher = inbox_watcher.InboxWatcher(fetch=lambda: [_phish()], emit=namespace["_inbox_emit"])
    assert watcher.scan_once()["emitted"] == 0
    fail[0] = False
    assert watcher.scan_once()["emitted"] == 1
    assert watcher.scan_once()["emitted"] == 0
    assert len(captured) == 1
    assert captured[0].module == "ARIA Inbox"
    assert captured[0].details["disposition"] == "observation"
