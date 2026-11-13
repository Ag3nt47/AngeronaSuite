from __future__ import annotations

import io
import re
import socket
import ssl
from types import SimpleNamespace

import pytest

from angerona.connectors import inbox_triage


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refused(*_args, **_kwargs):
        raise AssertionError("Inbox test attempted real network access")

    monkeypatch.setattr(socket, "socket", refused)
    monkeypatch.setattr(socket, "create_connection", refused)
    monkeypatch.setattr(socket, "getaddrinfo", refused)


def _message(body, *, html=False):
    content_type = "text/html" if html else "text/plain"
    return ("From: staff@example.com\r\nSubject: Team notes\r\n"
            "Authentication-Results: mail.example; spf=pass; dkim=pass; dmarc=pass\r\n"
            f"Content-Type: {content_type}; charset=utf-8\r\n\r\n{body}").encode()


def test_imap_connection_explicitly_requires_tls_certificate_and_hostname_verification(monkeypatch):
    captured = {}

    def fake_base_init(self, host, *, timeout, ssl_context):
        captured.update(host=host, timeout=timeout, context=ssl_context)

    monkeypatch.setattr(inbox_triage.imaplib.IMAP4_SSL, "__init__", fake_base_init)
    inbox_triage._BoundedIMAP4SSL("imap.example", deadline=10)

    assert captured["host"] == "imap.example"
    assert captured["timeout"] == inbox_triage._IMAP_TIMEOUT_SECONDS
    assert captured["context"].verify_mode == ssl.CERT_REQUIRED
    assert captured["context"].check_hostname is True


def _mailbox(monkeypatch, messages, *, uidvalidity=b"777"):
    instances = []

    class Mailbox:
        def __init__(self, host, *, deadline):
            assert host == "imap.example"
            assert deadline > inbox_triage.time.monotonic()
            self.closed = False
            self.requests = []
            self.untagged_responses = {"UIDVALIDITY": [uidvalidity]} if uidvalidity else {}
            instances.append(self)

        def login(self, user, password):
            assert (user, password) == ("inert-user", "inert-password")
            return "OK", []

        def select(self, folder, *, readonly):
            assert folder == "INBOX" and readonly is True
            return "OK", [str(len(messages)).encode()]

        def fetch(self, sequence, query):
            assert query == "(UID RFC822.SIZE)"
            row = messages[int(sequence) - 1]
            size = row.get("size", len(row["raw"]))
            return "OK", [f"{sequence} (UID {100 + int(sequence)} RFC822.SIZE {size})".encode()]

        def uid(self, command, uid, query):
            assert command == "fetch" and "BODY.PEEK[" in query
            amount = int(re.search(r"<0\.(\d+)>", query).group(1))
            sequence = int(uid) - 100
            row = messages[sequence - 1]
            size = row.get("size", len(row["raw"]))
            self.requests.append((sequence, query))
            if row.get("timeout"):
                raise TimeoutError("inert stalled body")
            raw = row["raw"]
            if "HEADER.FIELDS" in query:
                raw = raw.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"
            raw = raw[:amount]
            if row.get("truncate"):
                raw = raw[:-1]
            returned_uid = row.get("returned_uid", uid)
            header = f"{sequence} (UID {returned_uid} RFC822.SIZE {size} BODY[]<0> {{{len(raw)}}}".encode()
            return "OK", [(header, raw), b")"]

        def shutdown(self):
            self.closed = True

    monkeypatch.setattr(inbox_triage, "_BoundedIMAP4SSL", Mailbox)
    return instances


def test_live_inbox_adapter_extracts_html_links_and_continues_past_large_mail(monkeypatch):
    phish = _message('<a href="https://paypal.com.attacker.example/login">paypal.com</a>', html=True)
    messages = [{"raw": _message("ordinary notes")}, {"raw": phish},
                {"raw": _message("unread large body"), "size": 10 * 1024 * 1024}]
    instances = _mailbox(monkeypatch, messages)
    triage = inbox_triage.InboxTriage()

    result = triage.fetch_recent("imap.example", "inert-user", "inert-password", limit=3)

    assert len(result) == 3
    assert triage.score_message(result[0]).verdict == "INCOMPLETE"
    assert result[1]["urls"] == [("https://paypal.com.attacker.example/login", "paypal.com")]
    assert any("Link masks" in reason for reason in triage.score_message(result[1]).reasons)
    assert triage.score_message(result[2]).verdict == "CLEAN"
    assert triage.last_fetch_coverage["complete"] is False
    assert "HEADER.FIELDS" in instances[0].requests[0][1]
    assert all("<0." in query and "RFC822)" not in query for _, query in instances[0].requests)
    assert instances[0].closed


@pytest.mark.parametrize("href,shown,masked", [
    ("https://paypal.com.attacker.example", "paypal.com", True),
    ("https://notpaypal.com", "paypal.com", True),
    ("https://login.paypal.com", "paypal.com", False),
    ("https://PAYPAL.COM./", "https://paypal.com", False),
])
def test_link_comparison_uses_dns_label_boundaries(href, shown, masked):
    value = inbox_triage.InboxTriage().score_message({"urls": [(href, shown)]})
    assert any("Link masks" in reason for reason in value.reasons) is masked


def test_truncated_or_identity_changed_message_never_becomes_clean(monkeypatch):
    instances = _mailbox(monkeypatch, [
        {"raw": _message("ordinary notes")},
        {"raw": _message("ordinary notes"), "truncate": True},
        {"raw": _message("ordinary notes"), "returned_uid": "999"},
    ])
    triage = inbox_triage.InboxTriage()

    result = triage.fetch_recent("imap.example", "inert-user", "inert-password", limit=3)

    assert [triage.score_message(row).verdict for row in result] == ["INCOMPLETE", "INCOMPLETE", "CLEAN"]
    assert instances[0].closed


def test_deadline_failure_preserves_prior_results_and_reports_incomplete(monkeypatch):
    instances = _mailbox(monkeypatch, [
        {"raw": _message("not read")},
        {"raw": _message("stalled"), "timeout": True},
        {"raw": _message("first retained result")},
    ])
    triage = inbox_triage.InboxTriage()

    result = triage.fetch_recent("imap.example", "inert-user", "inert-password", limit=3)

    assert [triage.score_message(row).verdict for row in result] == ["CLEAN", "INCOMPLETE"]
    assert "first retained result" in result[0]["body"]
    assert instances[0].closed


@pytest.mark.parametrize("limit", [0, -1, 51, True])
def test_invalid_message_limit_is_rejected_before_connection(limit):
    with pytest.raises(ValueError, match="1–50"):
        inbox_triage.InboxTriage().fetch_recent("imap.example", "", "", limit=limit)


def _reader(data, monkeypatch, *, deadline=10):
    monkeypatch.setattr(inbox_triage.time, "monotonic", lambda: 0)
    value = object.__new__(inbox_triage._BoundedIMAP4SSL)
    value._deadline = deadline
    value._pending = bytearray()
    value._wire_bytes = 0
    value.sock = SimpleNamespace(settimeout=lambda timeout: None)
    value.file = io.BytesIO(data)
    return value


def test_server_literal_size_is_rejected_before_read(monkeypatch):
    value = _reader(b"unused", monkeypatch)

    with pytest.raises(inbox_triage.imaplib.IMAP4.abort, match="literal byte budget"):
        value.read(inbox_triage._MAX_MESSAGE_BYTES + 2)

    assert value.file.tell() == 0


def test_imap_protocol_prefetch_preserves_literal_and_next_line(monkeypatch):
    value = _reader(b"* 1 FETCH (BODY[] {3}\r\nabc)\r\n", monkeypatch)
    assert value.readline() == b"* 1 FETCH (BODY[] {3}\r\n"
    assert value.read(3) == b"abc"
    assert value.readline() == b")\r\n"


def test_protocol_line_and_total_wire_bytes_have_independent_bounds(monkeypatch):
    value = _reader(b"x" * (inbox_triage._MAX_IMAP_LINE_BYTES + 4096), monkeypatch)
    with pytest.raises(inbox_triage.imaplib.IMAP4.abort, match="line budget"):
        value.readline()
    assert value.file.tell() <= inbox_triage._MAX_IMAP_LINE_BYTES + 4096

    value = _reader(b"x", monkeypatch)
    value._wire_bytes = inbox_triage._MAX_POLL_BYTES + 1024 * 1024
    with pytest.raises(inbox_triage.imaplib.IMAP4.abort, match="protocol byte budget"):
        value.read(1)


def test_imap_deadline_is_rechecked_while_peer_keeps_sending(monkeypatch):
    value = _reader(b"", monkeypatch, deadline=2)
    now = [0.0]

    class SlowBytes:
        def read1(self, _size):
            now[0] += 0.25
            return b"x"

    value.file = SlowBytes()
    monkeypatch.setattr(inbox_triage.time, "monotonic", lambda: now[0])

    with pytest.raises(TimeoutError, match="deadline"):
        value.read(20)

    assert now[0] == 2


def test_text_and_html_link_limits_are_explicitly_incomplete():
    raw = _message("x" * (inbox_triage._MAX_TEXT_CHARS + 1))
    value = inbox_triage._normalize_message(raw, size=len(raw))
    assert len(value["body"]) <= inbox_triage._MAX_TEXT_CHARS
    assert inbox_triage.InboxTriage().score_message(value).verdict == "INCOMPLETE"

    raw = _message('<a href="https://example.com">example.com</a>' * (inbox_triage._MAX_LINKS + 1), html=True)
    value = inbox_triage._normalize_message(raw, size=len(raw))
    assert len(value["urls"]) == inbox_triage._MAX_LINKS
    assert value["coverage"]["complete"] is False


def test_raw_authentication_results_cannot_change_native_mail_score():
    base = _message('<a href="https://paypal.com.attacker.example">paypal.com</a>', html=True)
    original = b"Authentication-Results: mail.example; spf=pass; dkim=pass; dmarc=pass\r\n"
    headers = [b"", original,
               b"Authentication-Results: receiving.example; spf=fail; dkim=none; dmarc=fail\r\n"]
    triage = inbox_triage.InboxTriage()
    results = []
    for header in headers:
        raw = base.replace(original, header)
        message = inbox_triage._normalize_message(raw, size=len(raw))
        verdict = triage.score_message(message)
        assert message["auth"] == {}
        assert message["authentication"]["verified"] is False
        assert "reported" in message["authentication"]
        assert any("authentication is unverified" in reason for reason in verdict.reasons)
        assert any("Link masks" in reason for reason in verdict.reasons)
        results.append(verdict.score)
    assert len(set(results)) == 1


def test_authentication_gap_is_separate_from_content_coverage_and_has_no_upgrade_flag():
    raw = _message("ordinary notes")
    message = inbox_triage._normalize_message(raw, size=len(raw))
    assert message["coverage"]["complete"] is True
    message["authentication"]["verified"] = True  # Untrusted metadata cannot authorize a score input.
    message["auth"] = {"spf": "fail", "dkim": "fail", "dmarc": "fail"}
    verdict = inbox_triage.InboxTriage().score_message(message)
    assert verdict.score == 0 and verdict.verdict == "CLEAN"
    assert any("authentication is unverified" in reason for reason in verdict.reasons)


def test_direct_normalized_auth_inputs_retain_their_heuristic_contract():
    triage = inbox_triage.InboxTriage()
    direct = {"subject": "ordinary notes", "auth": {"spf": "fail", "dkim": "fail", "dmarc": "fail"}}
    assert triage.score_message(direct).score == 50


def test_native_delivery_identity_is_stable_and_binds_uidvalidity_and_raw_content(monkeypatch):
    messages = [{"raw": _message("ordinary notes")}]
    _mailbox(monkeypatch, messages)
    triage = inbox_triage.InboxTriage()
    fetch = lambda: triage.fetch_recent("imap.example", "inert-user", "inert-password", limit=1)[0]
    first = fetch()["message_identity"]
    assert fetch()["message_identity"] == first
    assert triage.last_fetch_coverage["authentication_verified"] is False
    _mailbox(monkeypatch, messages, uidvalidity=b"778")
    assert fetch()["message_identity"] != first
    _mailbox(monkeypatch, [{"raw": _message("different content")}])
    assert fetch()["message_identity"] != first
