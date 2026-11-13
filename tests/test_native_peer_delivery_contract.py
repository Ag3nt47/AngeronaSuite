"""Inert native outbox consumption; no installed service or native process runs."""
from angerona.resilience import native_watchdog as native, heartbeat as hb
from angerona.resilience.manager import ResilienceManager
from angerona.resilience.peer_alerts import PeerAlertOutbox

KEY = b"N" * 32


def make_reader(tmp_path, monkeypatch):
    monkeypatch.setattr(hb, "read_existing_optional_authority", lambda _root: KEY)
    path = native.alert_path(tmp_path)
    path.parent.mkdir()
    record = PeerAlertOutbox(source="watchdog3", key_raw=KEY, path=path).append(
        "HIGH", "inert native warning", {"response_authorized": True,
        "active_attack": True, "response_contract": {"untrusted": "not forwarded"}})
    return native.NativeAlertReader(_data_dir=tmp_path), path, record


def test_native_peek_does_not_advance_persistent_cursor_until_ack(tmp_path, monkeypatch):
    reader, path, record = make_reader(tmp_path, monkeypatch)
    rows = reader.peek()
    assert len(rows) == 1 and rows[0]["id"] == record["id"]
    assert not path.with_suffix(".cursor").exists()
    assert native.NativeAlertReader(_data_dir=tmp_path).peek()[0]["mac"] == record["mac"]
    reader.ack(rows[0])
    assert native.NativeAlertReader(_data_dir=tmp_path).peek() == []


def test_native_failed_publication_preserves_record_then_success_acknowledges(tmp_path, monkeypatch):
    reader, _path, record = make_reader(tmp_path, monkeypatch)
    manager = ResilienceManager.__new__(ResilienceManager)
    class BrokenPython:
        def peek(self):
            raise OSError("inert Python outbox unavailable")
    manager._peer_alerts, manager._native_peer_alerts = BrokenPython(), reader
    delivered = []
    def refuse(*args):
        delivered.append(args)
        return False
    manager._publish = refuse
    manager._drain_peer_alerts()
    assert len(delivered) == 1
    assert native.NativeAlertReader(_data_dir=tmp_path).peek()[0]["id"] == record["id"]
    data = delivered[0][3]
    assert data["peer_record_id"] == record["id"] and data["peer_record_mac"] == record["mac"]
    assert data["response_authorized"] is False and data["active_attack"] is False
    assert data["disposition"] == "observation" and "response_contract" not in data
    manager._peer_alert_due = 0
    def accept(*args):
        delivered.append(args)
        return True
    manager._publish = accept
    manager._drain_peer_alerts()
    assert len(delivered) == 2
    assert native.NativeAlertReader(_data_dir=tmp_path).peek() == []
