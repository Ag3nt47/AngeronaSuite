from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from angerona.resilience import manager, peer_alerts


def _pair(tmp_path):
    key, path = b"p" * 32, tmp_path / "peer_alerts.jsonl"
    writer = peer_alerts.PeerAlertOutbox(key_raw=key, path=path)
    reader = peer_alerts.PeerAlertReader(key_raw=key, path=path)
    return writer, reader, key, path


def test_peek_does_not_consume_an_undelivered_alert(tmp_path):
    writer, reader, key, path = _pair(tmp_path)
    original = writer.append("HIGH", "core unexpectedly exited", {"component": "core"})
    [record] = reader.peek()
    assert record == original
    assert not path.with_suffix(".cursor").exists()
    assert peer_alerts.PeerAlertReader(key_raw=key, path=path).peek() == [original]
    reader.ack(record)
    assert peer_alerts.PeerAlertReader(key_raw=key, path=path).peek() == []


def test_manager_acknowledges_only_after_publish_and_preserves_original(monkeypatch, tmp_path):
    writer, reader, key, path = _pair(tmp_path)
    original = writer.append("HIGH", "core exited", {"active_attack": True, "response_authorized": True,
                                                     "response_contract": {"untrusted": "annotation"}})
    retained = deepcopy(original)
    clock, delivered = [100.0], []
    monkeypatch.setattr(manager.time, "monotonic", lambda: clock[0])
    instance = manager.ResilienceManager.__new__(manager.ResilienceManager)
    instance._peer_alerts = reader
    instance._peer_alert_due = 0.0

    def unavailable(_event):
        raise RuntimeError("fixture EventBus unavailable")

    instance.bus = SimpleNamespace(publish=unavailable)
    instance._drain_peer_alerts()
    assert not path.with_suffix(".cursor").exists()
    assert reader.peek() == [original]
    instance.bus = SimpleNamespace(publish=delivered.append)
    clock[0] += 3
    instance._drain_peer_alerts()
    assert len(delivered) == 1
    details = delivered[0].details
    assert details["peer_record_id"] == original["id"] and details["peer_record_mac"] == original["mac"]
    assert details["response_authorized"] is False and details["active_attack"] is False
    assert details["disposition"] == "observation" and "response_contract" not in details
    assert original == retained  # Authenticated source record was never edited.
    assert peer_alerts.PeerAlertReader(key_raw=key, path=path).peek() == []


def test_failed_ack_keeps_exact_original_pending(monkeypatch, tmp_path):
    writer, reader, _key, _path = _pair(tmp_path)
    writer.append("HIGH", "pending source evidence")
    [record] = reader.peek()
    store = reader._store_cursor

    def unavailable(_mac):
        raise OSError("fixture cursor unavailable")

    monkeypatch.setattr(reader, "_store_cursor", unavailable)
    try:
        reader.ack(record)
    except OSError:
        pass
    else:
        raise AssertionError("failed storage unexpectedly acknowledged")
    assert reader.peek() == [record]
    monkeypatch.setattr(reader, "_store_cursor", store)
    reader.ack(record)
    assert reader.peek() == []


def test_reordered_genesis_cannot_replay_old_signed_rows(tmp_path):
    writer, reader, _key, path = _pair(tmp_path)
    first = writer.append("HIGH", "first")
    assert reader.drain() == [first]
    writer.append("HIGH", "second")
    original = path.read_bytes()
    lines = original.splitlines()
    path.write_bytes(lines[1] + b"\n" + lines[0] + b"\n")
    records = reader.drain()
    assert any(record["id"] == "tamper" for record in records)
    assert all(record.get("mac") is None for record in records)
    path.write_bytes(original)
    assert reader.peek() == []


def test_rotation_cursor_loss_is_explicit_and_does_not_replay_retention(monkeypatch, tmp_path):
    monkeypatch.setattr(peer_alerts, "_MAX_FILE", 1100)
    writer, reader, _key, _path = _pair(tmp_path)
    writer.append("HIGH", "already acknowledged")
    reader.drain()
    for index in range(15):
        writer.append("HIGH", f"retained event {index}")
    records = reader.drain()
    assert [record["id"] for record in records] == ["gap"]
    assert "acknowledged-cursor-not-retained" in records[0]["details"]["coverage_gaps"]
    assert records[0]["details"]["complete"] is False
    writer.append("HIGH", "fresh after gap acknowledgement")
    assert [record["msg"] for record in reader.drain()] == ["fresh after gap acknowledgement"]


def test_nested_and_oversized_input_stays_bounded_and_reports_gap(monkeypatch, tmp_path):
    writer, _reader, key, path = _pair(tmp_path)
    path.write_bytes(b"[" * 1800 + b"]" * 1800 + b"\n")
    peer_alerts.PeerAlertOutbox(key_raw=key, path=path)  # Malformed tail cannot disable the writer.
    reader = peer_alerts.PeerAlertReader(key_raw=key, path=path)
    assert reader.drain()[0]["id"] == "tamper"
    path.write_bytes(b"x" * (peer_alerts._MAX_LINE + 1) + b"\n")
    reader = peer_alerts.PeerAlertReader(key_raw=key, path=path)
    assert "record-byte-budget" in reader.drain()[0]["details"]["coverage_gaps"]
    path.with_suffix(".cursor").write_bytes(b"x" * (peer_alerts._MAX_CURSOR + 1))
    path.write_bytes(b"")
    record = writer.append("HIGH", "unanchored after invalid cursor")
    reader = peer_alerts.PeerAlertReader(key_raw=key, path=path)
    records = reader.peek()
    assert all(row.get("mac") is None for row in records)
    assert any("acknowledged-cursor-not-retained" in row["details"]["coverage_gaps"] for row in records)
    assert record["msg"] == "unanchored after invalid cursor"


def test_pending_page_including_diagnostic_obeys_budget(monkeypatch, tmp_path):
    monkeypatch.setattr(peer_alerts, "_MAX_DRAIN", 2)
    writer, reader, _key, path = _pair(tmp_path)
    for index in range(5):
        writer.append("HIGH", f"event {index}")
    with path.open("ab") as stream:
        stream.write(b'{"forged":true}\n')
    first = reader.drain()
    assert len(first) == 2 and first[0]["id"] == "tamper"
    remaining = reader.drain() + reader.drain()
    assert len(remaining) == 4
    assert len({row["mac"] for row in first + remaining if "mac" in row}) == 5


def test_rotated_file_boundary_cannot_restart_with_an_older_signed_genesis(tmp_path):
    writer, reader, _key, path = _pair(tmp_path)
    writer.append("HIGH", "old genesis")
    writer.append("HIGH", "current first")
    writer.append("HIGH", "current last")
    reader.drain()
    lines = path.read_bytes().splitlines()
    path.with_suffix(".jsonl.1").write_bytes(b"\n".join(lines[1:]) + b"\n")
    path.write_bytes(lines[0] + b"\n")
    records = reader.peek()
    assert any(record["id"] == "tamper" for record in records)
    assert all(record.get("mac") is None for record in records)


def test_writer_restart_between_rotation_and_append_preserves_predecessor(tmp_path):
    writer, reader, key, path = _pair(tmp_path)
    writer.append("HIGH", "before rotation")
    reader.drain()
    path.replace(path.with_suffix(".jsonl.1"))
    replacement = peer_alerts.PeerAlertOutbox(key_raw=key, path=path)
    replacement.append("HIGH", "after writer restart")
    assert [row["msg"] for row in reader.drain()] == ["after writer restart"]


@pytest.mark.parametrize("restart_reader", [False, True])
def test_signed_immediate_successor_anchors_a_rotated_away_cursor(tmp_path, restart_reader):
    writer, reader, key, path = _pair(tmp_path)
    writer.append("HIGH", "acknowledged predecessor")
    reader.drain()
    successor = writer.append("HIGH", "retained immediate successor")
    path.write_bytes(path.read_bytes().splitlines()[-1] + b"\n")
    if restart_reader:
        reader = peer_alerts.PeerAlertReader(key_raw=key, path=path)
    assert reader.drain() == [successor]
    assert reader.drain() == []


def test_missing_intermediate_record_remains_an_explicit_gap(tmp_path):
    writer, reader, _key, path = _pair(tmp_path)
    writer.append("HIGH", "acknowledged predecessor")
    reader.drain()
    writer.append("HIGH", "missing intermediate")
    writer.append("HIGH", "retained suffix without immediate cursor predecessor")
    path.write_bytes(path.read_bytes().splitlines()[-1] + b"\n")
    records = reader.drain()
    assert [record["id"] for record in records] == ["gap"]
    assert "acknowledged-cursor-not-retained" in records[0]["details"]["coverage_gaps"]
