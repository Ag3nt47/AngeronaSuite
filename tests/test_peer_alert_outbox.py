"""Peer-watchdog alert outbox: core-death alerts survive the core's death."""
from __future__ import annotations

import json
import secrets
from pathlib import Path

from angerona.resilience import peer_alerts
from angerona.resilience.peer_alerts import PeerAlertOutbox, PeerAlertReader


def _pair(tmp_path: Path, key: bytes | None = None):
    key = key or secrets.token_bytes(32)
    path = tmp_path / "peer_alerts.jsonl"
    return key, path, PeerAlertOutbox(key_raw=key, path=path)


def test_core_death_alert_is_delivered_exactly_once_across_reader_restarts(tmp_path):
    key, path, outbox = _pair(tmp_path)
    callback = outbox.supervisor_callback()
    callback("HIGH", "Component 'core' stopped unexpectedly", {"component": "core", "pid": 4242})
    callback("INFO", "routine", {})  # Below MEDIUM: never persisted.
    first = PeerAlertReader(key_raw=key, path=path).drain()
    assert [r["msg"] for r in first] == ["Component 'core' stopped unexpectedly"]
    assert first[0]["details"] == {"component": "core", "pid": 4242}
    assert PeerAlertReader(key_raw=key, path=path).drain() == []
    callback("CRITICAL", "restart pressure", {"restarts_1h": 9})
    assert [r["msg"] for r in PeerAlertReader(key_raw=key, path=path).drain()] == ["restart pressure"]


def test_forged_edited_and_wrong_key_records_are_reported_never_trusted(tmp_path):
    key, path, outbox = _pair(tmp_path)
    outbox.append("HIGH", "genuine")
    lines = path.read_bytes().splitlines()
    edited = json.loads(lines[0])
    edited["msg"] = "attacker text"
    path.write_bytes(json.dumps(edited).encode() + b"\n" + b'{"msg":"forged"}\n')
    drained = PeerAlertReader(key_raw=key, path=path).drain()
    assert [r["id"] for r in drained] == ["tamper"]
    assert drained[0]["level"] == "HIGH"
    assert drained[0]["details"]["unauthenticated_records"] == 2
    other = PeerAlertOutbox(key_raw=secrets.token_bytes(32), path=tmp_path / "other.jsonl")
    other.append("HIGH", "foreign key")
    foreign = PeerAlertReader(key_raw=key, path=tmp_path / "other.jsonl").drain()
    assert [r["id"] for r in foreign] == ["tamper"]


def test_outbox_is_bounded_and_rotates_without_losing_chain_verification(tmp_path, monkeypatch):
    monkeypatch.setattr(peer_alerts, "_MAX_FILE", 2048)
    key, path, outbox = _pair(tmp_path)
    for index in range(40):
        outbox.append("MEDIUM", f"event {index}", {"blob": "x" * 200})
    assert path.stat().st_size <= 2048
    assert path.with_suffix(".jsonl.1").exists()
    drained = PeerAlertReader(key_raw=key, path=path).drain()
    assert drained and all(r["id"] != "tamper" for r in drained)
    assert drained[-1]["msg"] == "event 39"


def test_oversized_details_are_bounded_not_dropped(tmp_path):
    key, path, outbox = _pair(tmp_path)
    record = outbox.append("HIGH", "m" * 5000, {f"k{i}": "v" * 1000 for i in range(40)})
    assert len(record["msg"]) == 512 and len(record["details"]) <= 24
    assert all(len(line) <= 4096 for line in path.read_bytes().splitlines())
    assert PeerAlertReader(key_raw=key, path=path).drain()[0]["msg"] == "m" * 512


def test_self_test_passes():
    ok, detail = peer_alerts.self_test()
    assert ok, detail


def test_peer_watchdog_wires_supervisor_events_to_the_outbox():
    source = (Path(__file__).resolve().parents[1] / "src" / "angerona" / "resilience" / "watchdog.py").read_text(encoding="utf-8")
    assert "PeerAlertOutbox(\"peer-watchdog\").supervisor_callback()" in source
    assert "on_event=forward_event" in source
    assert "hunter.on_supervisor_event(level, msg, details)" in source
