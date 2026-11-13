"""The native Go protocol must interoperate with the actual Python codecs."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from angerona.resilience.heartbeat import HeartbeatReader
from angerona.resilience.peer_alerts import PeerAlertReader


def test_go_records_verify_with_the_real_python_heartbeat_and_alert_readers(tmp_path):
    go = shutil.which("go")
    if go is None:
        pytest.skip("Go compiler is required for native-to-Python interoperability")
    root = Path(__file__).resolve().parents[1]
    environment = dict(os.environ)
    environment.update(ANGERONA_WATCHDOG3_INTEROP_EXPORT="1", GOTOOLCHAIN="local", GOWORK="off")
    result = subprocess.run([go, "test", "-mod=readonly", "-run", "^TestExportPythonInterop$",
        "-count=1", "-v", "."], cwd=root / "frz" / "watchdog3", env=environment,
        stdin=subprocess.DEVNULL, capture_output=True, timeout=90,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    assert result.returncode == 0, result.stderr.decode(errors="replace")[:2000]
    assert len(result.stdout) <= 16 * 1024, "Native fixture output exceeded its capture bound"
    marker = b"WATCHDOG3_INTEROP "
    lines = [line[len(marker):] for line in result.stdout.splitlines() if line.startswith(marker)]
    assert len(lines) == 1, "Native protocol fixture did not emit exactly one exported record"
    payload = json.loads(base64.b64decode(lines[0], validate=True))
    assert set(payload) == {"heartbeat_hex", "alert_line_base64"}
    key = bytes(range(32))
    heartbeat = tmp_path / "core.hb"
    heartbeat.write_bytes(bytes.fromhex(payload["heartbeat_hex"]))
    reader = HeartbeatReader("core", path=heartbeat, key_raw=key)
    record = reader.read()
    assert reader.authentication_status(record=record) == "authenticated"
    assert record["pid"] == 1234 and record["counter"] == 42
    assert record["ts_ns"] == 1_700_000_000_125_000_000
    assert HeartbeatReader("watchdog", path=heartbeat, key_raw=key).authentication_status() == "invalid"
    alert = tmp_path / "watchdog3-peer-alerts.jsonl"
    alert.write_bytes(base64.b64decode(payload["alert_line_base64"], validate=True))
    outbox = PeerAlertReader(key_raw=key, path=alert)
    records = outbox.drain()
    assert len(records) == 1 and records[0]["source"] == "watchdog3"
    assert records[0]["level"] == "HIGH" and records[0]["id"] != "tamper"
    assert outbox.drain() == []
    with alert.open("ab") as stream:
        stream.write(b'{"forged":true}\n')
    assert outbox.drain()[-1]["id"] == "tamper"
