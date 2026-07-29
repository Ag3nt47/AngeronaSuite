from __future__ import annotations

import sqlite3
from pathlib import Path

from angerona.core.eventbus import BusAuthority, Event, Severity
from angerona.gui.telemetry_worker import TelemetryWorker


def _event_db(path: Path, authority: BusAuthority) -> None:
    con = sqlite3.connect(path)
    con.execute(
        "CREATE TABLE events (ts REAL, module TEXT, severity INTEGER, "
        "message TEXT, details TEXT, hmac_sig TEXT)"
    )
    event = Event(
        ts=1234.5,
        module="Sensor",
        severity=Severity.HIGH,
        message="authentic",
        details={"pid": 42},
    )
    con.execute(
        "INSERT INTO events VALUES (?,?,?,?,?,?)",
        (
            event.ts, event.module, int(event.severity), event.message,
            '{"pid":42}', authority.sign(event),
        ),
    )
    con.commit()
    con.close()


def test_telemetry_cursor_rejects_tampered_persisted_row_visibly(tmp_path):
    authority = BusAuthority(b"k" * 32)
    db = tmp_path / "events.db"
    _event_db(db, authority)
    con = sqlite3.connect(db)
    con.execute("UPDATE events SET message='forged critical shutdown'")
    con.commit()
    con.close()

    worker = TelemetryWorker(str(db))
    worker._ledger_authority = authority
    rows = worker._read_memc()
    assert len(rows) == 1
    assert rows[0]["module"] == "Ledger Integrity"
    assert rows[0]["severity"] == int(Severity.CRITICAL)
    assert rows[0]["details"]["_ledger_integrity"] == "rejected"
    assert "forged critical shutdown" not in rows[0]["message"]
    assert worker._last_rowid == 1


def test_telemetry_cursor_accepts_valid_hmac_and_keeps_incremental_seek(tmp_path):
    authority = BusAuthority(b"k" * 32)
    db = tmp_path / "events.db"
    _event_db(db, authority)
    worker = TelemetryWorker(str(db))
    worker._ledger_authority = authority
    first = worker._read_memc()
    assert [row["message"] for row in first] == ["authentic"]
    assert worker._read_memc() == []


def test_precreated_known_bus_key_is_quarantined_before_read(tmp_path, monkeypatch):
    import angerona.core.eventbus as eventbus
    import angerona.core.hardening as hardening

    known = b"A" * 32
    key_path = tmp_path / "bus.key"
    key_path.write_text(known.hex(), encoding="ascii")
    monkeypatch.setattr(
        eventbus.BusAuthority, "_key_path", staticmethod(lambda: key_path)
    )
    monkeypatch.setattr(hardening, "key_acl_required", lambda: True)
    monkeypatch.setattr(hardening, "ensure_sensitive_parent", lambda *_a, **_k: None)
    monkeypatch.setattr(hardening, "sensitive_file_is_protected", lambda _p: False)
    monkeypatch.setattr(hardening, "secure_sensitive_file", lambda *_a, **_k: True)

    authority = eventbus.BusAuthority.load()
    probe = Event(module="probe", message="probe")
    assert authority.sign(probe) != BusAuthority(known).sign(probe)
    assert list(tmp_path.glob("bus.key.rejected-*"))


def test_launcher_protects_parent_before_runtime_key_access():
    root = Path(__file__).parents[1]
    launcher = (root / "start-angerona.bat").read_text(encoding="utf-8")
    custody = (root / "tools" / "protect-key-custody.ps1").read_text(
        encoding="utf-8"
    )
    protect_at = launcher.index("protect-key-custody.ps1")
    first_runtime_create = launcher.index('if not exist "%TEMP%" mkdir')
    assert protect_at < first_runtime_create
    assert "[IO.Directory]::CreateDirectory($Path, $security)" in custody
    assert 'foreach ($name in @("bus.key", "shutdown.key"))' in custody
