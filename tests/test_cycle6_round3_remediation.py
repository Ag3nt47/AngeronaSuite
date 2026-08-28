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
            event.ts,
            event.module,
            int(event.severity),
            event.message,
            '{"pid":42}',
            authority.sign(event),
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
    monkeypatch.setattr(eventbus.BusAuthority, "_key_path", staticmethod(lambda: key_path))
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
    custody = (root / "tools" / "protect-key-custody.ps1").read_text(encoding="utf-8")
    protect_at = launcher.index("protect-key-custody.ps1")
    first_runtime_create = launcher.index('if not exist "%TEMP%" mkdir')
    assert protect_at < first_runtime_create
    assert "[IO.Directory]::CreateDirectory($Path, $security)" in custody
    assert 'foreach ($name in @("bus.key", "shutdown.key"))' in custody


def test_key_custody_uses_valid_separate_icacls_command_forms():
    root = Path(__file__).parents[1]
    custody = (root / "tools" / "protect-key-custody.ps1").read_text(encoding="utf-8")

    # icacls accepts /setowner and DACL mutation as distinct syntaxes. Combining
    # them caused the elevated launcher to abort with "Invalid parameter
    # /setowner" before Angerona could start.
    owner_call = 'Invoke-Icacls @($DataRoot, "/setowner", "*S-1-5-32-544", "/T", "/L", "/Q")'
    reset_call = 'Invoke-Icacls @($children, "/reset", "/T", "/L", "/Q")'
    assert owner_call in custody
    assert reset_call in custody
    assert "/inheritance:r" not in custody
    assert custody.index("Set-Acl -LiteralPath $DataRoot") < custody.index(owner_call)
    assert "Assert-NoReparsePoints $DataRoot" in custody
    migration_at = custody.index("One-time runtime data migration is required.")
    root_check_at = custody.index("Assert-RootNotReparsePoint $DataRoot", migration_at)
    protect_root_at = custody.index("Set-Acl -LiteralPath $DataRoot", root_check_at)
    owner_at = custody.index(owner_call, protect_root_at)
    reset_at = custody.index(reset_call, owner_at)
    descendant_check_at = custody.index("Assert-NoReparsePoints $DataRoot", reset_at)
    assert root_check_at < protect_root_at < owner_at < reset_at < descendant_check_at
    assert '$custodyMarker = Join-Path $DataRoot ".custody-v1"' in custody
    assert "One-time runtime data migration is required." in custody


def test_key_custody_refuses_a_volume_root_before_any_acl_mutation():
    root = Path(__file__).parents[1]
    custody = (root / "tools" / "protect-key-custody.ps1").read_text(encoding="utf-8")

    guard_call = "$DataRoot = Resolve-SafeDataRoot $DataRoot"
    marker_write = '$custodyMarker = Join-Path $DataRoot ".custody-v1"'
    first_mutation = "Set-Acl -LiteralPath $DataRoot"
    assert "[IO.Path]::GetFullPath($Path)" in custody
    assert "[IO.Path]::GetPathRoot($fullPath)" in custody
    assert "Refusing to protect an entire filesystem volume root" in custody
    assert custody.index(guard_call) < custody.index(marker_write)
    assert custody.index(guard_call) < custody.index(first_mutation)


def test_sensitive_key_acl_uses_separate_owner_and_dacl_commands(
    tmp_path,
    monkeypatch,
):
    from angerona.core import hardening

    calls = []

    def completed(command, **_kwargs):
        calls.append(command)
        return type("Result", (), {"returncode": 0})()

    monkeypatch.setattr(hardening.subprocess, "run", completed)
    assert hardening.secure_sensitive_file(tmp_path / "bus.key", required=True)
    assert len(calls) == 2
    assert "/setowner" in calls[0]
    assert "/inheritance:r" not in calls[0]
    assert "/grant:r" not in calls[0]
    assert "/inheritance:r" in calls[1]
    assert "/grant:r" in calls[1]
    assert "/setowner" not in calls[1]
