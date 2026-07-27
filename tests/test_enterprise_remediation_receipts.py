from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from angerona.core import report_attest
from angerona.core.remediation_log import RemediationLog


def _install_test_key(tmp_path: Path, monkeypatch) -> Path:
    key = tmp_path / "bus.key"
    key.write_text(bytes(range(32)).hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key)
    return key


def test_remediation_receipts_are_signed_chained_and_record_bound(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _install_test_key(tmp_path, monkeypatch)
    ledger = RemediationLog(tmp_path / "flight-recorder.db")
    ledger.log(
        trigger="test",
        mitre="T1055",
        action_key="quarantine_file",
        action_title="Quarantine",
        outcome="applied",
        verified=1,
        record={"target": "sample", "ok": True},
    )
    ledger.log(
        trigger="test",
        mitre="T1071",
        action_key="network_isolation",
        action_title="Network isolation",
        outcome="dry_run",
        verified=-1,
        record={"target": "203.0.113.1"},
    )

    status = ledger.verify_receipt_chain()
    rows = ledger.recent(2)

    assert status["valid"] is True
    assert status["verified_receipts"] == 2
    assert len(status["head_hash"]) == 64
    assert all(row["receipt_authenticity"] is True for row in rows)
    assert all(str(row["receipt_id"]).startswith("RCP-") for row in rows)


def test_action_record_tamper_breaks_proof_chain(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _install_test_key(tmp_path, monkeypatch)
    ledger = RemediationLog(tmp_path / "flight-recorder.db")
    ledger.log(
        trigger="test",
        action_key="registry_hardening",
        outcome="applied",
        verified=1,
        record={"before": 0, "after": 1},
    )
    with ledger._lock:
        ledger._db.execute(
            "UPDATE remediation_log SET record_json = ? WHERE id = 1",
            (json.dumps({"before": 0, "after": 0}),),
        )
        ledger._db.commit()

    status = ledger.verify_receipt_chain()
    assert status["valid"] is False
    assert status["broken_id"] == 1
    assert "record digest" in status["reason"]


def test_applied_without_independent_verification_is_not_valid_proof(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _install_test_key(tmp_path, monkeypatch)
    ledger = RemediationLog(tmp_path / "flight-recorder.db")
    ledger.log(
        trigger="test",
        action_key="unsafe_claim",
        outcome="applied",
        verified=-1,
        record={"return_code": 0},
    )
    status = ledger.verify_receipt_chain()
    assert status["valid"] is False
    assert "lacks a passed postcondition" in status["reason"]


def test_existing_remediation_schema_is_migrated_additively(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _install_test_key(tmp_path, monkeypatch)
    db_path = tmp_path / "legacy.db"
    db = sqlite3.connect(db_path)
    db.execute(
        """
        CREATE TABLE remediation_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            trigger TEXT NOT NULL DEFAULT '',
            mitre TEXT NOT NULL DEFAULT '-',
            action_key TEXT NOT NULL DEFAULT 'none',
            action_title TEXT NOT NULL DEFAULT '',
            outcome TEXT NOT NULL DEFAULT 'dry_run',
            verified INTEGER NOT NULL DEFAULT -1,
            host_level INTEGER NOT NULL DEFAULT 0,
            record_json TEXT
        )
        """
    )
    db.execute(
        """
        INSERT INTO remediation_log
          (ts, trigger, mitre, action_key, action_title, outcome,
           verified, host_level, record_json)
        VALUES (1.0, 'legacy', '-', 'none', '', 'dry_run', -1, 0, NULL)
        """
    )
    db.commit()
    db.close()

    ledger = RemediationLog(db_path)
    ledger.log(trigger="new", action_key="none", outcome="dry_run")
    status = ledger.verify_receipt_chain()

    assert status["valid"] is True
    assert status["legacy_rows"] == 1
    assert status["verified_receipts"] == 1
