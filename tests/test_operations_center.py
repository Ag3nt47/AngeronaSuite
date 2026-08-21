from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

from angerona.core.evidence_store import EvidenceEnvelope, EvidenceStore
from angerona.core.operations_center import LocalOperationsCenter


class _Manager:
    def capability_inventory(self):
        return [
            {"name": "Telemetry", "enabled": True, "available": True, "status": "running"},
            {"name": "SOAR", "enabled": True, "available": True, "status": "stopped"},
        ]


def _evidence() -> EvidenceEnvelope:
    return EvidenceEnvelope(
        event_id="evt-local-soc-1",
        observed_at=time.time(),
        category="process_activity",
        activity="observe",
        severity=3,
        message=r"suspicious token=do-not-export at C:\Users\Alice\secret.txt",
        module="Telemetry Scanner",
        attributes={"pid": 42},
    )


def test_local_soc_case_hunt_custody_and_audit(tmp_path: Path) -> None:
    evidence_store = EvidenceStore(tmp_path / "evidence.db")
    event = _evidence()
    evidence_store.append(event)
    service = LocalOperationsCenter(
        tmp_path,
        evidence_store=evidence_store,
        manager=_Manager(),
        config=SimpleNamespace(ui_motion_enabled=False),
        master_key=b"k" * 32,
    )
    try:
        case = service.create_case(
            "Investigate local process", assignee="operator", tags=("endpoint",)
        )
        service.add_case_comment(case.case_id, "Validated against the local baseline")
        result = service.hunt(field="module", value="telemetry", hours=1, limit=10)
        assert result.evidence == (event,)
        reference = service.attach_evidence(case.case_id, result.evidence[0])
        assert service.cases.evidence_counts() == {case.case_id: 1}
        assert service.cases.verify_custody(reference.evidence_id)
        assert [item.kind for item in service.cases.timeline(case.case_id)] == ["comment"]

        summary = service.summary()
        assert summary["local_only"] is True
        assert summary["boundaries"] == {
            "cloud_required": False,
            "remote_shell": False,
            "arbitrary_query_language": False,
            "detection_activation": "trusted-signature-required",
            "raw_evidence_in_case_database": False,
        }
        assert summary["audit"]["ok"] is True
        assert summary["case_status"]["open"] == 1

        export = service.export_case(case.case_id, tmp_path / "case.json")
        payload = export.read_text(encoding="utf-8")
        assert "do-not-export" not in payload
        assert "Alice" not in payload
        assert json.loads(payload)["case"]["title"] == "Investigate local process"
    finally:
        service.close()
        evidence_store.close()


def test_inventory_is_minimized_and_unsigned_detection_cannot_activate(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setattr(
        "angerona.core.operations_center.importlib.metadata.distributions", lambda: ()
    )
    service = LocalOperationsCenter(
        tmp_path, manager=_Manager(), master_key=b"z" * 32
    )
    try:
        snapshot = service.collect_inventory()
        encoded = json.dumps(
            [record.value for record in snapshot.records], default=str
        ).lower()
        assert "agent47" not in encoded
        assert "users\\" not in encoded
        assert {record.name for record in snapshot.records} == {
            "angerona", "angerona_modules", "operating_system"
        }

        invalid = tmp_path / "unsigned.json"
        invalid.write_text("{}", encoding="utf-8")
        report = service.stage_detection(invalid)
        assert report.ok is False
        assert service.audit.health("local")["chain_verified"] is True
    finally:
        service.close()
