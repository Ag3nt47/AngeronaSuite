import json

import pytest

from angerona.core.admin_audit import AdminAuditEntry, AdminAuditLedger
from angerona.core.authorization import (
    AuthorizationPolicy,
    AuthorizationRequest,
    Principal,
    PrincipalKind,
    Role,
    RoleBinding,
)


KEY = b"a" * 32


def _entry(record_id: str, tenant: str, stamp: float) -> AdminAuditEntry:
    return AdminAuditEntry(
        record_id=record_id,
        tenant_id=tenant,
        actor_id="operator-one",
        session_id="session-one",
        source="test-suite",
        action="policy.update",
        target="policy-one",
        decision="allowed",
        approval_id="approval-one",
        result="success",
        correlation_id=f"correlation:{record_id}",
        timestamp=stamp,
        before={"state": "old"},
        after={"state": "new"},
        details={"path": r"C:\Users\Alice\secret.txt"},
    )


def test_interleaved_tenants_have_independently_verifiable_exports(tmp_path):
    ledger = AdminAuditLedger(tmp_path / "audit.db", KEY, clock=lambda: 50)
    ledger.append(_entry("record-a1", "tenant-a", 1))
    ledger.append(_entry("record-b1", "tenant-b", 2))
    ledger.append(_entry("record-a2", "tenant-a", 3))
    assert ledger.verify()

    exported = ledger.export("tenant-a")
    assert ledger.verify_export(exported, "tenant-a")
    assert not ledger.verify_export(exported, "tenant-b")
    value = json.loads(exported)
    assert [item["sequence"] for item in value["records"]] == [1, 3]
    assert all(
        item["entry"]["tenant_id"] == "tenant-a"
        for item in value["records"]
    )

    value["records"][0]["entry"]["result"] = "failure"
    assert not ledger.verify_export(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode(),
        "tenant-a",
    )
    ledger.close()


def test_database_triggers_and_hmac_chain_detect_mutation(tmp_path):
    ledger = AdminAuditLedger(tmp_path / "audit.db", KEY)
    record = ledger.append(_entry("record-one", "tenant-a", 1))
    with pytest.raises(Exception, match="append-only"):
        ledger._db.execute(
            "UPDATE admin_audit SET action='other' WHERE sequence=?",
            (record.sequence,),
        )
    ledger._db.execute("DROP TRIGGER admin_audit_no_update")
    ledger._db.execute(
        "UPDATE admin_audit SET entry_json=? WHERE sequence=?",
        (json.dumps({"injected": True}), record.sequence),
    )
    assert not ledger.verify()
    ledger.close()


def test_authorization_audit_uses_real_tenant_and_collision_safe_identity(tmp_path):
    ledger = AdminAuditLedger(tmp_path / "audit.db", KEY)
    policy = AuthorizationPolicy(
        (Principal("operator-one", PrincipalKind.HUMAN),),
        (Role("reader", ("fleet.device.read",)),),
        (RoleBinding("operator-one", "reader", "fleet/tenant-a"),),
        KEY,
        audit_sink=ledger.record_authorization,
    )
    decision = policy.decide(AuthorizationRequest(
        "request-one", "operator-one", "fleet.device.read",
        "fleet/tenant-a", "device-one",
    ), now=10)
    rows = ledger.query("tenant-a")
    assert decision.allowed and len(rows) == 1
    assert rows[0].entry.tenant_id == "tenant-a"
    assert rows[0].entry.details["request_digest"] == decision.request_digest

    second_policy = AuthorizationPolicy(
        (Principal("operator-one", PrincipalKind.HUMAN),),
        (Role("reader", ("fleet.device.read",)),),
        (RoleBinding("operator-one", "reader", "fleet/tenant-b"),),
        KEY,
        audit_sink=ledger.record_authorization,
    )
    second = second_policy.decide(AuthorizationRequest(
        "request-one", "operator-one", "fleet.device.read",
        "fleet/tenant-b", "device-one",
    ), now=10)
    assert second.allowed
    assert len(ledger.query("tenant-a")) == 1
    assert len(ledger.query("tenant-b")) == 1
    ledger.close()


def test_audit_sink_failure_prevents_authorization_completion():
    def unavailable(_decision):
        raise RuntimeError("audit unavailable")

    policy = AuthorizationPolicy(
        (Principal("operator-one", PrincipalKind.HUMAN),),
        (Role("reader", ("fleet.device.read",)),),
        (RoleBinding("operator-one", "reader", "fleet/tenant-a"),),
        KEY,
        audit_sink=unavailable,
    )
    with pytest.raises(RuntimeError, match="audit unavailable"):
        policy.decide(AuthorizationRequest(
            "request-one", "operator-one", "fleet.device.read",
            "fleet/tenant-a",
        ), now=1)
