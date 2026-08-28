from __future__ import annotations

from types import SimpleNamespace

import pytest

from angerona.core.attack_tracker import (
    ATTACK_CATALOG_SCOPE,
    ATTACK_VERSION,
    TACTIC_ORDER,
    AttackTracker,
    _TID_TO_META,
)
from angerona.core.eventbus import Event, Severity
from angerona.core.ocsf_export import to_finding, validate_finding_shape
from angerona.core.sigma_engine import SigmaSet, load_rules, match


pytest.importorskip("yaml")


def test_attack_catalog_uses_enterprise_v19_2_tactic_vocabulary() -> None:
    assert ATTACK_VERSION == "19.2"
    assert ATTACK_CATALOG_SCOPE == "curated-enterprise-endpoint"
    assert TACTIC_ORDER == [
        ("TA0043", "Reconnaissance"),
        ("TA0042", "Resource Development"),
        ("TA0001", "Initial Access"),
        ("TA0002", "Execution"),
        ("TA0003", "Persistence"),
        ("TA0004", "Privilege Escalation"),
        ("TA0005", "Stealth"),
        ("TA0112", "Defense Impairment"),
        ("TA0006", "Credential Access"),
        ("TA0007", "Discovery"),
        ("TA0008", "Lateral Movement"),
        ("TA0009", "Collection"),
        ("TA0011", "Command and Control"),
        ("TA0010", "Exfiltration"),
        ("TA0040", "Impact"),
    ]
    assert _TID_TO_META["T1685"][1] == "TA0112"
    assert _TID_TO_META["T1686"][1] == "TA0112"
    assert _TID_TO_META["T1112"][1] == "TA0112"
    assert "T1562.001" not in _TID_TO_META
    assert "T1070.001" not in _TID_TO_META


def test_tracker_normalizes_rolling_upgrade_legacy_ids_to_v19() -> None:
    tracker = AttackTracker()
    tracker.on_event(SimpleNamespace(
        mitre_tags=["T1562.001", "T1562.002", "T1070.001"], id="evt-1"
    ))

    snapshot = tracker.snapshot()

    assert snapshot["attack_version"] == "19.2"
    assert snapshot["matrix"]["T1685"]["count"] == 1
    assert snapshot["matrix"]["T1685.001"]["count"] == 1
    assert snapshot["matrix"]["T1685.005"]["count"] == 1


def test_navigator_export_declares_current_exact_versions() -> None:
    pytest.importorskip("PySide6")
    from angerona.gui.attack_heatmap import build_navigator_layer

    layer = build_navigator_layer({
        "matrix": {
            "T1685": {"count": 3, "heat": 0.42, "last_seen": "2026-08-27T12:00:00"},
            "T1059.001": {"count": 0, "heat": 0.0, "last_seen": None},
            "T9999": {"count": 99, "heat": 1.0, "last_seen": "unmapped"},
        }
    }, exported_at="2026-08-27T12:34:56")

    assert layer["versions"] == {
        "attack": "19.2",
        "navigator": "5.3.2",
        "layer": "4.5",
    }
    assert layer["domain"] == "enterprise-attack"
    assert layer["techniques"] == [{
        "techniqueID": "T1685",
        "score": 42,
        "comment": "hits=3 last=2026-08-27T12:00:00",
        "enabled": True,
        "showSubtechniques": False,
    }]
    assert {row["name"]: row["value"] for row in layer["metadata"]} == {
        "ATT&CK content": "19.2",
        "Catalog scope": "curated-enterprise-endpoint",
    }
    assert "not a complete Enterprise ATT&CK coverage statement" in layer["description"]


def test_ocsf_observables_have_v1_8_type_ids_and_resolving_evidence_paths() -> None:
    finding = to_finding(Event(
        "Process Monitor",
        "Suspicious process opened a remote endpoint",
        Severity.HIGH,
        details={
            "pid": 4242,
            "image": r"C:\Windows\System32\sample.exe",
            "dest_ip": "203.0.113.9:443",
            "path": r"C:\Temp\payload.bin",
            "username": "analyst",
            "mitre": ["T1071", "not-a-technique"],
        },
    ))

    ok, errors = validate_finding_shape(finding)

    assert ok, errors
    by_name = {item["name"]: item for item in finding["observables"]}
    assert by_name["evidences[0].process"]["type_id"] == 25
    assert by_name["evidences[0].process.pid"]["type_id"] == 15
    assert by_name["evidences[0].process.name"]["type_id"] == 9
    assert by_name["evidences[0].process.name"]["value"] == "sample.exe"
    assert by_name["evidences[0].process.file.path"]["type_id"] == 45
    assert by_name["evidences[0].dst_endpoint.ip"]["type_id"] == 2
    assert by_name["evidences[0].file.path"]["type_id"] == 45
    assert by_name["evidences[0].user"]["type_id"] == 21
    assert by_name["evidences[0].user.name"]["type_id"] == 4
    assert by_name["evidences[0].user.name"]["value"] == "analyst"
    assert finding["unmapped"]["ocsf_mapping"]["scope"] == "constrained-preview"
    assert finding["attacks"] == [{"technique": {"uid": "T1071"}}]


def test_ocsf_validator_refuses_legacy_nonresolving_observable_shape() -> None:
    finding = to_finding(Event("Detector", "evidence", Severity.MEDIUM))
    finding["observables"].append({
        "name": "process.pid", "type": "Process", "value": "42"
    })

    ok, errors = validate_finding_shape(finding)

    assert not ok
    assert any("type_id" in error for error in errors)
    assert any("does not resolve" in error for error in errors)


def test_sigma_import_returns_explicit_admission_receipt() -> None:
    result = load_rules("""
title: Exact supported subset
detection:
  selection:
    image|endswith: powershell.exe
  condition: selection
""")

    assert len(result) == 1
    assert result.receipt.accepted is True
    assert result.receipt.code == "ADMITTED"
    assert result.receipt.admitted_count == 1
    assert "constrained Sigma" in result.receipt.subset


@pytest.mark.parametrize(
    ("rule", "code"),
    (
        ("""
title: Logsource cannot be ignored
logsource:
  category: process_creation
detection:
  selection:
    image: powershell.exe
  condition: selection
""", "UNSUPPORTED_LOGSOURCE"),
        ("""
title: Unsupported chained modifier
detection:
  selection:
    image|contains|all: powershell
  condition: selection
""", "UNSUPPORTED_SELECTION"),
        ("""
title: Unsupported standard wildcard
detection:
  selection:
    image: '*powershell.exe'
  condition: selection
""", "UNSUPPORTED_SELECTION"),
        ("""
title: Unsupported correlation
correlation:
  type: event_count
detection:
  selection:
    image: powershell.exe
  condition: selection
""", "UNSUPPORTED_CORRELATION"),
    ),
)
def test_sigma_unsupported_rules_fail_with_bounded_reason(rule: str, code: str) -> None:
    result = load_rules(rule)

    assert result == []
    assert result.receipt.accepted is False
    assert result.receipt.code == code
    assert result.receipt.rejected_count == 1
    assert 0 < len(result.receipt.reason) <= 256


def test_sigma_batch_is_atomic_and_refused_rule_cannot_enter_set() -> None:
    rules = SigmaSet()
    count = rules.add_yaml("""
title: Supported first document
detection:
  selection:
    image: cmd.exe
  condition: selection
---
title: Unsupported second document
logsource:
  category: process_creation
detection:
  selection:
    image: cmd.exe
  condition: selection
""")

    assert count == 0
    assert rules.rules == []
    assert rules.last_admission.accepted is False
    assert rules.last_admission.code == "UNSUPPORTED_LOGSOURCE"


def test_sigma_match_refuses_unsupported_rules_and_protects_trusted_fields() -> None:
    event = Event(
        "Process Monitor", "spawn", Severity.HIGH,
        details={"module": "forged", "image": "PowerShell.EXE"},
    )
    supported = {
        "detection": {
            "selection": {"module": "Process Monitor"},
            "condition": "selection",
        }
    }
    unsupported = {
        "detection": {
            "selection": {"image": "*.exe"},
            "condition": "selection",
        }
    }

    assert match(supported, event)
    assert not match(unsupported, event)
