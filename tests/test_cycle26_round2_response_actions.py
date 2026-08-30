from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import remediation_log
from angerona.modules import remediation_actions as actions


class _AuditLog:
    def __init__(self) -> None:
        self.entries: list[dict] = []

    def log(self, **entry):
        self.entries.append(entry)
        return {"receipt_id": f"proof-{len(self.entries)}"}


@pytest.mark.parametrize(
    ("action_type", "extra"),
    [
        (actions.QuarantineFileAction, {}),
        (actions.AVDetectionQuarantineAction, {"threat_name": "test threat"}),
    ],
)
def test_legacy_path_quarantine_is_inert_even_when_called_directly(
    action_type, extra: dict, tmp_path: Path
) -> None:
    source = tmp_path / "detected.bin"
    source.write_bytes(b"original-object")
    quarantine = tmp_path / "quarantine"
    weakness = {"path": str(source), **extra}
    action = action_type()

    assert all(not isinstance(item, action_type) for item in actions.ACTIONS)
    assert any(isinstance(item, action_type) for item in actions.PROPOSAL_ONLY_ACTIONS)
    result = action.apply(weakness, quarantine)

    assert result["ok"] is False
    assert result["proposal_only"] is True
    assert result["executable"] is False
    assert action.verify(weakness, result) is False
    assert source.read_bytes() == b"original-object"
    assert not quarantine.exists()


def test_defender_deny_classification_dominates_every_generic_target(
    monkeypatch, tmp_path: Path
) -> None:
    audit = _AuditLog()
    monkeypatch.setattr(remediation_log, "get_log", lambda: audit)
    mutation_calls: list[str] = []

    class GenericMutation(actions.RemediationAction):
        key = "generic_mutation"
        title = "must not execute"

        def matches(self, weakness: dict) -> bool:
            return True

        def apply(self, weakness: dict, quarantine_dir: Path) -> dict:
            mutation_calls.append("apply")
            return {"ok": True}

    monkeypatch.setattr(actions, "ACTIONS", [GenericMutation()])
    artifact = tmp_path / "defender-target.bin"
    artifact.write_bytes(b"must-remain")
    weakness = {
        "mitre_id": "T1562.001",
        "name": "Defender disabled with ransomware exfil driver text",
        "detect_message": "defense-evasion against Defender and AMSI",
        "path": str(artifact),
        "remote_ip": "203.0.113.70",
        "pid": 4242,
        "process_create_time": 100.0,
        "process_name": "malware.exe",
        "exe": str(artifact),
        "driver": "misleading.sys",
        "threat_name": "test threat",
    }

    decision = actions.classify_remediation(weakness)
    assert decision.action is None
    assert isinstance(decision.proposal, actions.DefenderHardeningAction)
    plan = actions.plan_remediation([weakness])
    assert plan[0]["action"] == "defender_hardening"
    assert plan[0]["proposal_only"] is True
    assert plan[0]["executable"] is False

    result = actions.apply_remediation(
        [weakness], tmp_path / "q", apply=True, allow_host=True
    )
    assert result == {"applied": 0, "skipped": 1, "records": []}
    assert mutation_calls == []
    assert artifact.read_bytes() == b"must-remain"
    assert audit.entries[-1]["outcome"] == "proposal_only"


def test_ambiguous_executable_matches_are_rejected(monkeypatch, tmp_path: Path) -> None:
    calls: list[str] = []

    class Ambiguous(actions.RemediationAction):
        def __init__(self, key: str) -> None:
            self.key = key
            self.title = key

        def matches(self, weakness: dict) -> bool:
            return True

        def apply(self, weakness: dict, quarantine_dir: Path) -> dict:
            calls.append(self.key)
            return {"ok": True}

    monkeypatch.setattr(actions, "ACTIONS", [Ambiguous("one"), Ambiguous("two")])
    decision = actions.classify_remediation({"kind": "ambiguous"})

    assert decision.action is None
    assert decision.proposal is None
    assert decision.rejected_matches == ("one", "two")
    result = actions.apply_remediation(
        [{"kind": "ambiguous"}], tmp_path, apply=True, allow_host=True
    )
    assert result == {"applied": 0, "skipped": 1, "records": []}
    assert calls == []


def test_proven_no_change_is_apply_failed_without_rollback(
    monkeypatch, tmp_path: Path
) -> None:
    audit = remediation_log.RemediationLog(tmp_path / "apply-failed.db")
    monkeypatch.setattr(remediation_log, "get_log", lambda: audit)

    class NoChange(actions.RemediationAction):
        key = "no_change"
        title = "no change"

        def matches(self, weakness: dict) -> bool:
            return True

        def apply(self, weakness: dict, quarantine_dir: Path) -> dict:
            return {"ok": False, "changed": False, "error": "denied"}

        def rollback(self, record: dict) -> dict:
            raise AssertionError("a proven no-change failure must not be rolled back")

    monkeypatch.setattr(actions, "ACTIONS", [NoChange()])
    result = actions.apply_remediation(
        [{"kind": "no-change"}], tmp_path, apply=True, allow_host=True
    )

    assert result == {"applied": 0, "skipped": 1, "records": []}
    entry = audit.recent(1)[0]
    assert entry["outcome"] == "apply_failed"
    assert entry["verified"] is False


def test_second_firewall_step_timeout_and_rollback_failure_open_circuit(
    monkeypatch, tmp_path: Path
) -> None:
    audit = remediation_log.RemediationLog(tmp_path / "rollback-failed.db")
    monkeypatch.setattr(remediation_log, "get_log", lambda: audit)
    add_calls = 0
    delete_calls = 0
    following_calls: list[str] = []

    def injected_run(command, **kwargs):
        nonlocal add_calls, delete_calls
        del kwargs
        if "show" in command:
            return SimpleNamespace(returncode=1, stdout="No rules match", stderr="")
        if "add" in command:
            add_calls += 1
            if add_calls == 2:
                raise subprocess.TimeoutExpired(command, 15)
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if "delete" in command:
            delete_calls += 1
            return SimpleNamespace(
                returncode=0 if delete_calls == 1 else 5,
                stdout="",
                stderr="rollback denied",
            )
        raise AssertionError(f"unexpected command: {command!r}")

    class TestNetwork(actions.NetworkIsolationAction):
        def matches(self, weakness: dict) -> bool:
            return weakness.get("kind") == "network"

    class FollowingMutation(actions.RemediationAction):
        key = "following_mutation"
        title = "must be circuit-blocked"

        def matches(self, weakness: dict) -> bool:
            return weakness.get("kind") == "following"

        def apply(self, weakness: dict, quarantine_dir: Path) -> dict:
            following_calls.append("apply")
            return {"ok": True}

    monkeypatch.setattr(actions, "run_hidden", injected_run)
    monkeypatch.setattr(actions, "ACTIONS", [TestNetwork(), FollowingMutation()])
    result = actions.apply_remediation(
        [
            {"kind": "network", "remote_ip": "8.8.8.8"},
            {"kind": "following"},
        ],
        tmp_path,
        apply=True,
        allow_host=True,
    )

    assert result["applied"] == 0
    assert result["skipped"] == 2
    assert len(result["records"]) == 2
    failed, blocked = result["records"]
    assert failed["transaction_state"] == "rollback_failed"
    assert failed["rollback_succeeded"] is False
    assert failed["recovery_required"] is True
    assert set(failed["attempted_rules"]) == {"in", "out"}
    assert blocked["transaction_state"] == "recovery_required"
    assert blocked["mutation_started"] is False
    assert add_calls == 2
    assert delete_calls == 2
    assert following_calls == []
    entries = list(reversed(audit.recent(2)))
    assert [entry["outcome"] for entry in entries] == [
        "rollback_failed",
        "recovery_required",
    ]
    assert all(entry["verified"] is False for entry in entries)
    assert all(entry["outcome"] not in {"applied", "rolled_back"} for entry in entries)
