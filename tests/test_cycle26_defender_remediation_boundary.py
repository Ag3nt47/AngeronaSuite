from __future__ import annotations

from angerona.core import remediation_log
from angerona.modules import remediation_actions as actions


def _defender_weakness() -> dict:
    return {
        "mitre_id": "T1562.001",
        "name": "Microsoft Defender real-time protection disabled",
        "detect_message": "defense-evasion against Defender",
    }


class _AuditLog:
    def __init__(self) -> None:
        self.entries: list[dict] = []

    def log(self, **entry):
        self.entries.append(entry)
        return f"proof-{len(self.entries)}"


def test_defender_response_is_explanatory_and_never_executable(
    monkeypatch, tmp_path
) -> None:
    audit = _AuditLog()
    monkeypatch.setattr(remediation_log, "get_log", lambda: audit)

    def unexpected_process(*args, **kwargs):
        raise AssertionError(f"proposal-only Defender response ran a process: {args!r} {kwargs!r}")

    monkeypatch.setattr(actions, "run_hidden", unexpected_process)
    weakness = _defender_weakness()
    proposal = actions.DefenderHardeningAction()

    assert not any(isinstance(action, actions.DefenderHardeningAction)
                   for action in actions.ACTIONS)
    assert any(isinstance(action, actions.DefenderHardeningAction)
               for action in actions.PROPOSAL_ONLY_ACTIONS)

    direct = proposal.apply(weakness, tmp_path)
    assert direct["ok"] is False
    assert direct["proposal_only"] is True
    assert direct["executable"] is False
    assert direct["reason"] == proposal.proposal_reason
    assert proposal.verify(weakness, direct) is False

    plan = actions.plan_remediation([weakness])
    assert plan == [{
        "mitre": "T1562.001",
        "action": "defender_hardening",
        "title": proposal.title,
        "proposal_only": True,
        "executable": False,
        "reason": proposal.proposal_reason,
    }]

    result = actions.apply_remediation(
        [weakness], tmp_path, apply=True, allow_host=True,
    )
    assert result == {"applied": 0, "skipped": 1, "records": []}
    assert audit.entries
    assert all(entry["outcome"] != "applied" for entry in audit.entries)
    assert all(entry["verified"] != 1 for entry in audit.entries)
    assert audit.entries[-1]["outcome"] == "proposal_only"
    assert audit.entries[-1]["record"]["executable"] is False


def test_failed_apply_cannot_be_promoted_by_an_already_true_postcondition(
    monkeypatch, tmp_path
) -> None:
    audit = remediation_log.RemediationLog(tmp_path / "failed-action.db")
    monkeypatch.setattr(remediation_log, "get_log", lambda: audit)

    class FailedAction(actions.RemediationAction):
        key = "failed_test_action"
        title = "failed test action"
        durable_transaction = True

        def __init__(self) -> None:
            self.verified = False
            self.rolled_back = False

        def matches(self, weakness: dict) -> bool:
            return True

        def begin_transaction(self, weakness: dict, quarantine_dir) -> dict:
            return {
                "action": self.key,
                "prior_state": "inert-fixture",
                "compensation_ready": True,
                "mutation_started": False,
                "transaction_state": "prepared",
            }

        def apply(self, weakness: dict, quarantine_dir) -> dict:
            return {"ok": False, "rc": 1, "action": self.key}

        def verify(self, weakness: dict, record: dict) -> bool:
            self.verified = True
            return True

        def rollback(self, record: dict) -> dict:
            self.rolled_back = True
            return {"ok": True}

        def verify_rollback(self, record: dict) -> bool:
            return self.rolled_back and record.get("prior_state") == "inert-fixture"

    failed = FailedAction()
    monkeypatch.setattr(actions, "ACTIONS", [failed])
    monkeypatch.setattr(actions, "PROPOSAL_ONLY_ACTIONS", ())

    result = actions.apply_remediation(
        [{"mitre_id": "T0000"}], tmp_path, apply=True, allow_host=True,
    )

    assert result == {"applied": 0, "skipped": 1, "records": []}
    assert failed.verified is False
    assert failed.rolled_back is True
    entry = audit.recent(1)[0]
    assert entry["outcome"] == "rolled_back"
    assert entry["verified"] is False
    audit.close()


def test_defender_proposal_never_invokes_a_process_under_any_apply_gate(
    monkeypatch, tmp_path
) -> None:
    audit = _AuditLog()
    monkeypatch.setattr(remediation_log, "get_log", lambda: audit)
    monkeypatch.setenv("ANGERONA_AUTO_REMEDIATE", "1")
    process_calls: list[tuple[tuple, dict]] = []

    def observed_process(*args, **kwargs):
        process_calls.append((args, kwargs))
        raise AssertionError("Defender proposal crossed into the subprocess boundary")

    monkeypatch.setattr(actions, "run_hidden", observed_process)
    for apply, allow_host in (
        (False, False),
        (False, True),
        (False, None),
        (True, False),
        (True, True),
        (True, None),
    ):
        result = actions.apply_remediation(
            [_defender_weakness()],
            tmp_path,
            apply=apply,
            allow_host=allow_host,
        )
        assert result == {"applied": 0, "skipped": 1, "records": []}

    assert process_calls == []
    assert len(audit.entries) == 6
    assert all(entry["outcome"] == "proposal_only" for entry in audit.entries)
