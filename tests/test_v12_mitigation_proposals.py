from __future__ import annotations

import json

from angerona.shark import playbook_tuner
from angerona.modules.remediation_actions import PersistenceCleanupAction


def test_containment_tuner_stages_typed_non_executable_proposal(tmp_path, monkeypatch) -> None:
    proposal_root = tmp_path / "containment"
    proposal_root.mkdir()
    monkeypatch.setattr(playbook_tuner, "_proposal_root", lambda: proposal_root)

    result = playbook_tuner.tune_containment(
        "T1055.001",
        {"failed_action": "suspend", "artifact": "C:/evidence/sample.exe"},
    )

    assert result["ok"] is True
    assert result["executed"] is False
    assert result["verified"] is False
    assert result["reverify"] == "NOT_RUN"
    path = proposal_root / (result["proposal_id"] + ".json")
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["schema"] == "angerona.containment-proposal.v12"
    assert document["response_authorized"] is False
    assert document["intent"]["remote_scope"] == "operator-must-select"
    assert not list(proposal_root.glob("*.ps1"))


def test_containment_tuner_refuses_invalid_technique(tmp_path, monkeypatch) -> None:
    proposal_root = tmp_path / "containment"
    proposal_root.mkdir()
    monkeypatch.setattr(playbook_tuner, "_proposal_root", lambda: proposal_root)

    result = playbook_tuner.tune_containment("../../run-me")

    assert result["ok"] is False
    assert result["executed"] is False
    assert not tuple(proposal_root.iterdir())


def test_large_timeline_is_digest_only_and_bounded(tmp_path, monkeypatch) -> None:
    proposal_root = tmp_path / "containment"
    proposal_root.mkdir()
    monkeypatch.setattr(playbook_tuner, "_proposal_root", lambda: proposal_root)

    result = playbook_tuner.tune_containment("T1055", {"data": "x" * 100_000})
    document = json.loads(
        (proposal_root / (result["proposal_id"] + ".json")).read_text(encoding="utf-8")
    )

    assert "data" not in document["evidence"]
    assert document["evidence"]["original_bytes"] > 64 * 1024
    assert len(json.dumps(document)) < 20_000


def test_ambiguous_autorun_cleanup_is_proposal_only(tmp_path) -> None:
    action = PersistenceCleanupAction()
    finding = {
        "mitre_id": "T1547.001",
        "run_key_value": "Updater",
        "message": "autorun persistence",
    }

    assert action.matches(finding) is False
    result = action.apply(finding, tmp_path)
    assert result["ok"] is False
    assert result["proposal_only"] is True
    assert action.verify(finding, result) is False
