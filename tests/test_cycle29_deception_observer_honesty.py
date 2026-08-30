from __future__ import annotations

from pathlib import Path

from angerona.core.eventbus import EventBus
from angerona.modules import deception


def _module(tmp_path: Path, monkeypatch) -> deception.DeceptionModule:
    monkeypatch.delenv("ANGERONA_USER_FOLDER_DECEPTION", raising=False)
    monkeypatch.setattr(deception, "_repo_root", lambda: tmp_path)
    module = deception.DeceptionModule()
    module.bind(EventBus())
    return module


def test_active_deception_reports_exact_mutation_delete_visibility(
    tmp_path: Path, monkeypatch
) -> None:
    module = _module(tmp_path, monkeypatch)
    module.stop()

    module.run()

    assert module.health == 70
    assert "mutation/deletion visibility active" in module.health_note
    evidence = module.health_evidence
    assert evidence is not None
    assert "read telemetry is unavailable" in str(evidence["reason"])
    planted = next(
        event
        for event in module._bus.recent(20)
        if event.details.get("coverage") == "file-mutation-and-deletion"
    )
    assert planted.details["read_visibility"] is False
    assert planted.details["evidence_path"] == str(module._base)
    assert "audited reads are not claimed" in planted.message


def test_plain_file_read_is_not_misreported_as_a_canary_detection(
    tmp_path: Path, monkeypatch
) -> None:
    module = _module(tmp_path, monkeypatch)
    module._plant()
    path = Path(next(iter(module._canaries)))
    before = len(module._bus.recent(100))

    assert path.read_text(encoding="utf-8")
    module._check_canaries()

    assert len(module._bus.recent(100)) == before


def test_dynamic_lure_text_does_not_claim_unavailable_read_observation(
    tmp_path: Path, monkeypatch
) -> None:
    module = _module(tmp_path, monkeypatch)
    module._base.mkdir(parents=True)
    monkeypatch.setattr(module, "_plant_fake_registry_cred", lambda _name: None)

    module._restage("credential discovery")

    lure = next(path for path in module._base.iterdir() if path.is_file())
    text = lure.read_text(encoding="utf-8")
    assert "File mutation or deletion is logged" in text
    assert "audited reads require the configured OS audit source" in text
    assert "Any access" not in text
