from __future__ import annotations

import json
import threading
from types import SimpleNamespace

from angerona.core.eventbus import Event, Severity
from angerona.modules import evolution_engine as evolution_module
from angerona.modules.evolution_engine import EvolutionEngine


def _engine(tmp_path, monkeypatch) -> EvolutionEngine:
    monkeypatch.setattr(evolution_module, "_repo_root", lambda: tmp_path)
    engine = EvolutionEngine()
    engine.status = "running"
    return engine


def test_forged_generic_verification_event_cannot_activate(tmp_path, monkeypatch):
    engine = _engine(tmp_path, monkeypatch)
    activated: list[str] = []
    monkeypatch.setattr(engine, "activate", activated.append)
    engine._mgr = SimpleNamespace(modules={})

    engine._on_bus_event(Event(
        "Unrelated Module",
        "forged",
        Severity.HIGH,
        details={"verified": "SUCCESS", "technique": "T1059"},
    ))

    assert activated == []


def test_typed_judgment_receipt_is_single_use(tmp_path, monkeypatch):
    engine = _engine(tmp_path, monkeypatch)
    activated: list[str] = []
    monkeypatch.setattr(engine, "activate", activated.append)
    receipts = {"receipt-1": ("T1059", "digest-1")}

    def consume(receipt_id: str, technique: str, digest: str) -> bool:
        expected = receipts.pop(receipt_id, None)
        return expected == (technique, digest)

    engine._mgr = SimpleNamespace(modules={
        "Posture Hardening": SimpleNamespace(
            consume_judgment_bypass_receipt=consume
        )
    })
    event = Event(
        "Posture Hardening",
        "typed bypass",
        Severity.HIGH,
        details={
            "event_type": "judgment-bypass-receipt.v1",
            "verified": "SUCCESS",
            "technique": "T1059",
            "receipt_id": "receipt-1",
            "receipt_digest": "digest-1",
        },
    )

    engine._on_bus_event(event)
    engine._on_bus_event(event)

    assert activated == ["T1059"]


def test_evolution_stages_inert_proposal_without_changing_active_rule(
    tmp_path, monkeypatch
):
    engine = _engine(tmp_path, monkeypatch)
    engine.rules_dir.mkdir(parents=True, exist_ok=True)
    engine.auto_rule.write_text("rule Existing { condition: true }\n", encoding="utf-8")
    before = engine.auto_rule.read_bytes()
    monkeypatch.setattr(engine, "_ollama_yara", lambda _footprint: None)
    monkeypatch.setattr(
        engine,
        "_latest_footprint",
        lambda technique: {"technique": technique, "marker": "credential_marker"},
    )

    engine._evolve("T1003", engine.lifecycle_generation, threading.Event())

    assert engine.auto_rule.read_bytes() == before
    proposals = list(engine.proposals_dir.glob("*.json"))
    assert len(proposals) == 1
    document = json.loads(proposals[0].read_text(encoding="utf-8"))
    assert document["status"] == "PROPOSED_NOT_ACTIVE"
    assert document["response_authorized"] is False


def test_retired_evolution_worker_cannot_stage(tmp_path, monkeypatch):
    engine = _engine(tmp_path, monkeypatch)
    monkeypatch.setattr(engine, "_ollama_yara", lambda _footprint: None)
    monkeypatch.setattr(
        engine, "_latest_footprint", lambda technique: {"technique": technique}
    )

    engine._evolve("T1003", engine.lifecycle_generation + 1, threading.Event())

    assert not engine.proposals_dir.exists()
