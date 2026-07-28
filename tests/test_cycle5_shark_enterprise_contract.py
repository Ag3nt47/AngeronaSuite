"""Cycle 5 enterprise controls for Angerona's benign drill engines."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import report_attest
from angerona.modules.evolution_engine import EvolutionEngine
from angerona.modules import evolution_engine as evolution_module
from angerona.shark.aar_report import generate_aar
from angerona.shark.red_team import RedTeamEngine, RedTeamStep
from angerona.shark.run_manifest import (
    DrillHistoryIntegrityError,
    attest_run_history,
    build_run_history,
    load_verified_history,
    preflight_run,
    verify_run_history,
    write_run_history,
)
from angerona.shark.shark_attack import SharkAttackEngine, SharkStep


_TEST_KEY = bytes(range(32))


def _accepted_preflight(custom=None):
    decision = preflight_run(
        kind="shark",
        cycles=1,
        jitter_range=(0.0, 1.0),
        noise_chance=0.25,
        custom=custom,
    )
    assert decision.accepted
    return decision


def _history(tmp_path: Path) -> dict:
    marker = tmp_path / "inert-marker.txt"
    marker.write_text("BENIGN TEST MARKER", encoding="utf-8")
    return build_run_history(
        kind="shark",
        run_id="shark-test-001",
        generated="2026-07-28 12:00:00",
        steps=[
            {
                "stage": "Persistence (simulated)",
                "technique": "Marker only (T1547.001)",
                "description": "Inert marker written.",
                "ts_start": 10.0,
                "ts_end": 11.0,
                "artifact_paths": [str(marker)],
                "pid": None,
                "detail": "",
                "ok": True,
            }
        ],
        preflight=_accepted_preflight(),
        status="completed",
    )


def test_preflight_is_bounded_deterministic_and_does_not_store_custom_body():
    secret_body = "benign-but-private operator text"
    custom = {"name": "operator marker", "payload": secret_body}
    first = _accepted_preflight(custom)
    second = _accepted_preflight(custom)

    assert first.request_digest == second.request_digest
    assert first.custom == {
        "name": "operator marker",
        "payload_bytes": len(secret_body.encode("utf-8")),
        "payload_sha256": hashlib.sha256(secret_body.encode("utf-8")).hexdigest(),
    }
    assert secret_body not in json.dumps(first.as_dict())

    refused = preflight_run(
        kind="shark",
        cycles=999,
        jitter_range=(-1, 99),
        noise_chance=2,
        custom={"name": "x", "payload": "x" * (16 * 1024 + 1)},
    )
    assert not refused.accepted
    assert len(refused.violations) >= 4

    remote = preflight_run(
        kind="shark",
        cycles=1,
        jitter_range=(0, 1),
        noise_chance=0,
        target_dir=r"\\server\share",
    )
    assert not remote.accepted
    assert "network and device paths are not permitted" in remote.violations

    log_injection = preflight_run(
        kind="shark",
        cycles=1,
        jitter_range=(0, 1),
        noise_chance=0,
        custom={"name": "trusted\n[PASS] forged", "payload": "marker"},
    )
    assert not log_injection.accepted
    assert (
        "custom technique name must not contain control characters"
        in log_injection.violations
    )


def test_preflight_rejects_non_utf8_text_without_raising():
    decision = preflight_run(
        kind="shark",
        cycles=1,
        jitter_range=(0, 1),
        noise_chance=0,
        custom={"name": "marker", "payload": "\ud800"},
    )
    assert not decision.accepted
    assert "custom payload must be valid UTF-8 text" in decision.violations


def test_manifest_binds_steps_artifacts_attack_ids_and_campaign(tmp_path):
    history = _history(tmp_path)
    step = history["steps"][0]
    receipt = step["evidence_receipt"]["artifact_receipts"][0]

    assert step["run_id"] == history["run_id"]
    assert step["step_id"].startswith("DSTEP-")
    assert step["attack_ids"] == ["T1547.001"]
    assert receipt["name"] == "inert-marker.txt"
    assert receipt["status"] == "hashed"
    assert receipt["size"] == len("BENIGN TEST MARKER")
    assert receipt["sha256"] == hashlib.sha256(
        b"BENIGN TEST MARKER"
    ).hexdigest()
    assert "BENIGN TEST MARKER" not in json.dumps(history)
    assert history["campaign"]["realized_plan_sha256"]
    assert history["safety_contract"]["actual_usage"]["within_budget"] is True

    signed = attest_run_history(history, key=_TEST_KEY)
    verified = verify_run_history(signed, key=_TEST_KEY)
    assert verified.valid
    assert verified.authenticity == "ok"
    assert verified.steps == 1


def test_tampering_breaks_authenticity_and_the_internal_evidence_chain(tmp_path):
    history = _history(tmp_path)
    signed = attest_run_history(history, key=_TEST_KEY)
    signed["steps"][0]["technique"] = "altered"
    verified = verify_run_history(signed, key=_TEST_KEY)
    assert not verified.valid
    assert verified.authenticity == "bad"

    unsigned = _history(tmp_path)
    unsigned["steps"][0]["stage"] = "altered"
    chain_only = verify_run_history(unsigned, require_authenticity=False)
    assert not chain_only.valid
    assert "evidence hash" in chain_only.reason


def test_engine_preflight_refuses_before_threads_or_artifacts(tmp_path):
    events: list[str] = []
    shark = SharkAttackEngine(
        tmp_path / "shark",
        documents_dir=tmp_path / "markers",
        on_event=events.append,
    )
    red = RedTeamEngine(
        tmp_path / "red",
        documents_dir=tmp_path / "markers",
        on_event=events.append,
    )

    assert not shark.start(complexity=999)
    assert not red.start(complexity=999)
    assert shark._thread is None
    assert red._thread is None
    assert not shark.history_path.exists()
    assert not red.history_path.exists()
    assert not (tmp_path / "markers").exists()
    assert any("refused by the safety contract" in event for event in events)


def test_atomic_write_load_and_aar_fail_closed_after_tamper(
    tmp_path, monkeypatch
):
    key_path = tmp_path / "bus.key"
    key_path.write_text(_TEST_KEY.hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)

    path = tmp_path / "shark_history.json"
    assert write_run_history(path, _history(tmp_path))
    loaded = load_verified_history(path)
    assert loaded["run_id"] == "shark-test-001"

    tampered = json.loads(path.read_text(encoding="utf-8"))
    tampered["steps"][0]["description"] = "poisoned ground truth"
    path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(DrillHistoryIntegrityError, match="HMAC"):
        load_verified_history(path)
    report = generate_aar(data_dir=tmp_path)
    assert "integrity check failed" in report
    assert "AAR not generated" in report


def test_both_engines_write_verified_dataclass_ground_truth(
    tmp_path, monkeypatch
):
    key_path = tmp_path / "bus.key"
    key_path.write_text(_TEST_KEY.hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)

    shark = SharkAttackEngine(tmp_path / "shark")
    shark.run_id = "shark-dataclass"
    shark._run_contract = preflight_run(
        kind="shark",
        cycles=1,
        jitter_range=(0, 1),
        noise_chance=0,
        target_dir=shark.documents_dir,
    )
    shark.steps = [
        SharkStep("Discovery", "read-only T1087", "read only", 1.0, 2.0)
    ]
    shark._write_history()

    red = RedTeamEngine(tmp_path / "red")
    red.run_id = "red-dataclass"
    red._run_contract = preflight_run(
        kind="red_team",
        cycles=1,
        jitter_range=(0, 1),
        noise_chance=0,
        target_dir=red.documents_dir,
    )
    red.steps = [
        RedTeamStep("Discovery", "read-only T1087", "read only", 1.0, 2.0)
    ]
    red._write_history()

    assert load_verified_history(shark.history_path)["kind"] == "shark"
    assert load_verified_history(red.history_path)["kind"] == "red_team"


def test_legacy_history_requires_an_explicit_compatibility_policy():
    legacy = {"run_id": "old", "steps": []}
    refused = verify_run_history(legacy)
    accepted = verify_run_history(legacy, allow_legacy=True)

    assert not refused.valid
    assert refused.legacy
    assert accepted.valid
    assert accepted.legacy
    assert accepted.authenticity == "legacy-unsigned"


def test_evolution_engine_only_uses_verified_drill_ground_truth(
    tmp_path, monkeypatch
):
    key_path = tmp_path / "bus.key"
    key_path.write_text(_TEST_KEY.hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)
    monkeypatch.setattr(
        evolution_module.Config,
        "load",
        lambda: SimpleNamespace(data_dir=tmp_path),
    )

    history_path = tmp_path / "shark_history.json"
    history = _history(tmp_path)
    history["steps"][0]["technique"] = "Synthetic T1547.001"
    # Rebuild so the evidence chain binds the changed technique.
    history = build_run_history(
        kind="shark",
        run_id="shark-evolution-001",
        generated="2026-07-28 12:00:00",
        steps=[
            {
                "stage": "Persistence (simulated)",
                "technique": "Synthetic T1547.001",
                "description": "Inert marker written.",
                "ts_start": 10.0,
                "ts_end": 11.0,
                "artifact_paths": [],
                "pid": None,
                "detail": "",
                "ok": True,
            }
        ],
        preflight=_accepted_preflight(),
        status="completed",
    )
    assert write_run_history(history_path, history)

    engine = object.__new__(EvolutionEngine)
    engine.attack_feed = tmp_path / "missing-feed.log"
    assert engine._latest_footprint("T1547.001")["run_id"] == "shark-evolution-001"

    tampered = json.loads(history_path.read_text(encoding="utf-8"))
    tampered["steps"][0]["description"] = "poisoned"
    history_path.write_text(json.dumps(tampered), encoding="utf-8")
    assert engine._latest_footprint("T1547.001") == {
        "technique": "T1547.001",
        "detail": "no footprint found",
    }
