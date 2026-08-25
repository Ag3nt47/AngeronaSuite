from __future__ import annotations

import json
import hashlib
import time
from pathlib import Path

import pytest

from angerona.core import drill_resolution, report_attest
from angerona.core.eventbus import EventBus
from angerona.core.storage import FlightRecorder
from angerona.modules.posture_hardening import PostureHardening
from angerona.modules.purple_guard import PurpleGuard, policy_path
from angerona.modules.soar_engine import ActiveResponseSOAR
from angerona.shark.aar_report import evaluate


def _verdict(
    mitre: str,
    *,
    caught: bool,
    ts_start: float,
    stage: str | None = None,
    detected_by: str | None = None,
) -> dict:
    row = {
        "stage": stage or f"Stage {mitre}",
        "technique": f"{mitre} inert marker",
        "description": "benign purple-team verification marker",
        "ts_start": ts_start,
        "category": "detection",
        "caught": caught,
    }
    if detected_by:
        row["detected_by"] = detected_by
    return row


def _report(run_id: str, *verdicts: dict) -> dict:
    return {"run_id": run_id, "verdicts": list(verdicts)}


def _verified_verdict(root: Path, run_id: str, *, ts_start: float) -> dict:
    state = drill_resolution.resolution_snapshot(root)["t1003"]
    proof = drill_resolution.verify_detector_evidence(
        "T1003",
        run_id,
        detector="Purple Remediation Guard",
        event_ts=time.time() + 1,
        event_details={"mitre": "T1003", "artifact_path": "inert-marker",
                       "detector_policy": "reviewed-redteam-candidate"},
        data_dir=root,
        expected_contract_id=state["contract_id"],
        expected_contract_digest=state["contract_digest"],
    )
    assert proof["ok"]
    row = _verdict(
        "T1003",
        caught=True,
        ts_start=ts_start,
        detected_by="Purple Remediation Guard",
    )
    row["action_contract_id"] = state["contract_id"]
    row["action_contract_digest"] = state["contract_digest"]
    return row


def _write(path: Path, doc: dict, *, signed: bool = True) -> Path:
    payload = report_attest.attest(doc) if signed else doc
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


@pytest.fixture
def strict_module(tmp_path, monkeypatch):
    key_path = tmp_path / "bus.key"
    key_path.write_text(bytes(range(32)).hex(), encoding="ascii")
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)
    monkeypatch.setenv("ANGERONA_REQUIRE_SIGNED_AAR", "1")

    module = PostureHardening(data_dir=tmp_path)
    emitted: list[tuple[object, dict]] = []
    module.emit = lambda _message, severity=None, **details: emitted.append(
        (severity, details)
    )
    module._log_attempt = lambda *_args, **_kwargs: None
    return module, tmp_path, emitted


def test_signed_report_preserves_strict_ingest_and_manual_resolution(strict_module):
    module, root, _emitted = strict_module
    report_path = _write(
        root / "redteam_aar.json",
        _report("run-signed", _verdict("T1003", caught=False, ts_start=10.0)),
    )

    assert module.ingest_redteam_report(report_path) == [
        {"mitre": "T1003", "name": "Stage T1003"}
    ]
    result = module.resolve_redteam_report(report_path)

    assert result["ok"] is True
    assert result["candidates"] == 1
    assert result["verification_required"] is True
    assert module.weaknesses("VULNERABLE")[0]["mitre_id"] == "T1003"


def test_caught_but_unremediated_step_is_an_actionable_response_gap(strict_module):
    module, root, _emitted = strict_module
    verdict = _verdict("T1003", caught=True, ts_start=11.0)
    verdict["remediated"] = False
    report_path = _write(root / "redteam_aar.json", _report("run-response-gap", verdict))

    learned = module.ingest_redteam_report(report_path)
    result = module.resolve_redteam_report(report_path)

    assert learned == [{"mitre": "T1003", "name": "Stage T1003"}]
    assert result["ok"] is True
    assert result["candidates"] == 1
    assert result["findings"][0]["gap_kind"] == "response"


def test_response_only_gap_candidate_closes_on_fresh_inert_full_drill(
    strict_module, monkeypatch,
) -> None:
    module, root, _emitted = strict_module
    source = _verdict("T1003", caught=True, ts_start=time.time() - 5)
    source["remediated"] = False
    report_path = _write(root / "redteam_aar.json", _report("source-run", source))
    resolution = module.resolve_redteam_report(report_path)
    assert resolution["candidates"] == 1

    recorder = FlightRecorder(root / "flight-recorder.db")
    bus = EventBus()
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus)
    guard = PurpleGuard(root)
    guard.bind(bus)
    response = ActiveResponseSOAR()
    response.bind(bus)
    sandbox = root / "drill-sandbox"
    sandbox.mkdir()
    marker = sandbox / "_redteam_lsass_dump_freshfull.txt"
    started = time.time()
    marker.write_text("ANGERONA inert second-run marker", encoding="utf-8")
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK", "1")
    monkeypatch.setenv("ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY", "HIGH")
    monkeypatch.setenv("ANGERONA_SOAR_RESPONSE_SCOPE", str(sandbox))
    try:
        assert guard.scan_once(guard._policy_snapshot()) == 1
        # Windows' wall clock commonly gives back-to-back publications an
        # identical timestamp. Freeze the response receipt at the detector's
        # timestamp so this remains a deterministic correlation regression,
        # independent of host timer granularity.
        detector = bus.recent(1)[0]
        monkeypatch.setattr(time, "time", lambda: detector.ts)
        assert response.process_pending_once() == 1
        events = bus.recent(100)
    finally:
        recorder.close()

    verdicts = evaluate(
        {
            "run_id": "fresh-proof-run",
            "steps": [{
                "stage": "Credential Access (simulated)",
                "technique": "T1003 marker",
                "description": "fresh inert marker",
                "ts_start": started,
                "ts_end": time.time(),
                "artifact_paths": [str(marker)],
            }],
        },
        events,
        {"Credential Access (simulated)": "detection"},
    )
    metrics = drill_resolution.reconcile_verdicts(
        verdicts, "fresh-proof-run", root,
    )

    assert verdicts[0].catch is not None
    assert verdicts[0].catch.module == "Purple Remediation Guard"
    assert verdicts[0].remediation is not None
    assert verdicts[0].remediation.module == "Adversary Combat"
    assert verdicts[0].remediation.details["postcondition_verified"] is True
    assert metrics["verified_closures"] == 1
    assert not marker.exists()


def test_displayed_report_digest_and_run_id_fail_closed_on_replacement(strict_module):
    module, root, _emitted = strict_module
    report_path = _write(
        root / "redteam_aar.json",
        _report("reviewed-run", _verdict("T1003", caught=False, ts_start=12.0)),
    )
    reviewed = report_path.read_bytes()
    digest = hashlib.sha256(reviewed).hexdigest()
    _write(
        report_path,
        _report("replacement-run", _verdict("T1546.003", caught=False, ts_start=13.0)),
    )

    result = module.resolve_redteam_report(
        report_path,
        expected_run_id="reviewed-run",
        expected_report_sha256=digest,
    )

    assert result["ok"] is False
    assert result["binding_failed"] is True
    assert not policy_path(root).exists()


def test_unsigned_report_cannot_ingest_or_resolve_in_strict_mode(strict_module):
    module, root, emitted = strict_module
    report_path = _write(
        root / "redteam_aar.json",
        _report("run-unsigned", _verdict("T1003", caught=False, ts_start=20.0)),
        signed=False,
    )

    assert module.ingest_redteam_report(report_path) == []
    result = module.resolve_redteam_report(report_path)

    assert result["ok"] is False
    assert result["authentication_failed"] is True
    assert result["fail_closed"] is True
    assert module.weaknesses() == []
    assert not policy_path(root).exists()
    assert emitted and emitted[0][1]["fail_closed"] is True


def test_tampered_signed_report_cannot_ingest_or_resolve(strict_module):
    module, root, emitted = strict_module
    payload = report_attest.attest(
        _report("run-original", _verdict("T1003", caught=False, ts_start=30.0))
    )
    payload["run_id"] = "run-attacker-modified"
    report_path = root / "redteam_aar.json"
    report_path.write_text(json.dumps(payload), encoding="utf-8")

    assert module.ingest_redteam_report(report_path) == []
    result = module.resolve_redteam_report(report_path)

    assert result["ok"] is False
    assert result["authentication_failed"] is True
    assert module.weaknesses() == []
    assert not policy_path(root).exists()
    assert emitted and emitted[0][1]["fail_closed"] is True


def test_verifier_error_is_fail_closed_in_strict_mode(strict_module, monkeypatch):
    module, root, emitted = strict_module
    report_path = _write(
        root / "redteam_aar.json",
        _report("run-error", _verdict("T1003", caught=False, ts_start=40.0)),
    )

    def _raise(_doc):
        raise RuntimeError("simulated verifier failure")

    monkeypatch.setattr(report_attest, "classify_for_ingest", _raise)

    assert module.ingest_redteam_report(report_path) == []
    result = module.resolve_redteam_report(report_path)

    assert result["ok"] is False
    assert result["fail_closed"] is True
    assert "verifier failed" in module.last_error
    assert module.weaknesses() == []
    assert not policy_path(root).exists()
    assert emitted and emitted[0][1]["fail_closed"] is True


def test_same_run_cannot_self_certify_but_later_signed_run_can(strict_module):
    module, root, _emitted = strict_module
    report_path = root / "redteam_aar.json"

    _write(
        report_path,
        _report("run-a", _verdict("T1003", caught=False, ts_start=50.0)),
    )
    assert len(module.ingest_redteam_report(report_path)) == 1
    assert module.resolve_redteam_report(report_path)["candidates"] == 1

    _write(
        report_path,
        _report(
            "run-a",
            _verdict(
                "T1003",
                caught=True,
                ts_start=51.0,
                detected_by="Purple Remediation Guard",
            ),
        ),
    )
    assert module.ingest_redteam_report(report_path) == []
    assert module.weaknesses("VULNERABLE")[0]["mitre_id"] == "T1003"

    _write(
        report_path,
        _report(
            "run-b",
            _verified_verdict(root, "run-b", ts_start=52.0),
        ),
    )
    assert module.ingest_redteam_report(report_path) == []
    assert module.weaknesses("PATCHED")[0]["mitre_id"] == "T1003"


def test_signed_summary_without_raw_lifecycle_binding_cannot_close(strict_module):
    module, root, _emitted = strict_module
    report_path = root / "redteam_aar.json"
    _write(
        report_path,
        _report("run-a", _verdict("T1003", caught=False, ts_start=55.0)),
    )
    module.ingest_redteam_report(report_path)
    module.resolve_redteam_report(report_path)

    _write(
        report_path,
        _report(
            "run-b",
            _verdict(
                "T1003",
                caught=True,
                ts_start=56.0,
                detected_by="Purple Remediation Guard",
            ),
        ),
    )
    module.ingest_redteam_report(report_path)
    assert module.weaknesses("PATCHED") == []
    assert module.weaknesses("VULNERABLE")


def test_future_signed_miss_reopens_a_verified_patch(strict_module):
    module, root, _emitted = strict_module
    report_path = root / "redteam_aar.json"

    _write(
        report_path,
        _report("run-a", _verdict("T1003", caught=False, ts_start=60.0)),
    )
    module.ingest_redteam_report(report_path)
    module.resolve_redteam_report(report_path)
    _write(
        report_path,
        _report(
            "run-b",
            _verified_verdict(root, "run-b", ts_start=61.0),
        ),
    )
    module.ingest_redteam_report(report_path)
    assert module.weaknesses("PATCHED")

    _write(
        report_path,
        _report("run-c", _verdict("T1003", caught=False, ts_start=62.0)),
    )
    reopened = module.ingest_redteam_report(report_path)

    assert reopened == [{"mitre": "T1003", "name": "Stage T1003"}]
    assert module.weaknesses("PATCHED") == []
    assert module.weaknesses("VULNERABLE")[0]["mitre_id"] == "T1003"


def test_manual_resolution_dedupes_candidates_and_surfaces_unsupported(strict_module):
    module, root, _emitted = strict_module
    report_path = _write(
        root / "redteam_aar.json",
        _report(
            "run-mixed",
            _verdict("T1003", caught=False, ts_start=70.0, stage="first supported"),
            _verdict("T1003", caught=False, ts_start=71.0, stage="duplicate supported"),
            _verdict("T9999", caught=False, ts_start=72.0, stage="first unsupported"),
            _verdict("T9999", caught=False, ts_start=73.0, stage="duplicate unsupported"),
        ),
    )

    result = module.resolve_redteam_report(report_path)

    assert result["ok"] is True
    assert result["candidates"] == 1
    assert result["unsupported"] == ["T9999"]
    assert [row["mitre"] for row in result["findings"]] == [
        "T1003",
        "T1003",
        "T9999",
        "T9999",
    ]
