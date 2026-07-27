from __future__ import annotations

import json
from pathlib import Path

import pytest

from angerona.core import report_attest
from angerona.modules.posture_hardening import PostureHardening
from angerona.modules.purple_guard import policy_path


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
            _verdict(
                "T1003",
                caught=True,
                ts_start=52.0,
                detected_by="Purple Remediation Guard",
            ),
        ),
    )
    assert module.ingest_redteam_report(report_path) == []
    assert module.weaknesses("PATCHED")[0]["mitre_id"] == "T1003"


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
            _verdict(
                "T1003",
                caught=True,
                ts_start=61.0,
                detected_by="Purple Remediation Guard",
            ),
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
