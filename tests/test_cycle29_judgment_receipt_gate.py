from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from angerona.core import report_attest
from angerona.core.eventbus import BusAuthority, Event, Severity
from angerona.core.judgment_gate import (
    RECEIPT_SCHEMA,
    TEST_IDENTITY,
    JudgmentVerificationError,
    parse_judgment_receipt,
    run_judgment_verification,
)
from angerona.core.win import popen_hidden
from angerona.modules.intel_sync import IntelSyncModule
from angerona.modules.posture_hardening import PostureHardening


_KEY = b"j" * 32
_NONCE = "a" * 32
_TECHNIQUE = "T1055"
_VERIFIER = "b" * 64
_MARKER = f"_verify_parent_spoof_{_NONCE[:12]}.txt"


def _document(*, outcome: str = "BLOCKED") -> dict:
    event = Event(
        module="File Integrity Monitor",
        message=f"Observed inert marker {_MARKER}",
        severity=Severity.HIGH,
        ts=102.0,
        details={"practice": True},
    )
    event = Event(
        module=event.module,
        message=event.message,
        severity=event.severity,
        ts=event.ts,
        details=event.details,
        hmac_sig=BusAuthority(_KEY).sign(event),
    )
    evidence = {
        "module": event.module,
        "message": event.message,
        "severity": int(event.severity),
        "ts": event.ts,
        "details": event.details,
        "hmac_sig": event.hmac_sig,
    }
    document = {
        "schema": RECEIPT_SCHEMA,
        "nonce": _NONCE,
        "technique_id": _TECHNIQUE,
        "outcome": outcome,
        "test_identity": TEST_IDENTITY,
        "verifier_sha256": _VERIFIER,
        "marker_name": _MARKER,
        "marker_sha256": "c" * 64,
        "started_at": 100.0,
        "completed_at": 105.0,
        "events_examined": 1,
        "event": evidence if outcome == "BLOCKED" else None,
    }
    document[report_attest.SIG_FIELD] = report_attest.sign_doc(document, key=_KEY)
    return document


@pytest.fixture
def authority(monkeypatch, tmp_path):
    monkeypatch.setenv("ANGERONA_DATA", str(tmp_path))
    (tmp_path / "bus.key").write_text(_KEY.hex(), encoding="ascii")


def _parse(document: dict, **overrides):
    kwargs = {
        "returncode": 0,
        "nonce": _NONCE,
        "technique_id": _TECHNIQUE,
        "verifier_sha256": _VERIFIER,
        "launched_at": 100.0,
        "received_at": 106.0,
    }
    kwargs.update(overrides)
    return parse_judgment_receipt(json.dumps(document), **kwargs)


def test_exact_signed_receipt_and_nested_detector_event_are_required(authority) -> None:
    result = _parse(_document())
    assert result.outcome == "BLOCKED"

    tampered = _document()
    tampered["event"]["hmac_sig"] = "0" * 64
    tampered[report_attest.SIG_FIELD] = report_attest.sign_doc(tampered, key=_KEY)
    with pytest.raises(JudgmentVerificationError, match="event HMAC"):
        _parse(tampered)


def test_nonzero_substring_noise_replay_and_wrong_nonce_fail(authority) -> None:
    document = _document()
    with pytest.raises(JudgmentVerificationError, match="status 9"):
        _parse(document, returncode=9)
    with pytest.raises(JudgmentVerificationError, match="one bounded receipt"):
        parse_judgment_receipt(
            "VERIFICATION_RESULT: BLOCKED\n" + json.dumps(document),
            returncode=0,
            nonce=_NONCE,
            technique_id=_TECHNIQUE,
            verifier_sha256=_VERIFIER,
            launched_at=100.0,
            received_at=106.0,
        )
    with pytest.raises(JudgmentVerificationError, match="values"):
        _parse(document, nonce="d" * 32)


def test_success_receipt_is_bypass_evidence_not_detector_evidence(authority) -> None:
    result = _parse(_document(outcome="SUCCESS"))
    assert result.outcome == "SUCCESS"

    ambiguous = _document(outcome="SUCCESS")
    ambiguous["event"] = _document()["event"]
    ambiguous[report_attest.SIG_FIELD] = report_attest.sign_doc(ambiguous, key=_KEY)
    with pytest.raises(JudgmentVerificationError, match="ambiguity"):
        _parse(ambiguous)


def test_intel_blocked_canary_never_claims_rule_install_or_promotion(
    monkeypatch, tmp_path,
) -> None:
    monkeypatch.setenv("ANGERONA_DATA", str(tmp_path))
    module = IntelSyncModule()
    module._pending_confirm["CVE-TEST"] = {
        "cve": "CVE-TEST",
        "mitre": "T1055",
        "remediation": "review",
    }
    module._judgment_verify = lambda _technique: "BLOCKED"
    emitted = []
    module.emit = lambda message, severity, **details: emitted.append(
        (message, severity, details)
    )

    result = module.confirm("CVE-TEST")

    assert result["interception_verified"] is True
    assert result["promoted"] is False
    assert module._pending_confirm["CVE-TEST"]["active"] is False
    assert emitted[-1][2]["installed"] is False


def test_posture_blocked_canary_does_not_close_weakness(monkeypatch, tmp_path) -> None:
    module = PostureHardening(data_dir=tmp_path)
    module.record_weakness(
        "T1055",
        "Injection gap",
        "HIGH",
        remediation_path="",
        source="host",
    )
    receipt = {"schema": RECEIPT_SCHEMA}
    monkeypatch.setattr(
        "angerona.core.judgment_gate.run_judgment_verification",
        lambda *_args, **_kwargs: SimpleNamespace(
            outcome="BLOCKED",
            receipt=receipt,
        ),
    )

    result = module.verify_mitigation("T1055", settle=4.0)

    assert result["interception_verified"] is True
    assert result["patched"] is False
    assert "T1055" not in module._certified
    weakness = next(item for item in module.weaknesses() if item["mitre_id"] == "T1055")
    assert weakness["status"] == "VULNERABLE"


def test_isolated_child_returns_authentic_complete_bypass_receipt(
    monkeypatch, tmp_path,
) -> None:
    monkeypatch.setenv("ANGERONA_DATA", str(tmp_path))
    BusAuthority.generate()

    def isolated_test_process(command, **kwargs):
        # The repository fixture forces the pytest parent into a disposable,
        # non-elevated source-data mode.  That in-process patch cannot cross the
        # real ``-I`` child boundary on an elevated hosted runner, so reproduce
        # the same test-only resolver inside the bootstrap.  No production
        # environment switch or elevated data-root bypass is introduced.
        isolated = list(command)
        assert isolated[1:3] == ["-I", "-c"]
        marker = "sys.path.insert(0,r);"
        assert isolated[3].count(marker) == 1
        isolated[3] = isolated[3].replace(
            marker,
            marker
            + "from angerona.core import data_paths;"
            + "data_paths._elevated_source_runtime=lambda:False;",
            1,
        )
        return popen_hidden(isolated, **kwargs)

    result = run_judgment_verification(
        "T1055",
        settle=4.0,
        process_factory=isolated_test_process,
    )

    assert result.outcome == "SUCCESS"
    assert result.receipt["schema"] == RECEIPT_SCHEMA
    assert result.receipt["event"] is None
