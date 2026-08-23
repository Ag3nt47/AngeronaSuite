from __future__ import annotations

from pathlib import Path

import pytest

from angerona.core import practice_scope
from angerona.core.eventbus import Event, Severity
from angerona.core.threat import event_disposition, is_active_threat
from angerona.modules.av_telemetry_bridge import _local_artifact_paths
from angerona.modules.evidence_lattice import EvidenceLattice
from angerona.shark.red_team import RedTeamEngine


@pytest.fixture(autouse=True)
def _empty_practice_scope():
    practice_scope.clear()
    yield
    practice_scope.clear()


def _critical(module: str, message: str = "detected", **details) -> Event:
    return Event(module, message, Severity.CRITICAL, details=details)


@pytest.mark.parametrize(
    "event_type",
    [
        "usb_approval_required",
        "usb_approval_rejected",
        "usb_pin_lockout",
        "usb_media_risk",
        "usb_autorun_policy",
    ],
)
def test_usb_policy_and_approval_events_are_exposure_not_active(event_type: str) -> None:
    event = _critical(
        "Removable-Media / USB Monitor",
        event_type=event_type,
        mountpoint="E:\\",
    )

    assert event_disposition(event) == "exposure"
    assert not is_active_threat(event)


def test_explicit_active_usb_attack_evidence_still_wins() -> None:
    event = _critical(
        "Removable-Media / USB Monitor",
        event_type="usb_media_risk",
        mountpoint="E:\\",
        active_attack=True,
    )

    assert event_disposition(event) == "active"
    assert is_active_threat(event)


def test_unregistered_redteam_lookalike_and_simulated_claim_remain_active(
    tmp_path: Path,
) -> None:
    fake = tmp_path / "_redteam_lsass_dump_forged.txt"
    event = _critical(
        "File Integrity Monitor",
        f"NEW _redteam_ marker (simulated): {fake}",
        path=str(fake),
        simulated=True,
        practice=True,
    )

    assert event_disposition(event) == "active"
    assert is_active_threat(event)


def test_only_exact_registered_artifact_is_practice(tmp_path: Path) -> None:
    run_id = "redteam-registered-abc123"
    registered = tmp_path / "one" / "_redteam_lsass_dump_same.txt"
    lookalike = tmp_path / "two" / registered.name
    practice_scope.register_artifact(registered, run_id, kind="red-team")

    exact = _critical("File Integrity Monitor", path=str(registered))
    copied_name = _critical("File Integrity Monitor", path=str(lookalike))

    assert event_disposition(exact) == "practice"
    assert not is_active_threat(exact)
    assert event_disposition(copied_name) == "active"


def test_completed_run_revokes_artifact_and_process_provenance(tmp_path: Path) -> None:
    run_id = "redteam-finished-abc123"
    marker = tmp_path / "_redteam_lsass_dump_reused.txt"
    token = "ANGERONA_REDTEAM_deadbeef"
    practice_scope.register_artifact(marker, run_id, kind="red-team")
    practice_scope.register_process(token, run_id, pid=4242, kind="red-team")

    assert event_disposition(_critical("FIM", path=str(marker))) == "practice"
    assert event_disposition(_critical(
        "Telemetry Scanner", correlation_token=token, pid=4242,
    )) == "practice"
    assert practice_scope.unregister_run(run_id) == 3
    assert event_disposition(_critical("FIM", path=str(marker))) == "active"
    assert event_disposition(_critical(
        "Telemetry Scanner", correlation_token=token, pid=4242,
    )) == "active"


def test_registered_process_requires_exact_token_and_pid() -> None:
    token = "ANGERONA_REDTEAM_deadbeef"
    practice_scope.register_process(token, "redteam-run-1", pid=4242)

    exact = _critical(
        "Purple Remediation Guard",
        event_type="purple_process_detection",
        pid=4242,
        correlation_token=token,
    )
    wrong_pid = _critical(
        "Purple Remediation Guard",
        event_type="purple_process_detection",
        pid=9999,
        correlation_token=token,
    )
    forged = _critical(
        "Purple Remediation Guard",
        event_type="purple_process_detection",
        pid=4242,
        correlation_token="ANGERONA_REDTEAM_cafebabe",
    )

    assert event_disposition(exact) == "practice"
    assert event_disposition(wrong_pid) == "active"
    assert event_disposition(forged) == "active"


def test_practice_registration_expires(monkeypatch: pytest.MonkeyPatch,
                                       tmp_path: Path) -> None:
    clock = [100.0]
    monkeypatch.setattr(practice_scope.time, "monotonic", lambda: clock[0])
    marker = tmp_path / "marker.txt"
    practice_scope.register_artifact(marker, "run-expiring", ttl=1.0)
    event = _critical("YARA Scanner", path=str(marker))
    assert event_disposition(event) == "practice"

    clock[0] = 102.0
    assert event_disposition(event) == "active"


def test_integrity_verification_failure_is_not_passive_exposure() -> None:
    event = _critical(
        "Posture Hardening",
        "AAR authenticity verification failed; report refused",
        fail_closed=True,
    )

    assert event_disposition(event) == "active"


def test_passive_vulnerability_is_exposure_but_active_exploitation_wins() -> None:
    passive = _critical(
        "Vulnerability Assessment",
        source="cisa_kev",
        finding_kind="passive_vulnerability",
        cve="CVE-2026-12345",
    )
    exploited = _critical(
        "Vulnerability Assessment",
        source="cisa_kev",
        finding_kind="passive_vulnerability",
        cve="CVE-2026-12345",
        active_exploitation=True,
    )

    assert event_disposition(passive) == "exposure"
    assert event_disposition(exploited) == "active"


def test_health_reporting_and_defender_state_do_not_claim_active_attack() -> None:
    module_crash = Event(
        "Process Monitor",
        "Module crashed (attempt 1/3), restarting in 1s",
        Severity.HIGH,
    )
    heal_patch = Event(
        "HEAL",
        "Bug detected; proposed patch staged for review",
        Severity.HIGH,
    )
    defender_disabled = Event(
        "AV Telemetry Bridge",
        "Defender real-time protection disabled",
        Severity.CRITICAL,
        details={"eid": 5001},
    )
    defender_detection = Event(
        "AV Telemetry Bridge",
        "Defender detected malware",
        Severity.CRITICAL,
        details={"eid": 1116},
    )

    assert event_disposition(module_crash) == "health"
    assert event_disposition(heal_patch) == "health"
    assert event_disposition(defender_disabled) == "health"
    assert event_disposition(defender_detection) == "active"


def test_evidence_lattice_never_promotes_passive_exposure_to_live_attack() -> None:
    lattice = EvidenceLattice(window_s=30.0)
    results = []
    for index, module in enumerate(
        ("Vulnerability Assessment", "CISA KEV", "Upstream Threat Intel Sync")
    ):
        results.append(
            lattice.ingest(
                Event(
                    module,
                    "applicable vulnerability",
                    Severity.MEDIUM,
                    ts=float(index + 1),
                    details={
                        "pid": 4242,
                        "finding_kind": "passive_vulnerability",
                    },
                ),
                now=float(index + 1),
            )
        )

    assert results == [None, None, None]


def test_posture_practice_gap_requires_structured_authenticated_source() -> None:
    structured = _critical(
        "Posture Hardening",
        "display text does not establish trust",
        source="redteam",
        finding_kind="practice_gap",
        practice_run_id="old-signed-run",
    )
    message_only = _critical(
        "Posture Hardening",
        "NEW WEAKNESS (Red Team): simulated drill marker slipped past detection",
    )

    assert event_disposition(structured) == "practice"
    assert event_disposition(message_only) == "active"


def test_redteam_engine_registers_exact_marker_before_detection(tmp_path: Path) -> None:
    target = tmp_path / "target"
    engine = RedTeamEngine(tmp_path / "data", documents_dir=target)
    engine.run_id = "redteam-unit-123456"
    practice_scope.register_run(engine.run_id, kind="red-team")

    marker = engine._marker("_redteam_lsass_dump_12345678.txt", "inert")
    exact = _critical("File Integrity Monitor", path=str(marker))
    other = _critical(
        "File Integrity Monitor",
        path=str(target / "_redteam_lsass_dump_87654321.txt"),
    )

    assert event_disposition(exact) == "practice"
    assert event_disposition(other) == "active"


def test_defender_resource_normalization_is_local_and_unambiguous() -> None:
    assert _local_artifact_paths(r"file:_C:\Users\Alice\Downloads\eicar.txt") == (
        r"C:\Users\Alice\Downloads\eicar.txt",
    )
    assert _local_artifact_paths([
        r"file:_C:\one.txt",
        r"file:_D:\two.txt",
    ]) == (r"C:\one.txt", r"D:\two.txt")
    assert not _local_artifact_paths(r"containerfile:_C:\archive.zip")
    assert not _local_artifact_paths(r"file:_\\server\share\sample.txt")
    assert not _local_artifact_paths([r"file:_C:\safe.txt", "process:_1234"])


def test_mixed_defender_resources_cannot_hide_a_real_file() -> None:
    practice = r"C:\Drill\eicar.txt"
    malicious = r"C:\Temp\payload.exe"
    practice_scope.register_artifact(practice, "shark-run-one", kind="shark")
    mixed = _critical(
        "AV Telemetry Bridge",
        artifact_paths=[practice, malicious],
    )
    exact = _critical(
        "AV Telemetry Bridge",
        artifact_path=practice,
        artifact_paths=[practice],
    )

    assert event_disposition(mixed) == "active"
    assert event_disposition(exact) == "practice"
