from __future__ import annotations

from pathlib import Path

from defusedxml import ElementTree as ET

from angerona.core.practice_scope import register_artifact, unregister_run
from angerona.modules.file_integrity import _combat_file_contract, _registered_benign_noise
from angerona.modules import network_monitor, process_monitor
from angerona.modules.network_monitor import _block_remote_contract
from angerona.modules.process_monitor import ProcessMonitorModule
from angerona.modules.purple_guard import PurpleGuard, install_policies
from angerona.modules.sysmon_listener import _build_details


def test_fim_benign_noise_requires_exact_live_red_team_provenance(tmp_path: Path) -> None:
    marker = tmp_path / "_redteam_benign_note_probe.txt"
    marker.write_text("inert", encoding="utf-8")

    assert _registered_benign_noise(str(marker)) is False
    register_artifact(marker, "producer-test-red-team", kind="red-team")
    try:
        assert _registered_benign_noise(str(marker)) is True
        lookalike = tmp_path / "_redteam_benign_note_lookalike.txt"
        lookalike.write_text("unregistered", encoding="utf-8")
        assert _registered_benign_noise(str(lookalike)) is False
    finally:
        unregister_run("producer-test-red-team")


def test_office_child_heuristic_is_alert_only() -> None:
    module = ProcessMonitorModule()
    module._names[7] = "winword.exe"
    emitted = []
    module.emit = lambda message, severity, **details: emitted.append(details)

    module._evaluate(
        {
            "pid": 42,
            "ppid": 7,
            "name": "powershell.exe",
            "exe": r"C:\Users\me\Downloads\powershell.exe",
            "create_time": 1234.5,
        },
        {},
    )

    details = emitted[-1]
    assert details["pid"] == 42
    assert details["process_create_time"] == 1234.5
    assert "response_contract" not in details


def test_office_child_without_process_identity_is_not_response_authorized() -> None:
    module = ProcessMonitorModule()
    module._names[7] = "winword.exe"
    emitted = []
    module.emit = lambda message, severity, **details: emitted.append(details)

    module._evaluate(
        {"pid": 42, "ppid": 7, "name": "cmd.exe", "exe": "cmd.exe"},
        {},
    )

    assert "response_authorized" not in emitted[-1]


def test_reviewed_purple_file_policy_contracts_only_exact_artifact(tmp_path: Path) -> None:
    install_policies([{"mitre": "T1003"}], "producer-test", tmp_path)
    sandbox = tmp_path / "drill-sandbox"
    sandbox.mkdir()
    marker = sandbox / "_redteam_lsass_dump_probe.txt"
    marker.write_text("inert", encoding="utf-8")
    emitted = []
    module = PurpleGuard(tmp_path)
    module.emit = lambda message, severity, **details: emitted.append(details)

    assert module.scan_once() == 1
    contract = emitted[-1]["response_contract"]
    assert contract["actions"] == ["quarantine_file"]
    assert contract["targets"] == {"path": str(marker)}


def test_suspicious_port_alone_has_no_firewall_authority() -> None:
    assert _block_remote_contract("203.0.113.9") == {}


def test_corroborated_network_contract_binds_one_normalized_ip() -> None:
    assert _block_remote_contract(
        "203.0.113.9",
        corroborated=True,
        classification="threat-intel-ioc",
    ) == {
        "response_authorized": True,
        "response_classification": "threat-intel-ioc",
        "response_contract": {
            "version": 1,
            "actions": ["block_remote_ip"],
            "targets": {"remote_ips": ["203.0.113.9"]},
        },
    }


def test_combat_sensor_cache_age_is_fresher_than_poll_cadence(
    monkeypatch,
) -> None:
    monkeypatch.setenv("ANGERONA_ADVERSARY_COMBAT_ENABLED", "1")
    monkeypatch.setenv("ANGERONA_ADVERSARY_COMBAT_MODE", "maximum")
    assert network_monitor._snapshot_max_age() == 0.375
    assert network_monitor._snapshot_max_age() < network_monitor._poll_interval()
    assert process_monitor._snapshot_max_age() == 0.5


def test_generic_fim_change_has_no_response_authority() -> None:
    assert _combat_file_contract(r"C:\Users\me\Documents\notes.txt") == {}


def test_name_only_known_bad_driver_has_no_response_authority() -> None:
    assert _combat_file_contract(
        r"C:\evidence\rtcore64.sys",
        allow_host_isolation=True,
        allow_deception=True,
    ) == {}


def test_registered_byovd_practice_contract_is_exact(tmp_path: Path) -> None:
    marker = tmp_path / "angerona_byovd_drill.sys"
    marker.write_text("inert", encoding="utf-8")
    assert _combat_file_contract(str(marker), allow_host_isolation=True) == {}
    register_artifact(marker, "producer-test-byovd", kind="red-team")
    try:
        contract = _combat_file_contract(
            str(marker),
            allow_host_isolation=True,
            allow_deception=True,
        )["response_contract"]
    finally:
        unregister_run("producer-test-byovd")
    assert contract["targets"] == {
        "path": str(marker),
        "host": "local",
        "deception": "Smart Deception",
    }


def test_raw_sysmon_injection_has_no_destructive_response_authority() -> None:
    root = ET.fromstring(
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><EventData>"
        "<Data Name='SourceImage'>C:\\Users\\me\\payload.exe</Data>"
        "<Data Name='SourceProcessId'>42</Data>"
        "<Data Name='TargetImage'>C:\\Windows\\System32\\lsass.exe</Data>"
        "<Data Name='TargetProcessId'>500</Data>"
        "</EventData></Event>"
    )
    details = _build_details(8, root, "CreateRemoteThread", ["T1055.003"])

    assert details["response_authorized"] is False
    assert details["image"] == r"C:\Users\me\payload.exe"
    assert "response_contract" not in details
