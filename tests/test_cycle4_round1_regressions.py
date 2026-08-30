from __future__ import annotations

import json
import time

from angerona.core.eventbus import BusAuthority, Event, Severity


def test_windowed_dashboard_read_skips_contention(tmp_path, monkeypatch) -> None:
    from angerona.core import storage

    authority = BusAuthority(b"z" * 32)
    monkeypatch.setattr(
        storage.BusAuthority, "load", classmethod(lambda cls: authority)
    )
    recorder = storage.FlightRecorder(tmp_path / "events.db")
    try:
        recorder.record(Event("test", "older", Severity.HIGH, ts=10.0))
        recorder.record(Event("test", "newer", Severity.CRITICAL, ts=20.0))

        rows = recorder.try_recent_in_window(15.0, 25.0, Severity.HIGH, 10)
        assert rows is not None
        assert [row.message for row in rows] == ["newer"]

        assert recorder._ui_lock.acquire(blocking=False)
        started = time.perf_counter()
        try:
            assert recorder.try_recent_in_window(
                0.0, 30.0, Severity.INFO, 10
            ) is None
        finally:
            recorder._ui_lock.release()
        assert time.perf_counter() - started < 0.05
    finally:
        recorder.close()


def test_purple_guard_policy_install_deduplicates_findings(tmp_path) -> None:
    from angerona.modules.purple_guard import install_policies

    result = install_policies(
        [
            {"mitre": "T1059"},
            {"mitre": "t1059"},
            {"mitre": "T1003"},
            {"mitre": "T1003"},
            {"mitre": "T9999"},
            {"mitre": "T9999"},
        ],
        "cycle4",
        tmp_path,
    )

    assert result["installed"] == ["T1059", "T1003"]
    assert result["unsupported"] == ["T9999"]
    policy = json.loads((tmp_path / "shared_logs" / "purple_guard_policy.json").read_text())
    assert sorted(policy["techniques"]) == ["T1003", "T1059"]


def test_temporary_drill_response_scope_rejects_unrelated_files(
    tmp_path, monkeypatch
) -> None:
    from angerona.modules.soar_engine import ActiveResponseSOAR

    sandbox = tmp_path / "drill-sandbox"
    sandbox.mkdir()
    marker = sandbox / "_redteam_lsass_dump_deadbeef.txt"
    marker.write_text("inert marker", encoding="utf-8")
    unrelated = sandbox / "family-photo.txt"
    unrelated.write_text("personal data", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("not in scope", encoding="utf-8")
    monkeypatch.setenv("ANGERONA_SOAR_RESPONSE_SCOPE", str(sandbox))
    module = ActiveResponseSOAR()

    def event(path=None, cmdline="", *, contracted=True):
        details = {"cmdline": cmdline}
        if path is not None:
            details["artifact_path"] = str(path)
        if contracted:
            if path is not None:
                actions = ["quarantine_file"]
                targets = {"path": str(path)}
            else:
                actions = ["activate_honeypots"]
                targets = {"deception": "Smart Deception"}
            details.update({
                "response_authorized": True,
                "response_contract": {
                    "version": 1,
                    "actions": actions,
                    "targets": targets,
                },
            })
        return Event("detector", "alert", Severity.HIGH, details=details)

    assert module._event_in_response_scope(event(marker))
    assert not module._event_in_response_scope(event(unrelated))
    assert not module._event_in_response_scope(event(outside))
    assert not module._event_in_response_scope(event(marker, contracted=False))
    assert module._event_in_response_scope(
        event(cmdline="cmd /c rem ANGERONA_REDTEAM_deadbeef")
    )


def test_active_response_defaults_to_critical_and_aar_counts_only_success(
    monkeypatch,
) -> None:
    from angerona.modules.soar_engine import ActiveResponseSOAR
    from angerona.shark.aar_report import _is_remediation

    monkeypatch.delenv("ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY", raising=False)
    assert ActiveResponseSOAR._min_severity() is Severity.CRITICAL
    failed = Event(
        "Active Response SOAR", "no process acted on", Severity.HIGH,
        details={"mitigated": False},
    )
    succeeded = Event(
        "Active Response SOAR", "artifact removed", Severity.HIGH,
        details={"mitigated": True},
    )
    assert not _is_remediation(failed)
    assert _is_remediation(succeeded)


def test_launchers_keep_diagnostics_inside_the_runtime_root() -> None:
    root = __import__("pathlib").Path(__file__).resolve().parents[1]
    canonical = (root / "start-angerona.bat").read_text(encoding="utf-8")
    assert 'set "ANGERONA_DIAG_DIR=%ANGERONA_DATA%\\diagnostics"' in canonical
    assert 'set "ANGERONA_DIAG_DIR=%~dp0diagnostics"' not in canonical
    assert "if not defined ANGERONA_DATA" not in canonical
    assert '%LocalAppData%\\Angerona\\SourceData' in canonical
    guarded = (root / "start-angerona-guarded.bat").read_text(encoding="utf-8")
    assert 'call "%~dp0start-angerona.bat"' in guarded
    assert "ANGERONA_DATA" not in guarded
    assert 'angerona_watchdog.exe "venv\\Scripts\\pythonw.exe"' not in guarded


def test_signed_aar_is_default_and_attestation_selftest_preserves_policy(
    monkeypatch,
) -> None:
    from angerona.core.config import Config
    from angerona.core import report_attest

    assert Config().require_signed_aar is True
    monkeypatch.setenv("ANGERONA_REQUIRE_SIGNED_AAR", "1")
    ok, _detail = report_attest.self_test()
    assert ok
    assert report_attest.strict_mode()


def test_deep_alert_analysis_has_separate_default_off_cloud_consent() -> None:
    from angerona.core.config import Config

    config = Config()
    assert config.aria_cloud_fallback is False
    assert config.alert_analysis_cloud_fallback is False
