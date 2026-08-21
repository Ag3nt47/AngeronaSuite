from __future__ import annotations

import json
import os
import socket
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import angerona.core.security_scan_center as scan_module
from angerona.core.security_scan_center import (
    MAX_FILE_BYTES,
    MAX_SCAN_BYTES,
    MAX_SCAN_FILES,
    ScanCancellationToken,
    ScanFinding,
    ScanProgress,
    SecurityScanCenter,
)


class _FakeCompiler:
    def add_include_dir(self, _path):
        return None

    def add_source(self, _source, *, origin):
        assert origin.endswith("rules.yar")

    def build(self):
        return object()


class _FakeYaraScanner:
    def __init__(self, _compiled):
        self.paths: list[str] = []

    def set_timeout(self, value):
        assert 1 <= value <= 10

    def max_matches_per_pattern(self, value):
        assert value == 64

    def fast_scan(self, value):
        assert value is True

    def scan_file(self, path):
        self.paths.append(path)
        matches = [SimpleNamespace(identifier="Test_Malware")] if path.endswith("sample.exe") else []
        return SimpleNamespace(matching_rules=matches)


class _FakeYara:
    Compiler = _FakeCompiler
    Scanner = _FakeYaraScanner


class _NoRemoteMounts:
    @staticmethod
    def disk_partitions(*, all):
        assert all is True
        return []


def _center(**kwargs) -> SecurityScanCenter:
    return SecurityScanCenter(psutil_module=_NoRemoteMounts(), yara_module=_FakeYara, **kwargs)


def test_records_are_gui_and_json_friendly() -> None:
    finding = ScanFinding(
        "scan.test", "low", "Test", "Bounded observation", ("evidence",), ("review",)
    )
    progress = ScanProgress("scan", 1, 2, "working")

    assert finding.to_dict()["severity"] == "low"
    assert progress.to_dict() == {
        "phase": "scan", "completed": 1, "total_limit": 2, "detail": "working"
    }
    json.dumps(finding.to_dict())
    with pytest.raises(ValueError, match="severity"):
        ScanFinding("scan.bad", "urgent", "Test", "No")


def test_configurable_limits_can_only_reduce_global_caps() -> None:
    center = SecurityScanCenter(
        max_files=MAX_SCAN_FILES + 1,
        max_total_bytes=MAX_SCAN_BYTES + 1,
        max_file_bytes=MAX_FILE_BYTES + 1,
    )
    assert center.max_files == MAX_SCAN_FILES
    assert center.max_total_bytes == MAX_SCAN_BYTES
    assert center.max_file_bytes == MAX_FILE_BYTES
    with pytest.raises(ValueError, match="positive"):
        SecurityScanCenter(max_files=0)


def test_scan_path_runs_yara_and_metadata_without_exposing_selected_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resources = tmp_path / "resources"
    resources.mkdir()
    (resources / "rules.yar").write_text("rule Test { condition: true }", encoding="utf-8")
    monkeypatch.setattr(scan_module, "resource_root", lambda: resources)
    selected = tmp_path / "private-user-root"
    selected.mkdir()
    (selected / "sample.exe").write_bytes(b"MZ harmless test")
    (selected / "invoice.pdf.exe").write_bytes(b"not a PE")
    progress = []

    result = _center().scan_path(selected, progress=progress.append)
    payload = result.to_dict()
    rendered = json.dumps(payload)

    assert result.status == "completed"
    assert result.executed is True
    assert result.metrics["files_scanned"] == 2
    assert result.metrics["yara_status"] == "active"
    assert any(item.category == "Malware signatures" for item in result.findings)
    assert any("double extension" in item.title for item in result.findings)
    assert "private-user-root" not in rendered
    assert "harmless test" not in rendered
    assert progress[-1].phase == "completed"


def test_scan_path_never_follows_a_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resources = tmp_path / "resources"
    resources.mkdir()
    (resources / "rules.yar").write_text("rule Test { condition: true }", encoding="utf-8")
    monkeypatch.setattr(scan_module, "resource_root", lambda: resources)
    selected = tmp_path / "selected"
    outside = tmp_path / "outside"
    selected.mkdir()
    outside.mkdir()
    (outside / "sample.exe").write_bytes(b"MZ outside")
    try:
        (selected / "escape").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are unavailable for this test account")

    result = _center().scan_path(selected)

    assert result.metrics["files_scanned"] == 0
    assert not result.findings


def test_scan_rejects_remote_missing_and_link_roots(tmp_path: Path) -> None:
    center = _center()
    assert center.scan_path(r"\\server\share").status == "rejected"
    assert center.scan_path(tmp_path / "missing").status == "rejected"
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        return
    assert center.scan_path(link).status == "rejected"


def test_scan_honors_file_budget_and_cancellation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resources = tmp_path / "resources"
    resources.mkdir()
    (resources / "rules.yar").write_text("rule Test { condition: true }", encoding="utf-8")
    monkeypatch.setattr(scan_module, "resource_root", lambda: resources)
    selected = tmp_path / "selected"
    selected.mkdir()
    (selected / "one.txt").write_bytes(b"1234")
    (selected / "two.txt").write_bytes(b"5678")
    limited = _center(max_files=1).scan_path(selected)
    assert limited.status == "limited"
    assert limited.metrics["files_scanned"] == 1

    token = ScanCancellationToken()
    token.cancel()
    cancelled = _center().scan_path(selected, cancellation=token)
    assert cancelled.status == "cancelled"
    assert cancelled.metrics["files_scanned"] == 0


class _FakePsutilExposure:
    CONN_LISTEN = "LISTEN"

    @staticmethod
    def net_connections(*, kind):
        assert kind == "inet"
        return [
            SimpleNamespace(status="LISTEN", laddr=("0.0.0.0", 445), pid=100),
            SimpleNamespace(status="LISTEN", laddr=("127.0.0.1", 8080), pid=101),
            SimpleNamespace(status="ESTABLISHED", laddr=("10.0.0.7", 443), pid=102),
        ]

    @staticmethod
    def Process(pid):
        names = {100: "smbservice.exe", 101: "devserver.exe"}
        return SimpleNamespace(name=lambda: names[pid])


def test_passive_listener_audit_redacts_addresses_and_process_ids() -> None:
    center = SecurityScanCenter(psutil_module=_FakePsutilExposure())

    result = center.audit_listening_exposure()
    rendered = json.dumps(result.to_dict())

    assert result.status == "completed"
    assert result.metrics["listeners_reviewed"] == 2
    assert result.metrics["all_interface_listeners"] == 1
    assert any(item.severity == "high" and "SMB" in item.title for item in result.findings)
    assert "0.0.0.0" not in rendered
    assert "127.0.0.1" not in rendered
    assert '"pid"' not in rendered.casefold()
    assert "no packets were captured or transmitted" in result.summary.casefold()


def test_listener_audit_degrades_honestly_without_psutil(monkeypatch: pytest.MonkeyPatch) -> None:
    center = SecurityScanCenter()
    monkeypatch.setattr(center, "_psutil_module", lambda: None)
    result = center.audit_listening_exposure()
    assert result.status == "unsupported"
    assert result.supported is False


class _FakePsutilNetwork:
    @staticmethod
    def net_if_stats():
        return {
            "Secret WiFi Name": SimpleNamespace(isup=True),
            "Loopback Internal": SimpleNamespace(isup=True),
        }

    @staticmethod
    def net_if_addrs():
        return {
            "Secret WiFi Name": [SimpleNamespace(family=socket.AF_INET, address="8.8.8.8")],
            "Loopback Internal": [SimpleNamespace(family=socket.AF_INET, address="127.0.0.1")],
        }


def test_network_posture_is_aggregate_only() -> None:
    result = SecurityScanCenter(psutil_module=_FakePsutilNetwork()).summarize_network_posture()
    rendered = json.dumps(result.to_dict())

    assert result.metrics["active_interfaces"] == 2
    assert result.metrics["active_wireless_interfaces"] == 1
    assert result.metrics["global_address_count"] == 1
    assert any(item.finding_id == "network.global-address" for item in result.findings)
    assert "Secret WiFi Name" not in rendered
    assert "8.8.8.8" not in rendered
    assert "127.0.0.1" not in rendered


def _defender_fixture(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "ProgramData" / "Microsoft" / "Windows Defender"
    executable = root / "Platform" / "1.2.3" / "MpCmdRun.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"test executable placeholder")
    return root, executable


def test_defender_is_honestly_unsupported_off_windows() -> None:
    result = SecurityScanCenter(platform_system="Linux").run_microsoft_defender_scan(execute=True)
    assert result.status == "unsupported"
    assert result.executed is False


def test_defender_preview_is_explicit_and_path_private(tmp_path: Path) -> None:
    root, executable = _defender_fixture(tmp_path)
    target = tmp_path / "private target"
    target.mkdir()
    center = SecurityScanCenter(
        platform_system="Windows",
        trusted_defender_roots=(root,),
        trusted_defender_executable=executable,
        psutil_module=_NoRemoteMounts(),
    )

    result = center.run_microsoft_defender_scan(target)
    rendered = json.dumps(result.to_dict())

    assert result.status == "preview"
    assert result.executed is False
    assert result.metrics["remediation_disabled"] is True
    assert result.metrics["preview_argv"][-1] == "<selected-local-target>"
    assert "private target" not in rendered


def test_defender_execution_uses_strict_argv_and_discards_output(tmp_path: Path) -> None:
    root, executable = _defender_fixture(tmp_path)
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0)

    center = SecurityScanCenter(
        platform_system="Windows",
        trusted_defender_roots=(root,),
        trusted_defender_executable=executable,
        defender_runner=runner,
    )
    result = center.run_microsoft_defender_scan(execute=True, quick=True)
    rendered = json.dumps(result.to_dict())

    assert result.status == "completed"
    assert result.executed is True
    assert calls[0][0] == [
        str(executable.resolve()), "-Scan", "-ScanType", "1"
    ]
    assert "shell" not in calls[0][1]
    assert calls[0][1]["check"] is False
    assert calls[0][1]["stdout"] is subprocess.DEVNULL
    assert calls[0][1]["stderr"] is subprocess.DEVNULL
    assert result.metrics["output_capture"] == "disabled"
    assert result.metrics["remediation_disabled"] is False
    assert result.metrics["configured_threat_actions_possible"] is True
    assert "configured Defender threat actions" in result.summary
    assert "Users" not in rendered
    assert "192.0.2.1" not in rendered


def test_defender_refuses_untrusted_executable_and_cancelled_run(tmp_path: Path) -> None:
    root, executable = _defender_fixture(tmp_path)
    empty_root = tmp_path / "Program Files" / "Windows Defender"
    empty_root.mkdir(parents=True)
    outside = tmp_path / "untrusted" / "MpCmdRun.exe"
    outside.parent.mkdir()
    outside.write_bytes(b"not trusted")
    rejected = SecurityScanCenter(
        platform_system="Windows",
        trusted_defender_roots=(empty_root,),
        trusted_defender_executable=outside,
    ).run_microsoft_defender_scan(execute=True)
    assert rejected.status == "unsupported"

    token = ScanCancellationToken()
    token.cancel()
    cancelled = SecurityScanCenter(
        platform_system="Windows",
        trusted_defender_roots=(root,),
        trusted_defender_executable=executable,
    ).run_microsoft_defender_scan(execute=True, cancellation=token)
    assert cancelled.status == "cancelled"
    assert cancelled.executed is False


def test_no_api_accepts_remote_host_or_attack_parameters() -> None:
    public = {
        name for name in dir(SecurityScanCenter)
        if not name.startswith("_") and callable(getattr(SecurityScanCenter, name))
    }
    assert public == {
        "audit_listening_exposure",
        "run_microsoft_defender_scan",
        "scan_path",
        "summarize_network_posture",
    }
    source = Path(scan_module.__file__).read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert "quarantine(" not in source.casefold()
    assert "socket.connect" not in source
