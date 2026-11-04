"""Independent browser contact and local override observations."""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import json
from types import SimpleNamespace

import pytest

from angerona.core import security_scan_center, spyware_artifact_scan as artifact_scan
from angerona.core.spyware_artifact_scan import chromium_hsts_findings, hosts_findings, scan_chromium_hsts


def test_chromium_requires_an_exact_hsts_key_and_marks_an_advisory():
    wire = b"\x0etracookiepixel\x03xyz\x00"
    key = base64.b64encode(hashlib.sha256(wire).digest()).decode("ascii")
    raw = json.dumps({"sts": [
        {"host": "prefix" + key, "mode": "force-https", "sts_observed": 1788000000},
        {"host": key, "mode": "force-https", "sts_observed": 1788000000},
        {"host": key, "mode": "force-https", "sts_observed": 1788000030},
    ]}).encode()
    findings = chromium_hsts_findings(raw, cancelled=lambda: False)
    assert len(findings) == 1
    assert findings[0]["indicator"] == "tracookiepixel.xyz"
    assert findings[0]["observed_at"] == 1788000030
    assert findings[0]["response_authorized"] is False


def test_invalid_chromium_store_reports_a_gap(tmp_path):
    root = tmp_path / "browser"
    artifact = root / "Default" / "Network" / "TransportSecurity"
    artifact.parent.mkdir(parents=True)
    artifact.write_text('{"sts":[],"sts":[]}', encoding="utf-8")
    result = scan_chromium_hsts(cancelled=lambda: False, roots=(("Fixture", root),))
    assert result == {"state": "partial", "checked": 0, "skipped": 1, "findings": []}
    with pytest.raises(ValueError, match="Repeated"):
        chromium_hsts_findings(artifact.read_bytes(), cancelled=lambda: False)


def test_hosts_matching_is_exact_and_preserves_local_block_context():
    raw = b"127.0.0.1 tracookiepixel.xyz.example\n# 1.2.3.4 tracookiepixel.xyz\n0.0.0.0 cookie-sync.xyz\n"
    findings = hosts_findings(raw, cancelled=lambda: False)
    assert [row["indicator"] for row in findings] == ["cookie-sync.xyz"]
    assert findings[0]["loopback_or_unspecified"] is True
    assert findings[0]["response_authorized"] is False


def test_windows_temp_setting_uses_only_reviewed_aliases():
    root = artifact_scan._windows_temp_path(r"%userprofile%\Custom Temp",
                                            aliases={"USERPROFILE": r"D:\Operator"})
    assert str(root) == r"D:\Operator\Custom Temp"
    with pytest.raises(ValueError, match="unresolved"):
        artifact_scan._windows_temp_path(r"%PRIVATE_TOKEN%\Temp",
                                         aliases={"PRIVATE_TOKEN": r"D:\Operator"})


@pytest.mark.parametrize("path", [
    r"\\server\share\Temp", r"\\?\D:\Temp", r"D:Temp", "D:\\",
    r"D:\Parent\..\Temp", r"D:\Parent\.\Temp", r"D:\Temp:alternate",
    r"D:\Parent\NUL.txt", r"D:\Parent\Temp.", "D:\\Parent\\Temp ",
    "D:\\Temp\0other", "D:\\" + "x" * 4096,
])
def test_windows_temp_setting_rejects_unsafe_paths_before_probing(path):
    with pytest.raises(ValueError):
        artifact_scan._windows_temp_path(path)


@pytest.mark.parametrize(("hold", "reason"), [
    ("setting", "setting-unverified"),
    ("nonfixed", "scope-unverified"),
    ("reparse", "scope-unverified"),
    ("cancelled", "cancelled"),
])
def test_windows_temp_reader_holds_unsafe_scope_without_opening_files(tmp_path, monkeypatch, hold, reason):
    root = tmp_path / "private-configured-temp"
    monkeypatch.setattr(artifact_scan, "sys", SimpleNamespace(platform="win32"))

    def configured():
        if hold == "cancelled":
            pytest.fail("Cancelled request read the setting")
        if hold == "setting":
            raise OSError(f"Unable to read configuration: {root}")
        return root

    def hold_plain(path):
        assert path == root and hold == "reparse"
        raise OSError(f"reparse: {root}")

    monkeypatch.setattr(artifact_scan, "_configured_windows_temp", configured)
    monkeypatch.setattr(artifact_scan, "_is_local_root", lambda path: hold != "nonfixed")
    monkeypatch.setattr(artifact_scan, "_hold_plain_directories", hold_plain)
    monkeypatch.setattr(artifact_scan, "scan_selected_paths",
                        lambda *_args, **_kwargs: pytest.fail("Held scope reached file scanner"))
    result = artifact_scan.scan_windows_user_temp(cancelled=lambda: hold == "cancelled")
    assert result["state"] == ("partial" if hold == "cancelled" else "unavailable")
    assert result["reason"] == reason
    assert result["checked"] == 0 and result["findings"] == []
    assert "private-configured-temp" not in json.dumps(result)


@pytest.mark.parametrize(("scan_status", "files_scanned", "yara_status", "extra_metrics", "reason"), [
    ("completed", 2, "active", {}, None),
    ("completed", 2, "unavailable", {}, "signatures-unavailable"),
    ("limited", 64, "active", {}, "file-budget"),
    ("limited", 0, "active", {"traversal_limit_reason": "directory-queue-limit"}, "directory-queue-limit"),
    ("cancelled", 1, "active", {}, "cancelled"),
])
def test_windows_temp_reader_reuses_bounded_scan_and_keeps_paths_private(
    tmp_path, monkeypatch, scan_status, files_scanned, yara_status, extra_metrics, reason,
):
    root = tmp_path / "private-configured-temp"
    held = False
    monkeypatch.setattr(artifact_scan, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(artifact_scan, "_configured_windows_temp", lambda: root)
    monkeypatch.setattr(artifact_scan, "_is_local_root", lambda path: path == root)

    @contextmanager
    def hold_plain(path):
        nonlocal held
        assert path == root
        held = True
        try:
            yield
        finally:
            held = False

    sampling_modes = []

    class Scanner:
        def __init__(self, **limits):
            sampling_modes.append(limits.pop("sample_recent_root_directories", False))
            assert limits == {
                "max_files": 64, "max_total_bytes": 32 * 1024**2, "max_file_bytes": 4 * 1024**2,
                "max_directory_entries": 256, "max_directories": 32, "max_duration_seconds": 12,
            }

        def scan_path(self, selected, *, cancellation):
            assert selected == root and held and not cancellation.cancelled
            return SimpleNamespace(
                status=scan_status,
                metrics={"files_scanned": files_scanned, "yara_status": yara_status, **extra_metrics},
                findings=[SimpleNamespace(title="Review a file", finding_id="file.inert",
                                          evidence=(str(root / "private.exe"),))],
                errors=(f"Diagnostic with private path: {root}",),
            )

    monkeypatch.setattr(artifact_scan, "_hold_plain_directories", hold_plain)
    monkeypatch.setattr(security_scan_center, "SecurityScanCenter", Scanner)
    result = artifact_scan.scan_windows_user_temp(cancelled=lambda: False)
    assert sampling_modes == [True]
    expected_state = "partial" if reason else "completed"
    assert not held and result["state"] == expected_state and result["checked"] == files_scanned
    assert result["skipped"] == int(expected_state == "partial")
    assert result.get("reason") == reason
    assert result["findings"] == [{
        "classification": "advisory", "evidence_type": "windows-temp-file",
        "summary": "Review a file", "finding_id": "file.inert", "response_authorized": False,
    }]
    assert "private-configured-temp" not in json.dumps(result) and "private.exe" not in json.dumps(result)

    if reason == "directory-queue-limit":
        with hold_plain(root):
            selected = artifact_scan.scan_selected_paths((root,), cancelled=lambda: False)
        assert sampling_modes == [True, False]
        assert selected == {"state": "partial", "checked": 0, "skipped": 1, "findings": [{
            "classification": "advisory", "evidence_type": "selected-path-signature",
            "summary": "Review a file", "finding_id": "file.inert", "response_authorized": False,
        }]}


@pytest.mark.parametrize(("status", "metrics", "reason"), [
    ("rejected", {}, "rejected"),
    ("limited", {"traversal_limit_reason": "directory-limit"}, "directory-limit"),
    ("limited", {"traversal_limit_reason": "directory-entry-limit"}, "directory-entry-limit"),
    ("limited", {"timed_out": True, "traversal_limit_reason": "directory-queue-limit"}, "deadline"),
    ("limited", {"budget_skips": 1}, "byte-budget"),
    ("limited", {"bytes_scanned": 32 * 1024**2}, "byte-budget"),
    ("limited", {"oversize_files_skipped": 1}, "per-file-budget"),
    ("limited", {"signature_limit_reached": True}, "signature-limit"),
    ("limited", {"timed_out": 1, "budget_skips": True, "traversal_limit_reason": "C:/Private/Temp"},
     "scan-limited"),
    ("completed", {}, "scan-unconfirmed"),
])
def test_windows_temp_reason_requires_a_closed_status_and_typed_metrics(status, metrics, reason):
    assert artifact_scan._windows_temp_scan_reason(status, metrics) == reason


def test_legacy_chromium_store_is_reviewed_when_network_store_is_absent(tmp_path):
    root = tmp_path / "browser"
    profile = root / "Default"
    (profile / "Network").mkdir(parents=True)
    (profile / "TransportSecurity").write_text('{"sts":[]}', encoding="utf-8")
    result = scan_chromium_hsts(cancelled=lambda: False, roots=(("Fixture", root),))
    assert result == {"state": "completed", "checked": 1, "skipped": 0, "findings": []}
