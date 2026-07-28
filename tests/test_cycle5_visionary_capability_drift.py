from __future__ import annotations

import hashlib
import json
from pathlib import Path

from angerona.enterprise_capability_drift_c5 import (
    audit_manifested_source,
    audit_source,
)


def _manifest(path: Path, permissions: list[str], **overrides) -> dict:
    data = {
        "id": "test.enterprise.capability",
        "version": "1.0.0",
        "entrypoint": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "permissions": permissions,
        "signature": "",
    }
    data.update(overrides)
    return data


def _codes(report: dict) -> list[str]:
    return [row["code"] for row in report["findings"]]


def test_audit_never_imports_or_executes_inspected_source(tmp_path):
    sentinel = tmp_path / "executed.txt"
    source = tmp_path / "extension.py"
    source.write_text(
        "from pathlib import Path\n"
        f"Path({str(sentinel)!r}).write_text('executed')\n"
        "import requests\n"
        "def collect():\n"
        "    return requests.get('https://example.invalid')\n",
        encoding="utf-8",
    )

    report = audit_source(source, _manifest(source, []))

    assert not sentinel.exists()
    assert report["status"] == "fail"
    assert "permission.undeclared" in _codes(report)
    inferred = {row["permission"] for row in report["signals"]}
    assert {"filesystem.write", "network.connect"} <= inferred
    assert report["source_name"] == "extension.py"
    assert str(tmp_path) not in json.dumps(report)


def test_declared_read_only_capability_passes_and_is_deterministic(tmp_path):
    source = tmp_path / "reader.py"
    source.write_text(
        "from pathlib import Path\n"
        "def read_config(path):\n"
        "    return Path(path).read_text(encoding='utf-8')\n",
        encoding="utf-8",
    )
    manifest = _manifest(source, ["filesystem.read"])

    first = audit_source(source, manifest)
    second = audit_source(source, manifest)

    assert first == second
    assert first["status"] == "pass"
    assert first["summary"] == {
        "declared_permissions": 1,
        "inferred_permissions": 1,
        "errors": 0,
        "warnings": 0,
    }


def test_digest_and_entrypoint_drift_fail_closed(tmp_path):
    source = tmp_path / "module.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    manifest = _manifest(
        source,
        [],
        entrypoint="other.py",
        sha256="0" * 64,
    )

    report = audit_source(source, manifest)

    assert report["status"] == "fail"
    assert "integrity.entrypoint_mismatch" in _codes(report)
    assert "integrity.sha256_mismatch" in _codes(report)


def test_dynamic_execution_and_shell_are_reported(tmp_path):
    source = tmp_path / "runner.py"
    source.write_text(
        "import subprocess\n"
        "def run(command, text):\n"
        "    exec(text)\n"
        "    return subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )

    report = audit_source(source, _manifest(source, ["process.control"]))

    assert report["status"] == "fail"
    assert "dynamic.exec" in _codes(report)
    assert "process.shell" in _codes(report)
    assert "permission.undeclared" not in _codes(report)


def test_registry_and_firewall_capability_drift_is_visible(tmp_path):
    source = tmp_path / "hardener.py"
    source.write_text(
        "import winreg\n"
        "import subprocess\n"
        "def harden(key):\n"
        "    winreg.SetValueEx(key, 'Enabled', 0, winreg.REG_DWORD, 1)\n"
        "    subprocess.run(['powershell', 'New-NetFirewallRule'])\n",
        encoding="utf-8",
    )

    report = audit_source(source, _manifest(source, ["process.control"]))

    inferred = {row["permission"] for row in report["signals"]}
    assert "registry.write" in inferred
    assert "firewall.modify" in inferred
    assert report["summary"]["errors"] >= 2


def test_parse_errors_and_dynamic_file_modes_fail_closed(tmp_path):
    broken = tmp_path / "broken.py"
    broken.write_text("def nope(:\n", encoding="utf-8")
    broken_report = audit_source(broken, _manifest(broken, []))
    assert broken_report["status"] == "fail"
    assert "source.parse_failed" in _codes(broken_report)

    dynamic = tmp_path / "dynamic_mode.py"
    dynamic.write_text(
        "def access(path, mode):\n"
        "    return open(path, mode)\n",
        encoding="utf-8",
    )
    dynamic_report = audit_source(dynamic, _manifest(dynamic, []))
    assert dynamic_report["status"] == "fail"
    assert any(
        row["detector"] == "open(dynamic-mode)"
        for row in dynamic_report["signals"]
    )


def test_bounded_manifest_loader_and_missing_manifest(tmp_path):
    source = tmp_path / "reader.py"
    source.write_text("def value():\n    return 1\n", encoding="utf-8")
    missing = tmp_path / "missing.json"

    report = audit_manifested_source(source, missing)

    assert report["status"] == "fail"
    assert _codes(report) == ["manifest.unreadable"]

    manifest_path = tmp_path / "reader.angerona.json"
    manifest_path.write_text(
        json.dumps(_manifest(source, [])),
        encoding="utf-8",
    )
    assert audit_manifested_source(source, manifest_path)["status"] == "pass"

