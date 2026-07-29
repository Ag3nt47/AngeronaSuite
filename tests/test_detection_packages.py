from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from angerona.core.detection_packages import (
    PackageValidationError,
    load_package,
    seal_package,
    validate_package,
)


def _package():
    return {
        "schema_version": 1,
        "id": "org.angerona.benign-powershell-observation",
        "version": "1.0.0",
        "owner": "Angerona Community",
        "description": "Demonstrates bounded local detection packaging.",
        "telemetry": ["process.creation"],
        "attack": ["T1059.001"],
        "severity": "low",
        "confidence": 80,
        "logic": {"type": "sigma-subset", "detection": {
            "selection": {"image|endswith": "powershell.exe", "cmdline|contains": "Get-Process"},
            "condition": "selection",
        }},
        "fixtures": [
            {"name": "benign demo hit", "event": {
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "cmdline": "powershell.exe Get-Process",
            }, "expected_match": True},
            {"name": "unrelated process", "event": {
                "image": "C:\\Windows\\System32\\notepad.exe", "cmdline": "notepad.exe",
            }, "expected_match": False},
        ],
        "performance": {"max_eval_ms": 50, "max_events_per_second": 1000},
        "rollback": {"previous_digest": None, "instructions": "Disable this demonstration package."},
        "expires_at": "2035-01-01T00:00:00Z",
    }


def test_loads_verified_package_and_evaluates(tmp_path):
    path = tmp_path / "demo.json"
    path.write_text(json.dumps(seal_package(_package())), encoding="utf-8")
    package = load_package(path, now=datetime(2030, 1, 1, tzinfo=timezone.utc))
    assert package.package_id.endswith("observation")
    assert package.evaluate({"image": "powershell.exe", "cmdline": "Get-Process"})
    assert not package.evaluate({"image": "cmd.exe", "cmdline": "Get-Process"})


def test_tampering_fails_closed():
    document = seal_package(_package())
    document["confidence"] = 100
    with pytest.raises(PackageValidationError, match="digest"):
        validate_package(document)


@pytest.mark.parametrize("mutation", [
    lambda p: p["logic"]["detection"]["selection"].update({"cmdline|re": "(a+)+$"}),
    lambda p: p["logic"]["detection"].update({"condition": "selection or missing"}),
    lambda p: p.update({"unexpected": True}),
])
def test_unsafe_or_unknown_logic_fails_closed(mutation):
    document = _package()
    mutation(document)
    with pytest.raises(PackageValidationError):
        validate_package(seal_package(document))


def test_expired_package_and_failed_fixture_are_rejected(tmp_path):
    expired = _package()
    expired["expires_at"] = "2020-01-01T00:00:00Z"
    with pytest.raises(PackageValidationError, match="expired"):
        validate_package(seal_package(expired))

    broken = _package()
    broken["fixtures"][0]["expected_match"] = False
    path = tmp_path / "broken.json"
    path.write_text(json.dumps(seal_package(broken)), encoding="utf-8")
    with pytest.raises(PackageValidationError, match="fixture failed"):
        load_package(path, now=datetime(2030, 1, 1, tzinfo=timezone.utc))
