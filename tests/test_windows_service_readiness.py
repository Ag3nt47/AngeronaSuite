"""The read-only host report must never become install or activation authority."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest

from angerona.core.privilege import trusted_powershell_path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "Get-AngeronaServiceReadiness.ps1"
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell required")


def _run(command: str, data: dict | None = None) -> dict | list:
    environment = dict(os.environ, ANGERONA_READINESS_TEST_SCRIPT=str(SCRIPT))
    result = subprocess.run(
        [str(trusted_powershell_path()), "-NoProfile", "-NonInteractive", "-Command", command],
        input=json.dumps(data or {}), capture_output=True, text=True,
        env=environment, timeout=30, check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.lstrip("\ufeff"))


def _snapshot() -> dict:
    return {
        "Administrator": False,
        "Services": [],
        "Packages": [],
        "CandidateSignature": "NotSigned",
        "ConfigurationPresent": False,
        "LocalCodeSigningCertificateCount": 0,
        "Errors": [],
    }


def _report(snapshot: dict) -> dict:
    return _run(
        "$ErrorActionPreference='Stop'; "
        ". $env:ANGERONA_READINESS_TEST_SCRIPT; "
        "$snapshot=ConvertFrom-Json -InputObject ([Console]::In.ReadToEnd()); "
        "New-AngeronaServiceReadinessReport $snapshot | ConvertTo-Json -Depth 8 -Compress",
        snapshot,
    )


def test_source_checkout_reports_missing_deployment_without_running_anything():
    result = _report(_snapshot())
    assert result["ReadOnly"] is True and result["ActivationVerified"] is False
    assert set(result["Gaps"]) == {
        "NO_MATCHING_PACKAGE_OBSERVED", "SERVICE_NOT_OBSERVED:AngeronaProtection",
        "SERVICE_NOT_OBSERVED:AngeronaWatchdog3", "WATCHDOG_CONFIGURATION_NOT_OBSERVED",
        "DEVELOPMENT_WATCHDOG_NOT_VALIDLY_SIGNED",
    }
    assert result["Observation"] == "prerequisites_missing_or_unverified"


@pytest.mark.parametrize("administrator", [False, True])
def test_signature_package_and_scm_presence_never_attest_activation(administrator):
    snapshot = _snapshot()
    snapshot.update(
        Administrator=administrator,
        Packages=[{"Name": "Angerona", "Status": "Ok"}],
        Services=[{"Name": name, "State": "Running"} for name in
                  ("AngeronaProtection", "AngeronaWatchdog3")],
        CandidateSignature="Valid", ConfigurationPresent=True,
        LocalCodeSigningCertificateCount=1,
    )
    result = _report(snapshot)
    assert result["Gaps"] == []
    assert result["Observation"] == "external_acceptance_still_required"
    assert result["ActivationVerified"] is False
    assert len(result["RequiredAcceptance"]) == 4


def test_failed_inventory_stays_incomplete_and_certificate_absence_is_not_authority():
    snapshot = _snapshot()
    snapshot["Errors"] = ["PACKAGE_QUERY_UNAVAILABLE", "SERVICE_QUERY_UNAVAILABLE"]
    result = _report(snapshot)
    assert "OBSERVATION_INCOMPLETE" in result["Gaps"]
    assert result["LocalObservations"]["Errors"] == snapshot["Errors"]
    assert "LOCAL_CERTIFICATE_MISSING" not in result["Gaps"]
    assert any("cloud/HSM" in text for text in result["Limitations"])


def test_script_ast_is_diagnostic_only_and_contains_no_candidate_launch():
    result = _run(r"""
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
    $env:ANGERONA_READINESS_TEST_SCRIPT,[ref]$tokens,[ref]$errors)
if ($errors.Count -ne 0) { throw 'Readiness script has parse errors' }
$commands=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.CommandAst]
},$true) | ForEach-Object {$_.GetCommandName()} | Sort-Object -Unique)
[pscustomobject]@{Commands=$commands} | ConvertTo-Json -Compress
""")
    assert set(result["Commands"]) <= {
        "New-AngeronaServiceReadinessReport", "Get-AngeronaServiceReadiness",
        "Where-Object", "Split-Path", "Join-Path", "Get-CimInstance", "Select-Object",
        "Get-AppxPackage", "Get-AuthenticodeSignature", "Test-Path", "Get-ChildItem",
        "ConvertTo-Json",
    }
