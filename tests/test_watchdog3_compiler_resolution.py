"""Real PowerShell command discovery with inert private .exe files only."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/watchdog3_compiler_resolution_fixture.ps1"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows ApplicationInfo resolution")
def test_watchdog3_compiler_discovery_keeps_one_scalar_path(tmp_path: Path) -> None:
    # Prefer the same PowerShell edition used by native-watchdog CI. Neither
    # private go.exe file is runnable, and the fixture never invokes either.
    shell = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
    if shell is None:
        pytest.fail("Windows compiler-resolution regression needs PowerShell")
    fixture_root = tmp_path / "compiler-resolution"
    result = subprocess.run(
        [shell, "-NoLogo", "-NoProfile", "-NonInteractive",
         "-File", str(FIXTURE), "-FixtureRoot", str(fixture_root)],
        cwd=ROOT, capture_output=True, text=True, check=False, timeout=30.0,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    evidence = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert len(evidence) == 2
    discovery, outcome = evidence
    assert discovery["phase"] == "discovery" and discovery["powershell"]
    assert discovery["all_matches"] == 2
    assert discovery["default_matches"] in {1, 2}
    assert discovery["legacy_value_type"] == "System.String"
    assert discovery["legacy_failure_reproduced"] == (discovery["default_matches"] == 2)
    assert outcome == {
        "phase": "result", "first_match": True, "reversed_first_match": True,
        "explicit_path_preserved": True, "missing_held": True, "fake_images_executed": 0,
    }
    assert not fixture_root.exists()
