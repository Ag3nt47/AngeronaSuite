"""Shutdown owns canonical startup and proven venv redirector children only."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_startup_and_base_interpreter_child_require_exact_suite_parent():
    powershell = shutil.which("powershell")
    if powershell is None:
        pytest.skip("Windows ownership helper requires PowerShell")
    helper = str(ROOT / "tools" / "angerona_process_owner.ps1").replace("'", "''")
    root = str(ROOT).replace("'", "''")
    command = f"""
. '{helper}'
$root = '{root}'
$python = Join-Path $root 'venv\\Scripts\\python.exe'
$birth = [datetime]'2026-10-08T12:00:00Z'
function Process($id, $parent, $exe, $command, $born) {{
  [pscustomobject]@{{ProcessId=$id; ParentProcessId=$parent; ExecutablePath=$exe; CommandLine=$command; CreationDate=$born}}
}}
$starter = Process 10 1 $python ('"' + $python + '" -m angerona.startup') $birth
$child = Process 11 10 'C:\\Python\\python.exe' 'python.exe -m angerona.startup' $birth.AddSeconds(1)
$unrelated = Process 12 1 'C:\\Python\\python.exe' 'python.exe -m angerona.startup' $birth.AddSeconds(1)
$wrongArguments = Process 13 10 'C:\\Python\\python.exe' 'python.exe -m angerona' $birth.AddSeconds(1)
$reused = Process 14 10 'C:\\Python\\python.exe' 'python.exe -m angerona.startup' $birth.AddSeconds(-1)
$missingBirth = Process 15 10 'C:\\Python\\python.exe' 'python.exe -m angerona.startup' $null
$siblingPython = $root + '-copy\\venv\\Scripts\\python.exe'
$sibling = Process 20 1 $siblingPython ('"' + $siblingPython + '" -m angerona.startup') $birth
$siblingChild = Process 21 20 'C:\\Python\\python.exe' 'python.exe -m angerona.startup' $birth.AddSeconds(1)
$testParent = Process 30 1 $python ('"' + $python + '" -m pytest') $birth
$testChild = Process 31 30 'C:\\Python\\python.exe' 'python.exe -m pytest' $birth.AddSeconds(1)
$snapshot = @($starter,$child,$unrelated,$wrongArguments,$reused,$missingBirth,$sibling,$siblingChild,$testParent,$testChild)
$snapshot | ForEach-Object {{ [pscustomobject]@{{pid=$_.ProcessId; owned=(Test-AngeronaProcessOwnership -Process $_ -Root $root -ProcessSnapshot $snapshot)}} }} | ConvertTo-Json -Compress
"""
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        check=True, text=True, capture_output=True, timeout=20,
    )
    ownership = {row["pid"]: row["owned"] for row in json.loads(result.stdout)}
    assert ownership == {10: True, 11: True, 12: False, 13: False, 14: False,
                         15: False, 20: False, 21: False, 30: False, 31: False}
