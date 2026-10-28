"""Native process-generation admission with stale CIM and inert owned children."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / r"System32\WindowsPowerShell\v1.0\powershell.exe"
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows retained process identity")


def run(tmp_path, script):
    path = tmp_path / "process-admission.ps1"
    path.write_text("$ErrorActionPreference='Stop'\n. (Join-Path $env:PROCESS_TEST_ROOT 'tools\\startup_repair_common.ps1')\n"
                    + "function Get-CanonicalSourceStartupStorage { return (Join-Path $env:PROCESS_TEST_SCRATCH 'SourceData') }\n" + script,
                    encoding="utf-8")
    environment = dict(os.environ, PROCESS_TEST_ROOT=str(ROOT), PROCESS_TEST_SCRATCH=str(tmp_path),
                       TEMP=str(tmp_path), TMP=str(tmp_path), PSModulePath="")
    result = subprocess.run([str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(path)],
                            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=25, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("case", ["retired", "denied", "active", "reused-outside"])
def test_discovery_hints_require_native_liveness_identity_and_disposal(tmp_path, case):
    run(tmp_path, r"""
$case='__CASE__';$target=Join-Path $env:PROCESS_TEST_SCRATCH 'venv'
$script:disposed=$false
function Get-CimInstance { [pscustomobject]@{Name='python.exe';ExecutablePath=(Join-Path $target 'Scripts\python.exe');ProcessId=123} }
function Get-LiveRepairProcessIdentity([uint32]$ProcessId) {
    if($ProcessId -ne 123){throw 'Wrong discovery PID.'}
    $entry=[pscustomobject]@{State='live';ImagePath=(Join-Path $target 'Scripts\python.exe');CreationFileTime=99887766L;NativeError=0}
    if($case -eq 'retired'){$entry.State='retired';$entry.NativeError=87}
    if($case -eq 'denied'){$entry.State='unknown';$entry.NativeError=5;$entry.ImagePath=$null}
    if($case -eq 'reused-outside'){$entry.ImagePath='C:\Windows\System32\unrelated.exe'}
    $entry|Add-Member ScriptMethod Dispose {$script:disposed=$true};return $entry
}
$held=$false;$reason=''
try {Assert-NoActiveVenv $target}catch{$held=$true;$reason=$_.Exception.Message}
if($held -ne ($case -in @('denied','active')) -or !$script:disposed){throw 'Native admission or retained-handle cleanup failed.'}
if($case -eq 'denied' -and $reason -notmatch 'PID 123, native error 5'){throw 'Live unknown identity lost its PID/native error.'}
if($case -eq 'active' -and $reason -notmatch '99887766'){throw 'Active runtime lost its native creation FILETIME.'}
""".replace("__CASE__", case))


def test_real_current_handle_ignores_stale_image_hint_and_detects_actual_image(tmp_path):
    run(tmp_path, r"""
$native=Get-LiveRepairProcessIdentity ([uint32]$PID)
try {
    if($native.State -ne 'live' -or $native.CreationFileTime -le 0 -or !$native.ImagePath.EndsWith('powershell.exe',[StringComparison]::OrdinalIgnoreCase)){throw 'Actual self identity was not native and complete.'}
    $target=Join-Path $env:PROCESS_TEST_SCRATCH 'venv'
    function Get-CimInstance { [pscustomobject]@{Name='python.exe';ExecutablePath=(Join-Path $target 'Scripts\python.exe');ProcessId=$PID} }
    Assert-NoActiveVenv $target
    $actualDirectory=Split-Path -Parent $native.ImagePath
    function Get-CimInstance { [pscustomobject]@{Name='python.exe';ExecutablePath=$null;ProcessId=$PID} }
    $held=$false
    try {Assert-NoActiveVenv $actualDirectory}catch{$held=$_.Exception.Message -match 'still active.*native creation FILETIME'}
    if(!$held){throw 'An empty stale CIM image bypassed the actual native image.'}
}finally{$native.Dispose()}
""")


def test_real_retired_child_and_invalid_gone_pid_do_not_hold_stale_python_rows(tmp_path):
    run(tmp_path, r"""
$start=[Diagnostics.ProcessStartInfo]::new()
$start.FileName=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$start.Arguments='-NoLogo -NoProfile -NonInteractive -Command "exit 0"'
$start.UseShellExecute=$false;$start.CreateNoWindow=$true
$child=[Diagnostics.Process]::Start($start)
try {
    if(!$child.WaitForExit(10000)){throw 'Owned inert child did not retire naturally.'}
    $entry=Get-LiveRepairProcessIdentity ([uint32]$child.Id)
    try {if($entry.State -ne 'retired'){throw 'Exited native process was treated as live unknown.'}}finally{$entry.Dispose()}
    $gone=Get-LiveRepairProcessIdentity ([uint32]::MaxValue)
    try {if($gone.State -ne 'retired' -or $gone.NativeError -ne 87){throw 'Known invalid/gone PID did not prove native retirement.'}}finally{$gone.Dispose()}
    $target=Join-Path $env:PROCESS_TEST_SCRATCH 'venv'
    function Get-CimInstance { [pscustomobject]@{Name='python.exe';ExecutablePath=$null;ProcessId=$child.Id} }
    Assert-NoActiveVenv $target
}finally{$child.Dispose()}
""")


@pytest.mark.parametrize("failure", [False, True])
def test_compilation_uses_private_bounded_scratch_and_restores_inherited_temp(tmp_path, failure):
    run(tmp_path, r"""
$env:TEMP=Join-Path $env:PROCESS_TEST_SCRATCH 'untrusted-caller-temp'
$env:TMP=Join-Path $env:PROCESS_TEST_SCRATCH 'different-caller-temp'
$beforeTemp=$env:TEMP;$beforeTmp=$env:TMP
$script:compiled=$false
function Add-Type {
    param([string]$TypeDefinition)
    $script:compiled=$true
    if($env:TEMP -eq $beforeTemp -or $env:TMP -eq $beforeTmp -or $env:TEMP -ne $env:TMP){throw 'Compiler inherited caller scratch.'}
    Assert-PrivateRepairCustody $env:TEMP
    if((Split-Path -Leaf $env:TEMP) -ne 'process-compiler'){throw 'Compiler escaped its fixed owned namespace.'}
    if('__FAILURE__' -eq 'True'){throw 'Injected compiler error.'}
}
$failed=$false
try {Initialize-RepairLiveProcessIdentity}catch{$failed=$_.Exception.Message -match 'Injected compiler error'}
if('__FAILURE__' -eq 'False'){Initialize-RepairLiveProcessIdentity}
if(!$script:compiled -or $failed -ne ('__FAILURE__' -eq 'True')){throw 'Unexpected compiler test outcome.'}
if($env:TEMP -cne $beforeTemp -or $env:TMP -cne $beforeTmp){throw 'Caller TEMP/TMP were not restored.'}
""".replace("__FAILURE__", str(failure)))
