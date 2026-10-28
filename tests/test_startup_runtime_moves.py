"""Native transient-reader recovery with transaction identities preserved."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from test_startup_repair_tools import LIBRARY, _run


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows runtime directory sharing")


def test_short_native_directory_reader_retires_before_runtime_move(tmp_path: Path) -> None:
    result = _run(LIBRARY + r"""
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Threading;
public static class RuntimeReaderFixture {
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    static extern IntPtr CreateFileW(string path,uint access,uint share,IntPtr sa,uint creation,uint flags,IntPtr template);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    public static Thread Hold(string path) {
        IntPtr held=CreateFileW(path,0x80,1,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
        if(held==new IntPtr(-1)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        var worker=new Thread(()=>{Thread.Sleep(650);CloseHandle(held);});
        worker.IsBackground=true;worker.Start();return worker;
    }
}
'@
$id=Get-RepairDirectoryIdentity $venv
$destination=Join-Path $root 'preserved'
$worker=[RuntimeReaderFixture]::Hold($venv)
try {Move-RepairRuntimeDirectory $venv $destination $id}
finally {if(!$worker.Join(2000)){throw 'Owned reader thread did not retire.'}}
if((Get-RepairDirectoryIdentity $destination) -cne $id -or (Test-Path -LiteralPath $venv)){
    throw 'Original identity was lost or copied instead of moved.'
}
if([IO.File]::ReadAllText((Join-Path $destination 'identity')) -cne 'old-environment'){
    throw 'Preserved runtime bytes changed.'
}
""", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("case", ["permanent", "changed-source", "source-swap", "occupied-destination", "raced-destination", "active-process"])
def test_move_conflict_never_overwrites_or_bypasses_new_state(tmp_path: Path, case: str) -> None:
    result = _run(LIBRARY + f"\n$env:ANGERONA_MOVE_CASE='{case}'\n" + r"""
$destination=Join-Path $root 'preserved'
$id=Get-RepairDirectoryIdentity $venv
$script:moves=0
function Invoke-RepairDirectoryRename {
    param($From,$To,$ExpectedIdentity)
    $script:moves++
    if($env:ANGERONA_MOVE_CASE -in @('changed-source','source-swap')) {
        [IO.Directory]::Move($From,($From+'.original'))
        [void][IO.Directory]::CreateDirectory($From)
        [IO.File]::WriteAllText((Join-Path $From 'identity'),'foreign runtime')
        if($env:ANGERONA_MOVE_CASE -eq 'source-swap') {
            [Angerona.StartupRepairProcess]::RenameDirectoryExact($From,$To,$ExpectedIdentity)
            throw 'A source pathname replacement was accepted.'
        }
    }
    if($env:ANGERONA_MOVE_CASE -eq 'raced-destination') {
        [void][IO.Directory]::CreateDirectory($To)
        [IO.File]::WriteAllText((Join-Path $To 'identity'),'destination bytes')
        [Angerona.StartupRepairProcess]::RenameDirectoryExact($From,$To,$ExpectedIdentity)
        throw 'A raced existing destination was accepted.'
    }
    throw [ComponentModel.Win32Exception]::new(32)
}
if($env:ANGERONA_MOVE_CASE -eq 'occupied-destination') {
    [void][IO.Directory]::CreateDirectory($destination)
    [IO.File]::WriteAllText((Join-Path $destination 'identity'),'destination bytes')
}
if($env:ANGERONA_MOVE_CASE -eq 'active-process') {
    function Assert-NoActiveVenv {throw 'A real runtime generation is active.'}
}
$failed=$false
try {Move-RepairRuntimeDirectory $venv $destination $id} catch {$failed=$true}
if(!$failed){throw 'Move conflict was accepted.'}
$expectedCalls=switch($env:ANGERONA_MOVE_CASE){'permanent'{12};'changed-source'{1};'source-swap'{1};'raced-destination'{1};default{0}}
if($script:moves -ne $expectedCalls){throw "Unexpected move attempts: $script:moves"}
if($env:ANGERONA_MOVE_CASE -in @('changed-source','source-swap')) {
    if((Get-RepairDirectoryIdentity ($venv+'.original')) -cne $id){throw 'Original was lost.'}
    if([IO.File]::ReadAllText((Join-Path $venv 'identity')) -cne 'foreign runtime'){throw 'Foreign replacement was changed.'}
} elseif((Get-RepairDirectoryIdentity $venv) -cne $id){throw 'Original runtime changed.'}
if($env:ANGERONA_MOVE_CASE -in @('occupied-destination','raced-destination') -and
    [IO.File]::ReadAllText((Join-Path $destination 'identity')) -cne 'destination bytes'){
    throw 'Existing destination changed.'
}
""", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


def test_failure_record_includes_native_error_source_line_and_stack(tmp_path: Path) -> None:
    result = _run(LIBRARY + r"""
$script:RepairScratch=Get-CanonicalSourceStartupStorage
try {throw [ComponentModel.Win32Exception]::new(32)}
catch {Write-RepairFailureDiagnostic 'inert-error' $_}
""", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    path = tmp_path / "fixture" / "SourceData" / "repair-events.jsonl"
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert "Win32Exception" in records[0]["Detail"]
    assert "native=32" in records[0]["Detail"]
    assert "line=" in records[0]["Detail"]
    assert records[1]["Phase"] == "inert-error-stack"
    assert "harness.ps1" in records[1]["Detail"]


def test_expired_forward_budget_does_not_block_verified_rollback(tmp_path: Path) -> None:
    result = _run(LIBRARY + r"""
$transaction=Invoke-RepairTransaction
$script:RepairClock=[pscustomobject]@{Elapsed=[pscustomobject]@{TotalSeconds=901}}
Undo-RepairTransaction $transaction
if([IO.File]::ReadAllText((Join-Path $venv 'identity')) -cne 'old-environment'){
    throw 'The expired forward budget prevented original-runtime restoration.'
}
Assert-NoPendingRepair $root
""", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
