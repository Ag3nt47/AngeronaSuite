"""Critical startup working space stays separate from optional retained history."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / r"System32\WindowsPowerShell\v1.0\powershell.exe"
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Native private startup workspace")


def run(tmp_path, body):
    path = tmp_path / "critical-storage.ps1"
    path.write_text(r"""$ErrorActionPreference='Stop'
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $env:CRITICAL_TEST_ROOT 'tools\Invoke-AngeronaSourceStartup.ps1'),[ref]$null,[ref]$null)
foreach($node in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)) {
    . ([scriptblock]::Create($node.Extent.Text))
}
. (Join-Path $env:CRITICAL_TEST_ROOT 'tools\startup_repair_common.ps1')
function Get-CanonicalSourceStartupStorage {return (Join-Path $env:CRITICAL_TEST_SCRATCH 'canonical')}
$script:SourceStartupCriticalMode=$true
""" + body, encoding="utf-8")
    result = subprocess.run([str(POWERSHELL), "-NoProfile", "-NonInteractive", "-File", str(path)],
                            cwd=ROOT, env=dict(os.environ, CRITICAL_TEST_ROOT=str(ROOT),
                                               CRITICAL_TEST_SCRATCH=str(tmp_path), TEMP=str(tmp_path), TMP=str(tmp_path)),
                            capture_output=True, text=True, timeout=45, check=False,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(next(line[7:] for line in result.stdout.splitlines() if line.startswith("RESULT:")))


@pytest.mark.parametrize("nonempty", [False, True])
def test_retained_attempt_limit_does_not_block_critical_workspace_or_grow_guids(tmp_path, nonempty):
    result = run(tmp_path, r"""
$root=Join-Path $env:CRITICAL_TEST_SCRATCH 'installation';[void][IO.Directory]::CreateDirectory($root)
$storage=Join-Path $env:CRITICAL_TEST_SCRATCH 'state';New-PrivateRepairDirectory $storage
$base=Join-Path $storage 'tmp';[void][IO.Directory]::CreateDirectory($base)
for($number=0;$number -lt 32;$number++) {
    $old=Join-Path $base ('startup-temp.'+$number.ToString('x32'));New-PrivateRepairDirectory $old
    if(__NONEMPTY__){$stream=Open-PrivateRepairFile (Join-Path $old 'preserved.log');try{$bytes=[Text.Encoding]::UTF8.GetBytes('unique retained diagnostic');$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}}
}
$selected=New-SourceStartupTemporary $root $storage -Purpose control
for($number=0;$number -lt 40;$number++) {
    $stream=Open-PrivateRepairFile (Join-Path $selected 'source-action.log');$stream.Dispose()
    if((New-SourceStartupTemporary $root $storage -Purpose control) -cne $selected){throw 'Current supervisor allocated an unbounded new workspace.'}
}
if($script:SourceStartupScratchLease.CanWrite -or !$script:SourceStartupScratchLease.CanRead){throw 'Scratch lease grants mutation rights.'}
Close-SourceStartupCriticalWorkspaces
$legacy=@([IO.Directory]::EnumerateDirectories($base,'startup-temp.*')|Where-Object {[IO.Path]::GetFileName($_) -cmatch '^startup-temp\.[a-f0-9]{32}$'})
if($legacy.Count -ne 32){throw 'Legacy retained diagnostic directories were removed.'}
if(__NONEMPTY__){foreach($old in $legacy){if([IO.File]::ReadAllText((Join-Path $old 'preserved.log')) -cne 'unique retained diagnostic'){throw 'Retained diagnostic data changed.'}}}
Write-Output ('RESULT:'+(@{legacy=32;critical=[IO.Path]::GetFileName($selected);warning=[bool]$script:StartupStorageWarning}|ConvertTo-Json -Compress))
""".replace("__NONEMPTY__", "$true" if nonempty else "$false"))
    assert result == {"legacy": 32, "critical": "startup-temp.critical-control", "warning": True}


def test_active_read_guard_excludes_reclamation_and_uses_other_fixed_base(tmp_path):
    result = run(tmp_path, r"""
$root=Join-Path $env:CRITICAL_TEST_SCRATCH 'installation';[void][IO.Directory]::CreateDirectory($root)
$storage=Join-Path $env:CRITICAL_TEST_SCRATCH 'state';New-PrivateRepairDirectory $storage
$first=New-SourceStartupTemporary $root $storage -Purpose control
$held=$script:SourceStartupScratchLease
$script:SourceStartupCriticalWorkspaces=@{};$script:SourceStartupScratchLease=$null
try {
    $second=New-SourceStartupTemporary $root $storage -Purpose control
    if($second -ceq $first -or !(Test-Path -LiteralPath (Join-Path $first 'startup-critical.owner.json'))){throw 'An active read guard permitted workspace reclamation.'}
    Close-SourceStartupCriticalWorkspaces
}finally{$held.Dispose()}
$again=New-SourceStartupTemporary $root $storage -Purpose control
if($again -cne $first){throw 'A retired workspace was not safely reused.'}
Close-SourceStartupCriticalWorkspaces
Write-Output ('RESULT:'+(@{active_preserved=$true;retired_reused=$true}|ConvertTo-Json -Compress))
""")
    assert result == {"active_preserved": True, "retired_reused": True}


def test_many_unknown_history_names_are_bounded_advisory_and_preserved(tmp_path):
    result = run(tmp_path, r"""
$root=Join-Path $env:CRITICAL_TEST_SCRATCH 'installation';[void][IO.Directory]::CreateDirectory($root)
$storage=Join-Path $env:CRITICAL_TEST_SCRATCH 'state';New-PrivateRepairDirectory $storage
$base=Join-Path $storage 'tmp';[void][IO.Directory]::CreateDirectory($base)
for($number=0;$number -lt 129;$number++) {
    [void][IO.Directory]::CreateDirectory((Join-Path $base ('startup-temp.unknown-'+$number)))
}
$held=''
try{Assert-SourceStartupScratchBudget $base}catch{$held=$_.Exception.Message}
if($held -notlike '*bounded directory inventory*'){throw 'Unknown prefix history did not stop bounded discovery.'}
$selected=New-SourceStartupTemporary $root $storage -Purpose control
Close-SourceStartupCriticalWorkspaces
for($number=0;$number -lt 129;$number++) {
    if(![IO.Directory]::Exists((Join-Path $base ('startup-temp.unknown-'+$number)))){throw 'Unknown history was removed.'}
}
Write-Output ('RESULT:'+(@{critical=[IO.Path]::GetFileName($selected);warning=[bool]$script:StartupStorageWarning;unknown_preserved=129}|ConvertTo-Json -Compress))
""")
    assert result == {"critical": "startup-temp.critical-control", "warning": True, "unknown_preserved": 129}


def test_unknown_critical_working_data_is_preserved_with_bounded_fallback(tmp_path):
    result = run(tmp_path, r"""
$root=Join-Path $env:CRITICAL_TEST_SCRATCH 'installation';[void][IO.Directory]::CreateDirectory($root)
$storage=Join-Path $env:CRITICAL_TEST_SCRATCH 'state';New-PrivateRepairDirectory $storage
$first=New-SourceStartupTemporary $root $storage -Purpose control
$unknown=Open-PrivateRepairFile (Join-Path $first 'unknown-preserve.bin')
try{$unknown.SetLength(32MB+1)}finally{$unknown.Dispose()}
Close-SourceStartupCriticalWorkspaces
$second=New-SourceStartupTemporary $root $storage -Purpose control
if($second -ceq $first -or (Get-Item -LiteralPath (Join-Path $first 'unknown-preserve.bin')).Length -ne 32MB+1){throw 'Unknown working data was removed or ignored.'}
Close-SourceStartupCriticalWorkspaces
Write-Output ('RESULT:'+(@{unknown_preserved=$true;other_fixed_workspace=$true}|ConvertTo-Json -Compress))
""")
    assert result == {"unknown_preserved": True, "other_fixed_workspace": True}


def test_retry_after_interface_scratch_exception_stays_in_owned_loop(tmp_path):
    result = run(tmp_path, r"""
$script:count=0;$script:calls=[Collections.Generic.List[string]]::new()
function Start-SourceStartupShell {
    if(++$script:count -eq 1){throw 'Injected critical workspace writer/custody failure.'}
    $script:calls.Add('interface-retried')
}
function Invoke-SourceRecoveryWindow {$script:calls.Add('recovery');return 10}
function Test-SourceStartupShellClosed {return $false}
function Test-SourceStartupCapturesRetired {return $true}
function Write-SourceStartupStatus {}
function Write-SourceStartupEvent {}
function Add-SourceStartupAttempt {}
function Complete-SourceStartupRecovery {}
function Invoke-SourceCodeAction {
    $script:LastSourceRecoveryResult=[pscustomobject]@{schema=1;launch_held=$false;requires_mutation=$false;pending_kind='none';source_digest=('a'*64)}
    return 0
}
function Invoke-SourceStartupPass {$script:calls.Add('verified-pass');return 0}
$code=Invoke-SourceStartupLoop 'D:\inert-source-root'
Write-Output ('RESULT:'+(@{code=$code;calls=@($script:calls)}|ConvertTo-Json -Compress))
""")
    assert result == {"code": 0, "calls": ["recovery", "interface-retried", "verified-pass"]}
