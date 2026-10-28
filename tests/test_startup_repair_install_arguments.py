"""Capture real repair arguments without launching pip, installers or a runtime."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / r"System32\WindowsPowerShell\v1.0\powershell.exe"
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell repair argument construction")


def test_pip_downloads_and_installs_disable_shared_cache_and_preserve_locks_and_total_budget(tmp_path):
    environment = dict(os.environ, TEMP=str(tmp_path), TMP=str(tmp_path),
                       ANGERONA_TEST_ROOT=str(ROOT), ANGERONA_TEST_SCRATCH=str(tmp_path))
    script = tmp_path / "install-arguments.ps1"
    script.write_text(r"""$ErrorActionPreference='Stop'
$tokens=$null;$issues=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $env:ANGERONA_TEST_ROOT 'Repair-Angerona-Python.ps1'),[ref]$tokens,[ref]$issues)
if($issues.Count) {throw ($issues|Out-String)}
foreach($definition in $ast.FindAll({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst]
},$true)) {Invoke-Expression $definition.Extent.Text}
$root=$env:ANGERONA_TEST_SCRATCH
$python=Join-Path $root 'inert-python.exe'
$lock=Join-Path $root 'reviewed-requirements.txt'
$wheels=Join-Path $root 'reviewed-wheels'
$speech=Join-Path $root 'srt-reviewed.whl'
$script:RepairScratch=$root;$script:RepairCommandNumber=0
$script:RepairEnvironment=@{TEMP=$root;TMP=$root}
$script:ReviewedPythonBinding=$null
$script:RepairClock=[pscustomobject]@{Elapsed=[TimeSpan]::FromSeconds(0)}
$script:calls=[Collections.Generic.List[object]]::new()
$script:failOfflineDownload=$false
function Write-RepairDiagnostic {}
function Invoke-OwnedRepairProcess {
    param($FilePath,$Arguments,$WorkingDirectory,$Environment,$TimeoutSeconds,$LogPath)
    if($FilePath -cne $python -or $WorkingDirectory -cne $root) {throw 'Install target escaped the inert fixture.'}
    $script:calls.Add([pscustomobject]@{Arguments=@($Arguments);Timeout=$TimeoutSeconds})
    if($script:failOfflineDownload -and $Arguments[3] -ceq 'download' -and $Arguments -contains '--no-index') {return 1}
    return 0
}
Install-LockedRepairArtifacts $python $lock $wheels
Install-LocalRepairPackages $python $speech
if($script:calls.Count -ne 3) {throw 'Expected exactly three offline installs.'}
$expected=@(
    @('-I','-m','pip','install','--isolated','--no-cache-dir','--no-compile','--only-binary',':all:',
      '--require-hashes','--no-deps','--no-index','--find-links',$wheels,'--force-reinstall','-r',$lock),
    @('-I','-m','pip','install','--isolated','--no-cache-dir','--no-compile','--no-index','--no-build-isolation','--no-deps','-e',$root),
    @('-I','-m','pip','install','--isolated','--no-cache-dir','--no-compile','--no-index','--only-binary',':all:',
      '--no-deps','--force-reinstall',$speech)
)
$limits=@(300,120,60)
foreach($index in 0..2) {
    if(($script:calls[$index].Arguments|ConvertTo-Json -Compress) -cne
        ($expected[$index]|ConvertTo-Json -Compress)) {throw "Offline/hash/dependency/source flags changed for install $index."}
    if($script:calls[$index].Timeout -ne $limits[$index]) {throw 'Per-command installation deadline changed unexpectedly.'}
}
$script:calls.Clear()
function Assert-PlainRepairPath {
    param($Path)
    $absolute=[IO.Path]::GetFullPath($Path)
    if($absolute -cne $root -and !$absolute.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) {
        throw 'A fixture path escaped its own test directory.'
    }
}
function Get-RepairFileSha256 {
    param($Path)
    Assert-PlainRepairPath $Path
    $hash=[Security.Cryptography.SHA256]::Create()
    try {return [BitConverter]::ToString($hash.ComputeHash([IO.File]::ReadAllBytes($Path))).Replace('-','').ToLowerInvariant()}
    finally {$hash.Dispose()}
}
$cache=Join-Path $root '.tmp\repair-wheels\cache'
[void][IO.Directory]::CreateDirectory($cache)
[IO.File]::WriteAllText((Join-Path $cache 'reviewed.whl'),'inert reviewed fixture wheel')
[IO.File]::WriteAllText((Join-Path $cache 'unreviewed.whl'),'inert unreviewed fixture wheel')
$script:fixtureHash=Get-RepairFileSha256 (Join-Path $cache 'reviewed.whl')
function Get-RepairAllowedHashes {
    param($RequirementsPath)
    if($RequirementsPath -cne $lock) {throw 'An unreviewed requirement path was forwarded.'}
    $allowed=@{};$allowed[$script:fixtureHash]=$true;return $allowed
}
Get-LockedRepairArtifacts $python $lock $wheels
$offline=@('-I','-m','pip','download','--isolated','--no-cache-dir','--only-binary',':all:',
    '--require-hashes','--no-deps','--dest',$wheels,'--no-index','--find-links',$wheels,'-r',$lock)
if($script:calls.Count -ne 1 -or $script:calls[0].Timeout -ne 120 -or
    ($script:calls[0].Arguments|ConvertTo-Json -Compress) -cne ($offline|ConvertTo-Json -Compress)) {
    throw 'Hash-locked offline download flags or deadline changed.'
}
if(!(Test-Path -LiteralPath (Join-Path $wheels 'reviewed.whl')) -or
    (Test-Path -LiteralPath (Join-Path $wheels 'unreviewed.whl'))) {throw 'Reviewed cache filtering changed.'}
$script:calls.Clear();$script:failOfflineDownload=$true
Get-LockedRepairArtifacts $python $lock $wheels
$network=@('-I','-m','pip','download','--isolated','--no-cache-dir','--only-binary',':all:',
    '--require-hashes','--no-deps','--dest',$wheels,'--index-url','https://pypi.org/simple',
    '--timeout','15','--retries','1','--find-links',$wheels,'-r',$lock)
if($script:calls.Count -ne 2 -or $script:calls[1].Timeout -ne 240 -or
    ($script:calls[0].Arguments|ConvertTo-Json -Compress) -cne ($offline|ConvertTo-Json -Compress) -or
    ($script:calls[1].Arguments|ConvertTo-Json -Compress) -cne ($network|ConvertTo-Json -Compress)) {
    throw 'The canonical bounded download fallback lost its exact pins, cache flag or deadline.'
}
if([IO.File]::ReadAllText((Join-Path $cache 'unreviewed.whl')) -cne 'inert unreviewed fixture wheel') {
    throw 'Existing cache content was deleted or modified.'
}
$script:calls.Clear()
$script:RepairClock.Elapsed=[TimeSpan]::FromSeconds(875.25)
Install-LockedRepairArtifacts $python $lock $wheels
if($script:calls.Count -ne 1 -or $script:calls[0].Timeout -ne 24) {
    throw 'The 300-second install exceeded the remaining 900-second transaction budget.'
}
$script:RepairClock.Elapsed=[TimeSpan]::FromSeconds(900)
$held=$false
try {Install-LockedRepairArtifacts $python $lock $wheels} catch {$held=$_.Exception.Message -match '900-second'}
if(!$held -or $script:calls.Count -ne 1) {throw 'Expired overall budget admitted another command.'}
Write-Output 'offline-install-arguments-and-total-budget-verified'
""", encoding="utf-8")
    result = subprocess.run([str(POWERSHELL), "-NoProfile", "-NonInteractive", "-File", str(script)],
                            cwd=ROOT, env=environment, text=True, capture_output=True, timeout=20, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "offline-install-arguments-and-total-budget-verified" in result.stdout
