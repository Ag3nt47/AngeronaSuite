"""Inert installed-Python hint discovery and private repair diagnostics."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / (
    r"System32\WindowsPowerShell\v1.0\powershell.exe"
)
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows installed-runtime discovery")


LIBRARY = r"""
. (Join-Path $env:ANGERONA_TEST_ROOT 'tools\startup_repair_common.ps1')
$tokens=$null; $issues=$null
$ast=[Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $env:ANGERONA_TEST_ROOT 'Repair-Angerona-Python.ps1'),[ref]$tokens,[ref]$issues)
if($issues.Count) { throw ($issues|Out-String) }
foreach($definition in $ast.FindAll({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst]
},$true)) { Invoke-Expression $definition.Extent.Text }
$root=$env:ANGERONA_TEST_SCRATCH
$script:RepairScratch=Join-Path $root 'private-repair'
New-PrivateRepairDirectory $script:RepairScratch
$script:RepairClock=[Diagnostics.Stopwatch]::StartNew()
$script:RepairCommandNumber=0
$script:RepairDiagnosticCapped=$false
$script:ReviewedPythonBinding=$null
function Invoke-RepairCommand { throw 'Live executable/installer invocation forbidden in this fixture.' }
"""


def run(script: str, scratch: Path) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ, TEMP=str(scratch), TMP=str(scratch))
    environment["ANGERONA_TEST_ROOT"] = str(ROOT)
    environment["ANGERONA_TEST_SCRATCH"] = str(scratch)
    source = scratch / "discovery-fixture.ps1"
    source.write_text("$ErrorActionPreference='Stop'\n" + LIBRARY + script, encoding="utf-8")
    return subprocess.run(
        [str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(source)],
        cwd=ROOT, env=environment, text=True, capture_output=True, timeout=60, check=False,
    )


def test_discovery_rejects_one_candidate_and_executes_only_verified_physical_target(tmp_path):
    result = run(r"""
$bad=Join-Path $root 'bad.exe'; $alias=Join-Path $root 'alias.exe'
$physical=Join-Path $root 'python.exe'
foreach($path in @($bad,$alias,$physical)) { [IO.File]::WriteAllText($path,'inert fixture') }
function Get-RepairPythonHints { return @($bad,$alias) }
function Open-RepairPythonHint([string]$Path) {
    if($Path -eq $bad) { throw 'Injected rejected candidate; discovery must continue.' }
    $bound=[pscustomobject]@{PhysicalPath=$physical;Disposed=$false;Checks=0}
    $bound|Add-Member ScriptMethod AssertBound { $this.Checks++ }
    $bound|Add-Member ScriptMethod Dispose { $this.Disposed=$true }
    return $bound
}
function Get-AuthenticodeSignature {
    param([string]$LiteralPath)
    if($LiteralPath -cne $physical) { throw 'Alias reached signature authority.' }
    return [pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Subject='CN=Python Software Foundation'}}
}
$script:executed=@()
function Invoke-RepairCommand {
    param($Executable,$Arguments,$Label,$TimeoutSeconds,[switch]$AllowFailure)
    $script:executed+=,$Executable
    if($Arguments[0] -ne '-I' -or $TimeoutSeconds -ne 30) { throw 'Isolated ABI check changed.' }
    return 0
}
$found=Find-ReviewedPython
if($found -cne $physical -or $script:executed.Count -ne 1 -or $script:executed[0] -cne $physical) {
    throw 'Discovery did not select only the independently checked physical runtime.'
}
if($script:ReviewedPythonBinding.Disposed -or $script:ReviewedPythonBinding.Checks -lt 3) {
    throw 'Runtime binding was not retained through verification.'
}
$script:ReviewedPythonBinding.Dispose()
$records=@([IO.File]::ReadAllLines((Join-Path $script:RepairScratch 'repair-events.jsonl'))|ForEach-Object {$_|ConvertFrom-Json})
if($records.Outcome -notcontains 'rejected' -or $records.Outcome -notcontains 'accepted') {
    throw 'Discovery outcomes were lost.'
}
""", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("failure", ["signature", "abi", "binding"])
def test_failed_admission_disposes_binding_without_accepting_runtime(tmp_path, failure):
    script = "$env:FAILURE='" + failure + "'\n" + r"""
$physical=Join-Path $root 'python.exe'; [IO.File]::WriteAllText($physical,'inert')
$script:binding=[pscustomobject]@{PhysicalPath=$physical;Disposed=$false}
$script:binding|Add-Member ScriptMethod AssertBound {
    if($env:FAILURE -eq 'binding') { throw 'Injected physical identity change.' }
}
$script:binding|Add-Member ScriptMethod Dispose { $this.Disposed=$true }
function Open-RepairPythonHint { return $script:binding }
function Get-AuthenticodeSignature {
    $status=if($env:FAILURE -eq 'signature') {'HashMismatch'}else{'Valid'}
    [pscustomobject]@{Status=$status;SignerCertificate=[pscustomobject]@{Subject='O=Python Software Foundation'}}
}
$script:probes=0
function Invoke-RepairCommand { $script:probes++; return 1 }
if(Test-ReviewedPython $physical) { throw 'Failed candidate was admitted.' }
if(!$script:binding.Disposed -or $script:ReviewedPythonBinding) { throw 'Refused candidate custody leaked.' }
if($env:FAILURE -ne 'abi' -and $script:probes) { throw 'Unsigned/changed candidate reached execution.' }
"""
    result = run(script, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


def test_candidate_count_is_bounded_without_execution(tmp_path):
    result = run(r"""
function Get-RepairPythonHints { 1..100|ForEach-Object { 'D:\fixture\python-'+$_+'.exe' } }
$script:checked=0
function Test-ReviewedPython { $script:checked++; return $false }
if(Find-ReviewedPython) { throw 'Fixture unexpectedly admitted a runtime.' }
if($script:checked -ne 32) { throw 'Discovery candidate budget changed.' }
""", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("name", ["py.exe", "pythonw.exe"])
def test_registry_hint_cannot_broaden_repair_to_launcher_or_windowed_image(tmp_path, name):
    script = "$name='" + name + "'\n" + r"""
$physical=Join-Path $root $name; [IO.File]::WriteAllText($physical,'inert')
$script:binding=[pscustomobject]@{PhysicalPath=$physical;Disposed=$false}
$script:binding|Add-Member ScriptMethod AssertBound {}
$script:binding|Add-Member ScriptMethod Dispose { $this.Disposed=$true }
function Open-RepairPythonHint { return $script:binding }
$script:signatures=0; $script:probes=0
function Get-AuthenticodeSignature {
    $script:signatures++
    return [pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Subject='CN=Python Software Foundation'}}
}
function Invoke-RepairCommand { $script:probes++; return 0 }
if(Test-ReviewedPython $physical) { throw 'Registry hint broadened physical repair image authority.' }
if(!$script:binding.Disposed -or $script:signatures -or $script:probes) {
    throw 'Unapproved physical image reached signature/probe execution or retained custody.'
}
"""
    result = run(script, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


def test_native_redirected_hint_resolves_plain_target_and_pins_namespace(tmp_path):
    result = run(r"""
$physicalDirectory=Join-Path $root 'physical'
[void][IO.Directory]::CreateDirectory($physicalDirectory)
$physical=Join-Path $physicalDirectory 'python.exe'; [IO.File]::WriteAllText($physical,'inert-owned-fixture')
$alias=Join-Path $root 'redirected-installed-location'
[void](New-Item -ItemType Junction -Path $alias -Target $physicalDirectory)
$hint=Join-Path $alias 'python.exe'
$bound=Open-RepairPythonHint $hint
try {
    if(![string]::Equals($bound.PhysicalPath,$physical,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Hint alias remained execution authority.'
    }
    Assert-PlainRepairPath $bound.PhysicalPath -AllowHardLinks
    $bound.AssertBound()
    $writeRefused=$false
    try { $file=[IO.File]::Open($physical,'Open','Write','ReadWrite'); $file.Dispose() }
    catch { $writeRefused=$true }
    if(!$writeRefused) { throw 'Held runtime allowed another writer.' }
    $renameRefused=$false
    try { [IO.Directory]::Move($physicalDirectory,(Join-Path $root 'swapped')) }
    catch { $renameRefused=$true }
    if(!$renameRefused) { throw 'Physical namespace was not pinned.' }
    if([IO.File]::ReadAllText($physical) -cne 'inert-owned-fixture') { throw 'Fixture content changed.' }
} finally { $bound.Dispose() }
$closedRefused=$false
try { $bound.AssertBound() } catch { $closedRefused=$true }
if(!$closedRefused) { throw 'Disposed runtime binding remained usable.' }
""", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


def test_private_phase_log_is_bounded_and_does_not_capture_arguments_or_environment(tmp_path):
    result = run(r"""
$env:OPENAI_API_KEY='fixture-secret-must-not-appear'
1..200|ForEach-Object { Write-RepairDiagnostic 'fixture-phase' 'refused' ('bounded reason '+('x'*2000)) }
$path=Join-Path $script:RepairScratch 'repair-events.jsonl'
if((Get-Item -LiteralPath $path).Length -gt 65536) { throw 'Phase log exceeded byte budget.' }
$text=[IO.File]::ReadAllText($path)
if($text.Contains($env:OPENAI_API_KEY)) { throw 'Diagnostic logger captured inherited credentials.' }
$rows=@([IO.File]::ReadAllLines($path)|ForEach-Object { $_|ConvertFrom-Json })
if(!$rows.Count -or $rows[0].Detail.Length -gt 1024 -or !$script:RepairDiagnosticCapped) {
    throw 'Diagnostic bounded row/cap evidence missing.'
}
Assert-PrivateRepairCustody $path -AllowInherited
""", tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("target", [r"\??\UNC\not-a-host.invalid\share", r"\Device\HarddiskVolume1\python.exe"])
def test_reparse_decoder_refuses_nonlocal_targets_before_target_open(tmp_path, target):
    # Exercise raw mount-point input at the native resolver's pure decode seam;
    # neither sample is ever opened or used as an executable/registry location.
    script = "$target='" + target + "'\n" + r"""
Initialize-RepairPythonDiscovery
Add-Type -TypeDefinition @'
using System;
using System.Reflection;
using System.Text;
public static class RepairDiscoveryDecoderFixture {
    public static bool Refuses(Type resolver,string target) {
        byte[] encoded=Encoding.Unicode.GetBytes(target),buffer=new byte[16+Encoding.Unicode.GetByteCount(target)];
        Array.Copy(BitConverter.GetBytes((uint)0xA0000003),0,buffer,0,4);
        Array.Copy(BitConverter.GetBytes((ushort)(8+encoded.Length)),0,buffer,4,2);
        Array.Copy(BitConverter.GetBytes((ushort)encoded.Length),0,buffer,10,2);
        Array.Copy(encoded,0,buffer,16,encoded.Length);
        var method=resolver.GetMethod("DecodeReparseTarget",BindingFlags.NonPublic|BindingFlags.Static);
        try { method.Invoke(null,new object[]{buffer,(uint)buffer.Length,@"D:\fixture\alias"}); }
        catch(TargetInvocationException error) {
            return error.InnerException.Message.Contains("absolute local DOS path");
        }
        return false;
    }
}
'@
if(![RepairDiscoveryDecoderFixture]::Refuses([Angerona.RepairPythonImage],$target)) {
    throw 'UNC/device reparse target did not fail before target traversal.'
}
"""
    result = run(script, tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
