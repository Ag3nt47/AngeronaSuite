"""Inert protected-installer route selection; never executes a release payload."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / r"System32\WindowsPowerShell\v1.0\powershell.exe"
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Protected PowerShell route primitives")


LIBRARY = r"""
$ErrorActionPreference='Stop'
$tokens=$null;$issues=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $env:ROUTE_TEST_REPOSITORY 'Install-Angerona-Release.ps1'),[ref]$tokens,[ref]$issues)
if($issues.Count) {throw ($issues|Out-String)}
foreach($definition in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) {
    Invoke-Expression $definition.Extent.Text
}
$target=$env:ROUTE_TEST_SCRATCH
$script:protected=@();$script:signed=@()
function Assert-ProtectedPath([string]$Path,[bool]$Directory) {
    $script:protected+=,$Path
    if($env:ROUTE_TEST_CASE -eq 'unprotected' -and $Path.EndsWith('AngeronaSafeStart.exe')) {throw 'injected unprotected modern entry'}
}
function Assert-PublisherSignature([string]$Path,[string]$Certificate) {
    if($Certificate -cne ('a'*64)) {throw 'Publisher pin changed.'}
    $script:signed+=,$Path
    if($env:ROUTE_TEST_CASE -eq 'unsigned' -and $Path.EndsWith('AngeronaSafeStart.exe')) {throw 'injected unsigned modern entry'}
}
"""


def run(script, tmp_path, case=""):
    source = tmp_path / "route-fixture.ps1"
    source.write_text(LIBRARY + script + "\nexit 0\n", encoding="utf-8")
    environment = dict(os.environ, ROUTE_TEST_REPOSITORY=str(ROOT), ROUTE_TEST_SCRATCH=str(tmp_path),
                       ROUTE_TEST_CASE=case, TEMP=str(tmp_path), TMP=str(tmp_path), PSModulePath="")
    result = subprocess.run([str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(source)],
                            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("case", ["modern", "legacy", "missing", "directory", "unsigned", "unprotected", "unlisted"])
def test_installer_uses_authenticated_membership_and_does_not_fall_through(tmp_path, case):
    (tmp_path / "AngeronaStartup.exe").write_bytes(b"inert old helper")
    native = tmp_path / "AngeronaSafeStart.exe"
    if case == "directory":
        native.mkdir()
    elif case != "missing":
        native.write_bytes(b"inert native helper")
    run(r"""
$paths=@{}
if($env:ROUTE_TEST_CASE -ne 'unlisted') {$paths['angeronastartup.exe']=$true}
if($env:ROUTE_TEST_CASE -notin @('legacy','unlisted')) {$paths['angeronasafestart.exe']=$true}
$failed=$false;$selected=$null
try {$selected=Select-AuthenticatedReleaseStartup -TargetRoot $target -ManifestPaths $paths -Certificate ('a'*64)} catch {$failed=$true}
$expectedFailure=$env:ROUTE_TEST_CASE -notin @('modern','legacy')
if($failed -ne $expectedFailure) {throw 'Unexpected authenticated entry admission.'}
if(!$expectedFailure) {
    $name=if($env:ROUTE_TEST_CASE -eq 'modern') {'AngeronaSafeStart.exe'} else {'AngeronaStartup.exe'}
    if($selected -cne (Join-Path $target $name) -or $script:protected.Count -ne 1 -or $script:signed.Count -ne 1) {throw 'Selected entry lost custody or publisher proof.'}
}
if($expectedFailure -and ($script:protected -contains (Join-Path $target 'AngeronaStartup.exe') -or $script:signed -contains (Join-Path $target 'AngeronaStartup.exe'))) {
    throw 'An invalid declared modern entry fell through to legacy.'
}
""", tmp_path, case)


@pytest.mark.parametrize("case", ["modern-good", "modern-bad", "legacy"])
def test_only_modern_entry_receives_read_only_bootstrap_check_and_failure_holds(tmp_path, case):
    run(r"""
$script:argumentsSeen=@()
function AngeronaSafeStart.exe {
    $script:argumentsSeen=@($args)
    $global:LASTEXITCODE=if($env:ROUTE_TEST_CASE -eq 'modern-bad') {17} else {0}
}
function AngeronaStartup.exe {throw 'Legacy helper must not execute for a modern pin check.'}
$name=if($env:ROUTE_TEST_CASE -eq 'legacy') {'AngeronaStartup.exe'} else {'AngeronaSafeStart.exe'}
$failed=$false
try {Assert-AuthenticatedStartupBinding $name} catch {$failed=$true}
if($failed -ne ($env:ROUTE_TEST_CASE -eq 'modern-bad')) {throw 'Native binding failure was ignored.'}
if($env:ROUTE_TEST_CASE -eq 'legacy') {
    if($script:argumentsSeen.Count) {throw 'Legacy helper unexpectedly executed.'}
} elseif($script:argumentsSeen.Count -ne 1 -or $script:argumentsSeen[0] -cne '--verify-bootstrap') {throw 'Native check ran a normal app launch or changed its flags.'}
""", tmp_path, case)


def test_staged_native_check_uses_only_catalog_reconstruction_after_authorization(tmp_path):
    original = tmp_path / "raw-payload"
    reconstructed = tmp_path / "catalog-payload"
    original.mkdir()
    reconstructed.mkdir()
    for name in ("AngeronaSafeStart.exe", "AngeronaStartup.exe"):
        data = ("inert authenticated " + name).encode()
        (original / name).write_bytes(data)
        (reconstructed / name).write_bytes(data)
    unlisted = original / "AngeronaSafeStart.exe.config"
    unlisted.write_text("unmanifested CLR configuration must never accompany execution")
    run(r"""
$catalogPayload=Join-Path $target 'catalog-payload'
$payloadRoot=Join-Path $target 'raw-payload'
$paths=@{'angeronasafestart.exe'=$true;'angeronastartup.exe'=$true}
$script:checked=$null
function Assert-AuthenticatedStartupBinding([string]$StartupPath) {
    $script:checked=$StartupPath
    if(Test-Path -LiteralPath ($StartupPath+'.config')) {throw 'An unmanifested config reached the staged execution directory.'}
}
$selected=Select-AuthenticatedReleaseStartup -TargetRoot $catalogPayload -ManifestPaths $paths -Certificate ('a'*64)
Assert-AuthenticatedStartupBinding $selected
if($script:checked -cne (Join-Path $catalogPayload 'AngeronaSafeStart.exe')) {throw 'Staged validation escaped the reconstructed catalog.'}
if(!(Test-Path -LiteralPath (Join-Path $payloadRoot 'AngeronaSafeStart.exe.config'))) {throw 'The raw unlisted fixture was deleted.'}
""", tmp_path)
    source = (ROOT / "Install-Angerona-Release.ps1").read_text(encoding="utf-8")
    selection = "$stagedStartupPath = Select-AuthenticatedReleaseStartup -TargetRoot $catalogPayload"
    assert selection in source
    assert "Select-AuthenticatedReleaseStartup -TargetRoot $payloadRoot" not in source
    assert source.index("$catalogResult.Status -ne") < source.index("--candidate-root $payloadRoot")
    assert source.index("Threshold release authorization or anti-rollback verification failed") < source.index(selection)
    assert source.index(selection) < source.index("Assert-AuthenticatedStartupBinding $stagedStartupPath")
    assert source.index("Assert-AuthenticatedStartupBinding $stagedStartupPath") < source.index("$installPaths =")
    assert "Select-AuthenticatedReleaseStartup -TargetRoot $target" in source
    assert unlisted.is_file()
    assert not (reconstructed / unlisted.name).exists()
