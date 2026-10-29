"""Native process-generation admission with stale CIM and inert owned children."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / r"System32\WindowsPowerShell\v1.0\powershell.exe"
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows retained process identity")


def run(tmp_path, script, *, timeout=25):
    path = tmp_path / "process-admission.ps1"
    path.write_text("$ErrorActionPreference='Stop'\n. (Join-Path $env:PROCESS_TEST_ROOT 'tools\\startup_repair_common.ps1')\n"
                    + "function Get-CanonicalSourceStartupStorage { return (Join-Path $env:PROCESS_TEST_SCRATCH 'SourceData') }\n" + script,
                    encoding="utf-8")
    environment = dict(os.environ, PROCESS_TEST_ROOT=str(ROOT), PROCESS_TEST_SCRATCH=str(tmp_path),
                       TEMP=str(tmp_path), TMP=str(tmp_path), PSModulePath="")
    result = subprocess.run([str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(path)],
                            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=timeout, check=False)
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


@pytest.mark.parametrize("reader_mode", ["ready", "fail-before-publication"])
def test_owned_recovery_window_retires_its_exact_reader_tree_before_retry(tmp_path, reader_mode):
    run(tmp_path, r"""
$readerMode='__READER_MODE__'
$storage=Get-CanonicalSourceStartupStorage;New-PrivateRepairDirectory $storage
$scratch=Join-Path $storage 'window';New-PrivateRepairDirectory $scratch
Initialize-RepairLiveProcessIdentity
$systemPowerShell=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$childScript=Join-Path $scratch 'reader.ps1'
$identityPath=Join-Path $scratch 'reader.json'
$releasePath=Join-Path $scratch 'reader-retained'
$windowLog=Join-Path $scratch 'window.log'
[IO.File]::WriteAllText($childScript,@'
param($IdentityPath,$Mode)
$ErrorActionPreference='Stop'
try {
    [IO.File]::WriteAllText($IdentityPath+'.reader-stage','reader-entered')
    if($Mode -ceq 'fail-before-publication'){throw 'Injected reader failure before identity publication.'}
    $self=[Diagnostics.Process]::GetCurrentProcess()
    # This fixture exercises native ownership, not PowerShell module autoload.
    # Emit its fixed numeric identity using .NET only, with atomic publication.
    $wire='{"pid":'+$PID.ToString([Globalization.CultureInfo]::InvariantCulture)+',"birth":"'+$self.StartTime.ToUniversalTime().ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)+'"}'
    [IO.File]::WriteAllText($IdentityPath+'.reader-stage','identity-publishing')
    [IO.File]::WriteAllText($IdentityPath+'.publishing',$wire)
    [IO.File]::Move($IdentityPath+'.publishing',$IdentityPath)
    [IO.File]::WriteAllText($IdentityPath+'.reader-stage','identity-published')
    [Threading.Thread]::Sleep(60000)
}catch {
    $message=$_.Exception.ToString()
    [IO.File]::WriteAllText($IdentityPath+'.reader-error',$message.Substring(0,[Math]::Min(2048,$message.Length)))
    exit 41
}
'@)
$parentScript=Join-Path $scratch 'window.ps1'
[IO.File]::WriteAllText($parentScript,@'
param($ChildScript,$IdentityPath,$ReleasePath,$Mode)
$ErrorActionPreference='Stop'
$stagePath=$IdentityPath+'.parent-stage'
[IO.File]::WriteAllText($stagePath,'parent-entered; module-path='+[Environment]::GetEnvironmentVariable('PSModulePath'))
$start=[Diagnostics.ProcessStartInfo]::new()
$start.FileName=[IO.Path]::Combine([Environment]::SystemDirectory,'WindowsPowerShell\v1.0\powershell.exe')
$start.Arguments='-NoLogo -NoProfile -NonInteractive -File "'+$ChildScript+'" "'+$IdentityPath+'" "'+$Mode+'"'
$start.UseShellExecute=$false;$start.CreateNoWindow=$true
# Give the inert service-hosted child defined standard handles. Its stdin is
# immediately EOF; only a bounded tail is copied after this exact child exits.
$start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
$child=$null
try {
    [IO.File]::WriteAllText($stagePath,'reader-start-requested; argv='+$start.Arguments)
    $child=[Diagnostics.Process]::Start($start)
    $child.StandardInput.Close()
    $wire='{"pid":'+$child.Id.ToString([Globalization.CultureInfo]::InvariantCulture)+',"birth":"'+$child.StartTime.ToUniversalTime().ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)+'"}'
    [IO.File]::WriteAllText($IdentityPath+'.launching',$wire)
    [IO.File]::Move($IdentityPath+'.launching',$IdentityPath+'.launched')
    [IO.File]::WriteAllText($stagePath,'reader-launched; identity='+$wire)
    $clock=[Diagnostics.Stopwatch]::StartNew()
    while(![IO.File]::Exists($ReleasePath) -and $clock.ElapsedMilliseconds -lt 20000){
        if($child.HasExited){
            foreach($streamName in @('StandardOutput','StandardError')){
                $buffer=[char[]]::new(2048)
                $count=$child.$streamName.Read($buffer,0,$buffer.Length)
                [IO.File]::WriteAllText($IdentityPath+'.'+$streamName,[string]::new($buffer,0,$count))
            }
            throw ('Owned reader exited before retention acknowledgement; exit='+$child.ExitCode)
        }
        [Threading.Thread]::Sleep(20)
    }
    if(![IO.File]::Exists($ReleasePath)){throw 'Owned reader retention was not acknowledged within the fixture bound.'}
    if($child.HasExited){throw 'Owned reader retired before the Retry window exit.'}
    [IO.File]::WriteAllText($stagePath,'reader-retention-acknowledged; permitting-retry')
}catch {
    $message=$_.Exception.ToString()
    [IO.File]::WriteAllText($IdentityPath+'.parent-error',$message.Substring(0,[Math]::Min(2048,$message.Length)))
    throw
}finally{if($child){$child.Dispose()}}
exit 10
'@)
function Read-FixtureDiagnostic([string]$Path) {
    $stream=$null
    try {
        if(![IO.File]::Exists($Path)){return '[not published]'}
        # The owned native logger keeps its write handle open until retirement.
        # FileShare.ReadWrite permits that existing writer without masking the
        # original missing-publication failure with a sharing violation.
        $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
        $null=$stream.Seek([Math]::Max(0,$stream.Length-4096),[IO.SeekOrigin]::Begin)
        $buffer=[byte[]]::new(4096);$count=$stream.Read($buffer,0,$buffer.Length)
        return [Text.Encoding]::UTF8.GetString($buffer,0,$count)
    }catch{return ('[diagnostic unavailable: '+$_.Exception.GetType().Name+']')}
    finally{if($stream){$stream.Dispose()}}
}
function Get-FixtureDiagnostics {
    $text=''
    foreach($suffix in @('.parent-stage','.launched','.parent-error','.reader-stage','.reader-error','.StandardOutput','.StandardError')){
        $text+="`n"+$suffix+': '+(Read-FixtureDiagnostic ($identityPath+$suffix))
    }
    return $text+"`nwindow-log: "+(Read-FixtureDiagnostic $windowLog)
}
$environment=New-RepairChildEnvironment $scratch
$window=Start-OwnedRepairWindow -FilePath $systemPowerShell -Arguments @('-NoLogo','-NoProfile','-NonInteractive','-File',$parentScript,$childScript,$identityPath,$releasePath,$readerMode) -WorkingDirectory $scratch -Environment $environment -LogPath $windowLog
$reader=$null;$failure=$null
try {
    $clock=[Diagnostics.Stopwatch]::StartNew()
    # Budget both cold PowerShell starts on hosted runners. Retry itself stays
    # blocked on explicit native-handle retention, replacing a fixed 1.2s grace.
    while((![IO.File]::Exists($identityPath) -or ![IO.File]::Exists($identityPath+'.launched')) -and $clock.ElapsedMilliseconds -lt 15000){
        if($window.HasExited){throw ('Owned window exited before reader publication. '+(Get-FixtureDiagnostics))}
        [Threading.Thread]::Sleep(20)
    }
    if(![IO.File]::Exists($identityPath) -or ![IO.File]::Exists($identityPath+'.launched')){throw ('Owned reader and parent launch identity did not both publish within 15 seconds. '+(Get-FixtureDiagnostics))}
    $record=[IO.File]::ReadAllText($identityPath)|ConvertFrom-Json
    $launched=[IO.File]::ReadAllText($identityPath+'.launched')|ConvertFrom-Json
    if($record.pid -ne $launched.pid -or $record.birth -cne $launched.birth){throw 'The reader did not match its exact launched PID and native birth.'}
    $reader=[Diagnostics.Process]::GetProcessById([int]$record.pid);$null=$reader.Handle
    if($reader.HasExited -or $reader.StartTime.ToUniversalTime().ToFileTimeUtc().ToString() -cne $record.birth){throw 'Owned reader generation was not retained before window exit.'}
    $native=Get-LiveRepairProcessIdentity ([uint32]$record.pid)
    try {
        if($native.State -ne 'live' -or [string]$native.CreationFileTime -cne $record.birth -or
            ![string]::Equals($native.ImagePath,$systemPowerShell,[StringComparison]::OrdinalIgnoreCase)){throw 'Owned reader native image or generation did not match.'}
    }finally{$native.Dispose()}
    [IO.File]::WriteAllText($releasePath,'Native reader generation retained; permit Retry.')
    if(!$window.WaitForExit(10000) -or $window.ExitCode -ne 10){throw 'Retry result was not preserved.'}
    if($window.ProcessId -le 0 -or $window.CreationFileTime -le 0){throw 'Window launch identity was not recorded.'}
    if(!$reader.WaitForExit(0)){throw 'Retry returned while its exact owned reader was still active.'}
}catch{$failure=$_.Exception.Message}
finally{
    try {
        $window.Dispose()
        if($reader -and !$reader.WaitForExit(0)){throw 'The retained reader generation survived owned-window disposal.'}
    }finally{if($reader){$reader.Dispose()}}
}
if($readerMode -ceq 'fail-before-publication'){
    if(!$failure -or !$failure.Contains('Injected reader failure before identity publication.')){throw ('The controlled reader failure lost its original diagnostic. '+$failure)}
    if($failure.Contains('being used by another process')){throw 'The diagnostic path masked the original error with a log sharing conflict.'}
    if([IO.File]::Exists($identityPath) -or [IO.File]::Exists($releasePath)){throw 'A failed reader manufactured a ready identity or retention acknowledgement.'}
    if(!$window.HasExited -or $window.ProcessId -le 0 -or $window.CreationFileTime -le 0){throw 'The failed reader window lost exact retired-root custody.'}
}elseif($failure){throw $failure}
""".replace("__READER_MODE__", reader_mode), timeout=35)


def test_owned_recovery_window_disposal_retires_only_its_generation(tmp_path):
    run(tmp_path, r"""
$storage=Get-CanonicalSourceStartupStorage;New-PrivateRepairDirectory $storage
$scratch=Join-Path $storage 'window';New-PrivateRepairDirectory $scratch
Initialize-RepairLiveProcessIdentity
$systemPowerShell=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$environment=New-RepairChildEnvironment $scratch
$window=Start-OwnedRepairWindow -FilePath $systemPowerShell -Arguments @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 60') -WorkingDirectory $scratch -Environment $environment -LogPath (Join-Path $scratch 'window.log')
$owned=$null;$self=[Diagnostics.Process]::GetCurrentProcess();$null=$self.Handle
try {
    $clock=[Diagnostics.Stopwatch]::StartNew()
    while($window.ProcessId -eq 0 -and $clock.ElapsedMilliseconds -lt 10000){Start-Sleep -Milliseconds 20}
    $owned=[Diagnostics.Process]::GetProcessById([int]$window.ProcessId);$null=$owned.Handle
    if($owned.HasExited -or $owned.StartTime.ToUniversalTime().ToFileTimeUtc() -ne $window.CreationFileTime){throw 'Window generation was not retained before disposal.'}
    $window.Dispose()
    if(!$owned.WaitForExit(0) -or $self.HasExited){throw 'Window disposal did not isolate its owned generation.'}
    if($window.ExitCode -ne 1223){throw 'Window disposal lost its explicit cancellation result.'}
}finally{
    if($owned){$owned.Dispose()}
    $self.Dispose();$window.Dispose()
}
""")


def test_actual_occupied_core_instance_lease_still_excludes_mutation(tmp_path):
    run(tmp_path, r"""
$storage=Get-CanonicalSourceStartupStorage;New-PrivateRepairDirectory $storage
$path=Join-Path $storage 'angerona.instance.lock'
$file=Open-PrivateRepairFile -Path $path -Mode OpenOrCreate -Share ReadWrite;$file.Dispose()
$ready=Join-Path $storage 'core-ready'
$scriptPath=Join-Path $storage 'core-lease.ps1'
[IO.File]::WriteAllText($scriptPath,@'
param($LockPath,$ReadyPath)
$lease=[IO.File]::Open($LockPath,'Open','ReadWrite','ReadWrite')
try {$lease.Lock(0,1);[IO.File]::WriteAllText($ReadyPath,'held');Start-Sleep -Seconds 60}
finally{$lease.Dispose()}
'@)
$powershell=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$window=Start-OwnedRepairWindow -FilePath $powershell -Arguments @('-NoProfile','-NonInteractive','-File',$scriptPath,$path,$ready) -WorkingDirectory $storage -Environment (New-RepairChildEnvironment $storage) -LogPath (Join-Path $storage 'core-lease.log')
try {
    $clock=[Diagnostics.Stopwatch]::StartNew()
    while(!(Test-Path -LiteralPath $ready) -and $clock.ElapsedMilliseconds -lt 10000){Start-Sleep -Milliseconds 20}
    if(!(Test-Path -LiteralPath $ready)){throw 'The inert core fixture did not acquire its instance lease.'}
    $held=$false
    try {$unexpected=Enter-CanonicalCoreMutationLease;Exit-RepairLease $unexpected}
    catch {$held=$_.Exception.Message -match 'core owns the instance lease'}
    if(!$held){throw 'An actual occupied singleton byte-range lease permitted mutation.'}
}finally{$window.Dispose()}
$lease=Enter-CanonicalCoreMutationLease;Exit-RepairLease $lease
""")


def test_failed_native_retirement_keeps_handles_and_coordination_lease_and_blocks_new_work(tmp_path):
    run(tmp_path, r"""
# Compile a task-local fault fixture. Product code has no bypass or injection flag.
$source=[IO.File]::ReadAllText((Join-Path $env:PROCESS_TEST_ROOT 'tools\startup_repair_common.ps1'))
$needle='if(info.active!=0)throw new TimeoutException("Owned startup job is still active; retry is held.");'
if(!$source.Contains($needle)){throw 'The native retirement fixture no longer identifies its proof boundary.'}
$source=$source.Replace($needle,'if(System.Diagnostics.Stopwatch.GetTimestamp()>0)throw new TimeoutException("Injected native retirement proof failure.");')
# ScriptBlock.Create has no declaring file. Preserve the reviewed file's root
# context for its compiler fallback without changing the injected proof failure.
$rootLiteral="'"+$env:PROCESS_TEST_ROOT.Replace("'","''")+"'"
$source=$source.Replace('$fixedRoot = Split-Path -Parent $PSScriptRoot',('$fixedRoot = '+$rootLiteral))
. ([scriptblock]::Create($source))
function Get-CanonicalSourceStartupStorage {return (Join-Path $env:PROCESS_TEST_SCRATCH 'SourceData')}
$storage=Get-CanonicalSourceStartupStorage;New-PrivateRepairDirectory $storage
$lease=Enter-CanonicalSourceHelperLease
$powershell=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$environment=New-RepairChildEnvironment $storage
$window=Start-OwnedRepairWindow -FilePath $powershell -Arguments @('-NoProfile','-NonInteractive','-Command','exit 10') -WorkingDirectory $storage -Environment $environment -LogPath (Join-Path $storage 'failed-window.log')
$held=$false
try {$window.WaitForExit()}catch{$held=$true}
if(!$held -or ![Angerona.StartupRepairProcess]::CustodyPending){throw 'A failed retirement proof discarded custody.'}
Exit-RepairLease $lease
if(!$lease.CanRead){throw 'A failed retirement proof released its coordination lease.'}
$other=Open-PrivateRepairFile -Path (Join-Path $storage 'startup-helper.lock') -Mode OpenOrCreate -Share ReadWrite
try {
    $locked=$false
    try {$other.Lock(0,1)}catch{$locked=$true}
    if(!$locked){throw 'Another generation bypassed the retained helper lease.'}
}finally{$other.Dispose()}
$marker=Join-Path $storage 'must-not-launch'
$refused=$false
try {
    Invoke-OwnedRepairProcess -FilePath $powershell -Arguments @('-NoProfile','-NonInteractive','-Command',('[IO.File]::WriteAllText("'+$marker+'","launched")')) -WorkingDirectory $storage -Environment $environment -TimeoutSeconds 10 -LogPath (Join-Path $storage 'must-not-launch.log')
}catch{$refused=$true}
if(!$refused -or (Test-Path -LiteralPath $marker)){throw 'Unresolved native custody admitted another backend command.'}
# Fixture exits with all proved-terminated native generations still retained.
# Exiting is not asserted to be an independent retirement proof in production.
""")
