"""Actual Windows producer custody for bounded critical startup scratch."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest


ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Native Windows read-guard inheritance")


def fixture_environment(tmp_path):
    # Windows environment names are case-insensitive. This fixture owns the
    # module-path override; preserve every other ambient value and replace only
    # known spelling variants before constructing the native parent environment.
    environment = {key: value for key, value in os.environ.items()
                   if key.casefold() != "psmodulepath"}
    environment.update(LEASE_TEST_ROOT=str(ROOT), LEASE_TEST_SCRATCH=str(tmp_path),
                       LEASE_TEST_PYTHON=sys.executable, TEMP=str(tmp_path), TMP=str(tmp_path), PSMODULEPATH="")
    return environment


CHILD = r'''
import ctypes,json,os,sys,time
from ctypes import wintypes
from pathlib import Path
k=ctypes.WinDLL('kernel32',use_last_error=True)
k.GetCurrentProcess.restype=wintypes.HANDLE
k.GetProcessTimes.argtypes=(wintypes.HANDLE,*([ctypes.POINTER(wintypes.FILETIME)]*4))
k.GetFileType.argtypes=(wintypes.HANDLE,)
k.WriteFile.argtypes=(wintypes.HANDLE,wintypes.LPCVOID,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),wintypes.LPVOID)
times=[wintypes.FILETIME() for _ in range(4)]
assert k.GetProcessTimes(k.GetCurrentProcess(),*(ctypes.byref(x) for x in times))
raw=os.environ.get('ANGERONA_STARTUP_SCRATCH_LEASE_HANDLE')
readonly=None
if raw:
    h=wintypes.HANDLE(int(raw));assert k.GetFileType(h)==1
    written=wintypes.DWORD()
    readonly=not k.WriteFile(h,b'x',1,ctypes.byref(written),None) and ctypes.get_last_error()==5
    assert readonly
ready=Path(sys.argv[1]);release=Path(sys.argv[2])
row=dict(pid=os.getpid(),birth=str((times[0].dwHighDateTime<<32)|times[0].dwLowDateTime),handle_present=bool(raw),readonly=readonly)
partial=ready.with_suffix('.publishing');partial.write_text(json.dumps(row),encoding='utf-8');partial.replace(ready)
deadline=time.monotonic()+15
while not release.exists() and time.monotonic()<deadline:time.sleep(.02)
'''


SETUP = r"""$ErrorActionPreference='Stop'
. (Join-Path $env:LEASE_TEST_ROOT 'tools\startup_repair_common.ps1')
. (Join-Path $env:LEASE_TEST_ROOT 'tools\startup_assistant_capture.ps1')
function Get-CanonicalSourceStartupStorage {return (Join-Path $env:LEASE_TEST_SCRATCH 'canonical')}
$private=Join-Path $env:LEASE_TEST_SCRATCH 'guard-scope\startup-temp.critical-preflight';New-PrivateRepairDirectory $private
$guardPath=Join-Path $private 'startup-critical.lease'
$initial=Open-PrivateRepairFile $guardPath;$initial.Dispose()
$guard=[IO.File]::Open($guardPath,'Open','Read','Read')
$script:SourceStartupScratchLease=$guard;$script:SourceStartupCriticalMode=$true
$childEnvironment=New-RepairChildEnvironment $private
$childEnvironment['ANGERONA_STARTUP_SCRATCH_LEASE_HANDLE']='123456'
$arguments=@('-B','-I',(Join-Path $env:LEASE_TEST_SCRATCH 'child.py'),
    (Join-Path $env:LEASE_TEST_SCRATCH 'child-ready.json'),(Join-Path $env:LEASE_TEST_SCRATCH 'child-release'))
"""


def kernel():
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    k.OpenProcess.restype = wintypes.HANDLE
    k.GetProcessTimes.argtypes = (wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4))
    k.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    k.WaitForSingleObject.restype = wintypes.DWORD
    k.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
    k.CloseHandle.argtypes = (wintypes.HANDLE,)
    k.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                             wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    k.CreateFileW.restype = wintypes.HANDLE
    return k


def birth(k, handle):
    values = [wintypes.FILETIME() for _ in range(4)]
    if not k.GetProcessTimes(handle, *(ctypes.byref(v) for v in values)):
        raise ctypes.WinError(ctypes.get_last_error())
    return str((values[0].dwHighDateTime << 32) | values[0].dwLowDateTime)


def exclusive_write(k, path):
    handle = k.CreateFileW(str(path), 0x40000000, 0, None, 3, 0x00200000, None)
    if handle == wintypes.HANDLE(-1).value:
        return ctypes.get_last_error()
    assert k.CloseHandle(handle)
    return 0


def wait_json(path, process, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8-sig"))
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(f"Owned test parent exited before metadata: {stdout}\n{stderr}")
        time.sleep(.02)
    pytest.fail(f"Owned test fixture did not publish {path.name}")


@pytest.mark.parametrize("mode,orphan", [("native", False), ("capture", False), ("capture", True)])
def test_actual_producer_keeps_read_guard_after_parent_releases(tmp_path, mode, orphan):
    (tmp_path / "child.py").write_text(CHILD, encoding="utf-8")
    if mode == "native":
        start = r"""
$owner=Start-OwnedRepairWindow -FilePath $env:LEASE_TEST_PYTHON -Arguments $arguments -WorkingDirectory $env:LEASE_TEST_ROOT -Environment $childEnvironment -LogPath (Join-Path $private 'native.log')
$guard.Dispose();$script:SourceStartupScratchLease=$null
$clock=[Diagnostics.Stopwatch]::StartNew()
while($owner.ProcessId -eq 0 -and !$owner.HasExited -and $clock.ElapsedMilliseconds -lt 10000){Start-Sleep -Milliseconds 10}
if($owner.ProcessId -eq 0){throw 'Owned native producer never published its generation.'}
$row=@{pid=$owner.ProcessId;birth=[string]$owner.CreationFileTime;mode='native'}
"""
        finish = r"""
if(!$owner.WaitForExit(10000) -or $owner.ExitCode -ne 0){throw 'Owned native producer did not retire.'}
$owner.Dispose()
"""
    else:
        start = r"""
$owner=Invoke-SourceStartupCapturedAssistant -Python $env:LEASE_TEST_PYTHON -Arguments $arguments -WorkingDirectory $env:LEASE_TEST_ROOT -Environment $childEnvironment -StdoutPath (Join-Path $private 'out.log') -StderrPath (Join-Path $private 'err.log') -TimeoutSeconds 1
if(!$owner.TimedOut -or $owner.ExitCode -ne 124 -or !$owner.ScratchLeaseHandle){throw 'Capture did not preserve the exact active producer/read guard.'}
$guard.Dispose();$script:SourceStartupScratchLease=$null
$row=@{pid=$owner.ProcessId;birth=$owner.CreationTimeFileTime;mode='capture'}
"""
        finish = r"""
if(!$owner.Process.WaitForExit(10000)){throw 'Captured producer did not retire.'}
$clock=[Diagnostics.Stopwatch]::StartNew()
while(!$owner.ReadersComplete -and $clock.ElapsedMilliseconds -lt 3000){Start-Sleep -Milliseconds 20}
if(!$owner.ReadersComplete){throw 'Captured producer readers did not retire.'}
$owner.Process.Dispose()
"""
    source = SETUP + start + r"""
$partial=Join-Path $env:LEASE_TEST_SCRATCH 'parent-ready.publishing'
[IO.File]::WriteAllText($partial,($row|ConvertTo-Json -Compress))
[IO.File]::Move($partial,(Join-Path $env:LEASE_TEST_SCRATCH 'parent-ready.json'))
$clock=[Diagnostics.Stopwatch]::StartNew()
while(!(Test-Path -LiteralPath (Join-Path $env:LEASE_TEST_SCRATCH 'parent-release')) -and $clock.ElapsedMilliseconds -lt 12000){Start-Sleep -Milliseconds 20}
if(!(Test-Path -LiteralPath (Join-Path $env:LEASE_TEST_SCRATCH 'parent-release'))){throw 'Controller did not acknowledge exact native custody.'}
""" + ("[Environment]::Exit(0)\n" if orphan else finish)
    script = tmp_path / "parent.ps1"
    script.write_text(source, encoding="utf-8")
    environment = fixture_environment(tmp_path)
    k = kernel()
    process = subprocess.Popen([str(POWERSHELL), "-NoProfile", "-NonInteractive", "-File", str(script)],
                               cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    retained = {}
    try:
        parent = wait_json(tmp_path / "parent-ready.json", process)
        child = wait_json(tmp_path / "child-ready.json", process)
        for row in (parent, child):
            if row["pid"] in retained:
                assert birth(k, retained[row["pid"]]) == row["birth"]
                continue
            handle = k.OpenProcess(0x101001, False, row["pid"])
            assert handle
            assert birth(k, handle) == row["birth"]
            retained[row["pid"]] = handle
        assert child["handle_present"] is True
        assert child["readonly"] is True
        if orphan:
            (tmp_path / "parent-release").write_text("retained", encoding="ascii")
            process.wait(timeout=5)
            assert process.returncode == 0
            original = tmp_path / "guard-scope" / "startup-temp.critical-preflight"
            moved = tmp_path / "guard-scope" / "startup-temp.critical-preflight.moved"
            assert original.resolve().is_relative_to(tmp_path.resolve())
            assert moved.resolve().is_relative_to(tmp_path.resolve())
            try:
                original.rename(moved)
            except OSError as error:
                assert error.winerror in (5, 32)
            else:
                moved.rename(original)
                pytest.fail("A surviving producer's file guard did not pin its critical directory namespace")
            ancestor = tmp_path / "guard-scope"
            moved_ancestor = tmp_path / "guard-scope.moved"
            assert ancestor.resolve().is_relative_to(tmp_path.resolve())
            assert moved_ancestor.resolve().is_relative_to(tmp_path.resolve())
            try:
                ancestor.rename(moved_ancestor)
            except OSError as error:
                assert error.winerror in (5, 32)
            else:
                moved_ancestor.rename(ancestor)
                pytest.fail("A surviving producer's guard did not pin its critical ancestor namespace")
        # The original stream and every temporary parent bridge are closed.
        # For the orphan case the whole capture supervisor has also exited.
        assert k.WaitForSingleObject(retained[child["pid"]], 0) == 258
        assert exclusive_write(k, tmp_path / "guard-scope" / "startup-temp.critical-preflight" / "startup-critical.lease") == 32
        (tmp_path / "child-release").write_text("retire", encoding="ascii")
        if not orphan:
            (tmp_path / "parent-release").write_text("retained", encoding="ascii")
        stdout, stderr = process.communicate(timeout=12)
        assert process.returncode == 0, stdout + stderr
        for handle in retained.values():
            assert k.WaitForSingleObject(handle, 5000) == 0
        assert exclusive_write(k, tmp_path / "guard-scope" / "startup-temp.critical-preflight" / "startup-critical.lease") == 0
        if orphan:
            # The same moves now succeed: earlier rejection was active custody,
            # not an unrelated directory ACL or a working-directory pin.
            original.rename(moved)
            moved.rename(original)
            ancestor.rename(moved_ancestor)
            moved_ancestor.rename(ancestor)
    finally:
        (tmp_path / "child-release").write_text("retire", encoding="ascii")
        (tmp_path / "parent-release").write_text("retained", encoding="ascii")
        if process.poll() is None:
            try:
                process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.communicate(timeout=5)
        for handle in retained.values():
            if k.WaitForSingleObject(handle, 5000) != 0:
                assert k.TerminateProcess(handle, 1223)
                assert k.WaitForSingleObject(handle, 5000) == 0
            assert k.CloseHandle(handle)


@pytest.mark.parametrize("mode", ["native", "capture"])
def test_writable_scratch_guard_is_rejected_before_launch(tmp_path, mode):
    source = SETUP + r"""
$guard.Dispose();$script:SourceStartupScratchLease=$null
$writable=[IO.File]::Open($guardPath,'Open','ReadWrite','Read')
$refused=$false
try {
""" + (r"""
    $unexpected=Start-OwnedRepairWindow -FilePath $env:LEASE_TEST_PYTHON -Arguments @('-c','pass') -WorkingDirectory $private -Environment $childEnvironment -LogPath (Join-Path $private 'bad.log') -ScratchLease $writable -CriticalStartup
""" if mode == "native" else r"""
    $unexpected=Invoke-SourceStartupCapturedAssistant -Python $env:LEASE_TEST_PYTHON -Arguments @('-c','pass') -WorkingDirectory $private -Environment $childEnvironment -StdoutPath (Join-Path $private 'bad-out.log') -StderrPath (Join-Path $private 'bad-err.log') -ScratchLease $writable
""") + r"""
}catch{$refused=$_.Exception.Message -match 'read.only'}finally{$writable.Dispose()}
if(!$refused -or (Test-Path -LiteralPath (Join-Path $private 'bad.log')) -or
    (Test-Path -LiteralPath (Join-Path $private 'bad-out.log'))){throw 'Writable critical guard admitted a producer.'}
"""
    script = tmp_path / "rejected.ps1"
    script.write_text(source, encoding="utf-8")
    environment = fixture_environment(tmp_path)
    result = subprocess.run([str(POWERSHELL), "-NoProfile", "-NonInteractive", "-File", str(script)],
                            cwd=ROOT, env=environment, text=True, capture_output=True, timeout=20,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("mode", ["native", "capture"])
def test_ambient_numeric_handle_does_not_create_scratch_custody(tmp_path, mode):
    child = tmp_path / "ambient.py"
    child.write_text("import os,sys\nfrom pathlib import Path\n"
                     "Path(sys.argv[1]).write_text('present' if 'ANGERONA_STARTUP_SCRATCH_LEASE_HANDLE' in os.environ else 'absent',encoding='ascii')\n",
                     encoding="utf-8")
    source = SETUP + r"""
$guard.Dispose();$script:SourceStartupScratchLease=$null;$script:SourceStartupCriticalMode=$false
$marker=Join-Path $env:LEASE_TEST_SCRATCH 'ambient-result'
$arguments=@('-B','-I',(Join-Path $env:LEASE_TEST_SCRATCH 'ambient.py'),$marker)
""" + (r"""
$owner=Start-OwnedRepairWindow -FilePath $env:LEASE_TEST_PYTHON -Arguments $arguments -WorkingDirectory $private -Environment $childEnvironment -LogPath (Join-Path $private 'ambient.log')
try{if(!$owner.WaitForExit(10000) -or $owner.ExitCode -ne 0){throw 'Ambient native fixture failed.'}}finally{$owner.Dispose()}
""" if mode == "native" else r"""
$owner=Invoke-SourceStartupCapturedAssistant -Python $env:LEASE_TEST_PYTHON -Arguments $arguments -WorkingDirectory $private -Environment $childEnvironment -StdoutPath (Join-Path $private 'ambient-out.log') -StderrPath (Join-Path $private 'ambient-err.log') -TimeoutSeconds 10
if($owner.ExitCode -ne 0 -or !$owner.ReadersComplete -or $owner.ScratchLeaseHandle){throw 'Ambient capture fixture admitted custody.'}
$owner.Process.Dispose()
""") + r"""
if([IO.File]::ReadAllText($marker) -cne 'absent'){throw 'An ambient numeric handle was forwarded without an actual read guard.'}
"""
    _run_script(tmp_path, source)


def test_critical_mode_without_real_guard_does_not_start(tmp_path):
    source = SETUP + r"""
$guard.Dispose();$script:SourceStartupScratchLease=$null
$refused=$false
try {
    $unexpected=Start-OwnedRepairWindow -FilePath $env:LEASE_TEST_PYTHON -Arguments @('-c','pass') -WorkingDirectory $private -Environment $childEnvironment -LogPath (Join-Path $private 'missing-guard.log') -CriticalStartup
}catch{$refused=$_.Exception.Message -match 'requires a retained read guard'}
if(!$refused -or (Test-Path -LiteralPath (Join-Path $private 'missing-guard.log'))){throw 'Critical mode without actual custody admitted a producer.'}
"""
    _run_script(tmp_path, source)


@pytest.mark.parametrize("prefill,critical", [(0, True), (31 * 1024 * 1024, True), (0, False)])
def test_critical_native_output_discards_overflow_without_changing_exit(tmp_path, prefill, critical):
    (tmp_path / "quota.py").write_text("import sys\nsys.stdout.buffer.write(b'x'*(9*1024*1024))\nsys.stdout.flush()\nraise SystemExit(37)\n", encoding="utf-8")
    source = SETUP + f"\n$criticalMode=${str(critical).lower()}\n" + r"""
Initialize-OwnedRepairProcess
$prefillPath=Join-Path $private 'synthetic-prefill'
$fill=[IO.File]::Open($prefillPath,'CreateNew','Write','Read')
""" + f"try{{$fill.SetLength({prefill})}}finally{{$fill.Dispose()}}\n" + r"""
$log=Join-Path $private 'quota.log'
try {
    $code=Invoke-OwnedRepairProcess -FilePath $env:LEASE_TEST_PYTHON -Arguments @('-B','-I',(Join-Path $env:LEASE_TEST_SCRATCH 'quota.py')) -WorkingDirectory $env:LEASE_TEST_ROOT -Environment $childEnvironment -TimeoutSeconds 15 -LogPath $log -CriticalStartup:$criticalMode
    $length=(Get-Item -LiteralPath $log).Length
    Write-Output ('RESULT:'+(@{code=$code;length=$length}|ConvertTo-Json -Compress))
}finally{$guard.Dispose();[IO.File]::Delete($prefillPath);if(Test-Path -LiteralPath $log){[IO.File]::Delete($log)}}
"""
    result = _run_script(tmp_path, source)
    row = json.loads(next(line[7:] for line in result.stdout.splitlines() if line.startswith("RESULT:")))
    limit = min(8 * 1024 * 1024, 32 * 1024 * 1024 - prefill)
    assert row == {"code": 37, "length": limit}
    assert '"component":"critical-startup-output"' in result.stderr
    assert f'"dropped_bytes":{9 * 1024 * 1024 - limit}' in result.stderr


def test_critical_native_short_output_is_visible_before_actual_producer_exit(tmp_path):
    (tmp_path / "live-output.py").write_text(
        "import sys,time\nfrom pathlib import Path\n"
        "sys.stdout.buffer.write(b'ANGERONA_NATIVE_LIVE_MARKER\\n');sys.stdout.buffer.flush()\n"
        "release=Path(sys.argv[1]);deadline=time.monotonic()+12\n"
        "while not release.exists() and time.monotonic()<deadline:time.sleep(.02)\n"
        "raise SystemExit(37 if release.exists() else 38)\n", encoding="utf-8")
    source = SETUP + r"""
$release=Join-Path $env:LEASE_TEST_SCRATCH 'live-output-release'
$log=Join-Path $private 'live-output.log'
$owner=Start-OwnedRepairWindow -FilePath $env:LEASE_TEST_PYTHON -Arguments @('-B','-I',
    (Join-Path $env:LEASE_TEST_SCRATCH 'live-output.py'),$release) -WorkingDirectory $env:LEASE_TEST_ROOT `
    -Environment $childEnvironment -LogPath $log
try {
    $raw='';$clock=[Diagnostics.Stopwatch]::StartNew()
    while(!$raw -and $clock.ElapsedMilliseconds -lt 5000){
        if($owner.HasExited){throw 'Actual producer exited before live output observation.'}
        if([IO.File]::Exists($log)){
            $reader=[IO.File]::Open($log,'Open','Read','ReadWrite')
            try{
                $bytes=New-Object byte[] 128;$count=$reader.Read($bytes,0,$bytes.Length)
                $raw=[Text.Encoding]::UTF8.GetString($bytes,0,$count)
            }finally{$reader.Dispose()}
        }
        if(!$raw){Start-Sleep -Milliseconds 20}
    }
    if($raw -cne "ANGERONA_NATIVE_LIVE_MARKER`n" -or $owner.HasExited -or
        $owner.ProcessId -le 0 -or $owner.CreationFileTime -le 0){throw 'Bounded short output was not visible from the live exact native producer.'}
    [IO.File]::WriteAllText($release,'release')
    if(!$owner.WaitForExit(10000) -or $owner.ExitCode -ne 37){throw 'Actual live-output producer did not retire with its original exit.'}
    Write-Output ('RESULT:'+(@{live_marker=$true;code=$owner.ExitCode;bytes=(Get-Item -LiteralPath $log).Length}|ConvertTo-Json -Compress))
}catch{
    $failure=$_
    try{
        $rows=[Collections.Generic.List[object]]::new();$visited=0;$total=0L;$nonflat=0
        foreach($entry in [IO.Directory]::EnumerateFileSystemEntries($private)){
            if(++$visited -gt 128){break}
            $attributes=[IO.File]::GetAttributes($entry)
            $length=0L
            if(($attributes -band 0x410) -ne 0){$nonflat++}else{$length=([IO.FileInfo]::new($entry)).Length;$total+=$length}
            if($rows.Count -lt 16){$name=[IO.Path]::GetFileName($entry);$name=[regex]::Replace($name.Substring(0,[Math]::Min(96,$name.Length)),'[^\x20-\x7e]','?');$rows.Add(@{name=$name;attributes=[int]$attributes;bytes=$length})}
        }
        Write-Output ('FIXTURE-CRITICAL-INVENTORY:'+(@{visited=$visited;truncated=($visited -gt 128);bytes=$total;nonflat=$nonflat;entries=@($rows)}|ConvertTo-Json -Depth 4 -Compress))
    }catch{Write-Output 'FIXTURE-CRITICAL-INVENTORY-UNAVAILABLE'}
    throw $failure
}finally{
    [IO.File]::WriteAllText($release,'release')
    $owner.Dispose();$guard.Dispose()
}
"""
    result = _run_script(tmp_path, source)
    row = json.loads(next(line[7:] for line in result.stdout.splitlines() if line.startswith("RESULT:")))
    assert row == {"live_marker": True, "code": 37, "bytes": len("ANGERONA_NATIVE_LIVE_MARKER\n")}


@pytest.mark.parametrize("reason", ["non-flat", "entry-limit", "workspace-limit"])
def test_critical_native_zero_budget_reports_exact_bounded_reason(tmp_path, reason):
    (tmp_path / "budget.py").write_text(
        "import sys\nsys.stdout.buffer.write(b'quota-marker');sys.stdout.buffer.flush()\nraise SystemExit(37)\n",
        encoding="utf-8")
    setup = {
        "non-flat": "[void][IO.Directory]::CreateDirectory((Join-Path $private 'unknown-nested'))",
        "entry-limit": "for($index=0;$index -lt 127;$index++){[IO.File]::WriteAllBytes((Join-Path $private ('unknown-'+$index)),[byte[]]@())}",
        "workspace-limit": "$fill=[IO.File]::Open((Join-Path $private 'unknown-retained.bin'),'CreateNew','Write','Read');try{$fill.SetLength(32MB)}finally{$fill.Dispose()}",
    }[reason]
    source = SETUP + "\n" + setup + r"""
$log=Join-Path $private 'zero-budget.log'
$code=Invoke-OwnedRepairProcess -FilePath $env:LEASE_TEST_PYTHON -Arguments @('-B','-I',
    (Join-Path $env:LEASE_TEST_SCRATCH 'budget.py')) -WorkingDirectory $env:LEASE_TEST_ROOT `
    -Environment $childEnvironment -TimeoutSeconds 10 -LogPath $log
if($code -ne 37 -or ([IO.FileInfo]::new($log)).Length -ne 0){throw 'Zero budget changed native exit or admitted optional output.'}
$guard.Dispose()
"""
    result = _run_script(tmp_path, source)
    record = next(json.loads(line) for line in result.stderr.splitlines()
                  if line.startswith('{"component":"critical-startup-output"'))
    assert record["limit_reason"] == reason
    assert record["limit_bytes"] == 0 and record["dropped_bytes"] == len("quota-marker")
    assert record["failure_phase"] == record["exception_type"] == ""
    assert record["error_hresult"] is None
    assert record["inventory_entries"] <= 129
    assert len(json.dumps(record).encode("utf-8")) < 1024


def test_critical_native_sink_failure_reports_first_actual_kernel_error(tmp_path):
    source = SETUP + r"""
Initialize-OwnedRepairProcess
$sourcePath=Join-Path $private 'source-marker';[IO.File]::WriteAllBytes($sourcePath,[Text.Encoding]::ASCII.GetBytes('kernel-marker'))
$sinkPath=Join-Path $private 'read-only-sink';[IO.File]::WriteAllBytes($sinkPath,[byte[]]@())
$sourceStream=[IO.File]::Open($sourcePath,'Open','Read','ReadWrite')
$sink=[IO.File]::Open($sinkPath,'Open','Read','ReadWrite')
$flags=[Reflection.BindingFlags]'Instance,NonPublic'
$type=[Angerona.StartupRepairProcess].GetNestedType('CriticalOutput',[Reflection.BindingFlags]::NonPublic)
$constructor=$type.GetConstructors($flags)[0]
$pump=$constructor.Invoke(@($sourceStream.SafeFileHandle,$sink.SafeFileHandle,[long]1024,'available',[int]2,[long]13))
try{
    $type.GetMethod('Start',$flags).Invoke($pump,@())
    if(!$type.GetMethod('Wait',$flags).Invoke($pump,@([int]5000))){throw 'Actual failing sink pump did not retire.'}
    $json=$type.GetMethod('Diagnostic',$flags).Invoke($pump,@())
    $record=$json|ConvertFrom-Json
    if($record.failure_phase -notin @('sink-write','sink-flush') -or $record.error_hresult -ne -2147024891 -or
        $record.exception_type -cne 'UnauthorizedAccessException' -or $record.dropped_bytes -ne 13 -or
        $record.limit_bytes -ne 1024 -or $record.limit_reason -cne 'available' -or
        $json.Contains($private) -or [Text.Encoding]::UTF8.GetByteCount($json) -gt 1024){throw ('Actual kernel sink denial diagnostic was wrong: '+$json)}
    Write-Output ('RESULT:'+$json)
}finally{
    $type.GetMethod('Release',$flags).Invoke($pump,@());$sourceStream.Dispose();$sink.Dispose();$guard.Dispose()
}
"""
    result = _run_script(tmp_path, source)
    record = json.loads(next(line[7:] for line in result.stdout.splitlines() if line.startswith("RESULT:")))
    assert record["failure_phase"] in {"sink-write", "sink-flush"}
    assert record["error_hresult"] == -2147024891


def test_native_compiler_scratch_cannot_suppress_critical_live_output(tmp_path):
    (tmp_path / "compiler-child.py").write_text("print('COMPILER_SCOPE_LIVE', flush=True)\n", encoding="utf-8")
    source = SETUP + r"""
$script:RealCompilerCommand=Get-Command Add-Type -CommandType Cmdlet
$script:ObservedCompilerScratch='';$script:CompilerTransient=$null
function Add-Type {
    param([string]$TypeDefinition)
    if($TypeDefinition.Contains('public static class StartupRepairProcess')) {
        $script:ObservedCompilerScratch=[IO.Path]::GetFullPath($env:TEMP)
        $script:CompilerTransient=Join-Path $script:ObservedCompilerScratch 'compiler-still-active'
        [void][IO.Directory]::CreateDirectory($script:CompilerTransient)
    }
    & $script:RealCompilerCommand -TypeDefinition $TypeDefinition
}
$owner=$null
try {
    $log=Join-Path $private 'compiler-scope.log'
    $owner=Start-OwnedRepairWindow -FilePath $env:LEASE_TEST_PYTHON -Arguments @('-B','-I',
        (Join-Path $env:LEASE_TEST_SCRATCH 'compiler-child.py')) -WorkingDirectory $env:LEASE_TEST_ROOT `
        -Environment $childEnvironment -LogPath $log
    if(!$owner.WaitForExit(15000) -or $owner.ExitCode -ne 0){throw 'Actual compiler-scope child did not retire.'}
    if(!$script:ObservedCompilerScratch -or $script:ObservedCompilerScratch -ceq $private -or
        [IO.Path]::GetFileName($script:ObservedCompilerScratch) -cne 'process-compiler'){
        throw 'Native compilation used the flat critical log workspace.'
    }
    if([IO.File]::ReadAllText($log).Trim() -cne 'COMPILER_SCOPE_LIVE'){
        throw 'A retained compiler directory suppressed critical output.'
    }
    Write-Output 'RESULT:{"compiler_separate":true,"marker":true}'
}finally {
    if($owner){$owner.Dispose()};$guard.Dispose()
    if($script:CompilerTransient -and [IO.Directory]::Exists($script:CompilerTransient)){
        [IO.Directory]::Delete($script:CompilerTransient,$false)
    }
}
"""
    result = _run_script(tmp_path, source)
    row = json.loads(next(line[7:] for line in result.stdout.splitlines() if line.startswith("RESULT:")))
    assert row == {"compiler_separate": True, "marker": True}


def test_critical_capture_streams_share_remaining_workspace_budget(tmp_path):
    (tmp_path / "quota.py").write_text("import sys\nsys.stdout.buffer.write(b'x'*(2*1024*1024))\nsys.stdout.flush()\nsys.stderr.buffer.write(b'y'*(2*1024*1024))\nsys.stderr.flush()\nraise SystemExit(23)\n", encoding="utf-8")
    source = SETUP + r"""
Initialize-SourceStartupCapture
$prefillPath=Join-Path $private 'synthetic-prefill'
$fill=[IO.File]::Open($prefillPath,'CreateNew','Write','Read')
try{$fill.SetLength(31MB)}finally{$fill.Dispose()}
$out=Join-Path $private 'quota-out.log';$err=Join-Path $private 'quota-err.log'
try {
    $owner=Invoke-SourceStartupCapturedAssistant -Python $env:LEASE_TEST_PYTHON -Arguments @('-B','-I',(Join-Path $env:LEASE_TEST_SCRATCH 'quota.py')) -WorkingDirectory $env:LEASE_TEST_ROOT -Environment $childEnvironment -StdoutPath $out -StderrPath $err -TimeoutSeconds 10
    if(!$owner.Process.HasExited -or !$owner.ReadersComplete){throw 'Quota-bounded capture did not retire its real process/readers.'}
    Write-Output ('RESULT:'+(@{code=$owner.ExitCode;length=((Get-Item -LiteralPath $out).Length+(Get-Item -LiteralPath $err).Length);dropped=($owner.StdoutDropped+$owner.StderrDropped)}|ConvertTo-Json -Compress))
    $owner.Process.Dispose()
}finally{$guard.Dispose();[IO.File]::Delete($prefillPath);foreach($log in @($out,$err)){if(Test-Path -LiteralPath $log){[IO.File]::Delete($log)}}}
"""
    result = _run_script(tmp_path, source)
    row = json.loads(next(line[7:] for line in result.stdout.splitlines() if line.startswith("RESULT:")))
    assert row == {"code": 23, "length": 1024 * 1024, "dropped": 3 * 1024 * 1024}


def _run_script(tmp_path, source):
    script = tmp_path / "single.ps1"
    script.write_text(source, encoding="utf-8")
    environment = fixture_environment(tmp_path)
    result = subprocess.run([str(POWERSHELL), "-NoProfile", "-NonInteractive", "-File", str(script)],
                            cwd=ROOT, env=environment, text=True, capture_output=True, timeout=25,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0, result.stdout + result.stderr
    return result
