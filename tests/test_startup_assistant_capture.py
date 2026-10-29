"""Native inert startup capture: bounded bytes, identity, deadlines and custody."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time

import psutil
import pytest


ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / r"System32\WindowsPowerShell\v1.0\powershell.exe"
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell 5 native pipe capture")
LIMIT = 8 * 1024 * 1024


def run_capture(tmp_path, body, *, tail="", arguments=(), timeout=10):
    child = tmp_path / "inert-capture-child.py"
    child.write_text(body, encoding="utf-8")
    environment = dict(os.environ, ANGERONA_CAPTURE_ROOT=str(ROOT), ANGERONA_CAPTURE_SCRATCH=str(tmp_path),
                       ANGERONA_CAPTURE_PYTHON=sys._base_executable,
                       ANGERONA_CAPTURE_ARGS=json.dumps(list(arguments), ensure_ascii=True))
    source = tmp_path / "capture-harness.ps1"
    source.write_text(r"""$ErrorActionPreference='Stop'
. (Join-Path $env:ANGERONA_CAPTURE_ROOT 'tools\startup_assistant_capture.ps1')
$root=$env:ANGERONA_CAPTURE_SCRATCH
$private=Join-Path $root 'private-capture'
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($sid); $acl.SetAccessRuleProtection($true,$false)
foreach($identity in @($sid.Value,'S-1-5-18','S-1-5-32-544')) {
    $rule=[Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new($identity),'FullControl',
        'ContainerInherit, ObjectInherit','None','Allow')
    [void]$acl.AddAccessRule($rule)
}
[void][IO.Directory]::CreateDirectory($private,$acl)
$out=Join-Path $private 'stdout.log'; $err=Join-Path $private 'stderr.log'
$argv=@('-I',(Join-Path $root 'inert-capture-child.py'))
$extraArguments=ConvertFrom-Json $env:ANGERONA_CAPTURE_ARGS
foreach($extraArgument in $extraArguments) { $argv+=,[string]$extraArgument }
$ambientBefore=[string]$env:CAPTURE_CHILD_ONLY
$childEnvironment=@{SystemRoot=$env:SystemRoot;TEMP=$root;TMP=$root;CAPTURE_CHILD_ONLY='isolated fixture'}
$clock=[Diagnostics.Stopwatch]::StartNew()
""" + f"$timeout={timeout}\n" + tail + r"""
$result=Invoke-SourceStartupCapturedAssistant -Python $env:ANGERONA_CAPTURE_PYTHON `
    -Arguments $argv -WorkingDirectory $root -StdoutPath $out -StderrPath $err -TimeoutSeconds $timeout `
    -Environment $childEnvironment
$outputPrivate=$true
foreach($leaf in @($out,$err)) {
    $actual=[IO.File]::GetAccessControl($leaf)
    if(!$actual.AreAccessRulesProtected -or $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) {
        $outputPrivate=$false
    }
    foreach($entry in $actual.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if($entry.IsInherited -or $entry.AccessControlType -ne 'Allow' -or
            $entry.IdentityReference.Value -notin @($sid.Value,'S-1-5-18','S-1-5-32-544')) { $outputPrivate=$false }
    }
}
$answer=[ordered]@{ExitCode=$result.ExitCode;TimedOut=$result.TimedOut;ProcessId=$result.ProcessId;
    CreationTimeUtc=$result.CreationTimeUtc;CreationTimeFileTime=$result.CreationTimeFileTime;
    StdoutDropped=$result.StdoutDropped;StderrDropped=$result.StderrDropped;
    ReadersComplete=$result.ReadersComplete;CaptureError=$result.CaptureError;
    HandleValid=($result.Process.Handle -ne [IntPtr]::Zero);Elapsed=$clock.Elapsed.TotalSeconds;
    OutputPrivate=$outputPrivate;AmbientUntouched=([string]$env:CAPTURE_CHILD_ONLY -ceq $ambientBefore)}
if($result.ReadersComplete -and $result.Process.HasExited) { $result.Process.Dispose() }
$answer|ConvertTo-Json -Compress
""", encoding="utf-8")
    harness_out, harness_err = tmp_path / "harness-out.txt", tmp_path / "harness-err.txt"
    # .NET Framework inherits ambient inheritable handles during CreateProcess.
    # Use owned files here: an inert surviving child must not keep an outer
    # Python capture_output pipe open and delay observation of the PS exit.
    with harness_out.open("wb") as stdout, harness_err.open("wb") as stderr:
        result = subprocess.run([str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(source)],
                                cwd=ROOT, env=environment, stdout=stdout, stderr=stderr,
                                timeout=max(35, timeout + 15), check=False)
    captured, errors = harness_out.read_text(), harness_err.read_text()
    assert result.returncode == 0, captured + errors
    return json.loads(captured.strip()), tmp_path / "private-capture"


def retire_fixture(tmp_path, metadata, release):
    """Signal only this fixture and verify exact generation retirement, never kill."""
    release.write_text("retire", encoding="ascii")
    identity = json.loads(metadata.read_text())
    try:
        process = psutil.Process(identity["pid"])
        assert abs(process.create_time() - identity["birth"]) < 0.02
        assert str(tmp_path / "inert-capture-child.py").casefold() in " ".join(process.cmdline()).casefold()
        process.wait(timeout=15)
    except psutil.NoSuchProcess:
        pass


def test_capture_preserves_argv_exit_native_identity_and_child_environment(tmp_path):
    args = ["", "two words", 'embedded"quote', "trailing\\", "space and trailing\\", "caf\u00e9"]
    result, scratch = run_capture(tmp_path, "import json,os,sys\nprint(json.dumps({'args':sys.argv[1:],'env':os.getenv('CAPTURE_CHILD_ONLY')}))\nsys.stderr.write('bounded error')\nraise SystemExit(7)\n",
                                  arguments=args)
    assert result["ExitCode"] == 7 and not result["TimedOut"]
    assert result["ReadersComplete"] and result["HandleValid"]
    assert result["ProcessId"] > 0 and int(result["CreationTimeFileTime"]) > 0
    assert result["CreationTimeUtc"].endswith("Z")
    assert result["CaptureError"] == ""
    assert result["OutputPrivate"] and result["AmbientUntouched"]
    assert json.loads((scratch / "stdout.log").read_text()) == {"args": args, "env": "isolated fixture"}
    assert (scratch / "stderr.log").read_text() == "bounded error"
    assert result["StdoutDropped"] == result["StderrDropped"] == 0


def test_capture_accepts_actual_repair_environment_and_function_produced_paths(tmp_path):
    tail = r"""
. (Join-Path $env:ANGERONA_CAPTURE_ROOT 'tools\startup_repair_common.ps1')
$childEnvironment=New-RepairChildEnvironment $root
$childEnvironment['CAPTURE_CHILD_ONLY']='isolated fixture'
$childEnvironment['ANGERONA_DATA']=& {return [IO.Path]::GetFullPath($root)}
$childEnvironment['ANGERONA_DIAG_DIR']=Join-Path $root 'diagnostics'
$childEnvironment['ANGERONA_INSTALL_ROOT']=$root
"""
    result, scratch = run_capture(tmp_path,
        "import json,os\nprint(json.dumps({k:os.getenv(k) for k in ('CAPTURE_CHILD_ONLY','ANGERONA_DATA','ANGERONA_DIAG_DIR','ComSpec')}))\n",
        tail=tail)
    assert result["ExitCode"] == 0 and result["CaptureError"] == ""
    values = json.loads((scratch / "stdout.log").read_text())
    assert values["CAPTURE_CHILD_ONLY"] == "isolated fixture"
    assert Path(values["ANGERONA_DATA"]) == tmp_path
    assert Path(values["ANGERONA_DIAG_DIR"]) == tmp_path / "diagnostics"
    assert Path(values["ComSpec"]).name.casefold() == "cmd.exe"
    assert result["AmbientUntouched"]


@pytest.mark.parametrize("expression", ["$null", "42", "([pscustomobject]@{secret='must-not-be-rendered'})", '"nul"+[char]0+"value"'])
def test_capture_rejects_nonstring_or_nul_values_before_start_without_disclosing_them(tmp_path, expression):
    with pytest.raises(AssertionError, match="Invalid capture environment string value") as failure:
        run_capture(tmp_path, "from pathlib import Path\nPath('executed').write_text('bad')\n",
                    tail="$childEnvironment['BAD_VALUE']=" + expression + "\n")
    assert "must-not-be-rendered" not in str(failure.value)
    assert not (tmp_path / "executed").exists()
    assert not (tmp_path / "private-capture/stdout.log").exists()


def test_capture_caps_both_streams_and_reports_exact_discarded_bytes(tmp_path):
    count = LIMIT + 131_073
    body = f"import os\nleft={count}\nwhile left:\n n=min(left,8192)\n os.write(1,b'o'*n)\n os.write(2,b'e'*n)\n left-=n\n"
    # This is a 16+ MiB byte-cap/dual-pipe test, not a throughput benchmark.
    # WriteThrough output intentionally performs durable 8 KiB writes; loaded
    # volumes exceeded the generic 10/30-second fixture throughput budgets.
    # Use the unchanged production capture deadline for the full volume test.
    # The separate one-second case still exercises the exact timeout contract.
    result, scratch = run_capture(tmp_path, body, timeout=240)
    try:
        assert result["ExitCode"] == 0 and result["ReadersComplete"], json.dumps(result)
        assert (scratch / "stdout.log").stat().st_size == LIMIT
        assert (scratch / "stderr.log").stat().st_size == LIMIT
        assert result["StdoutDropped"] == result["StderrDropped"] == count - LIMIT
        assert result["CaptureError"] == ""
    finally:
        # These exact disposable outputs are large by design; retain no 16 MiB fixture.
        (scratch / "stdout.log").unlink()
        (scratch / "stderr.log").unlink()


def test_timeout_returns_live_exact_assistant_and_retains_process_handle(tmp_path):
    metadata, release = tmp_path / "identity.json", tmp_path / "release"
    body = """import json,os,pathlib,time
import ctypes
class FT(ctypes.Structure):_fields_=[('value',ctypes.c_ulonglong)]
created,exited,kernel,user=FT(),FT(),FT(),FT()
assert ctypes.windll.kernel32.GetProcessTimes(ctypes.c_void_p(-1),ctypes.byref(created),ctypes.byref(exited),ctypes.byref(kernel),ctypes.byref(user))
birth=(created.value-116444736000000000)/10000000
pathlib.Path('identity.json').write_text(json.dumps({'pid':os.getpid(),'birth':birth}))
until=time.monotonic()+12
while not pathlib.Path('release').exists() and time.monotonic()<until:time.sleep(.02)
"""
    try:
        result, _ = run_capture(tmp_path, body, timeout=1)
        assert result["ExitCode"] == 124 and result["TimedOut"]
        assert result["HandleValid"] and not result["ReadersComplete"]
        assert result["Elapsed"] < 6
        identity = json.loads(metadata.read_text())
        assert identity["pid"] == result["ProcessId"]
        process = psutil.Process(result["ProcessId"])
        assert abs(process.create_time() - identity["birth"]) < .02
        assert abs((int(result["CreationTimeFileTime"]) - 116444736000000000) / 10_000_000 - process.create_time()) < .02
    finally:
        if metadata.exists():
            retire_fixture(tmp_path, metadata, release)


def test_descendant_held_pipe_has_bounded_reader_grace(tmp_path):
    metadata, release = tmp_path / "identity.json", tmp_path / "release"
    body = """import json,os,pathlib,subprocess,sys,time
if len(sys.argv)==1:
 subprocess.Popen([sys.executable,'-I',__file__,'descendant'],close_fds=False)
else:
 import ctypes
 class FT(ctypes.Structure):_fields_=[('value',ctypes.c_ulonglong)]
 c,e,k,u=FT(),FT(),FT(),FT()
 assert ctypes.windll.kernel32.GetProcessTimes(ctypes.c_void_p(-1),ctypes.byref(c),ctypes.byref(e),ctypes.byref(k),ctypes.byref(u))
 pathlib.Path('identity.json').write_text(json.dumps({'pid':os.getpid(),'birth':(c.value-116444736000000000)/10000000}))
 until=time.monotonic()+12
 while not pathlib.Path('release').exists() and time.monotonic()<until:time.sleep(.02)
"""
    try:
        result, _ = run_capture(tmp_path, body)
        assert result["ExitCode"] == 0 and not result["TimedOut"]
        assert not result["ReadersComplete"]
        assert result["Elapsed"] < 6
    finally:
        deadline = time.monotonic() + 2
        while not metadata.exists() and time.monotonic() < deadline:
            time.sleep(.02)
        if metadata.exists():
            retire_fixture(tmp_path, metadata, release)


def test_existing_output_is_preserved_and_no_child_started(tmp_path):
    with pytest.raises(AssertionError, match=r"already\s+exists"):
        run_capture(tmp_path, "from pathlib import Path\nPath('executed').write_text('bad')",
                    tail="[IO.File]::WriteAllText($out,'preserved original')\n")
    assert (tmp_path / "private-capture" / "stdout.log").read_text() == "preserved original"
    assert not (tmp_path / "executed").exists()
