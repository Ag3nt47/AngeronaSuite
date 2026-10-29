"""Exercise the pinned batch payload with inert helpers and private fixture data."""
from __future__ import annotations

import os
import json
import base64
from pathlib import Path
import re
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))
try:
    import build_startup_recovery_manifest as BUILDER
    import update_startup_bootstrap as BOOTSTRAP
finally:
    sys.path.remove(str(TOOLS))
POWERSHELL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / r"System32\WindowsPowerShell\v1.0\powershell.exe"
pytestmark = pytest.mark.skipif(os.name != "nt", reason="OS PowerShell pinned bootstrap")


def ps_literal(path):
    return "'" + str(path).replace("'", "''") + "'"


def make_fixture(tmp_path, supervisor=None, *, elevated=False):
    root = tmp_path / "installation"
    storage = tmp_path / "private-source-data"
    state = tmp_path / "private-bundle-state"
    for relative in BUILDER.FILES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# Inert operational fixture\n", encoding="utf-8")
    common = (TOOLS / "startup_repair_common.ps1").read_text(encoding="utf-8-sig")
    (root / "tools/startup_repair_common.ps1").write_text(
        BOOTSTRAP.function_text(common, "Read-SourceStartupRecoveryPreferences") + "\n", encoding="utf-8")
    (root / "tools/Invoke-AngeronaSourceStartup.ps1").write_text(supervisor or r"""
param([string]$RepositoryRoot,[switch]$SetupOnly)
if(!$SetupOnly) {throw 'Fixture must never open a real app or recovery UI.'}
[IO.File]::WriteAllText((Join-Path $RepositoryRoot 'supervisor-receipt.json'),'inert supervisor executed')
exit 0
""", encoding="utf-8")
    verifier = (TOOLS / "verify_startup_recovery_bundle.ps1").read_text(encoding="utf-8-sig")
    # The hosted runner may be elevated; this newly pinned inert installation
    # supplies only the native-role answer. All original admission, file/ACL,
    # namespace and mutation-lease checks remain in its copied verifier.
    principal = "$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())"
    assert verifier.count(principal) == 1
    verifier = verifier.replace(principal,
        "$principal=[pscustomobject]@{}\n"
        "    $principal | Add-Member -MemberType ScriptMethod -Name IsInRole -Value {param($role);return "
        + ("$true" if elevated else "$false") + "}")
    for name, value in (("Get-BundleStateRoot", state), ("Get-BundleDataRoot", storage)):
        verifier, count = re.subn(rf"(?ms)^function {name}\s*\{{.*?^\}}",
                                  lambda match: f"function {name} {{ return {ps_literal(value)} }}", verifier)
        assert count == 1
    # Production has no transport switch. Replace its internal constructor only
    # inside this newly pinned fixture so any unexpected child HTTP fails closed.
    verifier, count = re.subn(r"(?ms)^function New-BundleBlobRequest\([^\n]*\) \{.*?^\}",
                              "function New-BundleBlobRequest { throw 'Fixture network forbidden.' }", verifier)
    assert count == 1
    (root / BUILDER.VERIFIER).write_text(verifier, encoding="utf-8")
    (root / "tools/startup_bootstrap_payload.ps1").write_bytes((TOOLS / "startup_bootstrap_payload.ps1").read_bytes())
    raw, _ = BUILDER.build_manifest(root)
    manifest = root / BUILDER.MANIFEST
    manifest.parent.mkdir()
    manifest.write_bytes(raw)
    payload = BOOTSTRAP.payload(root)
    payload, count = re.subn(r"(?m)^\$storage=.*$", lambda match: "$storage=" + ps_literal(storage), payload)
    assert count == 1
    return root, storage, state, payload


NETWORK_GUARD = r"""
Add-Type -TypeDefinition @'
using System;
using System.Net;
public sealed class AngeronaFixtureNetworkBlocker : IWebRequestCreate {
    public WebRequest Create(Uri address) { throw new InvalidOperationException("Fixture bootstrap network forbidden."); }
}
'@
if(![Net.WebRequest]::RegisterPrefix('https://api.github.com/repos/Ag3nt47/AngeronaSuite/git/blobs/',[AngeronaFixtureNetworkBlocker]::new())) {
    throw 'Fixture network guard was not installed.'
}
"""


def execute(tmp_path, root, storage, payload, settings, *, network_guard=NETWORK_GUARD, prelude=""):
    script = tmp_path / "bootstrap-fixture.ps1"
    # Definition-only import lets us create the real private ACL before the
    # complete bootstrap reads the fixture's preferences. No product main runs.
    setup = ("$ErrorActionPreference='Stop'\n. " + ps_literal(root / BUILDER.VERIFIER)
             + " -Root " + ps_literal(root) + " -ManifestSha256 ('0'*64) -ManifestBlobSha1 ('0'*40)\n"
             + "New-BundlePrivateDirectory " + ps_literal(storage) + "\n"
             # A hosted administrator token defaults plain WriteAllText files
             # to Administrators ownership, even in this user-owned directory.
             # Exercise the original consent reader with a genuinely private
             # fixture file instead of weakening its owner or DACL checks.
             + "function Write-FixturePrivateText([string]$FixturePath,[string]$FixtureText) {\n"
             + "$fixtureOwner=[Security.Principal.WindowsIdentity]::GetCurrent().User\n"
             + "$fixtureAcl=[Security.AccessControl.FileSecurity]::new()\n"
             + "$fixtureAcl.SetOwner($fixtureOwner);$fixtureAcl.SetAccessRuleProtection($true,$false)\n"
             + "foreach($fixtureSid in @($fixtureOwner.Value,'S-1-5-18','S-1-5-32-544')) {\n"
             + "    [void]$fixtureAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(\n"
             + "        [Security.Principal.SecurityIdentifier]::new($fixtureSid),\n"
             + "        [Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow))\n"
             + "}\n"
             + "$fixtureSettings=[IO.FileStream]::new($FixturePath"
             + ",[IO.FileMode]::CreateNew,([Security.AccessControl.FileSystemRights]::Read -bor "
             + "[Security.AccessControl.FileSystemRights]::Write),"
             + "[IO.FileShare]::Read,4096,[IO.FileOptions]::None,$fixtureAcl)\n"
             + "try {\n"
             + "    $fixtureBytes=[Text.UTF8Encoding]::new($false).GetBytes($FixtureText)\n"
             + "    $fixtureSettings.Write($fixtureBytes,0,$fixtureBytes.Length);$fixtureSettings.Flush($true)\n"
             + "}finally{$fixtureSettings.Dispose()}\n"
             + "}\n"
             + "Write-FixturePrivateText " + ps_literal(storage / "settings.json") + " " + ps_literal(settings) + "\n")
    # An absent verifier case still needs definition-only setup from the exact
    # reviewed inert fixture copy; it never imports the deleted operational path.
    setup_verifier = tmp_path / "fixture-setup-verifier.ps1"
    setup_source = root / BUILDER.VERIFIER
    if (tmp_path / "removed-verifier.ps1").exists():
        setup_verifier.write_bytes((tmp_path / "removed-verifier.ps1").read_bytes())
    elif setup_source.exists():
        setup_verifier.write_bytes(setup_source.read_bytes())
    else:
        setup_verifier.write_bytes((tmp_path / "removed-verifier.ps1").read_bytes())
    setup = setup.replace(ps_literal(setup_source), ps_literal(setup_verifier), 1)
    script.write_text(setup + network_guard + prelude + payload, encoding="utf-8")
    environment = dict(os.environ, ANGERONA_INSTALL_ROOT=str(root), ANGERONA_SETUP_ONLY="1",
                       TEMP=str(tmp_path), TMP=str(tmp_path), PSModulePath="")
    return subprocess.run([str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script)],
                          cwd=root, env=environment, text=True, capture_output=True, timeout=60, check=False)


def test_full_intact_payload_honors_master_off_and_runs_only_verified_inert_supervisor(tmp_path):
    root, storage, _, payload = make_fixture(tmp_path)
    result = execute(tmp_path, root, storage, payload,
                     '{"startup_recovery_enabled":false,"startup_recovery_github_enabled":false}')
    assert result.returncode == 0, result.stdout + result.stderr
    assert (root / "supervisor-receipt.json").read_text() == "inert supervisor executed"
    assert not (root / ".tmp/repair-wheels/startup-repair.lock").exists()


def test_elevated_fixture_is_refused_before_any_supervisor_or_source_mutation(tmp_path):
    root, storage, _, payload = make_fixture(tmp_path, elevated=True)
    original = (root / "src/angerona/startup.py").read_bytes()
    result = execute(tmp_path, root, storage, payload,
                     '{"startup_recovery_enabled":true,"startup_recovery_github_enabled":false}')
    assert result.returncode == 1, result.stdout + result.stderr
    assert "requires an unelevated user session" in result.stdout + result.stderr
    assert not (root / "supervisor-receipt.json").exists()
    assert (root / "src/angerona/startup.py").read_bytes() == original
    assert not (root / ".tmp/repair-wheels/startup-repair.lock").exists()


def test_github_off_changed_operational_payload_holds_without_network_or_overwrite(tmp_path):
    root, storage, state, payload = make_fixture(tmp_path)
    target = root / "src/angerona/startup.py"
    target.write_text("# operator edit\n")
    result = execute(tmp_path, root, storage, payload,
                     '{"startup_recovery_enabled":true,"startup_recovery_github_enabled":false}')
    assert result.returncode == 1, result.stdout + result.stderr
    assert not (root / "supervisor-receipt.json").exists()
    assert target.read_text() == "# operator edit\n"
    assert "offline repair is held" in (state / "report.json").read_text()
    assert "network forbidden" not in result.stdout + result.stderr


def test_github_off_missing_verifier_holds_before_any_mutable_helper(tmp_path):
    root, storage, _, payload = make_fixture(tmp_path)
    verifier = root / BUILDER.VERIFIER
    (tmp_path / "removed-verifier.ps1").write_bytes(verifier.read_bytes())
    verifier.unlink()
    result = execute(tmp_path, root, storage, payload,
                     '{"startup_recovery_enabled":true,"startup_recovery_github_enabled":false}')
    assert result.returncode == 1, result.stdout + result.stderr
    assert "automatic GitHub recovery is disabled" in result.stdout + result.stderr
    assert not verifier.exists() and not (root / "supervisor-receipt.json").exists()


def test_duplicate_master_consent_disables_mutation_for_changed_bundle(tmp_path):
    root, storage, state, payload = make_fixture(tmp_path)
    target = root / "src/angerona/startup.py"
    target.write_text("# operator edit\n")
    result = execute(tmp_path, root, storage, payload,
                     '{"startup_recovery_enabled":true,"startup_recovery_enabled":true,"startup_recovery_github_enabled":false}')
    assert result.returncode == 1, result.stdout + result.stderr
    assert not (root / "supervisor-receipt.json").exists()
    assert target.read_text() == "# operator edit\n"
    assert '"outcome":"changed"' in (state / "report.json").read_text()
    assert not (root / ".tmp/repair-wheels/startup-repair.lock").exists()


def test_generated_batch_command_has_complete_quoting_and_line_only_payload_marker(tmp_path):
    raw = (ROOT / "start-angerona.bat").read_text(encoding="utf-8-sig")
    line = next(line for line in raw.splitlines() if line.startswith('"%ANGERONA_POWERSHELL%"') and " -Command \"$s=" in line)
    assert line.endswith('"') and "^:__ANGERONA_PINNED_BOOTSTRAP__\\r?$" in line
    assert len(raw.split("\n" + BOOTSTRAP.MARKER + "\n")) == 2
    command = line.split(' -Command "', 1)[1][:-1]
    root, _, _, payload = make_fixture(tmp_path)
    for name, content in (("extracted-command.ps1", command), ("generated-payload.ps1", payload)):
        path = tmp_path / name
        path.write_text(content, encoding="utf-8")
        parser = "$issues=$null;[void][Management.Automation.Language.Parser]::ParseFile(" + ps_literal(path) + ",[ref]$null,[ref]$issues);if($issues){$issues|Out-String|Write-Error;exit 1}"
        result = subprocess.run([str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", parser],
                                cwd=root, capture_output=True, text=True, timeout=30, check=False)
        assert result.returncode == 0, result.stdout + result.stderr


FIXTURE_BLOB_TRANSPORT = r"""
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net;
public sealed class AngeronaFixtureBlobResponse : WebResponse {
    readonly byte[] data;
    public AngeronaFixtureBlobResponse(byte[] value) { data=value; }
    public override Stream GetResponseStream() { return new MemoryStream(data,false); }
}
public sealed class AngeronaFixtureBlobRequest : WebRequest {
    public override IWebProxy Proxy { get;set; }
    public override int Timeout { get;set; }
    public string UserAgent { get;set; }
    public int ReadWriteTimeout { get;set; }
    public bool AllowAutoRedirect { get;set; }
    public override WebResponse GetResponse() { return new AngeronaFixtureBlobResponse(AngeronaFixtureBlobFactory.Body); }
}
public sealed class AngeronaFixtureBlobFactory : IWebRequestCreate {
    public static byte[] Body;
    public static string Expected;
    public static string[] Locks;
    public WebRequest Create(Uri uri) {
        if(uri.AbsoluteUri!=Expected) throw new InvalidOperationException("An unpinned URI reached fixture transport.");
        foreach(string path in Locks) {
            using(var file=File.Open(path,FileMode.Open,FileAccess.ReadWrite,FileShare.ReadWrite)) {
                bool excluded=false;
                try { file.Lock(0,1); } catch(IOException) { excluded=true; }
                if(!excluded) {file.Unlock(0,1);throw new InvalidOperationException("Bootstrap publication lock was not held.");}
            }
        }
        return new AngeronaFixtureBlobRequest();
    }
}
'@
[AngeronaFixtureBlobFactory]::Body=[IO.File]::ReadAllBytes((Join-Path $env:TEMP 'fixture-blob-response.json'))
$metadata=[Text.Encoding]::UTF8.GetString([AngeronaFixtureBlobFactory]::Body)|ConvertFrom-Json
[AngeronaFixtureBlobFactory]::Expected='https://api.github.com/repos/Ag3nt47/AngeronaSuite/git/blobs/'+$metadata.sha
[AngeronaFixtureBlobFactory]::Locks=@((Join-Path $env:ANGERONA_INSTALL_ROOT '.tmp\repair-wheels\startup-repair.lock'),
    (Join-Path (Get-BundleDataRoot) 'startup-helper.lock'),(Join-Path (Get-BundleDataRoot) 'angerona.instance.lock'))
if(![Net.WebRequest]::RegisterPrefix('https://api.github.com/repos/Ag3nt47/AngeronaSuite/git/blobs/',[AngeronaFixtureBlobFactory]::new())) {
    throw 'Fixture blob transport could not be registered.'
}
"""


@pytest.mark.parametrize("full", [False, True])
def test_pinned_verifier_self_restore_holds_all_mutation_locks_and_preserves_private_edits(tmp_path, full):
    root, storage, _, payload = make_fixture(tmp_path)
    verifier = root / BUILDER.VERIFIER
    original = verifier.read_bytes()
    canonical = BUILDER.canonical_text(original)
    (tmp_path / "removed-verifier.ps1").write_bytes(original)
    response = dict(encoding="base64", sha=BUILDER.git_blob(canonical), size=len(canonical),
                    content=base64.b64encode(canonical).decode())
    (tmp_path / "fixture-blob-response.json").write_text(json.dumps(response), encoding="utf-8")
    edited = b"# operator verifier edit\r\n"
    verifier.write_bytes(edited)
    prelude = ""
    if full:
        prelude = r"""
$archive=Join-Path (Get-BundleDataRoot) 'logs\startup-recovery\bootstrap-preserved'
New-BundlePrivateDirectory $archive
for($i=0;$i -lt 16;$i++) {Write-FixturePrivateText (Join-Path $archive ($i.ToString('x32')+'.verifier.edited')) 'retained original'}
"""
    result = execute(tmp_path, root, storage, payload,
                     '{"startup_recovery_enabled":true,"startup_recovery_github_enabled":true}',
                     network_guard=FIXTURE_BLOB_TRANSPORT, prelude=prelude)
    archive = storage / "logs/startup-recovery/bootstrap-preserved"
    copies = list(archive.glob("*.verifier.edited"))
    if full:
        assert result.returncode == 1, result.stdout + result.stderr
        assert "Preserved bootstrap edits reached their limit" in result.stdout + result.stderr
        assert verifier.read_bytes() == edited
        assert len(copies) == 16 and all(item.read_text() == "retained original" for item in copies)
        assert not (root / "supervisor-receipt.json").exists()
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert BUILDER.canonical_text(verifier.read_bytes()) == canonical
        assert [item.read_bytes() for item in copies] == [edited]
        assert (root / "supervisor-receipt.json").exists()


def test_full_pinned_bootstrap_permits_sibling_runtime_rename_and_holds_namespace_attacks(tmp_path):
    supervisor = r"""
param([string]$RepositoryRoot,[switch]$SetupOnly)
$ErrorActionPreference='Stop'
if(!$SetupOnly){throw 'Only inert supervisor execution is allowed.'}
[Environment]::CurrentDirectory=Split-Path -Parent $RepositoryRoot
$runtime=Join-Path $RepositoryRoot 'inert-runtime';$backup=Join-Path $RepositoryRoot 'inert-runtime-backup'
[void][IO.Directory]::CreateDirectory($runtime)
[IO.File]::WriteAllText((Join-Path $runtime 'identity'),'owned inert runtime')
[IO.Directory]::Move($runtime,$backup)
Move-Item -LiteralPath $backup -Destination $runtime
$blocked=$false
try {[IO.Directory]::Move($RepositoryRoot,$RepositoryRoot+'.retargeted')}catch{$blocked=$true}
if(!$blocked){throw 'Pinned source ancestor could be renamed.'}
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class GuardedReparseProbe {
    [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern IntPtr CreateFileW(string p,uint a,uint s,IntPtr q,uint c,uint f,IntPtr t);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool DeviceIoControl(IntPtr h,uint c,byte[] b,uint n,IntPtr o,uint z,out uint r,IntPtr v);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    public static int Set(string source,string target) {
        var h=CreateFileW(source,0x40000000,7,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
        if(h==new IntPtr(-1))return Marshal.GetLastWin32Error();
        try {
            var sub=Encoding.Unicode.GetBytes(@"\??\"+target);var print=Encoding.Unicode.GetBytes(target);
            var b=new byte[16+sub.Length+2+print.Length+2];
            Array.Copy(BitConverter.GetBytes(0xA0000003u),0,b,0,4);Array.Copy(BitConverter.GetBytes((ushort)(b.Length-8)),0,b,4,2);
            Array.Copy(BitConverter.GetBytes((ushort)sub.Length),0,b,10,2);Array.Copy(BitConverter.GetBytes((ushort)(sub.Length+2)),0,b,12,2);Array.Copy(BitConverter.GetBytes((ushort)print.Length),0,b,14,2);
            Array.Copy(sub,0,b,16,sub.Length);Array.Copy(print,0,b,18+sub.Length,print.Length);uint got;
            return DeviceIoControl(h,0x900A4,b,(uint)b.Length,IntPtr.Zero,0,out got,IntPtr.Zero)?0:Marshal.GetLastWin32Error();
        }finally{CloseHandle(h);}
    }
}
'@
$other=Join-Path (Split-Path -Parent $RepositoryRoot) 'inert-other-target'
[void][IO.Directory]::CreateDirectory($other)
$errorCode=[GuardedReparseProbe]::Set($RepositoryRoot,$other)
if($errorCode -notin @(5,32,145)){throw ('Pinned nonempty source ancestor could be retargeted; error='+$errorCode)}
[IO.File]::WriteAllText((Join-Path $RepositoryRoot 'supervisor-receipt.json'),'runtime moved under verified leases; namespace attacks held')
exit 0
"""
    root, storage, _, payload = make_fixture(tmp_path, supervisor)
    result = execute(tmp_path, root, storage, payload,
                     '{"startup_recovery_enabled":true,"startup_recovery_github_enabled":false}')
    assert result.returncode == 0, result.stdout + result.stderr
    assert (root / "inert-runtime/identity").read_text() == "owned inert runtime"
    assert not (root / "inert-runtime-backup").exists()
    assert "namespace attacks held" in (root / "supervisor-receipt.json").read_text()
