"""Exercise the pinned batch payload with inert helpers and private fixture data."""
from __future__ import annotations

import os
import json
import base64
import ctypes
from ctypes import wintypes
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


FIXTURE_DEFAULT_OWNER = r"""
$ErrorActionPreference='Stop'
# The inert verifier models an ordinary source session on a hosted admin
# runner. Set only this disposable test child's default owner to TokenUser:
# native CreateFile(NULL security descriptor) then has ordinary-user ownership.
# No group, elevation, privilege, DACL, product file or pytest-parent token changes.
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
public sealed class AngeronaFixtureOwnerScope : IDisposable {
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr value);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr buffer,int size,out int needed);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool SetTokenInformation(IntPtr token,int kind,ref IntPtr value,int size);
    IntPtr token, original, user;
    bool changed;
    readonly string originalOwner, tokenUser;
    readonly bool administrator;
    public bool Restored { get; private set; }
    static IntPtr Read(IntPtr token,int kind) {
        int needed;
        GetTokenInformation(token,kind,IntPtr.Zero,0,out needed);
        if(needed<=0 || needed>65536) throw new InvalidOperationException("Fixture token information size is invalid.");
        IntPtr buffer=Marshal.AllocHGlobal(needed);
        try {
            if(!GetTokenInformation(token,kind,buffer,needed,out needed)) throw new Win32Exception(Marshal.GetLastWin32Error());
            return buffer;
        } catch { Marshal.FreeHGlobal(buffer); throw; }
    }
    static string Sid(IntPtr information) { return new SecurityIdentifier(Marshal.ReadIntPtr(information)).Value; }
    static bool Administrator() {
        using(WindowsIdentity identity=WindowsIdentity.GetCurrent()) {
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }
    static string CurrentUser() {
        using(WindowsIdentity identity=WindowsIdentity.GetCurrent()) { return identity.User.Value; }
    }
    public AngeronaFixtureOwnerScope() {
        administrator=Administrator();
        if(!OpenProcessToken(GetCurrentProcess(),0x88u,out token)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            IntPtr statistics=Read(token,10);
            try {
                long caller;
                if(!Int64.TryParse(Environment.GetEnvironmentVariable("ANGERONA_FIXTURE_CALLER_TOKEN_ID"),out caller) ||
                    Marshal.ReadInt64(statistics)==caller) throw new InvalidOperationException("Fixture child does not have a distinct caller token; owner adjustment refused.");
            } finally { Marshal.FreeHGlobal(statistics); }
            original=Read(token,4); user=Read(token,1);
            originalOwner=Sid(original); tokenUser=Sid(user);
            if(tokenUser!=CurrentUser()) throw new InvalidOperationException("Fixture process identity differs from the current user.");
            IntPtr requested=Marshal.ReadIntPtr(user);
            if(!SetTokenInformation(token,4,ref requested,IntPtr.Size)) throw new Win32Exception(Marshal.GetLastWin32Error());
            changed=true;
            IntPtr actual=Read(token,4);
            try { if(Sid(actual)!=tokenUser) throw new InvalidOperationException("Fixture default owner did not become TokenUser."); }
            finally { Marshal.FreeHGlobal(actual); }
            if(Administrator()!=administrator) throw new InvalidOperationException("Fixture owner adjustment changed elevation state.");
        } catch { Dispose(); throw; }
    }
    public void Dispose() {
        if(token==IntPtr.Zero) return;
        try {
            if(changed) {
                IntPtr prior=Marshal.ReadIntPtr(original);
                if(!SetTokenInformation(token,4,ref prior,IntPtr.Size)) throw new Win32Exception(Marshal.GetLastWin32Error());
                changed=false;
                IntPtr actual=Read(token,4);
                try { if(Sid(actual)!=originalOwner || Administrator()!=administrator) throw new InvalidOperationException("Fixture default owner/elevation did not restore."); }
                finally { Marshal.FreeHGlobal(actual); }
            }
            Restored=true;
        } finally {
            if(original!=IntPtr.Zero) { Marshal.FreeHGlobal(original); original=IntPtr.Zero; }
            if(user!=IntPtr.Zero) { Marshal.FreeHGlobal(user); user=IntPtr.Zero; }
            IntPtr held=token; token=IntPtr.Zero;
            if(!CloseHandle(held)) throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }
}
'@
$fixtureOwnerScope=[AngeronaFixtureOwnerScope]::new()
"""


def _fixture_caller_token_state():
    """Read only the pytest caller's primary token identity/default owner."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    advapi.OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE))
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD))
    advapi.GetTokenInformation.restype = wintypes.BOOL
    advapi.GetLengthSid.argtypes = (wintypes.LPVOID,)
    advapi.GetLengthSid.restype = wintypes.DWORD
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        information = {}
        for kind in (4, 10):
            needed = wintypes.DWORD()
            advapi.GetTokenInformation(token, kind, None, 0, ctypes.byref(needed))
            assert 0 < needed.value <= 65536
            buffer = ctypes.create_string_buffer(needed.value)
            if not advapi.GetTokenInformation(token, kind, buffer, len(buffer), ctypes.byref(needed)):
                raise ctypes.WinError(ctypes.get_last_error())
            information[kind] = buffer
        owner = information[4]
        owner_pointer = ctypes.c_void_p.from_buffer(owner).value
        assert ctypes.addressof(owner) <= owner_pointer < ctypes.addressof(owner) + len(owner)
        owner_length = advapi.GetLengthSid(owner_pointer)
        assert 0 < owner_length <= 1024 and owner_pointer + owner_length <= ctypes.addressof(owner) + len(owner)
        return ctypes.c_int64.from_buffer(information[10]).value, ctypes.string_at(owner_pointer, owner_length)
    finally:
        if not kernel.CloseHandle(token):
            raise ctypes.WinError(ctypes.get_last_error())


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
    script.write_text(FIXTURE_DEFAULT_OWNER + "\ntry {\n" + setup + network_guard + prelude + payload
                      + "\n}finally{\n$fixtureOwnerScope.Dispose()\n"
                      + "if(!$fixtureOwnerScope.Restored){throw 'Fixture default owner was not restored.'}\n"
                      + "[Console]::WriteLine('FIXTURE_DEFAULT_OWNER_RESTORED')\n}\n", encoding="utf-8")
    caller_token = _fixture_caller_token_state()
    environment = dict(os.environ, ANGERONA_INSTALL_ROOT=str(root), ANGERONA_SETUP_ONLY="1",
                       ANGERONA_FIXTURE_CALLER_TOKEN_ID=str(caller_token[0]),
                       TEMP=str(tmp_path), TMP=str(tmp_path), PSModulePath="")
    try:
        result = subprocess.run([str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script)],
                                cwd=root, env=environment, text=True, capture_output=True, timeout=60, check=False)
    finally:
        assert _fixture_caller_token_state() == caller_token, "The pytest caller's token identity/default owner changed."
    assert "FIXTURE_DEFAULT_OWNER_RESTORED" in result.stdout, result.stdout + result.stderr
    return result


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
