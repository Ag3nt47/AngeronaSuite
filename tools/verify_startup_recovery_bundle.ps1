[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Root,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ManifestSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$ManifestBlobSha1,
    [ValidatePattern('^$|^[0-9a-fA-F]{64}$')][string]$ExpectedVerifierSha256 = '',
    [switch]$CheckOnly,
    [switch]$Offline,
    [switch]$RunSupervisor,
    [switch]$SetupOnly
)

$ErrorActionPreference='Stop'
$script:BundleFiles=@(
    'Repair-Angerona-Python.ps1',
    'constraints-release.txt',
    'pyproject.toml',
    'requirements-bootstrap-pip.txt',
    'requirements-release-hashed.txt',
    'src/angerona/core/startup_diagnostics.py',
    'src/angerona/core/startup_recovery.py',
    'src/angerona/startup.py',
    'tools/Invoke-AngeronaSourceStartup.ps1',
    'tools/Invoke-AngeronaStartupRepair.ps1',
    'tools/Show-AngeronaStartupRecovery.ps1',
    'tools/angerona_recovery.py',
    'tools/build_srt_compat_wheel.py',
    'tools/source_trust_preflight.py',
    'tools/startup_assistant_capture.ps1',
    'tools/startup_repair_common.ps1',
    'tools/startup_source_recovery.py'
)
$script:BundleDeadline=$null

function Assert-BundlePlainPath([string]$Path,[switch]$AllowHardLinks) {
    if($Path -notmatch '^[A-Za-z]:\\' -or $Path.StartsWith('\\')) { throw 'Recovery bundle requires an absolute local path.' }
    $cursor=[IO.Path]::GetFullPath($Path)
    while($cursor) {
        if(Test-Path -LiteralPath $cursor) {
            $item=Get-Item -LiteralPath $cursor -Force
            if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                (!$AllowHardLinks -and !$item.PSIsContainer -and $item.LinkType -eq 'HardLink')) {
                throw 'Recovery bundle refuses linked or redirected paths.'
            }
        }
        $cursor=[IO.Path]::GetDirectoryName($cursor)
    }
}

function Get-BundleInstalledRoot { return [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot)) }

function Assert-BundleRoot([string]$Path) {
    Assert-BundlePlainPath $Path
    if(![string]::Equals([IO.Path]::GetFullPath($Path),(Get-BundleInstalledRoot),[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Recovery bundle accepts only its own fixed installation root.'
    }
    $drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($Path))
    if(!$drive.IsReady -or $drive.DriveType -ne 'Fixed') { throw 'Recovery bundle requires a ready fixed local drive.' }
    $principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Mutable source recovery requires an unelevated user session.'
    }
}

function Get-BundleStateRoot {
    return Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Angerona\SourceData\logs\startup-recovery\bundle-guard'
}

function Get-BundleDataRoot {
    return Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Angerona\SourceData'
}

function Assert-BundleLockCustody([string]$Path,[switch]$PermitReadOnlyPrincipals) {
    Assert-BundlePlainPath $Path
    $item=Get-Item -LiteralPath $Path -Force
    $acl=if($item.PSIsContainer) {[IO.Directory]::GetAccessControl($Path)}else{[IO.File]::GetAccessControl($Path)}
    $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $owner) { throw 'Recovery mutation lease has unknown owner custody.' }
    $readOnly=[Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [Security.AccessControl.FileSystemRights]::Synchronize
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if($rule.AccessControlType -ne 'Allow') { throw 'Recovery mutation lease has ambiguous access rules.' }
        if($rule.IdentityReference.Value -notin @($owner,'S-1-5-18','S-1-5-32-544') -and
            (!$PermitReadOnlyPrincipals -or ([long]$rule.FileSystemRights -band (-bnot [long]$readOnly)))) {
            throw 'Recovery mutation lease permits unrelated mutation.'
        }
    }
}

function Open-BundleMutationLock([string]$Path,[switch]$PermitReadOnlyPrincipals) {
    Assert-BundlePlainPath $Path
    $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl=[Security.AccessControl.FileSecurity]::new();$acl.SetOwner($owner);$acl.SetAccessRuleProtection($true,$false)
    foreach($sid in @($owner.Value,'S-1-5-18','S-1-5-32-544')) {
        [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    $lease=[IO.FileStream]::new($Path,[IO.FileMode]::OpenOrCreate,
        ([Security.AccessControl.FileSystemRights]::Read -bor [Security.AccessControl.FileSystemRights]::Write),
        [IO.FileShare]::ReadWrite,4096,[IO.FileOptions]::None,$acl)
    try {
        Assert-BundleLockCustody $Path -PermitReadOnlyPrincipals:$PermitReadOnlyPrincipals
        $lease.Lock(0,1);return $lease
    } catch { $lease.Dispose();throw 'Recovery mutation is held by an active runtime/helper or unknown lease custody.' }
}

function Close-BundleMutationLocks($Leases) {
    for($index=$Leases.Count-1;$index -ge 0;$index--) {
        try {$Leases[$index].Unlock(0,1)}finally{$Leases[$index].Dispose()}
    }
}

function Enter-BundleMutationLocks([string]$Root) {
    $leases=[Collections.Generic.List[object]]::new()
    try {
        $repair=Join-Path $Root '.tmp\repair-wheels'
        Assert-BundlePlainPath $repair;[void][IO.Directory]::CreateDirectory($repair);Assert-BundlePlainPath $repair
        $leases.Add((Open-BundleMutationLock (Join-Path $repair 'startup-repair.lock') -PermitReadOnlyPrincipals))
        $storage=Get-BundleDataRoot
        if(!(Test-Path -LiteralPath $storage)) { New-BundlePrivateDirectory $storage }
        Assert-BundleLockCustody $storage
        $leases.Add((Open-BundleMutationLock (Join-Path $storage 'startup-helper.lock')))
        $leases.Add((Open-BundleMutationLock (Join-Path $storage 'angerona.instance.lock')))
        return ,($leases.ToArray())
    } catch { Close-BundleMutationLocks $leases;throw }
}

function New-BundlePrivateDirectory([string]$Path) {
    Assert-BundlePlainPath $Path
    if(!(Test-Path -LiteralPath $Path)) {
        $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl=[Security.AccessControl.DirectorySecurity]::new()
        $acl.SetOwner($owner); $acl.SetAccessRuleProtection($true,$false)
        foreach($sid in @($owner.Value,'S-1-5-18','S-1-5-32-544')) {
            [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
                [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
        }
        [void][IO.Directory]::CreateDirectory($Path,$acl)
    }
    Assert-BundlePlainPath $Path
    $acl=[IO.Directory]::GetAccessControl($Path)
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if(!$acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid) {
        throw 'Recovery bundle state lacks private owner custody.'
    }
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -notin @($sid,'S-1-5-18','S-1-5-32-544')) {
            throw 'Recovery bundle state has an unrelated access principal.'
        }
    }
}

function Initialize-BundleNative([string]$State) {
    if('Angerona.StartupBundleFile' -as [type]) { return }
    $compiler=Join-Path $State 'compiler'
    New-BundlePrivateDirectory $compiler
    $total=0; $count=0
    foreach($file in Get-ChildItem -LiteralPath $compiler -Force) {
        Assert-BundlePlainPath $file.FullName
        if($file.PSIsContainer -or ++$count -gt 128) { throw 'Recovery compiler scratch requires review.' }
        $total+=$file.Length
        if($total -gt 2MB) { throw 'Recovery compiler scratch reached its capacity.' }
    }
    $oldTemp,$oldTmp=$env:TEMP,$env:TMP
    try {
        $env:TEMP=$compiler; $env:TMP=$compiler
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
namespace Angerona {
public sealed class StartupBundleFile : IDisposable {
    [StructLayout(LayoutKind.Sequential)] struct INFO {
        public uint attrs,createdLow,createdHigh,accessLow,accessHigh,writeLow,writeHigh;
        public uint volume,sizeHigh,sizeLow,links,indexHigh,indexLow;
    }
    [StructLayout(LayoutKind.Sequential)] struct SECURITY {
        public int size; public IntPtr descriptor; public bool inherit;
    }
    [StructLayout(LayoutKind.Sequential)] struct DISPOSITION { public uint flags; }
    [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
    static extern IntPtr CreateFileW(string path,uint access,uint share,IntPtr security,uint create,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr file,out INFO info);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(IntPtr file,int kind,ref DISPOSITION value,uint length);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileTime(IntPtr file,IntPtr created,IntPtr accessed,ref long modified);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr file);
    readonly List<IntPtr> directories=new List<IntPtr>();
    FileStream stream; INFO initial; readonly string path; bool closed;
    static void Check(bool ok) { if(!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    static INFO Information(IntPtr handle,bool directory) {
        INFO value; Check(GetFileInformationByHandle(handle,out value));
        if((value.attrs&0x400)!=0 || (((value.attrs&0x10)!=0)!=directory) || (!directory && value.links!=1))
            throw new IOException("Recovery bundle requires plain single-link files and directories.");
        return value;
    }
    static bool Equal(INFO a,INFO b) {
        return a.volume==b.volume && a.indexHigh==b.indexHigh && a.indexLow==b.indexLow &&
            a.sizeHigh==b.sizeHigh && a.sizeLow==b.sizeLow && a.writeHigh==b.writeHigh && a.writeLow==b.writeLow;
    }
    void Bound() {
        INFO held=Information(stream.SafeFileHandle.DangerousGetHandle(),false);
        IntPtr named=CreateFileW(path,0x80000000,7,IntPtr.Zero,3,0x00200000,IntPtr.Zero);
        Check(named!=new IntPtr(-1));
        try { if(!Equal(initial,held) || !Equal(initial,Information(named,false))) throw new IOException("Recovery file identity changed."); }
        finally { CloseHandle(named); }
    }
    public StartupBundleFile(string name,bool create,bool deletion) {
        path=Path.GetFullPath(name);
        try {
            if(!Path.IsPathRooted(path) || path.StartsWith(@"\\",StringComparison.Ordinal)) throw new IOException("Local recovery path required.");
            string root=Path.GetPathRoot(path),parent=Path.GetDirectoryName(path),current=root;
            var parts=new List<string>(); parts.Add(root);
            foreach(string part in parent.Substring(root.Length).Split(new[]{'\\'},StringSplitOptions.RemoveEmptyEntries)) {
                current=Path.Combine(current,part);parts.Add(current);
                if(parts.Count>64) throw new IOException("Recovery ancestry bound exceeded.");
            }
            foreach(string directory in parts) {
                // Traverse/attributes engage sharing checks without directory
                // enumeration. Allow child writes; deny deletion/rename of the
                // held ancestor itself. Verified file bytes remain SHARE_READ.
                IntPtr held=CreateFileW(directory,0x80|0x20,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
                Check(held!=new IntPtr(-1)); directories.Add(held);Information(held,true);
            }
            uint access=0x80000000|(deletion?0x10000u:0u)|(create?0x40000000u:0u);
            IntPtr handle=CreateFileW(path,access,1,IntPtr.Zero,create?1u:3u,0x00200000,IntPtr.Zero);
            Check(handle!=new IntPtr(-1));
            var safe=new SafeFileHandle(handle,true);
            try { stream=new FileStream(safe,create?FileAccess.ReadWrite:FileAccess.Read); }
            catch { safe.Dispose();throw; }
            initial=Information(handle,false);Bound();
        } catch { Dispose();throw; }
    }
    public byte[] Read(int limit) {
        Bound();long size=((long)initial.sizeHigh<<32)|initial.sizeLow;
        if(size>limit) throw new IOException("Recovery file exceeds its byte bound.");
        byte[] result=new byte[(int)size];stream.Position=0;int count=0;
        while(count<result.Length) { int read=stream.Read(result,count,result.Length-count);if(read==0)break;count+=read; }
        if(count!=result.Length || stream.ReadByte()!=-1) throw new IOException("Recovery file length changed.");
        Bound();return result;
    }
    public void Write(byte[] data) {
        stream.Write(data,0,data.Length);stream.Flush(true);initial=Information(stream.SafeFileHandle.DangerousGetHandle(),false);Bound();
    }
    public void SetModified(long time) {
        Bound();Check(SetFileTime(stream.SafeFileHandle.DangerousGetHandle(),IntPtr.Zero,IntPtr.Zero,ref time));
        initial=Information(stream.SafeFileHandle.DangerousGetHandle(),false);Bound();
    }
    public void Delete() {
        Bound();var value=new DISPOSITION();value.flags=0x11;
        Check(SetFileInformationByHandle(stream.SafeFileHandle.DangerousGetHandle(),21,ref value,4));
    }
    public void Dispose() {
        if(closed)return;closed=true;
        if(stream!=null)stream.Dispose();
        for(int index=directories.Count-1;index>=0;index--)CloseHandle(directories[index]);directories.Clear();
    }
}
}
'@
    } finally { $env:TEMP=$oldTemp; $env:TMP=$oldTmp }
}

function ConvertTo-BundleCanonical([byte[]]$Raw) {
    $text=[Text.UTF8Encoding]::new($false,$true).GetString($Raw)
    if($text.Length -and $text[0] -eq [char]0xfeff) { $text=$text.Substring(1) }
    $text=$text.Replace("`r`n","`n")
    if($text.Contains("`r") -or $text.Contains([string][char]0)) { throw 'Recovery text contains an unsupported lone CR or NUL.' }
    return ,([Text.UTF8Encoding]::new($false).GetBytes($text))
}

function Get-BundleHash([byte[]]$Bytes,[string]$Kind='sha256') {
    $hash=if($Kind -eq 'blob') {[Security.Cryptography.SHA1]::Create()}else{[Security.Cryptography.SHA256]::Create()}
    try {
        if($Kind -eq 'blob') {
            $header=[Text.Encoding]::ASCII.GetBytes('blob '+$Bytes.Length+[char]0)
            [void]$hash.TransformBlock($header,0,$header.Length,$header,0)
            [void]$hash.TransformFinalBlock($Bytes,0,$Bytes.Length)
            $value=$hash.Hash
        } else { $value=$hash.ComputeHash($Bytes) }
        return [BitConverter]::ToString($value).Replace('-','').ToLowerInvariant()
    } finally { $hash.Dispose() }
}

function Read-BundleFile([string]$Path,[int]$Limit=4194307) {
    $held=[Angerona.StartupBundleFile]::new($Path,$false,$false)
    try { return ,($held.Read($Limit)) } finally { $held.Dispose() }
}

function Assert-BundleBudget {
    if($script:BundleDeadline -and [DateTime]::UtcNow -gt $script:BundleDeadline) { throw 'Recovery bundle verification reached its elapsed-time limit.' }
}

function New-BundleBlobRequest([string]$Sha1) {
    if($Sha1 -notmatch '^[0-9a-f]{40}$') { throw 'Recovery blob identity is malformed.' }
    $url='https://api.github.com/repos/Ag3nt47/AngeronaSuite/git/blobs/'+$Sha1
    $request=[Net.HttpWebRequest]::Create($url)
    $request.Proxy=$null; $request.AllowAutoRedirect=$false; $request.UseDefaultCredentials=$false
    $request.Timeout=20000; $request.ReadWriteTimeout=15000
    $request.UserAgent='Angerona-Startup-Recovery-Bundle';$request.Accept='application/vnd.github+json'
    $request.Headers.Add('X-GitHub-Api-Version','2022-11-28')
    return $request
}

function Get-BundleBlob([string]$Sha1,[int]$Maximum) {
    Assert-BundleBudget
    $request=New-BundleBlobRequest $Sha1
    $response=$null;$memory=[IO.MemoryStream]::new()
    try {
        $response=$request.GetResponse()
        if([int]$response.StatusCode -ne 200) { throw 'Canonical recovery blob was unavailable.' }
        $bound=[int]([Math]::Ceiling($Maximum*4/3)+65536)
        if($response.ContentLength -gt $bound) { throw 'Canonical blob response exceeds its bound.' }
        $stream=$response.GetResponseStream();$buffer=New-Object byte[] 65536
        try {
            while(($count=$stream.Read($buffer,0,$buffer.Length)) -gt 0) {
                Assert-BundleBudget
                if($memory.Length+$count -gt $bound) { throw 'Canonical blob response exceeds its bound.' }
                $memory.Write($buffer,0,$count)
            }
        } finally { $stream.Dispose() }
        $document=[Text.UTF8Encoding]::new($false,$true).GetString($memory.ToArray())|ConvertFrom-Json
        if($document.sha -cne $Sha1 -or $document.encoding -cne 'base64' -or
            $document.size -isnot [int] -or $document.size -lt 0 -or $document.size -gt $Maximum -or
            $document.content -isnot [string] -or $document.content.Length -gt $bound) { throw 'Canonical blob metadata is invalid.' }
        [byte[]]$raw=[Convert]::FromBase64String($document.content)
        if($raw.Length -ne $document.size -or (Get-BundleHash $raw 'blob') -cne $Sha1) { throw 'Canonical Git blob bytes did not verify.' }
        return ,$raw
    } finally { $memory.Dispose();if($response){$response.Dispose()} }
}

function Read-BundleManifest([byte[]]$Bytes,[string]$Sha256,[string]$BlobSha1) {
    if($Bytes.Length -gt 128KB -or (Get-BundleHash $Bytes) -cne $Sha256.ToLowerInvariant() -or
        (Get-BundleHash $Bytes 'blob') -cne $BlobSha1.ToLowerInvariant()) { throw 'Recovery manifest does not match the batch trust anchor.' }
    $document=[Text.UTF8Encoding]::new($false,$true).GetString($Bytes)|ConvertFrom-Json
    if($document.schema -ne 1 -or $document.schema -isnot [int] -or
        $document.repository -cne 'Ag3nt47/AngeronaSuite' -or $document.canonical_text -cne 'utf8-lf-no-bom' -or
        @($document.files).Count -ne $script:BundleFiles.Count) { throw 'Recovery manifest schema/scope is invalid.' }
    $seen=@{};$canonicalFiles=@();$total=0
    foreach($entry in $document.files) {
        if($entry.path -isnot [string] -or $entry.path -cnotin $script:BundleFiles -or $seen.ContainsKey($entry.path) -or
            $entry.bytes -isnot [int] -or $entry.bytes -lt 0 -or $entry.bytes -gt 2MB -or
            $entry.sha256 -cnotmatch '^[0-9a-f]{64}$' -or $entry.git_blob_sha1 -cnotmatch '^[0-9a-f]{40}$') {
            throw 'Recovery manifest contains a duplicate, unsafe or unbounded path.'
        }
        $seen[$entry.path]=$true;$total+=$entry.bytes
        $canonicalFiles+=,[ordered]@{bytes=$entry.bytes;git_blob_sha1=$entry.git_blob_sha1;path=$entry.path;sha256=$entry.sha256}
    }
    if($total -gt 32MB) { throw 'Recovery bundle exceeds its aggregate byte bound.' }
    $canonical=[ordered]@{canonical_text='utf8-lf-no-bom';files=$canonicalFiles;repository='Ag3nt47/AngeronaSuite';schema=1}
    $encoded=([Text.UTF8Encoding]::new($false).GetBytes(($canonical|ConvertTo-Json -Depth 6 -Compress)+"`n"))
    if([Convert]::ToBase64String($encoded) -cne [Convert]::ToBase64String($Bytes)) {
        throw 'Recovery manifest has noncanonical, duplicate or unknown metadata.'
    }
    return $document
}

function Get-BundleQuarantineUsage([string]$State,[int]$Additional=0) {
    $bytes=0;$count=0
    foreach($entry in Get-ChildItem -LiteralPath $State -Force) {
        Assert-BundlePlainPath $entry.FullName
        if($entry.PSIsContainer) { if($entry.Name -ne 'compiler') { throw 'Unknown recovery-state directory requires review.' };continue }
        if(++$count -gt 260) { throw 'Recovery quarantine entry capacity requires review.' }
        if($entry.Name -notmatch '^(?:q-[0-9a-f]{32}\.(?:bin|json)|report\.json|bundle\.lock)$') {
            throw 'Unrecognized recovery quarantine files require review.'
        }
        $bytes+=$entry.Length
    }
    if($count+$Additional -gt 260) { throw 'Recovery quarantine entry capacity requires review.' }
    if($bytes -gt 32MB) { throw 'Recovery quarantine has reached its 32 MiB capacity.' }
    return [long]$bytes
}

function Get-BundleFreeBytes([string]$Path) { return [IO.DriveInfo]::new([IO.Path]::GetPathRoot($Path)).AvailableFreeSpace }

function Write-BundlePrivateFile([string]$Path,[byte[]]$Bytes) {
    $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl=[Security.AccessControl.FileSecurity]::new();$acl.SetOwner($owner);$acl.SetAccessRuleProtection($true,$false)
    foreach($sid in @($owner.Value,'S-1-5-18','S-1-5-32-544')) {
        [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    Assert-BundlePlainPath $Path
    $stream=[IO.FileStream]::new($Path,[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::FullControl,
        [IO.FileShare]::Read,4096,[IO.FileOptions]::None,$acl)
    try { $stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true) } finally { $stream.Dispose() }
    if((Get-BundleHash (Read-BundleFile $Path ($Bytes.Length+1))) -cne (Get-BundleHash $Bytes)) { throw 'Preserved recovery bytes failed durable readback.' }
}

function Save-BundleReport([string]$State,$Report) {
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Report|ConvertTo-Json -Depth 8 -Compress))
    if($bytes.Length -gt 64KB) { throw 'Recovery bundle report exceeds its byte bound.' }
    if((Get-BundleQuarantineUsage $State 1)+$bytes.Length -gt 32MB) { throw 'Recovery report capacity requires review.' }
    $temporary=Join-Path $State ('q-'+[Guid]::NewGuid().ToString('N')+'.json')
    Write-BundlePrivateFile $temporary $bytes
    $target=Join-Path $State 'report.json'
    Assert-BundlePlainPath $target
    if(Test-Path -LiteralPath $target) { [IO.File]::Replace($temporary,$target,[NullString]::Value) }
    else { [IO.File]::Move($temporary,$target) }
}

function Open-BundleVerifiedFiles([string]$Root,$Manifest,[string]$ManifestSha256,[string]$ManifestBlobSha1,[string]$VerifierSha256) {
    $held=[Collections.Generic.List[object]]::new()
    try {
        $pin=[Angerona.StartupBundleFile]::new((Join-Path $Root 'assets\startup-recovery-manifest.json'),$false,$false)
        $held.Add($pin)
        [void](Read-BundleManifest (ConvertTo-BundleCanonical ($pin.Read(131075))) $ManifestSha256 $ManifestBlobSha1)
        $body=[Angerona.StartupBundleFile]::new((Join-Path $Root 'tools\verify_startup_recovery_bundle.ps1'),$false,$false)
        $held.Add($body)
        if($VerifierSha256 -and (Get-BundleHash (ConvertTo-BundleCanonical ($body.Read(2097153)))) -cne $VerifierSha256.ToLowerInvariant()) {
            throw 'Verifier body changed before verified execution.'
        }
        foreach($entry in $Manifest.files) {
            $file=[Angerona.StartupBundleFile]::new((Join-Path $Root $entry.path),$false,$false)
            $held.Add($file)
            $data=ConvertTo-BundleCanonical ($file.Read(4194307))
            if($data.Length -ne $entry.bytes -or (Get-BundleHash $data) -cne $entry.sha256 -or (Get-BundleHash $data 'blob') -cne $entry.git_blob_sha1) {
                throw 'Recovery bundle changed before verified execution.'
            }
        }
        return ,($held.ToArray())
    } catch { foreach($file in $held){$file.Dispose()};throw }
}

function Invoke-BundleVerifiedSupervisor([string]$Root,[switch]$SetupOnly) {
    $hostPath=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    # Windows component-store hardlinks are normal for this OS-owned image.
    # The exception applies only to the fixed System-directory PowerShell host.
    Assert-BundlePlainPath $hostPath -AllowHardLinks
    $arguments=@('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $Root 'tools\Invoke-AngeronaSourceStartup.ps1'),'-RepositoryRoot',$Root)
    if($SetupOnly) { $arguments+='-SetupOnly' }
    & $hostPath @arguments | ForEach-Object { [Console]::WriteLine([string]$_) }
    return [int]$LASTEXITCODE
}

function Invoke-StartupRecoveryBundle {
    param([string]$Root,[string]$ManifestSha256,[string]$ManifestBlobSha1,[string]$ExpectedVerifierSha256='',
        [switch]$CheckOnly,[switch]$Offline,[switch]$RunSupervisor,[switch]$SetupOnly)
    Assert-BundleRoot $Root
    $script:BundleDeadline=[DateTime]::UtcNow.AddSeconds(180)
    $state=Get-BundleStateRoot
    # Create only the dedicated private leaf; existing settings/log ownership
    # and ACLs are never rewritten.
    $parent=Split-Path -Parent $state
    Assert-BundlePlainPath $parent;[void][IO.Directory]::CreateDirectory($parent);Assert-BundlePlainPath $parent
    New-BundlePrivateDirectory $state
    Initialize-BundleNative $state
    $leasePath=Join-Path $state 'bundle.lock';Assert-BundlePlainPath $leasePath
    $lease=[IO.File]::Open($leasePath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite)
    $report=[ordered]@{schema=1;outcome='held';changed_files=@();restored_files=@();quarantine=@();
        protection_status='not-attested';message='Recovery bundle verification did not finish.'}
    $mutation=@();$verified=@()
    try {
        $lease.Lock(0,1)
        if(!$CheckOnly) { $mutation=Enter-BundleMutationLocks $Root }
        if($ExpectedVerifierSha256) {
            $body=ConvertTo-BundleCanonical (Read-BundleFile (Join-Path $Root 'tools\verify_startup_recovery_bundle.ps1'))
            if((Get-BundleHash $body) -cne $ExpectedVerifierSha256.ToLowerInvariant()) { throw 'Verifier body differs from its independent batch pin; bootstrap repair is required.' }
        }
        $manifestPath=Join-Path $Root 'assets\startup-recovery-manifest.json'
        $manifestRaw=$null;$manifestCanonical=$null
        if(Test-Path -LiteralPath $manifestPath) {
            $manifestRaw=Read-BundleFile $manifestPath
            try { $manifestCanonical=ConvertTo-BundleCanonical $manifestRaw } catch { $manifestCanonical=$null }
        }
        $manifestGood=$manifestCanonical -and (Get-BundleHash $manifestCanonical) -ceq $ManifestSha256.ToLowerInvariant() -and
            (Get-BundleHash $manifestCanonical 'blob') -ceq $ManifestBlobSha1.ToLowerInvariant()
        if(!$manifestGood) {
            if($CheckOnly) { throw 'Pinned recovery manifest is missing/changed; CheckOnly cannot fetch or restore it.' }
            if($Offline) { throw 'Pinned recovery manifest is missing/changed and offline repair cannot fetch it.' }
            [byte[]]$manifestCanonical=Get-BundleBlob ($ManifestBlobSha1.ToLowerInvariant()) 131072
        }
        $manifest=Read-BundleManifest $manifestCanonical $ManifestSha256 $ManifestBlobSha1
        $changes=[Collections.Generic.List[object]]::new()
        if(!$manifestGood) { $changes.Add([pscustomobject]@{path='assets/startup-recovery-manifest.json';raw=$manifestRaw;data=$manifestCanonical}) }
        foreach($entry in $manifest.files) {
            Assert-BundleBudget
            $path=Join-Path $Root $entry.path;$raw=$null;$canonical=$null
            Assert-BundlePlainPath $path
            if(Test-Path -LiteralPath $path) {
                $raw=Read-BundleFile $path
                try { $canonical=ConvertTo-BundleCanonical $raw } catch { $canonical=$null }
            }
            if($null -eq $canonical -or $canonical.Length -ne $entry.bytes -or
                (Get-BundleHash $canonical) -cne $entry.sha256 -or (Get-BundleHash $canonical 'blob') -cne $entry.git_blob_sha1) {
                $changes.Add([pscustomobject]@{path=$entry.path;raw=$raw;data=$null;expected=$entry})
            }
        }
        $report=[ordered]@{schema=1;outcome='verified';changed_files=@($changes|ForEach-Object {$_.path});
            restored_files=@();quarantine=@();protection_status='not-attested';message='Pinned operational recovery files verified.'}
        if($changes.Count -and $CheckOnly) { $report.outcome='changed';$report.message='Changed or missing recovery files were detected; CheckOnly preserved them.' }
        elseif($changes.Count) {
            $needed=0
            foreach($change in $changes) {
                if($null -ne $change.raw) { if($change.raw.Length -gt 2MB) { throw 'Edited recovery file exceeds the 2 MiB preservation bound.' };$needed+=$change.raw.Length+4096 }
            }
            if((Get-BundleQuarantineUsage $state (2*$changes.Count+1))+$needed+64KB -gt 32MB) { throw 'Recovery quarantine capacity is full; unreviewed originals were preserved.' }
            if((Get-BundleFreeBytes $state) -lt 2GB+$needed -or (Get-BundleFreeBytes $Root) -lt 2GB+32MB) {
                throw 'Recovery bundle repair requires its 2 GiB reserve and staging capacity.'
            }
            foreach($change in $changes) {
                if($null -eq $change.data) {
                    if($Offline) { throw 'Changed recovery files require their exact pinned GitHub blobs; offline repair is held.' }
                    [byte[]]$data=Get-BundleBlob $change.expected.git_blob_sha1 ([int]$change.expected.bytes)
                    if($data.Length -ne $change.expected.bytes -or (Get-BundleHash $data) -cne $change.expected.sha256 -or
                        (Get-BundleHash $data 'blob') -cne $change.expected.git_blob_sha1 -or
                        [Convert]::ToBase64String((ConvertTo-BundleCanonical $data)) -cne [Convert]::ToBase64String($data)) {
                        throw 'Pinned recovery payload bytes did not verify.'
                    }
                    $change.data=$data
                }
            }
            foreach($change in $changes) {
                Assert-BundleBudget
                $path=Join-Path $Root $change.path
                $oldSecond=-1L
                if($null -ne $change.raw) {
                    $old=[Angerona.StartupBundleFile]::new($path,$false,$true)
                    try {
                        if((Get-BundleHash ($old.Read(4194307))) -cne (Get-BundleHash $change.raw)) { throw 'Recovery file changed after discovery; the editor version was preserved.' }
                        $oldSecond=[long][Math]::Floor([IO.File]::GetLastWriteTimeUtc($path).Ticks/10000000)
                        $id=[Guid]::NewGuid().ToString('N');$copy=Join-Path $state ('q-'+$id+'.bin')
                        Write-BundlePrivateFile $copy $change.raw
                        $metadata=[ordered]@{schema=1;path=$change.path;raw_sha256=(Get-BundleHash $change.raw);bytes=$change.raw.Length}
                        Write-BundlePrivateFile (Join-Path $state ('q-'+$id+'.json')) ([Text.UTF8Encoding]::new($false).GetBytes(($metadata|ConvertTo-Json -Compress)))
                        $report.quarantine+=,$id
                        $old.Delete()
                    } finally { $old.Dispose() }
                } elseif(Test-Path -LiteralPath $path) { throw 'A concurrent recovery file appeared; it was not overwritten.' }
                $created=[Angerona.StartupBundleFile]::new($path,$true,$false)
                try {
                    $created.Write($change.data)
                    if($change.path.EndsWith('.py',[StringComparison]::Ordinal)) {
                        $modified=[DateTime]::UtcNow.AddSeconds(2)
                        if([long][Math]::Floor($modified.Ticks/10000000) -eq $oldSecond) { $modified=$modified.AddSeconds(1) }
                        $created.SetModified($modified.ToFileTimeUtc())
                    }
                    if((Get-BundleHash ($created.Read(2097153))) -cne (Get-BundleHash $change.data)) { throw 'Restored recovery bytes did not verify.' }
                } finally { $created.Dispose() }
                $report.restored_files+=,$change.path
            }
            $report.outcome='repaired';$report.message='Exact pinned operational recovery files restored; edited originals remain private.'
        }
        # A partial or raced publication can never attest the bundle or start a
        # mutable helper. The next trusted invocation rechecks every byte again.
        if(!$CheckOnly -or ($RunSupervisor -and $changes.Count -eq 0)) {
            $verified=Open-BundleVerifiedFiles $Root $manifest $ManifestSha256 $ManifestBlobSha1 $ExpectedVerifierSha256
        }
        Save-BundleReport $state $report
        if($RunSupervisor -and $report.outcome -ne 'changed') {
            Close-BundleMutationLocks $mutation;$mutation=@()
            $report.supervisor_exit_code=Invoke-BundleVerifiedSupervisor $Root -SetupOnly:$SetupOnly
        }
        return [pscustomobject]$report
    } catch {
        $failure=$_
        $report.outcome='held';$report.message=$failure.Exception.Message.Substring(0,[Math]::Min(1024,$failure.Exception.Message.Length))
        try { Save-BundleReport $state $report } catch { }
        throw $failure
    } finally {
        foreach($file in $verified){$file.Dispose()}
        Close-BundleMutationLocks $mutation
        try {$lease.Unlock(0,1)}catch{};$lease.Dispose()
    }
}

if($MyInvocation.InvocationName -ne '.') {
    try {
        $result=Invoke-StartupRecoveryBundle -Root $Root -ManifestSha256 $ManifestSha256 -ManifestBlobSha1 $ManifestBlobSha1 `
            -ExpectedVerifierSha256 $ExpectedVerifierSha256 -CheckOnly:$CheckOnly -Offline:$Offline -RunSupervisor:$RunSupervisor -SetupOnly:$SetupOnly
        [Console]::WriteLine(($result|ConvertTo-Json -Depth 8 -Compress))
        if($result.outcome -eq 'changed') {exit 1};if($RunSupervisor){exit $result.supervisor_exit_code};exit 0
    } catch {
        [Console]::Error.WriteLine('Recovery bundle held: '+$_.Exception.Message)
        exit 1
    }
}
