# Shared source-startup primitives. Importing this file performs no repair,
# process creation, environment mutation, or native compilation.

function Assert-PlainRepairPath([string]$Path, [switch]$AllowHardLinks) {
    if (![IO.Path]::IsPathRooted($Path)) { throw 'Startup repair requires an absolute path.' }
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Startup repair refuses a redirected path: $cursor"
            }
            if (!$AllowHardLinks -and !$item.PSIsContainer -and $item.LinkType -eq 'HardLink') {
                throw "Startup repair refuses a file with multiple links: $cursor"
            }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
}

function Get-RepairFileSha256([string]$Path) {
    Assert-PlainRepairPath $Path
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $digest = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($digest.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() }
    finally { $digest.Dispose(); $stream.Dispose() }
}

function Initialize-RepairPythonDiscovery {
    if ('Angerona.RepairPythonImage' -as [type]) { return }
    # Discovery may follow an installed-location hint, but execution uses only
    # its independently verified physical path. Retained image/ancestor handles
    # exclude replacement while signature/ABI checks and the transaction run.
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
namespace Angerona {
public sealed class RepairPythonImage : IDisposable {
    [StructLayout(LayoutKind.Sequential)] struct FILE_INFORMATION {
        public uint attributes,createdLow,createdHigh,accessLow,accessHigh,writeLow,writeHigh;
        public uint volume,sizeHigh,sizeLow,links,indexHigh,indexLow;
    }
    [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
    static extern IntPtr CreateFileW(string path,uint access,uint share,IntPtr security,
        uint creation,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)]
    static extern bool GetFileInformationByHandle(IntPtr file,out FILE_INFORMATION info);
    [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
    static extern uint GetFinalPathNameByHandleW(IntPtr file,StringBuilder path,uint size,uint flags);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern uint GetDriveTypeW(string root);
    [DllImport("kernel32.dll",SetLastError=true)]
    static extern bool DeviceIoControl(IntPtr file,uint code,IntPtr input,uint inputSize,
        byte[] output,uint outputSize,out uint returned,IntPtr overlapped);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
    readonly List<IntPtr> handles=new List<IntPtr>();
    readonly string identity;
    public string PhysicalPath { get; private set; }
    bool closed;
    static void Check(bool ok) { if(!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    static string Identity(FILE_INFORMATION info) {
        return info.volume.ToString("x8")+":"+info.indexHigh.ToString("x8")+info.indexLow.ToString("x8");
    }
    static FILE_INFORMATION RawInformation(IntPtr handle) {
        FILE_INFORMATION info; Check(GetFileInformationByHandle(handle,out info));
        return info;
    }
    static FILE_INFORMATION Information(IntPtr handle,bool directory) {
        FILE_INFORMATION info=RawInformation(handle);
        if ((info.attributes&0x400)!=0 || (((info.attributes&0x10)!=0)!=directory))
            throw new IOException("Runtime discovery requires a plain file/directory.");
        return info;
    }
    IntPtr Open(string path,uint access,uint share,uint flags) {
        IntPtr handle=CreateFileW(path,access,share,IntPtr.Zero,3,flags,IntPtr.Zero);
        Check(handle!=new IntPtr(-1)); handles.Add(handle); return handle;
    }
    static string LocalPath(string path) {
        if(String.IsNullOrWhiteSpace(path) || path.Length>4096 || path.Length<3 ||
           !Char.IsLetter(path[0]) || path[1]!=':' || path[2]!='\\' || path.IndexOf('\0')>=0)
            throw new IOException("Runtime hint target must be an absolute local DOS path.");
        string value=Path.GetFullPath(path);
        if(GetDriveTypeW(Path.GetPathRoot(value))!=3)
            throw new IOException("Runtime hint target requires a fixed local volume.");
        return value;
    }
    static string ReparseTarget(IntPtr handle,string path) {
        byte[] buffer=new byte[16384]; uint returned;
        Check(DeviceIoControl(handle,0x900A8,IntPtr.Zero,0,buffer,16384,out returned,IntPtr.Zero));
        return DecodeReparseTarget(buffer,returned,path);
    }
    static string DecodeReparseTarget(byte[] buffer,uint returned,string path) {
        if(returned>buffer.Length) throw new IOException("Runtime hint data length is invalid.");
        if(returned<16 || BitConverter.ToUInt16(buffer,4)+8>returned)
            throw new IOException("Runtime hint reparse data is incomplete.");
        uint tag=BitConverter.ToUInt32(buffer,0); int start; bool relative=false;
        if(tag==0xA0000003) start=16;
        else if(tag==0xA000000C) {
            if(returned<20) throw new IOException("Runtime symlink data is incomplete.");
            uint flags=BitConverter.ToUInt32(buffer,16);
            if(flags>1) throw new IOException("Runtime symlink flags are unsupported.");
            relative=flags==1; start=20;
        } else throw new IOException("Runtime hint uses an unsupported reparse type.");
        int offset=BitConverter.ToUInt16(buffer,8),length=BitConverter.ToUInt16(buffer,10);
        if(length==0 || (offset&1)!=0 || (length&1)!=0 || start+offset+length>returned ||
           start+offset+length>BitConverter.ToUInt16(buffer,4)+8)
            throw new IOException("Runtime hint target is malformed.");
        string target=new UnicodeEncoding(false,false,true).GetString(buffer,start+offset,length);
        if(relative) {
            if(Path.IsPathRooted(target)) throw new IOException("Relative runtime hint is ambiguous.");
            return LocalPath(Path.Combine(Path.GetDirectoryName(path),target));
        }
        if(target.StartsWith(@"\??\",StringComparison.Ordinal) ||
           target.StartsWith(@"\\?\",StringComparison.Ordinal)) target=target.Substring(4);
        // UNC/device targets are refused before any open can contact them.
        return LocalPath(target);
    }
    IntPtr ResolveHint(string hint) {
        string pending=LocalPath(hint);
        for(int redirects=0;redirects<=8;redirects++) {
            string root=Path.GetPathRoot(pending),current=root;
            Information(Open(root,0x80|1,1,0x02000000|0x00200000),true);
            string[] parts=pending.Substring(root.Length).Split(new[]{'\\'},StringSplitOptions.RemoveEmptyEntries);
            if(parts.Length==0 || parts.Length>64) throw new IOException("Runtime hint component bound exceeded.");
            bool redirected=false;
            for(int index=0;index<parts.Length;index++) {
                current=Path.Combine(current,parts[index]);
                IntPtr handle=Open(current,0x80|1,1,0x02000000|0x00200000);
                FILE_INFORMATION info=RawInformation(handle);
                if((info.attributes&0x400)!=0) {
                    if(redirects==8) throw new IOException("Runtime hint redirect bound exceeded.");
                    string target=ReparseTarget(handle,current);
                    for(int rest=index+1;rest<parts.Length;rest++) target=Path.Combine(target,parts[rest]);
                    pending=LocalPath(target); redirected=true; break;
                }
                Information(handle,index<parts.Length-1);
                if(index==parts.Length-1) return handle;
            }
            if(!redirected) break;
        }
        throw new IOException("Runtime hint could not resolve a plain local image.");
    }
    static string FinalPath(IntPtr handle) {
        var text=new StringBuilder(32768);
        uint length=GetFinalPathNameByHandleW(handle,text,32768,0);
        Check(length!=0);
        if(length>=32768) throw new IOException("Runtime discovery path exceeds its bound.");
        string value=text.ToString();
        if(!value.StartsWith(@"\\?\",StringComparison.Ordinal) || value.Length<7 ||
           !Char.IsLetter(value[4]) || value[5]!=':' || value[6]!='\\')
            throw new IOException("Runtime discovery requires a local DOS-volume path.");
        value=Path.GetFullPath(value.Substring(4));
        if(GetDriveTypeW(Path.GetPathRoot(value))!=3)
            throw new IOException("Runtime discovery requires a fixed local volume.");
        return value;
    }
    public RepairPythonImage(string hint) {
        try {
            if(String.IsNullOrWhiteSpace(hint) || hint.Length>4096 || !Path.IsPathRooted(hint) ||
               hint.StartsWith(@"\\",StringComparison.Ordinal))
                throw new IOException("Runtime discovery hint must be an absolute local path.");
            // Resolve each component without following it first. Only bounded,
            // checked local targets may be traversed; UNC/unknown reparses never run.
            // FILE_READ_DATA is intentional: metadata-only opens do not
            // establish the sharing exclusion needed to pin executable bytes.
            IntPtr original=ResolveHint(hint);
            identity=Identity(Information(original,false));
            PhysicalPath=FinalPath(original);
            string parent=Path.GetDirectoryName(PhysicalPath);
            string root=Path.GetPathRoot(PhysicalPath);
            var directories=new List<string>();
            directories.Add(root);
            string current=root;
            foreach(string part in parent.Substring(root.Length).Split(new[]{'\\'},StringSplitOptions.RemoveEmptyEntries)) {
                current=Path.Combine(current,part); directories.Add(current);
            }
            foreach(string directory in directories)
                Information(Open(directory,0x80|1,1,0x02000000|0x00200000),true);
            AssertBound();
        } catch { Dispose(); throw; }
    }
    public void AssertBound() {
        if(closed) throw new ObjectDisposedException("RepairPythonImage");
        IntPtr named=CreateFileW(PhysicalPath,0x80|1,1,IntPtr.Zero,3,0x00200000,IntPtr.Zero);
        Check(named!=new IntPtr(-1));
        try {
            if(Identity(Information(named,false))!=identity ||
               !String.Equals(FinalPath(named),PhysicalPath,StringComparison.OrdinalIgnoreCase))
                throw new IOException("Physical runtime image changed during discovery.");
        } finally { CloseHandle(named); }
    }
    public void Dispose() {
        if(closed) return; closed=true;
        for(int index=handles.Count-1;index>=0;index--) CloseHandle(handles[index]);
        handles.Clear();
    }
}
}
'@
}

function Open-RepairPythonHint([string]$Path) {
    Initialize-RepairPythonDiscovery
    return [Angerona.RepairPythonImage]::new($Path)
}

function Get-RepairPathAcl([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    return $(if ($item.PSIsContainer) { [IO.Directory]::GetAccessControl($Path) }
        else { [IO.File]::GetAccessControl($Path) }
    )
}

function Assert-PrivateRepairCustody([string]$Path, [switch]$AllowInherited) {
    Assert-PlainRepairPath $Path
    $acl = Get-RepairPathAcl $Path
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $owner -or
        (!$AllowInherited -and !$acl.AreAccessRulesProtected)) {
        throw 'Startup repair evidence does not have private owner custody.'
    }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Allow' -or
            $rule.IdentityReference.Value -notin @($owner, 'S-1-5-18', 'S-1-5-32-544')) {
            throw 'Startup repair evidence has an unexpected access principal.'
        }
    }
}

function Get-CanonicalSourceStartupStorage {
    return Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Angerona\SourceData'
}

function Open-PrivateRepairFile {
    param([string]$Path, [IO.FileMode]$Mode = [IO.FileMode]::CreateNew,
        [IO.FileShare]$Share = [IO.FileShare]::Read)
    Assert-PlainRepairPath $Path
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetOwner($owner)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($owner.Value, 'S-1-5-18', 'S-1-5-32-544') | Select-Object -Unique) {
        $identity = [Security.Principal.SecurityIdentifier]::new($sid)
        [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $identity, [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    # Windows elevated tokens can default new file ownership to Administrators
    # even inside a user-owned directory. Set owner/DACL atomically on creation;
    # CreateFile ignores this descriptor when opening an existing file.
    $stream = [IO.FileStream]::new($Path, $Mode,
        ([Security.AccessControl.FileSystemRights]::Read -bor
            [Security.AccessControl.FileSystemRights]::Write), $Share, 4096,
        [IO.FileOptions]::None, $acl)
    try { Assert-PrivateRepairCustody $Path -AllowInherited; return $stream }
    catch { $stream.Dispose(); throw }
}

function Enter-CanonicalSourceHelperLease {
    $storage = [IO.Path]::GetFullPath((Get-CanonicalSourceStartupStorage))
    Assert-PlainRepairPath $storage
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($storage))
    if (!$drive.IsReady -or $drive.DriveType -ne [IO.DriveType]::Fixed) {
        throw 'The canonical source helper storage must use a fixed local drive.'
    }
    if (!(Test-Path -LiteralPath $storage)) { New-PrivateRepairDirectory $storage }
    Assert-PrivateRepairCustody $storage -AllowInherited
    $path = Join-Path $storage 'startup-helper.lock'
    Assert-PlainRepairPath $path
    $lease = Open-PrivateRepairFile -Path $path -Mode ([IO.FileMode]::OpenOrCreate) `
        -Share ([IO.FileShare]::ReadWrite)
    try {
        Assert-PrivateRepairCustody $path -AllowInherited
        $lease.Lock(0, 1)
        return $lease
    } catch {
        $lease.Dispose()
        throw 'The canonical source helper is active or its lease custody could not be verified.'
    }
}

function Get-StartupRepairPendingPath([string]$Root) {
    return Join-Path ([IO.Path]::GetFullPath($Root)) '.tmp\repair-wheels\startup-repair.pending'
}

function Enter-CanonicalCoreMutationLease {
    # The same byte-range lock used by SingletonLease, including cores launched
    # outside this checkout's venv. Never replace its inode or singleton record.
    $storage = Get-CanonicalSourceStartupStorage
    Assert-PrivateRepairCustody $storage -AllowInherited
    $path = Join-Path $storage 'angerona.instance.lock'
    $lease = Open-PrivateRepairFile -Path $path -Mode OpenOrCreate -Share ReadWrite
    try { $lease.Lock(0, 1); return $lease }
    catch { $lease.Dispose(); throw 'A core owns the instance lease; runtime/source mutation is held.' }
}

function Read-SourceStartupRecoveryPreferences([string]$Storage) {
    $result = @{ Enabled = $true; Github = $true }
    try {
        $path = Join-Path $Storage 'settings.json'
        Assert-PlainRepairPath $path
        if (!(Test-Path -LiteralPath $path)) { return $result }
        Assert-PrivateRepairCustody $path -AllowInherited
        $stream = [IO.File]::Open($path, 'Open', 'Read', 'Read')
        try {
            if ($stream.Length -gt 64KB) { throw 'Recovery preferences exceed 64 KiB.' }
            # Match Config's strict UTF-8 JSON contract. StreamReader's BOM
            # detection would accept UTF-16/UTF-8-BOM settings that Config
            # refuses, incorrectly enabling recovery from ambiguous consent.
            $bytes = New-Object byte[] ([int]$stream.Length)
            $offset = 0
            while ($offset -lt $bytes.Length) {
                $count = $stream.Read($bytes, $offset, $bytes.Length-$offset)
                if (!$count) { throw 'Recovery preferences changed during read.' }
                $offset += $count
            }
            $raw = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        } finally { $stream.Dispose() }
        # First validate JSON, then retain top-level duplicate keys which the
        # PowerShell deserializer would otherwise discard. Nested values have
        # no authority over these preferences. Unknown/ambiguous consent is off.
        $parsed = $raw | ConvertFrom-Json
        if ($null -eq $parsed -or $parsed -isnot [pscustomobject] -or $raw -notmatch '^\s*\{') { throw 'Settings must be a JSON object.' }
        $tokens = [regex]::Matches($raw, '"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"|[{}\[\]:,]|true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?')
        $position = 0; $depth = 0; $counts = @{}; $values = @{}
        for ($i = 0; $i -lt $tokens.Count; $i++) {
            $token = $tokens[$i]
            if ($raw.Substring($position, $token.Index-$position).Trim().Length) { throw 'Invalid JSON token.' }
            $position = $token.Index + $token.Length
            if ($token.Value -in @('{','[')) { $depth++; continue }
            if ($token.Value -in @('}',']')) { $depth--; continue }
            if ($depth -eq 1 -and $token.Value.StartsWith('"') -and $i+2 -lt $tokens.Count -and $tokens[$i+1].Value -eq ':') {
                $name = ConvertFrom-Json ('['+$token.Value+']')
                if ($name -cin @('startup_recovery_enabled','startup_recovery_github_enabled')) {
                    if (!$counts.ContainsKey([string]$name)) { $counts[[string]$name] = 0 }
                    $counts[[string]$name]++
                    $values[[string]$name] = $tokens[$i+2].Value
                }
            }
        }
        if ($raw.Substring($position).Trim().Length -or $raw -match ',\s*[}\]]') { throw 'Invalid JSON suffix or trailing comma.' }
        foreach ($pair in @(@('startup_recovery_enabled','Enabled'),@('startup_recovery_github_enabled','Github'))) {
            if ($counts.ContainsKey($pair[0])) { $result[$pair[1]] = ($counts[$pair[0]] -eq 1 -and $values[$pair[0]] -ceq 'true') }
        }
        return $result
    } catch { return @{ Enabled = $false; Github = $false } }
}

function Read-PendingRepairIntent([string]$Root) {
    $canonical = [IO.Path]::GetFullPath($Root)
    $pending = Get-StartupRepairPendingPath $canonical
    Assert-PrivateRepairCustody $pending
    $path = Join-Path $pending 'intent.json'
    Assert-PrivateRepairCustody $path -AllowInherited
    if ((Get-Item -LiteralPath $path).Length -gt 16384) { throw 'Startup repair intent is oversized.' }
    try { $intent = [IO.File]::ReadAllText($path) | ConvertFrom-Json }
    catch { throw 'Startup repair intent is corrupt; retain it for review.' }
    $fields = @('Schema','Id','Root','Venv','Scratch','Stage','Backup','OriginalId','CandidateId','HadOriginal')
    if ((@($intent.PSObject.Properties.Name | Sort-Object) -join ',') -ne
        (@($fields | Sort-Object) -join ',') -or $intent.Schema -ne 1 -or
        $intent.Id -notmatch '^[0-9a-f]{32}$' -or $intent.HadOriginal -isnot [bool] -or
        $intent.CandidateId -notmatch '^[0-9a-f]{8}:[0-9a-f]{16}$' -or
        ($intent.HadOriginal -and $intent.OriginalId -notmatch '^[0-9a-f]{8}:[0-9a-f]{16}$') -or
        (!$intent.HadOriginal -and $intent.OriginalId -ne '')) {
        throw 'Startup repair intent has an unknown schema or identity.'
    }
    $expectedScratch = Join-Path $canonical ('.tmp\repair-wheels\startup-repair.' + $intent.Id)
    $expectedBackup = Join-Path $canonical ('venv.incompatible.repair.' + $intent.Id)
    foreach ($pair in @(@($intent.Root,$canonical), @($intent.Venv,(Join-Path $canonical 'venv')),
            @($intent.Scratch,$expectedScratch), @($intent.Stage,(Join-Path $expectedScratch 'candidate')),
            @($intent.Backup,$expectedBackup))) {
        if ($pair[0] -cne $pair[1]) { throw 'Startup repair intent paths were changed; reconciliation refused.' }
        Assert-PlainRepairPath $pair[0]
    }
    Assert-PrivateRepairCustody $intent.Scratch
    $witness = Join-Path $intent.Scratch 'intent.witness.json'
    Assert-PrivateRepairCustody $witness -AllowInherited
    if ((Get-RepairFileSha256 $path) -ne (Get-RepairFileSha256 $witness)) {
        throw 'Startup repair intent differs from its private witness.'
    }
    $phasePath = Join-Path $pending 'phase.json'
    Assert-PrivateRepairCustody $phasePath -AllowInherited
    if ((Get-Item -LiteralPath $phasePath).Length -gt 1024) { throw 'Startup repair phase is oversized.' }
    try { $phase = [IO.File]::ReadAllText($phasePath) | ConvertFrom-Json }
    catch { throw 'Startup repair phase is corrupt.' }
    if ((@($phase.PSObject.Properties.Name | Sort-Object) -join ',') -ne 'Id,Phase,Schema' -or
        $phase.Schema -ne 1 -or $phase.Id -cne $intent.Id -or
        $phase.Phase -notin @('Prepared','BeforeBackup','BeforePromotion','Refreshing','Verified','RollingBack')) {
        throw 'Startup repair phase is unknown or inconsistent.'
    }
    return [pscustomobject]@{Intent=$intent;Phase=$phase.Phase;Pending=$pending}
}

function Assert-NoPendingRepair([string]$Root) {
    $pending = Get-StartupRepairPendingPath $Root
    $marker = Join-Path ([IO.Path]::GetFullPath($Root)) 'venv\.angerona-startup-repair.json'
    Assert-PlainRepairPath $pending
    Assert-PlainRepairPath $marker
    if (Test-Path -LiteralPath $pending) {
        [void](Read-PendingRepairIntent $Root)
        $exception = [InvalidOperationException]::new('An interrupted startup repair requires reconciliation before any runtime executes.')
        $exception.Data['AngeronaRepairPending'] = $true
        throw $exception
    }
    if (Test-Path -LiteralPath $marker) {
        throw 'A runtime repair marker exists without its private intent; preserve it for maintainer review.'
    }
    $parent = Join-Path ([IO.Path]::GetFullPath($Root)) '.tmp\repair-wheels'
    if (Test-Path -LiteralPath $parent -PathType Container) {
          $seen = 0
          foreach ($entry in [IO.Directory]::EnumerateDirectories($parent, 'startup-repair.*')) {
              if (++$seen -gt 8) { throw 'Retained runtime transaction inventory exceeds its review bound; preserve it for review.' }
              Assert-PlainRepairPath $entry
              $directory = Get-Item -LiteralPath $entry -Force
            if ($directory.Name -notmatch '^startup-repair\.([0-9a-f]{32})$') { continue }
            $id = $Matches[1]
            $witness = Join-Path $directory.FullName 'intent.witness.json'
            if (!(Test-Path -LiteralPath $witness)) { continue }
            Assert-PrivateRepairCustody $directory.FullName
            Assert-PrivateRepairCustody $witness -AllowInherited
            $resolutionPath = Join-Path $directory.FullName 'resolution.json'
            if (!(Test-Path -LiteralPath $resolutionPath)) {
                throw 'Private runtime intent evidence exists without its pending record or resolution; review is required.'
            }
            Assert-PrivateRepairCustody $resolutionPath -AllowInherited
            if ((Get-Item -LiteralPath $resolutionPath).Length -gt 1024) { throw 'Runtime repair resolution is oversized.' }
            try { $resolution = [IO.File]::ReadAllText($resolutionPath) | ConvertFrom-Json }
            catch { throw 'Runtime repair resolution is corrupt.' }
            if ((@($resolution.PSObject.Properties.Name | Sort-Object) -join ',') -ne 'Id,Outcome,Schema' -or
                $resolution.Schema -ne 1 -or $resolution.Id -cne $id -or
                $resolution.Outcome -notin @('Verified','RolledBack')) {
                throw 'Runtime repair resolution is unknown or was changed.'
            }
        }
    }
}

function New-PrivateRepairDirectory([string]$Path) {
    Assert-PlainRepairPath $Path
    if (Test-Path -LiteralPath $Path) { throw 'A fresh startup scratch directory is required.' }
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($owner)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($owner.Value, 'S-1-5-18', 'S-1-5-32-544') | Select-Object -Unique) {
        $identity = [Security.Principal.SecurityIdentifier]::new($sid)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $identity, [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
        [void]$acl.AddAccessRule($rule)
    }
    [void][IO.Directory]::CreateDirectory($Path, $acl)
    Assert-PlainRepairPath $Path
    $actual = [IO.Directory]::GetAccessControl($Path)
    if (!$actual.AreAccessRulesProtected -or
        $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $owner.Value) {
        throw 'Private startup scratch custody could not be verified.'
    }
    $allowed = @($owner.Value, 'S-1-5-18', 'S-1-5-32-544')
    foreach ($rule in $actual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.IsInherited -or $rule.AccessControlType -ne 'Allow' -or
            $rule.IdentityReference.Value -notin $allowed) {
            throw 'Private startup scratch has an unexpected access rule.'
        }
    }
}

function Enter-RepairLease([string]$Root) {
    $rootPath = [IO.Path]::GetFullPath($Root)
    $parent = Join-Path $rootPath '.tmp\repair-wheels'
    Assert-PlainRepairPath $parent
    [void][IO.Directory]::CreateDirectory($parent)
    $path = Join-Path $parent 'startup-repair.lock'
    Assert-PlainRepairPath $path
    $lease = [IO.File]::Open($path, [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
    try {
        $lease.Lock(0, 1)
        # Windows byte-range locks may extend past EOF. Never initialize or
        # truncate an existing file merely to acquire the runtime lease.
        return $lease
    } catch {
        $lease.Dispose()
        throw 'Another Angerona startup or repair holds the runtime lease. Retry after it exits.'
    }
}

function Exit-RepairLease($Lease) {
    if ($Lease) {
        if (('Angerona.StartupRepairProcess' -as [type]) -and
            [Angerona.StartupRepairProcess]::ParkLeaseIfPending($Lease)) { return }
        try { $Lease.Unlock(0, 1) } finally { $Lease.Dispose() }
    }
}

function Get-RepairProcessCompilerScratch {
    $storage = Get-CanonicalSourceStartupStorage
    $fixedRoot = Split-Path -Parent $PSScriptRoot
    $critical = Get-Variable -Name SourceStartupCriticalMode -Scope Script -ErrorAction SilentlyContinue
    $critical = $critical -and $critical.Value -is [bool] -and $critical.Value
    foreach ($path in @((Join-Path $storage 'tmp\process-compiler'),
            (Join-Path $fixedRoot '.tmp\process-compiler'))) {
        try {
            Assert-PlainRepairPath $path
            $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot([IO.Path]::GetFullPath($path)))
            if (!$drive.IsReady -or $drive.DriveType -ne 'Fixed' -or
                (!$critical -and $drive.AvailableFreeSpace -lt (2GB+2MB))) { continue }
            if (!(Test-Path -LiteralPath $path)) { New-PrivateRepairDirectory $path }
            Assert-PrivateRepairCustody $path
            $count = 0; $bytes = 0L
            foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($path)) {
                if (++$count -gt 120) { throw 'Process compiler scratch has reached its retained-file capacity.' }
                Assert-PrivateRepairCustody $entry -AllowInherited
                $item = Get-Item -LiteralPath $entry -Force
                if ($item.PSIsContainer) { throw 'Process compiler scratch contains an unexpected nested directory.' }
                $bytes += $item.Length
                if ($bytes+128KB -gt 2MB) { throw 'Process compiler scratch has reached its 2 MiB retained-byte capacity.' }
            }
            return $path
        } catch { Write-Verbose 'A private process compiler scratch location is unavailable or requires retained-artifact review.' }
    }
    throw 'Private bounded process compiler scratch is unavailable. Review retained process-compiler artifacts or restore the 2 GiB drive reserve before Retry; nothing was deleted.'
}

function Initialize-RepairLiveProcessIdentity {
    if ('Angerona.RepairLiveProcessIdentity' -as [type]) { return }
    $scratch = Get-RepairProcessCompilerScratch
    $savedTemp, $savedTmp = $env:TEMP, $env:TMP
    try {
        $env:TEMP = $scratch; $env:TMP = $scratch
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
namespace Angerona {
public sealed class RepairLiveProcessIdentity : IDisposable {
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint timeout);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr handle,out long birth,out long exit,out long kernel,out long user);
    [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool QueryFullProcessImageNameW(IntPtr handle,uint flags,StringBuilder image,ref uint length);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    IntPtr handle;
    public string State {get;private set;}
    public string ImagePath {get;private set;}
    public long CreationFileTime {get;private set;}
    public int NativeError {get;private set;}
    public uint ProcessId {get;private set;}
    bool Retired() {
        uint state=WaitForSingleObject(handle,0);
        if(state==0){State="retired";return true;}
        if(state!=258){State="unknown";NativeError=Marshal.GetLastWin32Error();}
        return false;
    }
    public RepairLiveProcessIdentity(uint pid) {
        State="unknown";ProcessId=pid;
        // QUERY_LIMITED_INFORMATION | SYNCHRONIZE, no mutation/termination right.
        handle=OpenProcess(0x00101000,false,pid);
        if(handle==IntPtr.Zero){NativeError=Marshal.GetLastWin32Error();if(NativeError==87)State="retired";return;}
        if(Retired() || NativeError!=0)return;
        long birth,exit,kernel,user;
        if(!GetProcessTimes(handle,out birth,out exit,out kernel,out user)) {
            NativeError=Marshal.GetLastWin32Error();Retired();return;
        }
        var image=new StringBuilder(32768);uint length=32768;
        if(!QueryFullProcessImageNameW(handle,0,image,ref length)) {
            NativeError=Marshal.GetLastWin32Error();Retired();return;
        }
        string path=image.ToString();
        if(path.StartsWith(@"\\?\",StringComparison.Ordinal) && path.Length>=7 && path[5]==':')path=path.Substring(4);
        if(birth<=0 || String.IsNullOrEmpty(path) || !Path.IsPathRooted(path)){NativeError=13;Retired();return;}
        try {ImagePath=Path.GetFullPath(path);}catch(Exception){NativeError=13;Retired();return;}
        CreationFileTime=birth;
        if(!Retired() && NativeError==0)State="live";
    }
    public void Dispose(){if(handle!=IntPtr.Zero){CloseHandle(handle);handle=IntPtr.Zero;}}
}
}
'@
    } finally { $env:TEMP = $savedTemp; $env:TMP = $savedTmp }
}

function Get-LiveRepairProcessIdentity([uint32]$ProcessId) {
    Initialize-RepairLiveProcessIdentity
    return [Angerona.RepairLiveProcessIdentity]::new($ProcessId)
}

function Assert-NoActiveVenv([string]$VenvPath) {
    $prefix = [IO.Path]::GetFullPath($VenvPath).TrimEnd('\') + '\'
    # CIM supplies discovery hints only. A retained native handle proves the
    # actual generation, liveness and image; stale rows/PID reuse are not busy.
    foreach ($process in Get-CimInstance Win32_Process -OperationTimeoutSec 10) {
        $hint = $process.ExecutablePath -is [string] -and
            $process.ExecutablePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
        if (!$hint -and $process.Name -notin @('python.exe', 'pythonw.exe', 'Angerona.exe', 'pip.exe')) { continue }
        if (!$process.ProcessId -or [long]$process.ProcessId -lt 1 -or [long]$process.ProcessId -gt [uint32]::MaxValue) {
            throw 'A Python/runtime process identity could not be inspected (invalid PID); repair refused.'
        }
        $identity = Get-LiveRepairProcessIdentity ([uint32]$process.ProcessId)
        try {
            if ($identity.State -eq 'retired') { continue }
            if ($identity.State -ne 'live' -or !$identity.ImagePath -or $identity.CreationFileTime -le 0) {
                throw "A Python/runtime process identity could not be inspected (PID $($process.ProcessId), native error $($identity.NativeError)); repair refused."
            }
            if ($identity.ImagePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw "An Angerona runtime process is still active (PID $($process.ProcessId), native creation FILETIME $($identity.CreationFileTime)); repair refused."
            }
        } finally { $identity.Dispose() }
    }
}

function New-RepairChildEnvironment([string]$Scratch) {
    Assert-PlainRepairPath $Scratch
    if (!(Test-Path -LiteralPath $Scratch -PathType Container)) {
        throw 'Owned startup scratch is unavailable.'
    }
    $system = [Environment]::SystemDirectory
    $windows = Split-Path -Parent $system
    $environment = @{
        SystemRoot = $windows; WINDIR = $windows
        SystemDrive = [IO.Path]::GetPathRoot($windows).TrimEnd('\')
        ComSpec = (Join-Path $system 'cmd.exe')
        PATH = "$system;$windows;$(Join-Path $system 'Wbem')"
        PATHEXT = '.COM;.EXE;.BAT;.CMD'
        USERPROFILE = [Environment]::GetFolderPath('UserProfile')
        LOCALAPPDATA = [Environment]::GetFolderPath('LocalApplicationData')
        APPDATA = [Environment]::GetFolderPath('ApplicationData')
        ProgramFiles = [Environment]::GetFolderPath('ProgramFiles')
        TEMP = $Scratch; TMP = $Scratch; PIP_CACHE_DIR = (Join-Path $Scratch 'pip-cache')
        PYTHONNOUSERSITE = '1'; PYTHONSAFEPATH = '1'; PYTHONDONTWRITEBYTECODE = '1'
        PIP_CONFIG_FILE = 'nul'; PIP_DISABLE_PIP_VERSION_CHECK = '1'
    }
    if ([Environment]::GetEnvironmentVariable('ANGERONA_SUPERVISED_RECOVERY') -ceq '1') {
        # Inhibition only: never a trust, privilege or response authority.
        $environment['ANGERONA_SUPERVISED_RECOVERY'] = '1'
    }
    return $environment
}

function Initialize-OwnedRepairProcess {
    if ('Angerona.StartupRepairProcess' -as [type]) { return }
    # Windows 10+: atomic job assignment avoids the suspended-child orphan
    # window. The handle allowlist prevents unrelated parent handles leaking.
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using System.IO;
namespace Angerona {
public static class StartupRepairProcess {
    static readonly object custodyGuard=new object();
    static readonly System.Collections.Generic.List<object> heldCustody=new System.Collections.Generic.List<object>();
    static readonly System.Collections.Generic.List<IDisposable> heldLeases=new System.Collections.Generic.List<IDisposable>();
    sealed class PendingCustody {
        internal IntPtr job,process,thread;
        internal System.Collections.Generic.List<IntPtr> members;
        internal Exception failure;
        internal object outputOwner;
    }
    public static bool CustodyPending { get { lock(custodyGuard)return heldCustody.Count!=0; } }
    public static bool ParkLeaseIfPending(IDisposable lease) {
        lock(custodyGuard) {
            if(heldCustody.Count==0)return false;
            heldLeases.Add(lease);return true;
        }
    }
    public static void RequireRetiredCustody() {
        if(CustodyPending)throw new InvalidOperationException("An owned startup generation has unresolved retirement custody. Its native handles and coordination leases remain retained; further startup and mutation attempts are held.");
    }
    [StructLayout(LayoutKind.Sequential)] struct SECURITY_ATTRIBUTES {
        public int length; public IntPtr descriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool inherit;
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct STARTUPINFO {
        public int cb; public string reserved, desktop, title;
        public uint x,y,xSize,ySize,xChars,yChars,fill,flags;
        public short show,reservedSize; public IntPtr reservedData,input,output,error;
    }
    [StructLayout(LayoutKind.Sequential)] struct STARTUPINFOEX {
        public STARTUPINFO startup; public IntPtr attributes;
    }
    [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION {
        public IntPtr process,thread; public uint processId,threadId;
    }
    [StructLayout(LayoutKind.Sequential)] struct BASIC_LIMITS {
        public long processTime,jobTime; public uint flags;
        public UIntPtr minWorking,maxWorking; public uint active;
        public UIntPtr affinity; public uint priority,scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] struct IO_COUNTERS {
        public ulong readOps,writeOps,otherOps,readBytes,writeBytes,otherBytes;
    }
    [StructLayout(LayoutKind.Sequential)] struct EXTENDED_LIMITS {
        public BASIC_LIMITS basic; public IO_COUNTERS io;
        public UIntPtr processMemory,jobMemory,peakProcess,peakJob;
    }
    [StructLayout(LayoutKind.Sequential)] struct FILE_INFORMATION {
        public uint attributes,createdLow,createdHigh,accessLow,accessHigh,writeLow,writeHigh;
        public uint volume,sizeHigh,sizeLow,links,indexHigh,indexLow;
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct REPAIR_RENAME_INFO {
        [MarshalAs(UnmanagedType.U1)] public bool replace;
        public IntPtr parent; public uint nameBytes; public char firstCharacter;
    }
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern IntPtr CreateJobObjectW(IntPtr security,string name);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetInformationJobObject(IntPtr job,int kind,ref EXTENDED_LIMITS info,int size);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool TerminateJobObject(IntPtr job,uint code);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,int flags,ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,
        IntPtr value,IntPtr size,IntPtr previous,IntPtr returned);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern bool CreateProcessW(string file,StringBuilder command,IntPtr processSecurity,
        IntPtr threadSecurity,bool inherit,uint flags,IntPtr environment,string directory,
        ref STARTUPINFOEX startup,out PROCESS_INFORMATION process);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern IntPtr CreateFileW(string path,uint access,uint share,ref SECURITY_ATTRIBUTES security,
        uint creation,uint flags,IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandle(IntPtr file,out FILE_INFORMATION info);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern uint GetFinalPathNameByHandleW(IntPtr file,StringBuilder path,uint size,uint flags);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetFileInformationByHandle(IntPtr file,int kind,IntPtr info,uint size);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern uint GetFileAttributesW(string path);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetProcessTimes(IntPtr process,out long created,out long exited,out long kernel,out long user);
    [StructLayout(LayoutKind.Sequential)] struct JOB_ACCOUNTING {
        public long user,kernel,periodUser,periodKernel;
        public uint faults,total,active,terminated;
    }
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool QueryInformationJobObject(IntPtr job,int kind,out JOB_ACCOUNTING info,int size,IntPtr returned);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool QueryInformationJobObject(IntPtr job,int kind,IntPtr info,int size,IntPtr returned);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool IsProcessInJob(IntPtr process,IntPtr job,out bool member);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool DuplicateHandle(IntPtr sourceProcess,IntPtr source,IntPtr targetProcess,out IntPtr target,uint access,bool inherit,uint options);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint GetFileType(IntPtr handle);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool CreatePipe(out IntPtr read,out IntPtr write,ref SECURITY_ATTRIBUTES security,uint size);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetHandleInformation(IntPtr handle,uint mask,uint flags);
    static void Check(bool ok) { if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    static IntPtr DuplicateScratchLease(SafeFileHandle lease) {
        if(lease==null)return IntPtr.Zero;
        bool retained=false;IntPtr copy=IntPtr.Zero;
        try {
            lease.DangerousAddRef(ref retained);
            Check(DuplicateHandle(GetCurrentProcess(),lease.DangerousGetHandle(),GetCurrentProcess(),out copy,0x120089u,true,0));
            FILE_INFORMATION info;Check(GetFileInformationByHandle(copy,out info));
            if(GetFileType(copy)!=1 || (info.attributes&0x410)!=0 || info.links!=1 || info.sizeHigh!=0 || info.sizeLow!=0)
                throw new InvalidOperationException("Critical scratch requires a plain zero-byte read guard.");
            var path=new StringBuilder(4096);uint size=GetFinalPathNameByHandleW(copy,path,4096,0);
            if(size==0 || size>=4096)throw new InvalidOperationException("Critical scratch guard path is unavailable.");
            string name=path.ToString();
            if(name.StartsWith(@"\\?\",StringComparison.Ordinal))name=name.Substring(4);
            string parent=System.IO.Path.GetFileName(System.IO.Path.GetDirectoryName(name));
            if(!String.Equals(System.IO.Path.GetFileName(name),"startup-critical.lease",StringComparison.Ordinal) ||
                (parent!="startup-temp.critical-interface" && parent!="startup-temp.critical-control" &&
                parent!="startup-temp.critical-preflight" && parent!="startup-temp.critical-recovery"))
                throw new InvalidOperationException("Critical scratch guard is outside its fixed workspace role.");
            IntPtr result=copy;copy=IntPtr.Zero;return result;
        } finally {
            if(copy!=IntPtr.Zero)CloseHandle(copy);
            if(retained)lease.DangerousRelease();
        }
    }
    static long CriticalOutputLimit(string log,IntPtr scratchLease) {
        const long workspace=32L*1024*1024, perLog=8L*1024*1024;
        var path=new StringBuilder(4096);uint size=GetFinalPathNameByHandleW(scratchLease,path,4096,0);
        if(size==0 || size>=4096)throw new InvalidOperationException("Critical output guard path is unavailable.");
        string guard=path.ToString();if(guard.StartsWith(@"\\?\",StringComparison.Ordinal))guard=guard.Substring(4);
        string directory=Path.GetDirectoryName(Path.GetFullPath(log));
        if(!String.Equals(directory,Path.GetDirectoryName(guard),StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Critical output must remain in its guarded workspace.");
        long used=0;int count=0;
        foreach(string entry in Directory.EnumerateFileSystemEntries(directory)) {
            if(++count>128)return 0;
            var attributes=File.GetAttributes(entry);
            if((attributes&(FileAttributes.Directory|FileAttributes.ReparsePoint))!=0)return 0;
            used+=new FileInfo(entry).Length;if(used>=workspace)return 0;
        }
        return Math.Min(perLog,workspace-used);
    }
    sealed class CriticalOutput {
        readonly FileStream input,output;
        readonly long limit;
        readonly System.Threading.ManualResetEvent complete=new System.Threading.ManualResetEvent(false);
        long dropped;
        internal string Error;
        internal long Dropped {get{return System.Threading.Interlocked.Read(ref dropped);}}
        internal CriticalOutput(SafeFileHandle read,SafeFileHandle write,long limit) {
            this.limit=limit;
            input=new FileStream(read,FileAccess.Read,8192,false);
            try {output=new FileStream(write,FileAccess.Write,8192,false);}
            catch {input.Dispose();throw;}
        }
        internal void Start() {
            var thread=new System.Threading.Thread(Pump);thread.IsBackground=true;
            thread.Name="Angerona bounded critical output";thread.Start();
        }
        void Pump() {
            var buffer=new byte[8192];long written=0;bool failed=false;
            try {
                int count;
                while((count=input.Read(buffer,0,buffer.Length))>0) {
                    int keep=failed?0:(int)Math.Min(count,Math.Max(0,limit-written));
                    if(keep>0)try{output.Write(buffer,0,keep);written+=keep;}
                        catch(Exception error){Error=error.GetType().Name+": critical output sink unavailable";failed=true;keep=0;}
                    System.Threading.Interlocked.Add(ref dropped,count-keep);
                }
            }catch(Exception error){Error=error.GetType().Name+": critical output reader unavailable";}
            finally {
                try{output.Flush(true);}catch(Exception error){Error=error.GetType().Name+": critical output flush unavailable";}
                try{output.Dispose();}catch(Exception error){Error=error.GetType().Name+": critical output close unavailable";}
                try{input.Dispose();}catch(Exception error){Error=error.GetType().Name+": critical pipe close unavailable";}
                complete.Set();
            }
        }
        internal bool Wait(int milliseconds){return complete.WaitOne(milliseconds);}
        internal void Release(){complete.Dispose();}
    }
    public static string DirectoryIdentity(string path) {
        var sa=new SECURITY_ATTRIBUTES(); sa.length=Marshal.SizeOf(sa);
        IntPtr file=CreateFileW(path,0,7,ref sa,3,0x02200000,IntPtr.Zero);
        Check(file!=new IntPtr(-1));
        try {
            FILE_INFORMATION info; Check(GetFileInformationByHandle(file,out info));
            if ((info.attributes & 0x400)!=0 || (info.attributes & 0x10)==0) {
                throw new InvalidOperationException("Runtime transaction identity is redirected or not a directory.");
            }
            return info.volume.ToString("x8")+":"+info.indexHigh.ToString("x8")+info.indexLow.ToString("x8");
        } finally { CloseHandle(file); }
    }
    static string RenameDirectoryPath(string path) {
        if (String.IsNullOrEmpty(path) || path.Length>32700 || path.Length<4 ||
            !Char.IsLetter(path[0]) || path[1]!=':' || path[2]!='\\' ||
            path.IndexOf('/')>=0 || path.IndexOf('\0')>=0) {
            throw new InvalidOperationException("Runtime rename requires a fixed local absolute path.");
        }
        string full=System.IO.Path.GetFullPath(path).TrimEnd('\\');
        if (full.Length<4 || !String.Equals(full,path.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase)) {
            throw new InvalidOperationException("Runtime rename path is not canonical.");
        }
        string[] parts=full.Substring(3).Split('\\');
        if (parts.Length>128) throw new InvalidOperationException("Runtime rename ancestry exceeds its bound.");
        foreach (string part in parts) {
            if (part.Length==0 || part=="." || part==".." || part.EndsWith(".",StringComparison.Ordinal) ||
                part.EndsWith(" ",StringComparison.Ordinal) ||
                part.IndexOfAny(System.IO.Path.GetInvalidFileNameChars())>=0) {
                throw new InvalidOperationException("Runtime rename contains an unsafe path component.");
            }
            string stem=part.Split('.')[0].ToUpperInvariant();
            if (stem=="CON" || stem=="PRN" || stem=="AUX" || stem=="NUL" ||
                (stem.Length==4 && (stem.StartsWith("COM",StringComparison.Ordinal) ||
                    stem.StartsWith("LPT",StringComparison.Ordinal)) && stem[3]>='1' && stem[3]<='9')) {
                throw new InvalidOperationException("Runtime rename contains a reserved device name.");
            }
        }
        return full;
    }
    static string RepairDirectoryKey(FILE_INFORMATION info) {
        return info.volume.ToString("x8")+":"+info.indexHigh.ToString("x8")+info.indexLow.ToString("x8");
    }
    static FILE_INFORMATION RequireRenameDirectory(IntPtr handle,string expectedPath) {
        FILE_INFORMATION info; Check(GetFileInformationByHandle(handle,out info));
        if ((info.attributes & 0x400)!=0 || (info.attributes & 0x10)==0) {
            throw new InvalidOperationException("Runtime rename directory is redirected or not a directory.");
        }
        var finalName=new StringBuilder(32768);
        uint length=GetFinalPathNameByHandleW(handle,finalName,(uint)finalName.Capacity,0);
        if (length==0) throw new Win32Exception(Marshal.GetLastWin32Error());
        if (length>=(uint)finalName.Capacity) throw new InvalidOperationException("Runtime rename final path exceeds its bound.");
        string finalPath=finalName.ToString();
        if (finalPath.StartsWith(@"\\?\",StringComparison.Ordinal) && finalPath.Length>=7 && finalPath[5]==':') {
            finalPath=finalPath.Substring(4);
        }
        if (!String.Equals(finalPath.TrimEnd('\\'),expectedPath.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase)) {
            throw new InvalidOperationException("Runtime rename directory no longer has its expected final path.");
        }
        return info;
    }
    static IntPtr OpenRenameDirectory(string path,uint access,uint share) {
        var sa=new SECURITY_ATTRIBUTES(); sa.length=Marshal.SizeOf(sa);
        IntPtr handle=CreateFileW(path,access,share,ref sa,3,0x02200000,IntPtr.Zero);
        Check(handle!=new IntPtr(-1));
        return handle;
    }
    static IntPtr PinRenameParent(string parent,System.Collections.Generic.List<IntPtr> handles,
        System.Collections.Generic.List<string> paths) {
        string cursor=System.IO.Path.GetPathRoot(parent);
        IntPtr last=IntPtr.Zero;
        string remainder=parent.Substring(cursor.Length);
        string[] parts=remainder.Length==0 ? new string[0] : remainder.Split('\\');
        for (int index=-1;index<parts.Length;index++) {
            if (index>=0) cursor=System.IO.Path.Combine(cursor,parts[index]);
            // Traverse/read-attributes only; child entries may change, but the
            // retained ancestor cannot be renamed/deleted (no SHARE_DELETE).
            last=OpenRenameDirectory(cursor,0xA0,3);
            handles.Add(last); paths.Add(cursor);
            RequireRenameDirectory(last,cursor);
        }
        return last;
    }
    public static void RenameDirectoryExact(string source,string destination,string expectedIdentity) {
        source=RenameDirectoryPath(source); destination=RenameDirectoryPath(destination);
        if (String.Equals(source,destination,StringComparison.OrdinalIgnoreCase) ||
            !System.Text.RegularExpressions.Regex.IsMatch(expectedIdentity ?? "",@"\A[0-9a-f]{8}:[0-9a-f]{16}\z")) {
            throw new InvalidOperationException("Runtime rename identity or destination is invalid.");
        }
        string targetParent=System.IO.Path.GetDirectoryName(destination);
        var handles=new System.Collections.Generic.List<IntPtr>();
        var paths=new System.Collections.Generic.List<string>();
        IntPtr sourceHandle=IntPtr.Zero, targetHandle=IntPtr.Zero, renameInfo=IntPtr.Zero;
        try {
            PinRenameParent(System.IO.Path.GetDirectoryName(source),handles,paths);
            IntPtr parentHandle=PinRenameParent(targetParent,handles,paths);
            // This handle both proves and performs the mutation. Denying new
            // DELETE opens prevents a source pathname swap after validation.
            sourceHandle=OpenRenameDirectory(source,0x10080,3);
            FILE_INFORMATION sourceInfo=RequireRenameDirectory(sourceHandle,source);
            FILE_INFORMATION parentInfo=RequireRenameDirectory(parentHandle,targetParent);
            if (RepairDirectoryKey(sourceInfo)!=expectedIdentity || sourceInfo.volume!=parentInfo.volume) {
                throw new InvalidOperationException("Runtime rename source identity or target volume changed.");
            }
            for (int index=0;index<handles.Count;index++) RequireRenameDirectory(handles[index],paths[index]);
            if (RepairDirectoryKey(RequireRenameDirectory(sourceHandle,source))!=expectedIdentity) {
                throw new InvalidOperationException("Runtime rename source changed before publication.");
            }
            byte[] name=Encoding.Unicode.GetBytes(destination);
            int nameOffset=Marshal.OffsetOf(typeof(REPAIR_RENAME_INFO),"firstCharacter").ToInt32();
            int bufferSize=checked(nameOffset+name.Length+2);
            renameInfo=Marshal.AllocHGlobal(bufferSize);
            Marshal.Copy(new byte[bufferSize],0,renameInfo,bufferSize);
            // Win32 absolute-target form, RootDirectory=NULL and no overwrite.
            // All validated ancestors remain pinned without SHARE_DELETE;
            // no POSIX/ignore-readonly flags or pathname-move fallback.
            Marshal.WriteIntPtr(renameInfo,Marshal.OffsetOf(typeof(REPAIR_RENAME_INFO),"parent").ToInt32(),IntPtr.Zero);
            Marshal.WriteInt32(renameInfo,Marshal.OffsetOf(typeof(REPAIR_RENAME_INFO),"nameBytes").ToInt32(),name.Length);
            Marshal.Copy(name,0,IntPtr.Add(renameInfo,nameOffset),name.Length);
            Check(SetFileInformationByHandle(sourceHandle,3,renameInfo,(uint)bufferSize));
            if (RepairDirectoryKey(RequireRenameDirectory(sourceHandle,destination))!=expectedIdentity) {
                throw new InvalidOperationException("Runtime rename retained-source identity changed after publication.");
            }
            // SHARE_DELETE is needed only on this additional observation
            // handle, to coexist with our retained source DELETE access.
            targetHandle=OpenRenameDirectory(destination,0x80,7);
            if (RepairDirectoryKey(RequireRenameDirectory(targetHandle,destination))!=expectedIdentity ||
                RepairDirectoryKey(RequireRenameDirectory(parentHandle,targetParent))!=RepairDirectoryKey(parentInfo)) {
                throw new InvalidOperationException("Runtime rename destination identity changed after publication.");
            }
            for (int index=0;index<handles.Count;index++) RequireRenameDirectory(handles[index],paths[index]);
            uint remaining=GetFileAttributesW(source);
            if (remaining!=0xffffffff) throw new InvalidOperationException("Runtime rename source pathname is occupied after publication.");
            int absentError=Marshal.GetLastWin32Error();
            if (absentError!=2 && absentError!=3) throw new Win32Exception(absentError);
        } finally {
            if (renameInfo!=IntPtr.Zero) Marshal.FreeHGlobal(renameInfo);
            if (targetHandle!=IntPtr.Zero) CloseHandle(targetHandle);
            if (sourceHandle!=IntPtr.Zero) CloseHandle(sourceHandle);
            for (int index=handles.Count-1;index>=0;index--) CloseHandle(handles[index]);
        }
    }
    static string Quote(string value) {
        var result = new StringBuilder("\""); int slashes = 0;
        foreach (char c in value) {
            if (c == '\\') { slashes++; continue; }
            if (c == '"') { result.Append('\\', slashes * 2 + 1); result.Append(c); }
            else { result.Append('\\', slashes); result.Append(c); }
            slashes = 0;
        }
        result.Append('\\', slashes * 2); return result.Append('"').ToString();
    }
    public sealed class Window : IDisposable {
        readonly System.Threading.CancellationTokenSource stop=new System.Threading.CancellationTokenSource();
        readonly System.Threading.Tasks.Task<int> completion;
        bool disposed;
        public uint ProcessId { get; internal set; }
        public long CreationFileTime { get; internal set; }
        public bool HasExited { get { return completion.IsCompleted; } }
        public int ExitCode { get { return completion.GetAwaiter().GetResult(); } }
        internal Window(string file,string[] args,string directory,string environment,string log,IntPtr scratchLease,bool critical) {
            completion=System.Threading.Tasks.Task.Factory.StartNew(
                ()=>RunCore(file,args,directory,environment,log,-1,stop.Token,this,scratchLease,critical),
                System.Threading.CancellationToken.None,System.Threading.Tasks.TaskCreationOptions.LongRunning,
                System.Threading.Tasks.TaskScheduler.Default);
        }
        public bool WaitForExit(int milliseconds) { return completion.Wait(milliseconds); }
        public void WaitForExit() { completion.GetAwaiter().GetResult(); }
        public void Dispose() {
            if(disposed)return;
            stop.Cancel();
            if(!completion.Wait(10000))throw new TimeoutException("Owned recovery window retirement could not be verified.");
            disposed=true;stop.Dispose();
        }
    }
    public static Window StartWindow(string file,string[] args,string directory,string environment,string log) {
        return new Window(file,args,directory,environment,log,IntPtr.Zero,false);
    }
    public static Window StartWindow(string file,string[] args,string directory,string environment,string log,
        SafeFileHandle scratchLease,bool critical) {
        IntPtr inherited=DuplicateScratchLease(scratchLease);
        try {
            if(critical && inherited==IntPtr.Zero)throw new InvalidOperationException("Critical startup requires a retained read guard.");
            return new Window(file,args,directory,environment,log,inherited,critical);
        } catch {if(inherited!=IntPtr.Zero)CloseHandle(inherited);throw;}
    }
    static void RetireJob(IntPtr job,IntPtr root,System.Collections.Generic.List<IntPtr> retained) {
        Exception custodyError=null;
        IntPtr list=Marshal.AllocHGlobal(8+4096*IntPtr.Size);
        try {
            try {
                Check(QueryInformationJobObject(job,3,list,8+4096*IntPtr.Size,IntPtr.Zero));
                uint count=unchecked((uint)Marshal.ReadInt32(list,4));
                if(count>4096)throw new InvalidOperationException("Owned startup process capacity requires review.");
                for(int i=0;i<count;i++) {
                    long pid=Marshal.ReadIntPtr(list,8+i*IntPtr.Size).ToInt64();
                    if(pid<1 || pid>uint.MaxValue)throw new InvalidOperationException("Owned startup process identity is invalid.");
                    IntPtr handle=OpenProcess(0x101000,false,(uint)pid);
                    if(handle==IntPtr.Zero) {
                        if(Marshal.GetLastWin32Error()==87)continue;
                        Check(false);
                    }
                    bool member;
                    if(!IsProcessInJob(handle,job,out member)) {
                        int error=Marshal.GetLastWin32Error();CloseHandle(handle);throw new Win32Exception(error);
                    }
                    if(member)retained.Add(handle);else CloseHandle(handle); // PID reuse never gains custody.
                }
            } catch(Exception error) { custodyError=error; }
            Check(TerminateJobObject(job,1223));
            var clock=System.Diagnostics.Stopwatch.StartNew();
            // Job accounting can reach zero before a terminating process has
            // signaled its handle or released file locks. Retain exact handles.
            if(WaitForSingleObject(root,5000)!=0)throw new TimeoutException("Owned startup root has not retired; retry is held.");
            foreach(IntPtr process in retained) {
                uint remaining=(uint)Math.Max(0,5000-clock.ElapsedMilliseconds);
                if(WaitForSingleObject(process,remaining)!=0)throw new TimeoutException("An owned startup descendant has not retired; retry is held.");
            }
            JOB_ACCOUNTING info;
            Check(QueryInformationJobObject(job,1,out info,Marshal.SizeOf(typeof(JOB_ACCOUNTING)),IntPtr.Zero));
            if(info.active!=0)throw new TimeoutException("Owned startup job is still active; retry is held.");
            if(custodyError!=null)throw new InvalidOperationException("Owned startup descendant custody could not be established.",custodyError);
        } finally {
            Marshal.FreeHGlobal(list);
        }
    }
    public static int Run(string file,string[] args,string directory,string environment,string log,int timeout) {
        return RunCore(file,args,directory,environment,log,timeout,System.Threading.CancellationToken.None,null,IntPtr.Zero,false);
    }
    public static int Run(string file,string[] args,string directory,string environment,string log,int timeout,
        SafeFileHandle scratchLease,bool critical) {
        IntPtr inherited=DuplicateScratchLease(scratchLease);
        if(critical && inherited==IntPtr.Zero)throw new InvalidOperationException("Critical startup requires a retained read guard.");
        return RunCore(file,args,directory,environment,log,timeout,System.Threading.CancellationToken.None,null,inherited,critical);
    }
    static string BindScratchEnvironment(string environment,IntPtr scratchLease) {
        if(environment==null)return null; // Existing direct native callers retain their original environment mode.
        var entries=new System.Collections.Generic.List<string>();
        foreach(string entry in environment.Split('\0')) {
            if(entry.Length==0)continue;
            int separator=entry.IndexOf('=');
            string key=separator<0?entry:entry.Substring(0,separator);
            if(!String.Equals(key,"ANGERONA_STARTUP_SCRATCH_LEASE_HANDLE",StringComparison.OrdinalIgnoreCase))entries.Add(entry);
        }
        if(scratchLease!=IntPtr.Zero)entries.Add("ANGERONA_STARTUP_SCRATCH_LEASE_HANDLE="+
            scratchLease.ToInt64().ToString(System.Globalization.CultureInfo.InvariantCulture));
        entries.Sort(StringComparer.OrdinalIgnoreCase);
        return String.Join("\0",entries.ToArray())+"\0\0";
    }
    static int RunCore(string file,string[] args,string directory,string environment,string log,int timeout,
        System.Threading.CancellationToken stop,Window owner,IntPtr scratchLease,bool critical) {
        IntPtr job=IntPtr.Zero, attrs=IntPtr.Zero, jobs=IntPtr.Zero, handles=IntPtr.Zero, env=IntPtr.Zero;
        IntPtr output=IntPtr.Zero, input=IntPtr.Zero; bool initialized=false;
        bool boundedOutput=scratchLease!=IntPtr.Zero;
        IntPtr pipeRead=IntPtr.Zero,pipeWrite=IntPtr.Zero;CriticalOutput criticalOutput=null;
        var pi = new PROCESS_INFORMATION();
        try {
            if(owner==null)RequireRetiredCustody(); // Independent diagnostic windows remain usable.
            job=CreateJobObjectW(IntPtr.Zero,null); Check(job!=IntPtr.Zero);
            var limits=new EXTENDED_LIMITS(); limits.basic.flags=0x2000;
            Check(SetInformationJobObject(job,9,ref limits,Marshal.SizeOf(limits)));
            var sa=new SECURITY_ATTRIBUTES(); sa.length=Marshal.SizeOf(sa); sa.inherit=true;
            output=CreateFileW(log,0x40000000,1,ref sa,1,0x80,IntPtr.Zero);
            Check(output!=new IntPtr(-1));
            if(boundedOutput) {
                // Only the bounded pipe writer is inheritable. The raw disk
                // sink must never escape into a concurrent Framework child.
                Check(SetHandleInformation(output,1,0));
                long limit=CriticalOutputLimit(log,scratchLease);
                Check(CreatePipe(out pipeRead,out pipeWrite,ref sa,8192));
                Check(SetHandleInformation(pipeRead,1,0));
                var readHandle=new SafeFileHandle(pipeRead,true);pipeRead=IntPtr.Zero;
                var writeHandle=new SafeFileHandle(output,true);output=IntPtr.Zero;
                try{criticalOutput=new CriticalOutput(readHandle,writeHandle,limit);criticalOutput.Start();}
                catch{readHandle.Dispose();writeHandle.Dispose();throw;}
            }
            input=CreateFileW(@"\\.\NUL",0x80000000,3,ref sa,3,0x80,IntPtr.Zero);
            Check(input!=new IntPtr(-1));
            IntPtr size=IntPtr.Zero; InitializeProcThreadAttributeList(IntPtr.Zero,2,0,ref size);
            attrs=Marshal.AllocHGlobal(size); Check(InitializeProcThreadAttributeList(attrs,2,0,ref size));
            initialized=true;
            jobs=Marshal.AllocHGlobal(IntPtr.Size); Marshal.WriteIntPtr(jobs,job);
            Check(UpdateProcThreadAttribute(attrs,0,new IntPtr(0x2000D),jobs,new IntPtr(IntPtr.Size),IntPtr.Zero,IntPtr.Zero));
            int handleCount=scratchLease==IntPtr.Zero?2:3;
            handles=Marshal.AllocHGlobal(IntPtr.Size*handleCount);
            IntPtr childOutput=boundedOutput?pipeWrite:output;
            Marshal.WriteIntPtr(handles,0,childOutput); Marshal.WriteIntPtr(handles,IntPtr.Size,input);
            if(scratchLease!=IntPtr.Zero)Marshal.WriteIntPtr(handles,IntPtr.Size*2,scratchLease);
            Check(UpdateProcThreadAttribute(attrs,0,new IntPtr(0x20002),handles,new IntPtr(IntPtr.Size*handleCount),IntPtr.Zero,IntPtr.Zero));
            var startup=new STARTUPINFOEX(); startup.startup.cb=Marshal.SizeOf(startup);
            startup.startup.flags=0x101; startup.startup.input=input;
            // An explicit GUI owner must show its first window. Background
            // commands retain SW_HIDE; CREATE_NO_WINDOW still suppresses consoles.
            startup.startup.show=(short)(owner!=null ? 1 : 0);
            startup.startup.output=childOutput; startup.startup.error=childOutput; startup.attributes=attrs;
            var command=new StringBuilder(Quote(file));
            foreach (string arg in args) command.Append(' ').Append(Quote(arg));
            env=Marshal.StringToHGlobalUni(BindScratchEnvironment(environment,scratchLease));
            Check(CreateProcessW(file,command,IntPtr.Zero,IntPtr.Zero,true,0x08080404,env,directory,ref startup,out pi));
            if(pipeWrite!=IntPtr.Zero){IntPtr bridge=pipeWrite;pipeWrite=IntPtr.Zero;Check(CloseHandle(bridge));}
            // The child now owns its read-only copy. Do not keep an accidental
            // parent bridge that could disguise failed inheritance in tests.
            if(scratchLease!=IntPtr.Zero){Check(CloseHandle(scratchLease));scratchLease=IntPtr.Zero;}
            if(owner!=null) {
                long created,exited,kernel,user;
                Check(GetProcessTimes(pi.process,out created,out exited,out kernel,out user));
                owner.CreationFileTime=created;owner.ProcessId=pi.processId;
            }
            Check(ResumeThread(pi.thread)!=0xFFFFFFFF);
            var clock=System.Diagnostics.Stopwatch.StartNew();
            uint waited=258;
            var volumes=new string[]{System.IO.Path.GetPathRoot(directory),System.IO.Path.GetPathRoot(log)};
            while(timeout<0 || clock.ElapsedMilliseconds<timeout) {
                if(stop.IsCancellationRequested)return 1223;
                waited=WaitForSingleObject(pi.process,(uint)(timeout<0 ? 100 : Math.Min(100,timeout-clock.ElapsedMilliseconds)));
                if(waited!=258) break;
                if(timeout<0)continue; // The read-only recovery UI waits for its operator.
                foreach(string volume in volumes) {
                    var disk=new System.IO.DriveInfo(volume);
                    if(!disk.IsReady || (!critical && disk.AvailableFreeSpace<2L*1024*1024*1024)) {
                        TerminateJobObject(job,112);WaitForSingleObject(pi.process,5000);
                        throw new System.IO.IOException("Owned startup command stopped at the 2 GiB drive-space reserve; existing runtime and evidence remain held.");
                    }
                }
            }
            if (waited==258) {
                TerminateJobObject(job,1460); WaitForSingleObject(pi.process,5000);
                throw new TimeoutException("Owned startup command exceeded its deadline.");
            }
            Check(waited==0); uint code; Check(GetExitCodeProcess(pi.process,out code));
            return unchecked((int)code);
        } finally {
            if(pipeWrite!=IntPtr.Zero){CloseHandle(pipeWrite);pipeWrite=IntPtr.Zero;}
            // Do not release a reader/mutation lease merely because a redirector
            // exited. Observe every descendant in this exact non-inherited job.
            var retained=new System.Collections.Generic.List<IntPtr>();
            try {
                if(job!=IntPtr.Zero && pi.process!=IntPtr.Zero)RetireJob(job,pi.process,retained);
            } catch(Exception error) {
                lock(custodyGuard)heldCustody.Add(new PendingCustody {
                    job=job,process=pi.process,thread=pi.thread,members=retained,failure=error,outputOwner=criticalOutput });
                // The failed proof must not become an apparent retirement just
                // because a finally block discarded every native witness.
                job=IntPtr.Zero;pi.process=IntPtr.Zero;pi.thread=IntPtr.Zero;retained=null;criticalOutput=null;
                throw new InvalidOperationException("Owned startup retirement is unresolved; exact native custody remains parked and Retry is held.",error);
            }
            finally {
            Exception outputRetirementError=null;
            if(criticalOutput!=null) {
                if(!criticalOutput.Wait(5000)) {
                    lock(custodyGuard)heldCustody.Add(criticalOutput);
                    outputRetirementError=new InvalidOperationException("Critical output reader retirement is unverified; its exact stream owner remains retained.");
                } else try {
                    if(criticalOutput.Dropped>0 || criticalOutput.Error!=null) {
                        try{Console.Error.WriteLine("{\"component\":\"critical-startup-output\",\"outcome\":\"limited\",\"dropped_bytes\":"+criticalOutput.Dropped+"}");}catch{}
                    }
                }finally{criticalOutput.Release();}
            }
            if(retained!=null)foreach(IntPtr process in retained)CloseHandle(process);
            if (job!=IntPtr.Zero) CloseHandle(job);
            if (pi.thread!=IntPtr.Zero) CloseHandle(pi.thread);
            if (pi.process!=IntPtr.Zero) CloseHandle(pi.process);
            if (output!=IntPtr.Zero && output!=new IntPtr(-1)) CloseHandle(output);
            if (input!=IntPtr.Zero && input!=new IntPtr(-1)) CloseHandle(input);
            if (scratchLease!=IntPtr.Zero) CloseHandle(scratchLease);
            if (pipeRead!=IntPtr.Zero) CloseHandle(pipeRead);
            if (initialized) DeleteProcThreadAttributeList(attrs);
            if (attrs!=IntPtr.Zero) Marshal.FreeHGlobal(attrs);
            if (jobs!=IntPtr.Zero) Marshal.FreeHGlobal(jobs);
            if (handles!=IntPtr.Zero) Marshal.FreeHGlobal(handles);
            if (env!=IntPtr.Zero) Marshal.FreeHGlobal(env);
            if(outputRetirementError!=null)throw outputRetirementError;
            }
        }
    }
}
}
'@
}

function Get-SourceStartupReadLease([IO.FileStream]$ScratchLease, [bool]$ExplicitLease = $false) {
    if (!$ExplicitLease -and $null -eq $ScratchLease) {
        $current = Get-Variable -Name SourceStartupScratchLease -Scope Script -ErrorAction SilentlyContinue
        if ($current) {
            if ($null -ne $current.Value -and $current.Value -isnot [IO.FileStream]) { throw 'Critical scratch lease must be an actual read-only file stream.' }
            $ScratchLease = $current.Value
        }
    }
    if ($null -eq $ScratchLease) { return $null }
    if (!$ScratchLease.CanRead -or $ScratchLease.CanWrite -or !$ScratchLease.CanSeek -or $ScratchLease.Length -ne 0) {
        throw 'Critical scratch lease must remain a zero-byte read-only file stream.'
    }
    Assert-PlainRepairPath $ScratchLease.Name
    Assert-PrivateRepairCustody $ScratchLease.Name
    if ([IO.Path]::GetFileName($ScratchLease.Name) -cne 'startup-critical.lease' -or
        [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($ScratchLease.Name)) -cnotmatch '^startup-temp\.critical-(interface|control|preflight|recovery)$') {
        throw 'Critical scratch guard is outside its fixed workspace role.'
    }
    return ,$ScratchLease
}

function Get-SourceStartupCriticalMode([bool]$Requested, [bool]$ExplicitMode) {
    if ($ExplicitMode) { return $Requested }
    $current = Get-Variable -Name SourceStartupCriticalMode -Scope Script -ErrorAction SilentlyContinue
    return [bool]($current -and $current.Value -is [bool] -and $current.Value)
}

function Invoke-OwnedRepairProcess {
    param([string]$FilePath, [string[]]$Arguments, [string]$WorkingDirectory,
        [Collections.IDictionary]$Environment, [ValidateRange(1,1800)][int]$TimeoutSeconds,
        [string]$LogPath, [IO.FileStream]$ScratchLease, [switch]$CriticalStartup)
    # Windows servicing legitimately hard-links system executables to WinSxS.
    # Callers choose/signature-check their fixed executable; it is never edited.
    Assert-PlainRepairPath $FilePath -AllowHardLinks
    Assert-PlainRepairPath $WorkingDirectory
    Assert-PlainRepairPath $LogPath
    if (!(Test-Path -LiteralPath $FilePath -PathType Leaf) -or
        (Test-Path -LiteralPath $LogPath)) { throw 'Owned startup command paths are unavailable.' }
    $entries = foreach ($name in ($Environment.Keys | Sort-Object)) {
        $value = [string]$Environment[$name]
        if ($name -notmatch '^[A-Za-z_][A-Za-z0-9_]*$' -or $value.Contains([char]0)) {
            throw 'Invalid owned startup command environment.'
        }
        "$name=$value"
    }
    Initialize-OwnedRepairProcess
    [Angerona.StartupRepairProcess]::RequireRetiredCustody()
    $scratchGuard = Get-SourceStartupReadLease $ScratchLease ($PSBoundParameters.ContainsKey('ScratchLease'))
    $critical = Get-SourceStartupCriticalMode $CriticalStartup.IsPresent ($PSBoundParameters.ContainsKey('CriticalStartup'))
    $block = ($entries -join [char]0) + [char]0 + [char]0
    return [Angerona.StartupRepairProcess]::Run($FilePath, $Arguments,
        $WorkingDirectory, $block, $LogPath, ($TimeoutSeconds * 1000),
        $(if ($scratchGuard) { $scratchGuard.SafeFileHandle } else { $null }), $critical)
}

function Start-OwnedRepairWindow {
    param([string]$FilePath, [string[]]$Arguments, [string]$WorkingDirectory,
        [Collections.IDictionary]$Environment, [string]$LogPath, [IO.FileStream]$ScratchLease, [switch]$CriticalStartup)
    Assert-PlainRepairPath $FilePath -AllowHardLinks
    Assert-PlainRepairPath $WorkingDirectory
    Assert-PlainRepairPath $LogPath
    if (!(Test-Path -LiteralPath $FilePath -PathType Leaf) -or (Test-Path -LiteralPath $LogPath)) {
        throw 'Owned recovery window paths are unavailable.'
    }
    $entries = foreach ($name in ($Environment.Keys | Sort-Object)) {
        $value = [string]$Environment[$name]
        if ($name -notmatch '^[A-Za-z_][A-Za-z0-9_]*$' -or $value.Contains([char]0)) {
            throw 'Invalid owned recovery window environment.'
        }
        "$name=$value"
    }
    Assert-PrivateRepairCustody $Environment['TEMP'] -AllowInherited
    $savedTemp, $savedTmp = $env:TEMP, $env:TMP
    try {
        $env:TEMP = $Environment['TEMP']; $env:TMP = $Environment['TMP']
        Initialize-OwnedRepairProcess
    } finally { $env:TEMP = $savedTemp; $env:TMP = $savedTmp }
    $block = ($entries -join [char]0) + [char]0 + [char]0
    $scratchGuard = Get-SourceStartupReadLease $ScratchLease ($PSBoundParameters.ContainsKey('ScratchLease'))
    $critical = Get-SourceStartupCriticalMode $CriticalStartup.IsPresent ($PSBoundParameters.ContainsKey('CriticalStartup'))
    return [Angerona.StartupRepairProcess]::StartWindow($FilePath, $Arguments, $WorkingDirectory, $block, $LogPath,
        $(if ($scratchGuard) { $scratchGuard.SafeFileHandle } else { $null }), $critical)
}
