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
        foreach ($directory in Get-ChildItem -LiteralPath $parent -Directory -Filter 'startup-repair.*') {
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
        try { $Lease.Unlock(0, 1) } finally { $Lease.Dispose() }
    }
}

function Assert-NoActiveVenv([string]$VenvPath) {
    $prefix = [IO.Path]::GetFullPath($VenvPath).TrimEnd('\') + '\'
    # Do not infer process identity from untrusted command-line/log text.
    foreach ($process in Get-CimInstance Win32_Process -OperationTimeoutSec 10) {
        if ($process.ExecutablePath -and
            $process.ExecutablePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "An Angerona runtime process is still active (PID $($process.ProcessId)); repair refused."
        }
        if (!$process.ExecutablePath -and
            $process.Name -in @('python.exe', 'pythonw.exe', 'Angerona.exe', 'pip.exe')) {
            throw 'A Python/runtime process identity could not be inspected; repair refused.'
        }
    }
}

function New-RepairChildEnvironment([string]$Scratch) {
    Assert-PlainRepairPath $Scratch
    if (!(Test-Path -LiteralPath $Scratch -PathType Container)) {
        throw 'Owned startup scratch is unavailable.'
    }
    $system = [Environment]::SystemDirectory
    $windows = Split-Path -Parent $system
    return @{
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
namespace Angerona {
public static class StartupRepairProcess {
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
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    static void Check(bool ok) { if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }
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
    public static int Run(string file,string[] args,string directory,string environment,string log,int timeout) {
        IntPtr job=IntPtr.Zero, attrs=IntPtr.Zero, jobs=IntPtr.Zero, handles=IntPtr.Zero, env=IntPtr.Zero;
        IntPtr output=IntPtr.Zero, input=IntPtr.Zero; bool initialized=false;
        var pi = new PROCESS_INFORMATION();
        try {
            job=CreateJobObjectW(IntPtr.Zero,null); Check(job!=IntPtr.Zero);
            var limits=new EXTENDED_LIMITS(); limits.basic.flags=0x2000;
            Check(SetInformationJobObject(job,9,ref limits,Marshal.SizeOf(limits)));
            var sa=new SECURITY_ATTRIBUTES(); sa.length=Marshal.SizeOf(sa); sa.inherit=true;
            output=CreateFileW(log,0x40000000,1,ref sa,1,0x80,IntPtr.Zero);
            Check(output!=new IntPtr(-1));
            input=CreateFileW(@"\\.\NUL",0x80000000,3,ref sa,3,0x80,IntPtr.Zero);
            Check(input!=new IntPtr(-1));
            IntPtr size=IntPtr.Zero; InitializeProcThreadAttributeList(IntPtr.Zero,2,0,ref size);
            attrs=Marshal.AllocHGlobal(size); Check(InitializeProcThreadAttributeList(attrs,2,0,ref size));
            initialized=true;
            jobs=Marshal.AllocHGlobal(IntPtr.Size); Marshal.WriteIntPtr(jobs,job);
            Check(UpdateProcThreadAttribute(attrs,0,new IntPtr(0x2000D),jobs,new IntPtr(IntPtr.Size),IntPtr.Zero,IntPtr.Zero));
            handles=Marshal.AllocHGlobal(IntPtr.Size*2);
            Marshal.WriteIntPtr(handles,0,output); Marshal.WriteIntPtr(handles,IntPtr.Size,input);
            Check(UpdateProcThreadAttribute(attrs,0,new IntPtr(0x20002),handles,new IntPtr(IntPtr.Size*2),IntPtr.Zero,IntPtr.Zero));
            var startup=new STARTUPINFOEX(); startup.startup.cb=Marshal.SizeOf(startup);
            startup.startup.flags=0x101; startup.startup.input=input;
            startup.startup.output=output; startup.startup.error=output; startup.attributes=attrs;
            var command=new StringBuilder(Quote(file));
            foreach (string arg in args) command.Append(' ').Append(Quote(arg));
            env=Marshal.StringToHGlobalUni(environment);
            Check(CreateProcessW(file,command,IntPtr.Zero,IntPtr.Zero,true,0x08080404,env,directory,ref startup,out pi));
            Check(ResumeThread(pi.thread)!=0xFFFFFFFF);
            uint waited=WaitForSingleObject(pi.process,checked((uint)timeout));
            if (waited==258) {
                TerminateJobObject(job,1460); WaitForSingleObject(pi.process,5000);
                throw new TimeoutException("Owned startup command exceeded its deadline.");
            }
            Check(waited==0); uint code; Check(GetExitCodeProcess(pi.process,out code));
            return unchecked((int)code);
        } finally {
            // Closing our non-inherited job kills only this command's descendants,
            // including children left behind after a normal parent exit.
            if (job!=IntPtr.Zero) CloseHandle(job);
            if (pi.thread!=IntPtr.Zero) CloseHandle(pi.thread);
            if (pi.process!=IntPtr.Zero) CloseHandle(pi.process);
            if (output!=IntPtr.Zero && output!=new IntPtr(-1)) CloseHandle(output);
            if (input!=IntPtr.Zero && input!=new IntPtr(-1)) CloseHandle(input);
            if (initialized) DeleteProcThreadAttributeList(attrs);
            if (attrs!=IntPtr.Zero) Marshal.FreeHGlobal(attrs);
            if (jobs!=IntPtr.Zero) Marshal.FreeHGlobal(jobs);
            if (handles!=IntPtr.Zero) Marshal.FreeHGlobal(handles);
            if (env!=IntPtr.Zero) Marshal.FreeHGlobal(env);
        }
    }
}
}
'@
}

function Invoke-OwnedRepairProcess {
    param([string]$FilePath, [string[]]$Arguments, [string]$WorkingDirectory,
        [Collections.IDictionary]$Environment, [ValidateRange(1,1800)][int]$TimeoutSeconds,
        [string]$LogPath)
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
    $block = ($entries -join [char]0) + [char]0 + [char]0
    return [Angerona.StartupRepairProcess]::Run($FilePath, $Arguments,
        $WorkingDirectory, $block, $LogPath, ($TimeoutSeconds * 1000))
}
