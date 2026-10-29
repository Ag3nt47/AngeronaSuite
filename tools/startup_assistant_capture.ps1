# Bounded, standalone Windows PowerShell 5 startup-assistant output capture.
# Dot-sourcing performs no compilation, process creation, or filesystem writes.

function Initialize-SourceStartupCapture {
    if ('Angerona.StartupCaptureSession' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;
namespace Angerona {
public sealed class StartupCaptureSession {
    public const long OutputLimit = 8L * 1024 * 1024;
    const int ChunkSize = 8192;
    [StructLayout(LayoutKind.Sequential)] struct FileInformation {
        public uint Attributes, CreatedLow, CreatedHigh, AccessLow, AccessHigh;
        public uint WriteLow, WriteHigh, Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share,
        IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation info);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetProcessTimes(IntPtr process, out long created, out long exited,
        out long kernel, out long user);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool DuplicateHandle(IntPtr sourceProcess,IntPtr source,IntPtr targetProcess,out IntPtr target,uint access,bool inherit,uint options);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint GetFileType(IntPtr handle);
    [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle,StringBuilder path,uint size,uint flags);
    static void Check(bool ok) { if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }
    readonly List<SafeFileHandle> directories = new List<SafeFileHandle>();
    readonly object custody = new object();
    Pump stdout, stderr;
    int remaining;
    long criticalOutputRemaining=Int64.MaxValue;
    bool criticalOutputBound;
    public Process Process { get; private set; }
    public int ProcessId { get; private set; }
    public string ProcessRole { get { return "assistant-launcher"; } }
    public string CreationTimeUtc { get; private set; }
    public string CreationTimeFileTime { get; private set; }
    public string ScratchLeaseHandle { get; private set; }
    public int ExitCode { get; private set; }
    public bool TimedOut { get; private set; }
    public bool ReadersComplete { get { return (stdout == null || stdout.Done) && (stderr == null || stderr.Done); } }
    public long StdoutDropped { get { return stdout == null ? 0 : Interlocked.Read(ref stdout.Dropped); } }
    public long StderrDropped { get { return stderr == null ? 0 : Interlocked.Read(ref stderr.Dropped); } }
    public string CaptureError {
        get {
            string result = monitorError;
            if (stdout != null && stdout.Error != null) result += " stdout: " + stdout.Error;
            if (stderr != null && stderr.Error != null) result += " stderr: " + stderr.Error;
            return result.Length <= 2000 ? result : result.Substring(0, 2000);
        }
    }
    string monitorError = "";
    sealed class Pump {
        readonly StartupCaptureSession owner;
        readonly FileStream input;
        readonly FileStream output;
        public long Dropped;
        public volatile bool Done;
        public volatile string Error;
        public Pump(StartupCaptureSession owner, FileStream input, FileStream output) {
            this.owner = owner; this.input = input; this.output = output;
        }
        public void Start() {
            Thread worker = new Thread(Run);
            worker.IsBackground = true;
            worker.Name = "Angerona bounded startup output";
            worker.Start();
        }
        void Run() {
            byte[] buffer = new byte[ChunkSize];
            long written = 0;
            bool sinkFailed = false;
            try {
                while (true) {
                    // Blocking native I/O belongs only to this retained background
                    // reader. The supervisor never joins it without a deadline.
                    int count = input.Read(buffer, 0, buffer.Length);
                    if (count == 0) break;
                    int keep = sinkFailed ? 0 : owner.ReserveOutput((int)Math.Min((long)count, OutputLimit - written));
                    if (keep > 0) {
                        try { output.Write(buffer, 0, keep); written += keep; }
                        catch (Exception error) {
                            Error = error.GetType().Name + ": output write failed";
                            sinkFailed = true; keep = 0;
                        }
                    }
                    Interlocked.Add(ref Dropped, (long)count - keep);
                }
            } catch (Exception error) {
                Error = error.GetType().Name + ": output reader failed";
            } finally {
                try { output.Dispose(); } catch (Exception error) { Error = error.GetType().Name + ": output close failed"; }
                try { input.Dispose(); } catch (Exception error) { Error = error.GetType().Name + ": pipe close failed"; }
                Done = true;
                owner.ReaderFinished();
            }
        }
    }
    void ReaderFinished() {
        if (Interlocked.Decrement(ref remaining) == 0) {
            if(criticalOutputBound && (StdoutDropped>0 || StderrDropped>0)) {
                try{Console.Error.WriteLine("{\"component\":\"critical-startup-output\",\"outcome\":\"limited\",\"dropped_bytes\":"+(StdoutDropped+StderrDropped)+"}");}catch{}
            }
            ReleaseDirectories();
        }
    }
    int ReserveOutput(int requested) {
        if(!criticalOutputBound)return requested;
        while(true) {
            long available=Interlocked.Read(ref criticalOutputRemaining);
            int keep=(int)Math.Min(requested,Math.Max(0,available));
            if(Interlocked.CompareExchange(ref criticalOutputRemaining,available-keep,available)==available)return keep;
        }
    }
    void ReleaseDirectories() {
        lock (custody) {
            foreach (SafeFileHandle handle in directories) handle.Dispose();
            directories.Clear();
        }
    }
    static string PlainPath(string path) {
        if (String.IsNullOrWhiteSpace(path) || path.Length > 4096 || path.IndexOf('\0') >= 0 ||
            path.Length < 3 || !Char.IsLetter(path[0]) || path[1] != ':' || (path[2] != '\\' && path[2] != '/'))
            throw new IOException("Capture requires an absolute local path.");
        return Path.GetFullPath(path);
    }
    void RetainDirectory(string path, bool requirePrivate) {
        List<string> chain = new List<string>();
        for (string cursor = path; cursor != null; cursor = Path.GetDirectoryName(cursor)) chain.Add(cursor);
        chain.Reverse();
        foreach (string item in chain) {
            SafeFileHandle handle = CreateFileW(item, 0x80, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
            Check(!handle.IsInvalid);
            directories.Add(handle);
            FileInformation info; Check(GetFileInformationByHandle(handle, out info));
            if ((info.Attributes & 0x400) != 0 || (info.Attributes & 0x10) == 0)
                throw new IOException("Capture refuses redirected or non-directory ancestors.");
        }
        if (requirePrivate) {
            string sid = WindowsIdentity.GetCurrent().User.Value;
            DirectorySecurity acl = Directory.GetAccessControl(path);
            if (!acl.AreAccessRulesProtected || acl.GetOwner(typeof(SecurityIdentifier)).Value != sid)
                throw new IOException("Capture requires a private scratch directory.");
            foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier))) {
                string allowed = rule.IdentityReference.Value;
                if (rule.IsInherited || rule.AccessControlType != AccessControlType.Allow ||
                    (allowed != sid && allowed != "S-1-5-18" && allowed != "S-1-5-32-544"))
                    throw new IOException("Capture scratch has an unexpected access rule.");
            }
        }
    }
    static FileStream CreateOutput(string path) {
        SecurityIdentifier owner = WindowsIdentity.GetCurrent().User;
        FileSecurity acl = new FileSecurity();
        acl.SetOwner(owner); acl.SetAccessRuleProtection(true, false);
        foreach (string sid in new string[] {owner.Value, "S-1-5-18", "S-1-5-32-544"})
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),
                FileSystemRights.FullControl, AccessControlType.Allow));
        FileStream result = new FileStream(path, FileMode.CreateNew, FileSystemRights.Write,
            FileShare.Read, ChunkSize, FileOptions.WriteThrough, acl);
        try {
            FileInformation info; Check(GetFileInformationByHandle(result.SafeFileHandle, out info));
            if ((info.Attributes & (0x400 | 0x10)) != 0 || info.Links != 1)
                throw new IOException("Capture output is not a plain single-link file.");
            return result;
        } catch { result.Dispose(); throw; }
    }
    static SafeFileHandle DuplicateScratchLease(SafeFileHandle lease) {
        if(lease==null)return null;
        bool retained=false;SafeFileHandle result=null;
        try {
            lease.DangerousAddRef(ref retained);IntPtr copy;
            Check(DuplicateHandle(GetCurrentProcess(),lease.DangerousGetHandle(),GetCurrentProcess(),out copy,0x120089u,true,0));
            result=new SafeFileHandle(copy,true);
            FileInformation info;Check(GetFileInformationByHandle(result,out info));
            if(GetFileType(copy)!=1 || (info.Attributes&0x410)!=0 || info.Links!=1 || info.SizeHigh!=0 || info.SizeLow!=0)
                throw new IOException("Critical scratch requires a plain zero-byte read guard.");
            var path=new StringBuilder(4096);uint size=GetFinalPathNameByHandleW(result,path,4096,0);
            if(size==0 || size>=4096)throw new IOException("Critical scratch guard path is unavailable.");
            string name=path.ToString();
            if(name.StartsWith(@"\\?\",StringComparison.Ordinal))name=name.Substring(4);
            string parent=Path.GetFileName(Path.GetDirectoryName(name));
            if(Path.GetFileName(name)!="startup-critical.lease" ||
                (parent!="startup-temp.critical-interface" && parent!="startup-temp.critical-control" &&
                parent!="startup-temp.critical-preflight" && parent!="startup-temp.critical-recovery"))
                throw new IOException("Critical scratch guard is outside its fixed workspace role.");
            SafeFileHandle owned=result;result=null;return owned;
        } finally {
            if(result!=null)result.Dispose();
            if(retained)lease.DangerousRelease();
        }
    }
    static readonly object scratchStartGuard=new object();
    static long CriticalOutputRemaining(string stdout,string stderr,SafeFileHandle lease) {
        const long workspace=32L*1024*1024;
        var path=new StringBuilder(4096);uint size=GetFinalPathNameByHandleW(lease,path,4096,0);
        if(size==0 || size>=4096)throw new IOException("Critical output guard path is unavailable.");
        string guard=path.ToString();if(guard.StartsWith(@"\\?\",StringComparison.Ordinal))guard=guard.Substring(4);
        string directory=Path.GetDirectoryName(guard);
        if(!String.Equals(directory,Path.GetDirectoryName(stdout),StringComparison.OrdinalIgnoreCase) ||
            !String.Equals(directory,Path.GetDirectoryName(stderr),StringComparison.OrdinalIgnoreCase))
            throw new IOException("Critical capture output must remain in its guarded workspace.");
        long used=0;int count=0;
        foreach(string entry in Directory.EnumerateFileSystemEntries(directory)) {
            if(++count>128)return 0;
            var attributes=File.GetAttributes(entry);
            if((attributes&(FileAttributes.Directory|FileAttributes.ReparsePoint))!=0)return 0;
            used+=new FileInfo(entry).Length;if(used>=workspace)return 0;
        }
        return workspace-used;
    }
    static string Quote(string argument) {
        if (argument == null || argument.IndexOf('\0') >= 0) throw new ArgumentException("Invalid capture argument.");
        StringBuilder value = new StringBuilder("\"");
        int slashes = 0;
        foreach (char ch in argument) {
            if (ch == '\\') { slashes++; continue; }
            if (ch == '"') { value.Append('\\', slashes * 2 + 1); value.Append(ch); }
            else { value.Append('\\', slashes); value.Append(ch); }
            slashes = 0;
        }
        value.Append('\\', slashes * 2); value.Append('"');
        return value.ToString();
    }
    public static StartupCaptureSession Run(string python, string[] arguments, string workingDirectory,
        string stdoutPath, string stderrPath, int timeoutSeconds, IDictionary environment) {
        return Run(python,arguments,workingDirectory,stdoutPath,stderrPath,timeoutSeconds,environment,null);
    }
    public static StartupCaptureSession Run(string python, string[] arguments, string workingDirectory,
        string stdoutPath, string stderrPath, int timeoutSeconds, IDictionary environment,SafeFileHandle scratchLease) {
        if (timeoutSeconds < 1 || timeoutSeconds > 900) throw new ArgumentOutOfRangeException("timeoutSeconds");
        if (arguments == null || arguments.Length > 64) throw new ArgumentException("Capture argument count is invalid.");
        StartupCaptureSession session = new StartupCaptureSession();
        FileStream output = null, error = null;
        bool started = false;
        try {
            string executable = PlainPath(python);
            string directory = PlainPath(workingDirectory);
            string outPath = PlainPath(stdoutPath), errPath = PlainPath(stderrPath);
            if (String.Equals(outPath, errPath, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Capture output paths must differ.");
            session.RetainDirectory(Path.GetDirectoryName(outPath), true);
            session.RetainDirectory(Path.GetDirectoryName(errPath), true);
            output = CreateOutput(outPath); error = CreateOutput(errPath);
            ProcessStartInfo start = new ProcessStartInfo();
            start.FileName = executable; start.WorkingDirectory = directory;
            start.UseShellExecute = false; start.CreateNoWindow = true;
            start.WindowStyle = ProcessWindowStyle.Hidden;
            start.RedirectStandardOutput = true; start.RedirectStandardError = true;
            StringBuilder command = new StringBuilder();
            foreach (string argument in arguments) {
                if (command.Length != 0) command.Append(' ');
                command.Append(Quote(argument));
                if (command.Length > 30000) throw new ArgumentException("Capture arguments exceed their limit.");
            }
            start.Arguments = command.ToString();
            if (environment != null) {
                start.EnvironmentVariables.Clear();
                foreach (DictionaryEntry pair in environment) {
                    string key = pair.Key as string, value = pair.Value as string;
                    if (String.IsNullOrEmpty(key) || key.IndexOf('=') >= 0 || key.IndexOf('\0') >= 0 ||
                        value == null || value.IndexOf('\0') >= 0) throw new ArgumentException("Invalid capture environment.");
                    start.EnvironmentVariables[key] = value;
                }
            }
            session.Process = new Process(); session.Process.StartInfo = start;
            // The value is generated only from this retained read guard. An
            // ambient numeric environment value cannot create critical custody.
            start.EnvironmentVariables.Remove("ANGERONA_STARTUP_SCRATCH_LEASE_HANDLE");
            lock(scratchStartGuard) {
                using(SafeFileHandle inherited=DuplicateScratchLease(scratchLease)) {
                    if(inherited!=null) {
                        session.criticalOutputRemaining=CriticalOutputRemaining(outPath,errPath,inherited);
                        session.criticalOutputBound=true;
                        session.ScratchLeaseHandle=inherited.DangerousGetHandle().ToInt64().ToString(System.Globalization.CultureInfo.InvariantCulture);
                        start.EnvironmentVariables["ANGERONA_STARTUP_SCRATCH_LEASE_HANDLE"]=session.ScratchLeaseHandle;
                    }
                    if (!session.Process.Start()) throw new IOException("The startup assistant did not start.");
                } // No parent bridge remains; the actual child must retain it.
            }
            started = true;
            session.ProcessId = session.Process.Id;
            long created, exited, kernel, user;
            Check(GetProcessTimes(session.Process.Handle, out created, out exited, out kernel, out user));
            session.CreationTimeFileTime = created.ToString(System.Globalization.CultureInfo.InvariantCulture);
            session.CreationTimeUtc = DateTime.FromFileTimeUtc(created).ToString("o", System.Globalization.CultureInfo.InvariantCulture);
            session.remaining = 2;
            session.stdout = new Pump(session, (FileStream)session.Process.StandardOutput.BaseStream, output);
            session.stderr = new Pump(session, (FileStream)session.Process.StandardError.BaseStream, error);
            output = null; error = null;
            session.stdout.Start(); session.stderr.Start();
            Stopwatch clock = Stopwatch.StartNew();
            bool done = false;
            while (clock.ElapsedMilliseconds < timeoutSeconds * 1000L) {
                if (session.Process.WaitForExit(50)) { done = true; break; }
            }
            session.TimedOut = !done;
            session.ExitCode = done ? session.Process.ExitCode : 124;
            // No unbounded WaitForExit() or pipe join: a descendant may own a write end.
            long readerDeadline = Math.Min(timeoutSeconds * 1000L, clock.ElapsedMilliseconds + 1000);
            while (!session.ReadersComplete && clock.ElapsedMilliseconds < readerDeadline) Thread.Sleep(20);
            return session;
        } catch (Exception exception) {
            if (!started) {
                if (session.Process != null) session.Process.Dispose();
                if (output != null) output.Dispose();
                if (error != null) error.Dispose();
                session.ReleaseDirectories();
                throw;
            }
            // After Start, preserve the exact live process and custody rather than killing
            // an assistant that may have already created the real dashboard.
            session.ExitCode = 125;
            session.monitorError = exception.GetType().Name + ": assistant capture monitoring failed";
            if (output != null) output.Dispose();
            if (error != null) error.Dispose();
            return session;
        }
    }
}
}
'@
}

function ConvertTo-SourceStartupCaptureEnvironment([Collections.IDictionary]$Environment) {
    if ($null -eq $Environment) { return $null }
    $result = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $Environment.GetEnumerator()) {
        if ($null -eq $entry.Key) { throw [ArgumentException]::new('Invalid capture environment key.') }
        $key = $entry.Key.PSObject.BaseObject
        if ($key -isnot [string] -or !$key.Length -or $key.IndexOf('=') -ge 0 -or $key.IndexOf([char]0) -ge 0) {
            throw [ArgumentException]::new('Invalid capture environment key.')
        }
        $value = if ($null -ne $entry.Value) { $entry.Value.PSObject.BaseObject } else { $null }
        if ($value -isnot [string] -or $value.IndexOf([char]0) -ge 0) {
            # Environment values can contain credentials; never include them in
            # errors. Do not coerce arbitrary objects through their ToString().
            throw [ArgumentException]::new('Invalid capture environment string value.')
        }
        if ($result.ContainsKey($key)) { throw [ArgumentException]::new('Duplicate capture environment key.') }
        $result.Add([string]$key, [string]$value)
    }
    # Preserve a single typed dictionary through PowerShell pipeline wrapping.
    return ,$result
}

function Invoke-SourceStartupCapturedAssistant {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Python,
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Arguments,
        [Parameter(Mandatory=$true)][string]$WorkingDirectory,
        [Parameter(Mandatory=$true)][string]$StdoutPath,
        [Parameter(Mandatory=$true)][string]$StderrPath,
        [ValidateRange(1,900)][int]$TimeoutSeconds = 240,
        [Collections.IDictionary]$Environment,
        [IO.FileStream]$ScratchLease
    )
    # Command/function-produced strings can remain PSObject-wrapped inside an
    # IDictionary. Normalize only string bases, without inheriting ambient keys.
    $normalizedEnvironment = ConvertTo-SourceStartupCaptureEnvironment $Environment
    if (!$PSBoundParameters.ContainsKey('ScratchLease')) {
        $current = Get-Variable -Name SourceStartupScratchLease -Scope Script -ErrorAction SilentlyContinue
        if ($current) {
            if ($null -ne $current.Value -and $current.Value -isnot [IO.FileStream]) { throw 'Critical scratch lease must be an actual read-only file stream.' }
            $ScratchLease = $current.Value
        }
    }
    if ($ScratchLease) {
        if (!$ScratchLease.CanRead -or $ScratchLease.CanWrite -or !$ScratchLease.CanSeek -or $ScratchLease.Length -ne 0) {
            throw 'Critical scratch lease must remain a zero-byte read-only file stream.'
        }
        $acl = [IO.File]::GetAccessControl($ScratchLease.Name)
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        try { $sid = $identity.User.Value } finally { $identity.Dispose() }
        if ([IO.Path]::GetFileName($ScratchLease.Name) -cne 'startup-critical.lease' -or
            [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($ScratchLease.Name)) -cnotmatch '^startup-temp\.critical-(interface|control|preflight|recovery)$') {
            throw 'Critical scratch guard is outside its fixed workspace role.'
        }
        if (!$acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid) {
            throw 'Critical scratch guard lacks private current-user custody.'
        }
        foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -notin @($sid,'S-1-5-18','S-1-5-32-544')) {
                throw 'Critical scratch guard contains an unexpected principal.'
            }
        }
    }
    Initialize-SourceStartupCapture
    $capture = [Angerona.StartupCaptureSession]::Run($Python, $Arguments, $WorkingDirectory,
        $StdoutPath, $StderrPath, $TimeoutSeconds, $normalizedEnvironment,
        $(if ($ScratchLease) { $ScratchLease.SafeFileHandle } else { $null }))
    # Return one typed owner, never intermixed child stdout and an exit code.
    return $capture
}
