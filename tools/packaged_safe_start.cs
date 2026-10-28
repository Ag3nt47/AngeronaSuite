// Independent .NET Framework entry point. The signed MSIX covers this image;
// the release build replaces exactly one helper digest literal below.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32.SafeHandles;

namespace Angerona.SafeStart {
internal static class Native {
    [StructLayout(LayoutKind.Sequential)] internal struct Info {
        internal uint attrs,createdLow,createdHigh,accessLow,accessHigh,writeLow,writeHigh;
        internal uint volume,sizeHigh,sizeLow,links,indexHigh,indexLow;
    }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] internal struct Startup {
        internal int size; internal string reserved,desktop,title;
        internal uint x,y,width,height,charsX,charsY,fill,flags; internal ushort show,reservedSize;
        internal IntPtr reservedBytes,input,output,error;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct Child {
        internal IntPtr process,thread; internal uint pid,tid;
    }
    [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
    internal static extern IntPtr CreateFileW(string path,uint access,uint share,IntPtr security,uint create,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern bool GetFileInformationByHandle(IntPtr file,out Info info);
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] internal static extern uint GetDriveTypeW(string root);
    [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
    internal static extern bool CreateProcessW(string image,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,
        bool inherit,uint flags,IntPtr environment,string directory,ref Startup startup,out Child child);
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern bool GetProcessTimes(IntPtr process,out long creation,out long exit,out long kernel,out long user);
    [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)] internal static extern bool QueryFullProcessImageNameW(IntPtr process,uint flags,StringBuilder name,ref uint length);
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern uint WaitForSingleObject(IntPtr process,uint milliseconds);
    [DllImport("kernel32.dll",SetLastError=true)] internal static extern bool GetExitCodeProcess(IntPtr process,out uint code);
    internal static void Require(bool valid) { if(!valid)throw new Win32Exception(Marshal.GetLastWin32Error()); }
    internal static Info Information(IntPtr file,bool directory) {
        Info info;Require(GetFileInformationByHandle(file,out info));
        if((info.attrs&0x400)!=0 || (((info.attrs&0x10)!=0)!=directory) || (!directory && info.links!=1))
            throw new IOException("helper-path-not-plain: a linked or redirected package path was refused.");
        return info;
    }
    internal static bool Same(Info a,Info b) {
        return a.volume==b.volume && a.indexHigh==b.indexHigh && a.indexLow==b.indexLow &&
            a.sizeHigh==b.sizeHigh && a.sizeLow==b.sizeLow && a.writeHigh==b.writeHigh && a.writeLow==b.writeLow;
    }
}

internal sealed class BoundHelper : IDisposable {
    readonly List<IntPtr> directories=new List<IntPtr>();
    FileStream stream;Native.Info initial;
    internal readonly string PathName;
    internal BoundHelper(string root,string expected) {
        PathName=Path.Combine(Path.GetFullPath(root),"AngeronaStartup.exe");
        try {
            if(!System.Text.RegularExpressions.Regex.IsMatch(expected,"\\A[0-9a-f]{64}\\z"))
                throw new IOException("helper-pin-invalid: the release helper pin is unavailable.");
            if(PathName.StartsWith(@"\\",StringComparison.Ordinal) || Native.GetDriveTypeW(Path.GetPathRoot(PathName))!=3)
                throw new IOException("helper-volume-invalid: a fixed local package path is required.");
            string volume=Path.GetPathRoot(PathName),current=volume,parent=Path.GetDirectoryName(PathName);
            var ancestry=new List<string>();ancestry.Add(volume);
            foreach(string part in parent.Substring(volume.Length).Split(new[]{'\\'},StringSplitOptions.RemoveEmptyEntries)) {
                current=Path.Combine(current,part);ancestry.Add(current);
                if(ancestry.Count>64)throw new IOException("helper-path-too-deep: package ancestry exceeded its limit.");
            }
            foreach(string directory in ancestry) {
                IntPtr file=Native.CreateFileW(directory,0x80|1,1,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
                Native.Require(file!=new IntPtr(-1));directories.Add(file);Native.Information(file,true);
            }
            IntPtr image=Native.CreateFileW(PathName,0x80000000,1,IntPtr.Zero,3,0x00200000,IntPtr.Zero);
            Native.Require(image!=new IntPtr(-1));
            var safe=new SafeFileHandle(image,true);
            try {stream=new FileStream(safe,FileAccess.Read);}catch{safe.Dispose();throw;}
            initial=Native.Information(image,false);
            long length=((long)initial.sizeHigh<<32)|initial.sizeLow;
            if(length<1 || length>512L*1024*1024)throw new IOException("helper-size-invalid: the helper exceeds its verification limit.");
            string actual;
            using(var hash=SHA256.Create())actual=BitConverter.ToString(hash.ComputeHash(stream)).Replace("-","").ToLowerInvariant();
            AssertBound();
            if(actual!=expected)throw new IOException("helper-digest-mismatch: the installed startup helper differs from this release.");
        }catch{Dispose();throw;}
    }
    internal void AssertBound() {
        if(stream==null)throw new ObjectDisposedException("BoundHelper");
        Native.Info held=Native.Information(stream.SafeFileHandle.DangerousGetHandle(),false);
        IntPtr named=Native.CreateFileW(PathName,0x80000000,1,IntPtr.Zero,3,0x00200000,IntPtr.Zero);
        Native.Require(named!=new IntPtr(-1));
        try {if(!Native.Same(initial,held)||!Native.Same(initial,Native.Information(named,false)))
            throw new IOException("helper-generation-changed: helper identity changed during verification.");}
        finally{Native.CloseHandle(named);}
    }
    public void Dispose() {
        if(stream!=null){stream.Dispose();stream=null;}
        for(int i=directories.Count-1;i>=0;i--)Native.CloseHandle(directories[i]);directories.Clear();
    }
}

internal sealed class OwnedStartup : IDisposable {
    IntPtr process;
    internal readonly uint Pid;
    internal long CreationFileTime {get;private set;}
    internal string StartFailure {get;private set;}
    internal OwnedStartup(BoundHelper helper) {
        helper.AssertBound();
        var startup=new Native.Startup();startup.size=Marshal.SizeOf(typeof(Native.Startup));
        Native.Child child;
        Native.Require(Native.CreateProcessW(helper.PathName,new StringBuilder("\""+helper.PathName+"\""+(Program.AutomaticStart?" --automatic-start":"")),IntPtr.Zero,IntPtr.Zero,
            false,0x08000004,IntPtr.Zero,Path.GetDirectoryName(helper.PathName),ref startup,out child));
        process=child.process;Pid=child.pid;
        try {
            long birth,exit,kernel,user;Native.Require(Native.GetProcessTimes(process,out birth,out exit,out kernel,out user));
            CreationFileTime=birth;
            var image=new StringBuilder(32768);uint size=32768;
            Native.Require(Native.QueryFullProcessImageNameW(process,0,image,ref size));
            if(birth<=0 || !String.Equals(Path.GetFullPath(image.ToString()),helper.PathName,StringComparison.OrdinalIgnoreCase))
                throw new IOException("helper-process-mismatch: the created native process does not match the bound helper.");
            helper.AssertBound();
            Native.Require(Native.ResumeThread(child.thread)!=UInt32.MaxValue);
        }catch(Exception error) {
            // An owned but unverified generation remains suspended. Never kill
            // it or launch another engine over a process whose exit is unknown.
            StartFailure="helper-process-held: "+Program.Describe(error);
        }finally{Native.CloseHandle(child.thread);}
    }
    internal bool Exited {
        get {
            if(process==IntPtr.Zero)throw new ObjectDisposedException("OwnedStartup");
            uint result=Native.WaitForSingleObject(process,0);
            if(result==0)return true;if(result==258)return false;
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }
    internal uint ExitCode {
        get {if(!Exited)throw new InvalidOperationException("The retained startup generation is still active.");
            uint code;Native.Require(Native.GetExitCodeProcess(process,out code));return code;}
    }
    internal bool WaitExited(uint milliseconds) {
        uint result=Native.WaitForSingleObject(process,milliseconds);
        if(result==0)return true;if(result==258)return false;throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    public void Dispose() {if(process!=IntPtr.Zero){Native.CloseHandle(process);process=IntPtr.Zero;}}
}

internal enum StartupState { Running,Ready,Failed,TimedOut }
internal sealed class StartupAdmission {
    readonly object gate=new object();bool cancelled;
    internal void Cancel() {lock(gate){cancelled=true;}}
    internal OwnedStartup TryStart(BoundHelper helper) {
        // Close and process creation share one admission decision. Cancellation
        // never disposes or terminates a process that already passed this gate.
        lock(gate){return cancelled?null:new OwnedStartup(helper);}
    }
}
internal static class StartupDeadline {
    internal static StartupState Inspect(OwnedStartup child,TimeSpan elapsed) {
        if(child.Exited)return child.ExitCode==0 && child.StartFailure==null ? StartupState.Ready : StartupState.Failed;
        if(child.StartFailure!=null)return StartupState.Failed;
        return elapsed.TotalSeconds>=180 ? StartupState.TimedOut : StartupState.Running;
    }
}

internal sealed class RecoveryWindow : Form {
    readonly TextBox details=new TextBox();readonly Button retry=new Button();
    readonly System.Windows.Forms.Timer timer=new System.Windows.Forms.Timer();
    readonly string root;BoundHelper helper;OwnedStartup child;Stopwatch clock;
    StartupAdmission admission;
    bool preparing,closeRequested;internal int Result=1;
    internal RecoveryWindow(string directory) {
        root=directory;Text="Angerona Safe Startup";Size=new Size(760,420);MinimumSize=new Size(560,320);StartPosition=FormStartPosition.CenterScreen;
        details.Multiline=true;details.ReadOnly=true;details.ScrollBars=ScrollBars.Vertical;details.Dock=DockStyle.Fill;
        var controls=new FlowLayoutPanel();controls.Dock=DockStyle.Bottom;controls.Height=52;
        retry.Text="Retry verified startup";retry.Width=170;retry.Click+=delegate{BeginAttempt();};
        var close=new Button();close.Text="Close";close.Width=90;close.Click+=delegate{Close();};
        var releases=new LinkLabel();releases.Text="Official signed releases";releases.AutoSize=true;releases.Margin=new Padding(15,8,3,3);
        releases.LinkClicked+=delegate{try{Process.Start(new ProcessStartInfo("https://github.com/Ag3nt47/AngeronaSuite/releases"){UseShellExecute=true});}catch{ShowIssue("release-page-unavailable: open the official releases page in your browser.");}};
        controls.Controls.Add(retry);controls.Controls.Add(close);controls.Controls.Add(releases);Controls.Add(details);Controls.Add(controls);
        timer.Interval=500;timer.Tick+=delegate{Observe();};
        Shown+=delegate{BeginAttempt();};FormClosing+=ClosingSafely;
        ShowIssue("Startup has not reported readiness. The independent startup helper will be verified before execution.");
    }
    void ShowIssue(string message) {
        details.Text="Startup is not ready. Protection status is unknown.\r\n\r\n"+message+
            "\r\n\r\nPrivate startup logs, if created: "+Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Angerona","Startup","logs")+"\r\n\r\n"+
            "Repair or reinstall through the signed MSIX/release authority. This window never downloads replacement package code.";
    }
    void BeginAttempt() {
        if(preparing)return;
        try{if(child!=null&&!child.Exited){retry.Enabled=false;return;}}catch(Exception error){retry.Enabled=false;ShowIssue(Program.Describe(error));return;}
        ReleaseExited();preparing=true;retry.Enabled=false;
        var attempt=new StartupAdmission();admission=attempt;
        ShowIssue("Verifying the fixed startup helper from this installed release...");
        ThreadPool.QueueUserWorkItem(delegate {
            BoundHelper bound=null;OwnedStartup owned=null;string error=null;
            try{
                bound=new BoundHelper(root,Program.HelperSha256);owned=attempt.TryStart(bound);
                if(owned==null){bound.Dispose();bound=null;error="startup-cancelled: Close cancelled an attempt before any helper was started.";}
            }catch(Exception issue){error=Program.Describe(issue);if(bound!=null){bound.Dispose();bound=null;}}
            BeginInvoke((MethodInvoker)delegate {
                preparing=false;helper=bound;child=owned;clock=Stopwatch.StartNew();
                if(error!=null){ShowIssue(error);retry.Enabled=true;if(closeRequested)Close();return;}
                timer.Start();Observe();
            });
        });
    }
    void Observe() {
        if(child==null)return;
        try {
            StartupState state=StartupDeadline.Inspect(child,clock.Elapsed);
            if(state==StartupState.Ready){Result=0;ReleaseExited();Close();return;}
            if(state==StartupState.Running){retry.Enabled=false;ShowIssue("The verified helper is checking runtime and dashboard readiness.\r\nOwned helper PID: "+child.Pid+"; native creation time: "+child.CreationFileTime+".\r\nRetry remains unavailable while this exact helper generation is active.");return;}
            if(state==StartupState.TimedOut){ShowIssue("helper-timeout: the 180-second readiness deadline elapsed. The helper and any core remain running.\r\nRetry stays disabled until the retained helper handle proves exit; closing this window preserves that work.");retry.Enabled=false;return;}
            bool exited=child.Exited;
            ShowIssue(child.StartFailure??("helper-exit-"+child.ExitCode+": startup did not report a ready dashboard."));
            retry.Enabled=exited;
            if(exited){ReleaseExited();if(closeRequested)Close();}
        }catch(Exception error){retry.Enabled=false;ShowIssue("helper-state-unknown: "+Program.Describe(error));}
    }
    void ReleaseExited() {
        if(child!=null){if(!child.Exited)return;child.Dispose();child=null;}
        if(helper!=null){helper.Dispose();helper=null;}timer.Stop();
    }
    void ClosingSafely(object sender,FormClosingEventArgs args) {
        if(preparing&&admission!=null)admission.Cancel();
        bool active=preparing;
        try{active=active||(child!=null&&!child.Exited);}catch{active=true;}
        if(active){args.Cancel=true;closeRequested=true;Hide();return;}
        ReleaseExited();timer.Dispose();
    }
}

internal static class Program {
    internal const string HelperSha256="__STARTUP_SHA256__";
    internal static bool AutomaticStart;
    internal static string Describe(Exception error) {
        var native=error as Win32Exception;
        if(native!=null)return "windows-error-"+native.NativeErrorCode+": the installed startup component could not be verified or started.";
        return error.Message.Length>1024?error.Message.Substring(0,1024):error.Message;
    }
    [STAThread] internal static int Main(string[] arguments) {
        string root=Path.GetDirectoryName(Application.ExecutablePath);
        if(arguments.Length==1 && arguments[0]=="--automatic-start") {
            AutomaticStart=true;
        } else if(arguments.Length!=0) {
            if(arguments.Length!=1||arguments[0]!="--verify-bootstrap")return 2;
            try{using(var helper=new BoundHelper(root,HelperSha256)){Console.WriteLine("Pinned startup helper verified; no application was launched.");return 0;}}
            catch(Exception error){Console.Error.WriteLine(Describe(error));return 1;}
        }
        Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
        using(var window=new RecoveryWindow(root)){Application.Run(window);return window.Result;}
    }
}
}
