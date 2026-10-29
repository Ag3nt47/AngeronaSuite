<# Independent Windows startup/recovery UI. No application imports, repair or launch authority. #>
[CmdletBinding()]
param(
    [string]$StatusFile,
    [string]$LogRoot,
    [string]$Message,
    [switch]$Headless,
    [switch]$StartupShell,
    [string]$StartupRunId,
    [int]$SupervisorPid,
    [long]$SupervisorCreationFileTime,
    [string]$PaintReceiptFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$fixedRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$localRuntime = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Angerona'
$ownedScratch = Join-Path $fixedRoot '.tmp'
$statusLimit = 64KB
$logLimit = 128KB

function Protect-RecoveryText([object]$TextValue, [int]$Limit = 4096) {
    if ($TextValue -isnot [string]) { return '' }
    $text = $TextValue.Substring(0, [Math]::Min($Limit, $TextValue.Length))
    $text = [regex]::Replace($text, '[\x00-\x08\x0b\x0c\x0e-\x1f]', '')
    return [regex]::Replace($text,
        '(?i)(?:\bBearer\s+[A-Za-z0-9._~+/-]+=*|\bsk-[A-Za-z0-9_-]{8,}|\b(?:api[_-]?key|password|secret|access[_-]?token)\s*[:=]\s*[^\s,;]+)',
        '[redacted]')
}

function Write-StartupShellDiagnostic([string]$Phase, [object]$Failure, [bool]$Painted) {
    # Advisory stderr only. Do not depend on JSON command/module loading while
    # explaining a failed reader/compiler/receipt step, or change the UI hold.
    try {
        $exception = $Failure.Exception.GetBaseException()
        $values = @((Protect-RecoveryText $Phase 64),
            $(if ($StartupRunId -cmatch '^[a-f0-9]{32}$') { $StartupRunId } else { '' }),
            (Protect-RecoveryText $exception.GetType().FullName 256),
            (Protect-RecoveryText $exception.Message 2048))
        $escaped = foreach ($value in $values) {
            $builder = [Text.StringBuilder]::new()
            foreach ($character in $value.ToCharArray()) {
                $number = [int]$character
                if ($number -eq 34) { [void]$builder.Append('\"') }
                elseif ($number -eq 92) { [void]$builder.Append('\\') }
                elseif ($number -lt 32 -or $number -gt 126) {
                    # ASCII JSON is valid UTF-8 even on an OEM-encoded Windows
                    # stderr stream. Preserve Unicode as complete JSON escapes.
                    [void]$builder.Append('\u')
                    [void]$builder.Append($number.ToString('x4', [Globalization.CultureInfo]::InvariantCulture))
                } else { [void]$builder.Append($character) }
            }
            $builder.ToString()
        }
        $birth = '0'; $self = $null
        try {
            $self = [Diagnostics.Process]::GetCurrentProcess()
            $birth = [string]$self.StartTime.ToUniversalTime().ToFileTimeUtc()
        } catch { } finally { if ($self) { $self.Dispose() } }
        $line = '{"schema":1,"component":"startup-recovery-ui","phase":"' + $escaped[0] +
            '","outcome":"held","utc":"' + [DateTime]::UtcNow.ToString('o') +
            '","run_id":"' + $escaped[1] + '","shell_pid":' + $PID +
            ',"shell_creation_filetime":"' + $birth + '","supervisor_pid":' + $SupervisorPid +
            ',"supervisor_creation_filetime":"' + [string]$SupervisorCreationFileTime +
            '","painted":' + $Painted.ToString().ToLowerInvariant() +
            ',"exception_type":"' + $escaped[2] + '","message":"' + $escaped[3] + '"}'
        $recordBytes = [Text.Encoding]::UTF8.GetByteCount($line) +
            [Text.Encoding]::UTF8.GetByteCount([Console]::Error.NewLine)
        if ($recordBytes -le 8192) {
            [Console]::Error.WriteLine($line)
        } else {
            [Console]::Error.WriteLine('{"schema":1,"component":"startup-recovery-ui","outcome":"held","diagnostic_omitted":true,"reason":"frame-capacity"}')
        }
    } catch { } # Diagnostics cannot replace the original held state or grant a receipt.
}

function Get-RecoveryCandidatePath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -notmatch '^[A-Za-z]:[\\/]' -or
        $Path.Substring(2).Contains(':') -or
        $Path.StartsWith('\\') -or $Path.StartsWith('//') -or
        @($Path -split '[\\/]' | Where-Object { $_ -eq '..' }).Count -gt 0) {
        throw 'Only an absolute local diagnostic path is accepted.'
    }
    $full = [IO.Path]::GetFullPath($Path)
    $allowed = $false
    foreach ($scope in @($localRuntime, $ownedScratch)) {
        $prefix = $scope.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
        if ($full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { $allowed = $true }
    }
    if (!$allowed) { throw 'Diagnostic path is outside the known startup directories.' }
    return $full
}

function Assert-RecoveryPath([string]$Path) {
    $full = Get-RecoveryCandidatePath $Path
    $cursor = $full
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Redirected diagnostic paths are unavailable.'
            }
        }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
    return $full
}

function Initialize-RecoveryReader {
    if ('AngeronaRecoveryReadV1' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
public static class AngeronaRecoveryReadV1 {
    [StructLayout(LayoutKind.Sequential)]
    private struct Info {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Creation;
        public System.Runtime.InteropServices.ComTypes.FILETIME Access;
        public System.Runtime.InteropServices.ComTypes.FILETIME Write;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern SafeFileHandle CreateFile(string name, uint access, uint share,
        IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle file, out Info info);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool GetProcessTimes(IntPtr process,
        out System.Runtime.InteropServices.ComTypes.FILETIME created,
        out System.Runtime.InteropServices.ComTypes.FILETIME exited,
        out System.Runtime.InteropServices.ComTypes.FILETIME kernel,
        out System.Runtime.InteropServices.ComTypes.FILETIME user);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool CloseHandle(IntPtr handle);
    private static Info Inspect(SafeFileHandle file) {
        Info value;
        if (file.IsInvalid || !GetFileInformationByHandle(file, out value))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        if ((value.Attributes & (0x10u | 0x400u)) != 0 || value.Links != 1)
            throw new IOException("Diagnostic must be a plain, single-link regular file.");
        return value;
    }
    private static bool Same(Info left, Info right) {
        return left.Volume == right.Volume && left.IndexHigh == right.IndexHigh &&
            left.IndexLow == right.IndexLow && left.SizeHigh == right.SizeHigh &&
            left.SizeLow == right.SizeLow && left.Write.dwHighDateTime == right.Write.dwHighDateTime &&
            left.Write.dwLowDateTime == right.Write.dwLowDateTime;
    }
    public static void Validate(string name) {
        using (SafeFileHandle held = CreateFile(name, 0x80u, 1, IntPtr.Zero, 3, 0x00200000u, IntPtr.Zero)) {
            Inspect(held);
        }
    }
    public static Task<string> BeginRead(string name, int limit) {
        return Task.Factory.StartNew(() => Read(name, limit, true));
    }
    private static void AssertScopedPath(string name, string first, string second) {
        if (String.IsNullOrWhiteSpace(name) || name.Length < 3 || name[1] != ':' ||
            (name[2] != '\\' && name[2] != '/') || name.IndexOf(':', 2) >= 0)
            throw new IOException("Only an absolute local diagnostic path is accepted.");
        foreach (string part in name.Split(new char[] {'\\', '/'}))
            if (part == "..") throw new IOException("Parent traversal is unavailable.");
        string full = Path.GetFullPath(name);
        bool allowed = false;
        foreach (string root in new string[] { first, second }) {
            string prefix = Path.GetFullPath(root).TrimEnd('\\', '/') + Path.DirectorySeparatorChar;
            if (full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) allowed = true;
        }
        if (!allowed) throw new IOException("Diagnostic path is outside the known startup directories.");
        for (string cursor = full; !String.IsNullOrEmpty(cursor); cursor = Path.GetDirectoryName(cursor)) {
            try {
                if ((File.GetAttributes(cursor) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Redirected diagnostic paths are unavailable.");
            } catch (FileNotFoundException) { } catch (DirectoryNotFoundException) { }
        }
    }
    public static Task<string> BeginReadScoped(string name, int limit, bool tail, string first, string second) {
        return Task.Factory.StartNew(() => {
            AssertScopedPath(name, first, second);
            string value = Read(name, limit, tail);
            AssertScopedPath(name, first, second);
            return value;
        });
    }
    public static long ProcessCreationFileTime(int pid) {
        IntPtr process = OpenProcess(0x101000u, false, pid);
        if (process == IntPtr.Zero) return 0;
        try {
            System.Runtime.InteropServices.ComTypes.FILETIME created, exited, kernel, user;
            if (WaitForSingleObject(process, 0) != 258u ||
                !GetProcessTimes(process, out created, out exited, out kernel, out user)) return 0;
            return (long)(((ulong)(uint)created.dwHighDateTime << 32) | (uint)created.dwLowDateTime);
        } finally { CloseHandle(process); }
    }
    public static void WritePaintReceipt(string name, string content, string first, string second) {
        AssertScopedPath(name, first, second);
        if (!String.Equals(Path.GetFileName(name), "startup-shell-painted.json", StringComparison.Ordinal))
            throw new IOException("Unexpected startup paint receipt name.");
        byte[] bytes = new UTF8Encoding(false).GetBytes(content);
        if (bytes.Length > 1024) throw new IOException("Startup paint receipt exceeds its bound.");
        using (SafeFileHandle held = CreateFile(name, 0x40000080u, 1, IntPtr.Zero, 3, 0x00200000u, IntPtr.Zero)) {
            Info before = Inspect(held);
            if (before.SizeHigh != 0 || before.SizeLow > 1024)
                throw new IOException("Startup paint receipt exceeds its bound.");
            using (FileStream stream = new FileStream(held, FileAccess.Write, 1024, false)) {
                stream.SetLength(0); stream.Write(bytes, 0, bytes.Length); stream.Flush(true);
                using (SafeFileHandle named = CreateFile(name, 0x80u, 3, IntPtr.Zero, 3, 0x00200000u, IntPtr.Zero)) {
                    Info after = Inspect(named);
                    if (before.Volume != after.Volume || before.IndexHigh != after.IndexHigh ||
                        before.IndexLow != after.IndexLow) throw new IOException("Startup receipt identity changed.");
                }
            }
        }
        AssertScopedPath(name, first, second);
    }
    public static string Read(string name, int limit, bool tail) {
        using (SafeFileHandle held = CreateFile(name, 0x80000000u, 1, IntPtr.Zero, 3, 0x00200000u, IntPtr.Zero)) {
            Info before = Inspect(held);
            long size = ((long)before.SizeHigh << 32) | before.SizeLow;
            if (!tail && size > limit) throw new IOException("Startup report exceeds its size limit.");
            bool omitted = tail && size > limit;
            using (FileStream stream = new FileStream(held, FileAccess.Read, 4096, false)) {
                if (omitted) stream.Seek(size - limit, SeekOrigin.Begin);
                byte[] bytes = new byte[limit + 1];
                int count = 0, next;
                while (count < bytes.Length && (next = stream.Read(bytes, count, bytes.Length - count)) > 0) count += next;
                if (count > limit) throw new IOException("Diagnostic exceeded its read limit.");
                using (SafeFileHandle named = CreateFile(name, 0x80u, 1, IntPtr.Zero, 3, 0x00200000u, IntPtr.Zero)) {
                    if (!Same(before, Inspect(named)) || !Same(before, Inspect(held)))
                        throw new IOException("Diagnostic identity changed during reading.");
                }
                string content = new UTF8Encoding(false, false).GetString(bytes, 0, count).TrimStart('\uFEFF');
                return (omitted ? "[Earlier diagnostic text omitted by the 128 KiB view limit.]\r\n" : "") + content;
            }
        }
    }
}
'@
}

function Read-RecoveryText([string]$Path, [int]$Limit, [bool]$Tail = $false) {
    $plain = Assert-RecoveryPath $Path
    Initialize-RecoveryReader
    $result = [AngeronaRecoveryReadV1]::Read($plain, $Limit, $Tail)
    [void](Assert-RecoveryPath $plain)
    return $result
}

function Get-RecoveryModel {
    param([string]$RawText, [switch]$FromMemory, [switch]$DeferLogValidation)
    $model = [ordered]@{
        schema = 1; phase = 'startup diagnostics'; outcome = 'report-unavailable'
        message = 'The startup report is unavailable. Retry safe recovery or inspect the launcher output.'
        protection_status = 'unknown'; log_path = ''; log_state = 'No diagnostic log was selected.'
        attempts = @(); report_valid = $false; omitted_attempts = 0
        run_id = ''; supervisor_pid = 0; supervisor_creation_filetime = ''
    }
    if ($Message) { $model.message = Protect-RecoveryText $Message }
    try {
        $statusPath = if ($FromMemory) { Get-RecoveryCandidatePath $StatusFile } else { Assert-RecoveryPath $StatusFile }
        if ([IO.Path]::GetExtension($statusPath) -ne '.json') { throw 'Expected a JSON startup report.' }
        $raw = if ($FromMemory) { $RawText } else { Read-RecoveryText $statusPath $statusLimit }
        $document = ConvertFrom-Json -InputObject $raw
        if (($document.schema -isnot [int] -and $document.schema -isnot [long]) -or
            $document.schema -ne 1) { throw 'Unrecognized startup report.' }
        $model.phase = Protect-RecoveryText $document.phase 256
        $model.outcome = Protect-RecoveryText $document.outcome 128
        if (!$Message) { $model.message = Protect-RecoveryText $document.message }
        $model.report_valid = $true
        $properties = @($document.PSObject.Properties.Name)
        if ($properties -contains 'run_id') { $model.run_id = Protect-RecoveryText $document.run_id 64 }
        if (($properties -contains 'supervisor_pid') -and
            ($document.supervisor_pid -is [int] -or $document.supervisor_pid -is [long])) {
            $model.supervisor_pid = $document.supervisor_pid
        }
        if ($properties -contains 'supervisor_creation_filetime') {
            $birth = [string]$document.supervisor_creation_filetime
            $parsedBirth = 0L
            if ($birth -match '^[0-9]{1,19}$' -and [long]::TryParse($birth, [ref]$parsedBirth) -and $parsedBirth -gt 0) {
                $model.supervisor_creation_filetime = [string]$parsedBirth
            }
        }
        if ($properties -contains 'attempts') {
            $attempts = @($document.attempts)
            $model.omitted_attempts = [Math]::Max(0, $attempts.Count - 32)
            foreach ($attempt in @($attempts | Select-Object -First 32)) {
                $row = [ordered]@{ strategy = ''; outcome = ''; exit_code = $null; detail = '' }
                $row.strategy = Protect-RecoveryText $attempt.strategy 256
                $row.outcome = Protect-RecoveryText $attempt.outcome 128
                $row.detail = Protect-RecoveryText $attempt.detail 1024
                if ($attempt.exit_code -is [int] -or $attempt.exit_code -is [long]) { $row.exit_code = $attempt.exit_code }
                $model.attempts += [pscustomobject]$row
            }
        }
        if (($properties -contains 'log_path') -and $document.log_path) {
            try {
                $selectedRoot = [IO.Path]::GetDirectoryName($statusPath)
                if ($LogRoot) {
                    $selectedRoot = if ($DeferLogValidation) { Get-RecoveryCandidatePath $LogRoot } else { Assert-RecoveryPath $LogRoot }
                }
                $log = if ($DeferLogValidation) { Get-RecoveryCandidatePath ([string]$document.log_path) } else { Assert-RecoveryPath ([string]$document.log_path) }
                $prefix = $selectedRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
                if (!$log.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
                    [IO.Path]::GetExtension($log).ToLowerInvariant() -notin @('.log', '.txt', '.jsonl', '.json')) {
                    throw 'Log is outside the selected diagnostic directory.'
                }
                $model.log_path = $log
                $model.log_state = 'Diagnostic text can be viewed here without executing it.'
                if (!$DeferLogValidation) {
                    if (!(Test-Path -LiteralPath $log -PathType Leaf)) { $model.log_state = 'The diagnostic log is missing; no file will be executed.' }
                    else { [AngeronaRecoveryReadV1]::Validate($log) }
                }
            } catch {
                $model.log_path = ''
                $model.log_state = 'The diagnostic log is missing, changed, unsafe or outside the selected directory.'
            }
        }
    } catch {
        $model.report_valid = $false
        $model.outcome = 'report-unavailable'
        if (!$Message) { $model.message = 'The startup report is missing, malformed, changed or unsafe. Its contents were not executed.' }
    }
    return [pscustomobject]$model
}

function Format-RecoveryModel($Model) {
    $rows = @("Phase: $($Model.phase)", "Outcome: $($Model.outcome)", '', $Model.message, '',
        'Protection is not verified by this recovery interface.',
        'This window does not start sensors, approve trust or change response policy.', '')
    $number = 0
    foreach ($attempt in $Model.attempts) {
        $number++
        $rows += "$number. $($attempt.strategy) - $($attempt.outcome) (exit $($attempt.exit_code))"
        if ($attempt.detail) { $rows += $attempt.detail }
    }
    if ($Model.omitted_attempts) { $rows += "$($Model.omitted_attempts) attempt rows omitted by the display limit." }
    $rows += @('', $Model.log_state)
    if ($Model.log_path) { $rows += $Model.log_path }
    return $rows -join [Environment]::NewLine
}

function Get-StartupDashboardState($Model) {
    # Status text is data. Only this fixed protocol can dismiss the shell; the
    # supervisor alone verifies the actual dashboard's readiness receipt.
    $state = [ordered]@{ state = 'waiting'; can_retry = $false; close_code = 1223
        dashboard_ready = $false; title = 'Waiting for startup verification'
        message = 'Waiting for a current startup report. Protection is unavailable.' }
    if (!$Model.report_valid -or $Model.run_id -cne $StartupRunId -or
        $Model.supervisor_pid -ne $SupervisorPid -or
        $Model.supervisor_creation_filetime -cne [string]$SupervisorCreationFileTime) {
        return [pscustomobject]$state
    }
    $state.message = $Model.message
    if ($Model.phase -ceq 'dashboard' -and $Model.outcome -ceq 'verified') {
        $state.state = 'ready'; $state.title = 'Dashboard readiness verified'
        $state.dashboard_ready = $true; $state.close_code = 0
    } elseif ($Model.outcome -cin @('operator-stopped', 'closed')) {
        $state.state = 'stopped'; $state.title = 'Startup stopped'; $state.close_code = 0
    } elseif ($Model.outcome -ceq 'custody-held') {
        $state.state = 'held'; $state.title = 'Process retirement requires review'
        $state.close_code = 0
    } elseif (($Model.phase -ceq 'preflight' -and $Model.outcome -ceq 'verified') -or
        $Model.outcome -cin @('needs-attention', 'needs-recovery', 'held', 'not-ready', 'failed')) {
        $state.state = 'held'; $state.title = 'Startup needs attention'
        $state.can_retry = $true; $state.close_code = 0
        if ($Model.phase -ceq 'preflight' -and $Model.outcome -ceq 'verified') {
            $state.message = 'Setup checks passed. A real dashboard has not been launched or verified.'
        }
    } elseif ($Model.outcome -cin @('checking', 'started', 'repairing', 'retrying')) {
        $state.state = 'checking'; $state.title = 'Checking and recovering startup'
    }
    return [pscustomobject]$state
}

function New-StartupStatusCard([string]$Caption) {
    $panel = [Windows.Forms.Panel]::new()
    $panel.Dock = 'Fill'; $panel.Margin = [Windows.Forms.Padding]::new(0, 0, 10, 0)
    $panel.BackColor = [Drawing.ColorTranslator]::FromHtml('#151f2c')
    $label = [Windows.Forms.Label]::new()
    $label.Text = $Caption; $label.Dock = 'Top'; $label.Height = 34
    $label.Padding = [Windows.Forms.Padding]::new(12, 10, 8, 0)
    $label.ForeColor = [Drawing.ColorTranslator]::FromHtml('#9eb3cb')
    $value = [Windows.Forms.Label]::new()
    $value.Text = 'Pending'; $value.Dock = 'Fill'; $value.Padding = [Windows.Forms.Padding]::new(12, 5, 8, 8)
    $value.Font = [Drawing.Font]::new('Segoe UI', 15, [Drawing.FontStyle]::Bold)
    $panel.Controls.Add($value); $panel.Controls.Add($label)
    return [pscustomobject]@{ Panel = $panel; Value = $value }
}

function Show-StartupDashboard {
    if ($StartupRunId -cnotmatch '^[a-f0-9]{32}$' -or $SupervisorPid -le 0 -or
        $SupervisorCreationFileTime -le 0 -or [string]::IsNullOrWhiteSpace($PaintReceiptFile)) {
        throw 'The startup dashboard requires a current supervisor identity and first-paint receipt.'
    }
    # Only OS UI assemblies are loaded before first paint. In particular, no
    # report, dependency, application source or recovery log is read here.
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form = [Windows.Forms.Form]::new()
    $form.Name = 'AngeronaStartupDashboard'; $form.Text = 'Angerona 1.14.1 - Safe Startup'
    $form.StartPosition = 'CenterScreen'; $form.MinimumSize = [Drawing.Size]::new(640, 500)
    $working = [Windows.Forms.Screen]::FromPoint([Windows.Forms.Cursor]::Position).WorkingArea
    $form.Size = [Drawing.Size]::new([Math]::Min(980, $working.Width - 32), [Math]::Min(730, $working.Height - 48))
    $form.BackColor = [Drawing.ColorTranslator]::FromHtml('#0b121c')
    $form.ForeColor = [Drawing.ColorTranslator]::FromHtml('#e7eef7')
    $form.Font = [Drawing.Font]::new('Segoe UI', 10)
    $form.Padding = [Windows.Forms.Padding]::new(18)
    $state = @{ ExitCode = 1223; State = 'waiting'; Painted = $false; Model = $null
        PollTask = $null; LogTask = $null; PollStarted = [DateTime]::MinValue; Closing = $false }
    $form.Tag = $state
    $layout = [Windows.Forms.TableLayoutPanel]::new()
    $layout.Dock = 'Fill'; $layout.ColumnCount = 1; $layout.RowCount = 6
    foreach ($height in @(65, 74, 104, 78)) {
        [void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new([Windows.Forms.SizeType]::Absolute, $height))
    }
    [void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new([Windows.Forms.SizeType]::Percent, 100))
    [void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new([Windows.Forms.SizeType]::Absolute, 82))
    $form.Controls.Add($layout)
    $brand = [Windows.Forms.Label]::new()
    $brand.Text = "ANGERONA  1.14.1`r`nSafe Startup dashboard"
    $brand.Dock = 'Fill'; $brand.Font = [Drawing.Font]::new('Segoe UI', 17, [Drawing.FontStyle]::Bold)
    $brand.ForeColor = [Drawing.ColorTranslator]::FromHtml('#28a4ff')
    $layout.Controls.Add($brand, 0, 0)
    $warning = [Windows.Forms.Label]::new()
    $warning.Text = "VERIFICATION PENDING - PROTECTION UNAVAILABLE`r`nThis startup interface runs no sensors and grants no trust or response authority."
    $warning.Dock = 'Fill'; $warning.Padding = [Windows.Forms.Padding]::new(10)
    $warning.BackColor = [Drawing.ColorTranslator]::FromHtml('#332918')
    $warning.ForeColor = [Drawing.ColorTranslator]::FromHtml('#ffd68a')
    $layout.Controls.Add($warning, 0, 1)
    $cards = [Windows.Forms.TableLayoutPanel]::new()
    $cards.Dock = 'Fill'; $cards.ColumnCount = 3; $cards.RowCount = 1
    for ($i = 0; $i -lt 3; $i++) {
        [void]$cards.ColumnStyles.Add([Windows.Forms.ColumnStyle]::new([Windows.Forms.SizeType]::Percent, 33.333))
    }
    $verification = New-StartupStatusCard 'VERIFICATION'
    $runtime = New-StartupStatusCard 'RUNTIME'
    $dashboard = New-StartupStatusCard 'DASHBOARD'
    $runtime.Value.Text = 'Not verified'; $dashboard.Value.Text = 'Not ready'
    $cards.Controls.Add($verification.Panel, 0, 0)
    $cards.Controls.Add($runtime.Panel, 1, 0); $cards.Controls.Add($dashboard.Panel, 2, 0)
    $layout.Controls.Add($cards, 0, 2)
    $progressPanel = [Windows.Forms.Panel]::new(); $progressPanel.Dock = 'Fill'
    $stage = [Windows.Forms.Label]::new(); $stage.Dock = 'Top'; $stage.Height = 50
    $stage.Text = "Opening independent startup dashboard...`r`nVerified checks and safe repairs will follow."
    $bar = [Windows.Forms.ProgressBar]::new(); $bar.Dock = 'Bottom'; $bar.Height = 8
    $bar.Style = 'Marquee'; $bar.MarqueeAnimationSpeed = 35
    $progressPanel.Controls.Add($bar); $progressPanel.Controls.Add($stage)
    $layout.Controls.Add($progressPanel, 0, 3)
    $view = [Windows.Forms.TextBox]::new(); $view.Name = 'StartupDetails'
    $view.Multiline = $true; $view.ReadOnly = $true; $view.ScrollBars = 'Vertical'; $view.WordWrap = $true
    $view.Dock = 'Fill'; $view.BackColor = $form.BackColor; $view.ForeColor = $form.ForeColor
    $view.Text = 'Startup diagnostics will appear here. No application code is loaded by this interface.'
    $layout.Controls.Add($view, 0, 4)
    $footer = [Windows.Forms.Panel]::new(); $footer.Dock = 'Fill'
    $hint = [Windows.Forms.Label]::new(); $hint.Dock = 'Top'; $hint.Height = 35
    $hint.Text = 'Close cancels further attempts. A current bounded check may finish before the supervisor stops.'
    $footer.Controls.Add($hint)
    $retry = [Windows.Forms.Button]::new(); $retry.Name = 'StartupRetry'
    $retry.Text = 'Retry safe startup'; $retry.SetBounds(0, 40, 155, 32); $retry.Enabled = $false
    $retry.Add_Click({ if ($retry.Enabled) { $state.ExitCode = 10; $form.Close() } })
    $footer.Controls.Add($retry)
    $detailsToggle = [Windows.Forms.Button]::new()
    $detailsToggle.Text = 'Hide details'; $detailsToggle.SetBounds(165, 40, 115, 32)
    $detailsToggle.Add_Click({
        $view.Visible = !$view.Visible
        $layout.RowStyles[4].SizeType = if ($view.Visible) { 'Percent' } else { 'Absolute' }
        $layout.RowStyles[4].Height = if ($view.Visible) { 100 } else { 0 }
        $detailsToggle.Text = if ($view.Visible) { 'Hide details' } else { 'Show details' }
    })
    $footer.Controls.Add($detailsToggle)
    $logButton = [Windows.Forms.Button]::new()
    $logButton.Text = 'Diagnostic log'; $logButton.SetBounds(290, 40, 130, 32); $logButton.Enabled = $false
    $footer.Controls.Add($logButton)
    $close = [Windows.Forms.Button]::new(); $close.Name = 'StartupClose'
    $close.Text = 'Close'; $close.SetBounds(430, 40, 110, 32)
    $close.Add_Click({ $form.Close() }); $footer.Controls.Add($close); $form.CancelButton = $close
    $footer.Add_Resize({ $close.Left = [Math]::Max(430, $footer.ClientSize.Width - $close.Width) })
    $layout.Controls.Add($footer, 0, 5)
    $pollTimer = [Windows.Forms.Timer]::new(); $pollTimer.Interval = 200
    $logTimer = [Windows.Forms.Timer]::new(); $logTimer.Interval = 100
    $logButton.Add_Click({
        if ($null -ne $state.LogTask -or $null -eq $state.Model -or !$state.Model.log_path) { return }
        $logButton.Enabled = $false
        $state.LogTask = [AngeronaRecoveryReadV1]::BeginReadScoped($state.Model.log_path, $logLimit, $true, $localRuntime, $ownedScratch)
        $logTimer.Start()
    })
    $logTimer.Add_Tick({
        if ($null -eq $state.LogTask -or !$state.LogTask.IsCompleted) { return }
        $logTimer.Stop()
        try { $textValue = Protect-RecoveryText $state.LogTask.Result $logLimit }
        catch { $textValue = 'Diagnostic text is missing, changed or unavailable. No file was executed.' }
        $state.LogTask = $null
        $dialog = [Windows.Forms.Form]::new()
        $dialog.Text = 'Angerona diagnostic text - read only'; $dialog.Size = [Drawing.Size]::new(820, 540)
        $textView = [Windows.Forms.TextBox]::new()
        $textView.Multiline = $true; $textView.ReadOnly = $true; $textView.ScrollBars = 'Vertical'
        $textView.WordWrap = $true; $textView.Dock = 'Fill'; $textView.Text = $textValue
        $dialog.Controls.Add($textView); [void]$dialog.ShowDialog($form); $dialog.Dispose()
        if (!$state.Closing) { $logButton.Enabled = $true }
    })
    $pollTimer.Add_Tick({
        if ($state.Closing) { return }
        if ([AngeronaRecoveryReadV1]::ProcessCreationFileTime($SupervisorPid) -ne $SupervisorCreationFileTime) {
            $pollTimer.Stop(); $state.State = 'held'; $state.ExitCode = 0; $retry.Enabled = $false
            $verification.Value.Text = 'Held'; $runtime.Value.Text = 'Unavailable'; $bar.Style = 'Continuous'
            $stage.Text = 'The startup supervisor is unavailable. Close this window and run Safe Startup again.'
            $hint.Text = 'No further launch or repair is authorized by this interface.'
            return
        }
        if ($null -eq $state.PollTask) {
            $state.PollStarted = [DateTime]::UtcNow
            $state.PollTask = [AngeronaRecoveryReadV1]::BeginReadScoped($StatusFile, $statusLimit, $false, $localRuntime, $ownedScratch)
            return
        }
        if (!$state.PollTask.IsCompleted) {
            if (([DateTime]::UtcNow - $state.PollStarted).TotalSeconds -gt 3) {
                $stage.Text = 'The diagnostic read is delayed. Protection remains unavailable; Close is still available.'
            }
            return
        }
        try { $model = Get-RecoveryModel -RawText $state.PollTask.Result -FromMemory -DeferLogValidation }
        catch { $model = [pscustomobject]@{ report_valid = $false } }
        finally { $state.PollTask = $null }
        $mapped = Get-StartupDashboardState $model
        $state.State = $mapped.state; $state.ExitCode = $mapped.close_code; $state.Model = $model
        $retry.Enabled = $mapped.can_retry
        $verification.Value.Text = if ($mapped.state -eq 'held') { 'Held' } elseif ($mapped.state -eq 'stopped') { 'Stopped' } else { 'Pending' }
        $runtime.Value.Text = if ($mapped.state -eq 'checking') { 'Checking' } else { 'Not verified' }
        $stage.Text = $mapped.title + [Environment]::NewLine + $mapped.message
        $bar.Style = if ($mapped.state -in @('held', 'stopped')) { 'Continuous' } else { 'Marquee' }
        if ($model.report_valid) {
            $view.Text = Format-RecoveryModel $model
            $logButton.Enabled = [bool]$model.log_path -and $null -eq $state.LogTask
        } else {
            $view.Text = 'The report is missing, malformed, changed or unsafe. Its contents were not executed.'
            $logButton.Enabled = $false
        }
        if ($mapped.state -eq 'held' -and !$mapped.can_retry) {
            $hint.Text = 'Owned work has not been proven retired. Retry is unavailable; Close only dismisses this interface.'
        } elseif ($mapped.state -eq 'stopped') {
            $hint.Text = 'Startup is stopped. Close dismisses this interface; no automatic retry will follow.'
        } elseif ($mapped.state -eq 'held') {
            $hint.Text = 'Protection is unavailable. Retry repeats verified startup checks; Close ends this startup attempt.'
        } else {
            $hint.Text = 'Close cancels further attempts. A current bounded check may finish before the supervisor stops.'
        }
        if ($mapped.dashboard_ready) { $state.ExitCode = 0; $form.Close() }
    })
    $form.Add_Shown({
        # Refresh completes the first native paint before any report/log read,
        # C# reader compilation, or paint-receipt filesystem operation.
        $form.Refresh(); $state.Painted = $true
        $connectionPhase = 'reader-initialization'
        try {
            Initialize-RecoveryReader
            $connectionPhase = 'supervisor-verification'
            $shellBirth = [AngeronaRecoveryReadV1]::ProcessCreationFileTime($PID)
            if ($shellBirth -le 0 -or
                [AngeronaRecoveryReadV1]::ProcessCreationFileTime($SupervisorPid) -ne $SupervisorCreationFileTime) {
                throw 'The startup supervisor generation could not be verified.'
            }
            $receipt = [ordered]@{ schema = 1; run_id = $StartupRunId
                supervisor_pid = $SupervisorPid; supervisor_creation_filetime = [string]$SupervisorCreationFileTime
                shell_pid = $PID; shell_creation_filetime = [string]$shellBirth }
            $connectionPhase = 'paint-receipt'
            [AngeronaRecoveryReadV1]::WritePaintReceipt($PaintReceiptFile,
                ($receipt | ConvertTo-Json -Compress), $localRuntime, $ownedScratch)
            $connectionPhase = 'status-poll-start'
            $pollTimer.Start()
        } catch {
            Write-StartupShellDiagnostic $connectionPhase $_ $state.Painted
            $state.State = 'held'; $state.ExitCode = 0; $bar.Style = 'Continuous'
            $verification.Value.Text = 'Held'; $runtime.Value.Text = 'Unavailable'
            $stage.Text = 'Startup interface could not establish its supervisor connection. Protection is unavailable.'
            $view.Text = Protect-RecoveryText $_.Exception.Message
            $hint.Text = 'Close this window and retry Safe Startup. No application engine was started by this interface.'
        }
    })
    $form.Add_FormClosing({ $state.Closing = $true; $pollTimer.Stop(); $logTimer.Stop() })
    try { [void]$form.ShowDialog(); return [int]$state.ExitCode }
    finally {
        $pollTimer.Stop(); $pollTimer.Dispose(); $logTimer.Stop(); $logTimer.Dispose(); $form.Dispose()
    }
}

try {
    if ($StartupShell -and !$Headless) { exit (Show-StartupDashboard) }
    $model = Get-RecoveryModel
    if ($Headless) {
        $model | ConvertTo-Json -Depth 6 -Compress
        if ($model.report_valid) { exit 0 }
        exit 11
    }
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form = [Windows.Forms.Form]::new()
    $form.Text = 'Angerona Recovery'
    $form.Size = [Drawing.Size]::new(820, 570)
    $form.StartPosition = 'CenterScreen'
    $form.MinimizeBox = $true
    $view = [Windows.Forms.TextBox]::new()
    $view.Multiline = $true; $view.ReadOnly = $true; $view.ScrollBars = 'Vertical'
    $view.WordWrap = $true; $view.SetBounds(16, 16, 770, 445)
    $view.Anchor = 'Top, Bottom, Left, Right'; $view.Text = Format-RecoveryModel $model
    $form.Controls.Add($view)
    $retry = [Windows.Forms.Button]::new()
    $retry.Text = 'Retry safe recovery'; $retry.SetBounds(16, 478, 165, 32)
    $retry.Anchor = 'Bottom, Left'; $retry.DialogResult = [Windows.Forms.DialogResult]::Retry
    $form.Controls.Add($retry)
    $logButton = [Windows.Forms.Button]::new()
    $logButton.Text = 'View diagnostic log'; $logButton.SetBounds(195, 478, 165, 32)
    $logButton.Anchor = 'Bottom, Left'; $logButton.Enabled = [bool]$model.log_path
    $logOperation = @{ Task = $null }
    $logTimer = [Windows.Forms.Timer]::new()
    $logTimer.Interval = 100
    $logButton.Add_Click({
        if ($null -ne $logOperation.Task) { return }
        $logButton.Enabled = $false
        # The C# worker touches only its own retained read handle. Every form
        # operation stays on the UI thread; one reader is admitted at a time.
        $logOperation.Task = [AngeronaRecoveryReadV1]::BeginRead($model.log_path, $logLimit)
        $logTimer.Start()
    })
    $logTimer.Add_Tick({
        if ($null -eq $logOperation.Task -or !$logOperation.Task.IsCompleted) { return }
        $logTimer.Stop()
        try { $logText = Protect-RecoveryText $logOperation.Task.Result $logLimit }
        catch { $logText = 'The diagnostic log is missing, changed or unavailable. No file was executed.' }
        $logOperation.Task = $null
        $dialog = [Windows.Forms.Form]::new()
        $dialog.Text = 'Angerona diagnostic text - read only'; $dialog.Size = [Drawing.Size]::new(820, 540)
        $text = [Windows.Forms.TextBox]::new()
        $text.Multiline = $true; $text.ReadOnly = $true; $text.ScrollBars = 'Vertical'
        $text.WordWrap = $true; $text.Dock = 'Fill'; $text.Text = $logText
        $dialog.Controls.Add($text)
        [void]$dialog.ShowDialog($form)
        $dialog.Dispose()
        $logButton.Enabled = $true
    })
    $form.Controls.Add($logButton)
    $close = [Windows.Forms.Button]::new()
    $close.Text = 'Close'; $close.SetBounds(680, 478, 105, 32)
    $close.Anchor = 'Bottom, Right'; $close.DialogResult = [Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($close); $form.CancelButton = $close
    $choice = $form.ShowDialog()
    $logTimer.Stop(); $logTimer.Dispose()
    $form.Dispose()
    if ($choice -eq [Windows.Forms.DialogResult]::Retry) { exit 10 }
    exit 0
} catch {
    $failure = [ordered]@{ phase = 'independent-recovery-ui'; outcome = 'ui-unavailable'
        exception_type = $_.Exception.GetType().Name
        message = Protect-RecoveryText $_.Exception.Message } | ConvertTo-Json -Compress
    [Console]::Error.WriteLine($failure)
    exit 11
}
