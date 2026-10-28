<# Independent Windows recovery UI. No application imports, repair or launch authority. #>
[CmdletBinding()]
param(
    [string]$StatusFile,
    [string]$LogRoot,
    [string]$Message,
    [switch]$Headless
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

function Assert-RecoveryPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or !$Path.Contains(':') -or
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
    $model = [ordered]@{
        schema = 1; phase = 'startup diagnostics'; outcome = 'report-unavailable'
        message = 'The startup report is unavailable. Retry safe recovery or inspect the launcher output.'
        protection_status = 'unknown'; log_path = ''; log_state = 'No diagnostic log was selected.'
        attempts = @(); report_valid = $false; omitted_attempts = 0
    }
    if ($Message) { $model.message = Protect-RecoveryText $Message }
    try {
        $statusPath = Assert-RecoveryPath $StatusFile
        if ([IO.Path]::GetExtension($statusPath) -ne '.json') { throw 'Expected a JSON startup report.' }
        $raw = Read-RecoveryText $statusPath $statusLimit
        $document = ConvertFrom-Json -InputObject $raw
        if (($document.schema -isnot [int] -and $document.schema -isnot [long]) -or
            $document.schema -ne 1) { throw 'Unrecognized startup report.' }
        $model.phase = Protect-RecoveryText $document.phase 256
        $model.outcome = Protect-RecoveryText $document.outcome 128
        if (!$Message) { $model.message = Protect-RecoveryText $document.message }
        $model.report_valid = $true
        $properties = @($document.PSObject.Properties.Name)
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
                if ($LogRoot) { $selectedRoot = Assert-RecoveryPath $LogRoot }
                $log = Assert-RecoveryPath ([string]$document.log_path)
                $prefix = $selectedRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
                if (!$log.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
                    [IO.Path]::GetExtension($log).ToLowerInvariant() -notin @('.log', '.txt', '.jsonl', '.json')) {
                    throw 'Log is outside the selected diagnostic directory.'
                }
                $model.log_path = $log
                $model.log_state = 'Diagnostic text can be viewed here without executing it.'
                if (!(Test-Path -LiteralPath $log -PathType Leaf)) { $model.log_state = 'The diagnostic log is missing; no file will be executed.' }
                else { [AngeronaRecoveryReadV1]::Validate($log) }
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

try {
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
