[CmdletBinding()]
param([string]$RepositoryRoot, [switch]$SetupOnly)

$ErrorActionPreference = 'Stop'

# These diagnostics are advisory and private. They never grant launch, repair,
# response or trust authority. Keep one bounded journal across startup attempts.
function Initialize-SourceStartupDiagnostics([string]$Storage) {
    $directory = Join-Path $Storage 'logs\startup-recovery'
    Assert-PlainRepairPath $directory
    if (!(Test-Path -LiteralPath $directory)) { New-PrivateRepairDirectory $directory }
    Assert-PrivateRepairCustody $directory
    $script:StartupDiagnosticRoot = $directory
    $script:StartupJournalPath = Join-Path $directory 'supervisor.jsonl'
    $script:StartupStatusPath = Join-Path $directory 'status.json'
    $script:StartupRunId = [Guid]::NewGuid().ToString('N')
    $script:StartupAttempts = [Collections.Generic.List[object]]::new()
    $script:StartupCommandNumber = 0
}

function Protect-SourceStartupText([object]$Value, [int]$Limit = 2000) {
    $text = [string]$Value
    $text = [regex]::Replace($text, '(?i)(Bearer\s+)[^\s]+', '$1[redacted]')
    $text = [regex]::Replace($text, '(?i)((?:password|secret|token|api[_-]?key)\s*[=:]\s*)[^\s,;]+', '$1[redacted]')
    $text = [regex]::Replace($text, '(?i)sk-[a-z0-9_-]{12,}', '[redacted]')
    if ($text.Length -gt $Limit) { $text = $text.Substring(0, $Limit) + ' [truncated]' }
    return $text
}

function Write-SourceStartupEvent([string]$Phase, [string]$Outcome,
    [string]$Message = '', [Nullable[int]]$ExitCode = $null, [string]$Strategy = '') {
    if (!$script:StartupJournalPath) { return }
    try {
        Assert-PrivateRepairCustody $script:StartupDiagnosticRoot
        $row = [ordered]@{ schema = 1; run_id = $script:StartupRunId
            utc = [DateTime]::UtcNow.ToString('o'); phase = $Phase; outcome = $Outcome
            strategy = $Strategy; message = (Protect-SourceStartupText $Message)
            exit_code = $ExitCode; supervisor_pid = $PID }
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($row | ConvertTo-Json -Compress) + "`n")
        if ($bytes.Length -gt 8192) { throw 'Startup diagnostic frame exceeds its bound.' }
        if ((Test-Path -LiteralPath $script:StartupJournalPath) -and
            ((Get-Item -LiteralPath $script:StartupJournalPath).Length + $bytes.Length) -gt 512KB) {
            for ($index = 3; $index -ge 1; $index--) {
                $target = Join-Path $script:StartupDiagnosticRoot "supervisor.$index.jsonl"
                if (Test-Path -LiteralPath $target) {
                    Assert-PrivateRepairCustody $target
                    if ($index -eq 3) { [IO.File]::Delete($target) }
                    else { [IO.File]::Move($target, (Join-Path $script:StartupDiagnosticRoot "supervisor.$($index + 1).jsonl")) }
                }
            }
            Assert-PrivateRepairCustody $script:StartupJournalPath
            [IO.File]::Move($script:StartupJournalPath, (Join-Path $script:StartupDiagnosticRoot 'supervisor.1.jsonl'))
        }
        $mode = if (Test-Path -LiteralPath $script:StartupJournalPath) { [IO.FileMode]::Open } else { [IO.FileMode]::CreateNew }
        $stream = Open-PrivateRepairFile -Path $script:StartupJournalPath -Mode $mode
        try {
            [void]$stream.Seek(0, [IO.SeekOrigin]::End)
            $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true)
        } finally { $stream.Dispose() }
    } catch {
        Write-Host '[startup] Diagnostic publication unavailable; retain the console explanation.'
    }
}

function Write-SourceStartupStatus([string]$Phase, [string]$Outcome, [string]$Message) {
    if ($script:StartupStorageWarning) { $Message += "`nStorage advisory: " + $script:StartupStorageWarning }
    Write-SourceStartupEvent $Phase $Outcome $Message
    if (!$script:StartupStatusPath) { return }
    $candidate = Join-Path $script:StartupDiagnosticRoot ('status.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        $rows = @()
        if ($script:StartupAttempts) { $rows = @($script:StartupAttempts | Select-Object -Last 32) }
        $status = [ordered]@{ schema = 1; phase = $Phase; outcome = $Outcome
            run_id = $script:StartupRunId; supervisor_pid = $PID
            supervisor_creation_filetime = [string]$script:StartupSupervisorCreationFileTime
            message = (Protect-SourceStartupText $Message 4000); log_path = $script:StartupJournalPath
            protection_status = 'unknown'; attempts = $rows }
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($status | ConvertTo-Json -Depth 5 -Compress))
        if ($bytes.Length -gt 64KB) { throw 'Startup status exceeds its bounded size.' }
        $stream = Open-PrivateRepairFile -Path $candidate
        try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        if (Test-Path -LiteralPath $script:StartupStatusPath) {
            Assert-PrivateRepairCustody $script:StartupStatusPath
            [IO.File]::Replace($candidate, $script:StartupStatusPath, [NullString]::Value)
        } else { [IO.File]::Move($candidate, $script:StartupStatusPath) }
    } catch {
        Write-SourceStartupEvent 'status-publication' 'unavailable' $_.Exception.Message
        Write-Host '[startup] Recovery status unavailable; the console remains diagnostic evidence.'
    }
    finally { if (Test-Path -LiteralPath $candidate) { [IO.File]::Delete($candidate) } }
}

function Add-SourceStartupAttempt([string]$Strategy, [int]$Code, [string]$Detail = '') {
    if ($null -ne $script:StartupAttempts) {
        if ($script:StartupAttempts.Count -ge 32) { $script:StartupAttempts.RemoveAt(0) }
        $script:StartupAttempts.Add([ordered]@{ strategy = $Strategy
            outcome = $(if ($Code -eq 0) { 'verified' } else { 'not-ready' })
            exit_code = $Code; detail = (Protect-SourceStartupText $Detail 1000) })
    }
    Write-SourceStartupEvent 'attempt' 'finished' $Detail $Code $Strategy
}

function Read-SourceStartupLogTail([string]$Path) {
    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) { return 'The expected diagnostic log was not produced.' }
    Assert-PlainRepairPath $Path
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        [void]$stream.Seek([Math]::Max(0, $stream.Length - 8192), [IO.SeekOrigin]::Begin)
        $bytes = New-Object byte[] 8192
        $count = $stream.Read($bytes, 0, $bytes.Length)
        return Protect-SourceStartupText ([Text.Encoding]::UTF8.GetString($bytes, 0, $count)) 8000
    } finally { $stream.Dispose() }
}

function ConvertTo-SourceStartupArgument([string]$Value) {
    $builder = [Text.StringBuilder]::new(); [void]$builder.Append([char]34)
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]92) { $slashes++; continue }
        if ($character -eq [char]34) { [void]$builder.Append([char]92, (2 * $slashes + 1)) }
        else { [void]$builder.Append([char]92, $slashes) }
        [void]$builder.Append($character); $slashes = 0
    }
    [void]$builder.Append([char]92, (2 * $slashes)); [void]$builder.Append([char]34)
    return $builder.ToString()
}

function Start-SourceStartupWindowProcess([string]$Executable, [string[]]$Arguments,
    [string]$WorkingDirectory, [Collections.IDictionary]$Environment) {
    $log = Join-Path $Environment['TEMP'] ('recovery-window.' + [Guid]::NewGuid().ToString('N') + '.log')
    return Start-OwnedRepairWindow -FilePath $Executable -Arguments $Arguments -WorkingDirectory $WorkingDirectory `
        -Environment $Environment -LogPath $log
}

function Test-SourceStartupShellClosed {
    if (!$script:StartupShell -or !$script:StartupShell.HasExited) { return $false }
    return $script:StartupShell.ExitCode -ne 10
}

function Start-SourceStartupShell([string]$Root) {
    if (!$script:StartupStatusPath) { return }
    if ($script:StartupShell) {
        if (!$script:StartupShell.HasExited) { return }
        if ($script:StartupShell.ExitCode -ne 10) { return }
        $script:StartupShell.Dispose(); $script:StartupShell = $null
    }
    $identity = Get-LiveRepairProcessIdentity ([uint32]$PID)
    try {
        if ($identity.State -ne 'live' -or $identity.CreationFileTime -le 0) { throw 'The startup supervisor generation is unavailable.' }
        $script:StartupSupervisorCreationFileTime = $identity.CreationFileTime
    } finally { $identity.Dispose() }
    $storage = Initialize-SourceStartupStorage
    $scratch = New-SourceStartupTemporary -Root $Root -Storage $storage -Purpose interface
    $receipt = Join-Path $scratch 'startup-shell-painted.json'
    $file = Open-PrivateRepairFile $receipt
    $file.Dispose()
    $shell = Join-Path $Root 'tools\Show-AngeronaStartupRecovery.ps1'
    Assert-SourceStartupPath $shell
    $powershell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $environment = New-RepairChildEnvironment $scratch
    Write-SourceStartupStatus 'startup' 'checking' 'Opening the recovery dashboard before runtime checks. Protection has not yet been verified.'
    $script:StartupShell = Start-SourceStartupWindowProcess $powershell @('-NoProfile', '-STA', '-File', $shell,
        '-StartupShell', '-StatusFile', $script:StartupStatusPath, '-StartupRunId', $script:StartupRunId,
        '-SupervisorPid', [string]$PID, '-SupervisorCreationFileTime', [string]$script:StartupSupervisorCreationFileTime,
        '-PaintReceiptFile', $receipt) $Root $environment
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ($clock.ElapsedMilliseconds -lt 20000) {
        if ($script:StartupShell.HasExited) { throw 'The independent startup dashboard closed before its first paint.' }
        Assert-PrivateRepairCustody $receipt
        $info = Get-Item -LiteralPath $receipt
        if ($info.Length -gt 1024) { throw 'The startup paint receipt exceeded its bound.' }
        if ($info.Length -gt 0) {
            try {
                $paint = [IO.File]::ReadAllText($receipt, [Text.UTF8Encoding]::new($false, $true)) | ConvertFrom-Json
                if ($paint.schema -eq 1 -and $paint.run_id -ceq $script:StartupRunId -and
                    [string]$paint.supervisor_pid -ceq [string]$PID -and
                    [string]$paint.supervisor_creation_filetime -ceq [string]$script:StartupSupervisorCreationFileTime -and
                    [string]$paint.shell_pid -ceq [string]$script:StartupShell.ProcessId -and
                    [string]$paint.shell_creation_filetime -ceq [string]$script:StartupShell.CreationFileTime) {
                    Write-SourceStartupEvent 'startup-shell' 'painted' 'Independent recovery dashboard painted; runtime and protection checks are pending.'
                    return
                }
            } catch { } # A partial bounded publication carries no launch authority.
        }
        Start-Sleep -Milliseconds 50
    }
    throw 'The independent startup dashboard did not confirm its first paint within 20 seconds.'
}

function Test-SourceStartupCapturesRetired {
    if (!$script:StartupPendingCaptures -or !$script:StartupPendingCaptures.Count) { return $true }
    $clock = [Diagnostics.Stopwatch]::StartNew()
    do {
        foreach ($capture in @($script:StartupPendingCaptures)) {
            if ($capture.ReadersComplete -and $capture.Process.HasExited) {
                $capture.Process.Dispose(); [void]$script:StartupPendingCaptures.Remove($capture)
            }
        }
        if (!$script:StartupPendingCaptures.Count) { return $true }
        if ($clock.ElapsedMilliseconds -ge 1000) { break }
        Start-Sleep -Milliseconds 25
    } while ($true)
    $capture = $script:StartupPendingCaptures[0]
    $script:LastStartupIssue = "The retained assistant generation (PID $($capture.ProcessId), native creation FILETIME $($capture.CreationTimeFileTime)) or its diagnostic readers is still active. Further startup and mutation attempts are held; an actual dashboard is preserved."
    Write-SourceStartupEvent 'assistant-retirement' 'held' $script:LastStartupIssue 85
    return $false
}

function Invoke-SourceRecoveryWindow([string]$Root, [string]$Message, [switch]$ReviewSource,
    [string]$ReportPath = '', [string]$ExpectedReportId = '') {
    $custodyHeld = ('Angerona.StartupRepairProcess' -as [type]) -and [Angerona.StartupRepairProcess]::CustodyPending
    if ($custodyHeld) {
        $Message = 'Owned process retirement could not be proved. Exact native handles and coordination leases remain retained; no further launch or mutation is admitted. Closing this interface does not prove independent process retirement. Review this generation before a new startup.'
    }
    Write-SourceStartupStatus 'recovery' $(if ($custodyHeld) { 'custody-held' } else { 'needs-attention' }) $Message
    if (!$ReviewSource -and $script:StartupShell) {
        try { $script:StartupShell.WaitForExit() }
        catch {
            if (!$custodyHeld) { throw }
            # The failed window's native owner remains parked in the custody
            # registry. A separate inert shell may still explain the hold.
            $script:StartupShell = $null
            try {
                Start-SourceStartupShell $Root
                Write-SourceStartupStatus 'recovery' 'custody-held' $Message
                $script:StartupShell.WaitForExit()
            } catch { Write-Host '[startup] Native retirement remains held; retain the diagnostics and review the existing generation.' }
            return 0
        }
        if ($custodyHeld) { return 0 }
        return [int]$script:StartupShell.ExitCode
    }
    $python = Join-Path $Root 'venv\Scripts\python.exe'
    $tool = Join-Path $Root 'tools\angerona_recovery.py'
    # This window imports only standard-library code; broken application imports
    # cannot remove the recovery interface. It never launches a security engine.
    if ($script:StartupStatusPath -and (Test-Path -LiteralPath $python -PathType Leaf) -and
        (Test-Path -LiteralPath $tool -PathType Leaf)) {
        $uiLease = $null
        try {
            Assert-SourceStartupPath $python; Assert-SourceStartupPath $tool
            $uiLease = Enter-RepairLease -Root $Root
            Assert-NoPendingRepair $Root
            $statusPath = if ($ReviewSource -and $ReportPath) { $ReportPath } else { $script:StartupStatusPath }
            $arguments = @('-I', $tool, '--status-file', $statusPath)
            if ($ReviewSource) { $arguments += '--review-source' }
            if ($ReviewSource -and $ExpectedReportId) { $arguments += @('--expected-report-id', $ExpectedReportId) }
            $scratch = New-SourceStartupTemporary -Root $Root -Storage (Initialize-SourceStartupStorage) -Purpose recovery
            $environment = New-RepairChildEnvironment $scratch
            $process = Start-SourceStartupWindowProcess $python $arguments $Root $environment
            try { $process.WaitForExit(); $code = $process.ExitCode }
            finally { $process.Dispose() }
            if ($null -ne $code -and [int]$code -in @(0, 10, 20, 21)) { return [int]$code }
            Write-SourceStartupEvent 'recovery-python' 'unavailable' 'The independent Python recovery view could not open.'
        } catch { Write-SourceStartupEvent 'recovery-python' 'unavailable' $_.Exception.Message }
        finally { if ($uiLease) { Exit-RepairLease $uiLease } }
    }
    $fallback = Join-Path $Root 'tools\Show-AngeronaStartupRecovery.ps1'
    try {
        Assert-SourceStartupPath $fallback
        $powershell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
        $arguments = @('-NoProfile', '-STA', '-File', $fallback)
        if ($script:StartupStatusPath -and (Test-Path -LiteralPath $script:StartupStatusPath)) {
            $arguments += @('-StatusFile', $script:StartupStatusPath)
        } else { $arguments += @('-Message', (Protect-SourceStartupText $Message)) }
        $scratch = New-SourceStartupTemporary -Root $Root -Storage (Initialize-SourceStartupStorage) -Purpose recovery
        $environment = New-RepairChildEnvironment $scratch
        $process = Start-SourceStartupWindowProcess $powershell $arguments $Root $environment
        try { $process.WaitForExit(); $code = $process.ExitCode }
        finally { $process.Dispose() }
        if (!$custodyHeld -and $null -ne $code -and [int]$code -eq 10) { return 10 }
    } catch { Write-Host "[startup] Recovery display failed: $($_.Exception.Message)" }
    return 0
}

function Invoke-SourceCodeAction([string]$Root, [string]$Action, [string]$Strategy = '',
    [string]$Choice = '', [string]$ExpectedId = '') {
    $script:LastSourceRecoveryResult = $null
    $storage = Initialize-SourceStartupStorage
    $tool = Join-Path $Root 'tools\startup_source_recovery.py'
    $python = Join-Path $Root 'venv\Scripts\python.exe'
    Assert-SourceStartupPath $tool; Assert-SourceStartupPath $python
    if (!(Test-Path -LiteralPath $python -PathType Leaf)) {
        $script:LastSourceRecoveryResult = [pscustomobject]@{launch_held=$true;reason_code='runtime-missing'}
        return 81
    }
    if (!(Test-Path -LiteralPath $tool -PathType Leaf)) {
        $script:LastSourceRecoveryResult = [pscustomobject]@{launch_held=$true;reason_code='source-helper-missing'}
        return 1
    }
    $lease = Enter-RepairLease -Root $Root
    $helperLease = $null
    $instanceLease = $null
    try {
        # Source tooling is independent of app imports, but must not run from a
        # runtime whose promotion/rollback is still unresolved.
        Assert-NoPendingRepair $Root
        if ($Action -in @('recover', 'apply-pending', 'fingerprint', 'inspect')) {
            $helperLease = Enter-CanonicalSourceHelperLease
        }
        if ($Action -in @('recover', 'apply-pending')) {
            if (Test-SourceStartupShellClosed) { return 1223 }
            $instanceLease = Enter-CanonicalCoreMutationLease
            Assert-NoActiveVenv -VenvPath (Join-Path $Root 'venv')
        }
        $scratch = New-SourceStartupTemporary -Root $Root -Storage $storage
        $environment = New-RepairChildEnvironment $scratch
        $arguments = @('-I', $tool, '--root', $Root, '--state-root', (Join-Path $storage 'startup-recovery'), '--action', $Action)
        if ($Strategy) { $arguments += @('--strategy', $Strategy) }
        if ($Action -eq 'recover' -and $script:LastSourceStartupError) {
            $arguments += @('--failure-detail', (Protect-SourceStartupText $script:LastSourceStartupError 4000))
        }
        if ($Choice) { $arguments += @('--choice', $Choice) }
        if ($ExpectedId) { $arguments += @('--expected-id', $ExpectedId) }
        if ($Action -in @('recover', 'apply-pending')) { $arguments += '--exclusive-startup' }
        if ($Action -eq 'snapshot') { $arguments += '--ready-observed' }
        if ($Action -eq 'snapshot' -and $script:StartupLaunchSourceDigest) {
            $arguments += @('--expected-source-digest', $script:StartupLaunchSourceDigest)
        }
        $savedTemp, $savedTmp = $env:TEMP, $env:TMP
        try { $env:TEMP = $scratch; $env:TMP = $scratch; Initialize-OwnedRepairProcess }
        finally { $env:TEMP = $savedTemp; $env:TMP = $savedTmp }
        $log = Join-Path $scratch 'source-action.log'
        $abiLog = Join-Path $scratch 'source-action-abi.log'
        $abi = 'import sys,sysconfig;raise SystemExit(0 if sys.version_info[:2]==(3,12) and sysconfig.get_platform()=="win-amd64" else 81)'
        $abiCode = [int](Invoke-OwnedRepairProcess -FilePath $python -Arguments @('-I', '-c', $abi) `
            -WorkingDirectory $Root -Environment $environment -TimeoutSeconds 30 -LogPath $abiLog)
        if ($abiCode -ne 0) {
            $script:LastSourceRecoveryResult = [pscustomobject]@{launch_held=$true;reason_code='runtime-invalid'}
            return 81
        }
        $code = [int](Invoke-OwnedRepairProcess -FilePath $python -Arguments $arguments -WorkingDirectory $Root `
            -Environment $environment -TimeoutSeconds 300 -LogPath $log)
        Assert-PlainRepairPath $log
        $info = Get-Item -LiteralPath $log
        if ($info.Length -gt 64KB) { throw 'Source recovery response exceeded its diagnostic bound.' }
        $response = [IO.File]::ReadAllText($log, [Text.Encoding]::UTF8).Trim()
        try { $script:LastSourceRecoveryResult = $response | ConvertFrom-Json }
        catch { Write-SourceStartupEvent 'source-recovery' 'response-unavailable' $response $code $Strategy; return 1 }
        if ($script:LastSourceRecoveryResult -isnot [pscustomobject] -or
            $script:LastSourceRecoveryResult.schema -ne 1 -or
            $script:LastSourceRecoveryResult.launch_held -isnot [bool]) {
            $script:LastSourceRecoveryResult = [pscustomobject]@{launch_held=$true;reason_code='invalid-source-response'}
            return 1
        }
        Write-SourceStartupEvent "source-$Action" $(if ($code -eq 0) { 'completed' } else { 'held' }) $response $code $Strategy
        return $code
    } finally {
        if ($instanceLease) { Exit-RepairLease $instanceLease }
        if ($helperLease) { Exit-RepairLease $helperLease }
        Exit-RepairLease $lease
    }
}

function Show-SourceStartupBundleReview {
    $paths = @()
    $storage = Initialize-SourceStartupStorage
    $reportPath = Join-Path $storage 'logs\startup-recovery\bundle-guard\report.json'
    if (Test-Path -LiteralPath $reportPath) {
        Assert-PrivateRepairCustody $reportPath -AllowInherited
        $stream = [IO.File]::Open($reportPath, 'Open', 'Read', 'Read')
        try {
            if ($stream.Length -gt 64KB) { throw 'Bundle recovery report exceeds its read bound.' }
            $reader = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false, $true))
            try { $report = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
        } finally { $stream.Dispose() }
        if ($report.schema -eq 1 -and $report.outcome -eq 'repaired') {
            $paths = @($report.restored_files | Select-Object -First 32 | ForEach-Object { Protect-SourceStartupText $_ 240 })
        }
    }
    if ($env:ANGERONA_BOOTSTRAP_RESTORED -eq '1') { $paths += 'tools/verify_startup_recovery_bundle.ps1' }
    if (!$paths.Count) { return }
    $message = "The dashboard passed its readiness check after restoring pinned recovery files:`n`n" + ($paths -join "`n") +
        "`n`nThese files differed from the reviewed bundle; this alone does not prove which edit caused a failure. Edited originals were preserved privately under logs/startup-recovery. Protection coverage is shown separately in the dashboard.`n`nKeep the repaired bundle to continue. To reintroduce edits to these trust checks, review the preserved files and rebuild/publish the recovery pins; there is no automatic trust override. Other application edits use the separate Keep working / Try preserved edits next startup review."
    Write-SourceStartupEvent 'bundle-review' 'dashboard-ready' $message
    Add-Type -AssemblyName System.Windows.Forms
    [void][Windows.Forms.MessageBox]::Show($message, 'Angerona startup corrective actions', 'OK', 'Information')
}

function Complete-SourceStartupRecovery([string]$Root) {
    # A ready receipt permits only an advisory source snapshot. It does not
    # attest protection, create a baseline/allowlist, or authorize host response.
    try {
        try { Show-SourceStartupBundleReview }
        catch { Write-SourceStartupEvent 'bundle-review' 'unavailable' $_.Exception.Message }
        if ($script:StartupRecoveryPreferences -and !$script:StartupRecoveryPreferences.Enabled) { return }
        if (!$script:StartupLaunchSourceDigest) {
            Write-Host '[startup] Dashboard is ready; no stable prelaunch source digest was available for a recovery snapshot.'
            return
        }
        $code = Invoke-SourceCodeAction -Root $Root -Action 'snapshot'
        if ($code -ne 0) { Write-Host '[startup] Dashboard is ready; its source snapshot could not be recorded.'; return }
        $report = $script:LastSourceRecoveryResult
        if (!$report -or !$report.pending_decision) { return }
        $paths = @($report.changed_files | Select-Object -First 32) -join "`n"
        $message = "Startup recovered. $($report.message)`nActions: $($report.action_summary)`nChanged source candidates (not all are proven causes):`n$paths`n`nKeep the working version, or schedule the preserved edits for another startup. Original edits are retained privately; no live source replacement is performed."
        $storage = Initialize-SourceStartupStorage
        $choice = Invoke-SourceRecoveryWindow -Root $Root -Message $message -ReviewSource `
            -ReportPath (Join-Path $storage 'startup-recovery\report.json') -ExpectedReportId ([string]$report.report_id)
        $decision = if ($choice -eq 20) { 'keep-working' } elseif ($choice -eq 21) { 'restore-edits' } else { '' }
        if ($decision) {
            $code = Invoke-SourceCodeAction -Root $Root -Action 'decision' -Choice $decision -ExpectedId ([string]$report.report_id)
            if ($code -ne 0) { Write-Host '[startup] The source decision could not be saved; preserved edits remain held.' }
        }
    } catch {
        Write-SourceStartupEvent 'post-ready-recovery' 'unavailable' $_.Exception.Message
        Write-Host '[startup] Dashboard is ready. Recovery details remain in the private startup diagnostics.'
    }
}

function Assert-SourceStartupHost {
    $system = [Environment]::SystemDirectory
    $expected = Join-Path $system 'WindowsPowerShell\v1.0\powershell.exe'
    $actual = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    if (![string]::Equals($actual, $expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Source startup requires the fixed Windows PowerShell host.'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $expected
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft') {
        throw 'The Windows PowerShell host signature could not be verified.'
    }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Mutable source startup requires a normal user session. Use the signed MSIX for Protect coverage.'
    }
}

function Assert-SourceStartupPath([string]$Path) {
    if (![IO.Path]::IsPathRooted($Path)) { throw 'Source startup requires absolute local paths.' }
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Source startup refuses a redirected path: $cursor"
            }
        }
        $next = [IO.Path]::GetDirectoryName($cursor)
        if ($next -eq $cursor) { break }
        $cursor = $next
    }
}

function Assert-SourceStartupSupervisorBoundary([string]$Root) {
    Assert-SourceStartupHost
    Assert-SourceStartupPath $Root
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($Root))
    if (!$drive.IsReady -or $drive.DriveType -ne [IO.DriveType]::Fixed) {
        throw 'Source startup requires a ready fixed local installation drive.'
    }
    foreach ($name in @('start-angerona.bat', 'tools\Invoke-AngeronaSourceStartup.ps1',
        'tools\startup_repair_common.ps1', 'tools\Invoke-AngeronaStartupRepair.ps1',
        'tools\angerona_recovery.py', 'tools\Show-AngeronaStartupRecovery.ps1',
        'tools\startup_source_recovery.py', 'tools\startup_assistant_capture.ps1', 'Repair-Angerona-Python.ps1')) {
        $path = Join-Path $Root $name
        Assert-SourceStartupPath $path
        if (!(Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "The source checkout is incomplete: $name"
        }
    }
    Assert-SourceStartupPath (Join-Path $Root 'venv')
}

function Assert-SourceStartupBoundary([string]$Root) {
    Assert-SourceStartupSupervisorBoundary $Root
    foreach ($name in @('pyproject.toml', 'constraints-release.txt', 'src\angerona\__init__.py',
        'src\angerona\startup.py', 'src\angerona\core\startup_recovery.py', 'tools\source_trust_preflight.py')) {
        $path = Join-Path $Root $name
        Assert-SourceStartupPath $path
        if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "Application source is incomplete: $name" }
    }
    Assert-SourceStartupPath (Join-Path $Root 'venv\Scripts\python.exe')
}

function Test-SourceStorageProof([string]$Directory) {
    $probe = Join-Path $Directory ('startup-check.' + [Guid]::NewGuid().ToString('N'))
    $bytes = [Text.Encoding]::UTF8.GetBytes('Angerona startup storage proof ' + [Guid]::NewGuid().ToString('N'))
    $stream = $null
    try {
        $stream = [IO.File]::Open($probe, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Position = 0
        $read = New-Object byte[] $bytes.Length
        if ($stream.Read($read, 0, $read.Length) -ne $bytes.Length -or
            [Convert]::ToBase64String($read) -cne [Convert]::ToBase64String($bytes)) {
            throw 'Startup storage readback did not match the flushed bytes.'
        }
    } finally {
        if ($stream) {
            $stream.Dispose()
            [IO.File]::Delete($probe) # Only the exclusively created proof file.
        }
    }
}

function Initialize-SourceStartupStorage {
    # Never migrate persistent state to a scratch drive, even if that drive has
    # ample room. Audit/evidence capacity is an independent mandatory gate.
    $local = [Environment]::GetFolderPath('LocalApplicationData')
    if (!$local) { throw 'Windows could not resolve Local AppData.' }
    $storage = [IO.Path]::GetFullPath((Join-Path $local 'Angerona\SourceData'))
    Assert-SourceStartupPath $storage
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($storage))
    if (!$drive.IsReady -or $drive.DriveType -ne [IO.DriveType]::Fixed) {
        throw "The canonical source data drive must be a ready fixed local drive: $storage"
    }
    if ($drive.AvailableFreeSpace -lt 128MB -and !$script:SourceStartupCriticalMode) {
        throw "The canonical source data drive needs at least 128 MB free: $storage. Free space there and retry; temporary storage on another drive cannot replace evidence capacity."
    }
    if ($drive.AvailableFreeSpace -lt 128MB) {
        $script:StartupStorageWarning = 'The data drive is below its recommended reserve. Required private write/read checks still apply; optional startup history is limited.'
    }
    foreach ($path in @($storage, (Join-Path $storage 'logs'))) {
        Assert-SourceStartupPath $path
        [void][IO.Directory]::CreateDirectory($path)
        Assert-SourceStartupPath $path
    }
    Test-SourceStorageProof $storage
    return $storage
}

function Assert-SourceStartupScratchBudget([string]$Base) {
    # Inspect only our immediate, named startup scratch roots. Never recurse
    # through general temp, scan evidence, quarantine or arbitrary .tmp caches.
    $visited = 0; $directories = 0; $bytes = 0L
    foreach ($directory in [IO.Directory]::EnumerateDirectories($Base, 'startup-temp.*')) {
        if (++$visited -gt 128) { throw 'Startup scratch history exceeds its bounded directory inventory; unknown names were preserved.' }
        if ([IO.Path]::GetFileName($directory) -cnotmatch '^startup-temp\.[a-f0-9]{32}$') { continue }
        if (++$directories -ge 32) { throw 'Startup scratch has 32 retained attempts; review its diagnostic files before another attempt.' }
        Assert-PrivateRepairCustody $directory
        $count = 0
        foreach ($file in [IO.Directory]::EnumerateFiles($directory)) {
            if (++$count -gt 128) { throw 'Startup scratch inventory exceeds its bounded file count.' }
            Assert-PlainRepairPath $file
            $bytes += (Get-Item -LiteralPath $file).Length
            if ($bytes + 32MB -gt 256MB) { throw 'Retained startup scratch reached its 256 MiB budget. Review diagnostics before allowing more attempts.' }
        }
        foreach ($nested in [IO.Directory]::EnumerateDirectories($directory)) {
            throw 'Startup scratch contains an unexpected nested directory; automatic reuse is held for review.'
        }
    }
}

function Reset-SourceStartupCriticalWorkingFiles([string]$Path, [string]$Purpose) {
    $patterns = @{
        interface = '^(?:startup-shell-painted\.json|recovery-window\.[a-f0-9]{32}\.log)$'
        recovery = '^recovery-window\.[a-f0-9]{32}\.log$'
        control = '^(?:source-action(?:-abi)?|verified-repair)\.log$'
        preflight = '^(?:abi|pip|source-trust|source-setup|launcher-stdout|launcher-stderr)\.log$'
    }
    $count = 0; $bytes = 0L
    foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($Path)) {
        if (++$count -gt 128) { throw 'Critical startup working inventory exceeds its 128-entry bound; existing files were preserved.' }
        Assert-PlainRepairPath $entry
        $item = Get-Item -LiteralPath $entry -Force
        if ($item.PSIsContainer) { throw 'Critical startup workspace contains an unexpected nested directory; existing contents were preserved.' }
        $name = $item.Name
        if ($name -cmatch $patterns[$Purpose]) {
            # Only named, nonauthoritative working outputs are recycled. An
            # actual writer/reader holding the file prevents this exclusive open.
            Assert-PrivateRepairCustody $entry -AllowInherited
            $probe = [IO.File]::Open($entry, 'Open', 'ReadWrite', 'None')
            $probe.Dispose()
            [IO.File]::Delete($entry)
        } else {
            $bytes += $item.Length
            if ($bytes -gt 32MB) { throw 'Critical startup working data exceeds its 32 MiB bound; unknown files were preserved.' }
        }
    }
}

function Close-SourceStartupCriticalWorkspaces {
    $script:SourceStartupScratchLease = $null
    if (!$script:SourceStartupCriticalWorkspaces) { return }
    foreach ($context in $script:SourceStartupCriticalWorkspaces.Values) {
        if ($context.Guard) { $context.Guard.Dispose() }
    }
    $script:SourceStartupCriticalWorkspaces = @{}
}

function New-SourceStartupTemporary([string]$Root, [string]$Storage,
    [ValidateSet('interface','control','preflight','recovery')][string]$Purpose = 'control') {
    # A small fixed critical workspace is separate from optional retained
    # diagnostics. Quota recommendations never turn old empty/log directories
    # into a permanent admission veto for a healthy dashboard.
    if (!$script:SourceStartupCriticalWorkspaces) { $script:SourceStartupCriticalWorkspaces = @{} }
    $key = [IO.Path]::GetFullPath($Root) + '|' + [IO.Path]::GetFullPath($Storage) + '|' + $Purpose
    if ($script:SourceStartupCriticalWorkspaces.ContainsKey($key)) {
        $context = $script:SourceStartupCriticalWorkspaces[$key]
        if (!$context.Guard.CanRead -or $context.Guard.CanWrite) { throw 'Critical startup workspace custody is unavailable.' }
        Assert-PrivateRepairCustody $context.Path
        Reset-SourceStartupCriticalWorkingFiles $context.Path $Purpose
        Test-SourceStorageProof $context.Path
        $script:SourceStartupScratchLease = $context.Guard
        return $context.Path
    }
    foreach ($base in @((Join-Path $Storage 'tmp'), (Join-Path $Root '.tmp'))) {
        $writer = $null; $guard = $null
        try {
            Assert-SourceStartupPath $base
            $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($base))
            if (!$drive.IsReady -or $drive.DriveType -ne [IO.DriveType]::Fixed) { continue }
            if (!$script:SourceStartupCriticalMode -and $drive.AvailableFreeSpace -lt (2GB+32MB)) { continue }
            [void][IO.Directory]::CreateDirectory($base)
            Assert-SourceStartupPath $base
            try { Assert-SourceStartupScratchBudget $base }
            catch { $script:StartupStorageWarning = 'Retained startup diagnostics reached their limit. Startup uses a bounded critical workspace; review retained diagnostics in storage settings.' }
            if ($drive.AvailableFreeSpace -lt (2GB+32MB)) {
                $script:StartupStorageWarning = 'The temporary drive is below its recommended reserve. Required private write/read checks still apply; optional startup history is limited.'
            }
            $scratch = Join-Path $base ('startup-temp.critical-' + $Purpose)
            Assert-SourceStartupPath $scratch
            if (!(Test-Path -LiteralPath $scratch)) { New-PrivateRepairDirectory -Path $scratch }
            Assert-PrivateRepairCustody $scratch
            $leasePath = Join-Path $scratch 'startup-critical.lease'
            $writer = Open-PrivateRepairFile -Path $leasePath -Mode OpenOrCreate -Share None
            if ($writer.Length -ne 0) { throw 'Critical startup lease file has unexpected data.' }
            Reset-SourceStartupCriticalWorkingFiles $scratch $Purpose
            $ownerPath = Join-Path $scratch 'startup-critical.owner.json'
            if (Test-Path -LiteralPath $ownerPath) {
                Assert-PrivateRepairCustody $ownerPath -AllowInherited
                if ((Get-Item -LiteralPath $ownerPath).Length -gt 1024) { throw 'Critical startup ownership marker exceeds its bound.' }
                [IO.File]::Delete($ownerPath)
            }
            $nonce = [Guid]::NewGuid().ToString('N')
            $owner = Open-PrivateRepairFile -Path $ownerPath
            try {
                $payload = [Text.Encoding]::UTF8.GetBytes('{"schema":1,"nonce":"' + $nonce + '","pid":' + $PID + '}')
                $owner.Write($payload, 0, $payload.Length); $owner.Flush($true)
            } finally { $owner.Dispose() }
            $writer.Dispose(); $writer = $null
            $guard = [IO.File]::Open($leasePath, 'Open', 'Read', 'Read')
            Assert-PrivateRepairCustody $leasePath
            $observed = [IO.File]::ReadAllText($ownerPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
            if ($observed.schema -ne 1 -or $observed.nonce -cne $nonce -or $observed.pid -ne $PID) {
                throw 'A competing startup claimed the critical workspace before its read lease was retained.'
            }
            Test-SourceStorageProof $scratch
            $script:SourceStartupCriticalWorkspaces[$key] = [pscustomobject]@{ Path = $scratch; Guard = $guard }
            $script:SourceStartupScratchLease = $guard; $guard = $null
            return $scratch
        } catch { Write-Verbose ('A private critical startup workspace is unavailable: ' + $_.Exception.Message) }
        finally { if ($writer) { $writer.Dispose() }; if ($guard) { $guard.Dispose() } }
    }
    throw 'No critical startup workspace could be privately leased and written. Existing active producers and unknown data were preserved; retained diagnostic counts and recommended reserves did not waive custody or actual writability.'
}

function Invoke-SourceStartupAssistant([string]$Python, [string]$Root,
    [Collections.IDictionary]$Environment, [string]$Scratch, [switch]$SoftwareRenderer,
    [switch]$NoStartupWindow) {
    $stdout = Join-Path $Scratch 'launcher-stdout.log'
    $stderr = Join-Path $Scratch 'launcher-stderr.log'
    . (Join-Path $Root 'tools\startup_assistant_capture.ps1')
    $arguments = @('-m', 'angerona.startup', '--chill')
    if ($SoftwareRenderer) { $arguments += '--software-renderer' }
    if ($NoStartupWindow) { $arguments += '--no-startup-window' }
    $savedTemp, $savedTmp = $env:TEMP, $env:TMP
    try {
        $env:TEMP = $Scratch; $env:TMP = $Scratch
        $capture = Invoke-SourceStartupCapturedAssistant -Python $Python -Arguments $arguments `
            -WorkingDirectory $Root -Environment $Environment -StdoutPath $stdout -StderrPath $stderr -TimeoutSeconds 240
    } finally { $env:TEMP = $savedTemp; $env:TMP = $savedTmp }
    # Never place the assistant/dashboard in a kill-on-close repair job. The
    # helper preserves a live dashboard after monitoring cancellation/timeout.
    $code = $capture.ExitCode
    if ($null -eq $code) { throw 'The startup assistant exit status could not be verified.' }
    try {
        # Retain ownership before advisory inspection/disposal or logging. A
        # diagnostic failure cannot discard the native status or a live owner.
        if ($null -eq $script:StartupPendingCaptures) { $script:StartupPendingCaptures = [Collections.Generic.List[object]]::new() }
        $script:StartupPendingCaptures.Add($capture)
        if ($capture.ReadersComplete -and $capture.Process.HasExited) {
            $capture.Process.Dispose()
            [void]$script:StartupPendingCaptures.Remove($capture)
        }
    Write-SourceStartupEvent 'assistant-capture' 'bounded' ($capture | Select-Object ProcessId,ProcessRole,CreationTimeUtc,CreationTimeFileTime,TimedOut,ReadersComplete,StdoutDropped,StderrDropped,CaptureError | ConvertTo-Json -Compress) ([int]$code)
    if ($capture.TimedOut) {
        $script:LastStartupIssue = 'The assistant monitor reached 240 seconds. Its exact launcher process and possible dashboard were preserved. Review the existing generation before Retry.'
        Write-Host $script:LastStartupIssue
    }
    Write-SourceStartupEvent 'assistant' 'exited' '' ([int]$code)
    if ($code -ne 0) {
        $persistent = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Angerona\SourceData\logs\startup-preflight.log'
        Write-Host "Startup assistant stderr: $stderr"
        Write-Host "Dependency and native Qt details: $persistent"
        foreach ($path in @($stderr, $persistent)) {
            try { Write-SourceStartupEvent 'assistant-diagnostic' 'tail' (Read-SourceStartupLogTail $path) ([int]$code) }
            catch { Write-SourceStartupEvent 'assistant-diagnostic' 'unavailable' $_.Exception.Message }
        }
        $dashboard = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Angerona\SourceData\logs\startup-dashboard.log'
        $parts = @()
        foreach ($path in @($stderr, $persistent, $dashboard)) {
            try { $parts += Read-SourceStartupLogTail $path } catch { }
        }
        $script:LastSourceStartupError = Protect-SourceStartupText ($parts -join "`n") 4000
        $script:LastStartupIssue = $script:LastSourceStartupError
    }
    } catch {
        # These are advisory publication errors after a known native result.
        # Never manufacture exit 1 (and source rollback) from a missing log.
        $detail = $_.Exception.Message
        try {
            $script:LastStartupIssue = "Assistant native exit $code was retained; diagnostic publication failed: " + (Protect-SourceStartupText $detail 1000)
            Write-SourceStartupEvent 'assistant-diagnostic' 'unavailable' $script:LastStartupIssue ([int]$code)
        } catch { }
        Write-Host "[startup] Assistant native exit $code was retained; additional diagnostics were unavailable."
    }
    return [int]$code
}

function Invoke-SourceStartupPass([string]$Root, [switch]$SetupOnly, [switch]$SoftwareRenderer,
    [switch]$NoStartupWindow) {
    Assert-SourceStartupBoundary $Root
    $storage = Initialize-SourceStartupStorage
    $lease = Enter-RepairLease -Root $Root
    try {
        try {
            Assert-NoPendingRepair -Root $Root
        } catch {
            if ($_.Exception.Data['AngeronaRepairPending'] -eq $true) { return 81 }
            throw
        }
        $venv = Join-Path $Root 'venv'
        # This pass only reads the shared runtime. Actual runtime/source repair
        # retains full process exclusion; the helper/core keep their own leases.
        $python = Join-Path $venv 'Scripts\python.exe'
        if (!(Test-Path -LiteralPath $python -PathType Leaf)) { return 81 }
        $scratch = New-SourceStartupTemporary -Root $Root -Storage $storage -Purpose preflight
        $child = New-RepairChildEnvironment -Scratch $scratch
        if ($script:StartupAutomaticAttempt) { $child['ANGERONA_SUPERVISED_RECOVERY'] = '1' }
        [void]$child.Remove('QT_QPA_PLATFORM')
        $child['ANGERONA_DATA'] = $storage
        $child['ANGERONA_DIAG_DIR'] = Join-Path $storage 'diagnostics'
        $child['ANGERONA_STORAGE_AUTOMIGRATE'] = '0'
        $child['ANGERONA_INSTALL_ROOT'] = $Root
        # UI lifecycle handoff only: the verified parent owns recovery attempts.
        # This flag grants no policy/response authority and is not sent to core.
        $child['ANGERONA_STARTUP_SUPERVISED'] = '1'
        foreach ($name in @('ANGERONA_OLLAMA_MODELS', 'OLLAMA_MODELS')) {
            $value = [Environment]::GetEnvironmentVariable($name)
            if ($null -ne $value) { $child[$name] = $value }
        }
        $savedTemp, $savedTmp = $env:TEMP, $env:TMP
        try {
            $env:TEMP = $scratch; $env:TMP = $scratch
            Initialize-OwnedRepairProcess
        } finally { $env:TEMP = $savedTemp; $env:TMP = $savedTmp }
        $abi = "import sys,sysconfig; raise SystemExit(0 if sys.version_info[:2] == (3, 12) and sysconfig.get_platform() == 'win-amd64' else 81)"
        $code = Invoke-OwnedRepairProcess -FilePath $python -Arguments @('-c', $abi) `
            -WorkingDirectory $Root -Environment $child -TimeoutSeconds 30 -LogPath (Join-Path $scratch 'abi.log')
        if ($code -ne 0) { if ($code -eq 81) { return 81 }; return 85 }
        if (Test-SourceStartupShellClosed) { return 1223 }
        $pip = @'
import importlib.metadata as m
try:
    raise SystemExit(0 if m.version('pip') == '26.2.2' else 82)
except m.PackageNotFoundError:
    raise SystemExit(82)
'@
        $code = Invoke-OwnedRepairProcess -FilePath $python -Arguments @('-c', $pip) `
            -WorkingDirectory $Root -Environment $child -TimeoutSeconds 30 -LogPath (Join-Path $scratch 'pip.log')
        if ($code -ne 0) { if ($code -eq 82) { return 82 }; return 85 }
        if (Test-SourceStartupShellClosed) { return 1223 }
        $code = Invoke-OwnedRepairProcess -FilePath $python -Arguments @((Join-Path $Root 'tools\source_trust_preflight.py')) `
            -WorkingDirectory $Root -Environment $child -TimeoutSeconds 30 -LogPath (Join-Path $scratch 'source-trust.log')
        if ($code -ne 0) { return 85 }
        if (Test-SourceStartupShellClosed) { return 1223 }
        if ($SetupOnly) {
            $arguments = @('-m', 'angerona.startup', '--check-only', '--chill')
            if ($SoftwareRenderer) { $arguments += '--software-renderer' }
            return Invoke-OwnedRepairProcess -FilePath $python -Arguments $arguments `
                -WorkingDirectory $Root -Environment $child -TimeoutSeconds 120 -LogPath (Join-Path $scratch 'source-setup.log')
        }
        return Invoke-SourceStartupAssistant -Python $python -Root $Root -Environment $child `
            -Scratch $scratch -SoftwareRenderer:$SoftwareRenderer -NoStartupWindow:$NoStartupWindow
    } finally { Exit-RepairLease -Lease $lease }
}

function Invoke-SourceStartupRepair([string]$Root, [string]$Category) {
    # A completed helper has exited and its launch lease has been released.
    # Repair independently acquires that same lease, validates authority and
    # refuses a still-live dashboard. This is the only repair call site.
    $powershell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $previousCritical = $script:SourceStartupCriticalMode
    $script:SourceStartupCriticalMode = $false
    try {
    $storage = Initialize-SourceStartupStorage
    $scratch = New-SourceStartupTemporary -Root $Root -Storage $storage
    $environment = New-RepairChildEnvironment $scratch
    $log = Join-Path $scratch 'verified-repair.log'
    $savedTemp, $savedTmp = $env:TEMP, $env:TMP
    try {
        $env:TEMP = $scratch; $env:TMP = $scratch
        Initialize-OwnedRepairProcess
    } finally { $env:TEMP = $savedTemp; $env:TMP = $savedTmp }
    Write-SourceStartupEvent 'repair' 'started' "Verified $Category repair; command output: $log"
    # Capture output separately: returning native stdout together with LASTEXITCODE
    # made a successful verbose repair look like a nonzero array to the caller.
    $code = Invoke-OwnedRepairProcess -FilePath $powershell -Arguments @('-NoProfile', '-NonInteractive',
        '-File', (Join-Path $Root 'tools\Invoke-AngeronaStartupRepair.ps1'), '-RepositoryRoot', $Root,
        '-FailureCategory', $Category, '-Attempt', '1') -WorkingDirectory $Root `
        -Environment $environment -TimeoutSeconds 1100 -LogPath $log
    try {
        $tail = Read-SourceStartupLogTail $log
        if ($code -ne 0) { $script:LastStartupIssue = $tail }
        Write-Host $tail
        Write-SourceStartupEvent 'repair' 'finished' $tail ([int]$code) $Category
    } catch {
        $script:LastStartupIssue = "Verified repair returned native exit $code; its diagnostic tail is unavailable."
        Write-Host "[startup] $script:LastStartupIssue"
    }
    return [int]$code
    } finally { $script:SourceStartupCriticalMode = $previousCritical }
}

function Invoke-SourceStartupLoop([string]$Root, [switch]$SetupOnly) {
    $previousCritical = $script:SourceStartupCriticalMode
    $script:SourceStartupCriticalMode = $true
    $categories = @{ 81 = 'Runtime'; 82 = 'Dependencies'; 83 = 'GuiRuntime' }
    $repairs = @{}
    $software = $false
    $noWindow = $false
    $sourceStrategies = @{}
    $sourceReportId = ''
    $automaticSourceRetry = $false
    try {
    while ($true) {
        if (!$SetupOnly) {
            try { Start-SourceStartupShell $Root }
            catch {
                $script:LastStartupIssue = $_.Exception.Message
                Write-SourceStartupEvent 'startup-interface' 'infrastructure-held' $_.Exception.Message 85
                $choice = Invoke-SourceRecoveryWindow $Root $script:LastStartupIssue
                if ($choice -eq 10) { continue }
                return 1223
            }
        }
        if (('Angerona.StartupRepairProcess' -as [type]) -and [Angerona.StartupRepairProcess]::CustodyPending) {
            if (!$SetupOnly) { [void](Invoke-SourceRecoveryWindow $Root 'Owned process retirement requires review.') }
            return 85
        }
        if (Test-SourceStartupShellClosed) { return 1223 }
        if (!(Test-SourceStartupCapturesRetired)) {
            if ($SetupOnly) { return 85 }
            $choice = Invoke-SourceRecoveryWindow $Root $script:LastStartupIssue
            if ($choice -eq 10) { continue }
            return 1223
        }
        $enabled = !$script:StartupRecoveryPreferences -or $script:StartupRecoveryPreferences.Enabled
        $githubEnabled = !$script:StartupRecoveryPreferences -or $script:StartupRecoveryPreferences.Github
        $sourceAdmission = 0
        $script:StartupLaunchSourceDigest = ''
        # Coherence is mandatory before any app import, including --check-only.
        # Advisory diagnostic availability must never control this safety gate.
        if ($true) {
            try {
                # Inspect first. Sharing Python for a read-only review must not
                # make every ordinary launch request an exclusive source repair.
                $pendingCode = Invoke-SourceCodeAction -Root $Root -Action 'inspect'
                $inspection = $script:LastSourceRecoveryResult
                if ($pendingCode -ne 81 -and (!$inspection -or $inspection.requires_mutation -isnot [bool] -or
                    $inspection.pending_kind -cnotin @('none', 'edits', 'transaction') -or
                    $inspection.requires_mutation -ne ($inspection.pending_kind -cne 'none') -or
                    ($inspection.pending_kind -ceq 'transaction' -and !$inspection.launch_held))) {
                    throw 'The read-only source coherence response is incomplete or invalid.'
                }
                if ($pendingCode -ne 81 -and $enabled -and !$SetupOnly -and $inspection.requires_mutation) {
                    $pendingCode = Invoke-SourceCodeAction -Root $Root -Action 'apply-pending'
                }
                if ($pendingCode -eq 81) { $sourceAdmission = 81 }
                elseif ($pendingCode -ne 0 -or !$script:LastSourceRecoveryResult -or $script:LastSourceRecoveryResult.launch_held) { $sourceAdmission = 1 }
                if ($script:LastSourceRecoveryResult.report_id) { $sourceReportId = [string]$script:LastSourceRecoveryResult.report_id }
            } catch {
                if ($_.Exception.Data['AngeronaRepairPending'] -eq $true) { $sourceAdmission = 81 }
                else { $sourceAdmission = 1 }
                $script:LastStartupIssue = $_.Exception.Message
                Write-SourceStartupEvent 'source-admission' 'held' $_.Exception.Message
            }
            if ($sourceAdmission -eq 1) {
                if ($SetupOnly) { return 1 }
                $choice = Invoke-SourceRecoveryWindow $Root 'Source coherence or its exclusive startup lease could not be established. No application source or security engine will be loaded until recovery is resolved.'
                if ($choice -eq 10) { continue }
                return 1223
            }
            if ($sourceAdmission -eq 0 -and !$SetupOnly) {
                try {
                    $fingerprintCode = Invoke-SourceCodeAction -Root $Root -Action 'fingerprint'
                    if ($fingerprintCode -eq 81) { $sourceAdmission = 81 }
                    elseif ($fingerprintCode -eq 0 -and !$script:LastSourceRecoveryResult.launch_held -and
                        $script:LastSourceRecoveryResult.source_digest -cmatch '^[0-9a-f]{64}$') {
                        $script:StartupLaunchSourceDigest = [string]$script:LastSourceRecoveryResult.source_digest
                    } else { $sourceAdmission = 1 }
                } catch {
                    $sourceAdmission = 1
                    $script:LastStartupIssue = $_.Exception.Message
                    Write-SourceStartupEvent 'source-fingerprint' 'held' $_.Exception.Message
                }
                if ($sourceAdmission -eq 1) {
                    $choice = Invoke-SourceRecoveryWindow $Root 'The source fingerprint or its exclusive lease could not be established. Startup is held for review.'
                    if ($choice -eq 10) { continue }
                    return 1223
                }
            }
        }
        $strategy = if ($noWindow) { 'verified-without-startup-window' } elseif ($software) { 'verified-software-renderer' } else { 'verified-normal-startup' }
        Write-SourceStartupStatus 'startup' 'checking' "Trying $strategy. All runtime, data and dashboard checks remain required."
        try {
            if ($sourceAdmission -eq 81) { $code = 81 }
            else {
                # Attempt history already retains earlier failures. Only a
                # diagnostic from this pass may describe its native result.
                $script:LastStartupIssue = ''
                $script:StartupAutomaticAttempt = $automaticSourceRetry
                $code = [int](Invoke-SourceStartupPass -Root $Root -SetupOnly:$SetupOnly `
                    -SoftwareRenderer:$software -NoStartupWindow:$noWindow)
            }
        }
        catch {
            # Only a returned native application exit 1 can select application
            # source recovery. Launcher, scratch, lease, compiler, process and
            # capture-admission exceptions are infrastructure holds instead.
            $code = 85
            $script:LastStartupIssue = $_.Exception.Message
            Write-SourceStartupEvent 'startup' 'infrastructure-held' $_.Exception.Message $code $strategy
            Write-Host "[startup] $($_.Exception.Message)"
        }
        Add-SourceStartupAttempt $strategy $code $script:LastStartupIssue
        if ($code -eq 1223) {
            Write-SourceStartupStatus 'startup' 'closed' 'Startup monitoring was cancelled. Further attempts are stopped; any actual dashboard remains preserved.'
            return 1223
        }
        if ($code -eq 86) {
            Write-SourceStartupStatus 'startup' 'operator-stopped' 'Authenticated STOP was honored. No dashboard readiness or protection was claimed.'
            return 0
        }
        if ($code -eq 0) {
            $script:StartupDashboardVerified = !$SetupOnly
            if ($SetupOnly) { Write-SourceStartupStatus 'preflight' 'verified' 'Setup checks passed. No dashboard was launched or observed.' }
            else { Write-SourceStartupStatus 'dashboard' 'verified' 'The dashboard readiness receipt passed; protection coverage is reported separately by the application.' }
            if (!$SetupOnly -and $script:StartupDiagnosticRoot) { Complete-SourceStartupRecovery $Root }
            return 0
        }
        if (Test-SourceStartupShellClosed) { return 1223 }
        if ($enabled -and $code -eq 1 -and $script:StartupDiagnosticRoot -and !$SetupOnly) {
            $automaticSourceRetry = $true
            $restored = $false
            foreach ($sourceStrategy in @('last-ready', 'github-head', 'github-parent')) {
                if (!$githubEnabled -and $sourceStrategy.StartsWith('github-')) { continue }
                if ($sourceStrategies.ContainsKey($sourceStrategy)) { continue }
                $sourceStrategies[$sourceStrategy] = $true
                Write-Host "[startup] Checking bounded, preserved source recovery: $sourceStrategy"
                try {
                    $sourceCode = Invoke-SourceCodeAction -Root $Root -Action 'recover' -Strategy $sourceStrategy -ExpectedId $sourceReportId
                    if ($script:LastSourceRecoveryResult -and $script:LastSourceRecoveryResult.report_id) {
                        $sourceReportId = [string]$script:LastSourceRecoveryResult.report_id
                    }
                } catch { $sourceCode = 1; $script:LastStartupIssue = $_.Exception.Message; Write-SourceStartupEvent 'source-recovery' 'held' $_.Exception.Message 1 $sourceStrategy }
                Add-SourceStartupAttempt "source-$sourceStrategy" $sourceCode $script:LastStartupIssue
                if ($script:LastSourceRecoveryResult.launch_held) { break }
                if ($sourceCode -eq 0 -and $script:LastSourceRecoveryResult.changed) { $restored = $true; break }
            }
            if ($restored) { $software = $false; $noWindow = $false; continue }
        }
        if ($enabled -and $code -in @(84, 87) -and !$noWindow -and !$SetupOnly) {
            $noWindow = $true
            Write-Host '[startup] Trying the independent non-Tk bootstrap after a startup-window failure or fully retired preflight timeout; every dependency and dashboard check remains required.'
            continue
        }
        if ($enabled -and $code -eq 83 -and !$software) {
            $software = $true
            Write-Host '[startup] Trying a clean software-rendering environment, with the same startup checks.'
            continue
        }
        if ($enabled -and $categories.ContainsKey($code) -and !$repairs.ContainsKey($code)) {
            $category = $categories[$code]; $repairs[$code] = $true
            Write-Host "Attempting verified $category recovery; settings and evidence are preserved."
            try { $repairCode = [int](Invoke-SourceStartupRepair -Root $Root -Category $category) }
            catch {
                $repairCode = 1
                $script:LastStartupIssue = $_.Exception.Message
                Write-SourceStartupEvent 'repair' 'exception' $_.Exception.Message $repairCode $category
                Write-Host "[startup] Repair details: $($_.Exception.Message)"
            }
            Add-SourceStartupAttempt "repair-$category" $repairCode $script:LastStartupIssue
            if ($repairCode -eq 0) {
                Write-Host 'Repair verification passed. Rechecking the complete startup boundary...'
                continue
            }
        }
        if ($SetupOnly) { return 1 }
        $message = if ($code -in @(85, 87, 124, 125)) {
            'Launcher infrastructure or monitoring is held. This result does not establish an application-source defect; no source rollback or runtime reinstall was selected. Any existing assistant or dashboard generation is preserved. Review the diagnostic phase before Retry, which repeats the complete ownership and startup checks. Protection remains unverified.'
        } else {
            'Normal startup is not ready. Automatic distinct verified strategies have been tried for this failure. The independent recovery screen remains available; Retry runs the complete checks again. No protection or successful repair is inferred from an open recovery window.'
        }
        if ($script:LastStartupIssue) { $message += "`n`nReported failure: " + (Protect-SourceStartupText $script:LastStartupIssue 2000) }
        $choice = Invoke-SourceRecoveryWindow $Root $message
        if ($choice -ne 10) { Write-SourceStartupStatus 'recovery' 'closed' 'Recovery was closed by the operator.'; return 1223 }
        # Only an explicit user Retry starts a fresh round; ambient flags and
        # repeated identical failures cannot create an unattended repair loop.
        $repairs = @{}; $software = $false; $noWindow = $false; $sourceStrategies = @{}; $automaticSourceRetry = $false
    }
    } finally {
        if ($script:StartupShell) {
            if ($script:StartupDashboardVerified) { [void]$script:StartupShell.WaitForExit(10000) }
            $script:StartupShell.Dispose()
            $script:StartupShell = $null
        }
        Close-SourceStartupCriticalWorkspaces
        $script:SourceStartupCriticalMode = $previousCritical
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        Assert-SourceStartupHost
        $fixedRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
        if ($RepositoryRoot -and ![string]::Equals([IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\'), $fixedRoot.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
            throw 'The source startup repository does not match this fixed launcher.'
        }
        Assert-SourceStartupSupervisorBoundary $fixedRoot
        . (Join-Path $fixedRoot 'tools\startup_repair_common.ps1')
        $script:SourceStartupCriticalMode = $true
        $script:StartupRecoveryPreferences = @{ Enabled = $false; Github = $false }
        try {
            $storage = Initialize-SourceStartupStorage
            $script:StartupRecoveryPreferences = Read-SourceStartupRecoveryPreferences $storage
            Initialize-SourceStartupDiagnostics $storage
        }
        catch { Write-Host "[startup] Persistent diagnostics unavailable: $($_.Exception.Message)" }
        $result = Invoke-SourceStartupLoop -Root $fixedRoot -SetupOnly:$SetupOnly
        if (('Angerona.StartupRepairProcess' -as [type]) -and [Angerona.StartupRepairProcess]::CustodyPending) { exit 85 }
        exit $result
    } catch {
        Write-Host "[!] Angerona Safe Startup: $($_.Exception.Message)"
        Write-SourceStartupEvent 'supervisor' 'exception' $_.Exception.Message 1
        if (!$SetupOnly -and $fixedRoot) {
            $choice = Invoke-SourceRecoveryWindow $fixedRoot $_.Exception.Message
            if (('Angerona.StartupRepairProcess' -as [type]) -and [Angerona.StartupRepairProcess]::CustodyPending) { exit 85 }
            if ($choice -eq 10) { exit 10 }
            exit 1223
        }
        exit 1
    }
}
