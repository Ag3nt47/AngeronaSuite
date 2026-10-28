# This readable payload is embedded in start-angerona.bat by the manifest builder
# companion. The editable source batch file is its trust anchor, not an enclave.
$ErrorActionPreference='Stop'
$manifestSha='__MANIFEST_SHA256__'
$manifestBlob='__MANIFEST_BLOB_SHA1__'
$verifierSha='__VERIFIER_SHA256__'
$verifierBlob='__VERIFIER_BLOB_SHA1__'
$root=[IO.Path]::GetFullPath($env:ANGERONA_INSTALL_ROOT).TrimEnd('\')
$storage=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Angerona\SourceData'
$script:BootstrapCanonicalStorage=$storage
$fixedPS=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'

function Assert-BootstrapPlainPath([string]$Path) {
    if($Path -notmatch '^[a-zA-Z]:\\' -or $Path.StartsWith('\\')) { throw 'Startup requires a fixed local path.' }
    $cursor=[IO.Path]::GetFullPath($Path)
    while($cursor) {
        if(Test-Path -LiteralPath $cursor) {
            $item=Get-Item -LiteralPath $cursor -Force
            if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.LinkType -eq 'HardLink') {
                throw 'Startup refuses redirected or hardlinked recovery paths.'
            }
        }
        $cursor=[IO.Path]::GetDirectoryName($cursor)
    }
}
function Assert-BootstrapPrivate([string]$Path, [switch]$AllowInherited) {
    Assert-BootstrapPlainPath $Path
    $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $item=Get-Item -LiteralPath $Path -Force
    $acl=if($item.PSIsContainer) {[IO.Directory]::GetAccessControl($Path)} else {[IO.File]::GetAccessControl($Path)}
    if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $owner) { throw 'Recovery state has an unexpected owner.' }
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -notin @($owner,'S-1-5-18','S-1-5-32-544')) {
            throw 'Recovery state lacks private custody.'
        }
    }
}
function New-BootstrapPrivateDirectory([string]$Path) {
    Assert-BootstrapPlainPath $Path
    if(!(Test-Path -LiteralPath $Path)) {
        $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetOwner($owner);$acl.SetAccessRuleProtection($true,$false)
        foreach($sid in @($owner.Value,'S-1-5-18','S-1-5-32-544')) {
            [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
                [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
        }
        [void][IO.Directory]::CreateDirectory($Path,$acl)
    }
    Assert-BootstrapPrivate $Path
}
function Get-BootstrapCanonical([byte[]]$Raw) {
    $text=[Text.UTF8Encoding]::new($false,$true).GetString($Raw)
    if($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text=$text.Substring(1) }
    $text=$text.Replace("`r`n","`n")
    if($text.Contains("`r") -or $text.Contains([string][char]0)) { throw 'Recovery verifier text is invalid.' }
    return ,([Text.UTF8Encoding]::new($false).GetBytes($text))
}
function Get-BootstrapHash([byte[]]$Raw) {
    $algorithm=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($Raw))).Replace('-','').ToLowerInvariant() }
    finally { $algorithm.Dispose() }
}
function Get-BootstrapBlob([byte[]]$Raw) {
    $header=[Text.Encoding]::ASCII.GetBytes(('blob '+$Raw.Length+[char]0))
    $joined=New-Object byte[] ($header.Length+$Raw.Length)
    [Buffer]::BlockCopy($header,0,$joined,0,$header.Length);[Buffer]::BlockCopy($Raw,0,$joined,$header.Length,$Raw.Length)
    $algorithm=[Security.Cryptography.SHA1]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($joined))).Replace('-','').ToLowerInvariant() }
    finally { $algorithm.Dispose() }
}

# __PREFERENCES_FUNCTION__

# __BUNDLE_NATIVE_FUNCTION__

function Get-BundleDataRoot { return $script:BootstrapCanonicalStorage }
# __BUNDLE_LOCK_FUNCTIONS__

function Show-BootstrapRecovery([string]$Message) {
    Write-Host ('[startup] '+$Message)
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $form=[Windows.Forms.Form]::new();$form.Text='Angerona startup recovery';$form.Width=700;$form.Height=330
        $form.StartPosition='CenterScreen'
        $label=[Windows.Forms.TextBox]::new();$label.Multiline=$true;$label.ReadOnly=$true
        $label.Dock='Fill';$label.ScrollBars='Vertical'
        $label.Text="Angerona could not verify its recovery files. Protection is not verified.`r`n`r`n$Message`r`n`r`nSettings and evidence were preserved. Review the recovery settings or restore the official source launcher. Retry repeats verification."
        $buttons=[Windows.Forms.FlowLayoutPanel]::new();$buttons.Dock='Bottom';$buttons.Height=50
        $retry=[Windows.Forms.Button]::new();$retry.Text='Retry';$retry.Width=120;$retry.DialogResult='Retry'
        $close=[Windows.Forms.Button]::new();$close.Text='Close';$close.Width=120;$close.DialogResult='Cancel'
        $buttons.Controls.Add($retry);$buttons.Controls.Add($close);$form.Controls.Add($label);$form.Controls.Add($buttons)
        try { if($form.ShowDialog() -eq 'Retry') { return 10 };return 1223 } finally {$form.Dispose()}
    } catch { Write-Host '[startup] Recovery display unavailable; retain this console.'; return 1 }
}

$verifierLease=$null
$bootstrapMutation=@()
try {
    Assert-BootstrapPlainPath $root
    $drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($root))
    if(!$drive.IsReady -or $drive.DriveType -ne 'Fixed') { throw 'Source startup requires a ready fixed local drive.' }
    $prefs=Read-SourceStartupRecoveryPreferences $storage
    $path=Join-Path $root 'tools\verify_startup_recovery_bundle.ps1'
    Assert-BootstrapPlainPath $path
    $archive=Join-Path $storage 'logs\startup-recovery\bootstrap-preserved'
    New-BootstrapPrivateDirectory $archive
    Initialize-BundleNative $archive
    $raw=$null;$valid=$false
    if(Test-Path -LiteralPath $path) {
        $verifierLease=[Angerona.StartupBundleFile]::new($path,$false,$false)
        $raw=$verifierLease.Read(2097152)
        try {$valid=(Get-BootstrapHash (Get-BootstrapCanonical $raw)) -ceq $verifierSha} catch {$valid=$false}
    }
    if(!$valid) {
        if(!$prefs.Enabled -or !$prefs.Github) { throw 'Pinned recovery verifier is missing or changed; automatic GitHub recovery is disabled in Settings.' }
        $bootstrapMutation=Enter-BundleMutationLocks $root
        # No latest-branch code executes. Download only this exact pinned blob,
        # validate all bytes, and preserve any existing edits before replacement.
        [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
        $request=[Net.HttpWebRequest]::Create('https://api.github.com/repos/Ag3nt47/AngeronaSuite/git/blobs/'+$verifierBlob)
        $request.Proxy=$null;$request.UserAgent='Angerona-Pinned-Recovery';$request.Timeout=15000;$request.ReadWriteTimeout=15000
        $request.AllowAutoRedirect=$false
        $response=$request.GetResponse()
        try {
            $body=$response.GetResponseStream();$memory=[IO.MemoryStream]::new();$buffer=New-Object byte[] 8192
            $clock=[Diagnostics.Stopwatch]::StartNew()
            try {
                while(($count=$body.Read($buffer,0,$buffer.Length)) -gt 0) {
                    if($memory.Length+$count -gt 4MB -or $clock.Elapsed.TotalSeconds -gt 30) {throw 'Pinned recovery download exceeded its bound.'}
                    $memory.Write($buffer,0,$count)
                }
                $record=[Text.UTF8Encoding]::new($false,$true).GetString($memory.ToArray())|ConvertFrom-Json
            } finally {$memory.Dispose();$body.Dispose()}
        } finally {$response.Dispose()}
        if($record.encoding -cne 'base64' -or $record.sha -cne $verifierBlob -or $record.size -gt 2MB) { throw 'Pinned recovery response is invalid.' }
        $candidate=[Convert]::FromBase64String($record.content)
        if($candidate.Length -ne $record.size -or (Get-BootstrapBlob $candidate) -cne $verifierBlob -or
            (Get-BootstrapHash $candidate) -cne $verifierSha) { throw 'Pinned recovery verifier bytes do not match the published pins.' }
        $count=0;$total=0L
        foreach($file in [IO.Directory]::EnumerateFiles($archive)) {
            Assert-BootstrapPrivate $file;$count++;$total+=(Get-Item -LiteralPath $file).Length
            if($count -ge 16 -or $total -gt 32MB) {throw 'Preserved bootstrap edits reached their limit; review them before recovery.'}
        }
        if($null -ne $raw -and $total+$raw.Length -gt 32MB) {throw 'Preserved bootstrap edits would exceed their 32 MiB limit.'}
        foreach($base in @($archive,$root)) {
            if(([IO.DriveInfo]::new([IO.Path]::GetPathRoot($base))).AvailableFreeSpace -lt (2GB+4MB)) {throw 'Recovery preserves a 2 GiB free-space reserve.'}
        }
        if($verifierLease) {$verifierLease.Dispose();$verifierLease=$null}
        # Recheck the edited generation before publication; never overwrite a
        # concurrent new edit or remove a path outside this one fixed leaf.
        if(Test-Path -LiteralPath $path) {
            Assert-BootstrapPlainPath $path
            $check=[Angerona.StartupBundleFile]::new($path,$false,$true)
            try {
                if($null -eq $raw -or (Get-BootstrapHash ($check.Read(2097152))) -cne (Get-BootstrapHash $raw)) {throw 'Recovery verifier changed during review.'}
                $backup=Join-Path $archive (([Guid]::NewGuid().ToString('N'))+'.verifier.edited')
                $output=[Angerona.StartupBundleFile]::new($backup,$true,$false)
                try {$output.Write($raw)} finally {$output.Dispose()}
                Assert-BootstrapPrivate $backup
                $check.Delete()
            } finally {$check.Dispose()}
        } elseif($null -ne $raw) {
            throw 'The recovery verifier disappeared during review; edited bytes were not overwritten.'
        }
        $output=[Angerona.StartupBundleFile]::new($path,$true,$false)
        try {$output.Write($candidate)} finally {$output.Dispose()}
        $verifierLease=[Angerona.StartupBundleFile]::new($path,$false,$false)
        if((Get-BootstrapHash (Get-BootstrapCanonical ($verifierLease.Read(2097152)))) -cne $verifierSha) {throw 'Recovery verifier publication did not verify.'}
        Write-Host ('[startup] Restored the exact pinned recovery verifier. Preserved edits: '+$archive)
        $env:ANGERONA_BOOTSTRAP_RESTORED='1'
    }
    Close-BundleMutationLocks $bootstrapMutation;$bootstrapMutation=@()
    $arguments=@('-NoProfile','-NonInteractive','-File',$path,'-Root',$root,'-ManifestSha256',$manifestSha,
        '-ManifestBlobSha1',$manifestBlob,'-ExpectedVerifierSha256',$verifierSha,'-RunSupervisor')
    if(!$prefs.Enabled) {$arguments+='-CheckOnly'}
    if(!$prefs.Github) {$arguments+='-Offline'}
    if($env:ANGERONA_SETUP_ONLY -eq '1') {$arguments+='-SetupOnly'}
    & $fixedPS @arguments
    $code=[int]$LASTEXITCODE
    if($code -notin @(0,10,1223) -and $env:ANGERONA_SETUP_ONLY -ne '1') {
        exit (Show-BootstrapRecovery 'Recovery bundle or supervisor checks were held. Review the private startup-recovery diagnostics for the failing phase and preserved files.')
    }
    exit $code
} catch {
    if($env:ANGERONA_SETUP_ONLY -eq '1') {Write-Host ('[startup] '+$_.Exception.Message);exit 1}
    exit (Show-BootstrapRecovery $_.Exception.Message)
} finally {
    if($verifierLease) {$verifierLease.Dispose()}
    Close-BundleMutationLocks $bootstrapMutation
}
