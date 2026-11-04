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


# Pending source activation is checked using only this launcher anchor and
# fixed system APIs BEFORE any mutable verifier/supervisor/common is imported.
function Assert-ActivationBootstrapCustody([string]$Path) {
    Assert-BootstrapPlainPath $Path
    $item=Get-Item -LiteralPath $Path -Force
    $acl=if($item.PSIsContainer){[IO.Directory]::GetAccessControl($Path)}else{[IO.File]::GetAccessControl($Path)}
    $user=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $user){throw 'Original activation custody owner differs.'}
    $raw=[Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0)
    if(!$raw.DiscretionaryAcl -or $raw.DiscretionaryAcl.Count -ne 3){throw 'Original activation DACL count differs.'}
    if($item.PSIsContainer -and !$acl.AreAccessRulesProtected){throw 'Original activation directory is unprotected.'}
    $seen=@{}
    foreach($ace in $raw.DiscretionaryAcl){
        $sid=$ace.SecurityIdentifier.Value
        if($ace.AceType -ne [Security.AccessControl.AceType]::AccessAllowed -or $ace.AccessMask -ne 2032127 -or
            ($item.PSIsContainer -and [int]$ace.AceFlags -ne 3) -or
            (!$item.PSIsContainer -and [int]$ace.AceFlags -notin @(0,16)) -or
            $sid -cnotin @($user,'S-1-3-4','S-1-5-18','S-1-5-32-544') -or $seen.ContainsKey($sid)){
            throw 'Original activation custody has an unknown access rule.'
        }
        $seen[$sid]=$true
    }
    if(!$seen.ContainsKey('S-1-5-18') -or !$seen.ContainsKey('S-1-5-32-544') -or
        ($seen.ContainsKey($user) -eq $seen.ContainsKey('S-1-3-4'))){throw 'Original activation custody principals differ.'}
    if(!$item.PSIsContainer){Assert-ActivationBootstrapCustody ([IO.Path]::GetDirectoryName($Path))}
}
function Read-ActivationBootstrapRecord([string]$Path,[int]$Limit,$Holds,[switch]$BytesOnly) {
    Assert-ActivationBootstrapCustody $Path
    $lease=[Angerona.StartupBundleFile]::new($Path,$false,$false)
    $Holds.Add($lease)
    $raw=$lease.Read($Limit)
    $value=$null
    if(!$BytesOnly){
        try{$value=[Text.UTF8Encoding]::new($false,$true).GetString($raw)|ConvertFrom-Json -ErrorAction Stop}
        catch{throw 'Original source-activation metadata is invalid.'}
        if(!$value -or $value -is [Array] -or $value -is [string]){throw 'Original activation record is not an object.'}
    }
    return [pscustomobject]@{Value=$value;Sha256=(Get-BootstrapHash $raw);Bytes=$raw.Length;Lease=$lease}
}
function Assert-ActivationBootstrapFields($Value,[string[]]$Keys){
    $actual=@($Value.PSObject.Properties.Name)
    if($actual.Count -ne $Keys.Count -or @($actual|Where-Object{$_ -cnotin $Keys}).Count){throw 'Original activation record has unknown fields.'}
}
function Get-OriginalSourceActivationCapsule($Holds) {
    $state=Join-Path $storage 'github-updates';$path=Join-Path $state 'activation-pending.json'
    Assert-BootstrapPlainPath $path
    if(!(Test-Path -LiteralPath $path)){return $null}
    if($env:ANGERONA_SETUP_ONLY -eq '1'){throw 'Setup-only mode cannot reconcile an interrupted source update.'}
    $pending=Read-ActivationBootstrapRecord $path 65536 $Holds;$q=$pending.Value
    Assert-ActivationBootstrapFields $q @('schema','activation_id','plan_sha256','request_sha256','transaction_sha256','source_root')
    if($q.schema -cne 'angerona.source-activation-pending/v1' -or $q.source_root -cne $root -or
        $q.activation_id -isnot [string] -or $q.activation_id -cnotmatch '^[0-9a-f]{32}$' -or
        @($q.plan_sha256,$q.request_sha256,$q.transaction_sha256|Where-Object{$_ -isnot [string] -or $_ -cnotmatch '^[0-9a-f]{64}$'}).Count){
        throw 'Interrupted source update identity is malformed or foreign.'
    }
    $operation=Join-Path $state ('activations\apply-'+$q.activation_id)
    $plan=Read-ActivationBootstrapRecord (Join-Path $operation 'plan.json') 16777216 $Holds
    if($plan.Sha256 -cne $q.plan_sha256 -or $plan.Value.schema -cne 'angerona.source-activation-plan/v1' -or
        $plan.Value.activation_id -cne $q.activation_id -or $plan.Value.source_root -cne $root -or
        $plan.Value.state_root -cne $state -or $plan.Value.origin -cne 'https://github.com/Ag3nt47/AngeronaSuite.git'){
        throw 'Original approved plan is unavailable.'
    }
    $transaction=Read-ActivationBootstrapRecord (Join-Path $operation 'transaction.json') 16777216 $Holds
    if($transaction.Sha256 -cne $q.transaction_sha256 -or $transaction.Value.source_root -cne $root -or
        $transaction.Value.activation_id -cne $q.activation_id){throw 'Original interrupted transaction is unavailable.'}
    $request=Read-ActivationBootstrapRecord (Join-Path $operation ('requests\'+$q.request_sha256+'.json')) 65536 $Holds
    $r=$request.Value
    if($request.Sha256 -cne $q.request_sha256 -or $r.schema -cne 'angerona.source-activation-request/v1' -or
        $r.activation_id -cne $q.activation_id -or $r.plan_sha256 -cne $q.plan_sha256 -or $r.source_root -cne $root -or
        $r.state_root -cne $state -or $r.accepted -isnot [bool] -or !$r.accepted){throw 'Original explicit approval is unavailable.'}
    $owner=Read-ActivationBootstrapRecord (Join-Path $state 'activation-owner.json') 65536 $Holds;$c=$owner.Value
    Assert-ActivationBootstrapFields $c @('schema','launch_id','source_root','state_root','supervisor_pid','supervisor_birth','supervisor_image','token',
        'broker_pid','broker_birth','broker_image','core_pid','core_birth','core_image','owner_state')
    if($owner.Sha256 -cne $r.owner_sha256 -or $c.owner_state -cne 'bound' -or $c.source_root -cne $root -or
        $c.state_root -cne $state -or $c.launch_id -cne $r.launch_id -or $c.core_pid -ne $r.core_pid -or
        $c.core_birth -cne $r.core_birth -or $c.broker_pid -ne $r.broker_pid -or $c.broker_birth -cne $r.broker_birth -or
        $c.launch_id -isnot [string] -or $c.launch_id -cnotmatch '^[0-9a-f]{32}$') {throw 'Original native-controller approval lineage differs.'}
    $launch=Join-Path $state ('launches\'+$c.launch_id)
    $descriptor=Read-ActivationBootstrapRecord (Join-Path $launch 'descriptor.json') 8192 $Holds
    $ready=Read-ActivationBootstrapRecord (Join-Path $launch 'ready.json') 8192 $Holds
    if($descriptor.Value.token -cne $c.token -or $descriptor.Value.launch_id -cne $c.launch_id -or
        $descriptor.Value.source_root -cne $root -or $descriptor.Value.state_root -cne $state -or
        $descriptor.Value.supervisor_pid -ne $c.supervisor_pid -or $descriptor.Value.supervisor_birth -cne $c.supervisor_birth -or
        $ready.Value.descriptor_sha256 -cne $descriptor.Sha256 -or $ready.Value.core_pid -ne $c.core_pid -or
        $ready.Value.core_birth -cne $c.core_birth -or $ready.Value.core_image -cne $c.core_image){throw 'Original dashboard/launch lineage differs.'}
    $retired=Read-ActivationBootstrapRecord (Join-Path $launch 'core-retired.json') 8192 $Holds;$n=$retired.Value
    Assert-ActivationBootstrapFields $n @('schema','launch_id','core_pid','core_birth','core_exit_code','native_wait0','owner_sha256')
    if($n.schema -cne 'angerona.source-activation-core-retired/v1' -or $n.launch_id -cne $c.launch_id -or
        $n.core_pid -ne $c.core_pid -or $n.core_birth -cne $c.core_birth -or $n.core_exit_code -isnot [int] -or $n.core_exit_code -ne 0 -or
        $n.native_wait0 -isnot [bool] -or !$n.native_wait0 -or $n.owner_sha256 -cne $owner.Sha256){throw 'Original actual Core exit observation is unavailable.'}
    $stop=Read-ActivationBootstrapRecord (Join-Path $storage 'diagnostics\operator-stop.json') 65536 $Holds;$t=$stop.Value
    if($t.schema -isnot [int] -or $t.schema -ne 1 -or $t.state -cne 'retired' -or
        $t.forced -isnot [bool] -or $t.forced -or $t.operator_stop_recorded -isnot [bool] -or !$t.operator_stop_recorded -or
        @($t.pending_workers).Count -or @($t.pending_custody).Count -or $t.before_cleanup_pending -ne 0 -or
        $t.cleanup_error -cne '' -or $t.discovery_error -cne ''){throw 'Original managed STOP is incomplete.'}
    Assert-ActivationBootstrapFields $t.source_activation @('launch_id','activation_id','request_sha256','core_pid','core_birth')
    if($t.source_activation.launch_id -cne $c.launch_id -or $t.source_activation.activation_id -cne $q.activation_id -or
        $t.source_activation.request_sha256 -cne $q.request_sha256 -or $t.source_activation.core_pid -ne $c.core_pid -or
        $t.source_activation.core_birth -cne $c.core_birth){throw 'Managed STOP belongs to another source request.'}
    $capsule=Join-Path $operation 'broker'
    $snapshot=Read-ActivationBootstrapRecord (Join-Path $capsule 'snapshot.json') 65536 $Holds
    $names=@('tools/activate_source_update.py','src/angerona/core/source_activation_broker.py','src/angerona/core/source_activation_file.py',
        'src/angerona/core/startup_recovery.py','src/angerona/updater/source_git.py','tools/publication_transport.py',
        'tools/windows_publication_runtime.py','tools/publication_git_runtime_profile.json','tools/Resume-AngeronaSourceActivation.ps1','tools/startup_repair_common.ps1','src/angerona/core/source_activation_storage.py','src/angerona/resilience/heartbeat.py',
        'src/angerona/core/_source_tomli/__init__.py','src/angerona/core/_source_tomli/_parser.py','src/angerona/core/_source_tomli/_re.py','src/angerona/core/_source_tomli/_types.py','src/angerona/core/_source_tomli/LICENSE','src/angerona/core/source_activation_workspace.py')
    Assert-ActivationBootstrapFields $snapshot.Value @('schema','files')
    Assert-ActivationBootstrapFields $snapshot.Value.files $names
    Assert-ActivationBootstrapFields $plan.Value.broker_snapshot.files $names
    if($snapshot.Value.schema -cne 'angerona.source-activation-broker-snapshot/v1' -or
        $plan.Value.broker_snapshot.schema -cne $snapshot.Value.schema){throw 'Original capsule schema differs.'}
    $total=0L
    foreach($name in $names){
        $row=$snapshot.Value.files.PSObject.Properties[$name].Value
        $declared=$plan.Value.broker_snapshot.files.PSObject.Properties[$name].Value
        Assert-ActivationBootstrapFields $row @('bytes','sha256')
        if($row.bytes -isnot [int] -or $row.bytes -lt 1 -or $row.bytes -gt 4194304 -or
            $row.sha256 -isnot [string] -or $row.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $declared.bytes -ne $row.bytes -or $declared.sha256 -cne $row.sha256){throw 'Original capsule member declaration differs.'}
        $file=Read-ActivationBootstrapRecord (Join-Path $capsule ($name.Replace('/','\'))) 4194304 $Holds -BytesOnly
        if($file.Bytes -ne $row.bytes -or $file.Sha256 -cne $row.sha256){throw 'Original capsule member changed.'}
        $total+=$file.Bytes;if($total -gt 4194304){throw 'Original capsule exceeds its aggregate budget.'}
    }
    # Pending itself must be movable by the original transaction after all
    # immutable inputs/capsule members are sealed and independently rechecked.
    $pending.Lease.Dispose();[void]$Holds.Remove($pending.Lease)
    return [pscustomobject]@{Id=$q.activation_id;PlanSha=$q.plan_sha256;RequestSha=$q.request_sha256
        Resume=(Join-Path $capsule 'tools\Resume-AngeronaSourceActivation.ps1');Capsule=$capsule;State=$state;Operation=$operation}
}

function Invoke-OriginalSourceActivationHandoff($Bound,$Holds,[switch]$ConfirmReconciliation) {
    # Only exact already-sealed ORIGINAL code can define these helpers.
    . (Join-Path $Bound.Capsule 'tools\startup_repair_common.ps1')
    . $Bound.Resume
    Initialize-SourceActivationProcessOwner
    $gateOwner=$null;$cmdOwner=$null;$nextOwner=$null;$process=$null;$transferred=$false
    try {
        $gateOwner=[Angerona.SourceActivationProcessOwner]::new([uint32]$PID)
        $gateOwner.AssertLive($gateOwner.Birth,$fixedPS)
        if($gateOwner.InAnyJob()){throw 'Automatic recovery owner cannot prove survival outside the invoking host Job. Close this launcher and use the verified fixed Resume helper separately.'}
        $cmdOwner=[Angerona.SourceActivationProcessOwner]::new($gateOwner.ParentProcessId())
        Assert-SourceActivationBatchParent $cmdOwner $root
        $nonce=[Guid]::NewGuid().ToString('N')
        $handoffs=Join-Path $Bound.Operation 'handoffs'
        if(!(Test-Path -LiteralPath $handoffs)){New-PrivateRepairDirectory $handoffs}
        Assert-SourceActivationCustody $handoffs
        $count=0;foreach($entry in [IO.Directory]::EnumerateFileSystemEntries($handoffs)){if(++$count -ge 32){throw 'Recovery handoff history requires review; nothing was deleted.'}}
        $directory=Join-Path $handoffs $nonce;New-PrivateRepairDirectory $directory
        $args=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$Bound.Resume,
            '-RepositoryRoot',$root,'-ActivationId',$Bound.Id,'-PlanSha256',$Bound.PlanSha,'-RequestSha256',$Bound.RequestSha,
            '-GatePid',[string]$PID,'-GateBirth',[string]$gateOwner.Birth,'-CmdPid',[string]$cmdOwner.ProcessId,
            '-CmdBirth',[string]$cmdOwner.Birth,'-HandoffNonce',$nonce)
        if($ConfirmReconciliation){$args+='-ConfirmReconciliation'}
        $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$fixedPS
        $info.Arguments=($args|ForEach-Object{ConvertTo-SourceActivationArgument ([string]$_)}) -join ' '
        $info.WorkingDirectory=$Bound.Capsule;$info.UseShellExecute=$false;$info.CreateNoWindow=$true
        $info.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden;$info.EnvironmentVariables.Clear()
        foreach($entry in (New-RepairChildEnvironment $directory).GetEnumerator()){$info.EnvironmentVariables[$entry.Key]=[string]$entry.Value}
        $process=[Diagnostics.Process]::Start($info)
        if(!$process){throw 'The one fixed original recovery owner did not start.'}
        $nextOwner=[Angerona.SourceActivationProcessOwner]::new([uint32]$process.Id)
        $nextOwner.AssertLive($nextOwner.Birth,$fixedPS)
        if($nextOwner.InAnyJob() -or $nextOwner.ParentProcessId() -ne $PID){throw 'Independent original recovery owner ancestry/lifetime is unavailable.'}
        $ackPath=Join-Path $directory 'ready.json';$deadline=[DateTime]::UtcNow.AddSeconds(10)
        while(!(Test-Path -LiteralPath $ackPath) -and [DateTime]::UtcNow -lt $deadline){
            if($nextOwner.WaitForExit(0) -eq 0){throw 'Original recovery owner exited before handoff.'};Start-Sleep -Milliseconds 50
        }
        $ack=Read-ActivationBootstrapRecord $ackPath 8192 $Holds;$v=$ack.Value
        Assert-ActivationBootstrapFields $v @('schema','handoff_nonce','activation_id','plan_sha256','request_sha256',
            'gate_pid','gate_birth','cmd_pid','cmd_birth','resume_pid','resume_birth','resume_image')
        if($v.schema -cne 'angerona.source-activation-resume-ready/v1' -or $v.handoff_nonce -cne $nonce -or
            $v.activation_id -cne $Bound.Id -or $v.plan_sha256 -cne $Bound.PlanSha -or $v.request_sha256 -cne $Bound.RequestSha -or
            $v.gate_pid -ne $PID -or $v.gate_birth -cne [string]$gateOwner.Birth -or $v.cmd_pid -ne $cmdOwner.ProcessId -or
            $v.cmd_birth -cne [string]$cmdOwner.Birth -or $v.resume_pid -ne $process.Id -or
            $v.resume_birth -cne [string]$nextOwner.Birth -or $v.resume_image -cne $nextOwner.Image){throw 'Original recovery owner acknowledgement belongs to another generation.'}
        $nextOwner.AssertLive($nextOwner.Birth,$fixedPS)
        $transferred=$true
        return $true # ACK is NOT retirement; Resume independently waits both actual handles.
    } finally {
        if($nextOwner -and !$transferred -and $nextOwner.WaitForExit(35000) -ne 0){
            throw 'Original recovery handoff remains unproved; no source mutation was admitted.'
        }
        Close-SourceActivationQueries @($nextOwner,$cmdOwner,$gateOwner)
        if($process){$process.Dispose()}
    }
}


$verifierLease=$null
$bootstrapMutation=@()
$activationCapsuleHolds=[Collections.Generic.List[object]]::new()
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
    $activation=Get-OriginalSourceActivationCapsule $activationCapsuleHolds
    if($activation){
        if(!$prefs.Enabled){Write-Host '[startup] Automatic recovery is disabled. The verified original owner will require a separate default-No one-shot confirmation after actual launcher retirement.'}
        try {
            if(Invoke-OriginalSourceActivationHandoff $activation $activationCapsuleHolds -ConfirmReconciliation:(!$prefs.Enabled)){exit 88}
        } catch {
            throw ('No source action was admitted. A recorded original noninteractive /c handoff is required. Close this unsupported launcher and open start-angerona.bat through the verified canonical route; manual Resume without that record remains held. '+$_.Exception.Message)
        }
        throw 'The original recovery owner handoff was not proven; source remains held.'
    }

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
    if($activationCapsuleHolds){foreach($held in $activationCapsuleHolds){$held.Dispose()}}
    if($verifierLease) {$verifierLease.Dispose()}
    Close-BundleMutationLocks $bootstrapMutation
}
