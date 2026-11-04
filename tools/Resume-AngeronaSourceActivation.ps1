[CmdletBinding()]
param([string]$RepositoryRoot, [string]$ActivationId, [string]$PlanSha256, [string]$RequestSha256,
    [uint32]$GatePid, [string]$GateBirth, [uint32]$CmdPid, [string]$CmdBirth, [string]$HandoffNonce, [switch]$ConfirmReconciliation)
$ErrorActionPreference = 'Stop'

# Fixed-purpose original capsule only; never a pending-supplied command.
function ConvertTo-SourceActivationArgument([string]$Value) {
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


function Close-SourceActivationQueries([object[]]$Owners,[switch]$OptionalStartup) {
    $failed=$false
    foreach($owner in $Owners){if($owner){try{$owner.Dispose()}catch{$failed=$true}}}
    if($failed -or (('Angerona.SourceActivationProcessOwner' -as [type]) -and [Angerona.SourceActivationProcessOwner]::CustodyPending)){
        if($OptionalStartup){
            # No source guard/effect has begun. Keep exact uncertain raw owners
            # in the class hold registry until this normal supervisor exits.
            throw 'Optional source activation native observation is unavailable.'
        }
        Show-SourceActivationHeld
        [Threading.Thread]::Sleep([Threading.Timeout]::Infinite)
    }
}

function Get-SourceActivationStateRoot {
    return Join-Path (Get-CanonicalSourceStartupStorage) 'github-updates'
}
function Assert-SourceActivationHex([string]$Value, [int]$Length) {
    if ($Value -cnotmatch ('^[0-9a-f]{'+$Length+'}$')) { throw 'Source activation identity is malformed.' }
}
function Read-SourceActivationCapsule([string]$Root,[string]$State,[string]$Id,[string]$PlanSha,[string]$RequestSha) {
    Assert-SourceActivationHex $Id 32;Assert-SourceActivationHex $PlanSha 64;Assert-SourceActivationHex $RequestSha 64
    $Root=[IO.Path]::GetFullPath($Root).TrimEnd('\')
    if (![string]::Equals([IO.Path]::GetFullPath($State),(Get-SourceActivationStateRoot),[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Source activation storage is not canonical.'
    }
    Assert-PlainRepairPath $Root;Assert-SourceActivationCustody $State
    $operation=Join-Path $State ('activations\apply-'+$Id)
    Assert-SourceActivationCustody $operation
    $plan=Read-SourceActivationRecord (Join-Path $operation 'plan.json') 16777216
    $v=$plan.Value
    if ($plan.Sha256 -cne $PlanSha -or $v.schema -cne 'angerona.source-activation-plan/v1' -or
        $v.activation_id -cne $Id -or $v.source_root -cne $Root -or $v.state_root -cne $State -or
        $v.origin -cne 'https://github.com/Ag3nt47/AngeronaSuite.git') { throw 'The approved source plan changed.' }
    $request=Read-SourceActivationRecord (Join-Path $operation ('requests\'+$RequestSha+'.json'))
    $q=$request.Value
    if ($request.Sha256 -cne $RequestSha -or $q.schema -cne 'angerona.source-activation-request/v1' -or
        $q.activation_id -cne $Id -or $q.plan_sha256 -cne $PlanSha -or $q.source_root -cne $Root -or
        $q.state_root -cne $State -or $q.accepted -isnot [bool] -or !$q.accepted) { throw 'Exact source approval is unavailable.' }
    $owner=Read-SourceActivationRecord (Join-Path $State 'activation-owner.json')
    $c=$owner.Value
    Assert-SourceActivationFields $c @('schema','launch_id','source_root','state_root','supervisor_pid','supervisor_birth','supervisor_image',
        'token','broker_pid','broker_birth','broker_image','core_pid','core_birth','core_image','owner_state')
    if ($owner.Sha256 -cne $q.owner_sha256 -or $c.owner_state -cne 'bound' -or $c.schema -isnot [int] -or $c.schema -ne 1 -or
        $c.source_root -cne $Root -or $c.state_root -cne $State -or $c.launch_id -cne $q.launch_id -or
        $c.core_pid -ne $q.core_pid -or $c.core_birth -cne $q.core_birth -or
        $c.broker_pid -ne $q.broker_pid -or $c.broker_birth -cne $q.broker_birth) { throw 'Original controller differs from approval.' }
    Assert-SourceActivationHex $c.launch_id 32;Assert-SourceActivationHex $c.token 64
    $launch=Join-Path $State ('launches\'+$c.launch_id)
    $descriptor=Read-SourceActivationRecord (Join-Path $launch 'descriptor.json') 8192
    $ready=Read-SourceActivationRecord (Join-Path $launch 'ready.json') 8192
    if ($descriptor.Value.launch_id -cne $c.launch_id -or $descriptor.Value.token -cne $c.token -or
        $descriptor.Value.source_root -cne $Root -or $descriptor.Value.state_root -cne $State -or
        $descriptor.Value.supervisor_pid -ne $c.supervisor_pid -or $descriptor.Value.supervisor_birth -cne $c.supervisor_birth -or
        $ready.Value.descriptor_sha256 -cne $descriptor.Sha256 -or $ready.Value.core_pid -ne $c.core_pid -or
        $ready.Value.core_birth -cne $c.core_birth -or $ready.Value.core_image -cne $c.core_image) { throw 'Original launch lineage is incomplete.' }
    $retired=Read-SourceActivationRecord (Join-Path $launch 'core-retired.json') 8192
    Assert-SourceActivationFields $retired.Value @('schema','launch_id','core_pid','core_birth','core_exit_code','native_wait0','owner_sha256')
    if ($retired.Value.schema -cne 'angerona.source-activation-core-retired/v1' -or $retired.Value.launch_id -cne $c.launch_id -or
        $retired.Value.core_pid -ne $c.core_pid -or $retired.Value.core_birth -cne $c.core_birth -or
        $retired.Value.core_exit_code -isnot [int] -or $retired.Value.core_exit_code -ne 0 -or
        $retired.Value.native_wait0 -isnot [bool] -or !$retired.Value.native_wait0 -or $retired.Value.owner_sha256 -cne $owner.Sha256) {
        throw 'Actual original Core wait/exit observation is unavailable.'
    }
    $stop=Read-SourceActivationRecord (Join-Path (Get-CanonicalSourceStartupStorage) 'diagnostics\operator-stop.json')
    Assert-SourceActivationStopReceipt $stop.Value $request $c
    $capsule=Join-Path $operation 'broker'
    $snapshot=Get-SourceActivationOriginalSnapshot $capsule $v.broker_snapshot
    return [pscustomobject]@{Root=$Root;State=$State;Operation=$operation;Capsule=$capsule;Plan=$plan;Request=$request;Owner=$owner;Stop=$stop;Snapshot=$snapshot;CoreRetired=$retired}
}

function Get-SourceActivationOriginalSnapshot([string]$Capsule,$PlanSnapshot) {
    # Content/custody verification only; caller retains approval/native/STOP
    # gates. No current supervisor/common import or mutation is performed.
    Assert-SourceActivationCustody $capsule
    $snapshot=Read-SourceActivationRecord (Join-Path $capsule 'snapshot.json')
    $names=@('tools/activate_source_update.py','src/angerona/core/source_activation_broker.py',
        'src/angerona/core/source_activation_file.py','src/angerona/core/startup_recovery.py','src/angerona/updater/source_git.py',
        'tools/publication_transport.py','tools/windows_publication_runtime.py','tools/publication_git_runtime_profile.json',
        'tools/Resume-AngeronaSourceActivation.ps1','tools/startup_repair_common.ps1','src/angerona/core/source_activation_storage.py','src/angerona/resilience/heartbeat.py',
        'src/angerona/core/_source_tomli/__init__.py','src/angerona/core/_source_tomli/_parser.py','src/angerona/core/_source_tomli/_re.py','src/angerona/core/_source_tomli/_types.py','src/angerona/core/_source_tomli/LICENSE','src/angerona/core/source_activation_workspace.py')
    if ($snapshot.Value.schema -cne 'angerona.source-activation-broker-snapshot/v1' -or
        $PlanSnapshot.schema -cne $snapshot.Value.schema) { throw 'Original capsule schema is unavailable.' }
    Assert-SourceActivationFields $snapshot.Value @('schema','files')
    Assert-SourceActivationFields $snapshot.Value.files $names
    Assert-SourceActivationFields $PlanSnapshot.files $names
    $total=0L
    foreach ($name in $names) {
        $row=$snapshot.Value.files.PSObject.Properties[$name].Value
        $original=$PlanSnapshot.files.PSObject.Properties[$name].Value
        Assert-SourceActivationFields $row @('bytes','sha256');Assert-SourceActivationHex $row.sha256 64
        if ($row.bytes -isnot [int] -or $row.bytes -lt 1 -or $row.bytes -gt 4194304 -or
            $original.bytes -ne $row.bytes -or $original.sha256 -cne $row.sha256) { throw 'Original capsule member binding is invalid.' }
        $path=Join-Path $capsule ($name.Replace('/','\'))
        Assert-SourceActivationCustody $path -AllowInherited
        if ((Get-Item -LiteralPath $path).Length -ne $row.bytes -or (Get-RepairFileSha256 $path) -cne $row.sha256) {
            throw 'An original capsule member changed.'
        }
        $total+=$row.bytes
        if ($total -gt 4194304) { throw 'Original capsule exceeds its aggregate budget.' }
    }
    return $snapshot
}

function Archive-SourceActivationOwnerRecord($Owner,[string]$State) {
    if(![string]::Equals([IO.Path]::GetFullPath($State),(Get-SourceActivationStateRoot),[StringComparison]::OrdinalIgnoreCase)){
        throw 'Source owner archival storage differs.'
    }
    Assert-SourceActivationHex $Owner.Value.launch_id 32
    $source=Join-Path $State 'activation-owner.json'
    $launch=Join-Path $State ('launches\'+$Owner.Value.launch_id)
    Assert-SourceActivationCustody $launch
    $destination=Join-Path $launch 'owner-retired.json'
    if(Test-Path -LiteralPath $destination){throw 'Original owner history already exists; nothing was overwritten.'}
    $current=Read-SourceActivationRecord $source
    if($current.Sha256 -cne $Owner.Sha256){throw 'Exact old source owner changed; no new launch was admitted.'}
    # Fixed local bookkeeping only. Native retirement and successful terminal
    # publication are caller-proved BEFORE this path; the rename grants none.
    [IO.File]::Move($source,$destination)
    $archived=Read-SourceActivationRecord $destination
    if($archived.Sha256 -cne $Owner.Sha256 -or (Test-Path -LiteralPath $source)){
        throw 'Exact old source owner archival is incomplete.'
    }
}

function Invoke-SourceActivationCapsule($Bound,[ValidateSet('activate','reconcile')][string]$Operation) {
    $runtime=$null;$helper=$null;$core=$null;$self=$null;$pythonOwner=$null
    $sourceHeld=$false;$success=$false
    try {
        Initialize-SourceActivationProcessOwner
        $self=[Angerona.SourceActivationProcessOwner]::new([uint32]$PID)
        $systemPs=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
        $self.AssertLive($self.Birth,$systemPs)
        if ($Operation -ceq 'activate' -and ($PID -ne $Bound.Owner.Value.broker_pid -or
            [string]$self.Birth -cne $Bound.Owner.Value.broker_birth)) { throw 'Only the exact bound broker may activate.' }
        if ($Operation -ceq 'reconcile' -and ![Angerona.SourceActivationProcessOwner]::GenerationRetired(
            [uint32]$Bound.Owner.Value.broker_pid,[long]$Bound.Owner.Value.broker_birth,[string]$Bound.Owner.Value.broker_image)) {
            throw 'Old external broker is live; reconciliation remains held.'
        }
        if (![Angerona.SourceActivationProcessOwner]::GenerationRetired([uint32]$Bound.Owner.Value.supervisor_pid,
            [long]$Bound.Owner.Value.supervisor_birth,[string]$Bound.Owner.Value.supervisor_image)) {
            throw 'The canonical launch supervisor is still live; source mutation is held.'
        }
        Assert-SourceActivationRetiredScope $Bound.Request.Value $Bound.Owner.Value
        Assert-SourceControllerHeartbeatCustody
        $runtime=Enter-RepairLease -Root $Bound.Root
        Assert-NoPendingRepair -Root $Bound.Root
        $helper=Enter-CanonicalSourceHelperLease
        $core=Enter-CanonicalCoreMutationLease
        Assert-NoActiveVenv (Join-Path $Bound.Root 'venv')
        Assert-SourceActivationRetiredScope $Bound.Request.Value $Bound.Owner.Value
        $again=Read-SourceActivationCapsule $Bound.Root $Bound.State $Bound.Plan.Value.activation_id $Bound.Plan.Sha256 $Bound.Request.Sha256
        if ($again.Owner.Sha256 -cne $Bound.Owner.Sha256 -or $again.Stop.Sha256 -cne $Bound.Stop.Sha256 -or
            $again.Snapshot.Sha256 -cne $Bound.Snapshot.Sha256) { throw 'Source custody changed before exclusion.' }
        $nonce=[Guid]::NewGuid().ToString('N')
        $guardDirectory=$Bound.Operation # Original child requires direct operation guards.
        $parentSha=if($Operation -ceq 'activate') { $script:SourceActivationBrokerScriptSha } else {
            $Bound.Snapshot.Value.files.PSObject.Properties['tools/Resume-AngeronaSourceActivation.ps1'].Value.sha256 }
        Assert-SourceActivationHex $parentSha 64
        $guard=[ordered]@{schema=1;operation=$Operation;guard_nonce=$nonce;owner_sha256=$Bound.Owner.Sha256
            launch_id=$Bound.Owner.Value.launch_id;activation_id=$Bound.Plan.Value.activation_id
            plan_sha256=$Bound.Plan.Sha256;request_sha256=$Bound.Request.Sha256
            source_root=$Bound.Root;state_root=$Bound.State;parent_pid=$PID;parent_birth=[string]$self.Birth
            parent_image=$self.Image;parent_script_sha256=$parentSha;snapshot_sha256=$Bound.Snapshot.Sha256
            root_identity=$Bound.Plan.Value.root_identity
            leases=@{runtime=$true;source_helper=$true;core=$true;no_pending_repair=$true;no_active_venv=$true}
            retirement=@{core_pid=$Bound.Owner.Value.core_pid;core_birth=$Bound.Owner.Value.core_birth
                core_exit_code=0;complete=$true;gaps=@();stop_receipt_sha256=$Bound.Stop.Sha256;core_retired_sha256=$Bound.CoreRetired.Sha256}}
        $guardPath=Join-Path $guardDirectory ('guard-'+$nonce+'.json')
        $pythonOwner=Open-RepairPythonHint (Join-Path $Bound.Root 'venv\Scripts\python.exe')
        $pythonOwner.AssertBound()
        $tool=Join-Path $Bound.Capsule 'tools\activate_source_update.py'
        $outputRoot=Join-Path $Bound.Operation 'native-output'
        if(!(Test-Path -LiteralPath $outputRoot)){New-PrivateRepairDirectory $outputRoot}
        Assert-SourceActivationCustody $outputRoot
        if(!(Test-Path -LiteralPath $outputRoot -PathType Container)){throw 'Native output root is not a private directory.'}
        $outputCount=0
        foreach($entry in [IO.Directory]::EnumerateFileSystemEntries($outputRoot)){
            if(++$outputCount -ge 128){throw 'Native output history requires review; nothing was deleted.'}
            Assert-SourceActivationCustody $entry
            if(!(Test-Path -LiteralPath $entry -PathType Container) -or [IO.Path]::GetFileName($entry) -cnotmatch '^[0-9a-f]{32}$'){
                throw 'Unknown native output history remains held.'
            }
        }
        $outputDirectory=Join-Path $outputRoot $nonce
        New-PrivateRepairDirectory $outputDirectory
        $logPath=Join-Path $outputDirectory 'activation.log'
        # Compiler/Git TEMP is kept outside the declared log-only output tree.
        $scratch=Get-RepairProcessCompilerScratch
        $environment=New-RepairChildEnvironment $scratch
        $sourceHeld=$true # Before publishing any executable one-use guard.
        $guardRecord=Write-NewSourceActivationRecord $guardPath $guard
        $arguments=@('-I','-B','-S',$tool,'--root',$Bound.Root,'--state-root',$Bound.State,
            '--activation-id',$Bound.Plan.Value.activation_id,'--plan-sha256',$Bound.Plan.Sha256,
            '--request-sha256',$Bound.Request.Sha256,'--guard-file',$guardPath,'--guard-sha256',$guardRecord.Sha256)
        if ($Operation -ceq 'reconcile') { $arguments+='--reconcile' }
        $call=@{FilePath=$pythonOwner.PhysicalPath;Arguments=$arguments;WorkingDirectory=$Bound.Capsule
            Environment=$environment;TimeoutSeconds=300;LogPath=$logPath;RequireClosedHandles=$true
            ScratchLease=$null;CriticalStartup=$false}
        if($script:SourceUpdateHeartbeat){$call.Heartbeat=$script:SourceUpdateHeartbeat.Writer.PulseAction}
        $code=Invoke-OwnedRepairProcess @call
        [Angerona.StartupRepairProcess]::RequireRetiredCustody()
        if ($code -ne 0) { throw 'Source publication did not verify a terminal outcome.' }
        $result=Read-SourceActivationRecord (Join-Path $Bound.Operation ('result-'+$nonce+'.json'))
        $v=$result.Value
        Assert-SourceActivationFields $v @('schema','status','activation_id','plan_sha256','request_sha256',
            'guard_sha256','snapshot_sha256','source_root','state_root','root_identity','pending_present','result')
        if ($v.schema -cne 'angerona.source-activation-outcome/v1' -or $v.status -cnotin @('committed','rolled_back') -or
            $v.activation_id -cne $Bound.Plan.Value.activation_id -or $v.plan_sha256 -cne $Bound.Plan.Sha256 -or
            $v.request_sha256 -cne $Bound.Request.Sha256 -or $v.guard_sha256 -cne $guardRecord.Sha256 -or
            $v.snapshot_sha256 -cne $Bound.Snapshot.Sha256 -or $v.source_root -cne $Bound.Root -or
            $v.state_root -cne $Bound.State -or $v.pending_present -isnot [bool] -or $v.pending_present -or
            (Test-Path -LiteralPath (Join-Path $Bound.State 'activation-pending.json'))) { throw 'Exact source terminal receipt is incomplete.' }
        Assert-SourceActivationFields $v.root_identity @('device','inode')
        if ($v.root_identity.device -cne $Bound.Plan.Value.root_identity.device -or $v.root_identity.inode -cne $Bound.Plan.Value.root_identity.inode -or
            $v.result.status -cne $v.status -or $v.result.activation_id -cne $v.activation_id -or $v.result.plan_sha256 -cne $v.plan_sha256 -or
            $v.result.git_and_preferences_preserved -isnot [bool] -or !$v.result.git_and_preferences_preserved -or
            ($v.status -ceq 'rolled_back' -and ($v.result.original_source_verified -isnot [bool] -or !$v.result.original_source_verified))) {
            throw 'Whole-tree/Git/preferences terminal verification is incomplete.'
        }
        Assert-SourceActivationCustody $logPath -AllowInherited
        $logInfo=Get-Item -LiteralPath $logPath -Force
        if($logInfo.PSIsContainer -or $logInfo.Length -lt 0 -or $logInfo.Length -gt 1048576){throw 'Native output log exceeds its exact retention bound.'}
        $logSha=Get-RepairFileSha256 $logPath
        $logAfter=Get-Item -LiteralPath $logPath -Force
        if($logAfter.Length -ne $logInfo.Length -or $logAfter.LastWriteTimeUtc -ne $logInfo.LastWriteTimeUtc){throw 'Native output log changed after owned Job retirement.'}
        $outputReceipt=[ordered]@{schema='angerona.source-activation-native-output/v1'
            activation_id=$Bound.Plan.Value.activation_id;guard_nonce=$nonce;guard_sha256=$guardRecord.Sha256
            plan_sha256=$Bound.Plan.Sha256;request_sha256=$Bound.Request.Sha256;log_sha256=$logSha;log_bytes=[long]$logInfo.Length
            child_job_retired=$true;child_handles_closed=$true;inherited_descendants_retired=$true
            independent_attestation=$false;observation_source='parent-observed-owned-job'}
        $outputBytes=[Text.UTF8Encoding]::new($false).GetBytes(($outputReceipt|ConvertTo-Json -Compress))
        if($outputBytes.Length -gt 4096){throw 'Native output receipt exceeds its closed bound.'}
        [void](Write-NewSourceActivationRecord (Join-Path $outputDirectory 'receipt.json') $outputReceipt)
        Archive-SourceActivationOwnerRecord $Bound.Owner $Bound.State
        $sourceHeld=$false;$success=$true
    } finally {
        if ($sourceHeld -or (('Angerona.StartupRepairProcess' -as [type]) -and [Angerona.StartupRepairProcess]::CustodyPending)) {
            Stop-SourceControllerHeartbeat $script:SourceUpdateHeartbeat
            $script:SourceUpdateHeartbeat=$null
            Show-SourceActivationHeld
            [Threading.Thread]::Sleep([Threading.Timeout]::Infinite)
        }
        try {
            if ($pythonOwner) { $pythonOwner.Dispose() }
            if ($self) { $self.Dispose() }
            if ([Angerona.SourceActivationProcessOwner]::CustodyPending) { throw 'Native query close is held.' }
        } catch {
            [Threading.Thread]::Sleep([Threading.Timeout]::Infinite)
        }
        if ($core) { $core.Unlock(0,1);$core.Dispose() }
        if ($helper) { $helper.Unlock(0,1);$helper.Dispose() }
        if ($runtime) { Exit-RepairLease $runtime }
    }
    return $success
}


function New-SourceActivationLaunch([string]$Root) {
    Initialize-SourceActivationProcessOwner
    $self=[Angerona.SourceActivationProcessOwner]::new([uint32]$PID)
    try {
        $systemPs=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
        $self.AssertLive($self.Birth,$systemPs)
        if($self.InAnyJob()){throw 'Canonical source-update ownership is unavailable inside a host Job.'}
        $state=Get-SourceActivationStateRoot
        foreach ($path in @($state,(Join-Path $state 'launches'))) {
            if (!(Test-Path -LiteralPath $path)) { New-PrivateRepairDirectory $path }
            Assert-SourceActivationCustody $path
        }
        $launches=Join-Path $state 'launches';$count=0
        foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($launches)) {
            if (++$count -ge 128) { throw 'Source activation launch history requires review; nothing was deleted.' }
        }
        $id=[Guid]::NewGuid().ToString('N')
        $directory=Join-Path $launches $id
        New-PrivateRepairDirectory $directory
        $rng=[Security.Cryptography.RandomNumberGenerator]::Create();$secret=New-Object byte[] 32
        try {$rng.GetBytes($secret)} finally {$rng.Dispose()}
        $token=[BitConverter]::ToString($secret).Replace('-','').ToLowerInvariant()
        $scriptPath=Join-Path $Root 'tools\Invoke-AngeronaSourceStartup.ps1'
        $value=[ordered]@{schema='angerona.source-activation-launch/v1';launch_id=$id
            source_root=$Root;state_root=$state;supervisor_pid=$PID;supervisor_birth=[string]$self.Birth
            supervisor_image=$self.Image;token=$token;broker_script_sha256=(Get-RepairFileSha256 $scriptPath)}
        $record=Write-NewSourceActivationRecord (Join-Path $directory 'descriptor.json') $value
        Stop-SourceControllerHeartbeat $script:SourceStartupHeartbeat
        $script:SourceStartupHeartbeat=Start-SourceControllerHeartbeat 'source_startup' $id
        return [pscustomobject]@{Directory=$directory;Descriptor=$record;Root=$Root;State=$state;Id=$id}
    } finally {
        Close-SourceActivationQueries @($self) -OptionalStartup
    }
}

function Complete-SourceActivationLaunch($Launch) {
    $core=$null;$broker=$null;$process=$null;$adopted=$false;$ownerPath=$null
    try {
        $ready=Read-SourceActivationRecord (Join-Path $Launch.Directory 'ready.json') 8192
        $r=$ready.Value
        Assert-SourceActivationFields $r @('schema','launch_id','source_root','state_root','core_pid','core_birth','core_image','descriptor_sha256')
        if ($r.schema -cne 'angerona.source-activation-ready/v1' -or $r.launch_id -cne $Launch.Id -or
            $r.descriptor_sha256 -cne $Launch.Descriptor.Sha256 -or $r.source_root -cne $Launch.Root -or $r.state_root -cne $Launch.State -or
            $r.core_pid -isnot [int] -or $r.core_pid -lt 1 -or $r.core_birth -isnot [string] -or $r.core_birth -cnotmatch '^[1-9][0-9]{0,19}$') {
            throw 'Native Core readiness export is incomplete.'
        }
        $core=[Angerona.SourceActivationProcessOwner]::new([uint32]$r.core_pid)
        $core.AssertLive([long]$r.core_birth,[string]$r.core_image)
        $ownerPath=Join-Path $Launch.State 'activation-owner.json'
        if (Test-Path -LiteralPath $ownerPath) { throw 'An earlier source activation owner is retained; no context was replaced.' }
        $scriptPath=Join-Path $Launch.Root 'tools\Invoke-AngeronaSourceStartup.ps1'
        if ((Get-RepairFileSha256 $scriptPath) -cne $Launch.Descriptor.Value.broker_script_sha256) { throw 'The fixed broker host changed.' }
        $systemPs=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
        $args=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$scriptPath,
            '-RepositoryRoot',$Launch.Root,'-SourceActivationBroker',$Launch.Id,'-ActivationDescriptorSha256',$Launch.Descriptor.Sha256)
        $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$systemPs
        $info.Arguments=($args|ForEach-Object {ConvertTo-SourceActivationArgument ([string]$_)}) -join ' '
        $info.WorkingDirectory=$Launch.Root;$info.UseShellExecute=$false;$info.CreateNoWindow=$true
        $info.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
        $info.EnvironmentVariables.Clear()
        $environment=New-RepairChildEnvironment $Launch.Directory
        foreach ($key in $environment.Keys) {$info.EnvironmentVariables[$key]=[string]$environment[$key]}
        $process=[Diagnostics.Process]::Start($info)
        if (!$process) { throw 'The fixed hidden source controller did not start.' }
        $broker=[Angerona.SourceActivationProcessOwner]::new([uint32]$process.Id)
        $broker.AssertLive($broker.Birth,$systemPs)
        if($broker.InAnyJob()){throw 'External broker lifetime is not independent of the invoking host Job.'}
        $deadline=[DateTime]::UtcNow.AddSeconds(15)
        $readyPath=Join-Path $Launch.Directory 'broker-ready.json'
        while (!(Test-Path -LiteralPath $readyPath) -and [DateTime]::UtcNow -lt $deadline) {
            if ($broker.WaitForExit(0) -eq 0) { throw 'The source controller exited before binding.' }
            if($script:SourceStartupHeartbeat){$script:SourceStartupHeartbeat.Writer.Pulse()}
            Start-Sleep -Milliseconds 50
        }
        $bound=Read-SourceActivationRecord $readyPath 8192
        if ($bound.Value.schema -cne 'angerona.source-activation-broker-ready/v1' -or
            $bound.Value.launch_id -cne $Launch.Id -or $bound.Value.descriptor_sha256 -cne $Launch.Descriptor.Sha256 -or
            $bound.Value.broker_pid -ne $process.Id -or $bound.Value.broker_birth -cne [string]$broker.Birth -or
            $bound.Value.core_pid -ne $r.core_pid -or $bound.Value.core_birth -cne $r.core_birth) { throw 'The actual broker generation did not acknowledge this launch.' }
        $core.AssertLive([long]$r.core_birth,$r.core_image);$broker.AssertLive($broker.Birth,$systemPs)
        $d=$Launch.Descriptor.Value
        $context=[ordered]@{schema=1;launch_id=$Launch.Id;source_root=$Launch.Root;state_root=$Launch.State
            supervisor_pid=$d.supervisor_pid;supervisor_birth=$d.supervisor_birth;supervisor_image=$d.supervisor_image;token=$d.token
            broker_pid=$process.Id;broker_birth=[string]$broker.Birth;broker_image=$broker.Image
            core_pid=$r.core_pid;core_birth=$r.core_birth;core_image=$r.core_image;owner_state='bound'}
        # A query-close uncertainty cannot publish a usable activation owner.
        # The broker retains its independent Core handle; the launched Process
        # object below retains this exact child for bounded ACK observation.
        $queries=@($broker,$core);$broker=$null;$core=$null
        Close-SourceActivationQueries $queries -OptionalStartup
        if($process.HasExited){throw 'External controller retired before ownership publication.'}
        $owner=Write-NewSourceActivationRecord $ownerPath $context
        $ackPath=Join-Path $Launch.Directory 'broker-bound.json'
        while (!(Test-Path -LiteralPath $ackPath) -and [DateTime]::UtcNow -lt $deadline) {
            if ($process.HasExited) { throw 'The source controller exited before ownership transfer.' }
            if($script:SourceStartupHeartbeat){$script:SourceStartupHeartbeat.Writer.Pulse()}
            Start-Sleep -Milliseconds 50
        }
        $ack=Read-SourceActivationRecord $ackPath 8192
        if ($ack.Value.owner_sha256 -cne $owner.Sha256 -or $ack.Value.launch_id -cne $Launch.Id -or
            $ack.Value.broker_pid -ne $process.Id -or $ack.Value.broker_birth -cne [string]$context.broker_birth) { throw 'External source controller transfer was not acknowledged.' }
        if($process.HasExited){throw 'External controller retired before transfer completion.'}
        $adopted=$true
        Write-Host '[startup] External source update controller is bound; update application still requires explicit consent and normal retirement.'
    } finally {
        # A child that never received an owner record has its own bounded
        # binding deadline. No source dispatch is possible without approval.
        if($process -and !$adopted -and (!$ownerPath -or !(Test-Path -LiteralPath $ownerPath))){
            $optionalClock=[Diagnostics.Stopwatch]::StartNew();$optionalRetired=$false
            while($optionalClock.ElapsedMilliseconds -lt 30000){
                $optionalRetired=$process.WaitForExit([int][Math]::Min(500,30000-$optionalClock.ElapsedMilliseconds))
                if($script:SourceStartupHeartbeat){$script:SourceStartupHeartbeat.Writer.Pulse()}
                if($optionalRetired){break}
            }
            if(!$optionalRetired){
                Write-Host '[startup] Optional unbound controller retirement is unverified; activation remains unavailable.'
            }
        }
        Close-SourceActivationQueries @($broker,$core) -OptionalStartup
        if($process){$process.Dispose()}
    }
}


function Invoke-SourceActivationBroker([string]$Root,[string]$LaunchId,[string]$DescriptorSha) {
    Assert-SourceActivationHex $LaunchId 32;Assert-SourceActivationHex $DescriptorSha 64
    Initialize-SourceActivationProcessOwner
    $state=Get-SourceActivationStateRoot;$launch=Join-Path $state ('launches\'+$LaunchId)
    $descriptor=Read-SourceActivationRecord (Join-Path $launch 'descriptor.json') 8192
    $ready=Read-SourceActivationRecord (Join-Path $launch 'ready.json') 8192
    $d=$descriptor.Value;$r=$ready.Value;$self=$null;$core=$null;$activationDispatchStarted=$false
    if ($descriptor.Sha256 -cne $DescriptorSha -or $d.launch_id -cne $LaunchId -or $d.source_root -cne $Root -or
        $d.state_root -cne $state -or $r.descriptor_sha256 -cne $DescriptorSha -or $r.launch_id -cne $LaunchId -or
        $r.source_root -cne $Root -or $r.state_root -cne $state) { throw 'Broker launch descriptor/readiness lineage changed.' }
    $script:SourceActivationBrokerScriptSha=Get-RepairFileSha256 (Join-Path $Root 'tools\Invoke-AngeronaSourceStartup.ps1')
    if ($script:SourceActivationBrokerScriptSha -cne $d.broker_script_sha256) { throw 'Fixed broker script binding changed.' }
    try {
        $systemPs=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
        $self=[Angerona.SourceActivationProcessOwner]::new([uint32]$PID);$self.AssertLive($self.Birth,$systemPs)
        if($self.InAnyJob()){throw 'External broker lifetime is held inside an unknown Job.'}
        $core=[Angerona.SourceActivationProcessOwner]::new([uint32]$r.core_pid);$core.AssertLive([long]$r.core_birth,$r.core_image)
        $binding=[ordered]@{schema='angerona.source-activation-broker-ready/v1';launch_id=$LaunchId;descriptor_sha256=$DescriptorSha
            broker_pid=$PID;broker_birth=[string]$self.Birth;core_pid=$r.core_pid;core_birth=$r.core_birth}
        [void](Write-NewSourceActivationRecord (Join-Path $launch 'broker-ready.json') $binding)
        $ownerPath=Join-Path $state 'activation-owner.json';$deadline=[DateTime]::UtcNow.AddSeconds(15)
        while (!(Test-Path -LiteralPath $ownerPath) -and [DateTime]::UtcNow -lt $deadline) {
            $core.AssertLive([long]$r.core_birth,$r.core_image);Start-Sleep -Milliseconds 50
        }
        $owner=Read-SourceActivationRecord $ownerPath;$c=$owner.Value
        Assert-SourceActivationFields $c @('schema','launch_id','source_root','state_root','supervisor_pid','supervisor_birth','supervisor_image',
            'token','broker_pid','broker_birth','broker_image','core_pid','core_birth','core_image','owner_state')
        if ($c.schema -isnot [int] -or $c.schema -ne 1 -or $c.owner_state -cne 'bound' -or
            $c.launch_id -cne $LaunchId -or $c.source_root -cne $Root -or $c.state_root -cne $state -or $c.token -cne $d.token -or
            $c.broker_pid -ne $PID -or $c.broker_birth -cne [string]$self.Birth -or $c.broker_image -cne $self.Image -or
            $c.core_pid -ne $r.core_pid -or $c.core_birth -cne $r.core_birth -or $c.core_image -cne $r.core_image -or
            $c.supervisor_pid -ne $d.supervisor_pid -or $c.supervisor_birth -cne $d.supervisor_birth -or
            $c.supervisor_image -cne $d.supervisor_image) { throw 'Only the exact canonical parent may bind this external controller.' }
        [void](Write-NewSourceActivationRecord (Join-Path $launch 'broker-bound.json') ([ordered]@{
            schema='angerona.source-activation-broker-bound/v1';launch_id=$LaunchId;owner_sha256=$owner.Sha256
            broker_pid=$PID;broker_birth=[string]$self.Birth}))
        $script:SourceUpdateHeartbeat=Start-SourceControllerHeartbeat 'source_update_owner' $LaunchId
        $closedSelf=$self;$self=$null;$closedSelf.Dispose()
        # Existing process lifetime only. No polling thread, response authority,
        # Core Job assignment or Core STOP join dependency is introduced.
        while($core.WaitForExit(500) -ne 0){
            if($script:SourceUpdateHeartbeat){$script:SourceUpdateHeartbeat.Writer.Pulse()}
        }
        if($script:SourceUpdateHeartbeat){$script:SourceUpdateHeartbeat.Writer.Pulse()}
        $coreExitCode=$core.ExitCode
        $closedCore=$core;$core=$null;$closedCore.Dispose()
        $requestPath=Join-Path $state 'activation-request.json'
        if (!(Test-Path -LiteralPath $requestPath)) {
            # No consent means no restart. Preserve the historical exact owner.
            Archive-SourceActivationOwnerRecord $owner $state
            return
        }
        if ($coreExitCode -ne 0) { throw 'Core did not retire normally; no source action was admitted.' }
        $request=Read-SourceActivationRecord $requestPath
        if ($request.Value.owner_sha256 -cne $owner.Sha256 -or $request.Value.launch_id -cne $LaunchId -or
            $request.Value.core_pid -ne $c.core_pid -or $request.Value.core_birth -cne $c.core_birth) {
            throw 'Retained approval belongs to another owner or Core.'
        }
        $retired=[ordered]@{schema='angerona.source-activation-core-retired/v1';launch_id=$LaunchId
            core_pid=$c.core_pid;core_birth=$c.core_birth;core_exit_code=0;native_wait0=$true;owner_sha256=$owner.Sha256}
        [void](Write-NewSourceActivationRecord (Join-Path $launch 'core-retired.json') $retired)
        $bound=Read-SourceActivationCapsule $Root $state $request.Value.activation_id $request.Value.plan_sha256 $request.Sha256
        $activationDispatchStarted=$true
        if (Invoke-SourceActivationCapsule $bound 'activate') {
            # One approved restart attempt through canonical startup, outside
            # the already-retired finite publication Job. Readiness is separate.
            Invoke-SourceActivationFreshStartup $Root $launch
        }
    } finally {
        Stop-SourceControllerHeartbeat $script:SourceUpdateHeartbeat
        $script:SourceUpdateHeartbeat=$null
        if($activationDispatchStarted){Close-SourceActivationQueries @($core,$self)}
        else {Close-SourceActivationQueries @($core,$self) -OptionalStartup}
    }
}


function Assert-SourceActivationBatchParent($Cmd,[string]$Root) {
    $expected=Join-Path ([Environment]::SystemDirectory) 'cmd.exe'
    $Cmd.AssertLive($Cmd.Birth,$expected)
    $line=$Cmd.CommandLine()
    # Closed noninteractive invocation only. Never wait for or force-close a
    # user's interactive shell, nor execute anything selected by this string.
    $match=[regex]::Match($line,'^\s*(?:"[^"]+"|\S+)\s+(?:/d\s+)?/c\s+(.+?)\s*$','IgnoreCase')
    if(!$match.Success){throw 'The invoking cmd is not a proved noninteractive /c launcher.'}
    $target=$match.Groups[1].Value.Trim()
    if($target -match '[&|<>^%\x00\r\n]'){throw 'Compound or expanded cmd launch is unsupported for automatic reconciliation.'}
    while($target.Length -ge 2 -and $target[0] -eq '"' -and $target[$target.Length-1] -eq '"'){$target=$target.Substring(1,$target.Length-2).Trim()}
    $full=Join-Path $Root 'start-angerona.bat'
    if(![string]::Equals($target,'start-angerona.bat',[StringComparison]::OrdinalIgnoreCase) -and
        ![string]::Equals($target,$full,[StringComparison]::OrdinalIgnoreCase)){throw 'The noninteractive command is not this fixed source launcher.'}
    if($Cmd.InAnyJob()){throw 'Invoking cmd Job lifetime cannot establish a surviving independent recovery owner.'}
}

function Assert-SourceActivationRecordedHandoff($Record,$Bound,[string]$Nonce) {
    Assert-SourceActivationHex $Nonce 32
    $v=$Record.Value
    Assert-SourceActivationFields $v @('schema','handoff_nonce','activation_id','plan_sha256','request_sha256',
        'gate_pid','gate_birth','cmd_pid','cmd_birth','resume_pid','resume_birth','resume_image')
    if($v.schema -cne 'angerona.source-activation-resume-ready/v1' -or $v.handoff_nonce -cne $Nonce -or
        $v.activation_id -cne $Bound.Plan.Value.activation_id -or $v.plan_sha256 -cne $Bound.Plan.Sha256 -or
        $v.request_sha256 -cne $Bound.Request.Sha256){throw 'Recorded original handoff belongs to another approval.'}
    foreach($name in @('gate_pid','cmd_pid','resume_pid')){
        $value=$v.PSObject.Properties[$name].Value
        if(($value -isnot [int] -and $value -isnot [long]) -or $value -lt 1 -or $value -gt 4294967295){throw 'Recorded handoff PID is not a literal native identifier.'}
    }
    foreach($name in @('gate_birth','cmd_birth','resume_birth')){
        $value=$v.PSObject.Properties[$name].Value
        if($value -isnot [string] -or $value -cnotmatch '^[1-9][0-9]{0,18}$' -or [long]::Parse($value) -le 0){throw 'Recorded handoff birth is invalid.'}
    }
    $systemPs=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    if($v.resume_image -isnot [string] -or ![string]::Equals($v.resume_image,$systemPs,[StringComparison]::OrdinalIgnoreCase)){
        throw 'Recorded handoff owner image differs from the fixed host.'
    }
}

function Get-SourceActivationRetiredHandoff($Bound,[string]$Nonce) {
    Assert-SourceActivationHex $Nonce 32
    $directory=Join-Path $Bound.Operation ('handoffs\'+$Nonce)
    try {$record=Read-SourceActivationRecord (Join-Path $directory 'ready.json') 8192}
    catch {throw 'A bound original handoff record is unavailable. Use the canonical verified noninteractive source gate; no source action was admitted.'}
    Assert-SourceActivationRecordedHandoff $record $Bound $Nonce
    Initialize-SourceActivationProcessOwner
    $v=$record.Value
    $psImage=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $cmdImage=Join-Path ([Environment]::SystemDirectory) 'cmd.exe'
    if(![Angerona.SourceActivationProcessOwner]::GenerationRetired([uint32]$v.gate_pid,[long]$v.gate_birth,$psImage) -or
        ![Angerona.SourceActivationProcessOwner]::GenerationRetired([uint32]$v.cmd_pid,[long]$v.cmd_birth,$cmdImage) -or
        ![Angerona.SourceActivationProcessOwner]::GenerationRetired([uint32]$v.resume_pid,[long]$v.resume_birth,$psImage)){
        throw 'A recorded original launcher/recovery generation is still live or unverified; no source action is admitted.'
    }
    return $record
}

function Wait-SourceActivationLauncherRetirement($Gate,$Cmd,[int]$TimeoutMilliseconds=30000) {
    if($TimeoutMilliseconds -lt 1 -or $TimeoutMilliseconds -gt 30000){throw 'Launcher wait budget is outside its fixed bound.'}
    $clock=[Diagnostics.Stopwatch]::StartNew()
    foreach($pair in @(@($Gate,88),@($Cmd,0))){
        $owner=$pair[0];$expected=[uint32]$pair[1]
        while($true){
            $left=$TimeoutMilliseconds-$clock.ElapsedMilliseconds
            if($left -le 0){throw 'Exact launcher generation did not retire before the fixed handoff deadline.'}
            $wait=$owner.WaitForExit([uint32][Math]::Min(500,$left))
            if($script:SourceUpdateHeartbeat){$script:SourceUpdateHeartbeat.Writer.Pulse()}
            if($wait -eq 0){break}
        }
        if($owner.ExitCode -ne $expected){throw 'Exact launcher generation exited outside its reserved handoff outcome.'}
    }
    return $true
}

function Show-SourceActivationHeld {
    $message='Source activation is held. Existing source, settings, approval and recovery evidence are preserved. No unverified application code will be loaded. Keep the retained recovery owner open and review the fixed source-activation diagnostics. A normal STOP and exact native retirement are required; this notice grants no approval.'
    Write-Host ('[activation] '+$message)
    try{[void]((New-Object -ComObject WScript.Shell).Popup($message,0,'Angerona Safe Startup - activation held',16))}catch{}
}
function Invoke-SourceActivationFreshStartup([string]$Root,[string]$Scratch) {
    $systemPs=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $normal=Join-Path $Root 'tools\Invoke-AngeronaSourceStartup.ps1'
    $args=@('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',$normal,'-RepositoryRoot',$Root,'-FreshSourceCache')
    # Same closed Windows argument quoting used by the canonical supervisor.
    $quoted=@($args|ForEach-Object{ConvertTo-SourceActivationArgument ([string]$_)})
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$systemPs;$info.Arguments=$quoted -join ' '
    $info.WorkingDirectory=$Root;$info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $info.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden;$info.EnvironmentVariables.Clear()
    foreach($entry in (New-RepairChildEnvironment $Scratch).GetEnumerator()){$info.EnvironmentVariables[$entry.Key]=[string]$entry.Value}
    $started=[Diagnostics.Process]::Start($info)
    if(!$started){throw 'Verified source is retained, but canonical restart could not be requested.'}
    $started.Dispose() # New canonical parent owns readiness and broker transfer.
}

if ($MyInvocation.InvocationName -ne '.') {
    $gate=$null;$cmd=$null;$self=$null;$resumeLease=$null
    try {
        $fixedHost=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
        if($PSVersionTable.PSVersion.Major -ne 5 -or ![string]::Equals([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName,$fixedHost,[StringComparison]::OrdinalIgnoreCase)){
            throw 'The fixed Windows PowerShell host is required.'
        }
        $currentIdentity=[Security.Principal.WindowsIdentity]::GetCurrent()
        try {$currentPrincipal=[Security.Principal.WindowsPrincipal]::new($currentIdentity);if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Source activation recovery must remain unelevated.'}}
        finally {$currentIdentity.Dispose()}
        $root=[IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\')
        $capsuleRoot=Split-Path -Parent $PSScriptRoot
        . (Join-Path $capsuleRoot 'tools\startup_repair_common.ps1')
        $bound=Read-SourceActivationCapsule $root (Get-SourceActivationStateRoot) $ActivationId $PlanSha256 $RequestSha256
        if(![string]::Equals($capsuleRoot,$bound.Capsule,[StringComparison]::OrdinalIgnoreCase)){throw 'Only the fixed original capsule may reconcile.'}
        Initialize-SourceActivationProcessOwner
        $self=[Angerona.SourceActivationProcessOwner]::new([uint32]$PID)
        $systemPs=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
        $self.AssertLive($self.Birth,$systemPs)
        if($self.InAnyJob()){throw 'Independent recovery lifetime is not established outside host Jobs.'}
        $resumeLease=Open-PrivateRepairFile (Join-Path $bound.Operation 'resume-owner.lock') -Mode OpenOrCreate -Share ReadWrite
        if($resumeLease.Length -eq 0){$resumeLease.WriteByte(0);$resumeLease.Flush($true)}
        if($resumeLease.Length -ne 1){throw 'Recovery owner lock shape is invalid.'}
        $resumeLease.Position=0
        if($resumeLease.ReadByte() -ne 0 -or $resumeLease.ReadByte() -ne -1){throw 'Recovery owner lock has unknown bytes.'}
        $resumeLease.Position=0
        $resumeLease.Lock(0,1) # One fixed recovery owner for this exact operation.
        $script:SourceUpdateHeartbeat=Start-SourceControllerHeartbeat 'source_update_owner' $bound.Owner.Value.launch_id
        $automatic=$GatePid -ne 0 -or $CmdPid -ne 0 -or $GateBirth -or $CmdBirth
        if(!$HandoffNonce){throw 'No bound original handoff is available. Close this recovery owner and use the canonical verified noninteractive source gate; no source was changed.'}
        Assert-SourceActivationHex $HandoffNonce 32
        $handoff=Join-Path $bound.Operation ('handoffs\'+$HandoffNonce)
        if($automatic){
            Assert-SourceActivationCustody $handoff
            Assert-SourceActivationHex $HandoffNonce 32
            if($GatePid -eq 0 -or $CmdPid -eq 0 -or $GateBirth -cnotmatch '^[1-9][0-9]{0,19}$' -or $CmdBirth -cnotmatch '^[1-9][0-9]{0,19}$'){
                throw 'Launcher retirement handoff is incomplete.'
            }
            $gate=[Angerona.SourceActivationProcessOwner]::new($GatePid);$gate.AssertLive([long]$GateBirth,$systemPs)
            $cmd=[Angerona.SourceActivationProcessOwner]::new($CmdPid)
            $cmd.AssertLive([long]$CmdBirth,(Join-Path ([Environment]::SystemDirectory) 'cmd.exe'))
            if($self.ParentProcessId() -ne $GatePid -or $gate.ParentProcessId() -ne $CmdPid -or $gate.InAnyJob()){
                throw 'Exact native launcher ancestry/lifetime is unavailable.'
            }
            Assert-SourceActivationBatchParent $cmd $root
            $ack=[ordered]@{schema='angerona.source-activation-resume-ready/v1';handoff_nonce=$HandoffNonce
                activation_id=$ActivationId;plan_sha256=$PlanSha256;request_sha256=$RequestSha256
                gate_pid=$GatePid;gate_birth=$GateBirth;cmd_pid=$CmdPid;cmd_birth=$CmdBirth
                resume_pid=$PID;resume_birth=[string]$self.Birth;resume_image=$self.Image}
            [void](Write-NewSourceActivationRecord (Join-Path $handoff 'ready.json') $ack)
            $self.Dispose();$self=$null
            # File/ack only admits handoff. Exact retained native waits below
            # prove the executing old bootstrap and /c launcher really retired.
            [void](Wait-SourceActivationLauncherRetirement $gate $cmd)
            $gate.Dispose();$gate=$null;$cmd.Dispose();$cmd=$null
        } else {
            # No close instruction or user Boolean is a retirement proof.
            # Only a previously bound original ACK may select these generations.
            [void](Get-SourceActivationRetiredHandoff $bound $HandoffNonce)
            $closedSelf=$self;$self=$null;$closedSelf.Dispose()
        }
        if(!$automatic -or $ConfirmReconciliation){
            # Disabled automatic recovery never implies approval. A verified
            # canonical handoff can offer this separate one-shot default-No.
            $question='Reconcile only this previously approved interrupted source update using its verified original recovery capsule, after actual recorded launcher retirement, then request one canonical startup? No setting is changed. Source remains held on uncertainty. Continue once?'
            $reply=(New-Object -ComObject WScript.Shell).Popup($question,0,'Angerona - reconcile approved source update',292)
            if($reply -ne 6){exit 1223}
        }
        if([Angerona.SourceActivationProcessOwner]::CustodyPending){throw 'Native handoff query close is held.'}
        if(!(Invoke-SourceActivationCapsule $bound 'reconcile')){throw 'Original source reconciliation remains held.'}
        Invoke-SourceActivationFreshStartup $root $bound.Operation
        exit 0
    } catch {
        Show-SourceActivationHeld
        exit 85
    } finally {
        Stop-SourceControllerHeartbeat $script:SourceUpdateHeartbeat
        $script:SourceUpdateHeartbeat=$null
        Close-SourceActivationQueries @($cmd,$gate,$self)
        if($resumeLease){$resumeLease.Unlock(0,1);$resumeLease.Dispose()}
    }
}
