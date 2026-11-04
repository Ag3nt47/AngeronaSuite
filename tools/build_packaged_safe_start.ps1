[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PayloadRoot)
$ErrorActionPreference='Stop'

function Assert-SafeStartBuildPath([string]$Path,[switch]$AllowHardLinks) {
    if($Path -notmatch '^[A-Za-z]:\\' -or $Path.StartsWith('\\')) {throw 'SafeStart build requires absolute local paths.'}
    $cursor=[IO.Path]::GetFullPath($Path)
    while($cursor) {
        if(Test-Path -LiteralPath $cursor) {
            $item=Get-Item -LiteralPath $cursor -Force
            if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                (!$AllowHardLinks -and !$item.PSIsContainer -and $item.LinkType -eq 'HardLink')) {
                throw 'SafeStart build refuses redirected or linked inputs.'
            }
        }
        $cursor=[IO.Path]::GetDirectoryName($cursor)
    }
}

function New-SafeStartBuildWorkspace([string]$Payload,[Security.AccessControl.DirectorySecurity]$Acl) {
    # CSC emits a separate CSC<32 hex>.TMP leaf for the default Win32 resource.
    # MAX_PATH includes the terminating NUL; source/output basenames are shorter.
    $compilerTemporaryLeafLength=3+32+4
    $volume=[IO.Path]::GetPathRoot($Payload)
    $parent=$Payload
    for($attempt=0;$parent -and $attempt -lt 128;$attempt++) {
        if([IO.Path]::GetPathRoot($parent) -ine $volume) {throw 'SafeStart workspace escaped its fixed volume.'}
        $candidate=Join-Path $parent ('.ss.'+[Guid]::NewGuid().ToString('N'))
        if($candidate.Length+1+$compilerTemporaryLeafLength+1 -le 260) {
            Assert-SafeStartBuildPath $parent
            if(!(Test-Path -LiteralPath $parent -PathType Container)) {throw 'SafeStart workspace ancestor is missing.'}
            if(Test-Path -LiteralPath $candidate) {throw 'SafeStart workspace nonce collision; existing contents preserved.'}
            try {[void][IO.Directory]::CreateDirectory($candidate,$Acl)}
            catch [UnauthorizedAccessException] {if(Test-Path -LiteralPath $candidate) {throw};$parent=[IO.Path]::GetDirectoryName($parent);continue}
            catch [IO.IOException] {if(Test-Path -LiteralPath $candidate) {throw};$parent=[IO.Path]::GetDirectoryName($parent);continue}
            Assert-SafeStartBuildPath $candidate
            $observed=[IO.Directory]::GetAccessControl($candidate)
            $owner=$Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
            $expected=@($Acl.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]) |
                ForEach-Object {$_.IdentityReference.Value} | Sort-Object -Unique)
            $rules=@($observed.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
            if(!$observed.AreAccessRulesProtected -or $observed.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $owner -or
                $rules.Count -ne $expected.Count -or
                (($rules | ForEach-Object {$_.IdentityReference.Value} | Sort-Object -Unique) -join ',') -cne ($expected -join ',')) {throw 'SafeStart workspace private ACL did not verify; directory retained.'}
            foreach($rule in $rules) {
                if($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
                    $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
                    $rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' -or
                    $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None -or
                    $rule.IdentityReference.Value -cnotin $expected) {throw 'SafeStart workspace private ACL did not verify; directory retained.'}
            }
            return $candidate
        }
        $parent=[IO.Path]::GetDirectoryName($parent)
    }
    throw 'No writable same-volume SafeStart workspace satisfies the CSC temporary-path bound.'
}

$root=[IO.Path]::GetFullPath($PayloadRoot)
Assert-SafeStartBuildPath $root
if(!(Test-Path -LiteralPath $root -PathType Container)) {throw 'Completed release payload directory is missing.'}
if(([IO.DriveInfo]::new([IO.Path]::GetPathRoot($root))).DriveType -ne 'Fixed') {throw 'SafeStart build requires a fixed local drive.'}
$helper=Join-Path $root 'AngeronaStartup.exe'
Assert-SafeStartBuildPath $helper
$source=Join-Path $PSScriptRoot 'packaged_safe_start.cs'
Assert-SafeStartBuildPath $source
if((Get-Item -LiteralPath $source).Length -gt 2MB) {throw 'SafeStart source exceeds its build bound.'}
$systemRoot=Split-Path -Parent ([Environment]::SystemDirectory)
$framework=Join-Path $systemRoot 'Microsoft.NET\Framework64\v4.0.30319'
$compiler=Join-Path $framework 'csc.exe'
Assert-SafeStartBuildPath $compiler -AllowHardLinks
if(!(Test-Path -LiteralPath $compiler -PathType Leaf)) {throw 'The OS .NET Framework x64 C# compiler is unavailable.'}
$held=[IO.File]::Open($helper,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
$scratch=$null;$scratchParent=$null;$temporary=$null;$image=$null
try {
    if($held.Length -lt 1 -or $held.Length -gt 512MB) {throw 'Completed startup helper exceeds its byte bound.'}
    $hash=[Security.Cryptography.SHA256]::Create()
    try {$pin=[BitConverter]::ToString($hash.ComputeHash($held)).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
    $text=[IO.File]::ReadAllText($source,[Text.UTF8Encoding]::new($false,$true))
    if([regex]::Matches($text,'__STARTUP_SHA256__').Count -ne 1) {throw 'SafeStart helper pin template is invalid.'}
    $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetOwner($owner);$acl.SetAccessRuleProtection($true,$false)
    foreach($sid in @($owner.Value,'S-1-5-18','S-1-5-32-544')) {
        [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    }
    $scratch=New-SafeStartBuildWorkspace $root $acl
    $scratchParent=[IO.Path]::GetDirectoryName($scratch)
    Assert-SafeStartBuildPath $scratch
    $temporary=Join-Path $scratch 'a.cs';$image=Join-Path $scratch 'a.exe'
    [IO.File]::WriteAllText($temporary,$text.Replace('__STARTUP_SHA256__',$pin),[Text.UTF8Encoding]::new($false))
    $arguments=@('/nologo','/noconfig','/nostdlib+','/target:winexe','/platform:x64','/optimize+',('/out:'+$image))
    foreach($assembly in @('mscorlib.dll','System.dll','System.Core.dll','System.Windows.Forms.dll','System.Drawing.dll')) {
        $reference=Join-Path $framework $assembly
        Assert-SafeStartBuildPath $reference -AllowHardLinks
        $arguments+=('/reference:'+$reference)
    }
    $arguments+=$temporary
    # Bound only the diagnostic text retained in the final error. PowerShell's
    # native pipeline still allocates complete lines before this callback;
    # this is not a process-memory or upstream-output bound. The compiler is
    # the fixed OS tool and source was bounded above; owned diagnostic jobs
    # apply their independent process/output limits when testing this script.
    $compilerDiagnostics=[Text.StringBuilder]::new()
    $compilerDiagnosticsTruncated=$false
    $priorErrorAction=$ErrorActionPreference
    $LASTEXITCODE=$null
    try {
        $ErrorActionPreference='Continue'
        & $compiler @arguments 2>&1 | ForEach-Object {
            $line=[string]$_
            $remaining=8192-$compilerDiagnostics.Length
            if($remaining -gt 0) {
                $part=$line.Substring(0,[Math]::Min($line.Length,$remaining))
                [void]$compilerDiagnostics.Append($part)
                if($compilerDiagnostics.Length+[Environment]::NewLine.Length -le 8192) {[void]$compilerDiagnostics.AppendLine()}
            }
            if($line.Length -gt $remaining) {$compilerDiagnosticsTruncated=$true}
        }
        $compilerExit=$LASTEXITCODE
    } finally {$ErrorActionPreference=$priorErrorAction}
    $imagePresent=Test-Path -LiteralPath $image -PathType Leaf
    if($null -eq $compilerExit -or $compilerExit -ne 0 -or !$imagePresent) {
        $exitHex=if($null -eq $compilerExit) {'unknown'} else {
            '0x{0:X8}' -f [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$compilerExit),0)
        }
        throw ('Independent SafeStart compilation failed. Compiler exit: {0} ({1}); output present: {2}; compiler/source/output path lengths: {3}/{4}/{5}; diagnostics truncated: {6}. Compiler diagnostics: {7}' -f
            $compilerExit,$exitHex,$imagePresent,$compiler.Length,$temporary.Length,$image.Length,
            $compilerDiagnosticsTruncated,$compilerDiagnostics.ToString())
    }
    $destination=Join-Path $root 'AngeronaSafeStart.exe'
    Assert-SafeStartBuildPath $destination
    if(Test-Path -LiteralPath $destination) {[IO.File]::Replace($image,$destination,[NullString]::Value)}
    else {[IO.File]::Move($image,$destination)}
    $output=[IO.File]::OpenRead($destination);$digest=[Security.Cryptography.SHA256]::Create()
    try {$wrapper=[BitConverter]::ToString($digest.ComputeHash($output)).Replace('-','').ToLowerInvariant()}finally{$digest.Dispose();$output.Dispose()}
    [Console]::WriteLine(([ordered]@{schema=1;startup_sha256=$pin;safe_start_sha256=$wrapper;artifact='AngeronaSafeStart.exe';signed=$false;build_workspace=$scratch}|ConvertTo-Json -Compress))
} finally {
    $held.Dispose()
    # Retire only the exact generated files. Unknown scratch contents are left
    # for review; no recursive cleanup can follow a path supplied by the caller.
    foreach($file in @($temporary,$image)) {
        if($file -and (Test-Path -LiteralPath $file)) {Assert-SafeStartBuildPath $file;[IO.File]::Delete($file)}
    }
    if($scratch -and (Test-Path -LiteralPath $scratch)) {
        $absolute=[IO.Path]::GetFullPath($scratch)
        if([IO.Path]::GetDirectoryName($absolute) -ne $scratchParent -or
            [IO.Path]::GetPathRoot($absolute) -ine [IO.Path]::GetPathRoot($root) -or
            !($scratchParent -eq $root -or $root.StartsWith(($scratchParent.TrimEnd('\')+'\'),[StringComparison]::OrdinalIgnoreCase)) -or
            [IO.Path]::GetFileName($absolute) -notmatch '^\.ss\.[0-9a-f]{32}$') {
            throw 'SafeStart cleanup target escaped its private build directory.'
        }
        Assert-SafeStartBuildPath $absolute
        if(@([IO.Directory]::EnumerateFileSystemEntries($absolute)).Count -eq 0) {[IO.Directory]::Delete($absolute,$false)}
    }
}
