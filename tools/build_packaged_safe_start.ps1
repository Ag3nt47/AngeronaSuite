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
$scratch=$null;$temporary=$null;$image=$null
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
    $scratch=Join-Path $root ('.safe-start-build.'+[Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($scratch,$acl)
    Assert-SafeStartBuildPath $scratch
    $temporary=Join-Path $scratch 'safe-start.cs';$image=Join-Path $scratch 'AngeronaSafeStart.exe'
    [IO.File]::WriteAllText($temporary,$text.Replace('__STARTUP_SHA256__',$pin),[Text.UTF8Encoding]::new($false))
    $arguments=@('/nologo','/noconfig','/nostdlib+','/target:winexe','/platform:x64','/optimize+',('/out:'+$image))
    foreach($assembly in @('mscorlib.dll','System.dll','System.Core.dll','System.Windows.Forms.dll','System.Drawing.dll')) {
        $reference=Join-Path $framework $assembly
        Assert-SafeStartBuildPath $reference -AllowHardLinks
        $arguments+=('/reference:'+$reference)
    }
    $arguments+=$temporary
    & $compiler @arguments
    if($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $image -PathType Leaf)) {throw 'Independent SafeStart compilation failed.'}
    $destination=Join-Path $root 'AngeronaSafeStart.exe'
    Assert-SafeStartBuildPath $destination
    if(Test-Path -LiteralPath $destination) {[IO.File]::Replace($image,$destination,[NullString]::Value)}
    else {[IO.File]::Move($image,$destination)}
    $output=[IO.File]::OpenRead($destination);$digest=[Security.Cryptography.SHA256]::Create()
    try {$wrapper=[BitConverter]::ToString($digest.ComputeHash($output)).Replace('-','').ToLowerInvariant()}finally{$digest.Dispose();$output.Dispose()}
    [Console]::WriteLine(([ordered]@{schema=1;startup_sha256=$pin;safe_start_sha256=$wrapper;artifact='AngeronaSafeStart.exe';signed=$false}|ConvertTo-Json -Compress))
} finally {
    $held.Dispose()
    # Retire only the exact generated files. Unknown scratch contents are left
    # for review; no recursive cleanup can follow a path supplied by the caller.
    foreach($file in @($temporary,$image)) {
        if($file -and (Test-Path -LiteralPath $file)) {Assert-SafeStartBuildPath $file;[IO.File]::Delete($file)}
    }
    if($scratch -and (Test-Path -LiteralPath $scratch)) {
        $absolute=[IO.Path]::GetFullPath($scratch)
        if([IO.Path]::GetDirectoryName($absolute) -ne $root -or [IO.Path]::GetFileName($absolute) -notmatch '^\.safe-start-build\.[0-9a-f]{32}$') {
            throw 'SafeStart cleanup target escaped its private build directory.'
        }
        Assert-SafeStartBuildPath $absolute
        if(@([IO.Directory]::EnumerateFileSystemEntries($absolute)).Count -eq 0) {[IO.Directory]::Delete($absolute,$false)}
    }
}
