[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$FixtureRoot)

$ErrorActionPreference = 'Stop'
$builder = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools/Build-AngeronaWatchdog3.ps1'
$parseTokens = $null
$parseErrors = $null
$buildAst = [Management.Automation.Language.Parser]::ParseFile($builder, [ref]$parseTokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'The production builder has parser errors.' }
$resolverBlocks = @($buildAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.IfStatementAst] -and
        $node.Extent.Text -match '^if \(\[string\]::IsNullOrWhiteSpace\(\$GoExecutable\)\)'
}, $true))
if ($resolverBlocks.Count -ne 1) { throw 'Expected one production Go discovery block.' }
$resolverCommands = @($resolverBlocks[0].FindAll({
    param($node)
    $node -is [Management.Automation.Language.CommandAst]
}, $true))
if ($resolverCommands.Count -ne 1 -or $resolverCommands[0].GetCommandName() -cne 'Get-Command') {
    throw 'The fixture only permits Get-Command; it must never execute a compiler image.'
}
$resolver = [scriptblock]::Create($resolverBlocks[0].Extent.Text)

function Resolve-FixtureGo([string]$ExplicitPath = '') {
    [string]$GoExecutable = $ExplicitPath
    . $resolver
    return $GoExecutable
}

$fixture = [IO.Path]::GetFullPath($FixtureRoot)
if ([IO.Directory]::Exists($fixture) -or [IO.File]::Exists($fixture)) {
    throw 'Fixture root must be a new private directory.'
}
$parent = [IO.Path]::GetDirectoryName($fixture)
if (-not [IO.Directory]::Exists($parent)) { throw 'Fixture parent directory is unavailable.' }
$first = [IO.Path]::Combine($fixture, 'first')
$second = [IO.Path]::Combine($fixture, 'second')
$empty = [IO.Path]::Combine($fixture, 'empty')
$firstGo = [IO.Path]::Combine($first, 'go.exe')
$secondGo = [IO.Path]::Combine($second, 'go.exe')
$savedPath = $env:PATH
$savedPathExt = $env:PATHEXT
$createdDirectories = @()
$createdFiles = @()
try {
    foreach ($directory in @($fixture, $first, $second, $empty)) {
        [IO.Directory]::CreateDirectory($directory) | Out-Null
        $createdDirectories += $directory
    }
    foreach ($image in @($firstGo, $secondGo)) {
        # Deliberately not a PE image. Get-Command discovers it; no call operator
        # or native execution is permitted anywhere in this fixture.
        [IO.File]::WriteAllText($image, 'INERT: compiler discovery only; never execute')
        $createdFiles += $image
    }
    $env:PATHEXT = '.EXE'
    $env:PATH = $first + [IO.Path]::PathSeparator + $second
    $allApplications = @(Get-Command go.exe -CommandType Application -All -ErrorAction Stop)
    if ($allApplications.Count -ne 2) { throw 'Two private PATH applications were not discovered.' }
    $defaultApplications = @(Get-Command go.exe -CommandType Application -ErrorAction Stop)
    [string]$legacyValue = (Get-Command go.exe -CommandType Application -ErrorAction Stop).Source
    $legacyFileExists = $false
    try { $legacyFileExists = [IO.File]::Exists([IO.Path]::GetFullPath($legacyValue)) } catch [ArgumentException] {} catch [NotSupportedException] {}
    $legacyFailureReproduced = $defaultApplications.Count -gt 1 -and -not $legacyFileExists
    # Record the exact host behavior, including a single-match host, before any
    # assertion. PowerShell versions may enumerate default matches differently.
    [Console]::WriteLine(([ordered]@{
        phase='discovery';powershell=$PSVersionTable.PSVersion.ToString()
        edition=$PSVersionTable.PSEdition;all_matches=$allApplications.Count
        default_matches=$defaultApplications.Count;legacy_value_type=$legacyValue.GetType().FullName
        legacy_is_first=($legacyValue -ceq $firstGo);legacy_file_exists=$legacyFileExists
        legacy_failure_reproduced=$legacyFailureReproduced
    } | ConvertTo-Json -Compress))
    if ($defaultApplications.Count -lt 1 -or $defaultApplications.Count -gt 2) {
        throw 'Unexpected default discovery count.'
    }
    if ($defaultApplications.Count -gt 1 -and -not $legacyFailureReproduced) {
        throw 'Multiple legacy paths unexpectedly resolved to a valid file.'
    }
    $selected = Resolve-FixtureGo
    if ($selected -cne $firstGo -or -not [IO.File]::Exists($selected)) {
        throw 'Production discovery did not select the first exact scalar application path.'
    }
    $env:PATH = $second + [IO.Path]::PathSeparator + $first
    if ((Resolve-FixtureGo) -cne $secondGo) { throw 'Reversed PATH did not select its first application.' }
    if ((Resolve-FixtureGo -ExplicitPath $firstGo) -cne $firstGo) {
        throw 'Explicit compiler selection was changed by discovery.'
    }
    $env:PATH = $empty
    $missingHeld = $false
    try { $null = Resolve-FixtureGo } catch [Management.Automation.CommandNotFoundException] { $missingHeld = $true }
    if (-not $missingHeld) { throw 'Missing compiler discovery must fail closed.' }
    [Console]::WriteLine(([ordered]@{
        phase='result';first_match=$true;reversed_first_match=$true
        explicit_path_preserved=$true;missing_held=$true;fake_images_executed=0
    } | ConvertTo-Json -Compress))
} finally {
    $env:PATH = $savedPath
    $env:PATHEXT = $savedPathExt
    # Delete only the exact files and nonrecursive empty directories we created.
    foreach ($image in $createdFiles) { [IO.File]::Delete($image) }
    [array]::Reverse($createdDirectories)
    foreach ($directory in $createdDirectories) { [IO.Directory]::Delete($directory, $false) }
}
