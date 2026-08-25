function Get-AngeronaCommandLineTokens {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return @() }
    $tokens = @()
    foreach ($match in [regex]::Matches($CommandLine, '(?:"([^"]*)"|(\S+))')) {
        if ($match.Groups[1].Success) { $tokens += $match.Groups[1].Value }
        else { $tokens += $match.Groups[2].Value }
    }
    return $tokens
}

function Test-AngeronaPathUnderRoot {
    param([string]$Candidate, [string]$Root)
    try {
        if (-not [IO.Path]::IsPathRooted($Candidate)) { return $false }
        $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd([char]92, [char]47)
        $candidatePath = [IO.Path]::GetFullPath($Candidate)
        $prefix = $rootPath + [IO.Path]::DirectorySeparatorChar
        return $candidatePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
    } catch { return $false }
}

function Test-AngeronaProcessOwnership {
    param($Process, [string]$Root)
    try {
        $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd([char]92, [char]47)
        $exe = if ($Process.ExecutablePath) { [IO.Path]::GetFullPath([string]$Process.ExecutablePath) } else { '' }
        $suiteInterpreters = @(
            [IO.Path]::GetFullPath((Join-Path $rootPath 'venv\Scripts\python.exe')),
            [IO.Path]::GetFullPath((Join-Path $rootPath 'venv\Scripts\pythonw.exe'))
        )
        $tokens = @(Get-AngeronaCommandLineTokens ([string]$Process.CommandLine))
        $suiteInterpreter = [bool]($suiteInterpreters | Where-Object {
            $exe.Equals($_, [StringComparison]::OrdinalIgnoreCase)
        })
        $approvedModules = @(
            'angerona',
            'angerona.resilience.scanner',
            'angerona.resilience.status_ui',
            'angerona.resilience.watchdog'
        )
        if (
            $suiteInterpreter -and
            $tokens.Count -ge 3 -and
            $tokens[1] -ceq '-m' -and
            $tokens[2] -cin $approvedModules
        ) { return $true }

        if ($tokens.Count -lt 2) { return $false }
        $approvedScripts = @(
            [IO.Path]::GetFullPath((Join-Path $rootPath 'src\angerona\__main__.py')),
            [IO.Path]::GetFullPath((Join-Path $rootPath 'blackbox_recorder.py'))
        )
        for ($i = 1; $i -lt $tokens.Count; $i++) {
            $token = [string]$tokens[$i]
            if ($token -in @('-W', '-X')) { $i++; continue }
            if ($token.StartsWith('-')) { continue }
            if ([IO.Path]::GetExtension($token) -notin @('.py', '.pyw')) { return $false }
            if (-not [IO.Path]::IsPathRooted($token)) { return $false }
            $script = [IO.Path]::GetFullPath($token)
            return [bool]($approvedScripts | Where-Object {
                $script.Equals($_, [StringComparison]::OrdinalIgnoreCase)
            })
        }
    } catch { }
    return $false
}
