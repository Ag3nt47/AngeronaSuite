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
        if ($suiteInterpreters | Where-Object { $exe.Equals($_, [StringComparison]::OrdinalIgnoreCase) }) {
            return $true
        }

        $tokens = @(Get-AngeronaCommandLineTokens ([string]$Process.CommandLine))
        if ($tokens.Count -lt 2) { return $false }
        for ($i = 1; $i -lt $tokens.Count; $i++) {
            $token = [string]$tokens[$i]
            if ($token -in @('-W', '-X')) { $i++; continue }
            if ($token.StartsWith('-')) { continue }
            if ([IO.Path]::GetExtension($token) -notin @('.py', '.pyw')) { return $false }
            return Test-AngeronaPathUnderRoot -Candidate $token -Root $rootPath
        }
    } catch { }
    return $false
}
