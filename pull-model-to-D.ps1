<# Download an Ollama model into Angerona's install-drive runtime folder. #>
param(
    [string]$Model = 'llama3:8b',
    [string]$Models = $(if ($env:ANGERONA_DATA) {
        Join-Path $env:ANGERONA_DATA 'ollama\models'
    } else {
        Join-Path $PSScriptRoot 'runtime-data\ollama\models'
    })
)
$ErrorActionPreference = 'Stop'
$Models = [IO.Path]::GetFullPath($Models)

$candidates = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama.exe'),
    (Join-Path $env:ProgramFiles 'Ollama\ollama.exe')
) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) }
$exe = $candidates | Select-Object -First 1
if (-not $exe) { throw 'Ollama is not installed in a supported location.' }

New-Item -ItemType Directory -Force -Path $Models | Out-Null
[Environment]::SetEnvironmentVariable('OLLAMA_MODELS', $Models, 'User')
$env:OLLAMA_MODELS = $Models
Write-Host "OLLAMA_MODELS -> $Models" -ForegroundColor Cyan

Get-Process ollama -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Process -FilePath $exe -ArgumentList 'serve' -WindowStyle Hidden
Start-Sleep -Seconds 4
& $exe pull $Model
& $exe list
