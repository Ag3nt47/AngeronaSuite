<#
================================================================================
  pull-model-to-D.ps1
  Downloads the llama3 model ONTO THE D DRIVE for Angerona's AI.

  Why a script: if the Ollama server is already running without OLLAMA_MODELS
  set, 'ollama pull' would download to C:. This sets the variable, restarts the
  server so it honours it, then pulls — guaranteeing the ~4.7GB model lands on D.

  RUN AS ADMIN:
    Win+R ->
    powershell -NoProfile -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File """D:\local-security-ai\AngeronaSuite\pull-model-to-D.ps1"""'"
================================================================================
#>
$ErrorActionPreference = 'Stop'
$Models = 'D:\Ollama\models'
$Model  = 'llama3'

function Say($m,$c='Gray'){ Write-Host $m -ForegroundColor $c }

# Locate ollama.exe (prefer the D install)
$exe = 'D:\Ollama\ollama.exe'
if (-not (Test-Path $exe)) { $exe = (Get-Command ollama -ErrorAction SilentlyContinue).Source }
if (-not $exe) { Say "Ollama not installed. Run setup-ollama-on-d.ps1 first." Red; exit 1 }
Say "Using: $exe"

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

New-Item -ItemType Directory -Force -Path $Models | Out-Null
[Environment]::SetEnvironmentVariable('OLLAMA_MODELS', $Models, $(if($IsAdmin){'Machine'}else{'User'}))
$env:OLLAMA_MODELS = $Models
Say "OLLAMA_MODELS -> $Models  (scope: $(if($IsAdmin){'Machine'}else{'User'}))"

# Restart the server so it picks up the models path
Say "Restarting Ollama server so it stores models on D ..."
Get-Process ollama -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-Process -FilePath $exe -ArgumentList 'serve' -WindowStyle Hidden
Start-Sleep -Seconds 4

# Pull the model (this is the ~4.7GB download; lands in $Models)
Say "Pulling '$Model' to $Models  (this is the big download) ..." Cyan
& $exe pull $Model

# Verify
Say "`nInstalled models:" Green
& $exe list
$bytes = (Get-ChildItem $Models -Recurse -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
$gb = if ($bytes) { [math]::Round($bytes/1GB,2) } else { 0 }
Say "`nModels folder $Models is now $gb GB."
Say "Done. Restart Angerona and AI Triage will go green." Green
