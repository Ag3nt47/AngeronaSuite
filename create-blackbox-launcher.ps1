<#
================================================================================
  create-blackbox-launcher.ps1
  Puts an "Angerona Black Box" shortcut on your Desktop (and an "Angerona"
  shortcut too, if you don't already have one) so both launch with one click.

  - Black Box icon: assets\icons\blackbox.ico  (black box on a blue background)
  - Runs the recorder with the venv's pythonw.exe (no console window), --show so
    its window opens the first time.
  - Writes create-blackbox-launcher.log next to this script recording exactly
    where the shortcut(s) were placed (helps when a OneDrive-redirected Desktop
    makes the icon "not appear" in the folder you're looking at).

  RUN (no admin needed):
    powershell -NoProfile -ExecutionPolicy Bypass -File "create-blackbox-launcher.ps1"
================================================================================
#>
$ErrorActionPreference = 'Stop'

$root    = $PSScriptRoot
if (-not $root) { $root = Split-Path -Parent $MyInvocation.MyCommand.Path }
$log     = Join-Path $root 'create-blackbox-launcher.log'
$wsh     = New-Object -ComObject WScript.Shell

function Log($m) {
    $line = "{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m
    Write-Host $line
    Add-Content -Path $log -Value $line -Encoding UTF8
}

"=== Angerona launcher run ===" | Out-File $log -Encoding UTF8
Log "root = $root"

# Collect every plausible Desktop location so the icon lands where the user
# actually looks: the shell 'Desktop' (may be OneDrive-redirected), the classic
# %USERPROFILE%\Desktop, and a OneDrive\Desktop if present. De-duplicated.
$desktops = @()
try { $desktops += [Environment]::GetFolderPath('Desktop') } catch {}
if ($env:USERPROFILE) { $desktops += (Join-Path $env:USERPROFILE 'Desktop') }
if ($env:OneDrive)    { $desktops += (Join-Path $env:OneDrive 'Desktop') }
$desktops = $desktops | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
Log ("desktops = " + ($desktops -join ' | '))

# Prefer the venv's windowless interpreter; fall back to system pythonw.
$pyw = Join-Path $root 'venv\Scripts\pythonw.exe'
if (-not (Test-Path $pyw)) { $pyw = 'pythonw.exe' }
Log "pythonw = $pyw"

$bbTarget = Join-Path $root 'blackbox_recorder.py'
$bbIcon   = Join-Path $root 'assets\icons\blackbox.ico'
if (-not (Test-Path $bbTarget)) { Log "ERROR: blackbox_recorder.py not found at $bbTarget"; exit 1 }

$made = 0
foreach ($d in $desktops) {
    try {
        $bbLnk = Join-Path $d 'Angerona Black Box.lnk'
        $s = $wsh.CreateShortcut($bbLnk)
        $s.TargetPath       = $pyw
        $s.Arguments        = '"' + $bbTarget + '" --show'
        $s.WorkingDirectory = $root
        if (Test-Path $bbIcon) { $s.IconLocation = $bbIcon }
        $s.Description      = 'Angerona Black Box - out-of-band diagnostic recorder (read-only)'
        $s.Save()
        if (Test-Path $bbLnk) { Log "OK  Black Box shortcut -> $bbLnk"; $made++ }
        else { Log "WARN save reported no error but file missing -> $bbLnk" }

        # Angerona shortcut too, if missing.
        $agLnk = Join-Path $d 'Angerona.lnk'
        if (-not (Test-Path $agLnk)) {
            $runBat = Join-Path $root 'run.bat'
            $agIcon = Join-Path $root 'assets\icons\angerona.ico'
            if (Test-Path $runBat) {
                $a = $wsh.CreateShortcut($agLnk)
                $a.TargetPath       = $runBat
                $a.WorkingDirectory = $root
                if (Test-Path $agIcon) { $a.IconLocation = $agIcon }
                $a.Description      = 'Angerona - local-first endpoint security suite'
                $a.Save()
                Log "OK  Angerona shortcut  -> $agLnk"
            }
        }
    } catch {
        Log ("ERROR on {0}: {1}" -f $d, $_.Exception.Message)
    }
}

Log "DONE. Black Box shortcuts created: $made"
Write-Host ""
Write-Host "If you still don't see it, check the OneDrive Desktop path logged above." -ForegroundColor Cyan
