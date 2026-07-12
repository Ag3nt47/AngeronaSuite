# Angerona dynamic SOAR playbook — T1547.001
# Generated 2026-07-08 20:03:23 after a containment bypass.
# Rollback: Remove-NetFirewallRule -Group 'Angerona-SOAR'

netsh advfirewall show all
New-NetFirewallRule -Direction Inbound -Protocol TCP,UDP -LocalPort 135 -Action Block
Get-WmiObject -Class Win32_Process -Filter "Name='wmiex.dll'" | ForEach-Object { $_.Terminate() }
Get-WmiObject -Class Win32_Process -Filter "Name='wmiex.dll'" | ForEach-Object { $_.SetState(0) }
New-NetFirewallRule -Direction Inbound -Protocol TCP,UDP -LocalPort 445 -Action Block
Get-Process -Name wmiex* | Where-Object {$_.MainWindowTitle -eq ""} | Stop-Process -Force
Get-Process -Name wmiex* | Where-Object {$_.MainWindowTitle -eq ""} | Remove-Process -Force