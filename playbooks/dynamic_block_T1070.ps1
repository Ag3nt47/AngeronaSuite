# Angerona dynamic SOAR playbook — T1070
# Generated 2026-07-12 19:57:30 after a containment bypass.
# Rollback: Remove-NetFirewallRule -Group 'Angerona-SOAR'

netsh advfirewall show all
New-NetFirewallRule -Direction Inbound -Protocol TCP,UDP -LocalPort 445 -Action Block
Get-WmiObject -Class Win32_Process -Filter "Name='explorer.exe'" | ForEach-Object { $_.Terminate() }
Get-WmiObject -Class Win32_Process -Filter "Name='svchost.exe'" | ForEach-Object { $_.Terminate() }
Get-WmiObject -Class Win32_Process -Filter "Name='wmiex.dll'" | ForEach-Object { $_.Terminate() }
New-NetFirewallRule -Direction Inbound -Protocol TCP,UDP -LocalPort 135 -Action Block
New-NetFirewallRule -Direction Inbound -Protocol TCP,UDP -LocalPort 139 -Action Block
Get-WmiObject -Class Win32_Process -Filter "Name='wmiex.dll'" | ForEach-Object { $_.SetState(0) }