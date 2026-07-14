# Angerona dynamic SOAR playbook — T1547.001
# Generated 2026-07-14 11:02:52 after a containment bypass.
# Rollback: Remove-NetFirewallRule -Group 'Angerona-SOAR'

netsh advfirewall show all
New-NetFirewallRule -Direction Inbound -Protocol TCP,UDP -LocalPort 135 -Action Block
Get-WmiObject -Class Win32_Process -Filter "Name='wmiex.dll'" | ForEach-Object { $_.Terminate() }
Get-WmiObject -Class Win32_Process -Filter "Name='wmiex.dll'" | ForEach-Object { $_.SetState(0) }
New-NetFirewallRule -Direction Inbound -Protocol TCP,UDP -LocalPort 445 -Action Block