# Angerona dynamic SOAR playbook — T1059
# Generated 2026-07-12 20:04:32 after a containment bypass.
# Rollback: Remove-NetFirewallRule -Group 'Angerona-SOAR'

netsh advfirewall show all
New-NetFirewallRule -Direction Inbound -Protocol TCP,UDP -LocalPort 135 -Action Block
Get-WmiObject -Class Win32_Process -Filter "ProcessId = 1234" | ForEach-Object { $_.Terminate() }
Get-WmiObject -Class Win32_Process -Filter "ProcessId = 5678" | ForEach-Object { $_.Terminate() }
New-NetFirewallRule -Direction Inbound -Protocol TCP,UDP -LocalPort 135 -Action Block
netsh advfirewall show all