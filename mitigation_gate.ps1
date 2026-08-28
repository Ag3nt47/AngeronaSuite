<#
  Angerona v1.12 compatibility stub.

  The former gate discovered and dot-sourced generated PowerShell while
  elevated. That mechanism had no exact target binding, transactional rollback,
  postcondition verification, or authenticated receipt, so it is intentionally
  disabled. Use the typed SOAR review queue or Adaptation workbench instead.
#>
$ErrorActionPreference = 'Stop'
Write-Error (
    'Legacy dynamic mitigation scripts are disabled in Angerona v1.12. ' +
    'Review a typed, precondition-bound action in the SOAR queue.'
)
exit 1
