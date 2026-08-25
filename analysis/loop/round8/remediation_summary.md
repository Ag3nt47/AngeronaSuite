# Round 8 — Host Adaption Remediation Summary

Date: 2026-08-24. All five adversary findings were remediated in the bounded
host-adaptation implementation. No arbitrary command surface, service/process
action, route edit, or firewall-disable path was added.

| Finding | Status | Applied mitigation |
| --- | --- | --- |
| R8-RT-01 | FIXED | Monotonic state revisions, compare-and-swap updates, a process-wide transaction lock, fresh context/automation authorization, and a final pre-execution guard prevent stale or concurrent workers from mutating the host. |
| R8-RT-02 | FIXED | Profile commands use trusted absolute PowerShell/System32 paths and a sanitized environment. Apply re-reads the effective Firewall ActiveStore and verifies exact profile postconditions; failure triggers verified rollback. Rollback verifies manifest/artifact digests and the restored effective profiles and bounded rule inventory. |
| R8-RT-03 | FIXED | Exceptions bind to the exact finding fingerprint, including before/after state. Feedback is one-shot per fingerprint, requires three distinct reviewed findings before tuning, and uses a 0.75 floor. Removing an exception removes its feedback contribution. |
| R8-RT-04 | FIXED | All matching contexts are ordered by profile strength. Public-network evidence cannot be hidden by adapter enumeration or weakened by SSID/VPN rules; automatic changes that relax the observed posture are refused for manual review. |
| R8-RT-05 | FIXED | Collector quality records completeness, availability, truncation, skips, and sanitized errors. Incomplete categories are not scored as healthy. Services include privacy-minimized command/account identity; listeners preserve protocol/family/address scope; firewall collection includes effective ActiveStore profiles and a bounded rule inventory. |

The later live read-only Windows smoke exposed one final integration issue:
`Get-NetFirewallProfile` without an explicit store returned `NotConfigured`
defaults on this host. The collector now requests `-PolicyStore ActiveStore`,
which returns the effective explicit `Block`/`Allow` values required by planning
and postcondition checks.

## Deferred depth

- Per-rule firewall filter joins for program, service, local/remote address, and
  local/remote port are not yet collected.
- Executable signer and content-hash attestation for service binaries is not yet
  implemented; the shipped service identity is privacy-minimized command digest,
  executable name, and account type/identifier.
- Crash-independent trial leases and event-driven network wakeups remain
  proposed and require native Windows lifecycle testing.

## Verification

- Focused final host-adaptation and GUI/performance set: **20 passed**.
- Full repository suite: **1077 passed, 3 intentional platform skips, 0 failed**
  in 75.71 seconds.
- Headless selfcheck: **26/26 passed**.
- Real elevated firewall mutation and physical network-topology acceptance were
  deliberately not run.

