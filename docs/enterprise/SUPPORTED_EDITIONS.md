# Supported editions and claims

Angerona has one open-source codebase. “Edition” describes verified deployment
scope, not a paywall.

## Community / Standalone

- Supported now on Windows from source; packaged support follows each release.
- One host, local data, local operator, offline detection and investigation.
- Optional integrations remain disabled until explicitly configured.
- Security fixes are never withheld from this edition.

## Fleet Preview

- Experimental, opt-in, loopback-only control-plane service.
- Tenant-isolated inventory and ingestion, signed requests, replay protection,
  typed jobs, policies, cases, response proposals, and receipts.
- Not supported on a public or Local Area Network interface.
- Does not claim production mutual TLS, SSO, high availability, or central scale.

## Enterprise candidate

This label is reserved until the release-maturity gates in
`ENTERPRISE_UPGRADE_TODO.txt` pass. It requires production identity, mutual TLS,
role governance, high availability, disaster recovery, signed delivery,
physical-host soak tests, external penetration testing, and support operations.

## Platform coverage

- Windows: Protect edition, user-mode; no production kernel driver.
- macOS: Observe source preview pending Apple entitlement/signing/notarization.
- Linux: selected headless/eBPF foundations; not parity with Windows.

Interfaces must show unavailable, unknown, degraded, preview, and externally
gated capabilities honestly. “Enterprise ready,” “tamper proof,” “zero trust,”
and certification claims require objective release evidence.
