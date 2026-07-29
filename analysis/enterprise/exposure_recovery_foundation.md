# Exposure and Recovery Foundation

The pure core service in `core/exposure_recovery.py` accepts observations from
existing software, driver, intelligence, and control collectors. It does not
duplicate scanning, CVE advice, shadow-copy monitoring, storage hygiene, IR
bundles, or remediation execution.

Exposure priority is deterministic and explains every contributing factor:
severity, confidence, known exploitation, reachability, runtime presence,
mitigation absence, and fix availability. Recovery plans contain only typed,
reversible steps with explicit prerequisites, verification, and rollback.
`execution_authorized` is permanently false in this planning layer.

Snapshots are local JSON, atomically replaced, schema-versioned, capped at 5,000
exposures/100 plans and 8 MiB, and returned through bounded copies.

Remaining enterprise gates include stable asset identity, signed intelligence
provenance, administrator-owned storage ACLs, retention classes, plan approval
binding, independent verification receipts, and integration with the privileged
broker. None of those should be simulated by this planning-only foundation.
