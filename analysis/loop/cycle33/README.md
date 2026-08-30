# Cycle 33 — AegisPath exposure and attack-path analysis

**Scope:** authorized defensive-only theoretical hardening

**Release target:** 1.13.0
**Disposition:** COMPLETE

## Round 1 — visionary and implementation

Microsoft and Tenable attack-path guidance, FIRST EPSS, CISA's Known Exploited
Vulnerabilities catalog, and NIST Cybersecurity Framework 2.0 were compared with
Angerona's existing provenance, asset, and vulnerability evidence. The selected
program adds an immutable evidence-bound exposure graph, bounded cycle-safe
confirmed/speculative paths, choke points, blast radius, inert breakpoint
counterfactuals, and explainable KEV/EPSS/criticality priority. `AegisPath` is an
embeddable Local SOC tab and its native guard is observe-only.

## Round 2 — adversarial repair

The initial audit recorded **9 findings (2 High, 6 Medium, 1 Low)** across
evidence authority, exact CVE applicability, absence/negative evidence,
selection manifests, graph bounds, provider failure, simulation coverage, and
priority truth. First remediation mapped and fixed all nine. Independent
re-attack found `C33-RA-01..07` (**2 High, 3 Medium, 2 Low**); second remediation
fixed all seven.

Confirmed and closed paths now require finite content-bound evidence. A
speculative `NOT_APPLICABLE` edge remains visible unless a current, bounded,
authoritative closed negative suppresses it. FULL/FILTERED selection and
expected sets are receipt-verified. Unverified what-if output is red and cannot
be represented as proof.

## Round 3 — performance and verification

Summary counts are O(paths), snapshot hashing/indexing/adjacency/priority/render
work is bounded, initial large analysis runs off the UI thread, and duplicate
Local SOC/widget refresh was removed. Final focused regressions passed
**40/40**; Ruff, `py_compile`, and the module self-test passed. Root serial,
performance, and integration gates found no reopened issue.

## Residual boundary

Manifest and relationship-absence authority remain local governed provider and
policy trust, not external PKI. Python can quarantine a blocked provider but
cannot terminate it. Work-byte estimates are not operating-system RSS. Large
what-if rendering is disabled in favor of bounded backend analysis. Simulation
is inert and proves neither exploit reachability nor remediation effectiveness.
