# Cycle 19 — Cross-platform sensor visibility attestation MVP

Date: 2026-08-21  
Scope: software-HMAC sensor-health metadata; Windows, macOS, Linux, and unknown
platform contracts.

## Outcome

Implemented a bounded, versioned visibility assertion that lets a provisioned
sensor report whether its expected canary families were observed. The status
surface classifies the latest authenticated state as `healthy`, `degraded`,
`blind`, or `untrusted` without ingesting raw events or triggering response.

This is deliberately **not** described as native, kernel, enclave, TPM, Secure
Enclave, or other hardware-backed proof. A valid document proves only that a
party holding the injected software HMAC authority produced the metadata.

## Contract and trust boundaries

- Canonical format: `angerona-visibility-attestation-v1`.
- Required metadata: sensor ID, platform, build and policy SHA-256, session
  epoch, sequence, sorted expected/observed canary families, cumulative drop
  count, issue/expiry time, and clock quality.
- Authority: caller-injected HMAC-SHA256 key of at least 32 bytes. There is no
  global key lookup or implicit filesystem authority in the component.
- Maximum canonical document size: 8 KiB.
- Maximum canary families: 32; identifiers are short allowlisted tokens.
- Maximum lifetime: 10 minutes; future issue time is bounded.
- Exact wrapper/payload schemas reject extension fields. Paths, usernames,
  command lines, network endpoints, response actions, and raw telemetry cannot
  be represented by the contract.
- Registry cardinality is bounded and least-recently-used. Rejected unauthenticated
  documents cannot create a claimed sensor identity in the registry.

## Classification rules

- `healthy`: current authenticated metadata, every expected canary observed,
  zero reported drops, and synchronized/estimated clock quality.
- `degraded`: at least one canary missing, a non-zero drop counter, or weak clock
  quality.
- `blind`: no expected canary was observed or the last authenticated assertion
  expired.
- `untrusted`: malformed/forged input, future-clock violation, replay, session or
  sequence regression, drop-counter regression, or material sensor-clock
  regression.

Session and sequence high-water marks remain intact after rejected regressions,
so an older document cannot lower the replay barrier. A higher session epoch may
legitimately reset the per-session sequence and drop counter.

## Integration

- `core/telemetry_coverage.py` accepts an optional preconfigured visibility
  registry, provides a bounded ingest method, and exports privacy-minimal status
  dictionaries.
- `core/status_report.py` adds a separate sensor-visibility section to JSON and
  text snapshots. When no authority is configured, it explicitly reports that
  no visibility proof is claimed.
- No network client, filesystem persistence, telemetry payload, or containment
  action was added.

## Deterministic verification

- New focused tests: **12 passed**.
- Visibility plus existing telemetry-coverage tests: **19 passed**.
- Visibility, telemetry coverage, and StatusReporter performance/regression
group: **23 passed**.
- Ruff correctness gate: PASS.
- Python compile gate: PASS.

Tests cover canonical signing, forgery, replay, sequence regression, future and
stale clocks, partial/zero canary observation, drop reporting and regression,
LRU eviction, strict key/cardinality bounds, privacy-field rejection, dynamic
expiry, and the explicit unconfigured state.

## Next hardening gate

Before calling this native or hardware-backed evidence, define a separate
platform-specific proof carrier and verifier (for example a signed Windows
service measurement, TPM quote, Apple Endpoint Security system-extension
identity, or Linux IMA/TPM evidence). That future proof should bind this exact
canonical payload and remain optional; absence must continue to display as
software-only visibility rather than silently upgrading trust.
