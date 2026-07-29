# Support and security operations

## Ownership roles

- Agent/runtime: Core Maintainer
- Sensors/content: Detection Maintainer
- Fleet/control/data: Platform Maintainer
- Identity/policy/update/release signing: Trust Maintainer
- Privacy/export: Privacy Maintainer
- UI/accessibility/documentation: Experience Maintainer
- Incident response/vulnerability intake: Security Response Lead

One person may hold multiple community roles, but high-impact approval and
release-signing actions still require an independent reviewer.

## Severity and response targets

- Critical: release/update trust compromise, secret exposure, unauthorized
  remote action, or destructive data loss. Acknowledge target: 1 day.
- High: exploitable privilege/trust failure or widespread bypass. Target: 2
  business days.
- Medium: bounded security/reliability defect. Target: 5 business days.
- Low: hardening, documentation, or limited-impact issue. Target: 10 business days.

Targets are community goals, not a commercial service-level agreement.

Diagnostic bundles are previewed and minimized before export. Credentials,
cookies, raw content, personal paths, and unrelated telemetry are excluded.
Escalation preserves evidence hashes and custody metadata. Known issues,
affected versions, mitigations, and fixed versions are published without
exposing reporters or exploit details prematurely.
