# Versioning and compatibility policy

Angerona follows semantic versioning for the application and independently
versions data and control contracts.

- Patch: compatible security, reliability, detection, and documentation fixes.
- Minor: backward-compatible capability or schema additions.
- Major: intentional compatibility break with migration and rollback guidance.

## Supported windows

- Settings and databases: current major plus the immediately preceding major,
  with explicit migration and backup.
- Fleet protocol: current protocol plus one previous minor during rolling
  upgrades. Unknown authorization semantics fail closed.
- Event schemas: producers declare versions; readers preserve unmapped source
  fields and reject unsupported mandatory semantics.
- Detection, policy, and plugin packages: exact API/schema version, signature,
  digest, expiry, and compatibility are checked before activation.

Downgrades never silently rewrite newer state. Operators must use a verified
backup or release-provided reverse migration. Trust roots, revocations, replay
ledgers, custody chains, and audit receipts are never downgraded to an
unauthenticated format.

Deprecations require one minor-release warning period and a documented
replacement. A security boundary may be removed immediately when continued
support would be unsafe.
