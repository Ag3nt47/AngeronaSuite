# Enterprise architecture decisions

These accepted decisions constrain implementation. Revisions require a dated
decision record and threat-model review.

## ADR-001 — Fleet identity and trust roots

Each endpoint owns a unique Ed25519 identity. Bootstrap is single-use and
short-lived. Production transport uses per-device mutual TLS credentials;
shared fleet secrets are not steady-state identity. Revocation and tenant
binding fail closed.

## ADR-002 — Control-plane deployment

Standalone protection works without a control plane. The current fleet service
is loopback-only. Public/LAN deployment requires mutual TLS, scoped
authorization, rate limits, high availability, backup, and recovery evidence.

## ADR-003 — Events and storage

Raw observation, normalized event, analytic conclusion, policy decision,
operator decision, response, and verification receipt remain distinct. OCSF is
the normalized interchange contract. Storage is bounded and privacy-classified.

## ADR-004 — Remote action safety

There is no generic remote shell. Commands are typed, signed, scoped, expiring,
idempotent, replay-resistant, approval-gated, reversible where possible, and
produce verification receipts. High-impact actions require separation of duty.

## ADR-005 — Software and content updates

Release artifacts, detection content, policy, and plugins have separate trust
channels. Activation requires signature, digest, compatibility, expiry,
preflight, canary/rollback metadata, and last-known-good recovery.

## ADR-006 — Multi-tenancy and plugin isolation

Tenant identity is an explicit predicate in every fleet query and write.
Plugins are disabled by default, verified before import, declare permissions,
privacy, egress and budgets, then stage and revalidate without lifecycle-time
execution.
