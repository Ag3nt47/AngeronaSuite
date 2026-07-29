# Loop 2 — Transactional Network Containment

## Implemented

The WFP controller now exposes a safe planning and proof boundary for future
privileged containment brokers:

- containment is limited to validated IP, CIDR, port, or executable-basename
  targets and an explicit traffic direction;
- preview (`dry_run`) is the default and preview plans cannot be applied;
- plans have a mandatory 30-second to 24-hour expiry;
- loopback, DNS, and DHCP recovery exclusions are always included;
- execution requires explicit approval and an injected, auditable privileged
  executor—there is no hidden `netsh` or shell enforcement path;
- approval is bound to the exact canonical plan identifier;
- submitted plan objects are treated as untrusted and fully reconstructed,
  revalidating targets, timestamps, TTL, exclusions, identity, and ordering;
- an executor must return concrete rollback actions or the transaction fails;
- deterministic SHA-256 plan and receipt digests make accidental or
  after-the-fact receipt modification detectable;
- an independent verification callback can require confirmation from another
  sensor or broker.

## Security guarantees

Malformed targets, shell metacharacters, arbitrary executable paths, naive
timestamps, empty scope, missing recovery exclusions, stale plans, silent execution, and
untracked execution all fail closed at the controller boundary. Given identical
inputs and time, plan identity and ordering are deterministic.

## Explicit limits

This layer does not itself install WFP filters, grant privileges, attest the
host, cryptographically authenticate an operator, or schedule expiry rollback.
Those responsibilities belong to a separately privileged broker and service
supervisor. SHA-256 receipt digests are tamper-evident checksums, not signatures;
enterprise deployments should have the broker sign receipts with a protected
machine key and independently verify both enforcement and rollback.

## Verification

`tests/test_wfp_containment_transactions.py`: 10 passed.
