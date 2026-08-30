# Release signing boundary

## Current state: publication disabled

The repository release workflow deliberately stops after it uploads three
explicitly untrusted inputs: `prepared-release-signing-request`,
`prepared-windows-payload`, and `prepared-windows-publisher-request`. The first
two contain unsigned executables, an unsigned catalog, a canonical payload
manifest, an SBOM, provenance, and a candidate statement. The third contains an
unsigned MSIX and ZIP plus their canonical SHA-256 request file. None is
authorization to install or publish.

No repository-controlled job receives a threshold seed, root-policy secret,
Windows publisher PFX, publisher password, or other exportable signing private
key. The workflow does not create the protected migration Setup while this
boundary is unprovisioned. Its no-permission authority job has no checkout,
artifact download, setup action, candidate command, or secret; it exits with a
failure after the unsigned package request exists. The public job depends
directly on that stopping gate and requests a
`finalized-windows-release-assets` artifact that no repository job produces.

This is a fail-closed safety boundary, not a simulated signing service. A tagged
release cannot reach packaging or GitHub publication until an independently
provisioned release authority replaces the stopping gate.

## Provisioning contract

The external authority must be maintained and reviewed independently of the
candidate repository. Its workflow or action must be referenced immutably and
must not check out, import, install, or execute candidate-controlled code. It
must:

1. authenticate the invocation with GitHub OIDC and validate the exact issuer,
   audience, repository, workflow identity, immutable workflow revision, tag,
   source commit, event, and approved environment before signing;
2. canonicalize and bound the prepared release statement using independently
   maintained code, recompute its SHA-256 digest, and treat all builder output
   as untrusted input;
3. require two independently administered, non-exportable release signer
   identities protected by separate reviewer and recovery policies;
4. expose no general signing oracle: an HSM/KMS adapter may authorize only the
   domain-separated digest for the one validated statement and invocation;
5. use a separately governed, non-exportable Windows publisher identity to sign
   the exact reviewed executables, catalog, MSIX, and any later approved Setup;
   an exportable PFX or password must never enter a repository runner;
6. independently pin the Windows publisher certificate, recompute the payload
   manifest, catalog, provenance, and canonical statement after signing, and
   finalize that statement against the immutable threshold root; and
7. return only the bounded witness/final authorization data and the exact
   `finalized-windows-release-assets` artifact expected by publication, without
   exposing signer credentials, root-maintainer authority, or mutable signer
   code to the candidate workspace.

Angerona's current v2 update authorization verifies Ed25519 signatures over the
canonical statement bytes. If the provisioned service signs a digest instead,
that must be introduced as an explicit versioned signature scheme with runtime
verification and migration tests; silently changing the signed message is not
permitted.

## Repository-enforced invariants

The checked-in workflow contains no exportable threshold or Windows publisher
secret. Static policy scans every workflow file for known and generic private-key
secret names. Regression tests parse the dependency graph and require unsigned
builder artifacts to pass through the stopping authority gate; neither a failed
gate nor a prepared request can be bypassed with `always()` or
`continue-on-error`. GitHub artifact attestations remain useful public
provenance, but they do not replace the independent release authorization and
Windows publisher controls described here.
