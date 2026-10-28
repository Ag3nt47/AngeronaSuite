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

## Independent packaged startup

The MSIX entry is `AngeronaSafeStart.exe`, an independent .NET Framework
Windows Forms bootstrap. It embeds the exact SHA-256 of its sibling
`AngeronaStartup.exe`, keeps native file and ancestor leases through execution,
and retains the created helper's process handle and creation time. A failed
helper pin, startup error or 180-second deadline leaves an independent recovery
view. A timeout preserves the helper and any possible core; another attempt
requires proof that the retained helper generation exited. This interface does
not attest protection or replace signed package bytes from a public GitHub file.

The unsigned preparation workflow embeds the unsigned helper digest only to
validate the prepared request. The external authority must use this final order:

1. Independently review and sign the final `AngeronaStartup.exe` bytes.
2. Rebuild SafeStart from independently accepted bootstrap source, embedding
   that final helper digest. Candidate-provided build scripts remain untrusted
   inputs under the provisioning contract above.
3. Sign the resulting SafeStart executable. Verify its embedded helper pin
   against the final signed helper before constructing the MSIX.
4. Recompute the final payload manifest, catalog, provenance and authorization
   statement after all executable changes, then sign and independently accept
   the final MSIX and release assets.

Any subsequent helper signing or byte change requires rebuilding and rechecking
its parent bootstrap. The repository's pre-packaging bootstrap check is a
consistency check for an untrusted prepared request; it does not replace the
external authority's independent verification. That authority remains
unprovisioned, so these source changes do not constitute a signed release.

## Repository-enforced invariants

The checked-in workflow contains no exportable threshold or Windows publisher
secret. Static policy scans every workflow file for known and generic private-key
secret names. Regression tests parse the dependency graph and require unsigned
builder artifacts to pass through the stopping authority gate; neither a failed
gate nor a prepared request can be bypassed with `always()` or
`continue-on-error`. GitHub artifact attestations remain useful public
provenance, but they do not replace the independent release authorization and
Windows publisher controls described here.
