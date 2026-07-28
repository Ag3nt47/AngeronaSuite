# Visionary Enterprise Cycle 5

## Outcome

Cycle 5 ships one additive, read-only capability: the **Capability Drift
Auditor** in `angerona.enterprise_capability_drift_c5`. It statically inspects a
bounded Python extension, compares sensitive operations with its declared
Capability Manifest v1 permissions, and produces a deterministic review report.
It never imports or executes the inspected extension.

This is deliberately not an admission decision, sandbox, or marketing claim.
The existing signature gate proves publisher approval and source integrity; the
new auditor adds evidence about whether the source appears consistent with what
the manifest claims.

## Loop 1 — Current enterprise research

- Velociraptor packages endpoint work into permission-aware artifacts and its
  verifier checks dangerous functions against `required_permissions` /
  `implied_permissions`. This directly supports a pre-execution capability-drift
  check:
  <https://docs.velociraptor.app/docs/artifacts/security/>
- Falco treats its plugin API as a formal, semantically versioned contract and
  refuses incompatible plugins:
  <https://falco.org/docs/reference/plugins/plugin-api-reference/>
- Sigstore verification binds an artifact digest to a signature and identity,
  while attestations allow policy to validate additional claims:
  <https://docs.sigstore.dev/cosign/verifying/verify/>
- SLSA 1.2 describes provenance and attestations as incremental supply-chain
  integrity controls:
  <https://slsa.dev/spec/v1.2/>
- Wazuh separates endpoint collection, analysis, indexing, and dashboard/control
  functions for scale and fault tolerance:
  <https://documentation.wazuh.com/current/getting-started/architecture.html>

## Loop 2 — Gap selection

The current shared tree already contains:

- detached capability manifests with source hashing and Ed25519 publisher trust;
- a bounded read-side causal incident graph;
- proof-carrying remediation receipts;
- an evidence-based enterprise-readiness report.

The remaining narrow gap was that a correctly signed manifest could still
declare fewer permissions than its source visibly uses. Automatic enforcement
based on heuristic static analysis would be unsafe, so Cycle 5 selected a
review-only auditor. This is low risk, creates no new thread or network surface,
changes no host state, and can later become one input to a human-controlled
extension admission workflow.

## Loop 3 — Shipped implementation

The auditor:

- reads only bounded, regular, non-symlink source and manifest files;
- parses Python with `ast` and never imports inspected code;
- resolves common import aliases;
- identifies static signals for network, process, filesystem, registry,
  firewall, credential-store, and AI permissions;
- flags dangerous dynamic execution, deserialization, `shell=True`, and native
  library loading;
- checks manifest source digest and entrypoint drift;
- reports undeclared high-risk capabilities as errors;
- reports declared-but-unobserved high-risk capabilities as information, not a
  false assurance;
- returns deterministic JSON-compatible reports without exposing full local
  paths.

Tests cover non-execution, deterministic output, declared read-only behavior,
digest and entrypoint drift, dynamic execution, shell invocation, registry and
firewall changes, dynamic file modes, syntax errors, bounded manifest loading,
and path privacy.

## Proposals, not shipped

1. Feed this report into the signed extension admission dialog after a human
   review workflow exists.
2. Add policy-pack signatures and staged/canary rollout for fleets.
3. Run a stronger semantic analyzer in CI and publish its result as a Sigstore
   or in-toto attestation.
4. Isolate accepted external extensions in an AppContainer or dedicated
   low-privilege worker; static analysis is not a security boundary.
5. Add mTLS device enrollment, RBAC, immutable administrator audit, central OCSF
   retention, and high availability as separate enterprise control-plane work.

## Residual risks

- Python behavior can be hidden behind aliases, reflection, native libraries,
  encoded strings, imported dependencies, or data-driven calls.
- Medium-confidence method-name heuristics can produce false positives.
- A clean report cannot prove benign behavior or completeness.
- Signature authenticity remains the responsibility of the existing manifest
  verifier.
- The auditor is currently a callable library and test-gated foundation; it is
  not yet wired into module loading or the GUI.

