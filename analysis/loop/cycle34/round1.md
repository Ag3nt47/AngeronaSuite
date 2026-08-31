# Cycle 34 Round 1 — initial hardening and research

## Findings and remediation

The initial audit recorded **five findings (3 High, 1 Medium, 1 Low)**. All five
were fixed.

- The flow-canvas launcher had a wildcard repository-serving boundary and a
  CDN dependency without integrity binding. The replacement serves only the
  canvas and runtime metrics on checked loopback requests; the browser
  dependency is version-pinned and Subresource Integrity protected.
- A legacy Detection Content registry could mutate production state outside
  promotion governance. Production transitions now require the private
  coordinator capability and persistent governance policy.
- DetectionForge could compose a detached evaluation engine instead of the
  subscribed Detection Runtime module. Local Operations Center now binds the
  exact managed module, engine, manager, EventBus, and lifecycle generation.
- Activating a second package could evict the first package's live rules. The
  coordinator now reconciles the complete governed active set and enforces the
  128-binding limit before mutation.
- Fleet Health Monitor was not bound to the Local Operations Center's exact
  store and identity authority. Composition now binds and validates that
  authority before module start.

Authenticated v2 detection-state migration was also constrained to complete,
consistent state/registry history; truncated history fails closed.

## Performance

AegisPath now builds immutable path and node indexes with each rendered
snapshot. Selecting a path performs work proportional to path length, and
selecting a node performs work proportional to its incident degree, instead of
rescanning all paths and edges. Selection semantics and displayed evidence are
unchanged.

## Research disposition

One web-research pass ranked 11 current defensive proposals from primary
sources. No MVP was selected or shipped because the three High findings took
priority. The exact proposal titles were not retained in the loop record, so
this documentation does not reconstruct or invent them.
