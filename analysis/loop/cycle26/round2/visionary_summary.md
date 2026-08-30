# Cycle 26 Round 2 Visionary — Authentication Extension Integrity Guard MVP

Date: 2026-08-28
Scope: bounded Windows-only defensive observation MVP
Implementation authority: no response authority; no host security mutation

## Outcome

Added a preview `Authentication Extension Integrity Guard` capability. It
observes a fixed Windows authentication-extension catalogue and produces
immutable, path-minimized evidence for:

- LSA `Authentication Packages`, `Notification Packages`, and `Security
  Packages`, including the corresponding fixed `Lsa\OSConfig` values;
- Credential Provider and Credential Provider Filter CLSID registrations and
  their exact `InprocServer32` binding; and
- ordered Network Provider names and each exact `ProviderPath` binding.

The collector never executes a registry value, starts a child process, invokes
`LoadLibrary`, searches `PATH`, performs general environment expansion, reads
credentials, or accesses LSASS memory. Package basenames are resolved only
against System32 obtained through WinAPI. Only recognized Windows-directory
aliases and absolute local-drive paths are admitted; ambiguous, command-like,
network, traversal, reparse, changing, oversized, over-budget, or unverifiable
objects remain explicitly unknown/rejected.

## Evidence and drift model

- Frozen dataclasses validate all snapshots, six required surfaces, strict
  binding order, registry view/type, component and path tokens, SHA256, file
  identity, Authenticode/catalog status, signer thumbprint, file version,
  owner/ACL evidence, coverage, limits, and changes.
- Fixed limits are 252 possible admitted bindings (42 per surface), 256
  components/details, 128 MiB per file, 512 MiB aggregate, 45 seconds per
  collection, 256 drift changes, and a 512 KiB baseline document.
- Raw local paths exist only in bounded immutable in-memory local details.
  Events and authenticated baselines contain purpose-keyed tokens; persisted
  reason fields reject local-path shapes.
- Comparison is pure and bounded. It detects addition, removal, modification,
  reordering, coverage change, component change, and host-binding mismatch. It
  never mutates or promotes the baseline.

## Baseline boundary

- The per-install `bus.key` is only loaded; it is never created, rotated, or
  replaced by this capability. Separate HMAC and privacy keys are derived.
- A complete first observation may be created once, exclusively, as
  provisional. Incomplete evidence is not enrolled.
- Trusted enrollment requires `approved=True`, a bounded operator identity,
  and a meaningful review reason. A provisional snapshot can be promoted only
  if the current snapshot is still exactly stable. Trusted replacement is
  refused and requires a separate future reset workflow.
- Drift never replaces either provisional or trusted state. HMAC/schema,
  host-binding, clock rollback, and freshness failures fail closed.
- Freshness is explicitly local software clock plus HMAC only. The cap is
  configurable only within 15 minutes through seven days and defaults to one
  day. Without an independent high-water or hardware witness, healthy evidence
  is capped at 75% with an exact reason.

## Capability/runtime contract

- Native Contract v12 metadata, Windows-only, mode `observe`, egress `none`,
  response authority `none`, and fixed 15-minute cadence.
- Every event declares exactly `read_only=True`,
  `response_authorized=False`, `response_authority=observe-only`, and
  `attribution=not-assessed`; raw paths and exception messages are omitted.
- Dependency injection supports deterministic safe providers in tests. Missing
  platform, registry, or stable HMAC authority yields all six surfaces as
  unknown rather than inventing a key or claiming absence is safe.
- The module exposes a bounded local detail snapshot and an explicit reviewed
  enrollment method for later GUI/API wiring; this slice intentionally did not
  change shared menus, Module Manager, pages, version, or global count tests.

## Review size and limits

The defensive core is 1,940 physical lines with 85 class/function methods; the
module is 444 physical lines. This is larger than the preferred small MVP
because strict parsing, immutable validation, authenticated persistence, and
the conservative native collector are co-located in the assigned core file.
Native breadth was frozen after the first implementation. No additional
registry surfaces, response actions, commands, signature engines, or UI code
were added. A later refactor may extract a reusable authenticated-baseline
primitive, but doing that inside this round would overlap existing security
state code and increase regression risk.

Known honest limitation: the built-in collector does not invoke a command-line
signature verifier. Authenticode/catalog, owner, ACL, and version evidence stay
partial/unknown when a safe in-process provider is unavailable. That limitation
does not become a clean result and is reflected in component evidence and the
75% local-only health ceiling.

## Files owned by this slice

- `src/angerona/core/windows_auth_extensions.py`
- `src/angerona/modules/authentication_extension_guard.py`
- `tests/test_windows_auth_extensions.py`
- `tests/test_authentication_extension_guard.py`
- `analysis/loop/cycle26/round2/visionary_summary.md`
- one append-only Cycle 26 Round 2 entry in `analysis/loop/LOOP_LOG.md`

## Verification

- `python -m py_compile` for both new product files: PASS.
- Ruff for both product files and both test files: PASS.
- Focused pytest: **15 passed, 0 failed**.
- Capability self-test: PASS — `bounded path-minimized drift and observe-only
  event contract verified`.
- Windows-target discovery: **81 capabilities, zero discovery errors, unique
  native v12 contracts**. The pre-existing global assertion still expects 80;
  it was deliberately not edited because global count ownership belongs to the
  integrating maintainer.
- `git diff --check` for owned files: PASS.

No commit or publication was performed by this agent.
