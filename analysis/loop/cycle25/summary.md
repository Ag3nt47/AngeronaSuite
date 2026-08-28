# Cycle 25 — Angerona v1.12 capability, adaptation, and reliability upgrade

Date: 2026-08-28
Product version: 1.12.0
Mode: local-first, actor-neutral, defensive-only engineering

## Outcome

Cycle 25 inspected every discovered capability and upgraded the shared product
contracts, operator workflows, delivery durability, mutation recovery,
standards truth, and GUI detail surfaces. It does not claim that every module
implementation was individually rewritten or assigned version 12.

The reproducible Windows-target inventory contains exactly **80 capabilities**:

- **5** native v12 contracts;
- **75** explicit compatibility adapters;
- implementation versions: **51 at 1.0.0**, **28 at 1.1.0**, and the macOS
  Observe preview at **0.1.0**.

Product semver and module implementation semver are intentionally independent.
All 80 receive the same validated v12 contract schema and operational
freshness/loss/lifecycle snapshot, while adapter metadata gaps remain visible.

## Guided adaptation and host recovery

- **Guided Auto Adapt** offers Balanced, Public, and Emergency Lockdown choices
  with explicit apply and baseline-enrollment options. It runs audit,
  completeness gating, immutable planning, and no-write simulation first.
- Accepted choices are copied immutably before background work starts. An
  optional apply requires a separate exact-plan confirmation; context-driven
  automation remains proposal-only and cannot mutate unattended.
- The recovery baseline is explicitly enrolled, HMAC-authenticated, host-bound,
  non-replaceable, and required before mutation. It restores the complete
  Windows Firewall policy—the complete mutation scope of Host Adaptation—not
  hardware, services, ports, applications, or network devices.
- Each apply also captures a pre-change snapshot. An HMAC transaction journal,
  exact verification, compensation, startup reconciliation, and mutation
  circuit breaker make interrupted work visible and recoverable.
- **Run safe automatic checkup** audits once and simulates every profile without
  writing.

## Capability and operator surfaces

- Capability Center and Module Inspector search, filter, sort, and open bounded
  details for contracts, implementation/native-adapter status, source,
  dependencies, permissions, paths, lifecycle, freshness, loss, and evidence.
- Adaptation, alerts, Context Info, Live Defense, CVE, and other row-based
  surfaces use typed severity/numeric sorting and bounded clickable details.
- Live Alert detail distinguishes record identity, deterministic fingerprint,
  and verified HMAC authenticity. Analysis is limited to two active workers and
  six queued exact event identities with deduplication.
- Temporary rule suppression requires exact confirmation, lasts 15 minutes,
  exposes audit and Undo, and cannot suppress integrity alerts.
- SOAR history clearing creates a recoverable archive and digest manifest;
  restore refuses overwrite. CVE detail work is owned and nonblocking.

## Reliability and hardening

- SIEM Forwarder and Remote Bridge use bounded durable outboxes, monotonic
  revision cursors, drain-stage-drain ordering, explicit gap receipts, leases,
  retries, dead letters, idempotent tombstones, and HMAC-authenticated mutable
  state. The queue key is independent of transport-key rotation.
- Configuration and Settings use atomic replacement plus compensation across
  settings bytes, protected credentials, environment projection, and autostart.
  Intel Sync uses atomic generation/cancel/status publication.
- Evolution and mitigation tuning are proposal-only. Behavioral changes require
  exact content-hash approval and return to pending review on drift.
- Process actions bind PID, creation time, executable/name and immediate
  revalidation. Driver and direction-specific firewall actions verify return
  codes, exact postconditions, and rollback. Ambiguous ACL lockdown is not a
  production action.
- Self-integrity covers full callable semantics; persistence results distinguish
  COMPLETE/PARTIAL/UNKNOWN; IPC secrets use protected storage with legacy
  plaintext removal; WTS/SSH/third-party-agent checks improve remote-session
  anti-lockout.

## Standards truth

- MITRE ATT&CK **19.2** with a curated **15-tactic** Enterprise endpoint
  catalog. It is not a complete coverage claim.
- ATT&CK Navigator **5.3.2**, layer format **4.5**, with exact content/catalog
  metadata.
- OCSF **1.8.0** resolving typed observable/evidence paths under a
  **constrained-preview** Detection Finding mapper. The local validator does not
  replace the upstream schema compiler.
- A deliberately limited Sigma evaluator with bounded YAML, explicit supported
  semantics, and atomic admission/refusal receipts. It does not claim full
  Sigma compatibility.

IPC Guard is likewise truthfully scoped: it is a protected-store authenticated
loopback diagnostic admission preview, not a production payload consumer or
TPM-backed channel.

## Three-round disposition

| Round | Work | Disposition |
| --- | --- | --- |
| 1 | Adversarial review of every discovered capability and shared authority/UX boundary; visionary and upstream comparison | Twelve traceable lineages recorded without invented CVSS scores. Core contract, adaptation, authority, remediation, persistence, IPC, integrity, and UI work entered remediation. |
| 2 | Failure-injection re-audit of exporters, cursors, settings, Intel Sync, IPC/Remote workers, and EventBus subscribers | Eight overlapping reliability records fixed. IPC self-test accounting race fixed. Residual crash/rollback/key-epoch boundaries documented. |
| 3 | Final adversarial closure, standards truth, UI safety, remote-session anti-lockout, performance, and independent QA | No open High/Critical code finding in the v1.12 change set. Twelve closure checks passed or received bounded fixes; accepted residuals remain explicit. |

See [prior_findings.md](prior_findings.md) for the non-duplicated current
disposition.

## Upstream comparison

Primary-source review compared Velociraptor client monitoring/local buffers,
Wazuh stateful/stateless Active Response, Fleet policy definitions, osquery pack
selectors, Elastic detection-as-code validation, and Velociraptor's community-
artifact warnings. Angerona adapted local contract, admission, durability, and
review ideas; it does **not** claim their fleet management, server architecture,
query/content ecosystem, or commercial support. Full sources and exact
conclusions are in
[round1/upstream_project_comparison.md](round1/upstream_project_comparison.md).

## Performance

| Applied change | Before | After | Measured result |
| --- | ---: | ---: | ---: |
| Exact-capacity C-backed recorder handoff | 22.306 us/event | 15.925 us/event | 28.6% faster |
| Immutable capability summary projection | 43.324 us/call | 1.508 us/call | 96.5% faster |
| Unchanged Module Inspector refresh | 13.458 ms | 0.474 ms | 96.5% faster |

No optimization weakened cadence, completeness, cryptographic checks, host-
mutation probes, response authority, or fail-closed behavior. Batched durable
commits, immutable compiled Sigma plans, and a global per-CVE detail-worker cap
remain proposals.

## Validation snapshot

Authoritative post-documentation release gate:

- serial pytest: **1,811 passed / 6 expected host-platform skips / 0 failed**;
- product compile: **346/346** files;
- **82/82** module files imported, **64/64** compatibility hooks constructed,
  and **80** capabilities discovered without duplicate identity;
- **92** standalone core/module self-tests passed, **12** expected
  inactive/platform skips, plus EventBus passed;
- selfcheck: **26/26** direct and batch;
- Ruff and diff checks: clean.

The serial run includes the three added performance regressions. They and their
surrounding performance/reliability group also passed a focused **106/106**
gate.

The first post-documentation run exposed a deterministic-test defect rather
than a product failure: after two injected `PermissionError` values, the test's
third attempt called the real Windows `os.replace`; a transient scanner lock
made the correctly bounded product retry occur a fourth time. The exact-three-
calls assertion was isolated from live filesystem timing without reducing the
product retry budget. One thousand synthetic retry schedules, the focused test
file, Ruff, and the authoritative serial rerun then passed.

One Eco 20-millisecond scheduling assertion failed once and passed 10/10
isolated. One concurrent YARA timeout passed five immediate isolated runs, the
complete module rerun, and both selfchecks. No test/security threshold was
weakened.

## Honest residuals and backlog

- Firewall recovery is not whole-host recovery.
- Durable row HMACs do not independently witness deletion or whole-database
  rollback; delivery is at least once and may duplicate.
- Transport-key coordination still uses restart epochs.
- OCSF and Sigma support is deliberately constrained.
- IPC Guard is not a payload service or hardware-backed transport.
- User-mode/WTS/process evidence cannot guarantee truth after privileged sensor
  compromise or enumerate every unknown remote-access mechanism.
- Seventy-five adapters still need incremental native contract declarations.
- No fleet server, multi-tenant control plane, arbitrary distributed query
  engine, community executable exchange, independent certification, or
  commercial-support claim was added.

## Primary sources

- https://docs.velociraptor.app/docs/clients/monitoring/
- https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html
- https://fleetdm.com/docs/configuration/yaml-files
- https://osquery.readthedocs.io/en/5.12.1/deployment/configuration/
- https://github.com/elastic/detection-rules
- https://docs.velociraptor.app/docs/artifacts/exchange_reference/
- https://attack.mitre.org/resources/versions/
- https://attack.mitre.org/tactics/enterprise/
- https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md
- https://raw.githubusercontent.com/ocsf/ocsf-schema/1.8.0/objects/observable.json
- https://raw.githubusercontent.com/ocsf/ocsf-schema/1.8.0/objects/evidences.json
- https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html

These sources support defensive engineering choices; they do not prove product
parity, coverage, efficacy, certification, or attribution.
