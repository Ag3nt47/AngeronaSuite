# Cycle 26 Round 1 — upstream defensive-project comparison

**Research snapshot:** 2026-08-28
**Scope:** Wazuh, Velociraptor, Fleet/osquery, Falco and Falco Rules,
Sysmon for Linux, OSV-Scanner, and GitHub artifact attestations
**Method:** official project repositories, releases, and repository-hosted
documentation only. Popularity counts are deliberately excluded: stars are not a
security or engineering-quality measure. This is a pattern comparison, not a claim
of feature parity, certification, or equivalent deployment scale.

## Executive result

Angerona should keep its single-host, privacy-bounded, explicit-authority design.
The strongest upstream ideas are separable contracts that improve truth without
importing a manager/agent platform:

1. add an offline software/SBOM vulnerability baseline with authenticated database
   freshness and explicit incomplete states;
2. make Linux sensor compatibility, attachment state, event loss, and fallback
   coverage first-class evidence;
3. mature detection packages into compatibility-bound stable/preview/experimental
   channels with a browsable content ledger; and
4. add a closed-catalog offline evidence collector that records every selected,
   skipped, limited, and failed collector.

Cycle 26 already closes an important usability gap: a module below 100% now carries
a bounded reason plus a trusted repository-relative source path and exact line, and
the Module Inspector presents that line in a red-highlighted read-only view. That is
more precise local failure evidence than a generic status badge, but it must not be
confused with proof that the underlying sensor observed every relevant event.

## Angerona baseline inspected

The comparison was made against the working Cycle 26 tree, including concurrent
reviewed-in-progress changes, not only the v1.12.0 release tag.

- `src/angerona/core/module_contract.py` defines a v12 capability contract with
  implementation version, mode, platforms, permissions, response authority,
  maturity, dependencies, loss behavior, self-test type, settings schema, and
  resource budget. Compatibility-adapted legacy metadata is labeled rather than
  presented as native.
- `src/angerona/gui/pages.py:1625` provides a searchable, filterable, sortable,
  clickable Capability Center. `src/angerona/gui/pages.py:2847` provides the new
  health-evidence dialog and red exact-line highlight.
- `src/angerona/core/module_base.py:191` records a mandatory bounded reason for
  degradation and only retains a source identity when the callsite is inside the
  trusted checkout. Packaged or external code is reported as unavailable instead of
  inventing a local path.
- `src/angerona/core/detection_packages.py` and
  `src/angerona/core/detection_registry.py` already provide bounded non-executable
  detection-as-code, digest verification, detached Ed25519 trust, expiry, benign
  fixtures, evaluation budgets, quarantine, atomic activation, and rollback.
- `src/angerona/core/security_scan_center.py` provides bounded local file/YARA-X,
  Defender, listener, and network-posture scans. Cycle 26 preserves component-level
  status and error truth when local and Defender scans are combined.
- `src/angerona/core/ir_bundle.py` creates an explicit-consent, size-bounded,
  privacy-redacted incident-response bundle. `src/angerona/core/hunt_operations.py`
  and related fleet-hunt code use closed catalogs, authenticated progress, host/data
  budgets, and explicit failure codes.
- `src/angerona/modules/linux_observe.py` intentionally provides rootless observation;
  `src/angerona/modules/ebpf_sensor.py` is a separate opt-in BCC sensor currently
  limited to `execve` and `tcp_sendmsg` kprobes.
- `.github/workflows/release.yml` already creates CycloneDX SBOMs and uses pinned
  GitHub build-provenance and SBOM-attestation actions. Angerona also has threshold
  publisher authorization and packaged payload verification in
  `src/angerona/core/update_authority.py` and
  `src/angerona/modules/release_transparency_guard.py`.
- The tracked `detection-packages/` directory currently contains one portable JSON
  package. This does **not** mean Angerona has only one detection: many detections are
  implemented directly in modules. It does mean the independently versioned,
  portable content ecosystem is still small.

## Project-by-project comparison

### Wazuh 4.14.5

The official 4.14.5 release was published on 2026-04-23. Wazuh's current
vulnerability scanner consumes normalized OS/package/hotfix inventory batches,
matches them against a local CVE database, and refuses to call the feed ready until
required data is present. Its active-response documentation describes a separate
execution lifecycle with command allowlisting, deduplication, timeouts, automatic
reversion for stateful actions, and dedicated logs.

- **Already present/adapted in Angerona:** typed response authority, previews,
  receipts, rollback, circuit breakers, privacy-bounded inventory records, exposure
  lifecycle, and explicit collector errors.
- **Intentionally narrower:** Angerona is not a central SIEM/indexer and should not
  add a cluster merely to imitate Wazuh.
- **Missing:** a complete local package/version/hotfix-to-advisory matcher with a
  locally usable vulnerability database, feed identity, feed age, ecosystem
  coverage, and an explicit `incomplete` result when inventory or advisory data is
  absent. The current CVE advisor reasons about supplied host-applicable CVEs; it is
  not that matcher.
- **Buildable adaptation:** an `Offline Vulnerability Baseline` operation that
  inventories supported package sources and lockfiles/SBOMs, matches against a
  separately imported authenticated advisory snapshot, and emits known/unknown/error
  per source. Remediation remains proposal-only.

Primary sources:

- [Wazuh 4.14.5 release](https://github.com/wazuh/wazuh/releases/tag/v4.14.5)
- [Wazuh vulnerability-scanner architecture](https://github.com/wazuh/wazuh/blob/main/docs/ref/modules/vulnerability-scanner/README.md)
- [Wazuh vulnerability-scanner configuration and readiness](https://github.com/wazuh/wazuh/blob/main/docs/ref/modules/vulnerability-scanner/configuration.md)
- [Wazuh active-response lifecycle](https://github.com/wazuh/wazuh/blob/main/docs/ref/modules/active-response/README.md)

### Velociraptor 0.76.5

Velociraptor centers collection on declarative VQL artifacts and can build a
self-contained offline collector from a selected artifact set. The official
collector path exposes target format, concurrency, CPU limit, progress timeout,
overall timeout, output target, and encryption choices. Its releases also show why
failure truth matters: recent fixes include offline undefined-field handling,
resumable-upload locking, performance limits, YARA-X behavior, and artifact-pack
error reporting.

- **Already present/adapted:** closed-catalog hunts, bounded progress and storage,
  privacy-redacted IR bundles, local Scan Center, YARA-X, time/size/file limits, and
  explicit consent.
- **Intentionally narrower:** Angerona's IR bundle deliberately excludes raw paths,
  command lines, credentials, raw addresses, and a raw host image. It should retain
  that privacy contract rather than emulate unrestricted forensic acquisition.
- **Missing:** a single closed-catalog UI/CLI that lets an operator select safe
  collectors, see privileges/preconditions and estimated budgets, run them offline,
  and receive a manifest that distinguishes `collected`, `skipped-precondition`,
  `unsupported`, `limited`, `cancelled`, and `failed` for every requested item.
- **Buildable adaptation:** an `Offline Evidence Collector` built from Angerona's
  existing capability contracts and IR sanitizer. It should be a signed/release-bound
  recipe plus results manifest, not arbitrary VQL or shell code. Default concurrency
  one is preferable when acquisition order or host impact matters; any parallel mode
  must state that order is not guaranteed.

Primary sources:

- [Velociraptor repository and Artifact Exchange overview](https://github.com/Velocidex/velociraptor)
- [Velociraptor 0.76 releases](https://github.com/Velocidex/velociraptor/releases)
- [Official offline-collector implementation and limits](https://github.com/Velocidex/velociraptor/blob/master/bin/offline.go)
- [Legacy artifact compatibility is version-bound](https://github.com/Velocidex/velociraptor/blob/master/artifacts/definitions/Server/Import/PreviousReleases.yaml)

### Fleet 4.85.1 and osquery

Fleet 4.85.1 was published on 2026-05-22. Fleet/osquery demonstrates two useful
contracts: reusable posture policies include platform, criticality, description, and
resolution; and osquery packs declare platform/version selectors, discovery
preconditions, schedules, and optional sharding. Fleet's newer host UI also exposes
the versions of the agent's component layers instead of presenting one ambiguous
agent version.

- **Already present/adapted:** the v12 capability contract, maturity/authority/mode
  filters, per-module implementation versions, platform requirements, metadata-gap
  labels, safe Auto Adapt profiles, clickable sortable rows, and exact health reason
  evidence.
- **Intentionally narrower:** Angerona should not accept arbitrary SQL from a GUI or
  imply Fleet's multi-host management scale. Its closed collector/action catalogs are
  a safer match for a local security product.
- **Missing:** a declarative, non-executable posture-check pack schema with explicit
  applicability preconditions, expected evidence, resolution, cadence, cost budget,
  and content version. Current capability contracts describe modules, while most
  individual checks remain code-defined.
- **Buildable adaptation:** `Posture Check Packs` composed only of registered read-only
  collectors and bounded comparisons. The Capability Center should show pack version,
  applicable/skipped reason, last evidence time, cost, and resolution. A failed
  prerequisite must be `unknown/incomplete`, never a pass.

Primary sources:

- [Fleet 4.85.1 releases](https://github.com/fleetdm/fleet/releases)
- [Fleet policy audit fields, including resolution and platform](https://github.com/fleetdm/fleet/blob/main/docs/Contributing/reference/audit-logs.md)
- [osquery query-pack selectors and discovery preconditions](https://github.com/osquery/osquery/blob/master/docs/wiki/deployment/configuration.md)
- [osquery schedule splay, event retention, and event-table controls](https://github.com/osquery/osquery/blob/master/docs/wiki/installation/cli-flags.md)
- [osquery instrumentation and extension model](https://github.com/osquery/osquery)

### Falco 0.44.1 and Falco Rules

Falco 0.44.1 was released on 2026-06-11. Falco separates engine, driver, plugins, and
rules compatibility. The Rules repository publishes stable, incubating, and sandbox
content; records required engine compatibility; supports selective overrides; and
warns that only release-branch content should be treated as compatible with a stable
engine. Falco's configuration also treats event drops and monitored-syscall selection
as operational concerns, while its modern BPF path uses CO-RE/BTF where supported.

- **Already present/adapted:** signed/digested bounded detection packages, expiry,
  fixture gates, performance budget, quarantine, immutable copies, atomic activation,
  rollback, and module-level stable/preview/experimental maturity.
- **Intentionally narrower:** Angerona's Sigma subset and JSON package grammar reject
  executable extensions. That restriction is a security property, not a deficiency.
- **Missing:** package-level maturity, required Angerona contract/schema version,
  required sensor fields, minimum sensor implementation versions, deprecation state,
  override provenance, and a browsable activation/rollback/test ledger. One portable
  package is insufficient to demonstrate broad detection-content maturity.
- **Missing in Linux observability:** the BCC sensor has no first-class BTF/ABI
  compatibility report, perf-buffer loss counter, attach-point inventory, or explicit
  statement of what remained unobserved while falling back.
- **Buildable adaptation:** `Detection Package v2` adds maturity and compatibility
  metadata without expanding the executable grammar. A `Detection Content` menu shows
  stable/preview/experimental packages, required telemetry, fixture/performance proof,
  signer, expiry, active digest, predecessor, and exact failure reasons. A separate
  `Linux Sensor Coverage` view reports kernel/BTF state, each attach point, events and
  drops, last event, and fallback coverage.

Primary sources:

- [Falco 0.44.1 release](https://github.com/falcosecurity/falco/releases/tag/0.44.1)
- [Falco components and release compatibility model](https://github.com/falcosecurity/falco/blob/master/RELEASE.md)
- [Falco Rules maturity and compatibility model](https://github.com/falcosecurity/rules)
- [Falco runtime configuration, rule selection, reload, and drop settings](https://github.com/falcosecurity/falco/blob/master/falco.yaml)

### Sysmon for Linux 1.5.2

Sysmon for Linux 1.5.2 was released on 2026-05-07. It persists process, network, and
file-system activity through Linux logging, supports advanced event filtering, uses
BTF for kernel offsets where available, allows a standalone BTF file, and provides an
offset-discovery fallback. It also documents field-size limits because oversized
events can exceed syslog defaults.

- **Already present/adapted:** rootless process/connection/login/system observation,
  a separate privileged eBPF sensor, bounded fields, platform requirements, and
  degraded health.
- **Intentionally narrower:** Angerona does not claim Sysmon event-schema or persistent
  collection parity. Its current eBPF sensor is an optional two-hook observer.
- **Missing:** explicit BTF/offset compatibility evidence, durable cursor/gap semantics
  for Linux kernel events, per-channel field truncation counters, perf-buffer loss
  accounting, and a tested fallback matrix across supported kernels.
- **Buildable adaptation:** first implement compatibility/loss truth around the current
  sensor. Only then consider a CO-RE sensor or an optional adapter that ingests an
  already-installed Sysmon-for-Linux journal. Do not silently install a privileged
  kernel sensor from the GUI.

Primary sources:

- [Sysmon for Linux repository and BTF behavior](https://github.com/microsoft/SysmonForLinux)
- [Sysmon for Linux 1.5.2 releases](https://github.com/microsoft/SysmonForLinux/releases/tag/1.5.2)
- [Official package installation paths](https://github.com/microsoft/SysmonForLinux/blob/main/INSTALL.md)

### OSV-Scanner 2.4.0 and GitHub artifact attestations

OSV-Scanner 2.4.0 was released on 2026-06-18. The v2 line scans source trees,
lockfiles, SPDX/CycloneDX SBOMs, and supported container images; it supports an offline
vulnerability database and uses explicit configuration failure handling. GitHub's
artifact-attestation actions generate signed build-provenance and SBOM attestations
that can be independently verified with GitHub tooling.

- **Already present/adapted:** CycloneDX output, checksums, pinned GitHub provenance
  and SBOM attestation actions, deterministic release evidence, threshold Ed25519
  release authorization, payload manifests, rollback floor, and runtime release
  transparency checks.
- **Intentionally narrower:** an OSV advisory match is evidence of a known published
  vulnerability, not proof of exploitability or a safe automated fix. Angerona should
  continue separating detection, reachability context, proposal, approval, and action.
- **Missing:** a host-facing offline SBOM/lockfile scan with database digest/age and
  ecosystem coverage; a Scan Center panel that explains what inputs were not parsed;
  and a simple public-release proof view linking the exact artifact digest to its
  GitHub attestation and bundled SBOM.
- **Buildable adaptation:** import a pinned, size-bounded OSV database snapshot through
  an authenticated update boundary, then scan only explicit local sources. Add
  `Release Proof` to the Help/About or Update surface: artifact SHA-256, SBOM SHA-256,
  provenance state, attestation verification instructions/link, publisher threshold,
  and honest unavailable/failure reasons.

Primary sources:

- [OSV-Scanner 2.4.0 releases](https://github.com/google/osv-scanner/releases/tag/v2.4.0)
- [OSV-Scanner source/SBOM scan behavior](https://github.com/google/osv-scanner/blob/main/docs/scan-source.md)
- [OSV-Scanner v2 changelog, including offline matching](https://github.com/google/osv-scanner/blob/main/CHANGELOG.md)
- [GitHub build and SBOM attestation guidance](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
- [GitHub's current attestation action](https://github.com/actions/attest)

## Ranked, buildable proposals

| Rank | Proposal | Security value | Cost | Classification | Acceptance boundary |
|---:|---|---|---|---|---|
| 1 | Offline Vulnerability Baseline for installed packages, lockfiles, and SBOMs | Very high | Medium | Missing; adapt Wazuh + OSV | Authenticated DB digest/age; known/unknown/error per source; no automatic fix |
| 2 | Linux Sensor Coverage and Loss Witness | Very high | Medium | Missing; adapt Falco + Sysmon | BTF/kernel/attach state, events, drops, gaps, fallback scope; loss cannot report healthy |
| 3 | Detection Package v2 maturity/compatibility ledger and menu | High | Low–medium | Foundation present; tune up from Falco Rules | Stable/preview/experimental, engine/sensor compatibility, signer, fixtures, perf, expiry, rollback |
| 4 | Closed-catalog Offline Evidence Collector | High | Medium–high | Partially present; adapt Velociraptor | Signed recipe, explicit consent, budgets, privacy policy, status for every requested collector |
| 5 | Dependency-aware Capability Coverage view | High | Medium | Contracts and health evidence present; tune up | Required sensor/collector state and freshness roll up as incomplete, never pass |
| 6 | Declarative Posture Check Packs | Medium–high | Medium | Missing; adapt Fleet/osquery safely | Registered read-only collectors only; precondition, cadence, cost, expected evidence, resolution |
| 7 | Release Proof viewer | Medium | Low | Publication proof present; UI tune up | Exact artifact/SBOM/provenance identities and independent verification path; honest unavailable state |
| 8 | Active-response lifecycle dashboard | Medium | Low–medium | Core authority/rollback present; Wazuh-inspired tune up | Deduplication key, timeout, revert/receipt state, and failed rollback are visible and sortable |

## Menu and health-evidence recommendations

The current Cycle 26 health dialog should be treated as the common disclosure
component, not a module-specific special case.

- Keep every Capability Center row clickable and sortable. Add typed sort keys for
  health percentage, maturity, implementation version, last evidence time, loss
  count, and dependency completeness.
- For health below 100%, display the bounded reason, local trusted source path and
  exact line when available, repository link, last transition time, affected
  capability, missing dependency/sensor, and the evidence age. Preserve the red line
  highlight as a diagnostic pointer, not an assertion that the code line is itself a
  vulnerability.
- For packaged builds, external modules, or changed source identity, say `source
  unavailable` and retain only a safe repository reference when it is known. Never
  open an arbitrary absolute path supplied by a module.
- Add `coverage` separately from `health`. A stable process at 100% health can still
  have intentionally narrow telemetry. Conversely, a missing optional sensor should
  not be mislabeled as failure if the capability contract clearly states the reduced
  coverage.
- Every aggregate Auto Run or Scan operation must preserve component status, errors,
  input coverage, time/size limits, and cancellation. `Complete` is permitted only
  when every required component completed and its prerequisites were verified.

## What not to copy

- Do not add arbitrary executable rules, VQL, SQL, PowerShell, or shell content to
  gain superficial flexibility. Extend closed schemas and registered collectors.
- Do not silently install privileged Linux sensors or weaken UAC/administrator
  boundaries for convenience.
- Do not equate a large rule count, project stars, a green process, or a successful
  scan command with complete defensive coverage.
- Do not copy central-manager scale claims into a single-host product. Angerona's
  truthful narrower scope is preferable to unsupported parity language.
- Do not let online feed failure erase the last authenticated offline baseline; mark
  it stale with its exact age and digest.

## Recommended Cycle 26 implementation slice

The lowest-risk, highest-leverage slice for this cycle is:

1. finish and regression-test the shared module health evidence and clickable
   Capability Center work already in progress;
2. add package-v2 maturity/compatibility fields and a read-only content ledger without
   changing the detection expression grammar;
3. add Linux sensor compatibility/drop counters and exact degraded reasons before
   adding new kernel hooks; and
4. design the offline vulnerability and evidence-collector schemas now, but gate
   product activation on authenticated offline data, bounded fixtures, failure-truth
   tests, and separate adversarial review.

This sequence upgrades operator truth immediately while avoiding a rushed privileged
collector or vulnerability-feed trust boundary.
