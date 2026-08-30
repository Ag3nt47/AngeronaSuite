# Cycle 26 Round 3 Visionary — Trust Boundaries After Adversarial Convergence

Date: 2026-08-28
Mode: defensive architecture and research synthesis only
Implementation authority: no product, host, release, credential, or network mutation

## Outcome

Cycle 26 materially narrowed several dangerous boundaries, but it did not make
Angerona or its host impossible to compromise. The correct next step is not to
add a wider automatic-response surface. It is to move authority out of shared
process memory, make local history externally witnessable, make runtime identity
portable without making it ambient, and give every operator-facing health or
adaptation conclusion a typed evidence lineage.

This review proposes five architectures and selects exactly one bounded future
MVP: **Health Evidence Lineage Envelope v1**. It is the safest near-term bridge
between the new 81-capability health contract and the broader isolation, drift,
and external-witness designs. No MVP or other product code was implemented in
this phase.

The ranking is a safe delivery order, not a statement that the lower-ranked
trust boundaries are less important. In particular, the external monotonic
witness and out-of-process response broker have the highest strategic security
value, but neither can be honestly compressed into a final-round local patch.

## What Cycle 26 established—and what it did not

| Boundary | Cycle 26 control now present | Remaining honest limit |
|---|---|---|
| Response transactions | Durable FULL-sync state, exact transition graph, owner and recovery capabilities, single claimant, object/path custody, atomic terminal receipt | A capability already present in the same Python process can be read or misused by arbitrary admitted introspective code; process crash remains fail-closed and requires governed recovery |
| Authentication baseline | Fixed canonical slot, stable object/root custody, strict evidence completeness, HMAC/root/name/schema binding, exclusive enrollment, drift without auto-promotion | Local HMAC plus software time cannot detect every valid same-slot rollback after restart; there is no independent high-water witness |
| Publication runtime | Exact canonical origin, closed workflow graph, isolated environment, immutable-blob public-asset proof, sealed reviewed Git/GCM runtime closure, profile-byte trust anchor | Already-loaded publisher Python and the explicit OS/System32 boundary remain roots of trust; one Windows runtime profile is not a portable cross-platform trust system |
| Module health evidence | Atomic health snapshot, bounded reason, canonical-source compiled-code manifest, trusted repository-relative path and exact line only when proved | A callsite explains where health was reported, not necessarily the root cause; there is not yet a durable lineage from dependencies and sensor coverage to the rendered row |
| Scan/self-test execution | Stable object reads, cooperative deadline/cancellation truth, isolated self-test child environment and resource bounds | Platform I/O and YARA are not hard-interruptible, and ordinary application-process isolation is not a kernel security boundary |
| Guided Auto Adapt | Restorable Windows Firewall baseline and reviewed planning/response primitives | Other security controls are not equivalently restorable; GPO/MDM/third-party ownership and contradictory collectors must remain explicit |

These limits are security properties because they prevent a local control from
being presented as stronger than its actual custody.

## Ranked architecture scorecard

Scores use 1–5. Higher impact and feasibility are better; higher delivery risk
is worse. `Priority score = impact + feasibility - risk` is only a delivery
heuristic. A low-feasibility independent trust boundary must not be replaced by
a high-scoring same-host approximation.

| Rank | Architecture | Impact | Feasibility | Delivery risk | Priority score | Disposition |
|---:|---|---:|---:|---:|---:|---|
| 1 | Health Evidence Lineage Envelope v1 | 5 | 5 | 2 | 8 | **One bounded future MVP selected** |
| 2 | Automated Security-Control Drift Witness | 5 | 4 | 3 | 6 | Design next; observation first |
| 3 | Signed Portable Publication Runtime Profiles | 4 | 3 | 3 | 4 | Prototype offline; do not replace current seal yet |
| 4 | Out-of-Process Capability Isolation and Response Broker | 5 | 2 | 4 | 3 | Strategic redesign; staged migration |
| 5 | Rollback-Resistant External Baseline Witness | 5 | 2 | 4 | 3 | Strategic P0; requires separate administration |

## 1. Health Evidence Lineage Envelope v1 — selected bounded future MVP

### Boundary addressed

`C26-R3-B05` showed that a plausible filename and dynamic function were not
enough to prove a health callsite. The compiled canonical-source manifest now
closes that direct forgery path. The next missing layer is semantic lineage:
operators need to know which dependency, sensor, freshness check, loss counter,
or lifecycle transition caused a health value, and whether the GUI is showing
one coherent generation of that evidence.

### Architecture

A central, non-authorizing `HealthEvidenceBroker` should construct a frozen,
bounded envelope from module facts rather than accepting a module-authored
display string as the complete truth. Envelope v1 should include:

- capability ID, implementation version, Capability Contract version, module
  lifecycle generation, and one broker-assigned health revision;
- health percentage plus a closed reason code and bounded operator text;
- applicable platform/privilege state and required-versus-optional dependency
  status;
- evidence freshness, coverage interval, loss/overflow count, and collection
  completion state;
- verified repository-relative source identity, canonical source digest,
  structural code-member identity, and exact line only when every proof holds;
- parent evidence IDs or dependency revisions that contributed to the result;
- previous envelope digest and current envelope digest for local ordering; and
- an explicit trust label: `verified-local-lineage`, `partial`, `stale`,
  `source-unavailable`, or `unverified`.

The local chain is provenance, not anti-rollback. It may use the existing
authenticated audit boundary for tamper evidence, but the UI and documentation
must never call it externally witnessed until architecture 5 is deployed.

The Capability Center should render only one atomic envelope per row. When
health is below 100%, clicking the health cell should show the exact reason,
affected dependency/evidence, age and loss, trusted local path, repository link,
and verified line. The line may be highlighted red as the reporting callsite;
the dialog must state that red identifies the diagnostic origin and does not by
itself assert that the source line is a vulnerability. If source or line proof
fails, the UI must say `source unavailable` or `line unverified` and provide no
arbitrary filesystem link.

### Strict MVP scope

The future MVP is limited to the existing `BaseModule` health path and
Capability Center. It adds no sensor, response action, file mutation, network
egress, external signer, cloud service, new privilege, or baseline promotion.
It does not change a module's health percentage; it makes the derivation and
display atomic, typed, and reviewable.

### MVP acceptance gates

1. Every discovered capability emits a valid bounded envelope, including 100%
   healthy, expected platform skip, never-started, stopped, crashed, stale,
   partial, and dependency-loss states.
2. Every value below 100% has a closed reason code and operator explanation.
   A verified source path and exact line are shown when provable; otherwise the
   missing proof is itself visible.
3. Dynamic `co_filename`, module-dictionary injection, stale function object,
   line-out-of-range, source replacement, symlink/reparse, hard-link, and
   packaged/no-source fixtures cannot create a trusted link or red line.
4. A module lifecycle restart increments generation. A GUI refresh cannot mix
   an old reason, new percentage, different source line, or stale dependency
   revision.
5. Dependency loss, collection truncation, timeout, and overflow cannot render
   100% unless the contract marks the input optional and shows the resulting
   coverage reduction separately.
6. The chain is bounded by count/bytes and exposes pruning continuity. No raw
   secret, credential, private path, event payload, or exception text enters a
   public envelope.
7. Sorts use typed health, version, freshness, loss, maturity, and dependency
   fields rather than rendered text. Row and health-cell navigation remain
   keyboard-accessible.
8. The 81-capability refresh benchmark remains within the existing 1.5-second
   UI cadence and preserves the Round 3 atomic-health performance improvement.

### Honest limit

Lineage proves what Angerona used to produce a health statement under the local
process and source-custody assumptions. It does not prove that the host, kernel,
firmware, module logic, or evidence source is uncompromised. A signed or
hash-chained false observation remains false.

## 2. Automated Security-Control Drift Witness

### Boundary addressed

The Round 1 innovation review correctly ranked protection-posture drift near
the top, while Cycle 26's Auto Adapt work proved automatic recovery only for
Windows Firewall. Treating Defender, ASR, HVCI, Credential Guard, LSA
protection, audit policy, PowerShell logging, App Control, and security-service
state as equally restorable would create a dangerous false guarantee.

### Architecture

Build a typed `SecurityControlFact` catalogue in two intentionally separate
planes:

```text
fixed read-only collectors
  -> normalized fact + source authority + completeness + policy owner
  -> contradiction/drift evaluator
  -> Health Evidence Lineage
  -> operator-selected Auto Adapt plan
  -> separately qualified per-control adapter, if one exists
  -> durable response transaction + verified postcondition + compensation
```

Each fact must declare applicability, effective value, desired value, owner
(`local`, `GPO`, `MDM`, `security product`, or `unknown`), source authority,
collection completeness, last-known-good identity, recovery support, reboot
impact, and evidence age. Multiple sources that disagree produce `conflict`,
not a favorable majority vote.

The Auto Adapt button may reduce tedious clicking by gathering the operator's
security goal once and generating a closed plan, but it must not convert a
choice such as “strong” into arbitrary commands. A plan should contain only
registered controls, exact current facts, compatibility preconditions, impact,
Undo support, and a short-lived approval digest. Revalidation immediately
before each action prevents stale-plan execution. Unsupported, enterprise-owned,
contradictory, or incomplete controls stay observe-only.

Every adapter must independently qualify through pre-state capture, simulation,
exact target custody, durable `PREPARED`/`MUTATING` state, postcondition,
compensation or explicit irreversibility, restart reconciliation, and failure
injection. Firewall remains the only default-restorable control until another
adapter passes that contract.

### Key failure tests

- GPO refresh during plan review; MDM/local conflict; third-party AV takeover;
- planned maintenance, stale approval, collector loss, and reboot-pending state;
- partial apply, compensation failure, duplicate click, concurrent Auto Adapt,
  crash before/after mutation, and policy reversal after postcondition;
- a “restore baseline” request when only some controls have recoverable state;
  the UI must list exactly what will and will not be restored.

### Honest limit

Drift can be legitimate, malicious, or a collection artifact. Local observation
cannot override enterprise policy ownership or prove adversary intent. Automatic
orchestration improves usability; it does not widen response authority or make
every discovered deviation safe to repair.

## 3. Signed Portable Publication Runtime Profiles

### Boundary addressed

`C26-R3-C07` through `C26-R3-C12` demonstrated that the publication process is
an executable supply chain: shell startup, environment, downloader, Git config,
credential helper, HTTPS transport, runtime DLLs, profile bytes, and operation
ordering all matter. The current Windows seal is intentionally exact and
strong, but it is one compiled trust anchor for one reviewed Git/GCM tree.

### Architecture

Define a deterministic, non-executable `PublicationRuntimeProfile v1` bundle
for each supported host/runtime tuple. It should bind:

- repository identity, publisher protocol version, platform/architecture, and
  exact runtime version/build;
- every admitted relative path, type, size, digest, mode/ACL expectation, and
  dependency edge, plus the aggregate tree digest;
- exact executable roles (`git`, HTTPS helper, credential helper, shell if
  unavoidable) and prohibited additions;
- the explicit OS trust boundary and minimum TLS/credential behavior;
- profile epoch, creation source commit, expiry/review state, and predecessor;
- a detached threshold signature from offline release-profile keys.

The already-loaded publisher must contain the fixed verification policy and
public-key set, parse duplicate-safe bounded bytes through stable handles, and
stage the exact tree into private custody before any repository or credential
operation. No online profile fetch, ambient package manager, PATH discovery,
mutable user trust store, or “latest compatible” selection may grant authority.
Key rotation, revocation, and recovery require a separately reviewed policy.

Portability means the same closed format and verifier can describe reviewed
Windows, Linux, and macOS runtime closures. It does not mean a Windows digest is
accepted elsewhere or that a signature allows unspecified files. The current
compiled Windows profile remains authoritative until offline generation,
threshold verification, downgrade, mutation, and cross-platform fixtures prove
that the new scheme is at least as strict.

### Key failure tests

- valid old-profile replay, unknown signer, partial threshold, signer rotation,
  duplicate key/path, path alias, extra sidecar, same-size replacement, and
  dependency omission;
- source/profile mutation before and during stable read/staging;
- platform/architecture confusion and locale/newline/JSON canonicalization;
- compromised ambient Git config, proxy, CA, askpass, credential helper, PATH,
  shell startup, working directory, and inherited secret environment;
- exact signature and runtime identity with a known-vulnerable or expired
  profile, which must remain blocked or explicitly review-required.

### Honest limit

A profile signature proves that approved keys authorized exact profile bytes;
it does not prove the runtime is vulnerability-free, the signer made a good
decision, the already-loaded verifier is uncompromised, or the OS/kernel is
honest. Without architecture 5, a still-valid older signed profile can be
locally replayable unless current code independently pins an epoch/profile ID.

## 4. Out-of-Process Capability Isolation and Response Broker

### Boundary addressed

`C26-R3-A06` and `C26-R3-A09` explicitly disclose the limit of owner and
coordinator capabilities inside one Python process. `C26-R3-B03` also showed
why child environment, startup, process count, output, CPU, and memory custody
must be explicit. The long-term answer is a narrow authority boundary, not
more obscure in-process tokens.

### Architecture

Split execution by authority class:

```text
unprivileged GUI/coordinator
  |-- observe workers: one bounded trust group each, no response authority
  |-- parser/scan workers: content-only handles, no pathname or network authority
  |-- health broker: validates typed evidence and source lineage
  `-- authenticated response broker: closed actions, exact targets, durable journal
        `-- minimal privileged helper only for separately approved OS mutations
```

Workers receive a fresh empty environment, fixed executable/image identity,
private working directory, deny-by-default network policy, OS resource limits,
one-time startup nonce, and a versioned length-bounded IPC schema. The broker
passes capability-scoped handles or immutable byte snapshots rather than raw
paths where supported. Every request binds caller image, process birth,
capability ID, action schema, exact target identity, plan digest, expiry, and
transaction generation. Unknown messages, schema drift, replay, excess output,
timeout, worker crash, or broker restart become explicit incomplete/fail-closed
state.

No observer or GUI process should hold the response transaction owner,
reconciliation coordinator, publication credential path, baseline signing key,
or unrestricted filesystem/network handle. The privileged helper implements a
small closed action catalogue; it does not expose Python import, shell,
PowerShell, arbitrary registry, arbitrary file, or generic command execution.

Migration should begin with high-risk parsers/self-tests and observe-only
modules, then health brokerage, then a shadow response broker. Host mutation
must remain on the current gated path until equivalence, crash recovery,
upgrade/downgrade, and independent red-team suites pass.

### Key failure tests

- arbitrary worker introspection cannot read another worker or broker token;
- malformed/fractured/oversized IPC, replay, PID reuse, broker restart, stale
  process identity, and confused-deputy target substitution fail closed;
- worker escape attempts have no inherited credential, proxy, PATH, Python,
  startup, network, response, baseline, or publication authority;
- broker crash at every transaction edge leaves one truthful durable state and
  never dispatches twice;
- update mixes of old/new broker and worker versions reject incompatible
  schemas rather than silently dropping evidence.

### Honest limit

Process separation reduces blast radius and makes capabilities meaningful; it
is not a guarantee against OS sandbox escape, same-user debug rights,
Administrator/SYSTEM, kernel/firmware compromise, or vulnerable privileged
helper code. The precise Windows token/AppContainer/service model and POSIX
equivalent need platform-specific threat models—not a lowest-common-denominator
claim.

## 5. Rollback-Resistant External Baseline Witness

### Boundary addressed

`C26-R3-B08` and `C26-R3-B09` closed pathname, slot, registry-loss, and trusted-
fork problems, while deliberately retaining the local software-clock/HMAC
rollback limitation. Similar replay risk applies to any same-host security-
control baseline, evidence-chain head, remediation high water, or publication
profile epoch. Another local file, registry value, database, DPAPI secret, TPM-
less counter, or loopback process is not independent custody.

### Architecture

Use a separately administered appliance or service with a distinct backup and
credential boundary. For each `(installation_id, evidence_domain)`, it exposes
an authenticated monotonic compare-and-swap operation over:

- prior sequence and prior opaque head;
- next sequence and SHA-256 of the next bounded local state;
- schema/policy/profile epoch and previous-state digest;
- request nonce, freshness window, and enrolled device identity; and
- an authenticated durable receipt containing the committed new head.

Only privacy-minimal digests, opaque installation/domain IDs, sequence numbers,
and policy epochs leave the host. Raw paths, control values, event records,
commands, users, network identifiers, credentials, and findings remain local.
The witness must durably commit before acknowledging and reject duplicate,
rollback, fork, clone, cross-domain, and predecessor-mismatch requests.

Outage is not converted to success. New local evidence can be retained as
`provisional / witness unavailable`, but trusted enrollment, baseline
replacement, historical pruning, and automated recovery must not advance past
the last externally acknowledged head. Restore, clone, reinstall, migration,
device replacement, external-ahead crash, witness loss, key rotation, and
break-glass re-enrollment require explicit operator policy and durable audit.

Start with authentication and security-control baseline heads. Add health-chain
or remediation heads only after update frequency, privacy, availability, and
recovery behavior are measured. The witness is not a command channel and
receives no host response authority.

### Key failure tests

- replay of two individually authentic old/new local states; divergent fork;
  copied host data root; cloned installation ID; domain confusion;
- local-first and witness-first crash, lost response, retry, duplicate request,
  reorder, stale nonce, long outage, restored witness backup, and external
  head ahead of local state;
- witness compromise simulation, key rotation/revocation, device replacement,
  and explicit break-glass recovery with visible loss of continuity;
- denial and latency prove reduced availability without being labeled tamper or
  healthy.

### Honest limit

An independent witness can detect or refuse state rollback under its own key,
storage, administration, and availability assumptions. It cannot prove the
local observation was true, prevent local destruction, identify an attacker,
survive simultaneous host-and-witness compromise, or protect against kernel or
firmware control. A TPM can strengthen device identity, but a local TPM counter
alone is not a separately administered witness.

## How the architectures compose

```text
isolated collectors/workers
  -> typed evidence
  -> Health Evidence Lineage Envelope
  -> Security-Control Drift Witness
  -> reviewed Auto Adapt plan
  -> isolated Response Broker + durable transaction/receipt
  -> optional external monotonic head for rollback visibility

portable signed publication profile
  -> sealed publisher runtime
  -> exact public commit/artifact proof
  -> optional external profile-epoch high water
```

The dependencies are deliberate:

- health lineage can ship locally without claiming process isolation or
  anti-rollback;
- security-control drift should consume lineage before any new repair adapter;
- response-process isolation should precede admitting hostile or third-party
  extensions;
- signed runtime profiles improve portable authenticity, while external
  witnessing is what can add rollback resistance; and
- no aggregate health, Auto Run, Auto Adapt, or publication result may be
  “complete” when a required component is partial, stale, lost, incompatible,
  unverified, or externally behind.

## Influence of the existing research and upstream comparison

This ranking does not add new web research. It uses the Cycle 26 Round 1 primary-
source review and upstream comparison already recorded in
`analysis/loop/innovation_ideas.md` and
`analysis/loop/cycle26/round1/upstream_project_comparison.md`.

- Wazuh reinforces explicit response lifecycle/rollback visibility; it does not
  justify arbitrary command execution in Angerona.
- Velociraptor reinforces bounded collector recipes and separation between
  collection and orchestration; Angerona should retain a closed collector
  catalogue rather than accept arbitrary VQL or shell.
- Fleet/osquery reinforces applicability, platform, resolution, cadence, and
  version fields for posture checks; an unmet prerequisite remains unknown.
- Falco and Falco Rules reinforce engine/sensor/content compatibility, maturity,
  drop accounting, and activation history; a healthy process is not complete
  telemetry.
- Sysmon for Linux reinforces explicit BTF/kernel/fallback and truncation/loss
  truth before broader privileged collection.
- OSV-Scanner and GitHub attestations reinforce offline data identity and public
  artifact provenance; a signature or advisory match is evidence, not a safe
  automatic remediation decision.

The useful adaptation is the contract discipline. Angerona should not copy
central-manager scale claims, executable rule languages, silent privileged
sensor installation, or rule-count marketing.

## Delivery order after the selected MVP

1. Specify and adversarially test Health Evidence Lineage Envelope v1 across
   all discovered capabilities, then wire the clickable/sortable UI to its
   atomic snapshot.
2. Add observation-only security-control facts and conflict/ownership truth.
   Qualify one future repair adapter at a time; never infer blanket
   restorability from the firewall baseline.
3. Build an offline profile compiler/verifier and mutation corpus for portable
   publication profiles. Keep the current exact runtime seal until the new
   verifier proves no downgrade.
4. Prototype process separation with no host mutation: parser/self-test worker
   first, health broker second, response shadow mode third.
5. Specify the external witness protocol, server state machine, enrollment,
   recovery, backup, and privacy model; validate with an isolated conformance
   harness before choosing deployment hardware or service.

## Explicit non-goals and assurance statement

- No exploit, payload, credential collection, persistence, evasion mechanism,
  hack-back, arbitrary remote scan, shell broker, or offensive simulation.
- No automatic Defender exclusion, GPO/MDM override, authentication-component
  removal, privileged sensor installation, profile download, or witness command
  channel.
- No claim that a green test suite proves absence of vulnerabilities. Confidence
  comes from explicit threat models, inert reproductions, independent bypass
  reviews, failure injection, bounded soak tests, and honest residual limits.
- No claim of tamper-proof user-mode defense against Administrator/SYSTEM,
  kernel, firmware, physical, supply-chain, signer, or external-witness
  compromise.
- No actor, agency, sponsor, or person attribution from a technique or evidence
  match.

## Phase evidence

This visionary phase changed only this analysis file and an append-only loop-log
entry. It changed no product code, tests, configuration, release workflow,
version, public documentation, host setting, credential, or network state.
Compile, Ruff, module self-test, GUI, response, and publication gates are
therefore not applicable to this phase. The underlying remediation and
performance evidence remains recorded in the sibling Round 3 artifacts; final
Cycle 26 release closure still belongs to the integrating QA/docs/publication
workflow.
