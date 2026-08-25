# Host Adaptation Visionary Pass — 2026-08-24

## Decision

Angerona's new Adaption workbench already has the right first production
boundary: observation, planning, simulation, and execution are separated;
profiles come from a closed catalog; plans are short-lived and bound to a host
and firewall-state digest; a Windows Firewall export is required before a
write; rollback artifacts are checked; automation is opt-in; and a persistent
rate breaker limits repeated changes. The GUI already exposes Overview, Audit &
Drift, Exceptions & Feedback, Profiles & Rollback, Sandbox, Automation, and
Activity.

The next pass should strengthen the trust boundaries around that design. In
particular:

- an unavailable or truncated collector must never look like configuration
  drift;
- a friendly SSID or weak VPN-interface guess must never cause a less
  restrictive posture than a stronger public-network signal;
- Angerona must understand the effective Windows Firewall policy and its
  owner, not only the local profile values;
- manual and automatic workers must not race through the breaker;
- command success must not be treated as a committed healthy state; and
- false-positive feedback must not become an attacker-influenceable learning
  channel.

This document began as a research/design pass. The later adversary-remediation
convergence shipped bounded versions of proposals 1-4: collector-quality
metadata, strongest-posture context ordering, effective Firewall ActiveStore
collection/postcondition verification, and single-flight revision-bound action
admission. Proposals 5-9 remain backlog, as do deep firewall filter joins and
service executable signer/content-hash attestation. The design does not
duplicate Angerona's existing Response Broker, WFP containment, Watchdog,
flight recorder, signed policy/content lifecycle, local AI broker, or
telemetry-blinding detector; the proposals deliberately reuse those seams.

Ranking uses an ordinal impact divided by an effort weight (S=1, S-M=1.5, M=2,
L=3). The quotient is a prioritization aid, not a delivery estimate.

| Rank | Proposal | Delivery band | Impact | Effort | Impact / effort | Mode |
|---:|---|---|---:|:---:|---:|---|
| 1 | Collector Quality Contract | Safe immediate | 5 | S | 5.00 | Detect / Harden / Visualize |
| 2 | Restrictive Context Lattice + Hysteresis | Safe immediate | 5 | S | 5.00 | Detect / Respond / Harden / Visualize |
| 3 | Effective Firewall Policy Ownership Guard | Safe immediate | 5 | S-M | 3.33 | Detect / Harden / Visualize |
| 4 | Authenticated Single-Flight Action Journal | Safe immediate | 5 | S-M | 3.33 | Respond / Harden / Visualize |
| 5 | Versioned Baseline Promotion Workflow | Safe immediate | 4 | S-M | 2.67 | Detect / Harden / Visualize |
| 6 | Event-Driven Drift Provenance | Safe immediate | 4 | S-M | 2.67 | Detect / Visualize |
| 7 | Trial-Lease Apply + Crash-Independent Rollback | Longer term | 5 | M | 2.50 | Respond / Harden / Visualize |
| 8 | Poisoning-Resistant Feedback Lab | Longer term | 4 | M | 2.00 | Detect / Harden / Visualize |
| 9 | Signed Windows Posture Packs | Longer term | 5 | L | 1.67 | Detect / Respond / Harden / Visualize |

---

## Safe immediate additions

## 1. Collector Quality Contract

**Pitch.** Make every audit value carry completeness, freshness, and truncation
state so loss of visibility can never be scored as host drift.

### Why now

NIST CSF 2.0 calls for configuration management and continuous monitoring of
hardware, software, runtime environments, and their data. CISA's current
StopRansomware guidance likewise recommends routine drift checks against a
consistent baseline. Those outcomes depend on distinguishing “confirmed
absent” from “not observed.” Sources:
[NIST Cybersecurity Framework 2.0](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf),
[CISA StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide).

The current collectors intentionally catch many host/permission errors and
return bounded lists. That is safe for uptime, but an empty services, ports, or
interfaces list can currently be compared as if every baseline item was
removed. MAX_SERVICES and MAX_PORTS also cap results without representing
truncation in the snapshot.

### Fit

- **Core:** extend host_adaptation snapshot schema v2 with a collection_health
  record for hardware, services, ports, network context, and firewall. Each
  record is one of complete, partial, unavailable, unsupported, or truncated
  and carries bounded counts, start/end time, source, and a sanitized reason
  code.
- **Drift engine:** compare a category only when both sides are compatible and
  complete. A visibility regression becomes its own High “coverage degraded”
  finding; it never emits thousands of false removals or lowers risk.
- **Existing architecture:** reuse platform capability contracts and World
  View's telemetry-blinding vocabulary. Do not create another health system.
- **GUI:** show coverage and freshness beside risk; exports preserve the
  quality metadata. This is Detect / Harden / Visualize.

### Effort

**S.** Schema migration and deterministic fixture tests. Limitations are
collector-specific permission failures, localized command output, and
Windows-version availability. Old v1 baselines should remain readable but
explicitly have unknown quality until recaptured.

### Safety

Defensive and read-only. Unknown visibility fails closed as “cannot assess”; it
does not trigger host mutation, auto-reversion, or an offensive probe.

---

## 2. Restrictive Context Lattice + Hysteresis

**Pitch.** Compose context signals so the most restrictive credible posture
wins, and require a stable dwell period before any automatic change.

### Why now

The final 2025 NIST zero-trust implementation guidance uses real-time,
risk-based assessment and continuous policy evaluation rather than trusting
location alone. Microsoft's 2026 trusted-signal documentation models Wi-Fi with
SSID, BSSID, and security type, while Network List Manager separately exposes
Public, Private, and DomainAuthenticated categories. Sources:
[NIST SP 1800-35, Implementing a Zero Trust Architecture](https://www.nist.gov/publications/implementing-zero-trust-architecture-high-level-document),
[Microsoft trusted-signal fields](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/trusted-signal-unlock),
[NLM_NETWORK_CATEGORY](https://learn.microsoft.com/en-us/windows/win32/api/netlistmgr/ne-netlistmgr-nlm_network_category).

Today an exact SSID match outranks Public, which means a familiar network name
can select a less restrictive profile even when Windows classifies the
connection as untrusted. VPN state is inferred from interface classification
and a single 15-second observation can trigger an armed profile.

### Fit

- **Core policy engine:** assign profiles a monotonic restrictiveness level and
  resolve all simultaneous matches with a deny-overrides/restrictive-wins
  lattice. Public or Unknown may harden; neither SSID nor VPN presence may
  automatically loosen a stronger posture.
- **Signal confidence:** add stable Windows network GUID, category, WLAN
  authentication/security type, privacy-hashed optional BSSID, VPN interface
  plus route evidence, source freshness, and confidence. Never persist WLAN
  keys or raw profile XML.
- **Hysteresis:** require two or three consistent samples over a configurable
  dwell period; debounce roaming; make Unknown and signal disagreement
  proposal-only. A transition to a less restrictive profile always requires an
  operator commit.
- **Sandbox/GUI:** add a scenario matrix for Public + known SSID, VPN drop,
  network roaming, and Unknown. Show each signal, confidence, conflict, chosen
  posture, and why. This is Detect / Respond / Harden / Visualize.

### Effort

**S** for the lattice, dwell state, and fixture-driven scenario sandbox;
**S-M** if native WLAN/NLM enrichment is included. Native APIs and Windows
edition differences are gated. On unsupported systems the feature remains
proposal-only.

### Safety

Defensive only. Context can tighten or propose; low-confidence context cannot
silently weaken protection, reclassify a network, connect to Wi-Fi, or inspect
network content.

---

## 3. Effective Firewall Policy Ownership Guard

**Pitch.** Refuse local adaptation when GPO, MDM, or another policy store owns
the effective result, and verify the ActiveStore rather than assuming local
command success.

### Why now

Microsoft documents that Windows Firewall's ActiveStore is the resultant set of
policy from persistent local policy, GPOs, service hardening, and dynamic
sources. It also documents that local-policy merge can be disabled and that
explicit allow rules can override a default block posture. Sources:
[Get-NetFirewallProfile policy stores](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile?view=windowsserver2025-ps),
[Windows Firewall rules and merge behavior](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules),
[Get-NetFirewallRule policy-source tracing](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=windowsserver2025-ps).

The current snapshot reads profile defaults and the plan writes the default
local policy. It does not yet report whether GPO/MDM owns the effective setting,
whether local policy is merged, or whether a “lockdown” default is weakened by
effective explicit allows.

### Fit

- **Core collector:** capture privacy-minimized ActiveStore, PersistentStore,
  RSOP/source type, merge behavior, active profile, and management ownership.
  Store aggregate counts and digests by rule source; expose rule detail only in
  a bounded local review view.
- **Planner:** mark managed/conflicting settings as non-writable and explain the
  authoritative source. A locally managed plan must include both persistent and
  effective precondition digests.
- **Executor:** after a write, re-read ActiveStore and require the intended
  effective postcondition. A command that succeeds but is overridden is a
  failed apply and enters recovery.
- **GUI:** add “Policy owner,” “effective result,” “local merge,” and “explicit
  rule caveat” to preview and sandbox. This is Detect / Harden / Visualize.

### Effort

**S-M.** Windows/NetSecurity only. MDM source attribution is not uniform across
all editions, and centrally managed endpoints must be reported as managed
rather than “fixed” locally.

### Safety

Defensive only. Angerona never edits a domain GPO, MDM policy, remote computer,
or organization policy. Ambiguous ownership blocks mutation and directs the
operator to the actual authority.

---

## 4. Authenticated Single-Flight Action Journal

**Pitch.** Reserve each adaptation atomically, count attempts and recovery
failures in the breaker, and bind every transition to Angerona's protected
action and evidence contracts.

### Why now

Microsoft's current circuit-breaker guidance calls for explicit Closed, Open,
and Half-Open states, time-windowed failure thresholds, health probes,
observability, manual override, and concurrency-safe implementation. Microsoft's
2026 least-privilege guidance also recommends binding authorization to the exact
action and target with short-lived authority and fresh approval for high-impact
changes. Sources:
[Microsoft Circuit Breaker pattern](https://learn.microsoft.com/en-us/azure/architecture/patterns/circuit-breaker),
[Microsoft identity, access, and least-privilege guidance](https://learn.microsoft.com/en-us/security/zero-trust/catalog-ai-defense-capabilities/identity-access-least-privilege).

The workbench can run a manual worker while the dashboard timer starts an
automatic cycle. The current check and later record are separate operations, so
two callers can pass the breaker before either records a change. Its local
SHA-256 envelopes detect accidental corruption but are not an authenticated
audit boundary against a same-user writer.

### Fit

- **Core:** acquire one durable, host-bound adaptation lease before breaker
  admission. Reserve the attempt and breaker budget in one transaction; then
  transition planned → snapshotted → applying → verifying → committed,
  failed, or rolled_back. Expired owner PID/generation leases recover visibly.
- **Circuit breaker:** count attempts, apply failures, postcondition failures,
  automatic rollbacks, and context churn—not only successful changes. Add a
  bounded Half-Open dry-run/probe state; it never performs a drastic automatic
  write.
- **Existing architecture:** route mutation authority through the current
  Response Broker/action-contract path and anchor action/receipt digests in the
  authenticated flight recorder. Reuse protected key custody rather than
  creating an adaptation secret.
- **GUI:** show the active lease, breaker reason, attempt/failure window, and
  correlation ID. This is Respond / Harden / Visualize.

### Effort

**S-M** for process-local single flight and authenticated receipts; **M** for a
durable cross-process reservation with crash recovery. Dependency: protected
key custody and an explicit lock/transaction primitive that works with the
Watchdog and Core processes.

### Safety

Defensive only. The journal grants no new action. Recovery and manual reset stay
available while an open breaker refuses ordinary writes; force-reset never
bypasses a fresh exact-plan confirmation.

---

## 5. Versioned Baseline Promotion Workflow

**Pitch.** Replace “overwrite the golden baseline” with draft, review, promote,
supersede, and restore lifecycle states.

### Why now

Microsoft's Security Compliance Toolkit treats baselines as comparable,
storable units and its Policy Analyzer highlights differences, conflicts, and
changes over time. NIST CSF 2.0 PR.PS-01 calls for established configuration
management practices. Sources:
[Microsoft Security Compliance Toolkit](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10),
[Microsoft Security Baselines](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines),
[NIST Cybersecurity Framework 2.0](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf).

A single replaceable baseline has no history, promotion reason, maintenance
window, compatibility gate, or quick restore. A compromised or simply
misconfigured moment can therefore become the new “normal” after one approval.

### Fit

- **Core:** store immutable, authenticated baseline revisions with draft,
  active, superseded, and quarantined states; parent digest; operator reason;
  OS/build/capability contract; collection quality; and optional expiry.
- **Promotion:** always show the delta from active baseline. Refuse promotion
  from partial/unavailable collectors, active High/Critical incidents, an open
  breaker, or a host/build incompatibility. Require a second acknowledgement
  for reduced protection.
- **Contexts:** allow a small bounded set of operator-named operational
  baselines such as Development or Travel, but use them for comparison only.
  Context never auto-promotes or silently rewrites a baseline.
- **GUI:** baseline timeline, compare, promote, restore, export, and “planned
  maintenance” annotation. This is Detect / Harden / Visualize.

### Effort

**S-M.** Reuses integrity stores, action receipts, and the existing drift table.
Migration keeps the current golden baseline as revision 1 with explicit legacy
provenance.

### Safety

Defensive only. Baselines describe expected state; they do not execute changes.
No AI, event, or automatic context may promote a baseline.

---

## 6. Event-Driven Drift Provenance

**Pitch.** Turn relevant Windows policy events into debounced drift audits that
explain who or what changed, without automatically fighting legitimate
administration.

### Why now

Microsoft recommends monitoring event 4950 against a defined firewall baseline.
Its current event catalog also identifies 4946–4948 for local rule changes,
4949 for reset, 4954 for Group Policy refresh, 4956 for active-profile change,
and 5025 for Firewall Service stop. Event 4697 is recommended for unexpected
service installation. Windows supports bookmarked push or pull subscriptions
through EvtSubscribe. Sources:
[Microsoft event 4950 guidance](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4950),
[Microsoft events to monitor](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor),
[Microsoft event 4697 guidance](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697),
[EvtSubscribe](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtsubscribe).

The current drift check is operator-run and the context timer does not watch
firewall or service policy changes. That can leave a long detection gap.

### Fit

- **BaseModule/existing endpoint-event engine:** subscribe to the bounded
  event-ID set with a durable bookmark and publish normalized signed evidence.
  Do not create a parallel Event Log collector.
- **Core adaptation:** debounce event bursts, correlate Angerona plan and receipt
  IDs/time windows, then schedule one read-only audit. Classify provenance as
  Angerona-approved, local-unattributed, Group Policy refresh, profile
  transition, service change, or collector gap.
- **GUI/EventBus:** show change lineage and open the exact drift result. A GPO
  refresh event is context, not proof of malicious change, and should not be
  scored without a resulting delta.
- **Modes:** Detect / Visualize.

### Effort

**S-M** if the existing Windows event pipeline already exposes these IDs;
otherwise **M** for a reliable bookmark lifecycle. Relevant audit subcategories
may be disabled, logs can wrap, and access may be denied; periodic bounded
polling remains a visible degraded fallback.

### Safety

Defensive and read-only. An event can trigger an audit or alert, never an
automatic policy reversal, service stop, process action, or remote collection.

---

## Longer-term work

## 7. Trial-Lease Apply + Crash-Independent Rollback

**Pitch.** Treat a policy change as a time-limited trial that commits only after
effective-state and local-health verification; otherwise an independent
Watchdog restores it.

### Why now

Microsoft documents native Windows Firewall export/import for backup and
restore, and WFP supports explicit ACID transactions for multi-filter changes.
NIST's cyber-resiliency guidance calls for dynamic reconfiguration without
significantly degrading or interrupting service. Sources:
[netsh advfirewall export/import](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-advfirewall),
[Windows Filtering Platform transaction management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management),
[NIST SP 800-160 Vol. 2 Rev. 1](https://csrc.nist.gov/pubs/sp/800/160/v2/r1/final).

The current implementation snapshots before apply and automatically imports on
an executor exception. A syntactically successful command can still break
connectivity, be overridden by effective policy, or be followed by a Core/GUI
crash before the operator can roll back.

### Fit

- **Core:** extend snapshot manifests with ready, trial, committed, rollback_due,
  restored, and failed states plus an authenticated deadline and expected
  postcondition digest.
- **Watchdog:** monitor only a pre-authorized trial receipt. If Core dies, the
  deadline expires, postconditions fail, or the operator presses “Connectivity
  lost,” import the exact verified snapshot. Recovery remains allowed while the
  ordinary breaker is open.
- **Health contract:** verify the effective ActiveStore, Windows Firewall/BFE
  service health, Angerona protected IPC/loopback, default-route presence, and
  optional operator-configured local dependency. No public Internet probe is
  required or enabled by default.
- **GUI:** show a countdown with Commit healthy state, Roll back now, and local
  recovery instructions. Lockdown never commits invisibly.
- **Future native broker:** when Angerona modifies multiple WFP filters, use one
  WFP transaction; keep profile-default changes on the documented NetSecurity
  path. This is Respond / Harden / Visualize.

### Effort

**M.** Windows-only, with physical-host, logoff, sleep/resume, service-restart,
and power-loss acceptance tests. The independent broker must be tightly scoped,
authenticated, replay-safe, and unable to import arbitrary files.

### Safety

Defensive recovery only. The Watchdog can restore one pre-authorized,
host-bound snapshot; it cannot run a shell, choose a new policy, contact a
remote target, or broaden containment.

---

## 8. Poisoning-Resistant Feedback Lab

**Pitch.** Move adaptive scoring into a reversible shadow-evaluation workflow so
attacker-influenced findings and repeated dismissals cannot silently train the
defender.

### Why now

NIST's March 2025 adversarial machine-learning taxonomy highlights poisoning,
evasion, privacy, and misuse attacks and explicitly addresses lifecycle
mitigations. NIST also cautions that AI/ML defenses are incomplete rather than
foolproof. Sources:
[NIST AI 100-2e2025](https://www.nist.gov/publications/adversarial-machine-learning-taxonomy-and-terminology-attacks-and-mitigations-0),
[NIST announcement and mitigation context](https://www.nist.gov/news-events/news/2025/03/nist-trustworthy-and-responsible-ai-report-adversarial-machine-learning).

The current feedback path reduces the weight of an entire category by ten
percent after a tuned dismissal, down to a floor. It does not distinguish an
exact development port from all ports, use positive feedback, decay old labels,
or evaluate the effect before activation. Although operator-confirmed, the
source finding can still be attacker-shaped.

### Fit

- **Core:** make feedback immutable signed labels scoped to finding type,
  identity pattern, context, baseline revision, and expiry. Never learn from an
  event merely because it exists.
- **Shadow evaluator:** replay only bounded stored feature summaries from recent
  audits and show false-positive reduction, missed known-positive changes,
  score delta, and affected findings. Raw paths, PIDs, SSIDs, or command lines
  are not training data.
- **Activation:** cap one proposed weight movement to a small delta; require a
  minimum count across separate audits, positive and negative evidence, exact
  operator approval, and automatic expiry/rollback. Global category tuning
  becomes legacy and is resettable.
- **AI boundary:** local AI may explain a proposal but cannot label evidence,
  calculate the deterministic score, or activate a change. Reuse the AI
  Security Broker for typed, cited explanations only.
- **GUI:** Pending feedback, Shadow result, Activate, Reject, Revert, and Reset
  controls. This is Detect / Harden / Visualize.

### Effort

**M.** The first version should remain deterministic rather than adding an ML
dependency. Real anomaly learning needs a much larger labeled corpus and
adversarial evaluation and is not justified for this local-first feature yet.

### Safety

Defensive only. No online self-training from attacker-controlled telemetry, no
cloud upload, no autonomous suppression, and no model-generated action.

---

## 9. Signed Windows Posture Packs

**Pitch.** Grow from three firewall profiles into versioned, signed,
applicability-gated posture assessments whose remediation remains typed,
previewed, reversible, and separately approved.

### Why now

Microsoft's August 2025 security-baseline guidance says a baseline should
enforce a setting only when it mitigates a contemporary threat without causing
worse operational impact. The current Security Compliance Toolkit can compare,
test, edit, store, and export Microsoft-recommended baselines; Windows Server
2025 OSConfig now adds versioned, role-aware local baselines with verify and
remove operations. Sources:
[Microsoft Security Baselines](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines),
[Microsoft Security Compliance Toolkit](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10),
[Windows Server 2025 OSConfig baselines](https://learn.microsoft.com/en-us/windows-server/security/osconfig/osconfig-how-to-configure-security-baselines).

Angerona's closed catalog is appropriately narrow today. Adding arbitrary
PowerShell would destroy that safety property, while hard-coding hundreds of
settings would create version and policy-ownership drift.

### Fit

- **Detection-content lifecycle:** define a non-executable posture-pack schema
  signed through Angerona's existing Ed25519 publisher path. It contains stable
  control IDs, supported OS/build/edition/role, read-only evidence adapters,
  expected values, severity/rationale, prerequisites, conflicts, verification,
  and rollback contract.
- **Phase A — Detect only:** import selected official SCT/Policy Analyzer data
  through an exact bounded parser, retain source/version/digest, and map a small
  first set to read-only checks: Firewall, Defender/ASR, audit policy,
  Credential Guard/VBS, and exposed services. No automatic download or claim of
  official certification.
- **Phase B — Reviewed hardening:** implement each mutation as a typed adapter
  with closed parameters, effective-policy ownership checks, exact dry run,
  trial lease, postcondition verification, and per-control rollback. AI text is
  explanation only.
- **GUI:** posture-pack catalog, applicability, unsupported/conflicting controls,
  evidence, exceptions with expiry, preview, per-control approval, verification,
  and rollback. Modes are Detect / Respond / Harden / Visualize.

### Effort

**L.** Dependencies include version-specific Windows APIs, edition/licensing
gates, domain/MDM precedence, signed-publisher operations, extensive clean-VM
acceptance, and a policy refresh/rollback lab. Start with five read-only
controls, not a broad compliance claim.

### Safety

Defensive only. Packs contain no executable script, shell, offensive technique,
credential material, remote target, or arbitrary registry path. Angerona does
not bypass enterprise policy, auto-apply a pack, claim CIS/STIG/Microsoft
certification, or weaponize a setting.

---

## Recommended implementation order

1. Ship the Collector Quality Contract and Restrictive Context Lattice together;
   they close the two most consequential “bad input becomes bad decision”
   paths.
2. Add effective-policy ownership before expanding any automatic apply.
3. Make action admission single-flight and authenticated before enabling
   auto-apply outside a lab.
4. Add versioned baseline promotion and event-driven provenance as read-side
   improvements.
5. Require a crash-independent trial lease before treating Emergency Lockdown
   as production-grade autonomous response.
6. Keep feedback in shadow mode until it passes poisoning and regression tests.
7. Treat posture packs as a separate signed-content program after the first six
   controls have physical-host evidence.

## Explicit non-proposals

- No arbitrary PowerShell, command editor, or “AI-generated fix and run.”
- No automatic service stop, process kill, route edit, Wi-Fi connect, or network
  reclassification in Adaption.
- No SSID-only trust decision and no raw Wi-Fi credential collection.
- No automatic reversion of GPO/MDM changes.
- No new kernel driver; future WFP work must reuse Angerona's existing reviewed
  broker and native qualification boundary.
- No offensive testing, exploit generation, persistence, credential access, or
  remote-control capability.
