# Cycle 25 / Round 1 — Visionary review and innovation disposition

Date: 2026-08-28
Mode: defensive-only research, design, and implementation review

## Outcome

The visionary pass prioritized less-button-heavy local operation without
turning observation, model output, or context into unattended authority. It
also used upstream defensive projects to improve Angerona's local contracts
without claiming fleet or standard parity.

## Shipped in v1.12

### Guided Auto Adapt and immutable recovery

One guided action now collects a closed security intent—Balanced, Public, or
Emergency Lockdown—and offers explicit baseline enrollment and an optional
apply request. The workflow performs one audit, rejects incomplete evidence,
builds an immutable plan, and simulates without writes. Applying is a separate
exact-plan confirmation. Accepted UI choices are copied immutably before work
starts, preventing a later widget change from altering consent.

The enrolled baseline is authenticated, host-bound, and non-replaceable. It
captures the complete Windows Firewall policy, which is the complete mutation
scope of Host Adaptation. Hardware, services, ports, and network context remain
observational and are not marketed as whole-host rollback.

### Safe automatic checkup

The comprehensive checkup audits once and simulates every registered profile
without writing. Context-driven automation remains proposal-only, including
lockdown recommendations and remote-session conditions.

### Capability Center and evidence-first UI

Every discovered capability has one searchable, sortable, clickable contract
and a common operational snapshot. Capability Center and Module Inspector show
implementation version, native/adapter status, source, dependencies,
permissions, paths, lifecycle, freshness, loss, and recent evidence.

Shared tables use typed severity/numeric sorting. Live Defense, alerts, Context
Info, adaptation rows, CVE items, and governed paths open bounded details.
Alert identity and record fingerprints are distinguished from verified HMAC
authenticity. Analysis is bounded to two active workers plus six queued exact
event identities. SOAR history clearing is a recoverable archive/restore
operation, and CVE detail workers are owned and nonblocking.

### Crash-aware local delivery and mutation

Durable SIEM/Remote outboxes, revision cursors, atomic settings/intelligence
updates, Host Adaptation journals, and startup reconciliation make interrupted
work visible. Evolution, mitigation tuning, and behavioral changes remain inert
until the appropriate exact review/approval path completes.

### Standards truth

ATT&CK 19.2, Navigator 5.3.2/layer 4.5, constrained OCSF 1.8, and the constrained
Sigma admission engine now declare exact version/scope. Unsupported Sigma
content returns an atomic refusal receipt rather than partial admission.

## Proposed / backlog

These ideas were reviewed but **not shipped** in v1.12:

1. **Batched durable outbox commits.** Potentially fewer
   `synchronous=FULL` commits, but crash-time duplicate/replay semantics need a
   dedicated design and proof.
2. **Immutable compiled Sigma plans.** Could reduce per-event validation cost at
   high rule counts, but the current public mutable-list behavior must first be
   replaced by an explicit immutable API.
3. **Global CVE detail-worker backpressure.** A global cap could bound bursts of
   distinct CVE clicks, but the queue/refusal UX needs an operator-visible
   contract.
4. **Independent outbox rollback witness.** A separate monotonic witness could
   detect row deletion or whole-database rollback beyond local HMAC custody.
5. **Coordinated live transport-key epochs.** Queue data no longer depends on
   the rotatable transport key, but coordinated live rotation without restart
   needs a versioned peer protocol.
6. **Native contract migration.** The 75 compatibility adapters should move to
   explicit native declarations incrementally, module by module; v1.12 does not
   pretend this migration is complete.

## Safety boundary

No idea authorizes exploitation, credential capture, remote scanning, arbitrary
scripts, log deletion, persistence, unreviewed downloads, hack-back, or automatic
host mutation derived from AI/content/context. The upstream comparison and
primary sources are recorded in
[upstream_project_comparison.md](upstream_project_comparison.md).
