# Round 1 Innovation Challenge — 2026-08-20

## Decision

Angerona does not need another broad subsystem in this sweep. It needs a few
high-leverage boundaries that make the suite more diagnosable, safer to operate,
and harder to misuse while preserving its local-first design.

This review compared the current 65-module tree, `README.md`, `llms.txt`, and
`ENTERPRISE_UPGRADE_TODO.txt` against current primary/authoritative sources. It
intentionally excludes ideas that Angerona already implements or has already
designed: the kernel-boundary posture ledger, transactional WFP containment,
telemetry-loss accounting, evidence claim resolution, Pktmon flight recording,
USN ransomware pulse, NTLM exit mapping, call-stack provenance, model airlock,
QUIC sightline, split-token architecture, App Control evidence, signed model
admission/ML-BOM, ClickFix correlation, ATT&CK v19/Sigma 2.1 contracts, and
ZTDNS/ECH correlation. Production mTLS/OIDC, Authenticode custody, HA/DR, and
physical-host soaks remain important external gates rather than new local
features.

Ranking uses ordinal impact divided by effort weight (`S=1`, `S-M=1.5`, `M=2`,
`M-L=2.5`). The quotient is a prioritization aid, not an engineering estimate.

| Rank | Proposal | Impact | Effort | Impact / effort | Mode |
|---:|---|---:|:---:|---:|---|
| 1 | Crash Breadcrumb Capsule + Fault-Domain Circuit Breaker | 5 | S-M | 3.33 | Detect / Harden / Visualize |
| 2 | RMM and Remote-Support Trust Ledger | 5 | S-M | 3.33 | Detect / Harden / Visualize |
| 3 | WinRE / Quick Machine Recovery Readiness | 3 | S | 3.00 | Harden / Visualize |
| 4 | Windows Hello–Bound Response Approval | 5 | M | 2.50 | Respond / Harden |
| 5 | MCP Tool-and-Data Provenance Firewall | 5 | M | 2.50 | Detect / Harden / Visualize |
| 6 | Purpose- and Epoch-Bound Telemetry Tokens | 4 | M | 2.00 | Harden / Privacy |
| 7 | Browser Session-Theft Behavior Correlator | 5 | M-L | 2.00 | Detect / Respond |

---

## 1. Crash Breadcrumb Capsule + Fault-Domain Circuit Breaker

**Pitch.** Keep a tiny, privacy-minimized, process-external record of which
Angerona fault domains were active immediately before a native crash, then use
repeatable evidence—not guesswork—to quarantine only an optional suspect module.

### Why now and threat model

Angerona already records Python/Qt exceptions and GUI stalls, and its watchdog
has restart budgets and safe mode. A native fail-fast can still terminate the
process before buffered logs identify the responsible QThread, dialog, native
library, or module generation. Windows Error Reporting (WER) can collect local
user-mode dumps, and Application Recovery and Restart can preserve state before
restart; Microsoft notes that local dumps are collected before the recovery
callback and that restart applies only after an application has run for at least
60 seconds. Sources: [Collecting user-mode dumps](https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps),
[Registering for Application Restart](https://learn.microsoft.com/en-us/windows/win32/recovery/registering-for-application-restart).

Threats include a crashing native dependency, stale Qt worker ownership,
restart storms, attacker-induced crash loops, and a diagnostics subsystem that
accidentally captures secrets. The capsule must help attribution without
becoming a memory dump or a new recovery authority.

### Fit and architecture

- **Core:** add `core/crash_capsule.py`, a fixed-size, checksummed shared-memory
  record containing release digest, monotonic boot/session ID, EventBus revision,
  module generation/state codes, active Qt worker IDs, dialog class identifiers,
  and the last bounded lifecycle transition. Never store event bodies, command
  lines, paths, prompts, network addresses, usernames, or stack memory.
- **Existing seams:** `module_manager.py`, `thread_lifecycle.py`, `crashlog.py`,
  and `uiwatchdog.py` update O(1) breadcrumbs. The independent Watchdog reads a
  sealed snapshot only after Core death and attaches its digest to existing
  `recovery_state.py` evidence.
- **Circuit breaker:** phase two may quarantine only a nonessential module after
  the same signed crash signature repeats across at least three fresh process
  generations. Core telemetry, recovery, storage integrity, and the watchdog are
  never automatically disabled. Operator reset and expiry are mandatory.

### Implementation slices

1. **S / recommended now:** diagnostic-only capsule and post-crash viewer; no
   behavior change, quarantine, dump collection, or registry mutation.
2. **S-M:** deterministic signature grouping and a GUI “Crash lineage” card.
3. **M:** policy-gated optional-module circuit breaker after physical-host soak.

### Tests and performance budget

- Kill/fail-fast fixtures verify the last committed capsule survives and never
  contains forbidden data classes.
- Torn writes, checksum corruption, stale PID reuse, clock rollback, full disk,
  concurrent QThreads, clean shutdown, and watchdog restart are covered.
- A single crash cannot disable anything; differing signatures do not aggregate.
- Update cost: p99 below 50 microseconds, one preallocated page, no per-event I/O,
  and no GUI-thread blocking.

### Safety

Defensive diagnostics only. Phase one does not change host policy, install WER
registry settings, capture process memory, or disable a module. Any later circuit
breaker is bounded, reversible, signed, optional-module-only, and never grants
the AI or watchdog arbitrary process-control authority.

---

## 2. RMM and Remote-Support Trust Ledger

**Pitch.** Treat remote-management software as a time-bound administrative
session with provenance, not as globally good or globally malicious software.

### Why now and threat model

CISA says ransomware actors continue to abuse Remote Monitoring and Management
(RMM) tools and recommends auditing authorized tools, unexpected execution, and
portable copies. A June 2025 advisory documented exploitation of SimpleHelp RMM
against multiple organizations. Sources: [CISA JCDC RMM Cyber Defense Plan](https://www.cisa.gov/topics/partnerships-and-collaboration/joint-cyber-defense-collaborative/jcdc-remote-monitoring-and-management-cyber-defense-plan),
[CISA StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide),
[CISA SimpleHelp RMM advisory](https://www.cisa.gov/sites/default/files/2025-06/aa25-163a-ransomware-simplehelp-rmm-compromise.pdf).

Angerona recognizes RDP/WinRM ATT&CK events but has no RMM/Quick Assist trust
object. The threat is a legitimate signed product launched from an unexpected
path, a portable/unmanaged copy, a new unattended service, an out-of-window
session, or an approved tool whose signer/hash/lineage suddenly changes.

### Fit and architecture

- **Core:** add `core/remote_support_trust.py` with a bounded `SupportSession`
  keyed by immutable process identity. Expected state binds exact path digest,
  signer/publisher, file hash/version, service identity, allowed parent, user
  session type, maintenance window, and expected network class.
- **BaseModule:** consume existing process, service/persistence, asset inventory,
  Authenticode, and network observations. Do not packet-inspect or enumerate
  remote screen content.
- **Trusted Processes:** add a separate “Remote support” policy category. An
  ordinary process allowlist must not silently authorize unattended access.
- **GUI:** display `approved-active`, `approved-out-of-window`, `portable`,
  `drifted`, `unexpected`, or `unknown`; show exact supporting evidence and
  policy expiry.

### Implementation slices

1. **S-M:** read-only inventory and exact-provenance drift alerts for an
   operator-supplied catalog; no vendor-name blacklist.
2. **M:** bounded session correlation across process/service/network evidence.
3. **M:** existing typed Response Broker may offer a preview to suspend an
   immutable process identity; never auto-contain on product name alone.

### Tests and performance budget

- Fixtures cover installed/portable RMM, valid update, signer drift, service
  creation, renamed binary, DLL side-load evidence, VPN/proxy use, expired
  maintenance window, PID reuse, missing signature service, and ordinary remote
  work tools.
- A signed binary is not automatically trusted; a basename match is never enough.
- One signal remains Low/Informational. High requires provenance drift plus a
  session/network/persistence signal.
- Reuse current process/network caches; no scan faster than 30 seconds, at most
  512 active/recent session records, and steady-state CPU below 0.2%.

### Safety

Defensive observation and existing typed response only. The feature never
connects to an RMM service, records a screen, captures credentials, discovers
vendor secrets, or teaches remote-tool exploitation.

---

## 3. WinRE / Quick Machine Recovery Readiness

**Pitch.** Show whether a Windows endpoint can recover from a boot-breaking
update or driver event—and whether recovery would make an unexpected cloud or
Wi-Fi egress—without modifying recovery configuration.

### Why now and threat model

Microsoft's Quick Machine Recovery (QMR), available on supported Windows 11
24H2+ builds, uses Windows Recovery Environment and can contact Windows Update
after repeated boot failure. Its configuration can include cloud remediation,
automatic retries, and Wi-Fi credentials. Microsoft calls it best effort and
documents exact version/edition gates. Sources: [Quick Machine Recovery](https://learn.microsoft.com/en-us/windows/configuration/quick-machine-recovery/),
[Recovery CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/recovery-csp).

Threats are a false “recoverable” claim when WinRE is disabled, unreviewed cloud
egress from recovery, recovery retry loops, unsupported builds, and accidental
display or retention of Wi-Fi secrets.

### Fit and architecture

- **Core:** add a pure parser/model for `enabled`, `disabled`, `unsupported`,
  `unreadable`, and `unknown`, plus cloud/auto-remediation booleans and bounded
  retry/time-to-reboot values.
- **Collector:** a Windows-only read-side module invokes the absolute trusted
  `%SystemRoot%\System32\reagentc.exe` with a short timeout. It parses only a
  bounded schema and discards Wi-Fi SSID/password elements before logging.
- **GUI:** add recovery readiness to Kernel/Posture evidence, explicitly marking
  cloud contact as opt-in egress—not universally good or bad.
- **Fleet:** expose only aggregate readiness state and policy digest; no recovery
  XML, SSID, password, path, or device identifier.

### Implementation slices

1. **S / recommended now:** version-gated, read-only status and privacy-safe UI.
2. **S-M:** signed drift evidence after Windows update/reboot.
3. **External lab only:** QMR test-mode evidence; never run recovery simulation
   from the ordinary desktop product.

### Tests and performance budget

- Fixtures cover supported/unsupported builds, WinRE disabled, malformed XML,
  secret-bearing XML, timeout, access denial, cloud on/off, auto-retry, and
  localization-safe parsing.
- Tests prove no SSID/password survives parsing, logs, exports, or exceptions.
- Poll at startup and no more than every six hours; timeout at five seconds;
  work stays off the GUI thread.

### Safety

Read-only and defensive. Angerona does not enable QMR, store recovery Wi-Fi
credentials, enter WinRE, run test mode, change retry policy, download a fix, or
claim QMR guarantees recovery.

---

## 4. Windows Hello–Bound Response Approval

**Pitch.** Bind every high-impact local response approval to the exact action
digest and an explicit Windows Hello or FIDO2 user gesture.

### Why now and threat model

NIST SP 800-63B-4, finalized in 2025, requires phishing-resistant options at
Authentication Assurance Level 2 and explains why manually entered OTPs are not
phishing-resistant. Windows exposes Win32 WebAuthn APIs for native applications
to use Windows Hello or external FIDO2 keys. Sources: [NIST SP 800-63B-4](https://www.nist.gov/publications/nist-sp-800-63b-4digital-identity-guidelines-authentication-and-authenticator),
[Windows WebAuthn APIs](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/webauthn-apis).

Angerona already has typed, expiring, idempotent response plans and approvals.
The remaining local threat is session/UI compromise, voice spoofing, stolen PIN,
or a confused operator approving a different action than the preview.

### Fit and architecture

- **Core:** add `core/operator_presence.py` behind an injectable adapter. The
  WebAuthn challenge binds action digest, target identity, expiry, policy
  version, case ID, and a nonce. The receipt stores credential ID token,
  authenticator flags, counter/result, and assertion digest—not biometric data.
- **Response:** `safe_response_session.py` and `response_broker.py` can require
  this receipt for policy-selected High/Critical actions. Existing multi-person
  approval remains separate; one Hello gesture cannot impersonate two people.
- **GUI:** the Windows-controlled verification prompt follows the exact action
  preview. Voice may navigate to the preview but cannot satisfy user presence.

### Implementation slices

1. **M:** optional local step-up for one reversible action, with injected fake
   authenticator tests and explicit unsupported/degraded states.
2. **M:** policy-required step-up for high-impact actions after accessibility,
   recovery, credential rotation, and lockout testing.

### Tests and performance budget

- Reject replay, wrong action digest, wrong relying-party ID, expired challenge,
  cloned credential record, missing user-verification flag, counter regression,
  cancellation, and changed target/PID generation.
- Reboot, credential deletion, Hello unavailable, external security key, and
  accessibility flows fail visibly without silently downgrading a required gate.
- No biometric template, PIN, authenticator secret, or raw attestation is logged.
- Verification adds no background work; target p95 after user gesture is below
  one second excluding human interaction.

### Safety

Defensive authorization only. It never reads biometric material or makes an AI
decision. A passkey assertion proves an approved user gesture bound to a request;
it does not prove the requested response is technically correct.

---

## 5. MCP Tool-and-Data Provenance Firewall

**Pitch.** Upgrade Angerona's older MCP surface so every request, tool result,
and model-visible datum carries identity, scope, taint, and an auditable lineage
receipt.

### Why now and threat model

Angerona currently implements MCP 2024-11-05 on loopback with an optional bearer
token. MCP 2025-06-18 adds structured tool output and resource-server
authorization requirements, including audience validation, resource indicators,
PKCE, and an explicit ban on token passthrough. The specification also says tool
descriptions are untrusted and users should understand and consent to tool use.
Sources: [MCP 2025-06-18 specification](https://modelcontextprotocol.io/specification/2025-06-18/index),
[MCP authorization](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization),
[MCP change log](https://modelcontextprotocol.io/specification/2025-06-18/changelog).

Threats are unauthorized local processes querying security data, confused-deputy
token reuse, malicious tool/result descriptions, telemetry prompt injection,
and an agent presenting an inference as if it were a sensor fact.

### Fit and architecture

- **Transport:** migrate to the current lifecycle/structured-output contract.
  Local mode gets an installation-generated short-lived scoped credential; a
  future non-loopback mode requires the enterprise authorization design rather
  than reusing the local token.
- **Core:** add a provenance envelope around every tool call/result:
  client identity, tool schema/version, normalized argument digest, scope,
  source evidence references, privacy class, untrusted-data taint, truncation,
  timestamp, and receipt digest.
- **AI boundary:** `analysis_worker.py`, `ai_security_broker.py`, and ARIA keep
  sensor evidence, operator text, external content, model inference, and
  deterministic policy decisions as different types. Taint can narrow access
  or force quotation; it can never grant a capability.
- **GUI:** show active clients, scopes, expiry, calls, denied calls, and exact
  fields disclosed. Revocation is immediate and audited.

### Implementation slices

1. **S-M:** make local authentication mandatory when MCP is enabled, rotate it,
   and add structured result schemas without adding write tools.
2. **M:** provenance/taint envelope and deterministic hostile-result eval corpus.
3. **L/external:** OAuth resource-server interoperability only with production
   identity infrastructure; never invent a home-grown remote auth server.

### Tests and performance budget

- Cover missing/expired/wrong-audience tokens, token passthrough, DNS rebinding,
  session fixation, malicious tool annotations, hostile event text, nested JSON,
  Unicode confusables, oversized results, replay, client revocation, and mixed
  privacy classes.
- No MCP path can invoke a shell or cross into Response Broker authority.
- Admission and envelope work p95 below 10 ms; maximum 1 MiB result, 500 rows,
  eight calls per plan, two concurrent plans, and existing server thread caps.

### Safety

Defensive read-only interoperability. No new offensive tools, generic shell,
credential relay, autonomous remediation, or hidden network listener. Remote
authorization remains out of scope until the external mTLS/OIDC gate exists.

---

## 6. Purpose- and Epoch-Bound Telemetry Tokens

**Pitch.** Replace indefinitely linkable pseudonyms with domain-separated,
purpose-specific tokens that rotate on policy epochs and require an audited
join permit for longitudinal analysis.

### Why now and threat model

Angerona already HMAC-tokenizes accounts, sources, processes, and destinations,
but a stable token can still become a long-lived tracking identifier. NIST SP
800-188 stresses that masking is not automatically sufficient de-identification
and calls for measurable re-identification review. The IETF Privacy Pass
architecture formalizes unlinkability across issuance/redemption contexts; this
proposal borrows the *context separation goal*, not its protocol. Sources:
[NIST SP 800-188](https://csrc.nist.gov/pubs/sp/800/188/final),
[RFC 9576 Privacy Pass Architecture](https://www.ietf.org/rfc/rfc9576.html).

Threats are accidental cross-purpose joins, breach-driven long-term tracking,
salt reuse between tenants/exports, and a rotation that silently destroys the
minimum correlation needed for detection.

### Fit and architecture

- **Core:** extend `data_governance.py` with HKDF-derived keys scoped to
  `(tenant, purpose, field class, epoch, schema version)`. A token includes only
  a short purpose/epoch identifier and MAC output.
- **Analytics:** identity/network analytics declare required lookback and
  purpose. A bounded overlap permits current/previous epoch comparison; broader
  joins require a short-lived, typed, audited re-tokenization plan executed at
  the protected local source.
- **Export:** each privacy manifest records token domain, epoch, joinability,
  retention, and deletion state without exposing derivation keys.
- **Migration:** stable legacy tokens remain labeled `legacy-linkable`; they are
  never silently relabeled or recomputed without source evidence.

### Implementation slices

1. **M:** domain separation for new exports and tests; no database migration.
2. **M:** epoch rotation for new analytics with measured detection impact.
3. **M-L:** controlled join permits only after privacy review and recovery tests.

### Tests and performance budget

- Same input in different tenant/purpose/field/epoch domains never matches;
  same authorized domain is deterministic.
- Reject weak/missing keys, epoch rollback, cross-tenant salt reuse, unknown
  versions, oversized values, and unauthorized join attempts.
- Replay current identity/NDR fixtures across an epoch boundary to quantify lost
  detections; no privacy change ships if safety-critical correlation regresses.
- Tokenization remains O(1), adds below 5% to current minimization benchmarks,
  and retains at most current plus previous epoch keys in memory.

### Safety

Privacy hardening only. It does not claim anonymization, export raw identifiers,
or weaken critical local detections. If privacy and essential response evidence
conflict, the feature must abstain and show the conflict rather than silently
breaking either guarantee.

---

## 7. Browser Session-Theft Behavior Correlator

**Pitch.** Detect an infostealer's behavior chain—unexpected access to browser
credential stores, decryption activity, staging, and outbound transfer—without
reading, copying, or logging a credential or cookie.

### Why now and threat model

Microsoft's May 2025 Lumma Stealer analysis shows practical hunting patterns for
non-browser processes opening sensitive browser files and for suspicious
cryptographic unprotect operations associated with browser data. Source:
[Microsoft: Lumma Stealer delivery and capabilities](https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/).

Angerona detects LSASS dumping but does not model theft of Chromium/Firefox
cookies, login databases, or session material. The threat is a signed or renamed
process accessing browser profile stores, invoking decryption, staging an
archive, then contacting a new destination. Browser backup, migration,
password-manager, AV, and enterprise-management software are major benign cases.

### Fit and architecture

- **Core:** add a bounded temporal state machine keyed by immutable process
  identity. Features are only category flags and keyed path digests:
  `browser-store-open`, `unexpected-reader`, `decrypt-operation`, `archive-stage`,
  `new-destination`, `user-session`, and `telemetry-missing`.
- **Sensors:** consume supported ETW/Event Log/Sysmon or normalized vendor events
  only when available. Do not install audit policy, read browser databases, hook
  crypto APIs, or scan cookie values. Missing file-open/decryption evidence is a
  visible coverage gap.
- **Baseline:** reuse `process_baseline.py`, exact signer/path/hash provenance,
  and supervised allowlisting. Never trust basename or publisher alone.
- **Response:** High confidence requires at least three independent classes,
  including behavior after access. Resolve Center may stage an exact-process
  scan/containment preview through existing typed actions.

### Implementation slices

1. **M:** offline analytic/replay engine with synthetic normalized evidence.
2. **M-L:** one version-gated passive Windows collector after physical-host
   privacy and performance measurement.
3. **M:** signed detection package and benign-enterprise fixture corpus.

### Tests and performance budget

- Positive fixtures cover direct database access, copied database, renamed
  runtime, decrypt-plus-stage, and stage-plus-egress. Negative fixtures cover
  browsers, backup/migration, AV, password managers, developer tools, updates,
  and profile repair.
- Path strings, URLs, cookie values, passwords, tokens, browser history, and file
  contents never reach persisted/exported evidence.
- Missing telemetry, PID reuse, out-of-order data, duplicated records, a single
  file open, or decryption alone cannot produce High/Critical or authorize action.
- Fixed five-minute windows, at most 2,048 process states, O(1) updates, and a
  measured throughput regression below 3% at 50,000 synthetic events/minute.

### Safety

Defensive detection only. It never opens a browser credential database, calls a
decryption routine, captures a cookie, simulates theft, generates an exfiltration
sample, or exposes an infostealer recipe.

---

## Recommended low-risk cut for this sweep

1. **Crash Breadcrumb Capsule, diagnostic-only slice.** It directly addresses
   the current random-crash problem, is one fixed page of metadata, and changes
   no recovery decision. It should land only after forbidden-field and forced-
   crash tests prove the capsule is privacy safe.
2. **WinRE/QMR Readiness, read-only slice.** It is small, version-gated, has no
   policy mutation, and makes a new Windows recovery/privacy boundary visible.
   Parsing must discard Wi-Fi elements before any log or model can see them.

The RMM trust ledger is the next detection feature after those two. WebAuthn,
MCP modernization, rotating telemetry tokens, and browser-theft correlation
change larger trust or data contracts and should receive their own threat-model
review before implementation.

## Defensive-only boundary

Every proposal is defensive, local-first, bounded, and fail-visible. None adds
exploitation, credential access, destructive payloads, stealth, arbitrary remote
execution, model-authored executable actions, packet decryption, offensive
simulation, or an unsigned kernel component. Observation does not authorize
response; response continues through Angerona's deterministic typed policy and
human approval paths.
