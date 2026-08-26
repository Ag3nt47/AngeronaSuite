# Cycle 23 — State-grade-pattern defensive hardening

Date: 2026-08-26
Product version: 1.10.3 (no version bump)
Mode: actor-neutral, defensive-only research and engineering

## Outcome

Cycle 23 added bounded defenses for advanced SSH persistence/tunneling, Windows
audit-log clearing and continuity loss, and untrusted physical Wi-Fi/Ethernet
paths. It also added a pinned Personal Sentinel gateway-attestation client, a
sanitized Live Defense Activity dashboard card, and a governed ARIA Defense
Memory.

The engineering target is observable tradecraft, not a named agency. SSH,
router, DNS/DHCP, tunneling, valid-account, and telemetry-suppression techniques
are shared across state, criminal, and insider activity. Angerona therefore
reports evidence as an advanced or state-grade *pattern* and leaves actor
attribution unassessed.

## Shipped capabilities

### SSH Surface / Key / Tunnel Guard (`SSHG`)

- Bounded, root-confined OpenSSH configuration and Include-graph observation.
- Aggregate identities for configured authorized-key, CA, principals, and host-
  key sources; public keys are fingerprinted and private keys are never read.
- Windows target and parent-chain custody checks, including replacement/delete-
  child rights and user-aware per-user source policy.
- Per-user `%h`, `%u`, `%U`, `%%`, and relative-home semantics with explicit
  unresolved/incomplete states rather than false missing-path claims.
- Fixed Windows OpenSSH provider/channel/event identities, capped reopen
  backoff, honest history-bounded recovery, and server/client process, listener,
  socket, PID-birth, and normalized forwarding evidence.
- A bounded consuming SSH option grammar recognizes supported direct and `-o`
  forwarding forms without retaining or publishing full command lines or raw
  endpoints.
- Observe-only: no listener probe, password/key guessing, login, key change,
  configuration edit, or remote-control authority.

### Audit Log Integrity Guard (`ALIG`)

- Fixed Windows Security, System, and Sysmon channel/provider/event identities
  for explicit clear, audit-policy, service, and telemetry-tamper evidence.
- Oldest-retained bounded replay on genuine first enrollment and fail-closed
  behavior when an established cursor/enrollment member disappears or changes.
- Record-bound generation anchors, staged publication, compare-and-swap state,
  and late/pre-publication validation to reject clear/refill generation races.
- Continuity-gap, retention regression, record-reuse, provider/schema rejection,
  and authenticated cursor-tamper evidence without raw XML disclosure.
- Quiescent state is re-read and authenticated without rotating identical files.
- Observe-only: it never clears, restores, exports, or changes a Windows log or
  audit policy.

### Zero-Trust Network Path Monitor (`NZTR`)

- Every active non-loopback physical Wi-Fi and Ethernet path begins untrusted,
  independent of SSID, private address, Windows profile, or location.
- Purpose-specific tokens preserve restart comparisons for DNS, DHCP, routes,
  gateway identity, connection profile, interface generation, and physical path
  additions without retaining raw local identifiers.
- Strict authenticated provisional/trusted baselines, completeness accounting,
  bounded in-flight child output, and fail-closed interface/route overflow.
- Newly observed paths emit `network.path_added`, enter an authenticated
  provisional pending set, survive restart, and promote only after every pending
  path remains active and unchanged. Other drift, absence, incomplete evidence,
  failed persistence, history eviction, or freshness loss blocks advancement.
- The monitor does not change routes, firewall rules, profiles, adapters, DNS,
  DHCP, or gateway configuration, and it grants no endpoint trust or response
  authority.

### Personal Sentinel Gateway attestation client

Intended topology:

```text
Angerona host
  -> operator-controlled Personal Sentinel gateway/firewall
  -> upstream/ISP router
  -> Internet
```

The shipped component is an explicit client for one exact interface/private-
literal HTTPS default gateway. It requires platform certificate-chain and
hostname validation plus a leaf-certificate SHA-256 pin, nonce/freshness,
expected policy digest, peer-IP binding, strict request/response bounds,
no-proxy/no-redirect behavior, complete IPv4/IPv6 selected-route evidence, and
unchanged pre/post route context. Optional mTLS file paths are supported.

The client attests only the observed path. It does not trust an endpoint,
identity, application, destination, upstream router, or gateway firmware. It
does not discover or manage routers, store router credentials, expose a route
or firewall mutation API, or implement the gateway appliance/server/routing
role. Missing or rejected enrollment leaves every path untrusted.

The optional compact continuity-receipt API is privacy-minimal and pinned to the
same enrolled gateway authority, but it is not a server-enforced monotonic
high-water source and is not represented as independent anti-rollback custody.

### Live Defense Activity

The dashboard card requests at most 16 recent public events and displays at
most five sanitized rows plus coarse module health. It refreshes through the
existing dashboard cadence, reads no `Event.details`, and redacts credentials,
local users, paths, addresses, MAC/EUI values, SSIDs, and interface identities.
It is an operational view—not source-code execution, a debugger, raw telemetry,
hidden AI reasoning, or chain-of-thought.

### ARIA Defense Memory

`assets/angerona_defense_memory.json` is a data-only defensive reference loaded
only after strict duplicate-free schema validation, structural/text bounds,
root confinement, regular non-reparse stable-file admission, and canonical
SHA-256 pin verification. It contains Angerona capabilities, usage guidance,
defensive measures, limits, and actor-neutral tradecraft mappings. It contains
no live telemetry, secrets, executable action, tool definition, offensive
procedure, or agency attribution.

Local runbook retrieval exposes it as `angerona://defense-memory`. If an
operator has separately authorized cloud fallback, only selected bounded,
redacted Defense Memory excerpts are eligible to cross that boundary; the whole
asset, live environment, runbooks, files, and conversation history remain
local.

### Independent-freshness client/store contract

`core/independent_high_water.py` defines a strictly injected, privacy-minimal
monotonic compare-and-swap protocol for separate audit and network domains.
State transitions bind the installation, domain, revision, authenticated-pair
digest, prior state digest, and opaque prior head. With a conforming authority,
behind, forked, cloned, migration, outage, and external-first crash states fail
visible and block advancement.

No production implementation of a separately administered monotonic service or
policy-bound Trusted Platform Module authority is bundled. With no injected
authority, local HMAC authenticity remains useful, but status is explicitly
`local-authenticity-only`, `independent_freshness_verified=false`, and matching
older local pairs remain replayable. A third local file, the Personal Sentinel
compact receipt, a loopback service, or the in-memory test fixture does not
satisfy independent custody.

## Three-round security disposition

| Round | New red-team findings | Disposition |
|---|---:|---|
| 1 | 9: 5 Medium, 3 Low, 1 Info | **9 fixed.** First-enrollment replay, clear/refill races, SSH Include/source/custody and Windows runtime/log coverage, persistent network drift/completeness, route-specific gateway proof, dashboard privacy, cross-platform discovery, and Defense Memory bounded admission were remediated. QA then reported paired valid-state rollback for Round 2 design. |
| 2 | 6: 2 Medium, 4 Low | **5 fixed; 1 deferred.** Fixed per-user SSH semantics/parent custody, interface-overflow completeness, OpenSSH source recovery, forwarding grammar, and audit provider/schema identity. R2-01 delivered the injected high-water protocol but retained the external authority as a deferred dependency. QA also fixed the SSH guard's omitted optional `register()` compatibility export. |
| 3 | 1 Medium | **1 fixed.** New physical paths now produce explicit privacy-safe evidence and restart-safe authenticated provisional reconciliation. |

Total red-team findings: **16**. Fixed: **15**. Deferred external dependency:
**1**. No Cycle 23 Critical or High finding was opened. The remaining item is
not treated as release-blocking, but it is not falsely closed.

Older findings were reconciled separately: A-07 is **RESOLVED** because Shadow
Shield uses SHA-256. A-04 (in-process admitted-extension authority), A-06
(PowerShell execution centralization/policy), and R6-03 (retained process/
executable identity leases through mutation) remain architectural or defense-
in-depth residuals.

## Performance disposition

| Round | Change | Measurement | Status |
|---|---|---:|---|
| 1 | Verify identical audit state without durable rotation | 42.189 ms -> 1.001 ms median (**97.6%**); up to 43,200 idle durable replacements/day avoided at unchanged cadence | Applied |
| 1 | Query command lines only for admitted SSH clients | 41.050 ms -> 3.726 ms median (**90.9%**) on the measured no-SSH host | Applied |
| 1 | Avoid rebuilding an already-clean untrusted network snapshot | 1,319.25 us -> 88.70 us (**93.3%**) at the declared bound | Applied |
| 2 | One-pass bounded per-user SSH token expansion | 213.317 ms -> 1.335 ms (**99.4%**) at the admitted maximum; fail-closed over-limit case 70.783 ms -> 0.827 ms (**98.8%**) | Applied |
| 3 | Pending-token set reuse and one-pass finding classification | Normal case was slower or savings were only tens of microseconds at an artificial maximum | Not applied |

Round 3 retained the direct bounded implementation. Pure 64-path evaluation
measured 3.113 ms for stable state and 2.817 ms for a 63-to-64 addition at the
unchanged 30-second monitor cadence. No optimization reduced polling, retry,
freshness, anchor, route, completeness, privacy, or observe-only checks.

## Final verification

- Pytest: **1,460 passed, 5 expected host-capability skips, 0 failed** from
  **1,465 collected tests across 208 files**.
- Product Python compile: **321/321**.
- Module files imported: **73/73**.
- `BaseModule` classes / manager instances: **71/71**, with zero discovery
  errors and no duplicate names or non-empty codes.
- Zero-argument compatibility `register()` hooks: **58/58** valid.
- Standalone core + Shark self-tests: **22/22**.
- Module harness: **50 passed, 0 failed, 21 expected skips**, plus EventBus PASS.
- Direct and batch selfcheck: **26/26** each.
- Ruff: **clean**.

The five pytest skips are explicit Windows host-capability gates for symlink,
directory-link/reparse, and POSIX permission primitives. The 21 module skips are
13 inactive/optional prerequisites, five operator-disabled capabilities, and
three platform-unavailable modules on the Windows host.

## Proposed or deferred—not shipped

- A separately administered Personal Sentinel monotonic witness/server or a
  policy-bound hardware high-water authority with durable CAS, device identity,
  backup, clone/re-enrollment, loss, and recovery policy.
- A Personal Sentinel gateway appliance/server and routing role.
- Gateway measured-boot, signed-firmware, or hardware-rooted policy attestation.
- Resource/destination-scoped egress-assurance leases.
- Authoritative SSH enrolled-key-to-session provenance receipts.
- Event-driven WEVT delivery, fixed-schema network inventory coalescing, and a
  narrow post-attestation route observer, pending dedicated equivalence and
  race/completeness proof.
- Local correlation/ambient-health wrapper modules, deprioritized because
  Evidence Lattice, incidents, Telemetry Expectations, Canary Drill, module
  health, and typed path-addition evidence already cover their local mechanics.

## Primary research sources

- CISA, AA25-239A, *People's Republic of China State-Sponsored Cyber Threat
  Actors Exploit Network Devices to Maintain Persistent Access to U.S. and
  Global Networks*: https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a
- CISA, AA24-038A, *PRC State-Sponsored Actors Compromise and Maintain
  Persistent Access to U.S. Critical Infrastructure*:
  https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf
- FBI/NSA, 2026 router/DNS-DHCP advisory context:
  https://www.ic3.gov/PSA/2026/PSA260407
- NSA, *Improve Router Hygiene*:
  https://media.defense.gov/2026/Jul/09/2003959498/-1/-1/0/CSA_IMPROVE_ROUTER_HYGIENE.PDF
- NIST SP 800-207, *Zero Trust Architecture*:
  https://csrc.nist.gov/pubs/sp/800/207/final
- Microsoft, *OpenSSH Server configuration for Windows*:
  https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration
- Microsoft, *Enable OpenSSH verbose logging*:
  https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/enable-openssh-verbose-logging
- MITRE ATT&CK T1070.001, *Clear Windows Event Logs*:
  https://attack.mitre.org/techniques/T1070/001/
- Microsoft, *The BadPilot campaign*:
  https://www.microsoft.com/en-us/security/blog/2025/02/12/the-badpilot-campaign-seashell-blizzard-subgroup-conducts-multiyear-global-access-operation/

These sources support defensive technique selection. Angerona's control design
is an engineering inference and is not an attribution claim.
