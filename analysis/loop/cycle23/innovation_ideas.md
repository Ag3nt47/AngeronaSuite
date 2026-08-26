# Cycle 23 — State-Grade Defensive Research and Innovation Priorities

Date: 2026-08-26  
Mode: defensive research only; no attribution engine and no offensive procedure library

## Research conclusion

The reliable engineering target is a set of observable tradecraft patterns, not a named agency. Public reporting shows that advanced operators reuse ordinary administrative surfaces—edge routers, SSH, DNS and DHCP changes, tunnels, valid accounts, and telemetry suppression. Those techniques are also available to criminal and insider actors, so Angerona must describe evidence as an advanced or state-grade pattern and leave actor attribution unassessed.

## Primary-source findings translated into controls

1. **Edge-device and SSH persistence.** CISA's 2025 advisory on PRC-linked router compromises describes SSH access, authorized-key changes, tunnels, routing or ACL manipulation, and log clearing. Defensive translation: inventory SSH configuration, key fingerprints, listeners, services, forwarding indicators, and authenticated drift state; never collect private keys or credentials.
2. **Cleared Windows audit evidence.** CISA's Volt Typhoon guidance specifically calls for investigating every Windows Security 1102 clear event. Defensive translation: watch explicit clear and audit-policy/service events while independently anchoring record continuity so clear/refill behavior remains visible even when the canonical clear event is absent.
3. **Router-mediated DNS and DHCP manipulation.** The FBI and NSA's 2026 router advisory describes compromised routing infrastructure used for DNS/DHCP adversary-in-the-middle positioning. Defensive translation: treat Wi-Fi and Ethernet as untrusted by location, tokenize identifiers, and watch DNS, DHCP, route, gateway-identity, connection-profile, and interface-epoch drift.
4. **Zero trust is resource-specific.** NIST SP 800-207 rejects implicit trust based only on network location. Defensive translation: a verified intermediate gateway may attest the path, but it must never grant implicit trust to applications, identities, devices, or destination resources.
5. **Off-host continuity.** Router and host logs can be disabled or erased. Defensive translation: offer a separately enrolled, pinned witness that accepts only bounded continuity metadata (sequence, previous receipt hash, digest, count, and nonce), not raw logs.

## Ranked buildable concepts

| Priority | Concept | Cycle 23 disposition |
|---|---|---|
| 1 | Independent authenticated event-log continuity guard | Built and entering adversarial validation |
| 2 | SSH Surface / Key / Tunnel Guard | Built and entering adversarial validation |
| 3 | Untrusted network-path epoch and drift monitor | Built and entering adversarial validation |
| 4 | Personal Sentinel Gateway pinned attestation client | Built and entering adversarial validation |
| 5 | Privacy-safe continuity witness receipt | Built as optional, explicitly enrolled contract |
| 6 | Redacted live defense activity panel | Built; displays observable event/module activity, never hidden reasoning |
| 7 | Governed ARIA Defense Memory | Built; canonical digest pin, strict schema, data-only retrieval |
| 8 | Multi-sensor tradecraft sequence correlator | Proposed for a later bounded cycle |
| 9 | Asset-role-specific egress policy and lease broker | Proposed; requires operator policy design |
| 10 | Gateway firmware attestor and signed boot measurement | Proposed; requires supported gateway hardware/firmware |
| 11 | Unelevated UI plus narrow privileged capability service | Long-term architecture proposal; too broad for this cycle |

## Sources

- CISA, *People's Republic of China State-Sponsored Cyber Threat Actors Exploit Network Devices to Maintain Persistent Access to U.S. and Global Networks* (AA25-239A): https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a
- CISA, *PRC State-Sponsored Actors Compromise and Maintain Persistent Access to U.S. Critical Infrastructure* (AA24-038A): https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf
- FBI/NSA, *Russian GRU Targeting Western Logistics Entities and Technology Companies* router/DNS-DHCP advisory context (2026): https://www.ic3.gov/PSA/2026/PSA260407
- NSA, *Improve Router Hygiene* (2026): https://media.defense.gov/2026/Jul/09/2003959498/-1/-1/0/CSA_IMPROVE_ROUTER_HYGIENE.PDF
- NIST SP 800-207, *Zero Trust Architecture*: https://csrc.nist.gov/pubs/sp/800/207/final
- Microsoft, *OpenSSH Server configuration for Windows*: https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration
- Microsoft, *Enable OpenSSH verbose logging*: https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/enable-openssh-verbose-logging
- MITRE ATT&CK T1070.001, *Clear Windows Event Logs*: https://attack.mitre.org/techniques/T1070/001/
- Microsoft, *The BadPilot campaign*: https://www.microsoft.com/en-us/security/blog/2025/02/12/the-badpilot-campaign-seashell-blizzard-subgroup-conducts-multiyear-global-access-operation/

## Safety boundary

This research does not include exploit instructions, credential attacks, router compromise procedures, or operational attribution. All implemented components are observe-only, fail closed, minimize identifiers, and emit `response_authorized=false`.
