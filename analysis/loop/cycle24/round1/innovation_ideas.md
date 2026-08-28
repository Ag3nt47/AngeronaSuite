# Cycle 24 Round 1 — Defensive Innovation Roadmap

Date: 2026-08-26

## Decision

Angerona should finish and independently gate the trust-boundary primitives
already added in the Cycle 24 working tree before adding another broad set of
detectors. The next best product work is to connect those primitives to
authoritative evidence and enforcement, then add four high-value Windows
detections that remain absent: user-intent/ClickFix chains, SSH key-to-session
provenance, loaded-DLL provenance, and WSL/Hyper-V boundary visibility.

This is actor-neutral defensive research. Signals describe observable
tradecraft and never prove a state, agency, sponsor, or individual. "Observed"
below means a primary source documents real incidents. "Established class"
means platform/agency guidance recognizes the attack mechanism. "Theoretical
or lab" means Angerona must not present it as production adversary activity
without incident evidence.

This innovation pass changed no product code, public documentation, version,
configuration, or release claim. Statuses describe the concurrent Cycle 24
working tree and are not final validation results.

## Status reconciliation

| Capability in the Cycle 24 working tree | Honest status | Remaining boundary |
|---|---|---|
| Identity/session analytics and `Identity Session Guard` | **Built core/observe-only bridge** | Consumes supplied structured evidence; no browser-token read, cloud API, or native event collector. |
| Driver Provenance Guard | **Built observe-only** | Round 1 found completeness can be falsely reported after bounded selection; enforcement remains out of scope. |
| Temporal Tradecraft Correlator | **Built observe-only** | Ordered SSH/session/tunnel/path/log correlation exists; broker-assigned producer identity is not yet wired. |
| Peripheral and DMA Posture Guard | **Built posture sensor** | Reports OS posture, not device-firmware trust, PiKVM identity, or hardware attestation. |
| Measured-boot parser and Platform Attestation Guard | **Built appraisal contract / prototype collector** | Default collector is OS posture only; a nonce-bound TPM quote provider and verifier must be injected. |
| Process Egress Lease Broker and Guard | **Built policy primitive / observe-only prototype** | Explicitly not a firewall; a separately privileged enforcement adapter is absent. |
| Personal Sentinel authority and HTTPS server | **Prototype** | Round 1 found symmetric verifier/signing authority, rollback/locking, TLS admission-DoS, and trusted-time replay issues. |
| Release authorization/floor, response capabilities, file leases, sensor provenance, recovery assurance, RAG provenance | **Code-backed foundations** | Several are not wired into privileged production paths; Round 1 findings must close before promotion. |

## Ranked roadmap

Ranking uses impact divided by effort weight (S=1, S-M=1.5, M=2, L=3).
Priority reflects security urgency, while the score reflects likely return on
engineering time.

| Rank | Priority | Proposal | Status | Threat evidence | Impact | Effort | Score |
|---:|:---:|---|---|---|---:|:---:|---:|
| 1 | P1 | ATT&CK v19 Detection-Strategy Conformance | Future enabler | Defensive standard | 4 | S-M | 2.67 |
| 2 | P0 | Wire Identity and Interactive-Access Provenance | Built engine; integration prototype | Observed | 5 | M | 2.50 |
| 3 | P0 | User-Intent / ClickFix Chain Guard | Future | Observed at scale | 5 | M | 2.50 |
| 4 | P0 | SSH Session Provenance and Crypto Agility | Future | Observed + theoretical PQ risk | 5 | M | 2.50 |
| 5 | P0 | Loaded-Module Provenance Graph | Future | Observed repeatedly | 5 | M | 2.50 |
| 6 | P1 | First-Hop Link Attestation v2 | Future extension | Established attack classes | 5 | M | 2.50 |
| 7 | P0 | Enforce Process-Bound Egress Leases | Policy prototype | Architectural blind spot | 4 | M | 2.00 |
| 8 | P1 | WSL / Hyper-V Boundary Guard | Future | Documented abuse + visibility gap | 4 | M | 2.00 |
| 9 | P1 | Out-of-Band Peripheral Context | Built posture; behavioral prototype needed | Observed OOB + established DMA class | 4 | M | 2.00 |
| 10 | P0 | Promote Personal Sentinel Witness and Measured Boot | Prototype | Observed tampering/bootkit motivation | 5 | L | 1.67 |
| 11 | P2 | Selective Call-Stack / Executable-Memory Provenance | Future experiment | Observed memory loading; spoofing is lab/research | 4 | L | 1.33 |

The external witness ranks lower by impact/effort only because it requires a
separately administered component. It remains P0 because it is the only item
that can improve evidence freshness after the local Administrator/SYSTEM trust
boundary is lost.

---

## 1. ATT&CK v19 Detection-Strategy Conformance

**Pitch.** Upgrade the heatmap from technique labels to version-pinned proof of
which MITRE Detection Strategies, Analytics, and Data Components Angerona
actually satisfies.

**Why now.** ATT&CK v18 replaced technique detection text with Detection
Strategy and Analytic objects and deprecated Data Sources. The current v19.2
Agile release adds fast-moving identity, token-theft, CI/CD, and user-execution
content. Technique association alone can therefore imply coverage when a
required source or predicate is absent.

Sources:

- [MITRE ATT&CK v18 defensive-model update](https://attack.mitre.org/resources/updates/updates-october-2025/)
- [MITRE ATT&CK current updates](https://attack.mitre.org/resources/updates/)
- [MITRE ATT&CK Detection Strategies](https://attack.mitre.org/detectionstrategies/)

**Fit.** Extend `core/attack_tracker.py`, module metadata, Shark validation,
and the ATT&CK GUI with `technique-associated`, `analytic-partial`,
`analytic-proven`, and `source-unavailable`. Pin an official CTI bundle and its
digest; require fixtures for mandatory predicates and source-loss behavior.
**Detect / Visualize.**

**Effort and constraints.** **S-M.** The main risk is semantic overclaiming,
not runtime false positives. MITRE mutable elements are environment-specific;
the imported content cannot become executable query text or response policy.

**Safety.** Data-only. ATT&CK objects cannot execute code, install content, or
authorize an action.

---

## 2. Wire Identity and Interactive-Access Provenance

**Pitch.** Connect the built privacy-tokenized identity engine to authoritative
local session/RMM events and optional bounded Entra exports so a user, device,
token, remote helper, and endpoint behavior must tell one consistent story.

**Threat status.** **Observed.** Microsoft documented Quick Assist misuse
leading to ransomware and suspected state-interest device-code phishing that
obtained tokens, registered a device, and acquired a Primary Refresh Token.

Sources:

- [Microsoft: Storm-2372 device-code phishing](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)
- [Microsoft: Quick Assist abuse leading to ransomware](https://www.microsoft.com/en-us/security/blog/2024/05/15/threat-actors-misusing-quick-assist-in-social-engineering-attacks-leading-to-ransomware/)
- [CISA communications-infrastructure hardening guidance](https://www.cisa.gov/resources-tools/resources/enhanced-visibility-and-hardening-guidance-communications-infrastructure)

**Fit.** Keep `core/identity_session.py` and `modules/identity_session_guard.py`
as the bounded analytic sink. Add fixed-schema collectors for Windows logon
session creation/end, privilege changes, approved RMM/Quick Assist lifecycle,
and browser-token-store access telemetry when the OS exposes it. Start cloud
coverage with explicit offline Entra sign-in/audit JSON; a future connector is
read-only, opt-in, bounded, and egress-consented. Correlate device-code flow,
new device/PRT evidence, session-ID continuity with user-agent/device change,
and endpoint execution. **Detect / Respond / Visualize.**

**Effort and false positives.** **M** for local/offline integration; **L** for a
production tenant connector. Helpdesk work, travel, VPN egress, browser updates,
and shared support devices are legitimate. Geolocation is context, not
identity. No cloud conclusion is valid when cloud logs are absent.

**Safety.** No credential/token collection, phishing simulation, remote-control
initiation, account takeover, or broad tenant mutation. Local response remains
an exact, separately authorized Combat action.

---

## 3. User-Intent / ClickFix Chain Guard

**Pitch.** Detect the transition from a browser/social lure to a user-launched
command and then to LOLBin download, memory load, persistence, or beaconing
without recording clipboard text, window content, or keystrokes.

**Threat status.** **Observed at scale.** Microsoft reported campaigns affecting
thousands of devices daily, used by criminals and nation-state actors, with a
2026 CrashFix variant adding browser disruption and a portable Python RAT.

Sources:

- [Microsoft: Think before you Click(Fix)](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/)
- [Microsoft Digital Defense Report 2025](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/bade/documents/products-and-services/en-us/security/Microsoft-Digital-Defense-Report-2025.pdf)
- [Microsoft: CrashFix Python RAT](https://www.microsoft.com/en-us/security/blog/2026/02/05/clickfix-variant-crashfix-deploying-python-rat-trojan/)

**Fit.** Add a BaseModule over existing process lineage, Sysmon/ETW, AMSI,
network, file, and scheduled-task evidence. Score an ordered chain: interactive
Explorer/terminal start; high-risk PowerShell/`mshta`/`rundll32`/`msbuild`/
`regasm`/renamed tool; remote retrieval or obfuscation; user-writable staging or
memory load; then persistence/beacon. Require multiple independent stages for
HIGH. Existing Combat may offer exact-process suspension only after fresh
revalidation. **Detect / Respond / Harden.**

**Effort and false positives.** **M.** Administrators, developers, installers,
and support scripts legitimately use these binaries. Process names alone cannot
exceed MEDIUM. Foreground/clipboard timing is optional metadata only; missing
intent telemetry remains `unknown`.

**Safety.** No clipboard capture, lure generation, payload execution, browser
injection, credential collection, or offensive simulation.

---

## 4. SSH Session Provenance and Crypto Agility

**Pitch.** Bind each admitted SSH session to authentication evidence,
authorized-key/certificate identity, process birth, listener, source token, and
forwarding behavior while reporting cryptographic downgrade and hybrid
post-quantum readiness.

**Threat status.** SSH key/tunnel persistence is **observed**. Microsoft
documented actors deploying OpenSSH keys and Tor hidden services for RDP/SSH
forwarding. Quantum decryption is **theoretical/future**; lack of hybrid PQ KEX
is posture, not compromise.

Sources:

- [Microsoft BadPilot / ShadowLink](https://www.microsoft.com/en-us/security/blog/2025/02/12/the-badpilot-campaign-seashell-blizzard-subgroup-conducts-multiyear-global-access-operation/)
- [OpenSSH Post-Quantum Cryptography](https://www.openssh.org/pq.html)
- [NIST FIPS 203 ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)

**Fit.** Extend the Cycle 23 SSH guard and new Temporal Correlator with fixed
OpenSSH event fields: session ID, SID/account token, source, listener,
authentication method, CA/principal, and key fingerprint when emitted. Join to
the exact `sshd` process/child and normalized forwarding. Emit
`unbound-session` instead of guessing. Parse installed-version and effective
KEX/cipher/MAC/host-key posture without connecting to a listener. **Detect /
Harden / Visualize.**

**Effort and false positives.** **M.** Fingerprints depend on OpenSSH version
and logging level; Angerona must not silently enable verbose logging. Bastions,
certificates, connection multiplexing, and authorized tunnels need explicit
policy. Windows OpenSSH cannot be assumed to match upstream algorithm support.

**Safety.** No private keys, credentials, login attempt, listener probe, tunnel
creation, config mutation, or key deletion.

---

## 5. Loaded-Module Provenance Graph

**Pitch.** Detect trusted executables loading unexpected DLLs from writable or
non-vendor paths by joining load-time signer, hash, custody, process identity,
installation provenance, and follow-on behavior.

**Threat status.** **Observed repeatedly.** Microsoft documented human-operated
intrusions staging DLLs in `ProgramData` and side-loading them through trusted
signed applications.

Sources:

- [Microsoft 2026 human-operated intrusion playbook](https://www.microsoft.com/en-us/security/blog/2026/04/18/crosstenant-helpdesk-impersonation-data-exfiltration-human-operated-intrusion-playbook/)
- [MITRE ATT&CK DLL hijacking/side-loading](https://attack.mitre.org/techniques/T1574/002/)
- [Microsoft DLL security guidance](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-security)

**Fit.** Add a BaseModule over fixed Sysmon Image Load, ETW ImageLoad where
supported, and Code Integrity sources. Key graph nodes by process-creation and
file identity; add signer, SHA-256 on admitted new/suspicious files, writable/
reparse custody, first-seen time, expected vendor root, and recent drop/network/
registry/persistence evidence. Keep the new Driver Provenance Guard separate:
kernel driver identity and user-mode DLL load provenance are different trust
problems. **Detect / Harden.**

**Effort and false positives.** **M.** Image-load volume is high. Cache by
stable file identity and retain only suspicious edges. Browsers, plugins,
updaters, accessibility/security tools, and portable apps legitimately mix
publishers; mismatch alone cannot authorize response.

**Safety.** Observe/audit only. Never plant, load, unload, or delete a DLL.

---

## 6. First-Hop Link Attestation v2

**Pitch.** Extend post-roam BSSID and IP path monitoring into a bounded Wi-Fi
management-plane and IPv6 first-hop identity with explicit mesh enrollment and
downgrade evidence.

**Threat status.** Evil twins, forged deauthentication, rogue IPv6 Router
Advertisements/DHCPv6, and neighbor spoofing are **established attack classes**;
these signals do not establish actor attribution.

Sources:

- [CISA Guide to Securing Networks for Wi-Fi](https://www.cisa.gov/sites/default/files/publications/A_Guide_to_Securing_Networks_for_Wi-Fi.pdf)
- [NSA WPA3 and Protected Management Frames](https://www.nsa.gov/portals/75/documents/what-we-do/cybersecurity/professional-resources/ctr-cybersecurity-technical-report-wpa3.pdf)
- [CISA IPv6 Considerations for TIC 3.0](https://www.cisa.gov/sites/default/files/publications/CISA%20IPv6%20Considerations%20for%20TIC%203.0.pdf)
- [Microsoft Native Wi-Fi API](https://learn.microsoft.com/en-us/windows/win32/api/_nwifi/)

**Fit.** Add privacy-tokenized visible-BSS/AP-group, auth/cipher, profile DACL,
PMF when exposed, RA router, prefix/options, DHCPv6 server, and neighbor/gateway
generation to Network Trust. Use Native Wi-Fi with explicit location consent;
retain `netsh` as degraded fallback. New BSSIDs never self-enroll; known mesh
groups require signed operator admission. **Detect / Harden / Visualize.**

**Effort and false positives.** **M.** Mesh roaming, extender/AP replacement,
firmware changes, prefix rotation, captive portals, and driver-limited PMF
visibility create drift. Require multiple changed fields. Passive evidence
cannot prove AP firmware or RF transmitter identity.

**Safety.** No wireless injection, deauthentication, handshake capture,
password test, rogue AP, or neighbor poisoning.

---

## 7. Enforce Process-Bound Egress Leases

**Pitch.** Connect the built lease broker to a privileged network adapter so
outbound permission is short-lived and bound to exact process birth,
executable-file identity, destination, purpose, gateway state, and DNS receipt.

**Threat status.** Architectural defense-in-depth gap. Encrypted DNS and ECH
are legitimate protections, but make plaintext DNS/SNI an unreliable policy
source; application-owned resolvers and direct-IP egress can bypass naive
domain allowlists.

Sources:

- [Microsoft Windows Zero Trust DNS](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/zero-trust-dns/)
- [NIST SP 800-81 Rev. 3](https://csrc.nist.gov/pubs/sp/800/81/r3/final)
- [IETF RFC 9849 TLS Encrypted Client Hello](https://datatracker.ietf.org/doc/rfc9849/)

**Fit.** Preserve `core/process_egress_lease.py` as policy and
`modules/process_egress_guard.py` as audit. Implement enforcement only in the
separately privileged service, with a retained OS process handle and bounded
executable-file lease. Bind trusted encrypted-DNS receipt, literal returned IP,
TTL, protocol, route/gateway generation, byte/connection budget, and exact
Undo. Native ZTDNS hardening remains edition-gated; all editions receive an
observe-only compatibility plan first. **Respond / Harden / Visualize.**

**Effort and false positives.** **M.** CDNs, short TTLs, VPNs, split DNS, QUIC,
captive portals, and processes with their own resolver complicate binding.
Native ZTDNS is not universally licensed. Audit before enforcement and retain
exact-peer containment as the portable fallback.

**Safety.** No DNS poisoning, TLS interception, certificate insertion, packet
injection, or broad permanent firewall rule.

---

## 8. WSL / Hyper-V Boundary Guard

**Pitch.** Treat WSL distributions, custom kernels, Windows/Linux interop,
mirrored networking, Hyper-V firewall, listeners, and cross-boundary processes
as first-class security assets.

**Threat status.** WSL indirect execution is documented by MITRE and Microsoft
documents real WSL telemetry gaps. A universal Angerona bypass claim remains
**unproven until tested**.

Sources:

- [Microsoft Defender for Endpoint plug-in for WSL](https://learn.microsoft.com/en-us/defender-endpoint/mde-plugin-wsl)
- [Microsoft WSL networking](https://learn.microsoft.com/en-us/windows/wsl/networking)
- [MITRE ATT&CK T1202 Indirect Command Execution](https://attack.mitre.org/techniques/T1202/)

**Fit.** Add a Windows BaseModule that uses fixed commands/APIs to inventory
WSL1/2, distro identity, custom kernel/interop/mount settings, NAT/mirrored mode,
DNS tunneling, proxy, Hyper-V firewall, vNICs/routes, localhost forwarding, and
listeners. Correlate `wsl.exe`/`wslhost.exe`/`vmmem`, `\\wsl$` writes, Windows
executables invoked from Linux, and external flows. An optional future signed
sidecar may emit bounded exec/connect events but accepts no commands. **Detect /
Harden / Visualize.**

**Effort and false positives.** **M** for Windows-side posture; **L** for a
reviewed sidecar. Developer systems legitimately run compilers, SSH, Docker,
and localhost services. A custom kernel is a coverage warning, not compromise.
WSL absence is a clean supported state.

**Safety.** No arbitrary WSL shell, exploit, container escape, persistence,
remote scan, or unsigned privileged component.

---

## 9. Out-of-Band Peripheral Context

**Pitch.** Extend the built DMA/control posture into device-arrival and session
context for HID/composite, USB NIC, KVM-like, Thunderbolt/USB4, and locked-host
events.

**Threat status.** **Observed** for PiKVM out-of-band access in Microsoft
incident response. Drive-by DMA is an **established physical attack class**;
Angerona-specific exploitation is not claimed.

Sources:

- [Microsoft: PiKVM access bypassing traditional EDR](https://www.microsoft.com/en-us/security/blog/2025/12/11/imposter-for-hire-how-fake-people-can-gain-very-real-access/)
- [Microsoft Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)

**Fit.** Keep `Peripheral and DMA Posture Guard` as the posture source. Add
bounded PnP arrival/removal evidence for HID, display, composite, USB NIC,
Thunderbolt/USB4, and PCIe hot-plug. Tokenize IDs and correlate new HID + USB
NIC/composite pairing, locked/unattended state, monitor change, new local peer,
and remote session. Never retain input contents. **Detect / Harden.**

**Effort and false positives.** **M.** Docks, accessibility devices, keyboards
with hubs, displays, and legitimate KVMs are common. Require enrollment and
multi-signal context. HDMI-only taps, separate-network KVMs, pre-OS DMA, and
malicious firmware perfectly impersonating enrolled hardware may remain
invisible.

**Safety.** No USB emulation, keystroke capture, DMA attempt, firmware
modification, or physical attack simulation.

---

## 10. Promote Personal Sentinel Witness and Measured Boot

**Pitch.** Remediate and independently gate the new authority/server, then use
it as the external monotonic witness and verifier for compact host checkpoints
and nonce-bound TPM measured-boot claims.

**Threat status.** Trust-boundary upgrade motivated by **observed** log
suppression, state rollback, defense impairment, and bootkits. A successful TPM
appraisal is not proof that the endpoint is safe.

Sources:

- [CISA AA25-239A immutable/off-host logging guidance](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [Microsoft Windows measured boot and health attestation](https://learn.microsoft.com/en-us/windows/security/operating-system-security/system-security/protect-high-value-assets-by-controlling-the-health-of-windows-10-based-devices)
- [IETF RFC 9334 RATS architecture](https://datatracker.ietf.org/doc/html/rfc9334)
- [Microsoft 2026 Secure Boot certificate transition](https://support.microsoft.com/en-US/servicing/os/secure-boot/2025/06/windows-secure-boot-certificate-expiration-and-ca-updates)
- [Microsoft BlackLotus mitigation guidance](https://support.microsoft.com/en-US/servicing/os/windows/2023/03/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023)

**Fit.** Close Round 1's symmetric signing/verifier, valid-snapshot rollback,
cross-process lock/fork, pre-semaphore TLS handshake, and trusted-time
challenge/sequence findings before promotion. Prefer asymmetric verifier
receipts with separately held signing authority. Bind per-install/domain CAS,
sequence, compact audit/network/platform/Combat digest, build/policy digest,
challenge, and signed receipt. Inject a real TPM quote collector and verifier
into the measured-boot contract; appraise PCR/TCG log plus Secure Boot,
BitLocker/HVCI/ELAM, KEK/DB/DBX state. **Detect / Harden / Visualize.**

**Effort and false positives.** **L.** Requires separate administration,
enrollment/recovery, verifier key custody, TPM/firmware matrices, reference
values, and update-aware PCR policy. BIOS/Windows updates legitimately change
measurements. Network blocking proves silence, not cause. Host+witness
compromise, verifier-key theft, malicious lower firmware, or poisoned reference
policy remain outside the guarantee.

**Safety.** No firmware flash, router administration, remote command channel,
automatic bricking, or claim that attestation grants endpoint/network trust.

---

## 11. Selective Call-Stack / Executable-Memory Provenance

**Pitch.** Prototype narrowly scoped stack and memory-region provenance around
corroborated high-risk events to find calls from unbacked executable memory or
unexpected runtimes without blanket hooks or continuous scanning.

**Threat status.** Reflective/in-memory loading is **observed**. Call-stack
spoofing and gadget-based bypass are **research/lab risks** here unless an
incident supplies stronger evidence.

Sources:

- [MITRE ATT&CK Reflective Code Loading](https://attack.mitre.org/techniques/T1620/)
- [Elastic Security Labs call-stack modality research](https://www.elastic.co/security-labs/misbehaving-modalities)
- [Microsoft ETW stack walking](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/xperf/stack-walking)

**Fit.** Enable stack walking only for reviewed kernel events/processes during
a bounded sampling window after other evidence. Resolve frames against a cached
module map and classify backed image, JIT runtime, private executable,
unreadable, or stale. Require unbacked/broken provenance plus sensitive behavior
and process/network/file corroboration. Expose sampling, event loss, resolution
failure, and CPU cost. **Detect / Visualize.**

**Effort and false positives.** **L.** Provider support, WOW64, symbols, JIT,
and protected processes are difficult. Browsers, .NET, Java, Python, profilers,
accessibility, anti-cheat, and security tools legitimately produce unusual
stacks. Ship only after soak tests prove bounded overhead and better precision
than existing injection/AMSI/Sysmon evidence. Do not claim ETW-TI or kernel
callback integrity from elevated user mode.

**Safety.** No injection, memory write, shellcode, stack manipulation, EDR
evasion implementation, unsigned driver, or offensive proof of concept.

## Recommended delivery order

1. Close the Cycle 24 Round 1 red-team findings and finish authoritative source
   wiring for driver completeness, sensor provenance, capability replay,
   release authorization, recovery revision binding, Sentinel CAS/time/TLS, and
   privileged-service custody.
2. Add ATT&CK v19 conformance so every later feature has a truthful source and
   analytic acceptance contract.
3. Wire Identity Session Guard and Process Egress enforcement; keep both
   observe/audit-only until realistic false-positive and compatibility data is
   available.
4. Implement ClickFix, SSH session provenance, and loaded-module provenance as
   the next detector batch.
5. Add First-Hop v2, WSL boundary visibility, and peripheral arrival context.
6. Promote Personal Sentinel/measured boot only as a separately administered
   release project. Keep call-stack provenance experimental.

## Cross-cutting gates

- Every conclusion reports source completeness, loss, freshness, platform,
  privilege, and version; `unknown` never becomes healthy.
- Positive and negative controls include ordinary developer/admin, helpdesk,
  plugin, mesh Wi-Fi, VPN/CDN, dock/KVM, and WSL workloads.
- Sensors have bounded queues, caches, cardinality, byte limits, cadence, and
  explicit overflow counters.
- High-impact response still requires fresh multi-source evidence, exact target
  identity, signed authority, verified postcondition, and Undo.
- Raw tokens, credentials, private keys, clipboard/keystroke content, SSIDs/
  BSSIDs, memory contents, and private identity records never enter public
  events or ARIA prompts.
- Theoretical/lab risks are labeled as such in findings and the GUI.

## Explicit non-goals

- No exploit, payload, credential theft, evasion implementation, remote scan,
  persistence, attack infrastructure, hack-back, or weaponized simulation.
- No SSH login/probe, Wi-Fi injection, DLL planting, token acquisition, DMA
  attempt, firmware mutation, or stack-spoof proof of concept.
- No unsigned kernel component or claim of tamper-proof user-mode telemetry
  against Administrator/SYSTEM or kernel compromise.
- No state/agency attribution and no claim of complete security.
