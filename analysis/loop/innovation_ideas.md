# Innovation Ideas — Round 1 (2026-07-14)

Cutting-edge, DEFENSIVE-ONLY proposals for Angerona, grounded in current
(≈last 12–18 months) EDR/NDR/SOAR research. Each is concretely buildable in the
existing `src/angerona/` codebase (drop-in `BaseModule`, `core/`, `engines/`, or
`gui/`) and cites at least one real source. Nothing here weaponizes anything —
every item detects, hardens, or visualizes.

Verified against current code so nothing duplicates what already ships: there is
**no** RunMRU/ClickFix detector, **no** browser-credential-store guard, **no**
JA4/TLS-fingerprint, **no** ETW-TI consumer, **no** OCSF export, and **no**
thread-callstack walker (grep of `src/angerona` for `RunMRU|clipboard|ClickFix|
JA4|Threat-Intelligence` found only unrelated GUI clipboard-copy code).

Ranked by **impact ÷ effort** (best first). See the shortlist at the bottom.

---

## 1. ClickFix / RunMRU clipboard-execution detector — TOP PICK
**Pitch:** Catch the #1 2025-26 initial-access chain: a fake-CAPTCHA page seeds a
LOLBIN command into the clipboard and lures the user to paste it into Run/PowerShell.

- **Why now:** Huntress' 2026 report attributes **53% of all malware-loader
  activity in 2025** to ClickFix; ESET saw a **517% increase** H1-2025 vs H2-2024.
  The strongest forensic signal is `HKCU\...\Explorer\RunMRU` writes followed by a
  `powershell/mshta/rundll32/wscript/curl` spawn with network egress within ~5s.
  (Microsoft Security Blog, "Think before you Click(Fix)", 2025-08-21,
  https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/
  ; Sekoia "ClickFix tactic: Revenge of detection",
  https://blog.sekoia.io/clickfix-tactic-revenge-of-detection/ )
- **Fit:** New drop-in module `modules/clickfix_detector.py` (**BaseModule**,
  **Detect**). Poll `RunMRU` via `winreg` (the pattern `persistence_sweep.py`
  already uses) and correlate against ETWG/ETWR 4688 process-creation events already
  on the EventBus; join on a 5s window + LOLBIN allowlist. Maps the new ATT&CK
  sub-technique **T1204.004 (Malicious Copy and Paste)** — feeds `attack_tracker`.
- **Effort:** **S.** Stdlib only (`winreg`, existing bus). Limit: RunMRU only fires
  for the Run dialog path; add a lightweight clipboard-content heuristic (optional
  `pywin32` `OpenClipboard`) to also catch paste-into-terminal.
- **Safety:** Read-only registry + bus correlation; alerts only. Containment left to
  the existing operator-gated SOAR.

## 2. Indirect prompt-injection tripwire for Angerona's own AI-in-the-loop
**Pitch:** Angerona pipes untrusted text (CVE descriptions, alert details, file
strings, web-fetched intel) into local Ollama for triage and *fix* advice — harden
that boundary so injected instructions can't steer a remediation.

- **Why now:** Prompt injection is **OWASP LLM01 (the #1 LLM risk for 2025 and
  2026)**; indirect injection hides payloads in documents/records the model reads and
  is the dominant risk once an LLM can invoke tools/apply changes. Angerona's CVE fix
  advisor and posture-hardening already turn AI output into (gated) PowerShell.
  (OWASP Top 10 for LLM Apps 2025, https://owasp.org/www-community/attacks/PromptInjection
  ; Microsoft MSRC "How Microsoft defends against indirect prompt injection", 2025-07,
  https://www.microsoft.com/en-us/msrc/blog/2025/07/how-microsoft-defends-against-indirect-prompt-injection-attacks
  ; IPIGuard tool-dependency-graph defense, https://arxiv.org/pdf/2508.15310 )
- **Fit:** Enhance `engines/ai_guardrail.py` + `modules/counter_agentic.py`
  (**engine + BaseModule**, **Harden**). Builds directly on the existing
  `neutralize_telemetry()` and A-03 destructive-denylist: add (a) an injected-
  instruction classifier over all model *inputs* (imperative-verb / "ignore previous"
  / zero-width-Unicode / role-switch heuristics), (b) a tool-invocation provenance
  gate so AI output derived from injected content cannot reach `apply_fix()` /
  `execute_remediation()` without a fresh operator confirm, and (c) a canary
  instruction ("if you can read this, output TOKEN") to flag context bleed.
- **Effort:** **M.** Pure-Python logic; no new deps. Extends tested guardrail code.
- **Safety:** Purely defensive — narrows what the AI can be tricked into doing.

## 3. Infostealer / browser-credential-store access guard
**Pitch:** Detect the 2025 infostealer boom — processes reading Chromium/Firefox
`Login Data`, cookies, `Local State`, or injecting into `chrome.exe` to defeat
App-Bound Encryption.

- **Why now:** Infostealers were the top 2025 credential-theft vector (66% EDR-bypass
  rate); an Oct-2025 C implementation injects into `chrome.exe` to call decryption
  APIs from trusted context and beat App-Bound Encryption. Best signals: handle/read
  on browser SQLite stores and DPAPI `CryptUnprotectData` from a non-browser process.
  (DeepStrike "Infostealer Malware in 2025",
  https://deepstrike.io/blog/infostealer-malware-credential-theft-2025 ; Detection
  Chokepoints "Browser Credential Theft",
  https://iimp0ster.github.io/detection-chokepoints/chokepoints/browser-credential-theft/ )
- **Fit:** New `modules/infostealer_guard.py` (**BaseModule**, **Detect**). Consume
  Sysmon **EID 10 (ProcessAccess)** and file events already bridged by
  `sysmon_listener.py`; flag non-browser opens of `\User Data\*\Login Data`,
  `\Network\Cookies`, `Local State`, and cross-process access into `chrome.exe`.
  Maps **T1555.003 / T1539 / T1552**. CRITICAL emit → existing SOAR can contain.
- **Effort:** **M.** Reuses the Sysmon bridge + `process_monitor`. Limit: needs
  Sysmon config with EID 10; degrade to psutil `open_files()` polling if absent.
- **Safety:** Read-only telemetry consumption; never touches browser data itself.

## 4. BYOVD behavioral EDR-kill / driver-tamper detector
**Pitch:** Flag the ransomware-favorite kill chain — a signed-but-vulnerable driver
loading, then a security process being handle-stripped or terminated.

- **Why now:** March-2026 reporting found **54 EDR-killers abusing 35 signed
  vulnerable drivers**; Feb-2026 Reynolds ransomware embedded a vulnerable driver
  *inside* the payload. Symantec/Carbon Black now detect the *behavior* (anomalous
  IOCTL asking to terminate a security product, handle stripping, callback removal) —
  driver-agnostic. (The Hacker News, "54 EDR Killers Use BYOVD…", 2026-03,
  https://thehackernews.com/2026/03/54-edr-killers-use-byovd-to-exploit-34.html ;
  Security.com "The BYOVD Epidemic",
  https://www.security.com/threat-intelligence/byovd-vulnerable-drivers )
- **Fit:** New `modules/byovd_guard.py` (**BaseModule**, **Detect**), leveraging the
  existing `intel_sync.is_known_bad_driver()` blocklist and `file_integrity` driver
  watch. Correlate Sysmon **EID 6 (DriverLoad)** / new kernel-service creation with a
  subsequent security-process (self, Defender, other AV) death or handle-open. Maps
  **T1562.001 / T1068 / T1211**. High-confidence CRITICAL when both fire in-window.
- **Effort:** **M.** Sysmon EID 6 + service enumeration (`persistence_sweep` pattern).
  Limit: user-mode can't *prevent* a kernel driver load — detect + alert + isolate
  only. Optional: escalate to signed `AngeronaSensor.sys` callback if present.
- **Safety:** Detection/alert only; no driver loading or kernel writes.

## 5. OCSF-normalized event export (SIEM/AI interoperability)
**Pitch:** Emit Angerona alerts in Open Cybersecurity Schema Framework JSON so they
drop straight into modern data lakes and AI-driven analytics.

- **Why now:** OCSF joined the Linux Foundation (Nov-2024), reached **v1.8.0 (Mar-2026)**,
  and v1.5/1.6 added first-class **ATT&CK + D3FEND** mapping; write detection logic
  once, run it across backends. It's becoming the AI-ready SOC lingua franca.
  (AWS Open Source Blog, "Powering AI-Driven Security with OCSF",
  https://aws.amazon.com/blogs/opensource/powering-ai-driven-security-with-the-open-cybersecurity-schema-framework/
  ; https://ocsf.io/ )
- **Fit:** Enhance `modules/siem_forwarder.py` + reuse `compliance_mapper.py`
  (**BaseModule**, **Visualize/interop**). Add an `ocsf` output format alongside CEF:
  map Angerona events to OCSF `Detection Finding` / `Process Activity` classes with
  the ATT&CK TID the `attack_tracker` already carries. Opt-in, idle until configured
  (same pattern as the existing `ANGERONA_SIEM_HOST` gate).
- **Effort:** **S–M.** Pure JSON mapping, stdlib. No egress unless configured.
- **Safety:** Local serialization; existing opt-in/no-default-IP guarantees hold.

## 6. D3FEND countermeasure overlay on the ATT&CK heatmap
**Pitch:** Show not just what attackers *do* (ATT&CK) but what Angerona *does back*
(MITRE D3FEND), turning the coverage view into a defensive-technique scorecard.

- **Why now:** OCSF 1.6 and the wider tooling ecosystem now map detections to
  **D3FEND** alongside ATT&CK; defenders increasingly want a countermeasure-centric
  view of their own stack. (AWS Open Source Blog on OCSF ATT&CK/D3FEND support,
  https://aws.amazon.com/blogs/opensource/ocsf-achieves-itu-support-powering-ai-ready-security-operations/ )
- **Fit:** Enhance `core/attack_coverage.py` + `gui/attack_heatmap.py` Coverage tab
  (**core + GUI**, **Visualize**). Add a curated ATT&CK→D3FEND map keyed to the
  existing vetted-action allow-list, and a "Defenses" column/tab linking to D3FEND
  pages (same anchor-routing the heatmap already uses for MITRE links).
- **Effort:** **S.** Static map + one GUI column. No new deps.
- **Safety:** Pure visualization of existing capability.

## 7. Callstack / unbacked-memory execution detection (transparent in-memory hunt)
**Pitch:** Find beacons and injected shellcode by walking thread stacks for return
addresses that don't map to any loaded module — the classic Cobalt Strike tell.

- **Why now:** With Elastic 8.11+, **kernel-ETW call-stack detections** became the
  most robust visibility into in-memory threats; return addresses in private/RWX
  (unbacked) memory reliably surface injected execution. Full ETW-TI requires
  PPL-Antimalware (see #10) — this is the user-mode-buildable cousin.
  (Elastic Security Labs, "Doubling Down: Detecting In-Memory Threats with Kernel
  ETW Call Stacks", https://www.elastic.co/security-labs/doubling-down-etw-callstacks )
- **Fit:** Enhance `modules/mem_inject_scanner.py` (**BaseModule**, **Detect**),
  which already does a VirtualQueryEx RWX scan. Add periodic `StackWalk64` /
  `RtlVirtualUnwind` (ctypes) on suspicious threads; flag frames whose return address
  falls in unbacked/private memory. Maps **T1055 / T1620 (Reflective Loading)**.
- **Effort:** **L.** ctypes stack-walking is fiddly and per-arch; throttle heavily and
  reuse the existing JIT allowlist + 60s dedup to bound cost. No admin driver needed.
- **Safety:** Read-only inspection of the process's own thread state; alert only.

## 8. JA4 / JA4+ passive TLS-client fingerprinting for C2 detection
**Pitch:** Fingerprint the TLS ClientHello of outbound connections (JA4) and match
against known implant signatures (Cobalt Strike, Sliver, Havoc) — no decryption.

- **Why now:** JA4/JA4+ is the 2024-25 successor to JA3, resistant to browser
  randomization, and adopted by Cloudflare/AWS/VirusTotal; specific JA4 hashes flag
  common C2 frameworks in encrypted traffic where DPI is infeasible.
  (FoxIO "JA4+ Network Fingerprinting", https://blog.foxio.io/ja4+-network-fingerprinting
  ; Team Cymru "A Primer on JA4",
  https://www.team-cymru.com/post/a-primer-on-ja4-empowering-threat-analysts-with-better-traffic-analysis )
- **Fit:** Enhance `modules/packet_sniffer.py` / `network_protocol_decoder.py`
  (**BaseModule**, **Detect** — NDR). Parse the ClientHello from captured packets,
  compute the JA4 string, and match a shipped known-bad set; complements
  `beacon_detector.py`'s cadence analysis. Maps **T1071.001 / T1573**.
- **Effort:** **M.** Needs ClientHello parsing on the capture path (scapy already an
  optional dep in `arp_watchdog`); ship a small curated JA4 blocklist, updatable via
  the existing `ANGERONA_IOC_FEED` mechanism. Limit: needs raw-packet capture.
- **Safety:** Passive observation of handshake metadata; no decryption, alert only.

## 9. Sticky-canary ransomware trap with entropy-rate confirmation
**Pitch:** Upgrade deception to Elastic-style "sticky" canaries that confirm
encryption in ~12s and, where possible, capture ransomware artifacts for IR.

- **Why now:** Canary files give **~12-second** detection of active encryption —
  faster than signature/behavioral methods — and combining a canary touch with an
  entropy-*rate* threshold (post-encryption confirmation) sharply cuts false positives.
  (Elastic Security Labs, "Ransomware in the honeypot: sticky canary files",
  https://www.elastic.co/security-labs/ransomware-in-the-honeypot-how-we-capture-keys
  ; MDPI dual-stage AIS + honeyfile framework, https://www.mdpi.com/2079-9292/15/10/2223 )
- **Fit:** Enhance `modules/deception.py` / `smart_deception.py` +
  `ransomware_heuristics.py` (**BaseModule**, **Detect/Respond**). Seed hidden
  canaries across user dirs; on canary write, immediately corroborate with the
  existing Shannon-entropy engine's *rate of rise* and trigger SOAR containment —
  a 2-signal, low-FP CRITICAL. Maps **T1486 / T1490**.
- **Effort:** **M.** Reuses honeytoken hygiene (`HIDDEN|SYSTEM`) and the entropy path;
  add a filesystem watch (`ReadDirectoryChangesW` via pywin32) on canary paths.
- **Safety:** Decoys + read-only entropy; containment stays operator-gated SOAR.

## 10. ETW-TI (Threat-Intelligence provider) sensor + tamper watch — HIGH VALUE, GATED
**Pitch:** Consume `Microsoft-Windows-Threat-Intelligence` for kernel-truth telemetry
on memory alloc, remote-thread, and APC — the events that user-mode ntdll patching
can't hide.

- **Why now:** ETW-TI is emitted by the kernel *after* the operation, immune to
  `ntdll!EtwEventWrite` patching, and is the backbone of modern in-memory detection.
  (Praetorian, "ETW Threat Intelligence and Hardware Breakpoints",
  https://www.praetorian.com/blog/etw-threat-intelligence-and-hardware-breakpoints/
  ; fluxsec, "Leveraging ETW Threat Intelligence for EDR",
  https://fluxsec.red/event-tracing-for-windows-threat-intelligence-rust-consumer )
- **Fit:** New `modules/etw_ti_sensor.py` (**BaseModule**, **Detect**), sibling to
  `etw_realtime_sensor.py`. **Hard limitation, stated honestly:** subscribing to the
  ETW-TI provider requires the consumer to run as **PsProtectedSignerAntimalware
  (PPL)**, which needs an Early-Launch Antimalware / Microsoft-signed cert Angerona
  does not have and cannot self-issue. So the *buildable* deliverable today is the
  defensive complement: **detect tampering with / disabling of the ETW-TI provider**
  (session-stop, provider-disable, `EtwEventWrite` hook — the `api_patch_detector`
  and `canary_drill` telemetry-blinding logic already do adjacent work), and keep the
  full consumer behind the documented signed-driver / PPL seam for a future ELAM build.
- **Effort:** **L (consumer blocked without PPL; tamper-watch is M).** No workaround
  attempted for the PPL gate — noted as a limitation per the rules.
- **Safety:** Read-only telemetry; tamper-watch alerts only.

---

## Ranked shortlist (impact ÷ effort)

| # | Title | Effort | Fit (one line) |
|---|---|---|---|
| 1 | ClickFix / RunMRU clipboard-execution detector | **S** | New `clickfix_detector` module; RunMRU+LOLBIN correlation (T1204.004) |
| 2 | Indirect prompt-injection tripwire for AI-in-loop | **M** | Harden `ai_guardrail`/`counter_agentic`; gate AI-driven remediations |
| 3 | Infostealer / browser-credential-store guard | **M** | New `infostealer_guard`; Sysmon EID10 on browser stores (T1555.003) |
| 4 | BYOVD behavioral EDR-kill detector | **M** | New `byovd_guard`; driver-load + security-proc-kill correlation (T1562.001) |
| 5 | OCSF-normalized event export | **S–M** | Enhance `siem_forwarder`; OCSF findings w/ ATT&CK mapping |
| 6 | D3FEND countermeasure overlay | **S** | Enhance `attack_coverage`+heatmap GUI; defense scorecard |
| 7 | Callstack / unbacked-memory execution detection | **L** | Enhance `mem_inject_scanner`; stackwalk for unbacked returns (T1055) |
| 8 | JA4/JA4+ TLS-client fingerprinting | **M** | Enhance `packet_sniffer`/NDRD; C2 fingerprint match (T1071.001) |
| 9 | Sticky-canary ransomware trap + entropy-rate | **M** | Enhance `deception`/`ransomware_heuristics`; 2-signal ~12s detect (T1486) |
| 10 | ETW-TI sensor + tamper watch | **L** (gated) | New `etw_ti_sensor`; consumer needs PPL (noted), tamper-watch buildable |
