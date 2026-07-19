# Innovation Ideas - Round 1 (2026-07-19)

This brief is defensive-only and ranked by expected **impact divided by effort**.
It was checked against the current Angerona tree before proposing work. Angerona
already has behavioral baselining, exact-path trusted processes, deterministic
drill-resolution records, telemetry expectation contracts, ARIA voice I/O,
confirm-before-write assistant actions, OCSF/D3FEND foundations, and a release ZIP.
The proposals below extend those foundations rather than relabeling work that
already exists.

The most important current-state observation is that
`PostureHardening.resolve_redteam_report()` calls `drill_resolution.resolve()` and
then marks matching `system_weaknesses` rows as `PATCHED`. That closes an alert, but
it does not install or validate a detector. This is consistent with the reported
failure mode where an After-Action Report remains at 0% after "remediation." The
first proposal directly replaces that administrative closure with proof of a
working detection path.

---

## 1. Proof-Carrying Purple Remediation

**Pitch:** A drill finding is not "fixed" until the same benign micro-probe is
re-run and Angerona proves the complete marker -> sensor -> detector -> signed
ledger chain succeeded.

**Why now:** The Center for Threat-Informed Defense recommends continuous,
behavior-based emulation: safely emulate behavior, observe telemetry, refine the
detection, and re-test regularly. NIST's 2025 SP 800-53 update likewise added root
cause analysis and emphasized update testing, integrity validation, and cyber
resiliency.

- [CTID - Can You Detect What You Can't Predict? Continuous Emulation as Detection Validation](https://ctid.mitre.org/blog/2025/08/04/lessons-from-sharepoint-vulnerability-cve-2025-53770/)
- [NIST - Revises Security and Privacy Control Catalog to Improve Software Update and Patch Releases](https://www.nist.gov/news-events/news/2025/08/nist-revises-security-and-privacy-control-catalog-improve-software-update)
- [CTID - Micro Emulation Plans](https://ctid.mitre.org/projects/micro-emulation-plans/)

**Fit:** Extend `core/drill_resolution.py`, `core/telemetry_contracts.py`,
`core/purple_loop.py`, `modules/posture_hardening.py`, and the Shark After-Action
Report GUI. This is **Detect + Harden + Visualize**. It is core orchestration, not a
new polling `BaseModule`.

**Architecture and implementation slices:**

1. Upgrade the resolution record to a versioned state machine:
   `OPEN -> ACKNOWLEDGED -> CANDIDATE_READY -> VERIFIED`. Only `VERIFIED` contributes
   to detection coverage or changes a weakness to `PATCHED`.
2. Give every drill technique a local manifest containing the benign probe,
   responsible detector/module, required trusted event fields, expected severity,
   cleanup routine, and deadline. Opaque run/step tokens must be present at every
   hop; display text can never satisfy a contract.
3. Change **Resolve Findings** to **Repair and re-test**. A vetted Sigma/YARA/config
   candidate can be staged, compiled, and operator-approved, then only that
   technique's harmless micro-probe runs. No full drill is required.
4. Require multiple exact echoes before verification: marker created, native sensor
   observation, detector alert carrying the same token, and signed Flight Recorder
   persistence. A missing echo leaves the finding open and explains which hop failed.
5. Store a compact proof receipt: run ID, technique, detector/rule digest, expected
   and observed echoes, timestamps, and ledger event signature. If the rule digest
   later changes or a future probe misses, reopen automatically.

**Effort:** **M.** The expectation engine and deterministic report path exist; the
main work is the technique manifest, state migration, targeted replay, and GUI.
Limit first delivery to the drill techniques that already have safe reversible
markers, then expand.

**Suitable for this pass:** **Yes - highest priority.** First slice: stop marking an
acknowledged miss as patched; add `VERIFIED` and targeted re-test for 3-4 reliable
techniques before broadening to all stages.

**Safety:** Defensive and non-destructive. Only Angerona's existing benign markers
may be replayed. Model output never becomes PowerShell or an active rule without
compile checks and explicit approval. Failure is fail-closed: the finding stays open.

---

## 2. Trust Passports - Evidence-Based, Revocable Process Trust

**Pitch:** Replace "this filename is safe" with a local, reviewable passport that
binds publisher, signature, canonical path, hash, parent lineage, install origin,
and normal network boundary - then expires or revokes trust when any key fact drifts.

**Why now:** Microsoft App Control supports trust decisions using signing
certificate, signed file metadata, hash, path, managed-install origin, and launching
process. Microsoft also recommends audit mode to discover legitimate applications
before enforcing a policy. That is a strong model for Angerona's local learner,
without relying on Microsoft's cloud reputation service.

- [Microsoft - App Control and AppLocker overview](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol-and-applocker-overview)
- [Microsoft - Understand App Control policy rules and file rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create)
- [Microsoft - Use audit events to create App Control policy rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/audit-appcontrol-policies)

**Fit:** Add `core/trust_passport.py`; enhance `core/process_allowlist.py`,
`modules/behavioral_tuner.py`, process/network telemetry enrichment, Resolve Center,
and Settings -> Trusted Processes. This is **Detect + Harden + Visualize**.

**Architecture and implementation slices:**

1. Build a local passport from canonical path, SHA-256, Authenticode chain/publisher,
   parent-child lineage, first-seen installer/process, user/session, and bounded
   network profile. Use `WinVerifyTrust`/Code Integrity logs locally; no reputation
   upload is required.
2. Add trust tiers: `OBSERVED`, `CANDIDATE`, `APPROVED`, `DRIFTED`, `REVOKED`.
   Learning creates candidates only. Promotion requires review or a separately
   trusted installer/publisher rule; it is never automatic because an attack could
   occur during the learning window.
3. Make trust a capped risk-reduction signal, not an invisibility cloak. It may skip
   repetitive INFO display and local-LLM triage, but it must never suppress memory
   scanning, telemetry-blinding alerts, credential access, a corroborated HIGH/
   CRITICAL chain, or a signature/hash mismatch.
4. For self-updating apps such as ProtonVPN, accept a new hash only when publisher,
   signed metadata, canonical install root, update lineage, and expected network
   profile remain valid. Otherwise move the passport to `DRIFTED` and ask once.
5. Add **Learn my normal apps for 24 hours** and a review queue showing exactly why
   each candidate earned trust, plus one-click revoke and an immutable local audit
   trail.

**Effort:** **M.** Uses existing process allowlist, baseline database, telemetry,
and Settings surfaces. Authenticode verification and schema migration are the main
new work. Windows-version differences must degrade to hash/path/lineage without
silently granting stronger trust.

**Suitable for this pass:** **Yes.** Implement the passport store, candidate review,
and the "trust reduces noise but cannot suppress critical controls" policy first;
automatic updater continuity can follow after field data.

**Safety:** Defensive-only. No process is started, injected, or modified. Trust is
revocable, time-bounded, evidence-based, local, and never sufficient by itself to
override corroborated malicious behavior.

---

## 3. Push-to-Talk ARIA with a Deterministic Settings Pilot

**Pitch:** Add a visible microphone button: press and hold, speak, review the local
transcript, then let ARIA change approved settings through the same typed settings
service as the GUI.

**Why now:** Windows exposes explicit microphone privacy controls and prominent
indicators when the microphone is active. Microsoft's System.Speech API can use the
default local audio device, while Angerona already has offline Vosk/sounddevice input
and Windows SAPI output. Push-to-talk provides clearer consent and lower idle CPU than
permanent wake-word listening.

- [Microsoft - Windows 11 privacy controls](https://learn.microsoft.com/en-us/windows/security/book/privacy-controls)
- [Microsoft - Privacy Policy CSP: microphone control remains user-controlled](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-Privacy)
- [Microsoft - SpeechRecognitionEngine.SetInputToDefaultAudioDevice](https://learn.microsoft.com/en-us/dotnet/api/system.speech.recognition.speechrecognitionengine.setinputtodefaultaudiodevice?view=netframework-4.8.1)

**Fit:** Enhance `gui/aria_hud.py`, the ARIA console row in
`gui/main_window.py`, `connectors/voice.py`, and the settings service proposed in
#4. This is **Harden + Quality of Life** in GUI/core; it is not a detector module.

**Architecture and implementation slices:**

1. Place a microphone button beside the ARIA prompt. Press begins capture; release,
   Escape, focus loss, or a 15-second ceiling stops it. Show an unmistakable active
   color, timer, and level meter. No background listening is needed for this mode.
2. Keep PCM in a bounded memory buffer, transcribe locally, then zero/drop the buffer.
   Do not write audio to disk. Display the transcript in the prompt so the user can
   edit or cancel before sending.
3. Add a deterministic, schema-driven settings grammar for approved intents such as
   "use my headset microphone," "turn Eco Mode on," or "open privacy settings."
   The LLM may explain an intent but cannot invent a setting key or value.
4. Read-only requests can answer immediately. Any change displays a canonical diff
   generated from trusted setting metadata, then requires a physical click or typed
   confirmation. Voice alone cannot confirm its own privileged change.
5. If microphone permission/backend/model is missing, the button opens the exact
   ARIA settings section with **Test microphone** and dependency status; it must never
   spin or repeatedly retry in the background.

**Effort:** **M.** Audio capture and meter code exist. The work is button lifecycle,
transcript preview, a bounded intent grammar, and safe settings integration.

**Suitable for this pass:** **Yes.** Ship push-to-talk + transcript preview first;
enable a very small allowlist of voice-changeable settings only after the settings
service in #4 is available.

**Safety:** Opt-in, visibly active, local by default, memory-only audio, hard timeout,
and no voice-only authorization for writes. No offensive capability is exposed.

---

## 4. Settings Capability Cockpit with Preview, Test, and Rollback

**Pitch:** Turn the long settings dialog into a searchable control center where each
feature shows prerequisites, privacy/CPU impact, live health, pending changes, test
results, restart needs, and one-click rollback.

**Why now:** NIST CM-3 calls for documented, reviewed, security/privacy-aware,
controlled configuration changes. CISA's Secure by Design guidance says product
makers should carry the burden of safe defaults instead of assuming customers will
discover insecure configuration steps.

- [NIST SP 800-53 Rev. 5 - CM-3 Configuration Change Control](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)
- [CISA - Product Security Bad Practices (2025)](https://www.cisa.gov/sites/default/files/2025-01/joint-guidance-product-security-bad-practices-508c_0.pdf)
- [CISA - Secure by Design: Shifting the Balance](https://www.cisa.gov/sites/default/files/2023-10/SecureByDesign_508c.pdf)

**Fit:** Add `core/settings_registry.py` and `core/settings_transaction.py`; replace
the monolithic construction/save logic in `gui/pages.py` incrementally with a
searchable `SettingsCenter`. Reuse `setup_wizard.py` field metadata. This is
**Harden + Visualize + Quality of Life**.

**Architecture and implementation slices:**

1. Define each setting once: typed key, range/choices, default, category, sensitivity,
   dependency, live/restart behavior, privacy/CPU impact, validator, tester, and
   reversible apply callback. GUI, Setup, console, and voice all consume the schema.
2. Save atomically as a transaction: validate all -> show diff -> apply safe live
   changes -> persist -> health-test. On failure, restore the last-known-good snapshot
   and explain the exact item that failed.
3. Add search and capability cards: `Ready`, `Needs dependency`, `Needs permission`,
   `Restart required`, `Degraded`, `Off`. Provide **Fix setup**, **Test**, **Restore
   default**, and **Undo last save**.
4. Add profiles (`Privacy first`, `Balanced`, `Full scan`, `Battery/Eco`) as previews,
   not blind bulk toggles. Every changed control remains visible before Apply.
5. Separate secrets from ordinary settings and never echo existing secret values in
   diffs, logs, screenshots, or voice responses.

**Effort:** **M-L.** The schema can be adopted tab by tab. Start with ARIA/voice,
privacy/egress, and performance because those are the user's highest-friction areas.

**Suitable for this pass:** **Yes, as an incremental foundation.** Implement the
registry/transaction layer and migrate ARIA voice + performance first; keep legacy
tabs working while the remaining categories move over.

**Safety:** Configuration only. Risky or egress-enabling settings default off, show
impact before applying, and are reversible. No setting bypasses existing confirmation
or response safety gates.

---

## 5. Driver Shield Audit and Safe Hardening Advisor

**Pitch:** Tell the user whether Windows' vulnerable-driver defenses are truly active,
surface Code Integrity evidence, and offer audit-first hardening guidance without
silently changing boot-critical policy.

**Why now:** Microsoft's August 2025 guidance says attackers abuse legitimate signed
but vulnerable drivers, recommends the vulnerable-driver blocklist plus the ASR rule,
and warns that driver blocking can break devices or rarely cause a blue screen. Its
2026 tamper-resiliency guidance recommends audit mode before block mode.

- [Microsoft - Recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)
- [Microsoft - Tamper resiliency with Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/tamper-resiliency)
- [Microsoft - Code Integrity event logging and system auditing](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/enabling-code-integrity-event-logging-and-system-auditing)

**Fit:** Add a read-mostly `BaseModule` such as `modules/driver_shield_audit.py`,
reuse `intel_sync`, Code Integrity/Defender event readers, and add a card to Threat
Intel or Settings -> Hardening. This is **Detect + Harden + Visualize**.

**Architecture and implementation slices:**

1. Inspect HVCI/Memory Integrity, Smart App Control, vulnerable-driver blocklist,
   relevant ASR audit/block state, policy age, and Code Integrity 3076/3077/3099
   events. Cache the slow inventory and refresh only on policy/event change.
2. Correlate a new driver service/load with blocklist/signature evidence and death or
   tamper of Angerona/Defender processes. High confidence requires at least two
   independent signals.
3. Show **Audit first**. Export a reviewed plan and open the relevant Windows control;
   never deploy an enforced WDAC policy automatically. Require reboot/compatibility
   warnings and a recovery plan before any operator-approved enforcement.

**Effort:** **S-M.** Read-only posture and event correlation are straightforward;
enforcement remains outside the first pass.

**Suitable for this pass:** **Yes for audit and visualization.** Defer policy
enforcement until representative hardware testing exists.

**Safety:** Defensive-only and audit-first. No driver is loaded, unloaded, disabled,
or blocked automatically; Angerona reports evidence and guides the operator.

---

## 6. Privacy Receipt Broker and Remote Bridge v2

**Pitch:** Route every optional outbound action through one fail-closed consent gate
and show a local receipt stating what category left, where it went, why, and which
redactions were applied - without storing the sensitive payload itself.

**Why now:** NIST's 2025 Privacy Framework update focuses on managing privacy risk as
personal data flows through complex systems. TLS 1.3 provides authenticated encrypted
transport. Angerona's current opt-in connectors are individually gated, but there is
no single enforceable boundary or operator-visible egress history; the current Remote
Bridge also uses plaintext event JSON and authenticates only one side of the session.

- [NIST - Privacy Framework](https://www.nist.gov/privacy-framework)
- [NIST - Privacy Framework 1.1 update](https://www.nist.gov/news-events/news/2025/04/nist-updates-privacy-framework-tying-it-recent-cybersecurity-guidelines)
- [IETF RFC 8446 - TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)

**Fit:** Add `core/egress_broker.py` and `core/privacy_receipts.py`; adapt cloud
escalation, research fetches, email/channel/Teams/mobile connectors, update checks,
and `modules/remote_bridge.py`. Add a Privacy tab/status chip. This is **Harden +
Visualize** in core/GUI.

**Architecture and implementation slices:**

1. Every outbound call declares destination, purpose, data classes, size ceiling,
   redactor, consent setting, timeout, and whether raw host identifiers are included.
   Unregistered sockets/HTTP helpers fail closed in production paths.
2. Store only a receipt: time, connector, destination class, purpose, payload digest,
   byte count, redaction count, consent source, and result. The UI can truthfully say
   **No data left this device** or list recent approved egress.
3. Add global offline mode and per-purpose consent with expiry. A connector cannot
   reuse "threat research" consent to send mailbox or host telemetry.
4. Immediate Remote Bridge containment: keep disabled, require an explicit bind
   address instead of defaulting to `0.0.0.0`, suppress hostname unless opted in, and
   label the existing protocol legacy/insecure.
5. Remote Bridge v2 uses TLS 1.3 mutual certificate authentication, payload size/schema
   limits, replay-resistant message IDs, and encrypted authenticated transport. Do not
   offer automatic plaintext downgrade.

**Effort:** **L** for complete connector migration and protocol v2; **S-M** for the
broker skeleton, UI receipts, and immediate bridge containment.

**Suitable for this pass:** **Partly.** Apply the bridge containment and broker API
now; migrate connectors in bounded batches. Treat mTLS as a versioned protocol change
with compatibility tests, not a rushed patch.

**Safety:** Privacy-preserving and defensive. Egress remains opt-in, receipts omit raw
payloads/secrets, and failure denies transmission rather than weakening a detector.

---

## 7. Attested One-Click Windows Installer

**Pitch:** Publish one verified installer that bundles required runtime dependencies,
puts privileged code in an administrator-owned location, lets the user choose the
data drive, and proves which GitHub workflow built it.

**Why now:** GitHub artifact attestations provide signed build provenance and can
include an SBOM. Microsoft notes that consistently signed releases carry publisher
identity and reduce SmartScreen friction; unsigned files rebuild reputation from zero.
This also fixes Angerona's public-release trust-boundary problem: elevated code should
not run from a broadly writable development checkout.

- [GitHub - Artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
- [GitHub - Establish build provenance with artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
- [Microsoft - SmartScreen reputation for Windows app developers](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)

**Fit:** Harden `.github/workflows/release.yml`; add a Windows installer definition
(WiX/Inno Setup/MSIX as selected), dependency lock/hashes, SBOM generation, release
manifest, install/uninstall tests, and first-run setup. This is **Harden + Quality of
Life** in packaging/CI, not a runtime module.

**Architecture and implementation slices:**

1. Pin Actions by full commit SHA and Python dependencies by locked version + hash.
   Verify the provenance/license/checksum of bundled third-party binaries such as
   YARA before they enter the package.
2. Build a self-contained executable/installer; never run general `pip install` as
   administrator on the user's machine. Put binaries under an administrator-owned
   program directory and runtime data under the user-selected data root (offer D:\
   when present, with a safe Windows fallback).
3. Publish SHA-256, SBOM, GitHub provenance attestation, and code signature. The
   installer verifies its manifest before elevation and aborts on mismatch.
4. First run shows exact optional download sizes for Ollama/model, offline speech
   model, and integrations. Required components install in one flow; optional large
   or cloud-capable pieces remain explicit choices.
5. CI tests clean install, launch, self-check, upgrade with data preservation,
   uninstall, and a standard-user attempt to modify privileged program files.

**Effort:** **L.** CI hardening is M; polished signed installer/upgrader and clean-VM
tests make the full item L. Code signing also needs an appropriate certificate or
documented unsigned-community-build expectation.

**Suitable for this pass:** **Partly.** Pin/lock/attest the release and build an
installer prototype now; production signing and broad clean-machine compatibility
testing may require follow-up.

**Safety:** Supply-chain hardening only. No dependencies are downloaded from floating
or unverified URLs during elevated install, optional network/model downloads require
consent, and uninstall preserves or explicitly offers to erase user evidence.

---

## 8. Evidence-Taint Firewall for AI and Voice Actions

**Pitch:** Mark all model context by provenance and prevent untrusted email, web,
telemetry, report, or speech text from becoming an executable action or misleading
confirmation dialog.

**Why now:** OWASP ranks prompt injection LLM01:2025 and recommends separating
untrusted content, least privilege, and human approval. OWASP's Excessive Agency
guidance warns that an email or other external record can steer an over-privileged
assistant. This is directly relevant to ARIA's inbox, research, telemetry, voice,
and remediation-advice surfaces.

- [OWASP - LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [OWASP - LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
- [OWASP - LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)

**Fit:** Add `core/provenance_labels.py`; enhance `core/assistant.py`,
`core/action_policy.py`, runbook/research/inbox adapters, ARIA Settings Pilot, and all
confirmation dialogs. This is **Harden** in core/GUI.

**Architecture and implementation slices:**

1. Wrap context fragments as typed records: `TRUSTED_POLICY`, `LOCAL_OPERATOR`,
   `HOST_TELEMETRY`, `REMOTE_CONTENT`, `EMAIL`, `MODEL_OUTPUT`, or `SPEECH_TRANSCRIPT`.
   Preserve labels through retrieval, summarization, and tool proposal creation.
2. Only deterministic code can construct an action name and typed arguments. Model
   output can select among registered intents or explain a proposal, but raw text
   cannot become a shell command, URL, file path, setting key, or confirmation body.
3. Generate approval dialogs from canonical action metadata, not model-authored text;
   always show the real target, changed values, data destination, and rollback path.
4. Promote the current shadow action-policy experiment to an authoritative gate only
   for a small, tested action class first (settings changes), with denial telemetry and
   no silent fallback. Expand after adversarial tests.

**Effort:** **M.** The assistant registry and shadow evaluator exist. The challenge is
propagating labels through every context adapter without breaking conversation quality.

**Suitable for this pass:** **After #4's typed settings service.** Protect voice-driven
settings first, then research/inbox-derived proposals and remediation advice.

**Safety:** Defensive-only. This removes agency from untrusted/model-authored text,
retains explicit operator approval, and cannot create offensive tooling.

---

## Ranked shortlist (impact / effort)

| Rank | Proposal | Effort | Best fit | This pass |
|---:|---|:---:|---|---|
| 1 | Proof-Carrying Purple Remediation | M | Core drill resolution + telemetry contracts + AAR | **Yes - first** |
| 2 | Trust Passports | M | Process allowlist + behavioral tuner + Trusted Processes UI | **Yes** |
| 3 | Push-to-Talk ARIA + Settings Pilot | M | ARIA HUD/console + local voice + typed settings | **Yes** |
| 4 | Settings Capability Cockpit | M-L | Shared settings registry/transaction + searchable GUI | **Yes, incremental** |
| 5 | Driver Shield Audit | S-M | New read-mostly module + Hardening view | **Yes, audit only** |
| 6 | Privacy Receipt Broker + Remote Bridge v2 | L | Central egress gate + Privacy UI + encrypted bridge | **Contain now; phase migration** |
| 7 | Attested One-Click Installer | L | Release CI + installer + provenance/SBOM | **CI/prototype now** |
| 8 | Evidence-Taint Firewall | M | Assistant/action policy + provenance-aware adapters | **After typed settings** |

### Recommended implementation order for the current improvement pass

1. Stop administrative drill closure from masquerading as a fix; add `VERIFIED` and
   targeted proof for a small reliable technique set.
2. Add the typed settings transaction foundation, then the push-to-talk button and
   a tiny allowlist of confirmable settings intents.
3. Add Trust Passport candidates and safety caps so normal signed apps reduce noise
   without becoming invisible.
4. Apply immediate Remote Bridge containment and release-workflow provenance/pinning.
5. If time remains, add the read-only Driver Shield posture card.

These slices deliver the user's most visible problems in this pass while keeping the
larger protocol, installer, and all-connector migrations reviewable and testable.
