# Angerona — 360° Circular Hardening Architecture

Angerona is a local-first, AI-augmented Windows EDR/NDR suite. Because it runs
elevated in **user mode** (no custom kernel driver), no single component is
trusted blindly: every layer is cross-checked by an out-of-band or
independently-sourced control, so compromising one sub-component does not blind
the whole suite.

This document is the design blueprint. Each ring notes its **status**:

- **Implemented** — shipped and covered by the headless self-check (`tools/selfcheck.py`).
- **Partial** — a working baseline ships; deeper hardening is designed but not built.
- **Design-only** — described here as intent; no code yet.

A guiding rule (enforced in review): **no 26th "orchestrator" module.** Security
emerges from *direct* cross-module checks (e.g. FIM asks INTL whether a dropped
driver is known-bad), never from a central control plane that would itself be a
single point of failure.

---

## Ring 1 — Static Integrity & Driver-Intel Shield

**Enforcers:** HERMETIC (Monolithic Packaging), INTL (Threat Intel), FIM (File
Integrity Monitor), Process Monitor.

- **Driver-Intel blocklist — Implemented.** `intel_sync.py` bundles an offline
  reference set of publicly-documented BYOVD drivers (the kind that populate
  Microsoft's Vulnerable Driver Blocklist) and exposes
  `is_known_bad_driver(name|sha256)`. No network — honours the zero-egress model.
- **Driver-write detection — Implemented.** `file_integrity.py` watches
  `System32\drivers` by name (cheap — no hashing hundreds of MB) and, on the
  generic watch set, classifies any `.sys` write or known-bad/drill driver as
  **CRITICAL** via a direct call into INTL's lookup (the Ring 1 interlock).
- **Boot integrity (PyOxidizer signed single-binary; TPM 2.0 PCR quote gating
  `.env` / `agent_memory.db` decryption; Authenticode) — Design-only.** The
  HERMETIC module today reports a packaging/signature *assessment*; the
  measured-boot key-release gate is future work.

**Interlock:** an unauthorized `.sys` drop or a match against the INTL feed
raises CRITICAL and flags the staging path before the OS parses the file.

---

## Ring 2 — Dynamic Validation (In-Memory Integrity)

**Enforcers:** APID (API Patch / Anti-Blinding Detector), SYS (Indirect Syscall Bridge).

- **API-hook detection — Implemented.** `api_patch_detector.py` reads pristine
  `ntdll.dll` / `kernel32.dll` from `System32` on disk, parses their export
  tables, and diffs the on-disk prologues against live memory to catch inline
  hooks (`E9`, `FF 25`, `68…C3`). *(Note: the PE parser previously used the
  wrong DataDirectory offset for PE32+ binaries, so on 64-bit hosts it silently
  parsed zero exports — fixed; it now resolves the watched exports.)*
- **Indirect Syscall Bridge — Partial, and intentionally bounded.** The module
  ships a **documented `ctypes` `Nt*` fallback** (normal, documented Windows API
  usage) and detects whether the compiled C helper is present. The design intent
  is that when APID flags a hook it trips a global runtime flag forcing mitigation
  actions to route around hooked user-mode exports.
  **The raw-assembly SSN-resolving syscall stubs that would step over user-mode
  hooks are deliberately NOT implemented in this project.** That primitive is a
  dual-use EDR-evasion technique whose real-world use is offensive; the same code
  is directly reusable to bypass *other* defenders. Angerona therefore keeps the
  documented API path and treats hook detection (APID) + response as the shipped
  behaviour. See "Explicitly out of scope" below.
- **Control-Flow Integrity (`-fsanitize=cfi`) + HPC monitor for ROP/JOP —
  Design-only.**

---

## Ring 3 — Runtime Vitality & Host Isolation

**Enforcers:** DRILL (Canary Drills), ETWG (ETW Core Listener), FRZ (Anti-Suspension Heartbeat).

- **Synthetic canary loop — Implemented.** `canary_drill.py` fires a benign
  synthetic probe on a **jittered** ~60 s cadence; ETWG must capture the matching
  Security 4688 event within a 6 s window. Consecutive misses raise a CRITICAL
  telemetry-blinding alert (dropped events are treated as active exploitation).
- **Cross-language heartbeat — Implemented (mmap side).** `frz_heartbeat.py`
  writes a nanosecond `mmap` clock on a **jittered** ~500 ms cadence for the
  detached Go watchdog (`frz/frz_watchdog.go`) to read. If the interpreter is
  suspended, the watchdog — running outside Python — is designed to drop host
  networking (WFP) while keeping loopback/Ollama open. *(The Go watchdog binary
  is built separately; the mmap protocol and jitter ship now.)*
- **Anti-TOCTOU jitter — Implemented.** `core/jitter.py` perturbs both loops by
  ±15% using `os.urandom` (the OS CSPRNG, not the seedable PRNG), so an automated
  adversary cannot map a fixed rhythm and fire in the dead space between sweeps.
  Jitter stays inside the watchdog's freeze threshold, so a late beat never
  false-triggers isolation.

---

## Ring 4 — Closed-Loop Posture Evolution & Threat-Intel Verification

**Enforcers:** Shark Attack Engine, Posture Hardening (HARD), Judgment Gate, INTL.

- **Feedback pipeline — Implemented.** Automated, **benign** red-team drills drop
  tagged marker footprints; techniques scoring SUCCESS / LOW-DETECTION are
  written to `agent_memory.db` as weaknesses.
- **Staged, hash-stamped remediation (Judgment Gate) — Implemented.** When HARD
  stages a remediation script it is SHA-256-stamped in a protected table the
  moment it is written. `execute_remediation()` re-hashes the on-disk file and
  **refuses to run** anything whose bytes changed since staging (e.g. an attacker
  swapping the `.ps1`), raising CRITICAL through `edr_logger`. Nothing that
  modifies the OS ever auto-executes — execution is review-gated and requires an
  explicit authorization.
- **Judgment verification — Implemented (verifier path).** `angerona.shark.verify`
  re-runs the attack footprint; only a verified BLOCKED result promotes a
  detection to active.

---

## Process self-hardening (agent surface reduction)

`core/hardening.py` applies process-mitigation policies to Angerona's **own**
process at startup (best-effort, never blocks launch):

- **Applied by default:** `ExtensionPointDisablePolicy` (blocks AppInit_DLLs /
  legacy hook injection), `ImageLoadPolicy` (no remote / no low-IL DLLs), and
  bottom-up + high-entropy ASLR.
- **Opt-in (`ANGERONA_HARDEN_AGGRESSIVE=1`):** Arbitrary Code Guard
  (`ProhibitDynamicCode`), which can break libraries that JIT/emit code.
- **Deliberately never applied:** `BinarySignaturePolicy = MicrosoftSignedOnly`.
  Angerona loads third-party, non-Microsoft-signed native DLLs (Qt/PySide6,
  pywin32, scapy); enabling this would block those loads and the app would die on
  launch. It is documented here so the omission is a decision, not an oversight.

---

## Performance path (keeping the loop fluid)

- **No cold starts:** the hot Ollama call sites send `keep_alive` so `llama3`
  stays resident in VRAM between triage calls.
- **UI never blocks:** telemetry is aggregated off-thread and flushed to widgets
  on a 100 ms `QTimer` batch (`gui/telemetry_worker.py`).
- **Speculative pre-warm (SPEC):** high-risk indicators pre-warm the model's
  context before the full analytical pass completes.

---

## Incident forensics UI

- **Blast-radius tree** — `build_blast_tree(pid)` = `{origin: PROV.ancestry,
  blast_radius: PROV.subtree}`, rendered as a hierarchical tree (upstream
  root-cause chain + downstream processes/files/network spawned).
- **Shark-vs-Shield collision view** — reads the latest red-team After-Action
  Report and shows, per simulated technique, BLOCKED vs MISSED, which **ring**
  caught it, the detecting module, and latency.

Both are reachable from the dashboard header (**FORENSICS** menu) and from the
Threat drill-down.

---

## The circular trust paradox

To blind the suite an adversary must hook APIs (caught by **APID**); if they drop
telemetry without hooks, **DRILL** alerts; if they freeze the process to stop
DRILL, **FRZ**'s out-of-process watchdog triggers network isolation; if they
modify binaries on disk, the (design-stage) TPM/Authenticode boot gate breaks.
Each escape route trips a different, independently-sourced ring.

---

## Explicitly out of scope (by policy, not omission)

Angerona does **not** ship hand-written indirect/direct **syscall-evasion stubs**
(raw-assembly SSN resolution that steps over user-mode API hooks), nor any code
that performs **real** driver loading/exploitation or **real** persistence
installation. These are dual-use offensive primitives: the identical code that
lets a defender "route around hooks" is what offensive tooling uses to evade
*other* EDRs. The project's red-team/BYOVD content is therefore **benign
simulation only** (tagged marker files that never load or register anything), and
the in-memory-integrity ring relies on **detection (APID)** plus the documented
`ctypes` API path rather than an evasion primitive.
