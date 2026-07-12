# PR: 360° Circular Hardening — self-hardening, driver shield, jitter, forensics UI

Implements four slices of the 360° hardening blueprint plus a real bug fix, all
verified on Windows by the headless self-check (`tools/selfcheck.py`, run via
`run-selfcheck.bat`). See `docs/ARCHITECTURE_360.md` for the full design and the
explicit out-of-scope policy.

**Test status:** 13/13 self-check phases pass. The single reported "failure" is
the harness asserting that some module `self_test`s failed — those are all
expected (modules the headless harness does not start report `stopped`; AI Triage
needs a live Ollama; SOAR is idle-by-design), not defects.

---

## Bug fix (high impact)

- **`modules/api_patch_detector.py`** — the PE export-table parser hard-coded the
  DataDirectory offset at +96 for both PE32 and PE32+. On 64-bit hosts (PE32+,
  magic `0x20b`) the directories are at **+112**, so it resolved a garbage export
  RVA and parsed **zero** ntdll exports — the entire inline-hook / anti-blinding
  detector was silently dead. Now `112 if magic==0x20b else 96`. Self-check:
  `parsed 7 ntdll export prologue(s) from disk`.

## Ring 4 — Judgment Gate integrity

- **`modules/posture_hardening.py`** — staged remediation scripts are now
  SHA-256-stamped on write (new `remediation_hashes` table). `execute_remediation`
  re-hashes the on-disk file and **blocks** execution on any mismatch, logging
  CRITICAL through `edr_logger`. Verified: clean script runs, tampered script is
  blocked before execution.

## Process self-hardening

- **`core/hardening.py`** (new) + wired into `__main__.py` — applies
  `ExtensionPointDisable`, `ImageLoad` (no remote / no low-IL), and ASLR by
  default; ACG opt-in via `ANGERONA_HARDEN_AGGRESSIVE=1`. `MicrosoftSignedOnly`
  is intentionally NOT applied (would block Qt/PySide6 DLLs and crash launch).

## Ring 1 — Driver-Intel Shield

- **`modules/intel_sync.py`** — offline BYOVD blocklist + `is_known_bad_driver()`
  (zero network).
- **`modules/file_integrity.py`** — name-only `System32\drivers` watch; classifies
  `.sys` writes / known-bad / drill drivers as CRITICAL via a direct INTL lookup
  (Ring 1 interlock); gained a real `self_test`.
- **`shark/shark_attack.py`** — a **benign** simulated BYOVD driver-drop technique
  shuffled into the drill pool (marker file only — nothing is created, loaded, or
  registered), self-cleaning.

## Ring 3 — Anti-TOCTOU timing jitter + perf

- **`core/jitter.py`** (new) — `os.urandom`-based ±spread jitter.
- **`modules/canary_drill.py`, `modules/frz_heartbeat.py`** — jittered cadences
  (canary ~51–69 s, heartbeat ~0.43–0.57 s), safely inside the watchdog threshold.
- **Ollama `keep_alive`** added to the hot paths: `modules/ai_triage.py`,
  `engines/core_engine.py`, `engines/unified_defense_engine.py`, `engines/sniffer.py`,
  `modules/posture_hardening.py`, `modules/evolution_engine.py`,
  `shark/playbook_tuner.py`. (Telemetry batch flush and SPEC pre-warm already
  existed.)

## Incident forensics UI

- **`gui/pages.py`** — clickable dashboard stat cards → detail windows
  (Alerts / Critical / Modules / Threat, the last with review-gated Attempt-fix /
  Harden). New **blast-radius tree** (`build_blast_tree(pid)` over PROV
  ancestry/subtree) and **Shark-vs-Shield collision view** (reads the red-team
  AAR, maps `detected_by` → ring, BLOCKED/MISSED per technique).
- **`gui/main_window.py`** — dashboard-level **FORENSICS** header menu opens both
  views (blast-radius prompts for a PID); they remain reachable from the Threat
  drill-down too.

## Tooling

- **`tools/selfcheck.py`** + **`run-selfcheck.bat`** (new) — offscreen headless
  harness: builds the whole app + every dialog, runs each module `self_test`, and
  exercises the new features (hash gate, hardening, driver shield, jitter bounds,
  blast/collision), writing a report file.

---

## Explicitly NOT included (policy)

No indirect/direct **syscall hook-evasion stubs** (raw-assembly SSN resolution to
step over user-mode hooks), and no **real** driver loading/exploitation or **real**
persistence. These are dual-use offensive primitives; the in-memory ring relies on
detection (APID) plus the documented `ctypes` `Nt*` path, and all red-team/BYOVD
content is benign simulation. See `docs/ARCHITECTURE_360.md` → "Explicitly out of
scope."

## Files changed

```
new:   src/angerona/core/hardening.py
new:   src/angerona/core/jitter.py
new:   tools/selfcheck.py
new:   run-selfcheck.bat
new:   docs/ARCHITECTURE_360.md
new:   docs/CHANGELOG-360-hardening.md
edit:  src/angerona/__main__.py
edit:  src/angerona/modules/api_patch_detector.py
edit:  src/angerona/modules/posture_hardening.py
edit:  src/angerona/modules/intel_sync.py
edit:  src/angerona/modules/file_integrity.py
edit:  src/angerona/modules/canary_drill.py
edit:  src/angerona/modules/frz_heartbeat.py
edit:  src/angerona/modules/ai_triage.py
edit:  src/angerona/modules/evolution_engine.py
edit:  src/angerona/engines/core_engine.py
edit:  src/angerona/engines/unified_defense_engine.py
edit:  src/angerona/engines/sniffer.py
edit:  src/angerona/shark/shark_attack.py
edit:  src/angerona/shark/playbook_tuner.py
edit:  src/angerona/gui/pages.py
edit:  src/angerona/gui/main_window.py
```
