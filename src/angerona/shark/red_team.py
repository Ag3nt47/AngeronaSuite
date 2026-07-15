"""red_team.py — The Red Team Attack Engine.

A SECOND, distinct adversary-simulation drill, separate from the Shark Attack
engine. Where the Shark drill models a noisy commodity-malware chain (email
lure → discovery → persistence marker → exfil), the Red Team drill models a
quieter, APT-style **credential-access / fileless-persistence** scenario so the
two exercise different detection surfaces.

SAFETY — identical philosophy to shark_attack.py: every step performs one
real-but-narrowly-scoped, fully reversible, benign action using ordinary
Python/OS primitives, logged here in the clear. It is NOT an evasion toolkit:
  * "Credential Access" writes an INERT marker file with a credential-dump-
    style *name* — it never reads lsass, the SAM, browsers, or any real secret.
  * "WMI Persistence" writes an INERT marker file that *names* a WMI event
    consumer — it never touches the real WMI repository.
  * "Defense Evasion" writes an INERT marker that *names* a log-clear / AMSI
    trick — it never clears a log or patches anything.
  * "Discovery" is read-only psutil enumeration (no subprocess, no exfil).
Nothing here evades detection; each step performs a believable, benign action
and the After-Action Report honestly records whether a detector noticed.
"""
from __future__ import annotations

import ctypes
import json
import os
import random
import sys
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

# Every marker this drill drops starts with this prefix, so a glob sweep can
# reliably find and remove ALL of them — including orphans from a prior run that
# crashed before cleanup.
_MARKER_PREFIX = "_redteam_"


class _DrillCancelled(Exception):
    """Internal control flow for an operator-requested drill stop."""

# ── Intensity presets ────────────────────────────────────────────────────────
# One knob the operator can slide from Low → Extreme; it scales the number of
# recursive phases, the timing jitter, the noise (false-positive) chance, the
# simulated threat level, and how many benign tagged processes are spawned.
INTENSITY_LEVELS: dict[str, dict] = {
    "Low":     dict(cycles=1, jitter=(3.0, 8.0), noise=0.15, threat=1, proc_mult=1),
    "Medium":  dict(cycles=2, jitter=(2.0, 6.0), noise=0.30, threat=2, proc_mult=1),
    "High":    dict(cycles=3, jitter=(1.0, 4.0), noise=0.45, threat=3, proc_mult=2),
    "Extreme": dict(cycles=4, jitter=(0.5, 2.5), noise=0.60, threat=5, proc_mult=3),
}
_INTENSITY_ORDER = ["Low", "Medium", "High", "Extreme"]

# Canonical ATT&CK kill-chain order for CAMPAIGN mode (chained, not shuffled).
_CAMPAIGN_ORDER = [
    "_step_initial_access", "_step_recon", "_step_credential_access",
    "_step_privilege_escalation", "_step_defense_evasion", "_step_registry_runkey",
    "_step_scheduled_task", "_step_wmi_persistence", "_step_lateral_movement",
    "_step_c2_beacon", "_step_exfil_staging", "_step_ransomware_canary",
    "_step_data_destruction", "_step_random_processes",
]


def _hide_file(path) -> None:
    """Mark a drill marker hidden+system so it never clutters the user's view
    while the (short-lived) drill runs. Detection does not depend on visibility."""
    if not sys.platform.startswith("win"):
        return
    try:
        ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x02 | 0x04)
    except Exception:
        pass


@dataclass
class RedTeamStep:
    stage: str
    technique: str
    description: str
    ts_start: float
    ts_end: float = 0.0
    artifact_paths: List[str] = field(default_factory=list)
    pid: Optional[int] = None
    pids: List[int] = field(default_factory=list)
    correlation_tokens: List[str] = field(default_factory=list)
    detail: str = ""
    ok: bool = True


class RedTeamEngine:
    """Runs one randomized, non-destructive Red Team playbook on a background
    thread. Mirrors SharkAttackEngine's interface (is_running / start /
    stop_and_clean / on_event) so the GUI wires it up the same way, but writes
    its OWN ground-truth log (redteam_history.json) and its own scenario."""

    def __init__(self, data_dir: Path,
                 documents_dir: Optional[Path] = None,
                 on_event: Optional[Callable[[str], None]] = None) -> None:
        self.data_dir = Path(data_dir)
        self.history_path = self.data_dir / "redteam_history.json"
        self.documents_dir = (Path(documents_dir) if documents_dir
                              else self.data_dir / "drill-sandbox")
        self._on_event = on_event
        self._thread: Optional[threading.Thread] = None
        self._running = threading.Event()
        self._cancel = threading.Event()
        self.run_id = ""
        self.steps: List[RedTeamStep] = []

    # ── helpers ──────────────────────────────────────────────────────────────
    def _narrate(self, msg: str) -> None:
        if self._on_event:
            try:
                self._on_event(msg)
            except Exception:
                pass

    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    def _jitter(self, lo: float, hi: float, note: str = "") -> None:
        d = round(random.uniform(lo, hi), 1)
        if note:
            self._narrate(f"⏳ Waiting {d}s (jitter) before: {note}")
        if self._cancel.wait(d):
            raise _DrillCancelled()

    def _record(self, stage, technique, description, ts_start, **kw) -> RedTeamStep:
        step = RedTeamStep(stage=stage, technique=technique, description=description,
                           ts_start=ts_start, ts_end=time.time(), **kw)
        self.steps.append(step)
        return step

    def _marker(self, name: str, body: str) -> Path:
        if self._cancel.is_set():
            raise _DrillCancelled()
        self.documents_dir.mkdir(parents=True, exist_ok=True)
        p = self.documents_dir / name
        p.write_text(body, encoding="utf-8")
        _hide_file(p)
        return p

    def _sweep_markers(self) -> int:
        """Delete EVERY drill marker in the target dir — tracked artifacts plus
        any orphaned `_redteam_*` files from earlier/crashed runs. Never raises."""
        removed = 0
        # 1) tracked per-step artifacts
        for step in self.steps:
            for p in step.artifact_paths:
                try:
                    if Path(p).exists():
                        Path(p).unlink(missing_ok=True)
                        removed += 1
                except Exception:
                    pass
        # 2) belt-and-suspenders glob sweep for anything left behind
        try:
            for p in self.documents_dir.glob(f"{_MARKER_PREFIX}*"):
                try:
                    p.unlink(missing_ok=True)
                    removed += 1
                except Exception:
                    pass
        except Exception:
            pass
        if removed:
            self._narrate(f"🧹 Red Team cleanup — removed {removed} test marker/file(s).")
        return removed

    # ── control ────────────────────────────────────────────────────────────
    def start(self, jitter_range=(2.0, 7.0), noise_chance=0.25,
              complexity=1, target_dir=None, custom=None,
              intensity=None, campaign=False) -> bool:
        """Run a randomized Red Team playbook.

        intensity — one of Low/Medium/High/Extreme. When given it drives cycles,
          jitter, noise, threat level and process count (overrides complexity).
        campaign  — when True the techniques run in a chained ATT&CK kill-chain
          order (recon → access → persist → C2 → exfil → impact) instead of the
          default per-phase shuffle, modelling a coherent operation.
        complexity — legacy phase count, used when intensity is not supplied.
        target_dir — where benign markers land. custom = optional benign
          {"name","payload"} technique (written verbatim, NEVER executed).
        """
        if self.is_running or (self._thread is not None and self._thread.is_alive()):
            return False
        self._cancel.clear()
        if target_dir:
            try:
                self.documents_dir = Path(target_dir)
            except Exception:
                pass
        preset = INTENSITY_LEVELS.get(str(intensity)) if intensity else None
        if preset:
            self._complexity = preset["cycles"]
            self._threat_level = preset["threat"]
            self._proc_mult = preset["proc_mult"]
            jitter_range = preset["jitter"]
            noise_chance = preset["noise"]
            self._intensity = str(intensity)
        else:
            self._complexity = max(1, int(complexity))
            self._threat_level = self._complexity
            self._proc_mult = 1
            self._intensity = f"complexity={self._complexity}"
        self._campaign = bool(campaign)
        self._custom = custom if (custom and custom.get("name") and custom.get("payload")) else None
        self.run_id = f"redteam-{int(time.time())}-{uuid.uuid4().hex[:6]}"
        self.steps = []
        # Pre-clean: nuke any leftover markers from a prior run that never got
        # swept (e.g. the app was killed mid-drill) so they don't accumulate.
        self._sweep_markers()
        self._running.set()
        self._thread = threading.Thread(
            target=self._run_playbook, args=(jitter_range, noise_chance),
            name="RedTeamEngine", daemon=True)
        self._thread.start()
        return True

    def stop_and_clean(self) -> None:
        self._cancel.set()
        self._running.clear()
        worker = self._thread
        if worker is not None and worker.is_alive() and worker is not threading.current_thread():
            worker.join(timeout=0.25)
        self._sweep_markers()

    # ── playbook ─────────────────────────────────────────────────────────────
    def _run_playbook(self, jitter_range, noise_chance) -> None:
        self._narrate(
            f"\U0001F5E1️ Red Team Attack {self.run_id} starting — an APT-style "
            "credential-access / fileless-persistence drill (distinct from the Shark "
            "drill). Unannounced and non-destructive. Watch the dashboard's Alerts "
            "panel + Modules table for the DEFENSE side reacting.")
        cycles = getattr(self, "_complexity", 1)
        custom = getattr(self, "_custom", None)
        campaign = getattr(self, "_campaign", False)
        self._narrate(f"\U0001F39B️ Intensity: {getattr(self,'_intensity','?')}; "
                      f"{cycles} phase(s); {'CAMPAIGN (chained kill-chain)' if campaign else 'randomized'}; "
                      f"target={self.documents_dir}" + ("; +1 custom benign technique" if custom else ""))
        cancelled = False
        try:
            for cycle in range(cycles):
                if self._cancel.is_set():
                    raise _DrillCancelled()
                if cycles > 1:
                    self._narrate(f"\U0001F501 Phase {cycle + 1}/{cycles} — deeper each pass "
                                  "(recon → escalate → persist → exfil → impact).")
                stage_fns = [
                    self._step_initial_access,
                    self._step_credential_access,
                    self._step_recon,
                    self._step_privilege_escalation,
                    self._step_wmi_persistence,
                    self._step_defense_evasion,
                    self._step_scheduled_task,
                    self._step_registry_runkey,
                    self._step_lateral_movement,
                    self._step_c2_beacon,
                    self._step_exfil_staging,
                    self._step_ransomware_canary,
                    self._step_data_destruction,
                    self._step_random_processes,
                ]
                if custom:
                    stage_fns.append(self._step_custom)
                if random.random() < noise_chance:
                    stage_fns.append(self._step_noise)
                else:
                    self._narrate("\U0001F3B2 Noise Injection — skipped this phase (random chance).")
                if campaign:
                    # chained kill-chain order (coherent operation), not shuffled
                    rank = {n: i for i, n in enumerate(_CAMPAIGN_ORDER)}
                    stage_fns.sort(key=lambda fn: rank.get(fn.__name__, 99))
                else:
                    random.shuffle(stage_fns)
                order = " → ".join(
                    fn.__name__.replace("_step_", "").replace("_", " ").title() for fn in stage_fns)
                self._narrate(f"\U0001F500 Technique order: {order}")
                for fn in stage_fns:
                    if self._cancel.is_set():
                        raise _DrillCancelled()
                    try:
                        fn(jitter_range)
                    except _DrillCancelled:
                        raise
                    except Exception as exc:
                        self._narrate(f"⚠ step error (non-fatal): {exc}")
                    if self._cancel.is_set():
                        raise _DrillCancelled()
        except _DrillCancelled:
            cancelled = True
        finally:
            self._write_history()
            n, ok = len(self.steps), sum(1 for s in self.steps if s.ok)
            if cancelled or self._cancel.is_set():
                self._running.clear()
                self._narrate(f"Red Team Attack cancelled - {ok}/{n} steps executed; cleaning markers.")
                self._sweep_markers()
            else:
                self._narrate(
                    f"\U0001F3C1 Red Team Attack complete — {ok}/{n} steps executed. "
                    "Generating the After-Action Report (brief settle window)…")
                self._running.clear()
                delay = getattr(self, "_cleanup_delay", 55.0)
                try:
                    threading.Timer(delay, self._sweep_markers).start()
                except Exception:
                    self._sweep_markers()

    def _step_credential_access(self, jitter_range) -> None:
        self._jitter(*jitter_range, note="Credential Access — drop an inert cred-dump marker")
        ts = time.time()
        hexid = uuid.uuid4().hex[:8]
        self._narrate("▶ STAGE: Credential Access [T1003-style] — writing an INERT marker "
                      f"named like an lsass credential dump into {self.documents_dir} "
                      "(no real memory/SAM/browser secret is ever touched).")
        p = self._marker(f"_redteam_lsass_dump_{hexid}.txt",
                         "ANGERONA RED TEAM drill — simulated credential-access marker. Inert.\n")
        self._record("Credential Access (simulated)", "T1003 marker",
                     "Inert lsass-dump-named marker written to Documents.",
                     ts, artifact_paths=[str(p)])

    def _step_recon(self, jitter_range) -> None:
        self._jitter(*jitter_range, note="Discovery — read-only host enumeration")
        ts = time.time()
        count = 0
        try:
            import psutil
            count = sum(1 for _ in psutil.process_iter(["pid", "name"]))
        except Exception:
            pass
        self._narrate(f"▶ STAGE: Discovery [T1057/T1082] — read-only enumeration of "
                      f"{count} running processes (no writes, no subprocess, no exfil).")
        self._record("Discovery", "read-only enumeration",
                     f"Enumerated {count} processes read-only.", ts,
                     detail="unmonitored by design")

    def _step_wmi_persistence(self, jitter_range) -> None:
        self._jitter(*jitter_range, note="Persistence — drop an inert WMI-subscription marker")
        ts = time.time()
        hexid = uuid.uuid4().hex[:8]
        self._narrate("▶ STAGE: WMI Persistence [T1546.003] — writing an INERT marker that "
                      f"NAMES a WMI __EventConsumer into {self.documents_dir}. The real WMI "
                      "repository (ROOT\\subscription) is never modified.")
        p = self._marker(f"_redteam_wmi_subscription_{hexid}.txt",
                         "ANGERONA RED TEAM drill — simulated WMI event-consumer marker. Inert.\n")
        self._record("WMI Persistence (simulated)", "T1546.003 marker",
                     "Inert WMI-subscription-named marker written to Documents.",
                     ts, artifact_paths=[str(p)])

    def _step_defense_evasion(self, jitter_range) -> None:
        self._jitter(*jitter_range, note="Defense Evasion — drop an inert log-clear/AMSI marker")
        ts = time.time()
        hexid = uuid.uuid4().hex[:8]
        self._narrate("▶ STAGE: Defense Evasion [T1070/T1562-style] — writing an INERT "
                      f"marker named like an AMSI-bypass / log-clear artifact into "
                      f"{self.documents_dir}. No log is cleared and nothing is patched.")
        p = self._marker(f"_redteam_amsi_bypass_{hexid}.txt",
                         "ANGERONA RED TEAM drill — simulated defense-evasion marker. Inert.\n")
        self._record("Defense Evasion (simulated)", "T1070 marker",
                     "Inert AMSI/log-clear-named marker written to Documents.",
                     ts, artifact_paths=[str(p)])

    def _step_noise(self, jitter_range) -> None:
        self._jitter(*jitter_range, note="Noise Injection — benign marker (false-positive check)")
        ts = time.time()
        hexid = uuid.uuid4().hex[:8]
        self._narrate("▶ STAGE: Noise Injection — a completely benign file the defenders "
                      "SHOULD ignore; if anything fires on it, that's a false positive.")
        p = self._marker(f"_redteam_benign_note_{hexid}.txt", "just an ordinary note\n")
        self._record("Noise Injection", "benign file",
                     "Benign marker written (should not trigger anything).",
                     ts, artifact_paths=[str(p)])

    def _step_custom(self, jitter_range) -> None:
        """User-defined benign technique. The text the operator supplied is
        written verbatim as an INERT marker file so the defensive stack can be
        tested against it — it is NEVER executed, interpreted, or run."""
        self._jitter(*jitter_range, note="Custom technique — user-defined benign marker")
        ts = time.time()
        c = getattr(self, "_custom", None) or {}
        name = str(c.get("name", "custom"))
        payload = str(c.get("payload", ""))
        hexid = uuid.uuid4().hex[:8]
        safe = "".join(ch for ch in name if ch.isalnum() or ch in "-_")[:40] or "custom"
        self._narrate(f"▶ STAGE: Custom [user-defined: {name}] — writing the text you supplied "
                      f"as an INERT marker into {self.documents_dir}. It is written verbatim to a "
                      "file and never executed — this tests whether the defense detects the "
                      "content, nothing runs.")
        p = self._marker(
            f"_redteam_custom_{safe}_{hexid}.txt",
            f"ANGERONA RED TEAM custom drill marker — INERT, never executed.\n"
            f"Technique: {name}\n---\n{payload}\n")
        self._record("Custom (simulated)", f"user-defined: {name}",
                     "User-defined benign marker written (content only, never executed).",
                     ts, artifact_paths=[str(p)])

    def _step_scheduled_task(self, jitter_range) -> None:
        self._jitter(*jitter_range, note="Persistence — inert scheduled-task marker")
        ts = time.time(); hexid = uuid.uuid4().hex[:8]
        self._narrate("▶ STAGE: Scheduled Task Persistence [T1053.005] — writing an INERT marker "
                      f"named like a malicious schtasks entry into {self.documents_dir}. No real "
                      "task is created.")
        p = self._marker(f"_redteam_schtask_{hexid}.txt",
                         "ANGERONA RED TEAM drill — simulated scheduled-task marker. Inert.\n")
        self._record("Scheduled Task (simulated)", "T1053.005 marker",
                     "Inert scheduled-task-named marker written to Documents.", ts,
                     artifact_paths=[str(p)])

    def _step_registry_runkey(self, jitter_range) -> None:
        self._jitter(*jitter_range, note="Persistence — inert Run-key marker")
        ts = time.time(); hexid = uuid.uuid4().hex[:8]
        self._narrate("▶ STAGE: Registry Run Key [T1547.001] — writing an INERT marker that NAMES "
                      f"an HKCU Run autostart entry into {self.documents_dir}. The real registry is "
                      "never modified.")
        p = self._marker(f"_redteam_runkey_{hexid}.txt",
                         "ANGERONA RED TEAM drill — simulated Run-key persistence marker. Inert.\n")
        self._record("Registry Run Key (simulated)", "T1547.001 marker",
                     "Inert Run-key-named marker written to Documents.", ts,
                     artifact_paths=[str(p)])

    def _step_lateral_movement(self, jitter_range) -> None:
        self._jitter(*jitter_range, note="Lateral Movement — inert PsExec/SMB marker")
        ts = time.time(); hexid = uuid.uuid4().hex[:8]
        self._narrate("▶ STAGE: Lateral Movement [T1021.002] — writing an INERT marker named like "
                      f"a PsExec/SMB admin-share artifact into {self.documents_dir}. No network "
                      "share or remote host is touched.")
        p = self._marker(f"_redteam_psexec_{hexid}.txt",
                         "ANGERONA RED TEAM drill — simulated lateral-movement marker. Inert.\n")
        self._record("Lateral Movement (simulated)", "T1021.002 marker",
                     "Inert PsExec/SMB-named marker written to Documents.", ts,
                     artifact_paths=[str(p)])

    def _step_exfil_staging(self, jitter_range) -> None:
        self._jitter(*jitter_range, note="Collection/Exfil — inert staging-archive marker")
        ts = time.time(); hexid = uuid.uuid4().hex[:8]
        self._narrate("▶ STAGE: Exfil Staging [T1074/T1560] — writing an INERT marker named like a "
                      f"staged .rar/.7z exfil archive into {self.documents_dir}. Nothing is "
                      "collected, compressed, or sent.")
        p = self._marker(f"_redteam_exfil_stage_{hexid}.txt",
                         "ANGERONA RED TEAM drill — simulated exfil-staging marker. Inert.\n")
        self._record("Exfil Staging (simulated)", "T1074 marker",
                     "Inert staging-archive-named marker written to Documents.", ts,
                     artifact_paths=[str(p)])

    def _step_ransomware_canary(self, jitter_range) -> None:
        self._jitter(*jitter_range, note="Impact — inert ransomware-note marker")
        ts = time.time(); hexid = uuid.uuid4().hex[:8]
        self._narrate("▶ STAGE: Ransomware Impact [T1486] — writing an INERT marker named like a "
                      f"ransom note / .locked file into {self.documents_dir}. No file is encrypted; "
                      "this only tests ransomware heuristics on the NAME/pattern.")
        p = self._marker(f"_redteam_README_DECRYPT_{hexid}.txt",
                         "ANGERONA RED TEAM drill — simulated ransom-note marker. Inert.\n")
        self._record("Ransomware Impact (simulated)", "T1486 marker",
                     "Inert ransom-note-named marker written to Documents.", ts,
                     artifact_paths=[str(p)])

    def _step_random_processes(self, jitter_range) -> None:
        """Spawn a few BENIGN, short-lived, red-team-TAGGED processes so the
        process-creation sensors (PROC/ETW) and the SOAR active-defense path get
        exercised end-to-end. Nothing harmful runs — each process just carries the
        tag on its command line and exits immediately."""
        import os
        import subprocess
        self._jitter(*jitter_range, note="Execution — benign tagged process spawns")
        ts = time.time()
        level = int(getattr(self, "_threat_level", getattr(self, "_complexity", 1)) or 1)
        mult = int(getattr(self, "_proc_mult", 1) or 1)
        n = min(2 + level * mult, 16)
        self._narrate(f"▶ STAGE: Benign Execution [T1059-style] — spawning {n} short-lived, "
                      "red-team-TAGGED processes (they exit immediately) so the process sensors "
                      "and SOAR see realistic process-creation activity. Nothing harmful runs.")
        spawned = 0
        pids = []
        tokens = []
        for _ in range(n):
            if self._cancel.is_set():
                break
            tag = f"ANGERONA_REDTEAM_{uuid.uuid4().hex[:8]}"
            try:
                if os.name == "nt":
                    proc = subprocess.Popen(["cmd", "/c", "rem", tag])   # no-op, exits
                else:
                    proc = subprocess.Popen(["sh", "-c", ": " + tag])
                spawned += 1
                pids.append(int(proc.pid))
                tokens.append(tag)
            except Exception:
                pass
            if self._cancel.wait(0.2):
                break
        self._record("Benign Execution (simulated)", "T1059 tagged spawns",
                     f"Spawned {spawned} short-lived red-team-tagged process(es).", ts,
                     pid=(pids[0] if pids else None), pids=pids,
                     correlation_tokens=tokens)

    def _step_initial_access(self, jitter_range) -> None:
        self._jitter(*jitter_range, note="Initial Access — inert phishing-attachment marker")
        ts = time.time(); hexid = uuid.uuid4().hex[:8]
        self._narrate("▶ STAGE: Initial Access [T1566.001] — writing an INERT marker named like a "
                      f"malicious phishing attachment (invoice macro) into {self.documents_dir}. "
                      "Nothing is opened, executed, or received over the network.")
        p = self._marker(f"_redteam_invoice_macro_{hexid}.txt",
                         "ANGERONA RED TEAM drill — simulated phishing-attachment marker. Inert.\n")
        self._record("Initial Access (simulated)", "T1566.001 marker",
                     "Inert phishing-attachment-named marker written.", ts, artifact_paths=[str(p)])

    def _step_privilege_escalation(self, jitter_range) -> None:
        self._jitter(*jitter_range, note="Privilege Escalation — inert UAC-bypass marker")
        ts = time.time(); hexid = uuid.uuid4().hex[:8]
        self._narrate("▶ STAGE: Privilege Escalation [T1548.002] — writing an INERT marker named "
                      f"like a UAC-bypass artifact (fodhelper/eventvwr) into {self.documents_dir}. "
                      "No token is manipulated and nothing is elevated.")
        p = self._marker(f"_redteam_uac_bypass_{hexid}.txt",
                         "ANGERONA RED TEAM drill — simulated UAC-bypass marker. Inert.\n")
        self._record("Privilege Escalation (simulated)", "T1548.002 marker",
                     "Inert UAC-bypass-named marker written.", ts, artifact_paths=[str(p)])

    def _step_c2_beacon(self, jitter_range) -> None:
        self._jitter(*jitter_range, note="Command & Control — inert beacon-config marker")
        ts = time.time(); hexid = uuid.uuid4().hex[:8]
        self._narrate("▶ STAGE: Command & Control [T1071/T1571] — writing an INERT marker that "
                      f"NAMES a C2 beacon profile / callback config into {self.documents_dir}. No "
                      "network callback is made — this only tests C2-config detection on the artifact.")
        p = self._marker(f"_redteam_c2_beacon_cfg_{hexid}.txt",
                         "ANGERONA RED TEAM drill — simulated C2 beacon-config marker. Inert. "
                         "No callback performed.\n")
        self._record("Command & Control (simulated)", "T1071 marker",
                     "Inert C2 beacon-config-named marker written.", ts, artifact_paths=[str(p)])

    def _step_data_destruction(self, jitter_range) -> None:
        self._jitter(*jitter_range, note="Impact — inert wiper marker")
        ts = time.time(); hexid = uuid.uuid4().hex[:8]
        self._narrate("▶ STAGE: Data Destruction [T1485] — writing an INERT marker named like a "
                      f"disk-wiper artifact into {self.documents_dir}. NOTHING is deleted, wiped, or "
                      "overwritten — only the NAME/pattern is presented to the heuristics.")
        p = self._marker(f"_redteam_wiper_{hexid}.txt",
                         "ANGERONA RED TEAM drill — simulated data-destruction marker. Inert.\n")
        self._record("Data Destruction (simulated)", "T1485 marker",
                     "Inert wiper-named marker written.", ts, artifact_paths=[str(p)])

    def _write_history(self) -> None:
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            payload = {
                "run_id": self.run_id,
                "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                "kind": "red_team",
                "steps": [asdict(s) for s in self.steps],
            }
            self.history_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception:
            pass


REDTEAM_STAGE_CATEGORY = {
    "Initial Access (simulated)": "detection",
    "Credential Access (simulated)": "detection",
    "Discovery": "unmonitored",
    "Privilege Escalation (simulated)": "detection",
    "WMI Persistence (simulated)": "detection",
    "Defense Evasion (simulated)": "detection",
    "Scheduled Task (simulated)": "detection",
    "Registry Run Key (simulated)": "detection",
    "Lateral Movement (simulated)": "detection",
    "Command & Control (simulated)": "detection",
    "Exfil Staging (simulated)": "detection",
    "Ransomware Impact (simulated)": "detection",
    "Data Destruction (simulated)": "detection",
    "Benign Execution (simulated)": "detection",
    "Noise Injection": "resilience",
}


def self_test() -> tuple[bool, str]:
    """Verify intensity presets, campaign-order integrity, and technique coverage
    without running the (file-writing / process-spawning) playbook thread."""
    # 1) intensity presets well-formed and monotically escalating
    keys = ("cycles", "jitter", "noise", "threat", "proc_mult")
    presets_ok = all(all(k in INTENSITY_LEVELS[l] for k in keys) for l in _INTENSITY_ORDER)
    escalating = ([INTENSITY_LEVELS[l]["cycles"] for l in _INTENSITY_ORDER] == sorted(
        [INTENSITY_LEVELS[l]["cycles"] for l in _INTENSITY_ORDER]))
    # 2) every campaign-order name maps to a real engine step method
    missing = [n for n in _CAMPAIGN_ORDER if not callable(getattr(RedTeamEngine, n, None))]
    # 3) campaign sort produces the canonical kill-chain order
    rank = {n: i for i, n in enumerate(_CAMPAIGN_ORDER)}
    sample = ["_step_ransomware_canary", "_step_recon", "_step_initial_access"]
    ordered = sorted(sample, key=lambda n: rank.get(n, 99))
    order_ok = ordered == ["_step_initial_access", "_step_recon", "_step_ransomware_canary"]
    ok = presets_ok and escalating and not missing and order_ok
    return ok, (f"intensity presets ok, {len(_CAMPAIGN_ORDER)} chained techniques, kill-chain order verified"
                if ok else f"failed: presets={presets_ok} escalate={escalating} missing={missing} order={order_ok}")
