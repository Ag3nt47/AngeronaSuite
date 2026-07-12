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
        home = Path(os.environ.get("USERPROFILE", str(Path.home())))
        self.documents_dir = Path(documents_dir) if documents_dir else (home / "Documents")
        self._on_event = on_event
        self._thread: Optional[threading.Thread] = None
        self._running = threading.Event()
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
        time.sleep(d)

    def _record(self, stage, technique, description, ts_start, **kw) -> RedTeamStep:
        step = RedTeamStep(stage=stage, technique=technique, description=description,
                           ts_start=ts_start, ts_end=time.time(), **kw)
        self.steps.append(step)
        return step

    def _marker(self, name: str, body: str) -> Path:
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
              complexity=1, target_dir=None, custom=None) -> bool:
        """complexity = number of recursive phases (Low=1, Medium=2, High=3).
        target_dir overrides where markers land. custom = optional
        {"name", "payload"} benign technique (marker text is written verbatim
        and NEVER executed)."""
        if self.is_running:
            return False
        if target_dir:
            try:
                self.documents_dir = Path(target_dir)
            except Exception:
                pass
        self._complexity = max(1, int(complexity))
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
        self._running.clear()
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
        if cycles > 1 or custom:
            self._narrate(f"\U0001F39B️ Complexity: {cycles} phase(s); target={self.documents_dir}"
                          + ("; +1 custom benign technique" if custom else ""))
        try:
            for cycle in range(cycles):
                if cycles > 1:
                    self._narrate(f"\U0001F501 Phase {cycle + 1}/{cycles} — deeper each pass "
                                  "(recon → escalate → persist).")
                stage_fns = [
                    self._step_credential_access,
                    self._step_recon,
                    self._step_wmi_persistence,
                    self._step_defense_evasion,
                    self._step_scheduled_task,
                    self._step_registry_runkey,
                    self._step_lateral_movement,
                    self._step_exfil_staging,
                    self._step_ransomware_canary,
                    self._step_random_processes,
                ]
                if custom:
                    stage_fns.append(self._step_custom)
                if random.random() < noise_chance:
                    stage_fns.append(self._step_noise)
                else:
                    self._narrate("\U0001F3B2 Noise Injection — skipped this phase (random chance).")
                random.shuffle(stage_fns)
                order = " → ".join(
                    fn.__name__.replace("_step_", "").replace("_", " ").title() for fn in stage_fns)
                self._narrate(f"\U0001F500 Technique order: {order}")
                for fn in stage_fns:
                    try:
                        fn(jitter_range)
                    except Exception as exc:
                        self._narrate(f"⚠ step error (non-fatal): {exc}")
        finally:
            self._write_history()
            n, ok = len(self.steps), sum(1 for s in self.steps if s.ok)
            self._narrate(
                f"\U0001F3C1 Red Team Attack complete — {ok}/{n} steps executed. "
                "Generating the After-Action Report (brief settle window)…")
            self._running.clear()
            # Auto-clean: give the defensive stack a settle window to detect the
            # markers (matches the AAR's ~45s settle), THEN sweep every test file
            # so the drill never litters the user's Documents. Runs on a daemon
            # timer so it can't block the playbook thread from exiting.
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
        n = min(2 + level, 8)
        self._narrate(f"▶ STAGE: Benign Execution [T1059-style] — spawning {n} short-lived, "
                      "red-team-TAGGED processes (they exit immediately) so the process sensors "
                      "and SOAR see realistic process-creation activity. Nothing harmful runs.")
        spawned = 0
        for _ in range(n):
            tag = f"ANGERONA_REDTEAM_{uuid.uuid4().hex[:8]}"
            try:
                if os.name == "nt":
                    subprocess.Popen(["cmd", "/c", "rem", tag])   # no-op comment, exits
                else:
                    subprocess.Popen(["sh", "-c", ": " + tag])
                spawned += 1
            except Exception:
                pass
            time.sleep(0.2)
        self._record("Benign Execution (simulated)", "T1059 tagged spawns",
                     f"Spawned {spawned} short-lived red-team-tagged process(es).", ts)

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
    "Credential Access (simulated)": "detection",
    "Discovery": "unmonitored",
    "WMI Persistence (simulated)": "detection",
    "Defense Evasion (simulated)": "detection",
    "Noise Injection": "resilience",
}
