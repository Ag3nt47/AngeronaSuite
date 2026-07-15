"""shark_attack.py — The Shark Attack Engine.

A non-destructive, autonomous adversary-simulation harness for exercising
Angerona's own detection + response pipeline end to end, on demand, via the
"Initiate Shark Attack" button in the dashboard header.

DESIGN PHILOSOPHY — read this before changing anything
--------------------------------------------------------------------------
This is a *blind* test for the HUMAN OPERATOR and for the running modules,
in the sense that neither gets advance warning a drill is starting — but it
is NOT an evasion toolkit. Every step below performs one real, narrowly
scoped, fully reversible action using ordinary Python/OS primitives, and is
logged here in the clear. Three categories of technique from the original
request were deliberately left out of this implementation:

  * Obfuscation/encoding specifically meant to defeat signature matching
  * Fileless execution (piping decoded payloads into an interpreter's stdin)
  * LoLBin abuse, and real persistence (registry Run keys, scheduled tasks,
    Startup-folder entries)

Those are functioning evasion / attacker-tradecraft primitives independent
of how they're labeled or what they're used to test — and once written as
generic, reusable code they don't know or care that they're only "supposed"
to run against your own sandboxed instance. This project's own
``engines/__init__.py`` already made the same call about ``self_compiler.py``
("anti-pattern in a security product... tamper surface, looks like
persistence/obfuscation") — this module holds to that same line. Every
variant added below (see VARIETY ENGINE) stays inside that boundary: they
vary filenames, containers, and dressing, never the underlying signature,
and never anything that actually evades detection.

A fair test of a detector doesn't need to out-stealth it first; it needs to
perform a believable action and honestly record whether the detector
noticed. That's what every step here does:

  * Initial Access  -> drop the industry-standard, fully inert EICAR test
                        string into Downloads (the exact mechanism this
                        project's own YARA self_test() already uses).
  * Discovery        -> read-only psutil enumeration (no subprocess calls).
  * "Persistence"    -> SIMULATED ONLY. Drops a marker file in a
                        File-Integrity-Monitor-watched directory instead of
                        touching the registry, Startup folder, or Task
                        Scheduler — so the detection surface a real
                        persistence write would create is still exercised,
                        without ever creating a real persistence mechanism.
  * Noise Injection  -> a real, legitimate, CPU/IO-heavy task done entirely
                        in-process, to check the SOAR engine doesn't kill
                        ordinary heavy work.
  * Exfiltration     -> a real but harmless outbound TCP connection to a
                        domain IANA reserves for documentation/testing, with
                        a fixed dummy marker. No real data, ever.

Each step is mapped to a rough MITRE ATT&CK tactic name for the After-Action
Report. The engine never publishes to the EventBus — modules and the human
operator find out the same way they would for a real incident: by actually
noticing the file, the connection, or the process. Its own ground-truth log
(``shark_history.json``) is only read afterward, by ``aar_report.py``.

VARIETY ENGINE
--------------------------------------------------------------------------
Two independent axes of randomization make every run genuinely different,
not just cosmetically:

  1. Each stage picks one of several real, distinct VARIANTS at random (a
     different lure filename/container for Initial Access, a different
     enumeration scope for Discovery, one vs. two marker files for
     Persistence, CPU- vs. I/O-bound for Noise Injection, a different
     port/pattern for Exfiltration). These are different *mechanisms*, not
     just different random suffixes — e.g. the "zipped" Initial Access
     variant tests whether signature scanning looks inside archives at
     all, which the plain-text variant can't tell you.
  2. The STAGE ORDER itself is shuffled per run (Noise Injection's
     inclusion is still a random coin flip, same as before). Real
     intrusions don't always do reconnaissance-then-foothold-then-
     persistence-then-exfil in that exact order, and Angerona's detection
     is purely event-reactive — it should never matter what order things
     happen in. Shuffling the order is itself a test of that assumption.

The ``stage`` field recorded for each step (used by aar_report.py's
category mapping and academy's explainer dictionary) never changes across
variants — only ``technique``/``description`` and the mechanics do.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import socket
import threading
import time
import uuid
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

# The exact, industry-standard AV test string — fully inert, recognized by
# every scanner on earth, and already wired into this project's own
# rules.yar and YARA self-test (see modules/yara_scanner.py). Using the real
# EICAR marker (instead of inventing a fake "malicious-looking" string)
# makes the test genuinely safe AND genuinely realistic at the same time.
# Every Initial Access / Persistence variant below embeds this exact,
# unmodified string — only the surrounding filename/container ever varies.
EICAR_MARKER = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

# IANA-reserved domains, explicitly set aside for documentation/testing —
# never real production targets (see RFC 2606), each resolving to a distinct
# IP. A single fixed host looked safe but broke repeatability: Network
# Monitor deliberately doesn't re-alert on a host it already saw within its
# novelty window (60 min by default — see modules/network_monitor.py), so a
# second drill run within that window against the SAME host correctly stops
# generating a "first contact" alert — Network Monitor working exactly as
# designed, but it made back-to-back drills report a false Exfiltration
# miss. Picking a random one of these each run keeps drills independently
# meaningful without weakening that anti-alert-fatigue behavior at all.
# ANGERONA_SHARK_EXFIL_HOST still overrides this outright if you want a
# fixed/custom target (e.g. your own controlled listener).
EXFIL_TEST_HOSTS = ["example.com", "example.net", "example.org"]
EXFIL_TEST_PORT = int(os.environ.get("ANGERONA_SHARK_EXFIL_PORT", "443"))
EXFIL_MARKER = b"ANGERONA-SHARK-TEST-EXFIL-MARKER\n"


def _pick_exfil_host() -> str:
    override = os.environ.get("ANGERONA_SHARK_EXFIL_HOST")
    return override if override else random.choice(EXFIL_TEST_HOSTS)


def _file_has_marker(p: Path) -> bool:
    """True if p's content contains EICAR_MARKER — the single safety check
    that lets cleanup ever delete anything (see _cleanup_stale_artifacts).
    Zip archives need their own path since the marker text is compressed,
    not literally present in the raw file bytes."""
    try:
        if p.suffix.lower() == ".zip":
            with zipfile.ZipFile(p) as zf:
                for name in zf.namelist():
                    try:
                        if EICAR_MARKER in zf.read(name).decode("ascii", errors="ignore"):
                            return True
                    except Exception:
                        continue
            return False
        text = p.read_text(encoding="ascii", errors="ignore")
        # EICAR for the lure/persistence markers, plus the benign BYOVD-drill
        # marker (kept as a literal here to avoid an import cycle at module load).
        return EICAR_MARKER in text or "ANGERONA-BYOVD-DRILL-BENIGN-MARKER" in text
    except Exception:
        return False


@dataclass
class SharkStep:
    stage: str              # rough ATT&CK tactic name, for the AAR
    technique: str          # short human label
    description: str
    ts_start: float
    ts_end: float = 0.0
    artifact_paths: List[str] = field(default_factory=list)
    pid: Optional[int] = None
    detail: str = ""
    ok: bool = True


class SharkAttackEngine:
    """Runs one randomized, non-destructive playbook on a background thread.

    Deliberately does NOT publish to the EventBus — the whole point of a
    blind test is that the modules and the analyst find out the same way
    they would for a real incident: by actually noticing the artifact. The
    engine's own ground-truth log (shark_history.json) is only compared
    afterward, by aar_report.py.
    """

    def __init__(self, data_dir: Path, downloads_dir: Optional[Path] = None,
                 documents_dir: Optional[Path] = None,
                 on_complete: Optional[Callable[[List[SharkStep]], None]] = None,
                 on_event: Optional[Callable[[str], None]] = None) -> None:
        self.data_dir = Path(data_dir)
        self.history_path = self.data_dir / "shark_history.json"
        sandbox = self.data_dir / "drill-sandbox"
        self.downloads_dir = Path(downloads_dir) if downloads_dir else sandbox
        self.documents_dir = Path(documents_dir) if documents_dir else sandbox
        self._on_complete = on_complete
        # Fired for every narration line ("what, where, when") as the
        # playbook runs, so a live monitor window can show the offense side
        # in real time — separate from shark_history.json, which is only
        # read afterward for the AAR comparison.
        self._on_event = on_event
        self._thread: Optional[threading.Thread] = None
        self._running = threading.Event()
        self.run_id = ""
        self.steps: List[SharkStep] = []

    def _narrate(self, msg: str) -> None:
        if self._on_event:
            try:
                self._on_event(msg)
            except Exception:
                pass  # a misbehaving listener must never crash the drill

    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    # ── Public control ──────────────────────────────────────────────────
    def start(self, jitter_range=(2.0, 9.0), noise_chance=0.25,
              complexity=1, target_dir=None, custom=None) -> bool:
        """Kick off one randomized run on a background thread.

        complexity = number of recursive phases (Low=1, Medium=2, High=3).
        target_dir overrides where document markers land. custom = optional
        {"name", "payload"} benign technique (text written verbatim, NEVER run).
        Returns False if a run is already in progress."""
        if self.is_running:
            return False
        if target_dir:
            try:
                self.documents_dir = Path(target_dir)
            except Exception:
                pass
        self._complexity = max(1, int(complexity))
        self._custom = custom if (custom and custom.get("name") and custom.get("payload")) else None
        self.run_id = f"shark-{int(time.time())}-{uuid.uuid4().hex[:6]}"
        self.steps = []
        self._running.set()
        self._thread = threading.Thread(
            target=self._run_playbook, args=(jitter_range, noise_chance),
            name="SharkAttackEngine", daemon=True,
        )
        self._thread.start()
        return True

    def stop_and_clean(self) -> None:
        """Best-effort cleanup of anything the last run created that the SOAR
        engine hasn't already removed. Safe to call any time."""
        for step in self.steps:
            for p in step.artifact_paths:
                try:
                    Path(p).unlink(missing_ok=True)
                except Exception:
                    pass

    # Cleanup safety limits — see _cleanup_stale_artifacts() docstring for why
    # these exist: the first version of this method deleted every leftover
    # artifact at once and it backfired badly. A real run showed File
    # Integrity Monitor firing SIX simultaneous HIGH "watched file deleted"
    # alerts, which SOAR Automation correlated and AI Triage then read as
    # "a previously unknown file was unexpectedly deleted... appearing to be
    # part of a persistence mechanism; Malicious" — a false alarm that pushed
    # the live threat level to HIGH, self-inflicted by Angerona's own
    # housekeeping. FIM alerting on deletion is CORRECT behavior (ransomware/
    # wipers delete files — that's genuinely worth a HIGH alert) and must
    # not be weakened; the fix is to never give it a reason to look like a
    # mass wipe in the first place.
    _CLEANUP_MIN_AGE_S = 600   # never touch anything younger than this — keeps
                               # cleanup completely out of the way of a run
                               # that might still be inside another module's
                               # detection window
    _CLEANUP_MAX_PER_RUN = 2   # drains a backlog gradually across several
                               # drills instead of all at once
    _CLEANUP_SPACING_S = 2.0   # and even within one run, one at a time with a
                               # gap — a trickle reads nothing like a wipe

    # Every filename pattern any variant below can produce, so cleanup finds
    # all of them. Kept as one list (rather than re-deriving from the step
    # code) so it's easy to audit — and easy to extend when a new variant is
    # added.
    _CLEANUP_GLOBS = [
        # (directory attribute name, glob pattern)
        ("downloads_dir", "invoice_*.txt"),
        ("downloads_dir", "resume_*.pdf.txt"),
        ("downloads_dir", "shipping_label_*.zip"),
        ("downloads_dir", "urgent_invoice_*.html"),
        ("documents_dir", "_shark_*.txt"),
        ("documents_dir", "angerona_byovd_drill.sys"),
    ]

    def _cleanup_stale_artifacts(self) -> None:
        """Sweep up leftover marker files from PRIOR runs before this one
        starts. stop_and_clean() only knows about the run that made a given
        SharkAttackEngine instance's own self.steps, which doesn't survive
        an app restart — so without this, every drill leaves artifacts in
        Downloads/Documents behind, forever. Left unchecked, those pile up
        and YARA/FIM keep re-matching old ones on every scan, muddying every
        later status snapshot (and AAR diagnosis) with detections that
        aren't from the current run.

        Content-verified via _file_has_marker() before deleting anything —
        so this can never touch a real user file that merely happens to
        share a naming pattern. Age-gated, capped, and spaced out (see the
        constants above) so it can never itself look like the kind of mass
        file deletion a real intrusion would cause."""
        now = time.time()
        candidates: List[Path] = []
        for dir_attr, pattern in self._CLEANUP_GLOBS:
            directory = getattr(self, dir_attr)
            try:
                for p in directory.glob(pattern):
                    try:
                        if now - p.stat().st_mtime < self._CLEANUP_MIN_AGE_S:
                            continue
                        if _file_has_marker(p):
                            candidates.append(p)
                    except Exception:
                        continue
            except Exception:
                continue

        removed = 0
        for p in candidates[: self._CLEANUP_MAX_PER_RUN]:
            try:
                p.unlink()
                removed += 1
                time.sleep(self._CLEANUP_SPACING_S)
            except Exception:
                continue
        if removed:
            self._narrate(f"\U0001F9F9 Cleaned up {removed} leftover artifact(s) from "
                          "earlier drills (aged, capped, and spaced out — never the "
                          "current run's own files, never a burst).")

    # ── Playbook ─────────────────────────────────────────────────────────
    def _jitter(self, lo: float, hi: float, note: str = "") -> None:
        """Randomized sleep so steps land like background dwell time instead
        of firing in an instantly-recognizable burst. Pure timing — this
        does not itself hide anything from a detector."""
        delay = random.uniform(lo, hi)
        if note:
            self._narrate(f"⏳ Waiting {delay:.1f}s (jitter) before: {note}")
        time.sleep(delay)

    def _run_playbook(self, jitter_range, noise_chance) -> None:
        self._narrate(
            f"\U0001F988 Shark Attack {self.run_id} starting — unannounced, "
            "non-destructive. The running modules get no advance notice. Watch "
            "the main dashboard's Alerts panel and Modules table for the "
            "DEFENSE side reacting in real time — this window only narrates "
            "the OFFENSE side.")
        self._cleanup_stale_artifacts()
        try:
            # VARIETY ENGINE, axis 2: shuffle the stage order every run.
            # Angerona's detection is purely event-reactive, so it should
            # never matter what order things happen in — shuffling is
            # itself a test of that. Noise Injection's inclusion is still
            # an independent coin flip, same as before.
            cycles = getattr(self, "_complexity", 1)
            custom = getattr(self, "_custom", None)
            if cycles > 1 or custom:
                self._narrate(f"\U0001F39B️ Complexity: {cycles} phase(s)"
                              + ("; +1 custom benign technique" if custom else ""))
            for cycle in range(cycles):
                if cycles > 1:
                    self._narrate(f"\U0001F501 Phase {cycle + 1}/{cycles}.")
                stage_fns = [
                    self._step_initial_access,
                    self._step_discovery,
                    self._step_simulated_persistence,
                    self._step_simulated_byovd,
                    self._step_exfiltration,
                ]
                if custom:
                    stage_fns.append(self._step_custom)
                if random.random() < noise_chance:
                    stage_fns.append(self._step_noise_injection)
                else:
                    self._narrate("\U0001F3B2 Noise Injection — skipped this phase (random chance).")
                random.shuffle(stage_fns)
                order = " → ".join(
                    fn.__name__.replace("_step_", "").replace("_", " ").title() for fn in stage_fns)
                self._narrate(f"\U0001F500 Technique order: {order}")
                for fn in stage_fns:
                    fn(jitter_range)
        finally:
            self._write_history()
            n, ok = len(self.steps), sum(1 for s in self.steps if s.ok)
            self._narrate(
                f"\U0001F3C1 Shark Attack complete — {ok}/{n} steps executed successfully. "
                "Generating the After-Action Report (allowing modules a brief "
                "settle window to finish reacting)…")
            self._running.clear()
            if self._on_complete:
                try:
                    self._on_complete(list(self.steps))
                except Exception:
                    pass

    def _record(self, stage, technique, description, ts_start, **kw) -> SharkStep:
        step = SharkStep(stage=stage, technique=technique, description=description,
                          ts_start=ts_start, ts_end=time.time(), **kw)
        self.steps.append(step)
        return step

    # 1) Initial Access — drop a known-inert test file where the YARA
    #    scanner already looks (Downloads). VARIETY ENGINE axis 1: four
    #    real, distinct lure containers, chosen at random. The EICAR
    #    signature itself is always the same unmodified string — only the
    #    filename/container dressing changes, which is what makes the
    #    "zipped" variant a genuinely informative, different test (does
    #    signature scanning look inside archives at all?) rather than just
    #    cosmetic variety.
    def _step_initial_access(self, jitter_range) -> None:
        self._jitter(*jitter_range, note="Initial Access — drop a test file in Downloads")
        ts = time.time()
        variant = random.choice(["plain_text", "double_extension", "zipped", "html_lure"])
        try:
            self.downloads_dir.mkdir(parents=True, exist_ok=True)
            hexid = uuid.uuid4().hex[:8]
            if variant == "plain_text":
                path = self.downloads_dir / f"invoice_{hexid}.txt"
                self._narrate("▶ STAGE: Initial Access [plain text lure] — dropping an inert "
                              f"EICAR-marker test file into {self.downloads_dir} (mimics opening "
                              "a malicious email attachment).")
                path.write_text(f"{EICAR_MARKER} :: Angerona Shark Attack drill sample\n",
                               encoding="ascii")
                technique = "T1204-style file drop (plain text)"
            elif variant == "double_extension":
                path = self.downloads_dir / f"resume_{hexid}.pdf.txt"
                self._narrate("▶ STAGE: Initial Access [double-extension lure] — dropping a "
                              f"file disguised to look like a PDF into {self.downloads_dir} "
                              "(a classic real-world phishing filename trick).")
                path.write_text(f"{EICAR_MARKER} :: Angerona Shark Attack drill sample "
                               "(double-extension lure)\n", encoding="ascii")
                technique = "T1204-style file drop (double extension)"
            elif variant == "zipped":
                path = self.downloads_dir / f"shipping_label_{hexid}.zip"
                self._narrate("▶ STAGE: Initial Access [zipped lure] — dropping an EICAR-marker "
                              f"test file inside a real .zip archive into {self.downloads_dir} "
                              "(tests whether signature scanning looks inside archives).")
                with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr("shipping_label.txt",
                               f"{EICAR_MARKER} :: Angerona Shark Attack drill sample (zipped)\n")
                technique = "T1204-style file drop (zipped)"
            else:  # html_lure
                path = self.downloads_dir / f"urgent_invoice_{hexid}.html"
                self._narrate("▶ STAGE: Initial Access [HTML lure] — dropping a static "
                              f"'view invoice' page containing the EICAR marker into "
                              f"{self.downloads_dir} (no scripts, purely static text).")
                path.write_text(f"<html><body><h1>Invoice</h1><p>{EICAR_MARKER}</p>"
                               "</body></html>\n", encoding="ascii")
                technique = "T1204-style file drop (HTML lure)"
            self._narrate(f"   done — wrote {path}")
            self._record("Initial Access", technique,
                         "Dropped an inert EICAR-marker test file into Downloads, "
                         "mimicking a user opening a malicious attachment.",
                         ts, artifact_paths=[str(path)])
        except Exception as exc:
            self._narrate(f"   failed: {exc}")
            self._record("Initial Access", "T1204-style file drop", f"failed: {exc}", ts, ok=False)

    # 2) Discovery — purely read-only enumeration via psutil. No subprocess
    #    calls, no LoLBins; this is the same kind of data the Process and
    #    Network modules already read every cycle. VARIETY ENGINE axis 1:
    #    three different enumeration scopes.
    def _step_discovery(self, jitter_range) -> None:
        self._jitter(*jitter_range, note="Discovery — read-only enumeration")
        ts = time.time()
        variant = random.choice(["process_net", "system_info", "net_interfaces"])
        try:
            if not psutil:
                raise RuntimeError("psutil not installed")
            n_proc, n_conn = len(psutil.pids()), len(psutil.net_connections())
            if variant == "process_net":
                self._narrate("▶ STAGE: Discovery [process/connection enumeration] — reading "
                              "the local process and connection tables in-process via psutil.")
                detail = f"{n_proc} processes and {n_conn} connections"
                technique = "T1057 / T1049 enumeration"
            elif variant == "system_info":
                n_users = len(psutil.users())
                self._narrate("▶ STAGE: Discovery [system/owner enumeration] — reading process, "
                              "connection, and logged-in-user tables in-process via psutil.")
                detail = f"{n_proc} processes, {n_conn} connections, {n_users} logged-in session(s)"
                technique = "T1057 / T1049 / T1033 enumeration"
            else:  # net_interfaces
                n_if = len(psutil.net_if_addrs())
                self._narrate("▶ STAGE: Discovery [network topology enumeration] — reading "
                              "process, connection, and network-interface tables via psutil.")
                detail = f"{n_proc} processes, {n_conn} connections, {n_if} network interface(s)"
                technique = "T1057 / T1049 / T1016 enumeration"
            self._narrate(f"   done — read {detail}.")
            self._record("Discovery", technique,
                         f"Enumerated {detail} (read-only; nothing is written or transmitted).", ts)
        except Exception as exc:
            self._narrate(f"   failed: {exc}")
            self._record("Discovery", "T1057 / T1049 enumeration", f"failed: {exc}", ts, ok=False)

    # 3) "Persistence" — SIMULATED ONLY. We deliberately do not touch the
    #    registry, Startup folder, or Task Scheduler. Instead we drop
    #    marker file(s) into Documents, which IS one of File Integrity
    #    Monitor's watched directories — so the detection surface a real
    #    persistence write would create is still exercised, without ever
    #    creating a real persistence mechanism. VARIETY ENGINE axis 1:
    #    one vs. two markers, and startup-suggestive naming.
    def _step_simulated_persistence(self, jitter_range) -> None:
        self._jitter(*jitter_range, note="Persistence (simulated) — marker file only, no real autorun")
        ts = time.time()
        variant = random.choice(["single_marker", "double_marker", "renamed_lure"])
        try:
            self.documents_dir.mkdir(parents=True, exist_ok=True)
            body = (f"{EICAR_MARKER} :: simulated persistence artifact "
                   "(NOT a real autorun, registry, or scheduled-task entry)\n")
            paths: List[Path] = []
            if variant == "single_marker":
                self._narrate("▶ STAGE: Persistence (SIMULATED) [single marker] — dropping one "
                              f"marker file in {self.documents_dir}. The registry, Startup "
                              "folder, and Task Scheduler are never touched.")
                p = self.documents_dir / f"_shark_persistence_marker_{uuid.uuid4().hex[:8]}.txt"
                p.write_text(body, encoding="ascii")
                paths.append(p)
                technique = "T1547-style marker only (single)"
            elif variant == "double_marker":
                self._narrate("▶ STAGE: Persistence (SIMULATED) [double marker] — dropping TWO "
                              f"marker files in {self.documents_dir} (a slightly more aggressive "
                              "dropper leaves multiple artifacts). The registry, Startup folder, "
                              "and Task Scheduler are never touched.")
                for _ in range(2):
                    p = self.documents_dir / f"_shark_persistence_marker_{uuid.uuid4().hex[:8]}.txt"
                    p.write_text(body, encoding="ascii")
                    paths.append(p)
                technique = "T1547-style marker only (double)"
            else:  # renamed_lure
                name = random.choice(["system_update_helper", "startup_cache_sync", "app_launch_assist"])
                self._narrate("▶ STAGE: Persistence (SIMULATED) [startup-suggestive naming] — "
                              "dropping a marker file named like a plausible startup helper in "
                              f"{self.documents_dir}. The registry, Startup folder, and Task "
                              "Scheduler are never touched.")
                p = self.documents_dir / f"_shark_{name}_{uuid.uuid4().hex[:8]}.txt"
                p.write_text(body, encoding="ascii")
                paths.append(p)
                technique = "T1547-style marker only (startup-suggestive name)"
            self._narrate("   done — wrote " + ", ".join(str(p) for p in paths))
            self._record("Persistence (simulated)", technique,
                         "Dropped a marker file in a File-Integrity-Monitor-watched "
                         "directory to test detection — no real autorun mechanism "
                         "was ever touched.", ts, artifact_paths=[str(p) for p in paths])
        except Exception as exc:
            self._narrate(f"   failed: {exc}")
            self._record("Persistence (simulated)", "T1547-style marker only", f"failed: {exc}", ts, ok=False)

    # 3b) "BYOVD" driver drop — SIMULATED ONLY. Writes ONE benign marker file
    #     named like a kernel driver into a File-Integrity-Monitor-watched
    #     directory. No real .sys is ever created, loaded, or registered as a
    #     service — the marker exists solely to exercise the Ring 1 Driver-Intel
    #     Shield (FIM ↔ INTL) end to end. The filename/marker come straight from
    #     intel_sync so the defender recognises them.
    def _step_simulated_byovd(self, jitter_range) -> None:
        self._jitter(*jitter_range,
                     note="BYOVD (simulated) — benign driver-named marker, nothing loaded")
        ts = time.time()
        try:
            from angerona.modules.intel_sync import BYOVD_DRILL_DRIVER, BYOVD_DRILL_MARKER
            self.documents_dir.mkdir(parents=True, exist_ok=True)
            self._narrate(
                "▶ STAGE: BYOVD (SIMULATED) — writing a benign marker file named like a kernel "
                f"driver ({BYOVD_DRILL_DRIVER}) into {self.documents_dir}, mimicking a vulnerable-"
                "driver drop + 'sc.exe create' registration. No real .sys is created, loaded, or "
                "registered — this only tests whether the Ring 1 Driver-Intel Shield intercepts it.")
            p = self.documents_dir / BYOVD_DRILL_DRIVER
            p.write_text(f"{BYOVD_DRILL_MARKER} :: simulated BYOVD driver drop "
                         "(benign -- NOT a real driver, never loaded)\n", encoding="utf-8")
            self._narrate(f"   done — wrote {p} (simulated driver-registration telemetry)")
            self._record("BYOVD (simulated)",
                         "T1068 / T1543.003-style driver drop (marker only)",
                         "Wrote a benign driver-named marker into a FIM-watched directory to test "
                         "the Driver-Intel Shield — no real driver was created, loaded, or "
                         "registered.", ts, artifact_paths=[str(p)])
        except Exception as exc:
            self._narrate(f"   failed: {exc}")
            self._record("BYOVD (simulated)", "T1068-style driver drop (marker only)",
                         f"failed: {exc}", ts, ok=False)

    # 3c) Custom technique — user-defined, benign. The operator-supplied text is
    #     written verbatim to an INERT marker file (never executed/interpreted),
    #     so the defensive stack can be tested against arbitrary content the user
    #     wants to try — without ever running it.
    def _step_custom(self, jitter_range) -> None:
        self._jitter(*jitter_range, note="Custom technique — user-defined benign marker")
        ts = time.time()
        c = getattr(self, "_custom", None) or {}
        name = str(c.get("name", "custom"))
        payload = str(c.get("payload", ""))
        hexid = uuid.uuid4().hex[:8]
        safe = "".join(ch for ch in name if ch.isalnum() or ch in "-_")[:40] or "custom"
        try:
            self.documents_dir.mkdir(parents=True, exist_ok=True)
            self._narrate(f"▶ STAGE: Custom [user-defined: {name}] — writing the text you supplied "
                          f"as an INERT marker into {self.documents_dir}. It is written verbatim and "
                          "never executed — this tests content detection only.")
            p = self.documents_dir / f"_shark_custom_{safe}_{hexid}.txt"
            p.write_text(f"ANGERONA custom drill marker — INERT, never executed.\n"
                         f"Technique: {name}\n---\n{payload}\n", encoding="utf-8")
            self._record("Custom (simulated)", f"user-defined: {name}",
                         "User-defined benign marker written (content only, never executed).",
                         ts, artifact_paths=[str(p)])
        except Exception as exc:
            self._narrate(f"   failed: {exc}")
            self._record("Custom (simulated)", f"user-defined: {name}", f"failed: {exc}", ts, ok=False)

    # 4) Noise injection — a real, fully legitimate, CPU/IO-heavy task.
    #    Nothing about any variant resembles malware; the point is purely
    #    to check that the SOAR engine doesn't wrongly kill ordinary heavy
    #    work. VARIETY ENGINE axis 1: I/O-heavy, CPU-only, and many-small-
    #    files — three genuinely different resource profiles.
    def _step_noise_injection(self, jitter_range) -> None:
        self._jitter(*jitter_range, note="Noise Injection — legitimate heavy CPU/IO task")
        ts = time.time()
        variant = random.choice(["io_heavy", "cpu_heavy", "many_small_files"])
        try:
            if variant == "io_heavy":
                tmp = self.data_dir / f"_shark_noise_{uuid.uuid4().hex[:8]}.zip"
                self._narrate(f"▶ STAGE: Noise Injection [I/O-heavy] — hashing + zipping 8MB of "
                              f"throwaway in-memory data to {tmp}.")
                blob = os.urandom(8_000_000)
                h = hashlib.sha256()
                with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
                    for i in range(8):
                        chunk = blob[i * 1_000_000:(i + 1) * 1_000_000]
                        h.update(chunk)
                        zf.writestr(f"chunk_{i}.bin", chunk)
                self._narrate(f"   done — wrote {tmp} (sha256 {h.hexdigest()[:16]}…)")
                technique, paths, detail = "false-positive resilience check (I/O-heavy)", [str(tmp)], h.hexdigest()[:16]
            elif variant == "cpu_heavy":
                self._narrate("▶ STAGE: Noise Injection [CPU-heavy] — running a tight, pure-CPU "
                              "hashing loop for a few seconds (no disk I/O at all) — checks the "
                              "SOAR engine doesn't overreact to a CPU spike alone.")
                start, n = time.time(), 0
                h = hashlib.sha256(b"angerona-shark-cpu-noise")
                while time.time() - start < 3.0:
                    h.update(h.digest())
                    n += 1
                self._narrate(f"   done — {n} hash iterations in ~3s, purely in-process.")
                technique, paths, detail = "false-positive resilience check (CPU-heavy)", [], f"{n} iters"
            else:  # many_small_files
                scratch = self.data_dir / f"_shark_noise_scratch_{uuid.uuid4().hex[:8]}"
                self._narrate("▶ STAGE: Noise Injection [I/O churn] — writing and deleting many "
                              f"small throwaway files in {scratch} (simulates a build tool/"
                              "installer's file churn) — checks the SOAR engine doesn't "
                              "overreact to burst I/O alone.")
                scratch.mkdir(parents=True, exist_ok=True)
                for i in range(200):
                    (scratch / f"chunk_{i}.tmp").write_bytes(os.urandom(4096))
                for f in scratch.glob("*.tmp"):
                    f.unlink(missing_ok=True)
                scratch.rmdir()
                self._narrate("   done — 200 small files written + deleted.")
                technique, paths, detail = "false-positive resilience check (I/O churn)", [], "200 files"
            self._record("Noise Injection", technique,
                         "Ran a legitimate CPU/IO-heavy task to verify the SOAR engine doesn't "
                         "kill safe heavy work.", ts, artifact_paths=paths, detail=detail)
        except Exception as exc:
            self._narrate(f"   failed: {exc}")
            self._record("Noise Injection", "false-positive resilience check", f"failed: {exc}", ts, ok=False)

    # 5) Exfiltration — a real but harmless outbound TCP connection to a
    #    domain IANA reserves specifically for documentation/testing, with a
    #    fixed dummy marker (never real data). Tests whether Network
    #    Monitor's new-external-connection detection notices it. VARIETY
    #    ENGINE axis 1: held connection on 443, held connection on 80, or
    #    a short burst of 3 sequential connections.
    #
    #    HOLD_OPEN_S: Network Monitor polls psutil.net_connections() every 4s
    #    and only counts connections currently in ESTABLISHED state (see
    #    modules/network_monitor.py). A connect-send-close done as fast as
    #    Python can do it typically completes in well under 100ms — that's
    #    faster than any interval-based poller can realistically observe,
    #    so the connection was effectively invisible before this fix (a real
    #    AAR run showed 0/5 detected, including this step, even though
    #    Network Monitor's novel-host detector is otherwise working fine).
    #    Holding the socket open for a few seconds isn't hiding anything —
    #    if anything it's the opposite of evasion — it just gives the poller
    #    a fair, realistic window to see what a real exfil connection
    #    (which stays open at least as long as the upload takes) would.
    #    6s (> one 4s poll period) should mathematically guarantee overlap
    #    against perfectly periodic polling, but a real run still missed —
    #    list_connections() does a full system-wide psutil scan every cycle,
    #    and its actual duration (plus scheduler jitter) can push the real
    #    inter-poll gap noticeably past 4s on a busy machine. 9s keeps a
    #    much wider safety margin without meaningfully lengthening the drill.
    HOLD_OPEN_S = 9.0

    def _step_exfiltration(self, jitter_range) -> None:
        self._jitter(*jitter_range, note="Exfiltration — outbound test connection")
        ts = time.time()
        host = _pick_exfil_host()
        variant = random.choice(["held_443", "held_80", "burst"])
        try:
            if variant == "burst":
                port = EXFIL_TEST_PORT
                self._narrate(f"▶ STAGE: Exfiltration [burst] — opening 3 short sequential "
                              f"outbound connections to {host}:{port} (simulates chunked "
                              "exfiltration).")
                for i in range(3):
                    with socket.create_connection((host, port), timeout=5) as s:
                        try:
                            s.sendall(EXFIL_MARKER)
                        except OSError:
                            pass
                        time.sleep(2.5)
                    self._narrate(f"   chunk {i + 1}/3 sent, connection closed.")
                    if i < 2:
                        time.sleep(1.0)
                self._narrate("   done.")
                technique = "T1041-style outbound test (burst)"
                desc = (f"Opened 3 short sequential outbound connections to {host}:{port} and "
                       "sent fixed dummy markers — no real data of any kind.")
            else:
                port = 80 if variant == "held_80" else EXFIL_TEST_PORT
                self._narrate(f"▶ STAGE: Exfiltration [held connection, port {port}] — opening "
                              f"a real outbound connection to {host}:{port} (IANA's reserved "
                              "test/documentation domain) and sending a fixed dummy marker. No "
                              "real data of any kind is ever read or transmitted.")
                with socket.create_connection((host, port), timeout=5) as s:
                    try:
                        s.sendall(EXFIL_MARKER)
                    except OSError:
                        pass  # the test host closing the connection is fine — TCP handshake already happened
                    self._narrate(f"   connected to {host}:{port}, holding the connection open "
                                  f"{self.HOLD_OPEN_S:.0f}s so Network Monitor's poller has a "
                                  "fair window to observe it.")
                    time.sleep(self.HOLD_OPEN_S)
                self._narrate("   done — connection closed.")
                technique = f"T1041-style outbound test (held, port {port})"
                desc = (f"Opened a real outbound connection to {host}:{port} and sent a fixed "
                       "dummy marker — no real data of any kind.")
            self._record("Exfiltration", technique, desc, ts, pid=os.getpid())
        except Exception as exc:
            self._narrate(f"   failed: {exc}")
            self._record("Exfiltration", "T1041-style outbound test", f"failed: {exc}", ts, ok=False)

    # ── Logging ──────────────────────────────────────────────────────────
    def _write_history(self) -> None:
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            payload = {
                "run_id": self.run_id,
                "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
                "steps": [asdict(s) for s in self.steps],
            }
            self.history_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception:
            pass
