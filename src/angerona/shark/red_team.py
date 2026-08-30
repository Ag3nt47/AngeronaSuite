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
import copy
import hashlib
import os
import random
import stat
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

from angerona.core.practice_scope import (
    register_artifact,
    register_process,
    register_run,
    unregister_run,
)
from angerona.modules.purple_guard import (
    RedTeamValidationError,
    RedTeamValidationLease,
)
from angerona.shark.run_manifest import (
    RED_TEAM_COMPREHENSIVE_PLAN,
    build_run_history,
    expected_red_team_plan,
    preflight_run,
    write_run_history,
)

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
    "_step_initial_access", "_step_public_facing_app", "_step_recon",
    "_step_account_discovery", "_step_network_service_discovery",
    "_step_network_connections_discovery", "_step_software_discovery",
    "_step_credential_access", "_step_credential_store",
    "_step_unsecured_credentials", "_step_user_execution",
    "_step_random_processes", "_step_privilege_escalation",
    "_step_exploitation_privilege", "_step_registry_runkey",
    "_step_scheduled_task", "_step_wmi_persistence", "_step_create_account",
    "_step_web_shell", "_step_dll_side_loading", "_step_defense_evasion",
    "_step_obfuscated_files", "_step_masquerading", "_step_impair_defenses",
    "_step_lateral_movement", "_step_remote_desktop", "_step_wmi_lateral",
    "_step_c2_beacon", "_step_tool_transfer", "_step_protocol_tunneling",
    "_step_automated_collection", "_step_local_data", "_step_exfil_staging",
    "_step_exfil_c2", "_step_exfil_web_service", "_step_ransomware_canary",
    "_step_inhibit_recovery", "_step_data_destruction",
]

_COMPREHENSIVE_PROBES = {
    str(row["key"]): dict(row) for row in RED_TEAM_COMPREHENSIVE_PLAN
}


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
    cycle: int = 0
    plan_step_id: str = ""


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
        self.default_documents_dir = (
            Path(documents_dir) if documents_dir else self.data_dir / "drill-sandbox"
        ).resolve(strict=False)
        self.documents_dir = self.default_documents_dir
        self._on_event = on_event
        self._thread: Optional[threading.Thread] = None
        self._running = threading.Event()
        self._cancel = threading.Event()
        self._cleanup_lock = threading.RLock()
        self._cleanup_timer: Optional[threading.Timer] = None
        self._cleanup_generation = 0
        self._evidence_lease = False
        self._probe_processes: List[object] = []
        self._owned_artifacts: List[Path] = []
        self._last_run_target = self.default_documents_dir
        self._validation_readiness: dict = {}
        self._validation_lease: RedTeamValidationLease | None = None
        self.run_id = ""
        self.steps: List[RedTeamStep] = []
        self._active_plan_entry: dict[str, object] | None = None

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
        plan_entry = self._active_plan_entry or {}
        kw.setdefault("cycle", int(plan_entry.get("cycle", 0) or 0))
        kw.setdefault("plan_step_id", str(plan_entry.get("plan_step_id") or ""))
        step = RedTeamStep(stage=stage, technique=technique, description=description,
                           ts_start=ts_start, ts_end=time.time(), **kw)
        self.steps.append(step)
        for path in step.artifact_paths:
            register_artifact(path, self.run_id, kind="red-team")
        for token in step.correlation_tokens:
            register_process(token, self.run_id, kind="red-team")
        return step

    def _marker(self, name: str, body: str) -> Path:
        if self._cancel.is_set():
            raise _DrillCancelled()
        lease = self._validation_lease
        if type(lease) is RedTeamValidationLease:
            RedTeamValidationLease.assert_target_identity(
                lease, run_id=self.run_id
            )
        self.documents_dir.mkdir(parents=True, exist_ok=True)
        p = self.documents_dir / name
        encoded = body.encode("utf-8")
        descriptor: int | None = None
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            if os.name == "nt":
                import msvcrt

                create_file = ctypes.windll.kernel32.CreateFileW
                create_file.argtypes = [
                    ctypes.c_wchar_p,
                    ctypes.c_uint32,
                    ctypes.c_uint32,
                    ctypes.c_void_p,
                    ctypes.c_uint32,
                    ctypes.c_uint32,
                    ctypes.c_void_p,
                ]
                create_file.restype = ctypes.c_void_p
                raw_handle = create_file(
                    str(p),
                    0x80000000 | 0x40000000 | 0x00010000,
                    0x1 | 0x2 | 0x4,
                    None,
                    1,  # CREATE_NEW
                    0x00200000,  # FILE_FLAG_OPEN_REPARSE_POINT
                    None,
                )
                invalid = ctypes.c_void_p(-1).value
                if raw_handle in (None, invalid):
                    error = int(ctypes.windll.kernel32.GetLastError())
                    if error in {80, 183} or p.exists():
                        raise FileExistsError(error, "marker already exists", str(p))
                    raise OSError(error, "exclusive marker creation failed", str(p))
                try:
                    descriptor = msvcrt.open_osfhandle(
                        int(raw_handle), os.O_RDWR | getattr(os, "O_BINARY", 0)
                    )
                except Exception:
                    ctypes.windll.kernel32.CloseHandle(
                        ctypes.c_void_p(raw_handle)
                    )
                    raise
            else:
                descriptor = os.open(p, flags, 0o600)
            created = os.fstat(descriptor)
            if (
                not stat.S_ISREG(created.st_mode)
                or int(getattr(created, "st_nlink", 1)) != 1
                or bool(getattr(created, "st_file_attributes", 0) & 0x400)
            ):
                raise RedTeamValidationError(
                    "marker creation did not yield one regular single-link file"
                )
            # Ownership begins only after exclusive creation proved that this
            # exact leaf did not pre-exist. Real-time AV/FIM can then resolve
            # provenance before the first content byte is written, without a
            # failed O_EXCL attempt ever granting cleanup authority over an
            # attacker-planted alias.
            register_artifact(p, self.run_id, kind="red-team")
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                if written <= 0:
                    raise OSError("marker write made no progress")
                offset += written
            os.fsync(descriptor)
            after = os.fstat(descriptor)
            path_stat = p.stat(follow_symlinks=False)
            if (
                (created.st_dev, created.st_ino)
                != (after.st_dev, after.st_ino)
                or (after.st_dev, after.st_ino)
                != (path_stat.st_dev, path_stat.st_ino)
                or int(getattr(after, "st_nlink", 1)) != 1
                or int(getattr(path_stat, "st_nlink", 1)) != 1
                or int(after.st_size) != len(encoded)
            ):
                raise RedTeamValidationError(
                    "marker identity changed during exclusive creation"
                )
            if type(lease) is RedTeamValidationLease:
                RedTeamValidationLease.register_artifact_handle(
                    lease, p, run_id=self.run_id
                )
            self._owned_artifacts.append(p)
        finally:
            if descriptor is not None:
                os.close(descriptor)
        _hide_file(p)
        return p

    def _artifact_paths_snapshot(self) -> tuple[Path, ...]:
        values = [Path(path) for path in tuple(self._owned_artifacts)]
        values.extend(
            Path(path)
            for step in tuple(self.steps)
            for path in tuple(step.artifact_paths)
        )
        return tuple(dict.fromkeys(values))

    def _sweep_markers(
        self,
        *,
        target_dir: Path | None = None,
        artifact_paths: tuple[Path, ...] | None = None,
    ) -> int:
        """Delete only exact in-memory drill artifacts from the owning run.

        Filename patterns never grant deletion authority. After a crash, an
        untracked marker is left for operator review rather than risking an
        unrelated user file in Documents or another selected target.
        """
        removed = 0
        try:
            target = Path(target_dir or self._last_run_target).resolve(strict=False)
        except (OSError, RuntimeError):
            return 0
        tracked = (
            artifact_paths
            if artifact_paths is not None
            else self._artifact_paths_snapshot()
        )
        # 1) tracked per-step artifacts
        seen: set[Path] = set()
        for value in tracked:
            try:
                path = Path(value).resolve(strict=False)
                if (
                    path in seen
                    or path.parent != target
                    or not path.name.startswith(_MARKER_PREFIX)
                ):
                    continue
                seen.add(path)
                lease = self._validation_lease
                if type(lease) is RedTeamValidationLease:
                    if RedTeamValidationLease.remove_registered_artifact(
                        lease, path, run_id=self.run_id
                    ):
                        removed += 1
                    # Never fall back to pathname-only deletion while an
                    # evidence lease exists; a failed identity check is a
                    # refusal, not permission to unlink whatever is there.
                    continue
                if path.exists():
                    path.unlink(missing_ok=True)
                    removed += 1
            except Exception:
                pass
        if removed:
            self._narrate(f"🧹 Red Team cleanup — removed {removed} test marker/file(s).")
        return removed

    def _cancel_pending_cleanup(self) -> None:
        """Invalidate and cancel cleanup scheduled by a completed prior run."""
        with self._cleanup_lock:
            self._cleanup_generation += 1
            timer = self._cleanup_timer
            self._cleanup_timer = None
            if timer is not None:
                timer.cancel()

    def hold_evidence_for_aar(self) -> None:
        """Prevent successful-run cleanup until the owning AAR snapshots it."""
        self._cancel_pending_cleanup()
        with self._cleanup_lock:
            self._evidence_lease = True

    def cancel_evidence_hold(self) -> bool:
        """Cancel a pre-start AAR hold after a refused launch.

        This deliberately does not sweep paths or unregister an older run.  A
        failed ``start()`` has no new ownership and therefore must not operate
        on evidence left by a prior run.
        """
        with self._cleanup_lock:
            worker = self._thread
            if self.is_running or (worker is not None and worker.is_alive()):
                return False
            self._evidence_lease = False
            return True

    def evidence_cleanup_scope(self) -> dict:
        """Capture immutable cleanup ownership for the currently completed run."""
        return {
            "run_id": str(self.run_id or ""),
            "target_dir": Path(self._last_run_target).resolve(strict=False),
            "artifact_paths": self._artifact_paths_snapshot(),
        }

    def release_evidence_after_aar(self, scope: dict | None = None) -> int:
        """Clean only one captured run after its AAR finished (success or error)."""
        captured = dict(scope or self.evidence_cleanup_scope())
        run_id = str(captured.get("run_id") or "")
        target = Path(captured.get("target_dir") or self.documents_dir)
        artifacts = tuple(Path(p) for p in captured.get("artifact_paths") or ())
        with self._cleanup_lock:
            self._evidence_lease = False
        removed = self._sweep_markers(
            target_dir=target,
            artifact_paths=artifacts,
        )
        self._cleanup_probe_processes()
        if run_id:
            unregister_run(run_id)
        return removed

    def _cleanup_probe_processes(self) -> None:
        """Bound cancellation cleanup to children spawned by this engine."""
        processes, self._probe_processes = self._probe_processes, []
        for process in processes:
            try:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=1.0)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass

    def _schedule_cleanup(
        self,
        delay: float,
        target_dir: Path,
        artifact_paths: tuple[Path, ...],
    ) -> None:
        """Schedule cleanup bound to one run's immutable target and paths."""
        target = Path(target_dir).resolve(strict=False)
        captured = tuple(Path(path).resolve(strict=False) for path in artifact_paths)
        captured_run_id = str(self.run_id or "")
        with self._cleanup_lock:
            self._cleanup_generation += 1
            generation = self._cleanup_generation
            previous = self._cleanup_timer
            if previous is not None:
                previous.cancel()

            def clean_originating_run() -> None:
                # Holding this lock through deletion serializes cleanup with a
                # new run's cancellation/pre-clean boundary. Once start() gets
                # past cancellation, a stale callback cannot resume later.
                with self._cleanup_lock:
                    if generation != self._cleanup_generation:
                        return
                    self._cleanup_timer = None
                    self._sweep_markers(
                        target_dir=target,
                        artifact_paths=captured,
                    )
                    if captured_run_id:
                        unregister_run(captured_run_id)

            timer = threading.Timer(max(0.0, float(delay)), clean_originating_run)
            timer.daemon = True
            self._cleanup_timer = timer
            timer.start()

    # ── control ────────────────────────────────────────────────────────────
    def start(self, jitter_range=(2.0, 7.0), noise_chance=0.25,
              complexity=1, target_dir=None, custom=None,
              intensity=None, campaign=False, comprehensive=False,
              readiness_receipt: Optional[dict] = None,
              validation_lease: object | None = None) -> bool:
        """Run a randomized Red Team playbook.

        intensity — one of Low/Medium/High/Extreme. When given it drives cycles,
          jitter, noise, threat level and process count (overrides complexity).
        campaign  — when True the techniques run in a chained ATT&CK kill-chain
          order (recon → access → persist → C2 → exfil → impact) instead of the
          default per-phase shuffle, modelling a coherent operation.
        comprehensive — add one bounded first-phase pass through the expanded
          fixed marker catalog. Every added behavior is inert and locally
          reversible; later phases repeat only the stable base inventory.
        complexity — legacy phase count, used when intensity is not supplied.
        target_dir — where benign markers land. custom = optional benign
          {"name","payload"} technique (written verbatim, NEVER executed).
        """
        if self.is_running or (self._thread is not None and self._thread.is_alive()):
            return False
        self._cancel.clear()
        # A custom target applies to one run only.  Falling back to the mutable
        # previous ``documents_dir`` made a later default launch silently reuse
        # an earlier custom path.
        candidate_target = (
            target_dir if target_dir is not None else self.default_documents_dir
        )
        preset = INTENSITY_LEVELS.get(str(intensity)) if intensity else None
        if preset:
            self._complexity = preset["cycles"]
            self._threat_level = preset["threat"]
            self._proc_mult = preset["proc_mult"]
            jitter_range = preset["jitter"]
            noise_chance = preset["noise"]
            self._intensity = str(intensity)
        else:
            # Validation and normalization happen in the safety preflight below.
            self._complexity = complexity
            self._threat_level = 1
            self._proc_mult = 1
            self._intensity = f"complexity={complexity}"
        preflight = preflight_run(
            kind="red_team",
            cycles=self._complexity,
            jitter_range=jitter_range,
            noise_chance=noise_chance,
            target_dir=candidate_target,
            custom=custom,
            campaign=bool(campaign),
            comprehensive=bool(comprehensive),
        )
        if not preflight.accepted:
            self._narrate(
                "Red Team drill refused by the safety contract: "
                + "; ".join(preflight.violations)
            )
            return False
        resolved_target = Path(candidate_target).resolve(strict=False)
        proposed_run_id = f"redteam-{int(time.time())}-{uuid.uuid4().hex[:6]}"
        if readiness_receipt is not None:
            self._narrate(
                "Red Team drill refused: legacy caller-supplied readiness receipts "
                "are not authoritative; acquire a live validation lease."
            )
            return False
        try:
            if type(validation_lease) is not RedTeamValidationLease:
                raise RedTeamValidationError(
                    "an exact live Red Team validation lease is required"
                )
            receipt = RedTeamValidationLease.consume_for_run(
                validation_lease,
                run_id=proposed_run_id,
                target=resolved_target,
                data_root=self.data_dir,
                run_ttl_seconds=float(
                    preflight.budget.get("admitted_run_ttl_seconds", 0)
                ),
            )
        except (RedTeamValidationError, OSError, RuntimeError, ValueError) as exc:
            self._narrate(f"Red Team drill refused: {exc}")
            return False
        # A completed run may still own a delayed cleanup callback. Cancel it
        # before changing shared run state or creating any marker for this run.
        prior_run_id = str(self.run_id or "")
        prior_artifacts = self._artifact_paths_snapshot()
        prior_target = Path(self._last_run_target).resolve(strict=False)
        self._cancel_pending_cleanup()
        self.documents_dir = resolved_target
        self._last_run_target = self.documents_dir
        self._run_contract = preflight
        self._complexity = preflight.cycles
        if not preset:
            self._threat_level = preflight.cycles
        jitter_range = preflight.jitter
        noise_chance = preflight.noise_chance
        self._campaign = bool(campaign)
        self._comprehensive = bool(preflight.comprehensive)
        self._expected_plan = expected_red_team_plan(preflight.as_dict())
        self._custom = (
            {
                "name": str(custom["name"]).strip(),
                "payload": str(custom["payload"]),
            }
            if preflight.custom is not None else None
        )
        self.run_id = proposed_run_id
        self._validation_readiness = receipt
        self._validation_lease = validation_lease
        register_run(self.run_id, kind="red-team")
        self.steps = []
        self._owned_artifacts = []
        # Pre-clean only exact artifacts still owned by this engine instance.
        # Crash-orphan prefix globs are deliberately forbidden: the selected
        # target may be Documents and names are not deletion provenance.
        self._sweep_markers(
            target_dir=prior_target,
            artifact_paths=prior_artifacts,
        )
        if prior_run_id:
            unregister_run(prior_run_id)
        self._running.set()
        self._thread = threading.Thread(
            target=self._run_playbook, args=(jitter_range, noise_chance),
            name="RedTeamEngine", daemon=True)
        try:
            self._thread.start()
        except (RuntimeError, OSError) as exc:
            self._running.clear()
            unregister_run(self.run_id)
            self.documents_dir = self.default_documents_dir
            try:
                RedTeamValidationLease.release(validation_lease)
            except Exception:
                pass
            self._validation_lease = None
            self._narrate(
                "Red Team drill refused: worker launch failed: "
                f"{type(exc).__name__}: {exc}"
            )
            return False
        return True

    def stop_and_clean(self) -> None:
        self._cancel_pending_cleanup()
        self._cancel.set()
        self._running.clear()
        worker = self._thread
        if worker is not None and worker.is_alive() and worker is not threading.current_thread():
            worker.join(timeout=0.25)
        self._sweep_markers(
            target_dir=self._last_run_target,
            artifact_paths=self._artifact_paths_snapshot(),
        )
        self._cleanup_probe_processes()
        unregister_run(self.run_id)

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
        comprehensive = getattr(self, "_comprehensive", False)
        self._narrate(f"\U0001F39B️ Intensity: {getattr(self,'_intensity','?')}; "
                      f"{cycles} phase(s); {'CAMPAIGN (chained kill-chain)' if campaign else 'randomized'}; "
                      f"catalog={'comprehensive' if comprehensive else 'base'}; "
                      f"target={self.documents_dir}" + ("; +1 custom benign technique" if custom else ""))
        cancelled = False
        plan_by_cycle_key = {
            (int(row["cycle"]), str(row["key"])): row
            for row in getattr(self, "_expected_plan", ())
        }
        function_plan_keys = {
            "_step_initial_access": "initial_access",
            "_step_recon": "discovery",
            "_step_credential_access": "credential_access",
            "_step_privilege_escalation": "privilege_escalation",
            "_step_defense_evasion": "defense_evasion",
            "_step_registry_runkey": "registry_runkey",
            "_step_scheduled_task": "scheduled_task",
            "_step_wmi_persistence": "wmi_persistence",
            "_step_lateral_movement": "lateral_movement",
            "_step_c2_beacon": "c2_beacon",
            "_step_exfil_staging": "exfil_staging",
            "_step_ransomware_canary": "ransomware_canary",
            "_step_data_destruction": "data_destruction",
            "_step_random_processes": "random_processes",
            "_step_custom": "custom",
        }
        function_plan_keys.update({
            f"_step_{key}": key for key in _COMPREHENSIVE_PROBES
        })
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
                if comprehensive and cycle == 0:
                    stage_fns.extend(
                        getattr(self, f"_step_{key}")
                        for key in _COMPREHENSIVE_PROBES
                    )
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
                    plan_key = function_plan_keys.get(fn.__name__, "")
                    if fn.__name__ == "_step_noise":
                        self._active_plan_entry = {
                            "cycle": cycle + 1,
                            "plan_step_id": (
                                f"RTP1-C{cycle + 1:02d}-NOISE"
                            ),
                        }
                    else:
                        self._active_plan_entry = plan_by_cycle_key.get(
                            (cycle + 1, plan_key)
                        )
                    before = len(self.steps)
                    try:
                        fn(jitter_range)
                    except _DrillCancelled:
                        raise
                    except Exception as exc:
                        self._narrate(f"⚠ mandatory step failed: {exc}")
                        if len(self.steps) == before and self._active_plan_entry:
                            expected = self._active_plan_entry
                            self._record(
                                str(expected.get("stage") or fn.__name__),
                                str(expected.get("technique") or "failed probe"),
                                "Mandatory inert simulation step failed before completion.",
                                time.time(),
                                detail=f"{type(exc).__name__}: {exc}"[:500],
                                ok=False,
                            )
                    else:
                        if len(self.steps) == before and self._active_plan_entry:
                            expected = self._active_plan_entry
                            self._record(
                                str(expected.get("stage") or fn.__name__),
                                str(expected.get("technique") or "missing probe"),
                                "Mandatory inert simulation step returned without evidence.",
                                time.time(),
                                detail="step returned without recording its mandatory result",
                                ok=False,
                            )
                    finally:
                        self._active_plan_entry = None
                    if self._cancel.is_set():
                        raise _DrillCancelled()
        except _DrillCancelled:
            cancelled = True
        finally:
            run_target = Path(self.documents_dir).resolve(strict=False)
            run_artifacts = self._artifact_paths_snapshot()
            self._last_run_target = run_target
            run_cancelled = cancelled or self._cancel.is_set()
            recorded_status = self._write_history(
                status="cancelled" if run_cancelled else "completed"
            )
            n, ok = len(self.steps), sum(1 for s in self.steps if s.ok)
            if run_cancelled:
                self._running.clear()
                self._narrate(f"Red Team Attack cancelled - {ok}/{n} steps executed; cleaning markers.")
                self._sweep_markers(
                    target_dir=run_target,
                    artifact_paths=run_artifacts,
                )
                self._cleanup_probe_processes()
                unregister_run(self.run_id)
            else:
                self._narrate(
                    f"\U0001F3C1 Red Team Attack {recorded_status} — {ok}/{n} steps executed. "
                    "Generating the After-Action Report (brief settle window)…")
                self._running.clear()
                with self._cleanup_lock:
                    evidence_held = self._evidence_lease
                if not evidence_held:
                    delay = getattr(self, "_cleanup_delay", 55.0)
                    try:
                        self._schedule_cleanup(
                            delay,
                            run_target,
                            run_artifacts,
                        )
                    except Exception:
                        self._sweep_markers(
                            target_dir=run_target,
                            artifact_paths=run_artifacts,
                        )
            # The next launch without a target always returns to the immutable
            # local sandbox, even after a custom-target exercise.
            self.documents_dir = self.default_documents_dir

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

    def _step_comprehensive_marker(self, key: str, jitter_range) -> None:
        """Create one fixed ATT&CK-shaped marker without performing the behavior.

        The specification is release-owned immutable data from ``run_manifest``;
        no operator text becomes a path, technique, or executable input. This is
        deliberately a detector-contract exercise, not an offensive primitive.
        """
        spec = _COMPREHENSIVE_PROBES[key]
        stage = str(spec["stage"])
        technique = str(spec["technique"])
        tactic = str(spec["tactic"])
        marker_token = str(spec["marker_token"])
        self._jitter(
            *jitter_range,
            note=f"{stage.removesuffix(' (simulated)')} — inert marker contract",
        )
        ts = time.time()
        hexid = uuid.uuid4().hex[:8]
        readable_stage = stage.removesuffix(" (simulated)")
        self._narrate(
            f"▶ STAGE: {readable_stage} [{technique.removesuffix(' marker')}] — "
            f"writing one fixed INERT marker into {self.documents_dir}. The named "
            "behavior is not performed: no credential access, persistence API, "
            "remote host, outbound traffic, security-control change, collection, "
            "encryption, or deletion occurs."
        )
        marker = self._marker(
            f"_redteam_{marker_token}_{hexid}.txt",
            "ANGERONA RED TEAM comprehensive drill — fixed inert marker.\n"
            f"Tactic: {tactic}\nTechnique: {technique}\n"
            "No named ATT&CK behavior was executed.\n",
        )
        self._record(
            stage,
            technique,
            f"Fixed inert {tactic} simulation marker written; no named behavior executed.",
            ts,
            artifact_paths=[str(marker)],
        )

    def _step_public_facing_app(self, jitter_range) -> None:
        self._step_comprehensive_marker("public_facing_app", jitter_range)

    def _step_user_execution(self, jitter_range) -> None:
        self._step_comprehensive_marker("user_execution", jitter_range)

    def _step_credential_store(self, jitter_range) -> None:
        self._step_comprehensive_marker("credential_store", jitter_range)

    def _step_unsecured_credentials(self, jitter_range) -> None:
        self._step_comprehensive_marker("unsecured_credentials", jitter_range)

    def _step_account_discovery(self, jitter_range) -> None:
        self._step_comprehensive_marker("account_discovery", jitter_range)

    def _step_network_service_discovery(self, jitter_range) -> None:
        self._step_comprehensive_marker("network_service_discovery", jitter_range)

    def _step_network_connections_discovery(self, jitter_range) -> None:
        self._step_comprehensive_marker("network_connections_discovery", jitter_range)

    def _step_software_discovery(self, jitter_range) -> None:
        self._step_comprehensive_marker("software_discovery", jitter_range)

    def _step_exploitation_privilege(self, jitter_range) -> None:
        self._step_comprehensive_marker("exploitation_privilege", jitter_range)

    def _step_create_account(self, jitter_range) -> None:
        self._step_comprehensive_marker("create_account", jitter_range)

    def _step_web_shell(self, jitter_range) -> None:
        self._step_comprehensive_marker("web_shell", jitter_range)

    def _step_dll_side_loading(self, jitter_range) -> None:
        self._step_comprehensive_marker("dll_side_loading", jitter_range)

    def _step_obfuscated_files(self, jitter_range) -> None:
        self._step_comprehensive_marker("obfuscated_files", jitter_range)

    def _step_masquerading(self, jitter_range) -> None:
        self._step_comprehensive_marker("masquerading", jitter_range)

    def _step_impair_defenses(self, jitter_range) -> None:
        self._step_comprehensive_marker("impair_defenses", jitter_range)

    def _step_remote_desktop(self, jitter_range) -> None:
        self._step_comprehensive_marker("remote_desktop", jitter_range)

    def _step_wmi_lateral(self, jitter_range) -> None:
        self._step_comprehensive_marker("wmi_lateral", jitter_range)

    def _step_tool_transfer(self, jitter_range) -> None:
        self._step_comprehensive_marker("tool_transfer", jitter_range)

    def _step_protocol_tunneling(self, jitter_range) -> None:
        self._step_comprehensive_marker("protocol_tunneling", jitter_range)

    def _step_automated_collection(self, jitter_range) -> None:
        self._step_comprehensive_marker("automated_collection", jitter_range)

    def _step_local_data(self, jitter_range) -> None:
        self._step_comprehensive_marker("local_data", jitter_range)

    def _step_exfil_c2(self, jitter_range) -> None:
        self._step_comprehensive_marker("exfil_c2", jitter_range)

    def _step_exfil_web_service(self, jitter_range) -> None:
        self._step_comprehensive_marker("exfil_web_service", jitter_range)

    def _step_inhibit_recovery(self, jitter_range) -> None:
        self._step_comprehensive_marker("inhibit_recovery", jitter_range)

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
        # The operator's label is intentionally absent from the filename.  A
        # label containing e.g. ``lsass_dump`` must not impersonate a standard
        # T1003 canary through a filename-substring detector.
        custom_id = uuid.uuid4().hex
        name_digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:12]
        self._narrate(f"▶ STAGE: Custom [user-defined: {name}] — writing the text you supplied "
                      f"as an INERT marker into {self.documents_dir}. It is written verbatim to a "
                      "file and never executed — this tests whether the defense detects the "
                      "content, nothing runs.")
        p = self._marker(
            f"_redteam_custom_{custom_id}_{name_digest}_{hexid}.txt",
            f"ANGERONA RED TEAM custom drill marker — INERT, never executed.\n"
            f"Technique: {name}\n---\n{payload}\n")
        self._record("Custom (simulated)", f"user-defined: {name}",
                     "User-defined benign marker written; informational until a "
                     "reviewed detector contract is explicitly attached.",
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
        tag on its command line and idles for at most 30 seconds."""
        import subprocess
        self._jitter(*jitter_range, note="Execution — benign tagged process spawns")
        ts = time.time()
        level = int(getattr(self, "_threat_level", getattr(self, "_complexity", 1)) or 1)
        mult = int(getattr(self, "_proc_mult", 1) or 1)
        n = min(2 + level * mult, 16)
        self._narrate(f"▶ STAGE: Benign Execution [T1059-style] — spawning {n} bounded, "
                      "red-team-TAGGED idle processes (maximum 30 seconds) so process sensors "
                      "and SOAR see realistic process-creation activity. Nothing harmful runs.")
        spawned = 0
        pids = []
        tokens = []
        for _ in range(n):
            if self._cancel.is_set():
                break
            tag = f"ANGERONA_REDTEAM_{uuid.uuid4().hex[:8]}"
            proc = None
            try:
                lease = self._validation_lease
                if type(lease) is RedTeamValidationLease:
                    RedTeamValidationLease.enroll_process_challenge(
                        lease, token=tag, run_id=self.run_id
                    )
                register_process(tag, self.run_id, kind="red-team")
                flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
                proc = subprocess.Popen(  # noqa: S603 - fixed interpreter, inert sleep
                    [sys.executable, "-c", "import time; time.sleep(30)", tag],
                    creationflags=flags,
                )
                if type(lease) is RedTeamValidationLease:
                    RedTeamValidationLease.bind_process_challenge(
                        lease, token=tag, pid=int(proc.pid), run_id=self.run_id
                    )
                self._probe_processes.append(proc)
                spawned += 1
                pids.append(int(proc.pid))
                tokens.append(tag)
                register_process(tag, self.run_id, pid=int(proc.pid), kind="red-team")
            except Exception:
                if proc is not None:
                    try:
                        proc.terminate()
                        proc.wait(timeout=1.0)
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass
            if self._cancel.wait(0.2):
                break
        self._record("Benign Execution (simulated)", "T1059 tagged spawns",
                     f"Spawned {spawned} bounded red-team-tagged idle process(es).", ts,
                     pid=(pids[0] if pids else None), pids=pids,
                     correlation_tokens=tokens, ok=(spawned == n and n > 0))

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

    def _write_history(self, status: str = "completed") -> str:
        try:
            payload = build_run_history(
                kind="red_team",
                run_id=self.run_id,
                generated=time.strftime("%Y-%m-%d %H:%M:%S"),
                steps=self.steps,
                preflight=self._run_contract,
                status=status,
            )
            if self._validation_readiness:
                payload["validation_readiness"] = copy.deepcopy(
                    self._validation_readiness
                )
            signed = write_run_history(self.history_path, payload)
            if not signed:
                self._narrate(
                    "⚠ Red Team ground-truth history was written without an "
                    "install-key HMAC; strict AAR generation will refuse it."
                )
            return str(payload.get("status") or "incomplete")
        except Exception as exc:
            self._narrate(
                f"⚠ Red Team ground-truth history could not be secured: "
                f"{type(exc).__name__}"
            )
            return "history-failed"


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
    "Custom (simulated)": "informational",
    **{
        str(row["stage"]): str(row["category"])
        for row in RED_TEAM_COMPREHENSIVE_PLAN
    },
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
    catalog_ok = (
        len(_COMPREHENSIVE_PROBES) == len(RED_TEAM_COMPREHENSIVE_PLAN)
        and all(
            callable(getattr(RedTeamEngine, f"_step_{key}", None))
            for key in _COMPREHENSIVE_PROBES
        )
    )
    ok = ok and catalog_ok
    return ok, (f"intensity presets ok, {len(_CAMPAIGN_ORDER)} chained techniques, "
                f"{len(_COMPREHENSIVE_PROBES)} comprehensive inert probes, kill-chain order verified"
                if ok else f"failed: presets={presets_ok} escalate={escalating} missing={missing} order={order_ok}")
