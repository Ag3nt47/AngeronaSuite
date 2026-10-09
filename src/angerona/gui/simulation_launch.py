"""Detached drill preparation; this module never imports or accesses Qt."""
from __future__ import annotations

import os
import threading
from pathlib import Path

from angerona.core.module_usage import reconcile_module_usage


_POLICY_KEYS = (
    "ANGERONA_SOAR_KILL_AND_ROLLBACK",
    "ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY",
    "ANGERONA_SOAR_RESPONSE_SCOPE",
)


class SimulationLaunch:
    """One bounded launch with an explicit GUI handoff or worker-side rollback.

    Cancellation never waits. A lease acquired after cancellation is released
    by this same worker before it exits. Success waits for claim(), so closing
    the owner before Qt receives the result cannot strand engines or authority.
    """

    def __init__(self, *, cfg, manager, bus, storage, data_root,
                 red_team_engine, shark_engine, response_escalated):
        self.cfg = dict(cfg)
        if isinstance(self.cfg.get("custom"), dict):
            self.cfg["custom"] = dict(self.cfg["custom"])
        self.manager, self.bus, self.storage = manager, bus, storage
        self.data_root = Path(data_root)
        self.red_team_engine, self.shark_engine = red_team_engine, shark_engine
        self.response_escalated = bool(response_escalated)
        self.previous_policy = {}
        self.target = str(cfg.get("target_dir") or red_team_engine.default_documents_dir).strip()
        self.runtime_watch = None
        self.lease = None
        self.readiness = {}
        self.started = []
        self.reason = ""
        self.success = False
        self.ready = threading.Event()
        self.finished = threading.Event()
        self.cancelled = threading.Event()
        self._decision = threading.Event()
        self._lock = threading.Lock()
        self._claimed = False
        self._policy_changed = False
        self.thread = threading.Thread(target=self._run, name="simulation-launch", daemon=True)

    def start(self):
        self.thread.start()

    def cancel(self, *_unused):
        with self._lock:
            if not self._claimed:
                self.cancelled.set()
                self._decision.set()

    def claim(self):
        with self._lock:
            if not self.ready.is_set() or not self.success or self.cancelled.is_set():
                return False
            self._claimed = True
            self._decision.set()
            return True

    def _check_cancelled(self):
        if self.cancelled.is_set():
            raise RuntimeError("Launch cancelled before acceptance.")

    def _prepare(self):
        from angerona.modules.file_integrity import register_runtime_watch
        from angerona.modules.yara_scanner import register_runtime_watch as watch_yara
        from angerona.shark.run_manifest import preflight_run

        cfg = self.cfg
        self._check_cancelled()
        self.previous_policy = {key: os.environ.get(key) for key in _POLICY_KEYS}
        if self.response_escalated:
            self._policy_changed = True
            os.environ[_POLICY_KEYS[0]] = "1"
            os.environ[_POLICY_KEYS[1]] = "MEDIUM"
            roots = [str(self.data_root / "drill-sandbox")]
            if cfg.get("target_dir"):
                roots.append(str(cfg["target_dir"]).strip())
            os.environ[_POLICY_KEYS[2]] = os.pathsep.join(dict.fromkeys(roots))
            reconcile_module_usage(self.manager)
        self._check_cancelled()
        if not register_runtime_watch(self.target):
            raise RuntimeError(f"File Integrity Monitor refused runtime target {self.target!r}")
        self.runtime_watch = self.target
        if not watch_yara(self.target):
            raise RuntimeError(f"YARA Scanner refused runtime target {self.target!r}")
        custom = cfg.get("custom") or None
        if cfg.get("run_shark"):
            result = preflight_run(
                kind="shark", cycles=cfg.get("complexity", 1),
                jitter_range=(2.0, 9.0), noise_chance=0.25,
                target_dir=self.target, custom=custom,
            )
            if not result.accepted:
                raise RuntimeError("Shark safety preflight rejected the run: " + "; ".join(result.violations))
        self._check_cancelled()
        if cfg.get("run_redteam"):
            from angerona.shark.red_team import INTENSITY_LEVELS
            from angerona.modules.purple_guard import acquire_redteam_validation_lease

            preset = INTENSITY_LEVELS.get(str(cfg.get("intensity")))
            result = preflight_run(
                kind="red_team", cycles=preset["cycles"] if preset else 1,
                jitter_range=preset["jitter"] if preset else (2.0, 7.0),
                noise_chance=preset["noise"] if preset else 0.25,
                target_dir=self.target, custom=custom,
                campaign=bool(cfg.get("campaign", False)),
                comprehensive=bool(cfg.get("comprehensive", True)),
            )
            if not result.accepted:
                raise RuntimeError("Red Team safety preflight rejected the run: " + "; ".join(result.violations))
            self._check_cancelled()
            self.lease = acquire_redteam_validation_lease(
                self.manager, self.bus, self.storage, self.data_root, self.target,
                comprehensive=bool(cfg.get("comprehensive", True)),
            )
            self.readiness = dict(self.lease.readiness)
            self._check_cancelled()
            self.red_team_engine.hold_evidence_for_aar()
            if not self.red_team_engine.start(
                intensity=cfg.get("intensity"), campaign=bool(cfg.get("campaign", False)),
                comprehensive=bool(cfg.get("comprehensive", True)), target_dir=self.target,
                custom=custom, validation_lease=self.lease,
            ):
                raise RuntimeError("Red Team engine safety preflight rejected the run")
            self.started.append(self.red_team_engine)
        self._check_cancelled()
        if cfg.get("run_shark"):
            if not self.shark_engine.start(
                complexity=cfg.get("complexity", 1), target_dir=self.target, custom=custom,
            ):
                raise RuntimeError("Shark engine safety preflight rejected the run")
            self.started.append(self.shark_engine)
        self._check_cancelled()
        if not self.started:
            raise RuntimeError("No engine accepted the run.")

    def _cleanup(self):
        errors = []
        for engine in self.started:
            try:
                engine.stop_and_clean()
            except Exception as exc:
                errors.append(f"engine cleanup: {type(exc).__name__}: {exc}")
        try:
            self.red_team_engine.cancel_evidence_hold()
        except Exception as exc:
            errors.append(f"evidence hold: {type(exc).__name__}: {exc}")
        if self.lease is not None:
            try:
                self.lease.release()
            except Exception as exc:
                errors.append(f"validation lease: {type(exc).__name__}: {exc}")
        if self.runtime_watch is not None:
            from angerona.modules.file_integrity import unregister_runtime_watch
            from angerona.modules.yara_scanner import unregister_runtime_watch as unwatch_yara
            for unwatch in (unregister_runtime_watch, unwatch_yara):
                try:
                    unwatch(self.runtime_watch)
                except Exception as exc:
                    errors.append(f"runtime watch: {type(exc).__name__}: {exc}")
        if self._policy_changed:
            for key, previous in self.previous_policy.items():
                if previous is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = previous
            try:
                reconcile_module_usage(self.manager)
            except Exception as exc:
                errors.append(f"response policy: {type(exc).__name__}: {exc}")
        if errors:
            self.reason += "; cleanup requires review: " + "; ".join(errors)

    def _run(self):
        try:
            self._prepare()
            self.success = True
            self.ready.set()
            self._decision.wait()  # Claim or cancellation, no GUI work here.
            if self._claimed:
                return
            self.success = False
            self.reason = "Launch cancelled before acceptance."
        except Exception as exc:
            self.reason = f"{type(exc).__name__}: {exc}"
        finally:
            if not self._claimed:
                self._cleanup()
            self.finished.set()
            self.ready.set()


def stop_engines(engines, finished, errors=None):
    """Run existing bounded engine cleanup without retaining GUI objects."""
    try:
        for engine in engines:
            try:
                engine.stop_and_clean()
            except Exception as exc:
                if errors is not None:
                    errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        finished.set()
