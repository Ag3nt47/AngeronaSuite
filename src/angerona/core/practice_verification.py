"""Deterministic, bounded verification for Red Team practice fixes.

This is deliberately not a host-hardening engine.  It replays only Angerona's
own inert marker contract through the installed Purple Guard detector and the
real Active Response SOAR playbook.  A practice finding closes only when the
positive control is detected, the benign negative control stays quiet, signed
evidence reaches the flight recorder, response succeeds, and the marker/process
is actually gone afterward.
"""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Callable, Iterable

from angerona.core import drill_resolution
from angerona.core.eventbus import Event, EventBus, Severity
from angerona.core.practice_scope import (
    register_artifact,
    register_process,
    register_run,
    unregister_run,
)


_FILE_TOKENS = {
    "T1003": "lsass_dump",
    "T1546.003": "wmi_subscription",
    "T1070": "amsi_bypass",
    "T1053.005": "schtask",
    "T1547.001": "runkey",
    "T1021.002": "psexec",
    "T1074": "exfil_stage",
    "T1486": "README_DECRYPT",
    "T1566.001": "invoice_macro",
    "T1548.002": "uac_bypass",
    "T1071": "c2_beacon_cfg",
    "T1485": "wiper",
}
_PROCESS_TECHNIQUE = "T1059"
_ENV_LOCK = threading.RLock()


def _emit_progress(progress: Callable[[int, str], None] | None,
                   percent: int, text: str) -> None:
    if progress is None:
        return
    try:
        progress(max(0, min(100, int(percent))), str(text))
    except Exception:
        pass


@contextmanager
def _scoped_practice_response(root: Path):
    keys = (
        "ANGERONA_SOAR_KILL_AND_ROLLBACK",
        "ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY",
        "ANGERONA_SOAR_RESPONSE_SCOPE",
    )
    with _ENV_LOCK:
        previous = {key: os.environ.get(key) for key in keys}
        os.environ["ANGERONA_SOAR_KILL_AND_ROLLBACK"] = "1"
        os.environ["ANGERONA_SOAR_KILL_AND_ROLLBACK_MIN_SEVERITY"] = "HIGH"
        os.environ["ANGERONA_SOAR_RESPONSE_SCOPE"] = str(root)
        try:
            yield
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


def _find_event(bus: EventBus, *, module: str, mitre: str,
                since: float, path: Path | None = None,
                verification_id: str = "",
                events: Iterable[Event] | None = None) -> Event | None:
    for event in (events if events is not None else bus.recent(500)):
        details = event.details or {}
        if event.ts < since or event.module != module:
            continue
        if str(details.get("mitre") or "").upper() != mitre:
            continue
        if verification_id and details.get("practice_verification_id") != verification_id:
            continue
        if path is not None:
            observed = details.get("artifact_path") or details.get("path")
            try:
                if Path(str(observed)).resolve(strict=False) != path.resolve(strict=False):
                    continue
            except (OSError, RuntimeError, ValueError):
                continue
        return event
    return None


def _find_response(bus: EventBus, trigger: Event, since: float,
                   events: Iterable[Event] | None = None) -> Event | None:
    for event in (events if events is not None else bus.recent(500)):
        if event.ts < since or event.module != "Active Response SOAR":
            continue
        details = event.details or {}
        try:
            same_trigger = abs(float(details.get("trigger_ts")) - trigger.ts) < 0.000001
        except (TypeError, ValueError):
            same_trigger = False
        if same_trigger and details.get("mitigated") is True:
            return event
    return None


def _recorded(db_path: Path, event: Event, timeout: float) -> bool:
    """Require the exact signed detector event to reach the SQLite ledger."""
    if not event.hmac_sig:
        return False
    deadline = time.monotonic() + max(0.1, float(timeout))
    while time.monotonic() < deadline:
        try:
            # A sqlite connection context manager commits/rolls back but does
            # not close.  ``closing`` is required here because practice retests
            # otherwise leave Windows handles that can lock temp databases.
            with closing(sqlite3.connect(db_path, timeout=0.5)) as db:
                row = db.execute(
                    "SELECT 1 FROM events WHERE module=? AND ts>=? AND ts<=? "
                    "AND hmac_sig=? LIMIT 1",
                    (
                        event.module,
                        event.ts - 0.000001,
                        event.ts + 0.000001,
                        event.hmac_sig,
                    ),
                ).fetchone()
            if row:
                return True
        except (OSError, sqlite3.Error, TypeError, ValueError):
            pass
        time.sleep(0.05)
    return False


def _publish_process_probe(bus: EventBus, verification_id: str) -> tuple[Event, subprocess.Popen]:
    tag = f"ANGERONA_REDTEAM_{verification_id[-8:]}"
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    register_process(tag, verification_id, kind="practice-verification")
    process = subprocess.Popen(  # noqa: S603 - fixed interpreter/argv, inert sleep only
        [sys.executable, "-c", "import time; time.sleep(30)", tag],
        creationflags=flags,
    )
    register_process(
        tag,
        verification_id,
        pid=int(process.pid),
        kind="practice-verification",
    )
    event = Event(
        "Red Team Practice Lab",
        "PRACTICE TEST: benign tagged process positive control.",
        Severity.INFO,
        details={
            "event_type": "process_creation",
            "pid": int(process.pid),
            "cmdline": f"{sys.executable} -c <inert sleep> {tag}",
            "correlation_token": tag,
            "practice_verification_id": verification_id,
            "run_id": verification_id,
        },
    )
    bus.publish(event)
    return event, process


def verify_practice_fixes(
    techniques: Iterable[str],
    *,
    source_run_id: str,
    data_dir: Path,
    db_path: Path,
    bus: EventBus,
    purple_guard,
    active_response,
    progress: Callable[[int, str], None] | None = None,
    recorder_timeout: float = 10.0,
) -> dict:
    """Run exact inert positive/negative controls and issue signed receipts."""
    requested = list(dict.fromkeys(str(value or "").upper() for value in techniques if value))
    root = Path(data_dir) / "drill-sandbox"
    root.mkdir(parents=True, exist_ok=True)
    if not requested:
        return {"ok": True, "verified": 0, "total": 0, "results": []}
    if purple_guard is None or active_response is None:
        return {
            "ok": False,
            "verified": 0,
            "total": len(requested),
            "error": "Purple Guard and Active Response SOAR must both be running",
            "results": [],
        }

    results = []
    total = len(requested)
    _emit_progress(progress, 5, "Preparing isolated practice controls")
    for index, mitre in enumerate(requested):
        # Hex-only so the ID can be safely carried in both process tokens and
        # the reviewed `_redteam_*_practice_<id>.txt` filename contract.
        verification_id = uuid.uuid4().hex
        register_run(verification_id, kind="practice-verification")
        started = time.time()
        positive: Path | None = None
        negative = root / f"_redteam_benign_note_practice_{verification_id}.txt"
        process: subprocess.Popen | None = None
        detection = response = None
        error = ""
        base_pct = 8 + int(index / max(1, total) * 84)
        _emit_progress(progress, base_pct, f"Testing {mitre} positive control")
        try:
            priority_cursor = bus.priority_revision()
            register_artifact(
                negative,
                verification_id,
                kind="practice-verification",
            )
            negative.write_text("PRACTICE NEGATIVE CONTROL — ordinary benign note.\n", encoding="utf-8")
            if mitre in _FILE_TOKENS:
                token = _FILE_TOKENS[mitre]
                positive = root / (
                    f"_redteam_{token}_practice_{verification_id}.txt"
                )
                register_artifact(
                    positive,
                    verification_id,
                    kind="practice-verification",
                )
                positive.write_text(
                    "ANGERONA PRACTICE TEST — inert positive marker; never executed.\n",
                    encoding="utf-8",
                )
            elif mitre == _PROCESS_TECHNIQUE:
                _probe, process = _publish_process_probe(bus, verification_id)
            else:
                raise ValueError("no registered inert practice control")

            # Exercise the exact production detector implementation immediately;
            # its normal background loop may also run, but de-duplication keeps it safe.
            policy = purple_guard._policy_snapshot()
            purple_guard.scan_once(policy)
            purple_guard.scan_process_once(policy)
            _det_revision, detector_events, detector_overflow = bus.priority_since(
                priority_cursor
            )
            if detector_overflow:
                raise RuntimeError("priority evidence lane overflowed during detector test")
            detection = _find_event(
                bus,
                module="Purple Remediation Guard",
                mitre=mitre,
                since=started,
                path=positive,
                verification_id=verification_id,
                events=detector_events,
            )
            negative_hit = any(
                event.module == "Purple Remediation Guard"
                and str((event.details or {}).get("path") or "") == str(negative)
                for event in bus.recent(500)
                if event.ts >= started
            )
            if detection is None:
                raise RuntimeError("positive control was not detected")
            if negative_hit:
                raise RuntimeError("benign negative control produced a detection")
            if not bus.verify(detection):
                raise RuntimeError("detector event signature verification failed")

            _emit_progress(progress, base_pct + 4, f"Testing {mitre} response and cleanup")
            with _scoped_practice_response(root):
                active_response.process_pending_once()
            _response_revision, response_events, response_overflow = bus.priority_since(
                priority_cursor
            )
            if response_overflow:
                raise RuntimeError("priority evidence lane overflowed during response test")
            response = _find_response(bus, detection, started, events=response_events)
            detection_persisted = _recorded(
                Path(db_path), detection, recorder_timeout
            )
            response_verified = response is not None and bus.verify(response)
            response_persisted = (
                response_verified
                and _recorded(Path(db_path), response, recorder_timeout)
            )
            postcondition = (
                not positive.exists() if positive is not None
                else process is not None and process.poll() is not None
            )
            checks = {
                "positive_control_detected": True,
                "negative_control_quiet": not negative_hit,
                # These two contract checks jointly require both exact HMACs
                # to be valid and durable, not merely visible in memory.
                "recorder_persisted": detection_persisted and response_persisted,
                "response_succeeded": response_verified and response_persisted,
                "postcondition_satisfied": postcondition,
                "detector_event_persisted": detection_persisted,
                "response_event_persisted": response_persisted,
            }
            verification = drill_resolution.verify_detector_evidence(
                mitre,
                verification_id,
                detector="Purple Remediation Guard",
                event_ts=detection.ts,
                event_details=detection.details or {},
                data_dir=data_dir,
                verification_mode="practice-probe",
                verification_checks=checks,
            )
            if not verification.get("ok"):
                raise RuntimeError(str(verification.get("error") or "receipt rejected"))
            contract = verification.get("contract") or {}
            receipt = contract.get("verification_receipt") or {}
            results.append({
                "mitre": mitre,
                "status": "PRACTICE_FIX_VERIFIED",
                "verification_id": verification_id,
                "receipt_id": receipt.get("receipt_id"),
                "detector": detection.module,
                "response": response.module if response else None,
                "checks": checks,
            })
        except Exception as exc:
            error = str(exc)
            results.append({
                "mitre": mitre,
                "status": "FIX_APPLIED_RETEST_FAILED",
                "verification_id": verification_id,
                "error": error,
            })
        finally:
            for path in (positive, negative):
                if path is not None:
                    try:
                        path.unlink(missing_ok=True)
                    except OSError:
                        pass
            if process is not None and process.poll() is None:
                try:
                    process.terminate()
                    process.wait(timeout=1.0)
                except Exception:
                    try:
                        process.kill()
                    except Exception:
                        pass
            unregister_run(verification_id)
        _emit_progress(
            progress,
            8 + int((index + 1) / max(1, total) * 84),
            f"{mitre}: {'verified' if not error else 'needs review'}",
        )

    verified = sum(row["status"] == "PRACTICE_FIX_VERIFIED" for row in results)
    _emit_progress(progress, 100, "Practice fix verification complete")
    return {
        "ok": verified == total,
        "verified": verified,
        "total": total,
        "source_run_id": source_run_id,
        "results": results,
        "practice_only": True,
    }
