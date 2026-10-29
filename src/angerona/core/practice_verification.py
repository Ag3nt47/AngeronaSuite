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
from angerona.core.eventbus import Event, EventBus
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


def _readiness_begin(bus, detector, responder, technique, run_id):
    """Private, fault-isolated seam for this real practice verifier only."""
    try:
        from angerona.core.verified_readiness import _practice_service
        service = _practice_service(bus)
        if service is not None:
            return service, service._begin_practice(detector, responder, technique, run_id)
    except Exception:
        pass
    return None, None


def _readiness_finish(binding, **evidence) -> None:
    service, ticket = binding
    if service is None or ticket is None:
        return
    try:
        service._finish_practice(ticket, **evidence)
    except Exception:
        # Advisory presentation must never invalidate a completed remediation,
        # retry a host action, or prevent the real verifier's cleanup.
        pass


def _emit_progress(progress: Callable[[int, str], None] | None,
                   percent: int, text: str) -> None:
    if progress is None:
        return
    try:
        progress(max(0, min(100, int(percent))), str(text))
    except Exception:
        pass


def _write_registered_marker(path: Path, body: str, run_id: str, *, lease) -> None:
    """Create one inert control exclusively, then bind its held file ID."""
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | os.O_EXCL
        | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(body.encode("utf-8"))
        stream.flush()
        os.fsync(stream.fileno())
        if not register_artifact(
            path, run_id, kind="practice-verification",
            descriptor=stream.fileno(),
        ):
            raise OSError("practice marker could not be bound to its created file ID")
        # Registry provenance is advisory; only the issuer's retained file
        # identity may authorize this positive control's eventual response.
        from angerona.modules.purple_guard import RedTeamValidationLease
        RedTeamValidationLease.register_artifact_handle(lease, path, run_id=run_id)


def _cleanup_markers(paths, *, lease, run_id: str) -> bool:
    """Delete only controls still matching this issuer's retained file IDs."""
    from angerona.modules.purple_guard import RedTeamValidationLease
    complete = True
    for path in paths:
        if path is None:
            continue
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            complete = False
            continue
        try:
            removed = RedTeamValidationLease.remove_registered_artifact(
                lease, path, run_id=run_id,
            )
        except Exception:
            removed = False
        complete = bool(removed) and complete
    return complete


def _pending_marker_handoff(lease, event, *, manager, bus, guard, recorder) -> bool:
    """Permit bounded observation of an exact pending handoff, never response."""
    from angerona.modules.purple_guard import _lease_authority
    try:
        state = _lease_authority(lease)
        details = event.details if isinstance(event.details, dict) else {}
        path = Path(os.path.abspath(str(details.get("path") or "")))
        key = os.path.normcase(str(path))
        with state.lock:
            record = (state.artifact_handles or {}).get(key)
            modules = getattr(manager, "modules", {})
            return bool(
                state.manager is manager and state.bus is bus
                and state.module is guard and state.recorder is recorder
                and getattr(manager, "bus", None) is bus
                and getattr(manager, "recorder", None) is recorder
                and isinstance(modules, dict) and modules.get(guard.name) is guard
                and getattr(guard, "_bus", None) is bus
                and getattr(guard, "_validation_lease", None) is lease
                and event.module == guard.name and bus.verify(event)
                and not state.released and not state.artifact_custody_failed
                and state.consumed and time.monotonic() <= state.run_deadline_monotonic
                and details.get("receipt_type") == "purple_simulation_validation"
                and details.get("evidence_kind") == "inert_file_marker"
                and details.get("lease_id") == state.lease_id
                and details.get("receipt_id") == state.receipt_id
                and details.get("run_id") == state.bound_run_id
                and details.get("target") == str(state.target) and path.parent == state.target
                and key in (state.artifact_handoffs or set())
                and record is not None and record[0] is None
            )
    except Exception:
        return False


def _retire_process(process: subprocess.Popen | None, *, progress=None) -> bool:
    """Wait for only the fixed, unreaped child owned by this Popen object."""
    if process is None:
        return True
    try:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=1.0)
        return True
    except (OSError, subprocess.TimeoutExpired):
        try:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=2.0)
            return True
        except (OSError, subprocess.TimeoutExpired):
            pass
    # The verifier's existing worker retains the Popen/native handle. Do not
    # return, release its issuer, start a replacement, or repeat a host action
    # while exact termination is uncertain. The fixed probe itself sleeps for
    # only 30 seconds; an externally suspended/unverifiable child remains held.
    _emit_progress(progress, 95, "Waiting for the owned practice process to retire")
    while True:
        try:
            process.wait(timeout=1.0)
            return True
        except subprocess.TimeoutExpired:
            continue
        except OSError:
            threading.Event().wait(0.1)


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
        if (same_trigger and details.get("mitigated") is True
                and details.get("trigger_module") == trigger.module
                and details.get("origin_event_digest") == trigger.hmac_sig
                and details.get("delegation_mode") == "issuer-original-event"
                and bus.verify(event)):
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


def _publish_process_probe(bus: EventBus, verification_id: str, *, lease) -> tuple[dict, subprocess.Popen]:
    from angerona.modules.purple_guard import RedTeamValidationLease

    if getattr(sys, "frozen", False):
        raise RuntimeError("this runtime has no admitted inert Python probe interpreter")
    tag = f"ANGERONA_REDTEAM_{verification_id[-8:]}"
    RedTeamValidationLease.enroll_process_challenge(
        lease, token=tag, run_id=verification_id,
    )
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    register_process(tag, verification_id, kind="practice-verification")
    # A venv redirector can outlive or detach from its child. The base runtime
    # executes this stdlib-only fixed program directly, with no helper child.
    executable = str(Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True))
    process = subprocess.Popen(  # noqa: S603 - fixed interpreter/argv, inert sleep only
        [executable, "-c", "import time; time.sleep(30)", tag],
        creationflags=flags,
    )
    try:
        register_process(tag, verification_id, pid=int(process.pid), kind="practice-verification")
        # This issuer API independently observes and publishes the exact native
        # child through the enrolled Process Monitor. No synthetic bus row may
        # substitute for that producer's signed receipt.
        binding = RedTeamValidationLease.bind_process_challenge(
            lease, token=tag, pid=int(process.pid), run_id=verification_id,
        )
        return binding, process
    except BaseException:
        _retire_process(process)
        raise


def verify_practice_fixes(
    techniques: Iterable[str],
    *,
    source_run_id: str,
    data_dir: Path,
    db_path: Path,
    bus: EventBus,
    purple_guard,
    active_response,
    manager=None,
    recorder=None,
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
    modules = getattr(manager, "modules", None)
    if (not isinstance(modules, dict)
            or modules.get("Purple Remediation Guard") is not purple_guard
            or modules.get("Active Response SOAR") is not active_response
            or getattr(manager, "bus", None) is not bus
            or recorder is None or getattr(manager, "recorder", None) is not recorder
            or Path(getattr(recorder, "_path", "")).resolve(strict=False)
            != Path(db_path).resolve(strict=False)):
        return {"ok": False, "verified": 0, "total": len(requested), "results": [],
                "error": "exact manager, module, EventBus and recorder binding is required"}
    from angerona.modules.purple_guard import (
        RedTeamValidationLease, acquire_redteam_validation_lease,
    )

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
        lease = None
        detection = response = None
        checks = {}
        readiness = (None, None)
        error = ""
        base_pct = 8 + int(index / max(1, total) * 84)
        _emit_progress(progress, base_pct, f"Testing {mitre} positive control")
        try:
            lease = acquire_redteam_validation_lease(
                manager, bus, recorder, Path(data_dir), root,
                timeout=min(8.0, max(0.1, float(recorder_timeout))),
            )
            RedTeamValidationLease.consume_for_run(
                lease, run_id=verification_id, target=root,
                data_root=Path(data_dir), run_ttl_seconds=120.0,
            )
            readiness = _readiness_begin(
                bus, purple_guard, active_response, mitre, verification_id,
            )
            priority_cursor = bus.priority_revision()
            _write_registered_marker(
                negative,
                "PRACTICE NEGATIVE CONTROL — ordinary benign note.\n",
                verification_id,
                lease=lease,
            )
            if mitre in _FILE_TOKENS:
                token = _FILE_TOKENS[mitre]
                positive = root / (
                    f"_redteam_{token}_practice_{verification_id}.txt"
                )
                _write_registered_marker(
                    positive,
                    "ANGERONA PRACTICE TEST — inert positive marker; never executed.\n",
                    verification_id,
                    lease=lease,
                )
            elif mitre == _PROCESS_TECHNIQUE:
                _probe, process = _publish_process_probe(bus, verification_id, lease=lease)
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
            # The running detector may have consumed its native queue just
            # before this manual scan. Wait for that one exact issuer-bound
            # result rather than publishing a synthetic replacement event.
            detector_deadline = time.monotonic() + min(10.0, max(0.1, float(recorder_timeout)))
            while detection is None and time.monotonic() < detector_deadline:
                time.sleep(0.025)
                _det_revision, detector_events, detector_overflow = bus.priority_since(priority_cursor)
                if detector_overflow:
                    raise RuntimeError("priority evidence lane overflowed during detector test")
                detection = _find_event(
                    bus, module="Purple Remediation Guard", mitre=mitre,
                    since=started, path=positive, verification_id=verification_id,
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
            issuer_verified = RedTeamValidationLease.verify_purple_event(
                lease, detection, {"attack_ids": [mitre]},
            )
            # The registered response owner may already be moving this exact
            # file. Its exclusive handoff temporarily makes historical file
            # proof unavailable. Observe the same opaque lease and receipt;
            # no response or closure can use a pending/unverified proof.
            while not issuer_verified and time.monotonic() < detector_deadline:
                pending = _pending_marker_handoff(
                    lease, detection, manager=manager, bus=bus,
                    guard=purple_guard, recorder=recorder,
                )
                # An exact handoff may have finished between the preceding
                # proof and the pending check. One immediate recheck is safe;
                # unavailable/released/wrongly-bound proof otherwise fails now.
                issuer_verified = RedTeamValidationLease.verify_purple_event(
                    lease, detection, {"attack_ids": [mitre]},
                )
                if issuer_verified or not pending:
                    break
                time.sleep(0.025)
                issuer_verified = RedTeamValidationLease.verify_purple_event(
                    lease, detection, {"attack_ids": [mitre]},
                )
            if not issuer_verified:
                raise RuntimeError("detector event lacks the exact issuer-backed control receipt")

            _emit_progress(progress, base_pct + 4, f"Testing {mitre} response and cleanup")
            response_deadline = time.monotonic() + min(10.0, max(0.1, float(recorder_timeout)))
            with _scoped_practice_response(root):
                active_response.process_pending_once()
                _response_revision, response_events, response_overflow = bus.priority_since(
                    priority_cursor
                )
                if response_overflow:
                    raise RuntimeError("priority evidence lane overflowed during response test")
                response = _find_response(bus, detection, started, events=response_events)
                if response is None:
                    # Dispatch already happened through the production owner.
                    # Observe only its exact committed receipt while this same
                    # issuer lease remains held; never retry the native action.
                    active_response.observe_issuer_completion(
                        detection, timeout=max(0.0, response_deadline - time.monotonic()),
                    )
                    _response_revision, response_events, response_overflow = bus.priority_since(
                        priority_cursor
                    )
                    if response_overflow:
                        raise RuntimeError("priority evidence lane overflowed during response observation")
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
            controls_cleaned = _cleanup_markers(
                (positive, negative), lease=lease, run_id=verification_id,
            )
            checks = {
                "positive_control_detected": True,
                "negative_control_quiet": not negative_hit,
                # These two contract checks jointly require both exact HMACs
                # to be valid and durable, not merely visible in memory.
                "recorder_persisted": detection_persisted and response_persisted,
                "response_succeeded": response_verified and response_persisted,
                "postcondition_satisfied": postcondition and controls_cleaned,
                "owned_marker_cleanup": controls_cleaned,
                "issuer_lease_verified": True,
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
            _readiness_finish(
                readiness, bus=bus, detection=detection, response=response,
                checks=checks, receipt_id=str(receipt.get("receipt_id") or ""),
            )
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
            _readiness_finish(
                readiness, bus=bus, detection=detection, response=response,
                checks=checks, failure=error,
            )
            results.append({
                "mitre": mitre,
                "status": "FIX_APPLIED_RETEST_FAILED",
                "verification_id": verification_id,
                "error": error,
            })
        finally:
            try:
                if lease is not None:
                    _cleanup_markers((positive, negative), lease=lease, run_id=verification_id)
                _retire_process(process, progress=progress)
            finally:
                if lease is not None:
                    RedTeamValidationLease.release(lease)
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
