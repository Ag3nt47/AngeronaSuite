"""Status reporter — writes a live snapshot of the whole app to disk.

Every few seconds it dumps the full dashboard state (modules + statuses, recent
alerts, counts, threat level) to two files:

    diagnostics/status.json   machine-readable
    diagnostics/status.txt    human-readable (mirrors the GUI)

This is the bridge that lets a person (or an assistant) who can't see the GUI
understand exactly what's on screen — just read status.txt.

Files are written only to the configured runtime-data diagnostics directory.
"""
from __future__ import annotations

import json
import math
import os
import stat
import tempfile
import threading
import time
from pathlib import Path
from typing import List

from angerona import __version__
from angerona.core.atomic_io import replace_with_retry
from angerona.core.crashlog_status import normal_log_status
from angerona.core.eventbus import EventBus, Severity
from angerona.core.privilege import is_admin
from angerona.core.subscriber_diagnostics import project_subscribers
from angerona.core.telemetry_storage_policy import STORAGE_REASONS, STORAGE_STATES

_THREAT = {Severity.INFO: "SECURE", Severity.LOW: "LOW", Severity.MEDIUM: "ELEVATED",
           Severity.HIGH: "HIGH", Severity.CRITICAL: "CRITICAL"}

_OPTIONAL_AUDIT_UNSET = object()
_OPTIONAL_AUDIT_COUNTERS = (
    "attempted", "recorded", "rejected", "rejected_oversize", "rejected_invalid",
    "unavailable", "persistence_unknown", "pending",
)
_OPTIONAL_AUDIT_RESULT_COUNTERS = (
    "attempted", "recorded", "rejected", "unavailable", "persistence_unknown",
)
_OPTIONAL_AUDIT_SCOPE = (
    "Instance-lifetime memory counters reset on instance replacement or restart; not durable "
    "across restart. Zero gaps do not prove history continuity. Native security journals and "
    "closure authority are separate."
)


def _optional_audit_view(source) -> dict:
    """Copy only bounded admission counters, without inferring writer health."""
    result = {"schema": 1, "state": "unavailable", "reason_code": "invalid_observation",
              "scope": "instance-lifetime", "durable": False, "response_authorized": False}
    try:
        if type(source) is not dict or len(source) > 32:
            raise ValueError
        source = dict(source)
        if (type(source.get("schema")) is not int or source["schema"] != 1
                or type(source.get("state")) is not str or source["state"] != "observed"
                or type(source.get("scope")) is not str or source["scope"] != "instance-lifetime"
                or source.get("durable") is not False
                or source.get("response_authorized") is not False
                or type(source.get("entry_limit_bytes")) is not int or source["entry_limit_bytes"] != 65536
                or type(source.get("scalar_allowance_bytes")) is not int or source["scalar_allowance_bytes"] != 32
                or type(source.get("coverage_gap")) is not bool):
            raise ValueError
        counters = {}
        for key in _OPTIONAL_AUDIT_COUNTERS:
            value = source.get(key)
            if type(value) is not int or not 0 <= value <= (1 << 63) - 1:
                raise ValueError
            counters[key] = value
        if (counters["attempted"] != sum(counters[key] for key in (
                "recorded", "rejected", "unavailable", "persistence_unknown", "pending"))
                or counters["rejected"] != counters["rejected_oversize"] + counters["rejected_invalid"]
                or not source["coverage_gap"] and any(counters[key] for key in (
                    "rejected", "unavailable", "persistence_unknown"))):
            raise ValueError
        result.update(counters, state="observed", reason_code="", entry_limit_bytes=65536,
                      scalar_allowance_bytes=32, coverage_gap=source["coverage_gap"])
    except Exception:
        pass
    return result


def _optional_audit_snapshot(ledger=_OPTIONAL_AUDIT_UNSET) -> dict:
    """Read the current instance's memory only; never initialize or query its DB."""
    unavailable = {"schema": 1, "state": "unavailable", "scope": "instance-lifetime",
                   "durable": False, "response_authorized": False}
    try:
        if ledger is _OPTIONAL_AUDIT_UNSET:
            from angerona.core.remediation_log import get_log
            ledger = get_log()
        if ledger is None:
            return dict(unavailable, reason_code="not_initialized")
        reader = getattr(ledger, "optional_audit_snapshot", None)
        if not callable(reader):
            return dict(unavailable, reason_code="reader_unavailable")
        return _optional_audit_view(reader())
    except Exception:
        return dict(unavailable, reason_code="reader_failed")


def optional_audit_status_text(source) -> str:
    """Render validated cached counters without refreshing their source."""
    view = _optional_audit_view(source)
    if view["state"] != "observed":
        return "Optional audit: unavailable; counts unknown.\n" + _OPTIONAL_AUDIT_SCOPE
    counts = ", ".join(f"{key}={view[key]}" for key in _OPTIONAL_AUDIT_COUNTERS)
    return (f"Optional audit: observed; {counts}, coverage_gap={view['coverage_gap']}; "
            f"entry_limit={view['entry_limit_bytes']} UTF-8 bytes.\n" + _OPTIONAL_AUDIT_SCOPE)


def optional_audit_result_text(source) -> str:
    """Render only per-invocation optional-audit results, never native authority."""
    unavailable = ("Optional audit (this invocation): unavailable; counts unknown. "
                   "Native results and closure authority are separate.")
    try:
        if type(source) is not dict or len(source) > 16:
            return unavailable
        source = dict(source)
        if (type(source.get("schema")) is not int or source["schema"] != 1
                or source.get("response_authorized") is not False):
            return unavailable
        counts = {}
        for key in _OPTIONAL_AUDIT_RESULT_COUNTERS:
            value = source.get(key)
            if type(value) is not int or not 0 <= value <= (1 << 63) - 1:
                return unavailable
            counts[key] = value
        if counts["attempted"] != sum(counts[key] for key in _OPTIONAL_AUDIT_RESULT_COUNTERS[1:]):
            return unavailable
        text = ", ".join(f"{key}={counts[key]}" for key in _OPTIONAL_AUDIT_RESULT_COUNTERS)
        return (f"Optional audit (this invocation): {text}. "
                "Native results and closure authority are separate.")
    except Exception:
        return unavailable


_TELEMETRY_STORAGE_COUNTERS = (
    "storage_pending_events", "parked_primary_events", "parked_overflow_events",
    "rejection_storage_hold", "storage_user_discarded", "storage_write_failures", "storage_hold_attempts",
    "replay_deferred", "maintenance_deferred",
)
_TELEMETRY_STORAGE_SCOPE = (
    "Cached telemetry-writer observations, not a drive quota or guaranteed response reserve. "
    "Other writers share the database. Pending events are volatile and may be lost on exit; "
    "counters reset with this instance. Write failures include unconfirmed outcomes. "
    "Zero gaps do not prove complete history."
)


def _telemetry_storage_view(source) -> dict:
    """Whitelist the cached budget DTO; absent facts and counts remain unknown."""
    unavailable = dict(schema=1, state="unavailable", reason_code="invalid_observation",
        scope="telemetry-writer-only", shared_database=True, no_os_quota=True,
        no_response_reserve=True, durable=False)
    try:
        if type(source) is not dict or len(source) > 48:
            return unavailable
        source = dict(source)
        required = (
            "schema", "state", "reason_code", "scope", "shared_database", "no_os_quota",
            "no_response_reserve", "durable", "configured", "blocked", "facts_stale",
            "probe_pending", "coverage_gap", "policy_generation", "facts_generation",
            "unit_limit_bytes", "db_target_bytes", "wal_target_bytes", "min_free_bytes",
            "db_bytes", "wal_bytes", "shm_bytes", "free_bytes", "facts_observed_monotonic",
            "facts_age_seconds", *_TELEMETRY_STORAGE_COUNTERS,
        )
        if any(key not in source for key in required):
            return unavailable
        if (type(source.get("schema")) is not int or source["schema"] != 1
                or type(source.get("state")) is not str or source["state"] not in STORAGE_STATES
                or type(source.get("reason_code")) is not str or source["reason_code"] not in STORAGE_REASONS
                or type(source.get("scope")) is not str or source["scope"] != "telemetry-writer-only"
                or source.get("shared_database") is not True
                or source.get("no_os_quota") is not True
                or source.get("no_response_reserve") is not True
                or source.get("durable") is not False):
            return unavailable
        result = dict(unavailable, state=source["state"], reason_code=source["reason_code"])
        for key in ("configured", "blocked", "facts_stale", "probe_pending", "coverage_gap"):
            if type(source.get(key)) is not bool:
                return unavailable
            result[key] = source[key]
        for key in ("policy_generation", "facts_generation", "unit_limit_bytes", *_TELEMETRY_STORAGE_COUNTERS):
            value = source.get(key)
            if type(value) is not int or not 0 <= value <= (1 << 63) - 1:
                return unavailable
            result[key] = value
        for key in ("db_target_bytes", "wal_target_bytes", "min_free_bytes",
                    "db_bytes", "wal_bytes", "shm_bytes", "free_bytes"):
            value = source.get(key)
            if value is not None and (type(value) is not int or not 0 <= value <= (1 << 63) - 1):
                return unavailable
            result[key] = value
        for key in ("facts_observed_monotonic", "facts_age_seconds"):
            value = source.get(key)
            if value is not None and (type(value) not in (int, float)
                    or not math.isfinite(value) or not 0 <= value <= (1 << 63) - 1):
                return unavailable
            result[key] = value
        if (result["unit_limit_bytes"] != 1048576
                or result["configured"] and result["state"] == "unconfigured"
                or not result["configured"] and result["state"] != "unconfigured"
                or result["facts_generation"] > result["policy_generation"]
                or result["parked_primary_events"] + result["parked_overflow_events"] > result["storage_pending_events"]
                or not result["coverage_gap"] and (
                    result["rejection_storage_hold"] or result["storage_user_discarded"]
                    or result["storage_write_failures"])):
            return unavailable
        target_ranges = (("db_target_bytes", 16, 16384),
                         ("wal_target_bytes", 4, 1024),
                         ("min_free_bytes", 512, 65536))
        if result["configured"]:
            if result["policy_generation"] < 1:
                return unavailable
            for key, lower, upper in target_ranges:
                value = result[key]
                if value is None or not lower * 1024**2 <= value <= upper * 1024**2:
                    return unavailable
        elif result["policy_generation"] != 0 or any(result[key] is not None for key, _, _ in target_ranges):
            return unavailable
        if result["state"] == "ready" and (
                result["reason_code"] != "" or result["blocked"]
                or result["facts_stale"] or result["probe_pending"]
                or result["facts_generation"] != result["policy_generation"]
                or any(result[key] is None for key in (
                    "db_bytes", "wal_bytes", "shm_bytes", "free_bytes",
                    "db_target_bytes", "wal_target_bytes", "min_free_bytes",
                    "facts_observed_monotonic", "facts_age_seconds"))):
            return unavailable
        return result
    except Exception:
        return unavailable


def _telemetry_storage_snapshot(storage) -> dict:
    """Use the existing recorder's memory getter; never construct or probe it."""
    try:
        reader = getattr(storage, "storage_budget_snapshot", None)
        return _telemetry_storage_view(reader() if callable(reader) else None)
    except Exception:
        return _telemetry_storage_view(None)


def telemetry_storage_status_text(source) -> str:
    view = _telemetry_storage_view(source)
    if "storage_pending_events" not in view:
        return "Telemetry storage: unavailable; sizes and counts unknown.\n" + _TELEMETRY_STORAGE_SCOPE
    return (f"Telemetry storage: {view['state']}; reason={view['reason_code'] or 'none'}; "
        f"pending={view['storage_pending_events']}, rejected={view['rejection_storage_hold']}, "
        f"write_failures={view['storage_write_failures']}, "
        f"user_discarded={view['storage_user_discarded']}, coverage_gap={view['coverage_gap']}.\n"
        f"Replay deferral attempts={view['replay_deferred']}; "
        f"maintenance deferral attempts={view['maintenance_deferred']} "
        "(cumulative in this instance, not current backlog counts).\n"
        + _TELEMETRY_STORAGE_SCOPE)


def _worker_identity(module) -> dict:
    """Advisory current-worker correlation, without host queries or module locks."""
    thread = getattr(module, "_thread", None)
    generation = getattr(module, "_lifecycle_generation", None)
    if (not isinstance(thread, threading.Thread) or type(generation) is not int
            or generation < 0 or not thread.is_alive()):
        return {}
    native_id = thread.native_id
    if (type(native_id) is not int or not 0 < native_id <= 0xFFFFFFFF
            or thread is not getattr(module, "_thread", None)
            or generation != getattr(module, "_lifecycle_generation", None)):
        return {}
    return {"native_id": str(native_id), "lifecycle_generation": generation,
            "advisory_only": True}


def _wer_observation_snapshot(manager) -> dict:
    """Whitelist a memory-only diagnostic view; never refresh a WER supplier."""
    result = {
        "schema": 1, "state": "not-configured", "reason_code": "module_absent",
        "advisory_only": True, "response_authorized": False,
        "upstream_delivery_verified": False, "ownership_cache_current": False,
        "scope": "Retained-owner admission only; no suspension or prevention attestation",
        "upstream_scope": "ETW/Sysmon delivery and absent companions remain unproven",
    }
    name = "Deterministic Fast-Path Interceptor"
    module = manager.modules.get(name)
    if module is None:
        return result
    try:
        enabled = manager.is_enabled(name)
        if type(enabled) is not bool:
            raise ValueError
        if not enabled:
            result.update(state="disabled", reason_code="module_disabled")
            return result
        reader = getattr(module, "wer_coverage_snapshot", None)
        if not callable(reader):
            result.update(state="unavailable", reason_code="reader_unavailable")
            return result
        source = reader()
        if type(source) is not dict or len(source) > 40:
            raise ValueError
        source = dict(source)  # One bounded publication copy before later policy checks.
        states = {"unmeasured", "unavailable", "stale", "admitted-at-last-check", "stopped"}
        reasons = {"", "no_observation", "invalid_publication", "generation_changed", "clock_invalid",
                   "clock_regressed", "ownership_rejected", "lease_expired", "invalid_counters",
                   "ingress_lost", "module_stopped", "worker_unavailable"}
        rejections = {"", "supplier_unbound", "caller_clock_invalid", "supplier_failed", "snapshot_type_invalid",
                      "snapshot_empty", "snapshot_oversized", "observation_clock_invalid", "regressed",
                      "row_type_invalid", "row_not_yet_valid", "row_expired", "duplicate_pid"}
        if (type(source.get("schema")) is not int
                or source["schema"] != 1 or type(source.get("state")) is not str
                or len(source["state"]) > 32 or source["state"] not in states
                or type(source.get("reason_code")) is not str
                or len(source["reason_code"]) > 32 or source["reason_code"] not in reasons
                or type(source.get("last_admission_result")) is not str
                or len(source["last_admission_result"]) > 16
                or source["last_admission_result"] not in {"unmeasured", "admitted", "rejected"}
                or type(source.get("ownership_reason_code")) is not str
                or len(source["ownership_reason_code"]) > 32
                or source["ownership_reason_code"] not in rejections
                or source.get("response_authorized") is not False
                or source.get("upstream_delivery_verified") is not False
                or source.get("advisory_only") is not True
                or type(source.get("ownership_cache_current")) is not bool
                or type(source.get("queue_capacity")) is not int or source["queue_capacity"] != 64):
            raise ValueError
        for key in ("lifecycle_generation", "observation_generation", "dropped", "ingress_lost_records",
                    "skipped_admission_attempts", "ownership_snapshot_count", "queued"):
            value = source.get(key)
            if value is not None and (type(value) is not int or not 0 <= value <= (1 << 63) - 1):
                raise ValueError
            result[key] = value
        if result["queued"] is not None and result["queued"] > 64:
            raise ValueError
        if result["dropped"] != result["ingress_lost_records"]:
            raise ValueError
        for key in ("attempted_monotonic", "checked_monotonic", "expires_monotonic", "checked_age_s"):
            value = source.get(key)
            if value is not None and (type(value) not in (int, float)
                                      or not 0 <= value <= 253402300799 or not math.isfinite(value)):
                raise ValueError
            result[key] = value
        roles = source.get("owned_roles")
        if (type(roles) is not tuple or len(roles) > 16
                or any(type(role) is not str or not 1 <= len(role) <= 32 or not role.isascii()
                       or not role[0].islower() or not all(char.islower() or char.isdigit() or char == "-" for char in role)
                       for role in roles)):
            raise ValueError
        if source["ownership_cache_current"]:
            checked, expiry, age = (source.get(key) for key in ("checked_monotonic", "expires_monotonic", "checked_age_s"))
            if (source["last_admission_result"] != "admitted" or source["ownership_reason_code"]
                    or source["state"] not in {"admitted-at-last-check", "unavailable"}
                    or source["state"] == "unavailable" and (source["reason_code"] != "ingress_lost"
                                                              or not source.get("ingress_lost_records"))
                    or source.get("lifecycle_generation") is None
                    or source.get("observation_generation") != source.get("lifecycle_generation")
                    or source.get("ownership_snapshot_count") != len(roles) or not roles
                    or any(result[key] is None for key in ("dropped", "skipped_admission_attempts", "queued"))
                    or checked is None or expiry is None or age is None or not checked < expiry <= checked + 5
                    or checked + age >= expiry):
                raise ValueError
        if source["state"] == "admitted-at-last-check" and (
                not source["ownership_cache_current"] or source.get("ingress_lost_records") != 0 or source["reason_code"]):
            raise ValueError
        # Re-check policy after the reader; a concurrent disable cannot export
        # the old result as current. Free text and unknown keys are never copied.
        enabled = manager.is_enabled(name)
        if type(enabled) is not bool:
            raise ValueError
        if manager.modules.get(name) is not module:
            result.update(state="unmeasured", reason_code="generation_changed", ownership_cache_current=False)
            return result
        if not enabled:
            result.update(state="disabled", reason_code="module_disabled", ownership_cache_current=False)
            return result
        for key in ("state", "reason_code", "last_admission_result", "ownership_reason_code", "ownership_cache_current"):
            result[key] = source[key]
        result.update(owned_roles=roles, queue_capacity=64)
    except Exception:
        # No arbitrary provider exception class/text, path or source payload.
        result = {key: result[key] for key in (
            "schema", "advisory_only", "response_authorized", "upstream_delivery_verified", "scope", "upstream_scope")}
        result.update(state="unavailable", reason_code="invalid_observation", ownership_cache_current=False)
    return result


def _ai_request_snapshot(manager) -> dict:
    """Whitelist cached request timings; never verify a service/model or sample a clock."""
    base = {"schema": 1, "state": "not-configured", "reason_code": "module_absent",
            "advisory_only": True, "response_authorized": False,
            "scope": "Cached request-path stages; inclusive timings are not isolated model cost or inference authority"}
    name = "AI Triage (Ollama)"
    phases = ("service-check", "model-check", "request")
    outcomes = {"unmeasured", "in-progress", "completed", "service-refused", "model-refused",
                "transport-refused", "prompt-refused", "configuration-refused", "circuit-open",
                "chill", "stopped", "generation-changed", "configuration-changed"}

    def counter(value):
        return type(value) is int and 0 <= value <= (1 << 63) - 1

    def number(value):
        return value is None or (type(value) in (int, float)
                                 and 0 <= value <= 253402300799 and math.isfinite(value))

    try:
        module = manager.modules.get(name)
        if module is None:
            return base
        enabled = manager.is_enabled(name)
        if type(enabled) is not bool:
            raise ValueError
        if not enabled:
            return dict(base, state="disabled", reason_code="module_disabled")
        reader = getattr(module, "request_stage_snapshot", None)
        if not callable(reader):
            return dict(base, state="unavailable", reason_code="reader_unavailable")
        source = reader()
        if (type(source) is not dict or len(source) > 24
                or type(source.get("schema")) is not int or source["schema"] != 1
                or source.get("advisory_only") is not True or source.get("response_authorized") is not False
                or type(source.get("state")) is not str or len(source["state"]) > 32
                or source["state"] not in {"unavailable", "unmeasured", "observed"}
                or type(source.get("reason_code")) is not str
                or len(source["reason_code"]) > 32
                or source["reason_code"] not in {"", "invalid_observation", "generation_changed"}):
            raise ValueError
        if source["state"] == "unavailable":
            return dict(base, state="unavailable", reason_code="invalid_observation")
        result = dict(base, state=source["state"], reason_code=source["reason_code"])
        for key in ("lifecycle_generation", "observation_generation", "attempt_count"):
            if not counter(source.get(key)):
                raise ValueError
            result[key] = source[key]
        for key, choices in (("stage", {*phases, "idle", "refused", "cancelled"}), ("outcome", outcomes)):
            value = source.get(key)
            if type(value) is not str or len(value) > 32 or value not in choices:
                raise ValueError
            result[key] = value
        for key in ("started_monotonic", "updated_monotonic"):
            if not number(source.get(key)):
                raise ValueError
            result[key] = source[key]
        if (result["started_monotonic"] is not None and result["updated_monotonic"] is not None
                and result["started_monotonic"] > result["updated_monotonic"]):
            raise ValueError
        entries = source.get("stage_entries")
        timings = source.get("completed_stage_timings")
        if (type(entries) is not dict or len(entries) != 3 or set(entries) != set(phases)
                or any(not counter(entries[key]) for key in phases)
                or type(timings) is not list or len(timings) > 3):
            raise ValueError
        result["stage_entries"] = {key: entries[key] for key in phases}
        rows = []
        for row in timings:
            if (type(row) is not dict or len(row) != 3
                    or set(row) != {"stage", "wall_seconds", "thread_cpu_seconds"}
                    or type(row.get("stage")) is not str or row["stage"] not in phases
                    or any(not number(row.get(key)) for key in ("wall_seconds", "thread_cpu_seconds"))
                    or any(old["stage"] == row["stage"] for old in rows)):
                raise ValueError
            rows.append({key: row[key] for key in ("stage", "wall_seconds", "thread_cpu_seconds")})
        result["completed_stage_timings"] = rows
        if (result["state"] == "observed" and (result["reason_code"] or not result["attempt_count"]
                or result["lifecycle_generation"] != result["observation_generation"])):
            raise ValueError
        if result["reason_code"] == "generation_changed" and (
                result["state"] != "unmeasured" or result["outcome"] != "unmeasured" or result["stage"] != "idle"):
            raise ValueError
        # Reader may have triggered a concurrent replacement/disable. Old timings
        # are historical evidence only; no observation becomes admission authority.
        enabled = manager.is_enabled(name)
        if type(enabled) is not bool:
            raise ValueError
        if manager.modules.get(name) is not module:
            return dict(base, state="unmeasured", reason_code="generation_changed")
        if not enabled:
            return dict(base, state="disabled", reason_code="module_disabled")
        return result
    except Exception:
        return dict(base, state="unavailable", reason_code="invalid_observation")


def _process_inventory_snapshot(owner) -> dict:
    """Copy bounded cached lifecycle evidence; never start or query a process."""
    result = {"state": "not-configured", "ready": False, "retired": False,
              "error_type": "", "advisory_only": True,
              "scope": "Cached inventory lifecycle; native identity and collection coverage are separate."}
    if owner is None:
        return result
    result["state"] = "unavailable"
    gaps = []

    def text(value, default=""):
        if type(value) is not str:
            return default
        if len(value) > 120:
            gaps.append("Cached diagnostic text was truncated")
        return "".join(char if char.isprintable() else " " for char in value[:120])

    def flag(row, name):
        value = row.get(name)
        if type(value) is not bool:
            gaps.append(f"Invalid cached {name} flag")
            return False
        return value

    def error(row, name):
        value = row.get(name)
        if value is None:
            return ""
        if type(value) is not str:
            gaps.append(f"Invalid cached {name}")
            return ""
        return text(value)

    try:
        snapshot = owner.lifecycle_snapshot()
    except Exception as exc:
        result["error_type"] = type(exc).__name__[:120]
        return result
    if type(snapshot) is not dict:
        result["error_type"] = "invalid-lifecycle-snapshot"
        return result
    result.update(state=text(snapshot.get("state"), "unavailable"),
                  ready=flag(snapshot, "ready"), retired=flag(snapshot, "retired"),
                  error_type=error(snapshot, "error_type"))
    if result["state"] not in {"configured", "starting", "running", "unavailable", "retiring", "stopped"}:
        result.update(state="unavailable", ready=False, error_type="invalid-lifecycle-state")
    raw = snapshot.get("provider")
    if type(raw) is not dict:
        result.update(state="unavailable", ready=False,
                      error_type="invalid-provider-snapshot")
        return result
    provider = {"state": text(raw.get("state"), "unavailable"),
                "ready": flag(raw, "ready"), "retired": flag(raw, "retired"),
                "error": error(raw, "error"),
                "retirement_error": error(raw, "retirement_error"),
                "auxiliary_close_unproven": flag(raw, "auxiliary_close_unproven")}
    for name in ("child_pid", "wrapper_pid"):
        value = raw.get(name)
        if value is None or type(value) is int and 0 < value <= 0xFFFFFFFF:
            provider[name] = value
        else:
            provider[name] = None
            gaps.append(f"Invalid cached {name}")
    birth = raw.get("child_birth")
    valid_birth = type(birth) is str and 0 < len(birth) <= 80 and birth.isascii()
    if valid_birth:
        if os.name == "nt":
            valid_birth = birth.isdecimal() and 0 < int(birth) <= 0xFFFFFFFFFFFFFFFF
        else:
            try:
                value = float.fromhex(birth)
                valid_birth = math.isfinite(value) and value > 0 and value.hex() == birth
            except (ValueError, OverflowError):
                valid_birth = False
    provider["child_birth_format"] = "windows-filetime" if os.name == "nt" else "posix-create-time-hex"
    if birth is None or valid_birth:
        provider["child_birth"] = birth  # Preserve the exact producer string, without numeric coercion.
    else:
        provider["child_birth"] = None
        gaps.append("Invalid cached child_birth")
    proofs = raw.get("retirement_proofs", [])
    if type(proofs) is list and len(proofs) <= 3:
        provider["retirement_proof_count"] = len(proofs)
        provider["retirement_waits_signaled"] = bool(proofs) and all(
            type(row) is dict and row.get("wait_signaled") is True for row in proofs)
    else:
        provider["retirement_proof_count"] = None
        provider["retirement_waits_signaled"] = False
        gaps.append("Cached retirement proof summary is unavailable")
    result["provider"] = provider
    if (result["state"] != "running" or result["retired"]
            or result["ready"] is not True or provider["ready"] is not True
            or provider["state"] != "ready" or provider["retired"]
            or provider["error"] or provider["retirement_error"]
            or provider["auxiliary_close_unproven"]):
        result["ready"] = False
        if result["state"] == "running":
            result["state"] = "unavailable"
    if provider["ready"] and any(provider[name] is None for name in ("child_pid", "child_birth", "wrapper_pid")):
        gaps.append("Cached ready provider lacks process identity")
    if gaps:
        result.update(state="unavailable", ready=False, diagnostic_gaps=gaps[:8])
    return result


class StatusReporter:
    def __init__(
        self, bus, storage, manager, config, interval: float = 3.0,
        telemetry_coverage=None, process_snapshot_lifecycle=None,
    ) -> None:
        self.bus, self.storage, self.manager, self.config = bus, storage, manager, config
        self.telemetry_coverage = telemetry_coverage
        self.process_snapshot_lifecycle = process_snapshot_lifecycle
        self.interval = interval
        self._stop = threading.Event()
        self._refresh = threading.Event()
        self._lifecycle_lock = threading.Lock()
        self._health_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._last_material: dict | None = None
        self._last_persisted_at = 0.0
        self._last_success_at: float | None = None
        self._write_failures = 0
        self._last_error_type = ""
        self._write_lock = threading.Lock()
        try:
            import psutil
            self._process_started_at = psutil.Process().create_time()
        except Exception:
            self._process_started_at = None

        # Keep the intended destination even when it is temporarily unavailable.
        self._dirs: List[Path] = [Path(os.path.abspath(config.data_dir)) / "diagnostics"]
        try:
            self._ensure_directory(self._dirs[0])
        except Exception as exc:
            self._record_failure(exc)

    # ── Lifecycle ────────────────────────────────────────────────────────────
    def start(self) -> None:
        with self._lifecycle_lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._start_worker_locked()

    def _start_worker_locked(self) -> None:
        self._refresh.set()
        worker = threading.Thread(target=self._loop, name="StatusReporter", daemon=True)
        worker.start()
        self._thread = worker

    def stop(self) -> None:
        with self._lifecycle_lock:
            self._stop.set()
            self._refresh.set()
            worker = self._thread
            if worker is not None and worker is not threading.current_thread():
                worker.join(timeout=2.0)
        try:
            self._write(force=True)  # one final snapshot on shutdown
        except Exception:
            pass  # _write retains bounded failure evidence for diagnostics.

    def recover(self) -> bool:
        """Request worker-owned refresh; an explicit stop is terminal here.

        Recovery performs no filesystem access on its caller's thread. A live
        worker keeps ownership even when a write is slow or temporarily failing.
        """
        with self._lifecycle_lock:
            if self._stop.is_set():
                return False
            if self._thread is None or not self._thread.is_alive():
                self._start_worker_locked()
            else:
                self._refresh.set()
            return True

    def recovery_snapshot(self) -> dict:
        """Report process-local writer evidence without exposing error text."""
        with self._lifecycle_lock:
            alive = self._thread is not None and self._thread.is_alive()
            stopping = self._stop.is_set()
        with self._health_lock:
            age = (
                None if self._last_success_at is None
                else max(0.0, time.monotonic() - self._last_success_at)
            )
            return {
                "worker_alive": alive,
                "stopping": stopping,
                "last_success_age_seconds": age,
                "write_failures": self._write_failures,
                "last_error_type": self._last_error_type,
                "healthy": bool(
                    alive and not stopping and age is not None
                    and age <= max(120.0, 3.0 * self._effective_interval())
                ),
            }

    def _record_failure(self, exc: Exception) -> None:
        with self._health_lock:
            self._write_failures += 1
            self._last_error_type = type(exc).__name__[:80]

    def _effective_interval(self) -> float:
        """Chill diagnostics are a heartbeat, not a continuous disk workload."""
        if bool(getattr(self.config, "runtime_chill_active", False)):
            return max(60.0, float(self.interval))
        return max(1.0, float(self.interval))

    def _loop(self) -> None:
        while not self._stop.is_set():
            force = self._refresh.is_set()
            if force:
                self._refresh.clear()
            failed = False
            try:
                failed = self._write(force=force) is False
            except Exception as exc:
                self._record_failure(exc)
                failed = True
            if failed:
                # Repeated recovery requests cannot turn a failed write into a
                # busy retry loop. Pending refresh is consumed next interval.
                self._stop.wait(self._effective_interval())
            else:
                self._refresh.wait(self._effective_interval())

    # ── Snapshot ─────────────────────────────────────────────────────────────
    def _bus_snapshot(self, *, with_details: bool = False):
        """Report actual inline-delivery evidence, without inventing a heartbeat.

        The bus has no dispatcher thread: a quiet revision is normal. Counters
        are cumulative for this process and do not prove a callback is currently
        blocked or that all security sensors are healthy.
        """
        rows = self.bus.subscriber_metrics()
        aggregate = {
            "delivery_mode": "inline",
            "revision": self.bus.revision(),
            "subscriber_count": len(rows),
            "deliveries": sum(row.deliveries for row in rows),
            "failures": sum(row.failures for row in rows),
            "budget_violations": sum(row.budget_violations for row in rows),
        }
        if not with_details:
            return aggregate
        try:
            activity = EventBus.subscriber_activity(self.bus) if type(self.bus) is EventBus else None
        except Exception:
            activity = None
        try:
            details = project_subscribers(rows, activity)
        except Exception:
            details = {
                "schema": 1, "state": "unavailable", "advisory_only": True,
                "response_authorized": False, "reason_codes": ["projection_unavailable"],
                "completed": None, "active": None,
            }
        return aggregate, details

    def _snapshot(self) -> dict:
        from angerona.core.threat import (
            active_threat_events, event_disposition, recent_threat_candidates,
        )
        events = self.bus.recent(200)
        active = active_threat_events(recent_threat_candidates(self.bus))
        active_level = max((event.severity for event in active), default=Severity.INFO)
        from angerona.core.module_usage import module_counts
        counts = module_counts(self.manager)
        mods = []
        worker_diagnostics = os.environ.get("ANGERONA_RUNTIME_METRICS") == "1"
        for name, m in sorted(self.manager.modules.items()):
            mods.append({
                "name": m.name, "category": m.category, "version": m.version,
                "status": m.status, "health": m.health, "health_state": m.health_state,
                "health_note": m.health_note, "enabled": self.manager.is_enabled(name),
                "last_error": m.last_error,
            })
            if worker_diagnostics:
                mods[-1]["worker"] = _worker_identity(m)
        telemetry = {}
        evicted_sensors = 0
        visibility = {
            "authority_configured": False,
            "sensors": {},
            "evicted_sensors": 0,
            "rejected_documents": 0,
            "limitation": (
                "No sensor visibility authority is configured; no native or "
                "hardware-backed visibility proof is claimed."
            ),
        }
        if self.telemetry_coverage is not None:
            telemetry = {
                sensor_id: {
                    "status": item.status,
                    "first_sequence": item.first_sequence,
                    "last_sequence": item.last_sequence,
                    "accepted": item.accepted,
                    "missing": item.missing,
                    "duplicates": item.duplicates,
                    "regressions": item.regressions,
                    "unsequenced": item.unsequenced,
                    "last_observed_at": item.last_observed_at,
                    "reason": item.reason,
                }
                for sensor_id, item in self.telemetry_coverage.snapshot().items()
            }
            evicted_sensors = self.telemetry_coverage.evicted_sensors
            visibility_snapshot = getattr(
                self.telemetry_coverage, "visibility_snapshot", None
            )
            if callable(visibility_snapshot):
                visibility = visibility_snapshot()
        active_critical = sum(
            1 for event in active if event.severity == Severity.CRITICAL
        )
        healer = getattr(self, "runtime_healer", None)
        recovery = healer.snapshot() if healer is not None else None
        # These are memory-only views. Capturing why response is held must not
        # read a journal, hash a model or probe a service on each status write.
        response = {"ready": False, "state": "UNAVAILABLE", "reason": "Response worker unavailable."}
        combat = self.manager.modules.get("Adversary Combat")
        reader = getattr(combat, "response_snapshot", None)
        if callable(reader):
            try:
                response = reader()
            except Exception:
                pass
        from dataclasses import asdict
        from angerona.core.ollama_lifecycle import startup_snapshot
        ollama_startup = asdict(startup_snapshot(self.config.ollama_host))
        event_bus, event_bus_subscribers = self._bus_snapshot(with_details=True)
        process_cycle = {"schema": 1, "state": "unavailable", "response_authorized": False}
        # Exact built-in cache getter only: no collection, callback execution,
        # SQLite, native I/O or module-defined custom accessor is admitted here.
        from angerona.modules.process_monitor import ProcessMonitorModule
        process_monitor = self.manager.modules.get("Process Monitor")
        if type(process_monitor) is ProcessMonitorModule:
            process_cycle = ProcessMonitorModule.cycle_diagnostic_snapshot(process_monitor)
        return {
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "generated_ts": time.time(),
            "pid": os.getpid(),
            "process_started_at": self._process_started_at,
            "heartbeat_interval_s": max(
                self._effective_interval(),
                60.0 if getattr(self.config, "runtime_chill_active", False) else 30.0,
            ),
            "event_bus": event_bus,
            "event_bus_subscribers": event_bus_subscribers,
            "process_monitor_cycle": process_cycle,
            "process_inventory": _process_inventory_snapshot(self.process_snapshot_lifecycle),
            "wer_observation": _wer_observation_snapshot(self.manager),
            "ai_request": _ai_request_snapshot(self.manager),
            "normal_crashlog": normal_log_status(),
            "optional_audit": _optional_audit_snapshot(),
            "telemetry_storage": _telemetry_storage_snapshot(self.storage),
            "runtime_healer": recovery,
            "automatic_response": response,
            "app_version": __version__,
            "admin": is_admin(),
            "threat_level": _THREAT[active_level],
            "chill_mode": bool(getattr(self.config, "runtime_chill_active", False)),
            "counts": {
                "modules_total": counts["enabled"],
                "modules_running": counts["running"],
                "modules_off": counts["off"],
                "modules_discovered": counts["discovered"],
                "alerts_24h": self.storage.count_since(time.time() - 86400),
                # Backward-compatible key: aliases the ten-minute live-hostile
                # count among retained, unresolved event evidence.
                "critical_24h": active_critical,
                "active_critical_10m": active_critical,
            },
            "ollama": {"host": self.config.ollama_host, "model": self.config.ollama_model,
                       "startup": ollama_startup},
            "telemetry_coverage": {
                "sensors": telemetry,
                "evicted_sensors": evicted_sensors,
                "limitation": (
                    "Healthy means no observed sequence discontinuity in this "
                    "process lifetime; it does not prove complete collection."
                ),
            },
            "sensor_visibility_attestations": visibility,
            "modules": mods,
            "recent_events": [
                {"time": e.time_str, "module": e.module,
                 "severity": e.severity.label, "disposition": event_disposition(e),
                 "message": e.message}
                for e in events[:60]
            ],
        }

    def _render_text(self, s: dict) -> str:
        c = s["counts"]
        inventory = s.get("process_inventory", {})
        inventory_error = (inventory.get("provider", {}).get("error")
                           or inventory.get("error_type")
                           or "cached lifecycle only; collection coverage is separate")
        wer = s.get("wer_observation", {})
        ai_request = s.get("ai_request", {})
        normal_logs = s.get("normal_crashlog", {})
        lines = [
            "=" * 78,
            " ANGERONA — LIVE STATUS SNAPSHOT",
            "=" * 78,
            f" Generated : {s['generated']}     v{s['app_version']}     Admin: {s['admin']}",
            f" Threat    : {s['threat_level']}"
            f"     Chill: {'ON' if s.get('chill_mode') else 'OFF'}",
            f" Modules   : {c['modules_running']}/{c['modules_total']} running"
            f"     Alerts(24h): {c['alerts_24h']}"
            f"     ActiveCritical(10m): {c['active_critical_10m']}",
            f" Ollama    : {s['ollama']['host']}  (model: {s['ollama']['model']})",
            f" AI startup: {s['ollama'].get('startup', {}).get('percent', 0)}% "
            f"{s['ollama'].get('startup', {}).get('stage', 'Not requested')}",
            f" AI request: {ai_request.get('state', 'unavailable')} / {ai_request.get('stage', 'unmeasured')} "
            f"— {ai_request.get('outcome', ai_request.get('reason_code', 'unmeasured'))}",
            "             Cached inclusive stage timings; no service/model refresh or inference authority.",
            f" Log budget: {normal_logs.get('state', 'unavailable')} — "
            f"limit={normal_logs.get('limit_bytes')} bytes/target/process; paused={normal_logs.get('paused')}",
            "             Cached normal Python/Qt writes only; native/external writers are outside this budget.",
            optional_audit_status_text(s.get("optional_audit")),
            telemetry_storage_status_text(s.get("telemetry_storage")),
            f" Response  : {s.get('automatic_response', {}).get('state', 'UNAVAILABLE')} "
            f"— {s.get('automatic_response', {}).get('reason', '')}",
            f" Inventory : {inventory.get('state', 'unavailable')} — {inventory_error}",
            f" WER       : {wer.get('state', 'unmeasured')} — {wer.get('reason_code', 'no_observation')}",
            f"             last={wer.get('last_admission_result', 'unmeasured')} "
            f"ownership={wer.get('ownership_reason_code', '') or 'no rejection recorded'} "
            f"age={wer.get('checked_age_s')}s lost={wer.get('ingress_lost_records', 'unknown')}",
            "             Retained-owner admission only; ETW/Sysmon delivery, absent companions and prevention remain unproven.",
            "",
            "-" * 78,
            " TELEMETRY COVERAGE",
            "-" * 78,
        ]
        coverage = s["telemetry_coverage"]
        if not coverage["sensors"]:
            lines.append("  No sensor sequence observations; coverage is unknown.")
        for sensor_id, item in coverage["sensors"].items():
            lines.append(
                f"  {sensor_id:<26} {item['status']:<8} "
                f"last={item['last_sequence']} missing={item['missing']} "
                f"duplicates={item['duplicates']} regressions={item['regressions']}"
            )
        if coverage["evicted_sensors"]:
            lines.append(
                f"  Sensor records evicted by cardinality bound: "
                f"{coverage['evicted_sensors']}"
            )
        visibility = s["sensor_visibility_attestations"]
        lines += ["", " SENSOR VISIBILITY ATTESTATIONS"]
        if not visibility["authority_configured"]:
            lines.append("  Not configured; no sensor visibility proof is claimed.")
        elif not visibility["sensors"]:
            lines.append("  No authenticated sensor visibility assertions received.")
        for sensor_id, item in visibility["sensors"].items():
            lines.append(
                f"  {sensor_id:<26} {item['classification']:<10} "
                f"seq={item['sequence']} drops={item['drop_count']} "
                f"clock={item['clock_quality']}"
            )
        if visibility["evicted_sensors"]:
            lines.append(
                "  Visibility records evicted by cardinality bound: "
                f"{visibility['evicted_sensors']}"
            )
        if visibility["rejected_documents"]:
            lines.append(
                f"  Rejected visibility documents: {visibility['rejected_documents']}"
            )
        lines.append(f"  Limitation: {visibility['limitation']}")
        if s.get("runtime_healer") is not None:
            lines += ["", " RUNTIME RECOVERY"]
            healing = s["runtime_healer"]
            lines.append(
                f"  Enabled: {bool(healing.get('enabled'))}"
                f"  Worker alive: {bool(healing.get('worker_alive'))}"
            )
            for name, item in healing.get("components", {}).items():
                lines.append(
                    f"  {name}: {item.get('state', 'unknown')}"
                    f" / attempts={item.get('attempts', 0)}"
                    f" / last result={item.get('last_result', '')}"
                )
                evidence = item.get("evidence", {})
                if "admission_rejected" in evidence:
                    lines.append(
                        "    Recorder delivery rejections: "
                        f"{evidence['admission_rejected']}"
                        f" / delivery/write coverage gap={evidence.get('coverage_gap', False)}"
                        " (process-lifetime counters; not a durable loss journal)"
                    )
        lines += [
            "",
            "-" * 78,
            " MODULES",
            "-" * 78,
        ]
        for m in s["modules"]:
            flag = "x" if m["enabled"] else " "
            health = f"{m['health']:>3}% {m['health_state']:<9}"
            line = f"  [{flag}] {m['status']:<8} {health} {m['name']:<26} ({m['category']})"
            if m.get("health_note"):
                line += f"\n        note: {m['health_note']}"
            if m["last_error"]:
                line += f"\n        last error: {m['last_error']}"
            lines.append(line)
        lines += ["", "-" * 78, " RECENT EVENTS (newest first)", "-" * 78]
        for e in s["recent_events"]:
            lines.append(f"  {e['time']}  {e['severity']:<8} {e['module']:<26} {e['message']}")
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _reject_linked_path(path: Path) -> None:
        """Fail closed for existing links/reparse points, including ancestors."""
        absolute = Path(os.path.abspath(path))
        for current in (absolute, *absolute.parents):
            try:
                metadata = current.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(metadata.st_mode) or (
                getattr(metadata, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            ):
                raise OSError("status destination traverses a linked path")
            if current == absolute and not stat.S_ISDIR(metadata.st_mode):
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink > 1:
                    raise OSError("status destination is not an ordinary file")

    @classmethod
    def _ensure_directory(cls, path: Path) -> None:
        cls._reject_linked_path(path)
        path.mkdir(parents=True, exist_ok=True)
        cls._reject_linked_path(path)

    @staticmethod
    def _atomic_write(path: Path, content: str) -> None:
        """Keep the previous complete snapshot readable until replacement."""
        StatusReporter._reject_linked_path(path)
        descriptor, name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
            StatusReporter._reject_linked_path(path)
            replace_with_retry(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def _write(self, *, force: bool = False) -> bool:
        # Shutdown may request its final snapshot while the reporter is writing.
        with self._write_lock:
            try:
                self._write_locked(force=force)
                return True
            except Exception as exc:
                self._record_failure(exc)
                return False

    def _write_locked(self, *, force: bool = False) -> None:
        snap = self._snapshot()
        material = dict(snap)
        material.pop("generated", None)
        material.pop("generated_ts", None)
        cycle = material.get("process_monitor_cycle")
        if type(cycle) is dict:
            # Routine work continuously changes stage stamps/counts/durations.
            # Keep that fresh detail when another change or the existing quiet
            # heartbeat warrants a write; it must not itself become a new timer.
            # Loss, source generation and terminal/startup transitions remain
            # material. This fingerprint never changes the snapshot we persist.
            stage = cycle.get("stage")
            execution_state = (
                stage if type(stage) is str and stage in {"unobserved", "startup", "stopped"}
                else "cycling"
            )
            material["process_monitor_cycle"] = {
                key: cycle.get(key) for key in
                ("schema", "state", "generation", "update_loss", "response_authorized")
            }
            material["process_monitor_cycle"]["execution_state"] = execution_state
        now = time.monotonic()
        heartbeat = 60.0 if snap.get("chill_mode") else 30.0
        if (
            not force
            and self._last_material == material
            and now - self._last_persisted_at < heartbeat
        ):
            return
        text = self._render_text(snap)
        wrote = False
        last_error = None
        for d in self._dirs:
            try:
                self._ensure_directory(d)
                self._atomic_write(d / "status.json", json.dumps(snap, indent=2))
                self._atomic_write(d / "status.txt", text)
                wrote = True
            except Exception as exc:
                last_error = exc
                continue
        if wrote:
            self._last_material = material
            self._last_persisted_at = now
            with self._health_lock:
                self._last_success_at = time.monotonic()
                self._last_error_type = ""
        elif last_error is not None:
            raise last_error
