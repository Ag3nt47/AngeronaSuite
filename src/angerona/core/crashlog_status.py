"""Bounded, read-only projection of cached normal crash-log observations.

This module does not install hooks, configure logging, inspect files or sample
a clock. Its supplier is imported only when a status projection is requested.
"""
from __future__ import annotations

from datetime import datetime

_MAX_COUNT = (1 << 63) - 1
_MAX_ALLOWANCE = 64 * 1024 * 1024
_ROLES = ("logs", "diagnostics")
_SOURCE_KEYS = frozenset({
    "schema", "limit_bytes", "message_bytes", "paused", "configured_at",
    "suppression_counts_lower_bound", "observations_cached", "native_fault_bytes_limited",
    "external_writers_limited", "os_quota", "targets",
})
_ROW_FIELDS = (
    "role", "reserved_bytes", "appended_bytes", "appended_blocks", "uncertain_bytes",
    "state", "reason", "checked_size_bytes", "checked_at", "suppressed_blocks",
    "suppressed_known_bytes", "suppressed_unknown_size_blocks", "last_suppression",
)
_ROW_KEYS = frozenset(_ROW_FIELDS)
_COUNTERS = (
    "reserved_bytes", "appended_bytes", "appended_blocks", "uncertain_bytes",
    "suppressed_blocks", "suppressed_known_bytes", "suppressed_unknown_size_blocks",
)
_REASONS = frozenset({
    "", "not-installed", "policy-paused", "resume-check-required",
    "file-limit", "process-limit", "io-uncertain",
})
_SUPPRESSIONS = frozenset({
    "", "lock-contention", "message-invalid", "message-limit", "policy-paused",
    "file-limit", "process-limit", "io-uncertain",
})
_SCOPE = ("Cached normal Python/Qt append allowances only; not an operating-system disk quota. "
          "Native fault output and external writers are not limited by these allowances.")
_OBSERVATION_SCOPE = (
    "Writer rows, suppression counters and configuration may have different as-of times. "
    "Checked sizes describe earlier opened-file checks, not current file presence, "
    "native capture health or protection status."
)


def _shape(value, keys: frozenset[str]) -> dict:
    if type(value) is not dict or len(value) != len(keys):
        raise ValueError
    value = value.copy()
    if (len(value) != len(keys)
            or any(type(key) is not str or len(key) > 40 or key not in keys for key in value)):
        raise ValueError
    return value


def _counter(value) -> bool:
    return type(value) is int and 0 <= value <= _MAX_COUNT


def _enum(value, choices) -> bool:
    return type(value) is str and len(value) <= 32 and value in choices


def _stamp(value) -> bool:
    if value is None:
        return True
    if (type(value) is not str or len(value) != 25 or not value.isascii()
            or not value.endswith("+00:00")):
        return False
    try:
        # Parse only bounded supplied text. There is deliberately no now(),
        # age calculation or assertion that this wall-clock value is current.
        return datetime.fromisoformat(value).isoformat(timespec="seconds") == value
    except ValueError:
        return False


def _unavailable() -> dict:
    return {
        "schema": 1, "state": "unavailable", "reason_code": "invalid_observation",
        "advisory_only": True, "scope": _SCOPE, "observation_scope": _OBSERVATION_SCOPE,
        "observations_cached": True, "native_fault_bytes_limited": False,
        "external_writers_limited": False, "os_quota": False,
        "limit_bytes": None, "message_bytes": None, "paused": None, "configured_at": None,
        "suppression_counts_lower_bound": True,
        "targets": tuple({
            "role": role, **{key: None for key in _COUNTERS},
            "state": "unavailable", "reason": "invalid-observation",
            "checked_size_bytes": None, "checked_at": None, "last_suppression": "",
        } for role in _ROLES),
    }


def _row(source, role: str, paused: bool, count_gap: bool) -> dict:
    row = _shape(source, _ROW_KEYS)
    if (type(row["role"]) is not str or row["role"] != role
            or not _enum(row["state"], {"not-installed", "ready", "held"})
            or not _enum(row["reason"], _REASONS)
            or not _enum(row["last_suppression"], _SUPPRESSIONS)
            or any(not _counter(row[key]) for key in _COUNTERS)):
        raise ValueError
    if (any(row[key] > _MAX_ALLOWANCE for key in (
            "reserved_bytes", "appended_bytes", "uncertain_bytes"))
            or row["reserved_bytes"] != row["appended_bytes"] + row["uncertain_bytes"]
            or bool(row["appended_blocks"]) != bool(row["appended_bytes"])
            or row["appended_blocks"] > row["appended_bytes"]):
        raise ValueError

    checked, stamp = row["checked_size_bytes"], row["checked_at"]
    if ((checked is None) != (stamp is None) or checked is not None and not _counter(checked)
            or not _stamp(stamp)):
        raise ValueError
    if row["reserved_bytes"] and checked is None:
        raise ValueError
    reason = row["reason"]
    expected = "held" if paused or reason not in ("", "not-installed") else (
        "not-installed" if reason == "not-installed" else "ready")
    if (row["state"] != expected
            or paused and reason not in {"policy-paused", "io-uncertain"}
            or reason == "" and (checked is None or not row["appended_bytes"])
            or reason in {"file-limit", "process-limit"} and checked is None
            or reason == "process-limit" and not row["reserved_bytes"]
            or row["uncertain_bytes"] and reason != "io-uncertain"
            or reason == "not-installed" and (row["reserved_bytes"] or checked is not None)):
        raise ValueError

    count, known, unknown = (row[key] for key in (
        "suppressed_blocks", "suppressed_known_bytes", "suppressed_unknown_size_blocks"))
    if (unknown > count or bool(count) != bool(row["last_suppression"])
            or not count and (known or unknown)
            or not known and unknown != count
            or not count_gap and known and unknown == count):
        raise ValueError
    # All copied values now have exact primitive types, bounded sizes and fixed
    # keys. Never copy provider paths, exception text or arbitrary annotations.
    return {key: row[key] for key in _ROW_FIELDS}


def normal_log_status() -> dict:
    """Whitelist one cached supplier result, or return a fixed coverage gap."""
    try:
        from angerona.core.crashlog import normal_write_snapshot

        source = _shape(normal_write_snapshot(), _SOURCE_KEYS)
        if (type(source["schema"]) is not str
                or source["schema"] != "angerona-normal-crashlog-budget-v1"
                or type(source["limit_bytes"]) is not int
                or not 1024 * 1024 <= source["limit_bytes"] <= _MAX_ALLOWANCE
                or source["limit_bytes"] % (1024 * 1024)
                or type(source["message_bytes"]) is not int
                or not 4 * 1024 <= source["message_bytes"] <= 256 * 1024
                or source["message_bytes"] % 1024
                or type(source["paused"]) is not bool
                or type(source["suppression_counts_lower_bound"]) is not bool
                or not _stamp(source["configured_at"])
                or source["observations_cached"] is not True
                or source["native_fault_bytes_limited"] is not False
                or source["external_writers_limited"] is not False
                or source["os_quota"] is not False
                or type(source["targets"]) is not tuple or len(source["targets"]) != 2):
            raise ValueError
        rows = tuple(_row(row, role, source["paused"], source["suppression_counts_lower_bound"])
                     for role, row in zip(_ROLES, source["targets"]))
        result = _unavailable()
        result.update(state="available", reason_code="", targets=rows)
        for key in ("limit_bytes", "message_bytes", "paused", "configured_at",
                    "suppression_counts_lower_bound"):
            result[key] = source[key]
        return result
    except Exception:
        # Import/supplier/validation failures all export the same bounded gap.
        # No exception class, message or partially accepted provider row escapes.
        return _unavailable()
