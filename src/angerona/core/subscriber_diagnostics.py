"""Bounded, non-authoritative projections of cached inline-delivery timings."""
from __future__ import annotations

import json
import math

from angerona.core.eventbus import (
    ActiveSubscriberDelivery, SubscriberActivity, SubscriberMetrics,
)

ROW_LIMIT = 64
BYTE_LIMIT = 16 * 1024
_MAX_COUNTER = 2**63 - 1
_MAX_DURATION = 2**53 - 1
_SCOPE = (
    "Advisory callback wall timings for current registrations; labels are not unique. "
    "Removed registrations disappear and replacements can reset counters. Concurrent "
    "callbacks overlap. Start stamps and completed timings grant no liveness, coverage, "
    "thread-affinity, trust or response authority."
)


def _unknown() -> dict:
    return {
        "state": "unavailable", "total_rows": None, "inspected_rows": None,
        "retained_rows": 0, "unavailable_rows": None, "omitted_rows": None,
        "row_limit_omitted_rows": None, "byte_budget_omitted_rows": None,
        "producer_omitted_rows": None, "rows": [],
    }


def _counter(value: object) -> bool:
    return type(value) is int and 0 <= value <= _MAX_COUNTER


def _number(value: object) -> bool:
    return (type(value) in (int, float) and 0 <= value <= _MAX_DURATION
            and math.isfinite(value))


def _name(value: object) -> tuple[str, bool]:
    if (type(value) is not str or not value or len(value) > 200
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError("invalid label")
    value.encode("utf-8", "strict")
    result = value[:160]
    while len(result.encode("utf-8")) > 480:
        result = result[:-1]
    return result, result != value


def _row(source: object, *, active: bool) -> dict:
    expected = ActiveSubscriberDelivery if active else SubscriberMetrics
    if type(source) is not expected:
        raise ValueError("invalid row")
    name, truncated = _name(source.name)
    result = {"name": name, "name_truncated": truncated}
    if active:
        if not _number(source.started_monotonic):
            raise ValueError("invalid start")
        return {**result, "started_monotonic": source.started_monotonic}
    counters = (source.deliveries, source.failures, source.budget_violations)
    timings = (source.last_delivery_ms, source.max_delivery_ms, source.total_delivery_ms)
    if (not all(_counter(value) for value in counters)
            or source.failures > source.deliveries
            or source.budget_violations > source.deliveries
            or not all(_number(value) for value in timings)
            or not _number(source.delivery_budget_ms)
            or not 0.1 <= source.delivery_budget_ms <= 60_000
            or not source.last_delivery_ms <= source.max_delivery_ms <= source.total_delivery_ms
            or (source.deliveries == 0 and any((*counters, *timings)))):
        raise ValueError("invalid metrics")
    return {
        **result, "delivery_budget_ms": source.delivery_budget_ms,
        "deliveries": source.deliveries, "failures": source.failures,
        "budget_violations": source.budget_violations,
        "last_delivery_ms": source.last_delivery_ms,
        "max_delivery_ms": source.max_delivery_ms,
        "total_delivery_ms": source.total_delivery_ms,
    }


def _section(rows: tuple, omitted: int, allowance: int, *, active: bool) -> dict:
    inspected = min(len(rows), allowance)
    result = {
        "state": "observed", "total_rows": len(rows) + omitted,
        "inspected_rows": inspected, "retained_rows": 0, "unavailable_rows": 0,
        "omitted_rows": len(rows) - inspected + omitted,
        "row_limit_omitted_rows": len(rows) - inspected,
        "byte_budget_omitted_rows": 0, "producer_omitted_rows": omitted, "rows": [],
    }
    for index in range(inspected):
        try:
            result["rows"].append(_row(rows[index], active=active))
        except (TypeError, ValueError, AttributeError, UnicodeError, OverflowError):
            result["unavailable_rows"] += 1
    result["retained_rows"] = len(result["rows"])
    return result


def encoded_projection_bytes(block: dict) -> int:
    """Exact indent=2 status-field fragment, including its enclosing field."""
    return len(json.dumps(
        {"event_bus_subscribers": block}, indent=2, allow_nan=False,
    ).encode("utf-8"))


def project_subscribers(completed: object, activity: object) -> dict:
    """Inspect at most 64 exact rows; never invoke callback/custom converters.

    The 16 KiB cap uses the actual indent=2 status-field fragment, rather than
    compact JSON. No clock is read, preserving existing quiet-write suppression.
    """
    block = {
        "schema": 1, "advisory_only": True, "response_authorized": False,
        "row_limit": ROW_LIMIT, "byte_limit": BYTE_LIMIT, "scope": _SCOPE,
        "state": "observed", "reason_codes": [],
        "completed": _unknown(), "active": _unknown(),
    }
    try:
        remaining = ROW_LIMIT
        if (type(activity) is SubscriberActivity and type(activity.rows) is tuple
                and len(activity.rows) <= ROW_LIMIT and _counter(activity.untracked_active)
                and activity.untracked_active <= _MAX_COUNTER - len(activity.rows)):
            block["active"] = _section(
                activity.rows, activity.untracked_active, remaining, active=True,
            )
            remaining -= block["active"]["inspected_rows"]
        if type(completed) is tuple:
            block["completed"] = _section(completed, 0, remaining, active=False)
        for name in ("active", "completed"):
            section = block[name]
            if section["state"] == "unavailable":
                block["reason_codes"].append("source_unavailable")
                continue
            if section["omitted_rows"]:
                block["reason_codes"].append("row_limit")
            if section["unavailable_rows"]:
                block["reason_codes"].append("invalid_row")
        # Prefer the current blocked-callback observations if bytes run short.
        while encoded_projection_bytes(block) > BYTE_LIMIT:
            section = block["completed"] if block["completed"]["rows"] else block["active"]
            if not section["rows"]:
                raise ValueError("envelope exceeds budget")
            section["rows"].pop()
            section["retained_rows"] -= 1
            section["byte_budget_omitted_rows"] += 1
            section["omitted_rows"] += 1
            if "byte_limit" not in block["reason_codes"]:
                block["reason_codes"].append("byte_limit")
        for name in ("active", "completed"):
            section = block[name]
            if section["state"] != "unavailable" and (section["omitted_rows"] or section["unavailable_rows"]):
                section["state"] = "partial"
        block["reason_codes"] = sorted(set(block["reason_codes"]))
        if block["reason_codes"]:
            block["state"] = "partial"
        if all(block[name]["state"] == "unavailable" for name in ("active", "completed")):
            block["state"] = "unavailable"
        return block
    except Exception:
        block.update(state="unavailable", reason_codes=["projection_unavailable"],
                     completed=_unknown(), active=_unknown())
        return block
