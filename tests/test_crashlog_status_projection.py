from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from angerona.core import crashlog, crashlog_status

_STAMP = "2026-10-30T12:00:00+00:00"
_MAX_COUNT = (1 << 63) - 1


def _source():
    return {
        "schema": "angerona-normal-crashlog-budget-v1",
        "limit_bytes": 8 * 1024 * 1024, "message_bytes": 64 * 1024,
        "paused": False, "configured_at": None,
        "suppression_counts_lower_bound": False, "observations_cached": True,
        "native_fault_bytes_limited": False, "external_writers_limited": False,
        "os_quota": False,
        "targets": tuple({
            "role": role, "reserved_bytes": 0, "appended_bytes": 0,
            "appended_blocks": 0, "uncertain_bytes": 0, "state": "not-installed",
            "reason": "not-installed", "checked_size_bytes": None, "checked_at": None,
            "suppressed_blocks": 0, "suppressed_known_bytes": 0,
            "suppressed_unknown_size_blocks": 0, "last_suppression": "",
        } for role in ("logs", "diagnostics")),
    }


@pytest.fixture
def supplier(monkeypatch):
    source, calls = _source(), []

    def read():
        calls.append(True)
        return source

    monkeypatch.setattr(crashlog, "normal_write_snapshot", read)
    return SimpleNamespace(source=source, calls=calls)


def _assert_gap(result):
    assert result == crashlog_status._unavailable()
    assert result["state"] == "unavailable" and result["reason_code"] == "invalid_observation"
    assert result["suppression_counts_lower_bound"]
    assert tuple(row["role"] for row in result["targets"]) == ("logs", "diagnostics")
    assert "private" not in json.dumps(result)


def test_real_cached_getter_is_memory_only_and_never_installs_or_reconfigures(monkeypatch):
    rows = tuple((role, 400, 400, 1, 0, "", 12, _STAMP) for role in ("logs", "diagnostics"))
    monkeypatch.setattr(crashlog, "_NORMAL_CACHE", (8 * 1024 * 1024, 64 * 1024, False, None, rows))
    monkeypatch.setattr(crashlog, "_NORMAL_SUPPRESSIONS",
                        {role: (1, 0, 1, "lock-contention") for role in ("logs", "diagnostics")})
    monkeypatch.setattr(crashlog, "_NORMAL_COUNT_GAP", False)

    def forbidden(*_args, **_kwargs):
        pytest.fail("status attempted installation, configuration, I/O, clock or native work")

    for name in ("install", "configure_normal_log_budget", "fstat", "_normal_stamp", "_write"):
        monkeypatch.setattr(crashlog, name, forbidden)
    monkeypatch.setattr(crashlog, "open", forbidden, raising=False)
    monkeypatch.setattr(crashlog, "datetime", SimpleNamespace(datetime=SimpleNamespace(now=forbidden)))
    monkeypatch.setattr(crashlog, "os", SimpleNamespace(getpid=forbidden))
    crashlog._NORMAL_LOCK.acquire()
    crashlog._NORMAL_STATS_LOCK.acquire()
    try:
        result = crashlog_status.normal_log_status()
    finally:
        crashlog._NORMAL_STATS_LOCK.release()
        crashlog._NORMAL_LOCK.release()
    assert result["state"] == "available" and result["reason_code"] == ""
    assert result["targets"][0]["appended_bytes"] == 400
    assert result["targets"][0]["checked_size_bytes"] == 12
    assert result["targets"][0]["last_suppression"] == "lock-contention"
    assert result["observations_cached"] and result["advisory_only"]
    assert result["native_fault_bytes_limited"] is False
    assert result["external_writers_limited"] is False and result["os_quota"] is False
    assert "different as-of times" in result["observation_scope"]
    assert "not an operating-system disk quota" in result["scope"]


def test_fixed_shape_one_read_and_detached_rows(supplier):
    result = crashlog_status.normal_log_status()
    assert supplier.calls == [True]
    assert result["state"] == "available" and len(result["targets"]) == 2
    assert set(result) == set(crashlog_status._unavailable())
    assert set(result["targets"][0]) == set(crashlog_status._unavailable()["targets"][0])
    result["targets"][0]["reserved_bytes"] = 99
    assert supplier.source["targets"][0]["reserved_bytes"] == 0
    supplier.source["targets"][1]["reason"] = "private-altered-after-read"
    assert result["targets"][1]["reason"] == "not-installed"


@pytest.mark.parametrize("field,value", [
    ("schema", "private-schema"), ("schema", 1),
    ("limit_bytes", True), ("limit_bytes", 1024 * 1024 - 1),
    ("limit_bytes", 64 * 1024 * 1024 + 1), ("limit_bytes", 1024 * 1024 + 1),
    ("message_bytes", False), ("message_bytes", 4095),
    ("message_bytes", 256 * 1024 + 1), ("message_bytes", 4097),
    ("paused", 0), ("suppression_counts_lower_bound", 1),
    ("observations_cached", False), ("native_fault_bytes_limited", True),
    ("external_writers_limited", True), ("os_quota", True),
    ("configured_at", "private-path"), ("configured_at", "2026-02-30T12:00:00+00:00"),
    ("configured_at", "2026-10-30T12:00:00Z"),
    ("configured_at", "2026-10-30T12:00:00+01:00"),
    ("configured_at", "2026-10-30T12:00:00.000000+00:00"),
    ("configured_at", "private" * 100_000),
    ("targets", []), ("targets", ()), ("targets", ({},) * 100_000),
], ids=[
    "schema-unknown", "schema-number", "limit-bool", "limit-below", "limit-above",
    "limit-unaligned", "message-bool", "message-below", "message-above", "message-unaligned",
    "paused-number", "count-gap-number", "cache-false", "native-quota-true",
    "external-quota-true", "os-quota-true", "configured-invalid", "configured-invalid-date",
    "configured-z-suffix", "configured-offset", "configured-fraction", "configured-oversized",
    "targets-list", "targets-empty", "targets-oversized",
])
def test_invalid_top_level_values_never_escape(supplier, field, value):
    supplier.source[field] = value
    _assert_gap(crashlog_status.normal_log_status())
    assert supplier.calls == [True]


@pytest.mark.parametrize("field,value", [
    ("role", "private/path"), ("state", "private-state"), ("reason", "private-error"),
    ("last_suppression", "private-message"), ("reserved_bytes", True),
    ("appended_bytes", -1), ("appended_blocks", 0.0),
    ("uncertain_bytes", 64 * 1024 * 1024 + 1),
    ("suppressed_blocks", _MAX_COUNT + 1), ("suppressed_known_bytes", "private"),
    ("suppressed_unknown_size_blocks", False), ("checked_size_bytes", -1),
    ("checked_size_bytes", True), ("checked_at", _STAMP),
    ("checked_at", "private" * 100_000),
], ids=[
    "role-unknown", "state-unknown", "reason-unknown", "suppression-unknown", "reserved-bool",
    "appended-negative", "blocks-float", "uncertain-above", "suppressed-above",
    "suppressed-bytes-text", "unknown-size-bool", "checked-negative", "checked-bool",
    "checked-orphan-timestamp", "checked-oversized-timestamp",
])
def test_invalid_row_values_never_escape(supplier, field, value):
    supplier.source["targets"][0][field] = value
    _assert_gap(crashlog_status.normal_log_status())


@pytest.mark.parametrize("changes", [
    {"reserved_bytes": 1},
    {"reserved_bytes": 1, "appended_bytes": 1},
    {"appended_blocks": 1},
    {"state": "ready", "reason": ""},
    {"state": "ready", "reason": "", "checked_size_bytes": 0, "checked_at": _STAMP},
    {"state": "held", "reason": "file-limit"},
    {"state": "held", "reason": "process-limit", "checked_size_bytes": 0,
     "checked_at": _STAMP},
    {"state": "not-installed", "reason": "policy-paused"},
    {"suppressed_blocks": 1},
    {"suppressed_known_bytes": 1},
    {"suppressed_unknown_size_blocks": 1},
    {"last_suppression": "lock-contention"},
    {"suppressed_blocks": 1, "last_suppression": "message-limit"},
    {"suppressed_blocks": 1, "suppressed_unknown_size_blocks": 1,
     "suppressed_known_bytes": 1, "last_suppression": "message-limit"},
])
def test_inconsistent_rows_are_fixed_gaps(supplier, changes):
    supplier.source["targets"][0].update(changes)
    _assert_gap(crashlog_status.normal_log_status())


def test_paused_uncertainty_and_lowered_policy_preserve_prior_allowance(supplier):
    supplier.source.update(paused=True, configured_at=_STAMP, limit_bytes=1024 * 1024,
                           suppression_counts_lower_bound=True)
    for row in supplier.source["targets"]:
        row.update(reserved_bytes=2 * 1024 * 1024, appended_bytes=1024 * 1024,
                   appended_blocks=1, uncertain_bytes=1024 * 1024,
                   state="held", reason="io-uncertain", checked_size_bytes=100,
                   checked_at=_STAMP, suppressed_blocks=_MAX_COUNT,
                   suppressed_unknown_size_blocks=_MAX_COUNT,
                   suppressed_known_bytes=_MAX_COUNT, last_suppression="io-uncertain")
    result = crashlog_status.normal_log_status()
    assert result["state"] == "available" and result["suppression_counts_lower_bound"]
    assert all(row["reason"] == "io-uncertain" for row in result["targets"])
    assert result["targets"][0]["reserved_bytes"] > result["limit_bytes"]


@pytest.mark.parametrize("reason", ["policy-paused", "resume-check-required", "io-uncertain"])
def test_unchecked_holds_and_cached_policy_hold_are_valid(supplier, reason):
    # A role absent from a later install can retain an older policy hold. Do
    # not equate that cached row's reason with the latest global pause toggle.
    for row in supplier.source["targets"]:
        row.update(state="held", reason=reason)
    assert crashlog_status.normal_log_status()["state"] == "available"


def test_paused_requires_explicit_held_policy_or_uncertainty(supplier):
    supplier.source["paused"] = True
    _assert_gap(crashlog_status.normal_log_status())
    for row in supplier.source["targets"]:
        row.update(state="held", reason="policy-paused")
    assert crashlog_status.normal_log_status()["state"] == "available"


@pytest.mark.parametrize("mutation", ["extra-top", "extra-row", "duplicate-role", "swap-roles",
                                      "row-list", "oversized-top", "oversized-row"])
def test_unknown_or_oversized_shapes_are_rejected(supplier, mutation):
    source = supplier.source
    if mutation == "extra-top":
        source["private-path"] = "private-evidence"
    elif mutation == "extra-row":
        source["targets"][0]["private-error"] = "private-evidence"
    elif mutation == "duplicate-role":
        source["targets"][1]["role"] = "logs"
    elif mutation == "swap-roles":
        source["targets"] = tuple(reversed(source["targets"]))
    elif mutation == "row-list":
        source["targets"] = ([], source["targets"][1])
    elif mutation == "oversized-top":
        source.update({str(index): "private" for index in range(1000)})
    else:
        source["targets"][0].update({str(index): "private" for index in range(1000)})
    _assert_gap(crashlog_status.normal_log_status())


def test_hostile_values_and_exception_text_are_never_formatted(supplier, monkeypatch):
    class Hostile(str):
        def __str__(self):
            pytest.fail("provider value was stringified")
        def __hash__(self):
            pytest.fail("provider value was hashed")
        def __eq__(self, _other):
            pytest.fail("provider value was compared")
    supplier.source["targets"][0]["reason"] = Hostile("private-secret")
    _assert_gap(crashlog_status.normal_log_status())
    supplier.source["targets"][0]["reason"] = "not-installed"
    supplier.source["configured_at"] = Hostile(_STAMP)
    _assert_gap(crashlog_status.normal_log_status())

    def failed():
        raise RuntimeError("private-path password=private-secret")
    monkeypatch.setattr(crashlog, "normal_write_snapshot", failed)
    _assert_gap(crashlog_status.normal_log_status())


def test_module_import_does_not_import_or_invoke_a_crashlog_supplier(monkeypatch):
    import builtins

    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "angerona.core.crashlog":
            pytest.fail("projection imported its supplier before a status request")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    path = Path(crashlog_status.__file__)
    spec = importlib.util.spec_from_file_location("_isolated_crashlog_status", path)
    isolated = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(isolated)
    assert callable(isolated.normal_log_status)


def test_supplier_import_failure_is_a_fixed_gap(monkeypatch):
    monkeypatch.setitem(sys.modules, "angerona.core.crashlog", None)
    _assert_gap(crashlog_status.normal_log_status())


def test_valid_supplied_timestamps_are_not_reinterpreted_as_freshness(supplier):
    supplier.source["configured_at"] = "0001-01-01T00:00:00+00:00"
    row = supplier.source["targets"][0]
    row.update(state="held", reason="file-limit", checked_size_bytes=_MAX_COUNT,
               checked_at="9999-12-31T23:59:59+00:00")
    result = crashlog_status.normal_log_status()
    assert result["state"] == "available"
    assert result["configured_at"] == "0001-01-01T00:00:00+00:00"
    assert result["targets"][0]["checked_at"] == "9999-12-31T23:59:59+00:00"


def test_dictionary_subclasses_cannot_supply_executable_accessors(monkeypatch):
    class Hostile(dict):
        def copy(self):
            pytest.fail("untrusted dictionary subclass was copied")
        def __len__(self):
            pytest.fail("untrusted dictionary subclass was measured")
    monkeypatch.setattr(crashlog, "normal_write_snapshot", lambda: Hostile(_source()))
    _assert_gap(crashlog_status.normal_log_status())
