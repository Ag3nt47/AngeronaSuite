"""Inert snapshot read/metadata fixtures; no model, install key or live capture."""
from __future__ import annotations

import copy
import hashlib
import json
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

import angerona.modules.self_healer as healer_module
from angerona.core.module_base import (
    sign_crash_snapshot_bundle,
    verify_crash_snapshot_bundle,
)
from angerona.modules.self_healer import SelfHealer


KEY = b"q" * 32
TB = 'Traceback:\n  File "fixture.py", line 1, in run\nRuntimeError'


def _counts(text: str, omitted: int = 0) -> dict:
    return {
        "original_chars": len(text) + omitted,
        "retained_chars": len(text),
        "omitted_chars": omitted,
        "unavailable": False,
    }


def _bundle(*, capture: bool = True, complete: bool = True) -> dict:
    document = {
        "module": "Fixture",
        "crashed_at": 1.0,
        "error": "RuntimeError",
        "traceback": TB if complete else "",
        "memory": {},
        "last_50_events": [],
    }
    if capture:
        excerpt = {"head": "", "tail": ""} if complete else {
            "head": TB[:20], "tail": TB[-20:],
        }
        retained = TB if complete else excerpt["head"] + excerpt["tail"]
        document["memory"]["capture"] = {
            "schema": 1,
            "policy": "angerona-crash-capture-v1",
            "traceback_complete": complete,
            "traceback_excerpt": excerpt,
            "text": {
                "module": _counts(document["module"]),
                "error": _counts(document["error"]),
                "traceback": _counts(retained, len(TB) - len(retained)),
            },
            "events": {
                "requested": 50,
                "returned": 0,
                "retained": 0,
                "omitted": 0,
                "unavailable": False,
                "text": [],
            },
            "memory_available": True,
            "byte_limit": 480 * 1024,
        }
    return document


def _signed(document: dict) -> tuple[dict, bytes]:
    signed = sign_crash_snapshot_bundle(document, key=KEY)
    return signed, json.dumps(signed, separators=(",", ":")).encode("utf-8")


@pytest.fixture
def healer(monkeypatch, tmp_path: Path) -> SelfHealer:
    monkeypatch.setattr(healer_module, "_data_base", lambda: tmp_path)
    monkeypatch.setattr(SelfHealer, "_install_key", staticmethod(lambda: KEY))
    instance = SelfHealer()
    instance._state_ready = True
    monkeypatch.setattr(instance, "_persist_state", lambda: True)
    return instance


def _install_forbidden_pipeline(monkeypatch, healer: SelfHealer) -> list[str]:
    calls: list[str] = []
    for name in ("_source_from_traceback", "_read_trusted_source", "_request_fix", "_stage"):
        def forbidden(*_args, _name=name, **_kwargs):
            calls.append(_name)
            raise AssertionError(f"held snapshot reached {_name}")
        monkeypatch.setattr(healer, name, forbidden)
    return calls


def _handle(healer: SelfHealer, body: bytes) -> tuple[bool, str]:
    return healer._handle_snapshot(
        Path("fixture.json"), hashlib.sha256(body).hexdigest(), body,
    )


@pytest.mark.parametrize("capture", [False, True])
def test_exact_v1_signature_and_complete_traceback_reach_inert_pipeline(
    monkeypatch, healer: SelfHealer, capture: bool,
) -> None:
    signed, body = _signed(_bundle(capture=capture))
    assert set(signed) == {
        "snapshot_schema", "module", "crashed_at", "error", "traceback",
        "memory", "last_50_events", "snapshot_hmac",
    }
    assert verify_crash_snapshot_bundle(signed, key=KEY)
    before = copy.deepcopy(signed)
    assert verify_crash_snapshot_bundle(signed, key=KEY)
    assert signed == before
    calls: list[tuple] = []
    monkeypatch.setattr(
        healer, "_source_from_traceback",
        lambda tb: calls.append(("select", tb)) or "fixture.py",
    )
    monkeypatch.setattr(healer, "_read_trusted_source", lambda _path: "value = 1\n")
    monkeypatch.setattr(
        healer, "_request_fix",
        lambda *args: calls.append(("model", *args)) or "value = 2\n",
    )
    monkeypatch.setattr(
        healer, "_stage", lambda *_args, **_kwargs: Path("fixture_staged.py"),
    )

    assert _handle(healer, body) == (True, "staged for operator review")
    assert calls[0] == ("select", TB)
    assert calls[1] == ("model", "Fixture", TB, "value = 1\n")
    assert healer._staged == 1


def test_incomplete_authenticated_excerpt_is_held_before_source_or_model(
    monkeypatch, healer: SelfHealer,
) -> None:
    calls = _install_forbidden_pipeline(monkeypatch, healer)
    _signed_document, body = _signed(_bundle(complete=False))
    success, reason = _handle(healer, body)
    assert success is False
    assert reason == "snapshot capture traceback is incomplete; manual review required"
    assert calls == []
    assert healer._staged == 0


def test_legacy_empty_traceback_keeps_its_existing_hold(
    monkeypatch, healer: SelfHealer,
) -> None:
    calls = _install_forbidden_pipeline(monkeypatch, healer)
    _signed_document, body = _signed(_bundle(capture=False, complete=False))
    assert _handle(healer, body) == (
        False, "snapshot traceback is missing or exceeds its bound",
    )
    assert calls == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", True), ("schema", 2), ("policy", "unknown"),
        ("traceback_complete", "true"), ("memory_available", 1),
        ("byte_limit", 512 * 1024),
        ("traceback_excerpt", {"head": "", "tail": "", "extra": ""}),
        ("traceback_excerpt", {"head": 1, "tail": ""}),
        ("events", {}), ("text", {}),
    ],
)
def test_malformed_or_unknown_authenticated_capture_is_held(
    monkeypatch, healer: SelfHealer, field: str, value: object,
) -> None:
    calls = _install_forbidden_pipeline(monkeypatch, healer)
    document = _bundle()
    document["memory"]["capture"][field] = value
    _signed_document, body = _signed(document)
    assert _handle(healer, body) == (
        False, "snapshot capture metadata is malformed or unsupported",
    )
    assert calls == []


@pytest.mark.parametrize(
    "mutation", ["missing", "extra", "null", "contradictory", "false_complete"],
)
def test_capture_shape_and_traceback_accounting_cannot_bypass_hold(
    monkeypatch, healer: SelfHealer, mutation: str,
) -> None:
    calls = _install_forbidden_pipeline(monkeypatch, healer)
    document = _bundle()
    capture = document["memory"]["capture"]
    if mutation == "missing":
        del capture["policy"]
    elif mutation == "extra":
        capture["future_authority"] = True
    elif mutation == "null":
        document["memory"]["capture"] = None
    elif mutation == "contradictory":
        capture["text"]["traceback"]["omitted_chars"] = 1
    else:
        capture["traceback_complete"] = False
    _signed_document, body = _signed(document)
    assert _handle(healer, body) == (
        False, "snapshot capture metadata is malformed or unsupported",
    )
    assert calls == []


def test_authenticated_capture_declared_byte_bound_is_checked_without_reencoding(
    monkeypatch, healer: SelfHealer,
) -> None:
    calls = _install_forbidden_pipeline(monkeypatch, healer)
    document = _bundle()
    document["memory"]["padding"] = "x" * (480 * 1024)
    _signed_document, body = _signed(document)
    assert len(body) > 480 * 1024
    assert _handle(healer, body) == (
        False, "snapshot capture metadata is malformed or unsupported",
    )
    assert calls == []


def test_tampered_capture_fails_authentication_before_metadata_or_source(
    monkeypatch, healer: SelfHealer,
) -> None:
    calls = _install_forbidden_pipeline(monkeypatch, healer)
    signed, _body = _signed(_bundle())
    signed["memory"]["capture"]["traceback_complete"] = False
    body = json.dumps(signed).encode("utf-8")
    assert _handle(healer, body) == (False, "crash snapshot authentication failed")
    assert calls == []


def test_event_metadata_matches_retained_authenticated_text() -> None:
    document = _bundle()
    event = {"ts": None, "module": "Fixture", "severity": "HIGH", "message": "retained"}
    document["last_50_events"] = [event]
    capture = document["memory"]["capture"]
    capture["events"] = {
        "requested": 50, "returned": 2, "retained": 1, "omitted": 1,
        "unavailable": False,
        "text": [{"index": 0, "timestamp_available": False, **{
            key: _counts(event[key]) for key in ("module", "severity", "message")
        }}],
    }
    _signed_document, body = _signed(document)
    assert healer_module._capture_refusal(document, len(body)) is None
    capture["events"]["text"][0]["message"]["retained_chars"] += 1
    assert healer_module._capture_refusal(document, len(body)) == (
        "snapshot capture metadata is malformed or unsupported"
    )


def test_unavailable_collectors_are_explicit_without_holding_complete_traceback() -> None:
    document = _bundle()
    capture = document["memory"]["capture"]
    capture["memory_available"] = False
    capture["events"].update(returned=None, omitted=None, unavailable=True)
    _signed_document, body = _signed(document)
    assert healer_module._capture_refusal(document, len(body)) is None


def test_unavailable_traceback_remains_incomplete_with_no_invented_counts(
    monkeypatch, healer: SelfHealer,
) -> None:
    calls = _install_forbidden_pipeline(monkeypatch, healer)
    document = _bundle(complete=False)
    capture = document["memory"]["capture"]
    capture["traceback_excerpt"] = {"head": "", "tail": ""}
    capture["text"]["traceback"] = {
        "original_chars": None, "retained_chars": 0,
        "omitted_chars": None, "unavailable": True,
    }
    _signed_document, body = _signed(document)
    assert _handle(healer, body) == (
        False, "snapshot capture traceback is incomplete; manual review required",
    )
    assert calls == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("original_chars", True), ("original_chars", None),
        ("retained_chars", True), ("retained_chars", 0),
        ("omitted_chars", -1), ("omitted_chars", None), ("unavailable", 0),
        ("unavailable", True),
    ],
)
def test_contradictory_authenticated_text_counts_hold_before_pipeline(
    monkeypatch, healer: SelfHealer, field: str, value: object,
) -> None:
    calls = _install_forbidden_pipeline(monkeypatch, healer)
    document = _bundle()
    document["memory"]["capture"]["text"]["module"][field] = value
    _signed_document, body = _signed(document)
    assert _handle(healer, body) == (
        False, "snapshot capture metadata is malformed or unsupported",
    )
    assert calls == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("requested", True), ("requested", 51), ("returned", None),
        ("returned", 51), ("retained", True), ("retained", 1),
        ("omitted", -1), ("unavailable", True), ("text", [{}]),
    ],
)
def test_malformed_authenticated_event_accounting_holds_before_pipeline(
    monkeypatch, healer: SelfHealer, field: str, value: object,
) -> None:
    calls = _install_forbidden_pipeline(monkeypatch, healer)
    document = _bundle()
    document["memory"]["capture"]["events"][field] = value
    _signed_document, body = _signed(document)
    assert _handle(healer, body) == (
        False, "snapshot capture metadata is malformed or unsupported",
    )
    assert calls == []


@pytest.mark.parametrize("kind", ["empty", "oversized"])
def test_reader_classifies_size_refusal_without_reading_body(
    monkeypatch, tmp_path: Path, kind: str,
) -> None:
    path = tmp_path / "fixture.json"
    with path.open("wb") as handle:
        if kind == "oversized":
            handle.truncate(healer_module._MAX_SNAPSHOT_BYTES + 1)
    def forbidden_read(*_args):
        raise AssertionError("size-refused file body was read")
    monkeypatch.setattr(healer_module.os, "read", forbidden_read)
    assert SelfHealer._read_snapshot(path) is None
    assert SelfHealer._snapshot_read.reason == kind


def test_reader_success_preserves_exact_tuple_and_512k_boundary(tmp_path: Path) -> None:
    path = tmp_path / "boundary.json"
    body = b"x" * healer_module._MAX_SNAPSHOT_BYTES
    path.write_bytes(body)
    assert SelfHealer._read_snapshot(path) == (hashlib.sha256(body).hexdigest(), body)


@pytest.mark.parametrize("reason", ["type_reparse", "unstable", "read_failed"])
def test_reader_refusal_reason_is_fixed_and_descriptor_is_closed(
    monkeypatch, reason: str,
) -> None:
    before = SimpleNamespace(
        st_mode=stat.S_IFREG, st_file_attributes=0, st_size=2,
        st_dev=1, st_ino=2, st_mtime_ns=3,
    )
    after = SimpleNamespace(**vars(before))
    if reason == "type_reparse":
        before.st_file_attributes = healer_module._REPARSE_POINT
    elif reason == "unstable":
        after.st_mtime_ns += 1
    closed: list[int] = []
    reads = iter((b"{}", b""))
    stats = iter((before, after))
    monkeypatch.setattr(healer_module.os, "open", lambda *_args: 417)
    monkeypatch.setattr(healer_module.os, "fstat", lambda _fd: next(stats))
    monkeypatch.setattr(healer_module.os, "close", lambda fd: closed.append(fd))
    def read(*_args):
        if reason == "read_failed":
            raise OSError("fixture read denial")
        return next(reads)
    monkeypatch.setattr(healer_module.os, "read", read)
    assert SelfHealer._read_snapshot(Path("fixture.json")) is None
    assert SelfHealer._snapshot_read.reason == reason
    assert closed == [417]


def test_pass_reports_candidate_coverage_counts_without_stale_adapter_reason(
    monkeypatch, healer: SelfHealer,
) -> None:
    candidates = [Path(f"prelaunch_{index}.json") for index in range(4)]
    monkeypatch.setattr(healer, "_snapshot_candidates", lambda _path: (candidates, False))
    reasons = iter(("empty", "oversized", "unstable", None))
    def reader(_path):
        reason = next(reasons)
        if reason is not None:
            healer._snapshot_read.reason = reason
        return None
    monkeypatch.setattr(healer, "_read_snapshot", reader)
    assert healer.process_snapshots_once(Path("unused")) == 0
    assert healer.health == 40
    assert healer.health_note == (
        "4 snapshot candidate file(s) could not be read safely; "
        "coverage incomplete (empty=1, oversized=1, unstable=1, unmeasured=1); retry pending"
    )
    assert not healer._completed and not healer._retries and not healer._dead_letters


def test_persistence_failure_retains_priority_over_reader_coverage(
    monkeypatch, healer: SelfHealer,
) -> None:
    healer._state_persist_failed = True
    monkeypatch.setattr(
        healer, "_snapshot_candidates", lambda _path: ([Path("empty.json")], False),
    )
    monkeypatch.setattr(healer, "_read_snapshot", lambda _path: None)
    assert healer.process_snapshots_once(Path("unused")) == 0
    assert healer.health == 25


@pytest.mark.parametrize("invalid_reason", ["unexpected", None, {"untrusted": True}])
def test_uninstrumented_or_unknown_reader_reason_is_unmeasured(
    monkeypatch, healer: SelfHealer, invalid_reason: object,
) -> None:
    monkeypatch.setattr(
        healer, "_snapshot_candidates", lambda _path: ([Path("fixture.json")], False),
    )
    def reader(_path):
        healer._snapshot_read.reason = invalid_reason
        return None
    monkeypatch.setattr(healer, "_read_snapshot", reader)
    assert healer.process_snapshots_once(Path("unused")) == 0
    assert "coverage incomplete (unmeasured=1)" in healer.health_note
    assert healer.health == 40


def test_incomplete_capture_retains_existing_retry_and_dead_letter_custody(
    monkeypatch, healer: SelfHealer,
) -> None:
    calls = _install_forbidden_pipeline(monkeypatch, healer)
    _signed_document, body = _signed(_bundle(complete=False))
    snapshot_id = hashlib.sha256(body).hexdigest()
    monkeypatch.setattr(
        healer, "_snapshot_candidates", lambda _path: ([Path("held.json")], False),
    )
    monkeypatch.setattr(healer, "_read_snapshot", lambda _path: (snapshot_id, body))
    assert [healer.process_snapshots_once(Path("unused")) for _ in range(3)] == [1, 1, 1]
    assert snapshot_id not in healer._completed
    assert snapshot_id not in healer._retries
    assert healer._dead_letters[snapshot_id] == (
        "snapshot capture traceback is incomplete; manual review required"
    )
    assert healer.health == 55
    assert calls == []
