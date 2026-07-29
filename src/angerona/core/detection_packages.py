"""Digest-verified, bounded detection-as-code packages.

Packages are JSON documents containing metadata, a deliberately small Sigma
selection subset, and benign fixtures.  Loading is fail-closed: schema, digest,
expiry, fixtures, and a local evaluation-time budget must all pass before a
package can be evaluated.  No package field is interpreted as executable code.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

from angerona.core.sigma_engine import match

MAX_PACKAGE_BYTES = 256 * 1024
MAX_SELECTIONS = 32
MAX_FIELDS_PER_SELECTION = 24
MAX_VALUES_PER_FIELD = 32
MAX_FIXTURES = 64
MAX_EVENT_FIELDS = 128
MAX_STRING_CHARS = 4096
_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,79}$")
_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-[a-z0-9.-]+)?$")
_ATTACK = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_FIELD = re.compile(r"^[A-Za-z0-9_.-]{1,80}(?:\|(contains|startswith|endswith))?$")
_COND_TOKEN = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
_LEVELS = {"informational", "low", "medium", "high", "critical"}
_ALLOWED_TOP = {
    "schema_version", "id", "version", "owner", "description",
    "telemetry", "attack", "severity", "confidence", "logic", "fixtures",
    "performance", "rollback", "expires_at", "digest",
}


class PackageValidationError(ValueError):
    """A package cannot be safely activated."""


def canonical_bytes(document: Mapping[str, Any]) -> bytes:
    """Return the stable bytes covered by ``digest``."""
    unsigned = {key: value for key, value in document.items() if key != "digest"}
    return json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def package_digest(document: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(document)).hexdigest()


def seal_package(document: Mapping[str, Any]) -> dict[str, Any]:
    """Copy and digest a package. Intended for trusted build tooling/tests."""
    sealed = dict(document)
    sealed["digest"] = package_digest(sealed)
    return sealed


def _fail(message: str) -> None:
    raise PackageValidationError(message)


def _bounded_string(value: Any, name: str, *, maximum: int = MAX_STRING_CHARS) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        _fail(f"{name} must be a non-empty string of at most {maximum} characters")
    return value


def _iso8601(value: Any, name: str) -> datetime:
    text = _bounded_string(value, name, maximum=40)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        _fail(f"{name} must be ISO-8601")
    if parsed.tzinfo is None:
        _fail(f"{name} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _validate_scalar(value: Any, name: str) -> None:
    if isinstance(value, str):
        if len(value) > MAX_STRING_CHARS:
            _fail(f"{name} is too long")
    elif value is not None and not isinstance(value, (bool, int, float)):
        _fail(f"{name} must contain only scalar values")


def _validate_detection(detection: Any) -> None:
    if not isinstance(detection, dict):
        _fail("logic.detection must be an object")
    condition = _bounded_string(detection.get("condition"), "logic.detection.condition", maximum=512)
    selections = {k: v for k, v in detection.items() if k != "condition"}
    if not selections or len(selections) > MAX_SELECTIONS:
        _fail("logic.detection has an invalid selection count")
    for name, selection in selections.items():
        if not isinstance(name, str) or not _COND_TOKEN.fullmatch(name):
            _fail("selection names must be simple identifiers")
        choices = selection if isinstance(selection, list) else [selection]
        if not choices or len(choices) > MAX_VALUES_PER_FIELD:
            _fail(f"selection {name} has an invalid branch count")
        for branch in choices:
            if not isinstance(branch, dict) or not branch or len(branch) > MAX_FIELDS_PER_SELECTION:
                _fail(f"selection {name} must contain a bounded field map")
            for field, expected in branch.items():
                if not isinstance(field, str) or not _FIELD.fullmatch(field):
                    _fail(f"unsafe or invalid field modifier: {field!r}")
                values = expected if isinstance(expected, list) else [expected]
                if not values or len(values) > MAX_VALUES_PER_FIELD:
                    _fail(f"field {field} has an invalid value count")
                for value in values:
                    _validate_scalar(value, field)
    # sigma_engine supports only this explicit, non-parenthesized grammar.
    normalized = condition.lower()
    if normalized in {"all of them", "1 of them", "any of them", "all of selection*", "1 of selection*"}:
        return
    parts = re.split(r"\s+(?:and|or|and not)\s+", normalized)
    if any(not _COND_TOKEN.fullmatch(part) or part not in selections for part in parts):
        _fail("condition references an unknown selection or unsupported expression")
    if " and not " in normalized and normalized.count(" and not ") > 1:
        _fail("condition permits at most one 'and not' clause")


def validate_package(
    document: Any, *, now: datetime | None = None, verify_digest: bool = True
) -> dict[str, Any]:
    """Validate a decoded package and return it, or raise fail-closed."""
    if not isinstance(document, dict):
        _fail("package must be a JSON object")
    unknown = set(document) - _ALLOWED_TOP
    if unknown:
        _fail(f"unknown package fields: {', '.join(sorted(unknown))}")
    required = _ALLOWED_TOP
    missing = required - set(document)
    if missing:
        _fail(f"missing package fields: {', '.join(sorted(missing))}")
    if document["schema_version"] != 1:
        _fail("unsupported schema_version")
    if not _ID.fullmatch(_bounded_string(document["id"], "id", maximum=80)):
        _fail("invalid package id")
    if not _VERSION.fullmatch(_bounded_string(document["version"], "version", maximum=80)):
        _fail("version must be semantic version syntax")
    _bounded_string(document["owner"], "owner", maximum=160)
    _bounded_string(document["description"], "description")
    if document["severity"] not in _LEVELS:
        _fail("invalid severity")
    confidence = document["confidence"]
    if type(confidence) is not int or not 0 <= confidence <= 100:
        _fail("confidence must be an integer from 0 through 100")
    telemetry = document["telemetry"]
    if (not isinstance(telemetry, list) or not telemetry or len(telemetry) > 32
            or any(not isinstance(v, str) or not _ID.fullmatch(v) for v in telemetry)):
        _fail("telemetry must contain 1-32 simple sensor identifiers")
    attack = document["attack"]
    if (not isinstance(attack, list) or not attack or len(attack) > 32
            or any(not isinstance(v, str) or not _ATTACK.fullmatch(v) for v in attack)):
        _fail("attack must contain valid ATT&CK technique identifiers")
    logic = document["logic"]
    if not isinstance(logic, dict) or set(logic) != {"type", "detection"} or logic["type"] != "sigma-subset":
        _fail("logic must be exactly a sigma-subset detection")
    _validate_detection(logic["detection"])
    performance = document["performance"]
    if not isinstance(performance, dict) or set(performance) != {"max_eval_ms", "max_events_per_second"}:
        _fail("performance fields are invalid")
    if (type(performance["max_eval_ms"]) not in (int, float)
            or not 0.05 <= performance["max_eval_ms"] <= 1000):
        _fail("max_eval_ms must be from 0.05 through 1000")
    if type(performance["max_events_per_second"]) is not int or not 1 <= performance["max_events_per_second"] <= 1_000_000:
        _fail("max_events_per_second must be from 1 through 1000000")
    rollback = document["rollback"]
    if not isinstance(rollback, dict) or set(rollback) != {"previous_digest", "instructions"}:
        _fail("rollback fields are invalid")
    previous = rollback["previous_digest"]
    if previous is not None and (not isinstance(previous, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", previous)):
        _fail("rollback.previous_digest is invalid")
    _bounded_string(rollback["instructions"], "rollback.instructions", maximum=1000)
    expiry = _iso8601(document["expires_at"], "expires_at")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if expiry <= current:
        _fail("package is expired")
    digest = document["digest"]
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        _fail("digest must be a lowercase SHA-256 digest")
    if verify_digest and not hmac.compare_digest(digest, package_digest(document)):
        _fail("package digest verification failed")
    fixtures = document["fixtures"]
    if not isinstance(fixtures, list) or not fixtures or len(fixtures) > MAX_FIXTURES:
        _fail("fixtures must contain 1-64 cases")
    for fixture in fixtures:
        if not isinstance(fixture, dict) or set(fixture) != {"name", "event", "expected_match"}:
            _fail("fixture fields are invalid")
        _bounded_string(fixture["name"], "fixture.name", maximum=160)
        event = fixture["event"]
        if not isinstance(event, dict) or len(event) > MAX_EVENT_FIELDS:
            _fail("fixture event is invalid")
        for key, value in event.items():
            if not isinstance(key, str) or not _FIELD.fullmatch(key):
                _fail("fixture event field is invalid")
            _validate_scalar(value, key)
        if type(fixture["expected_match"]) is not bool:
            _fail("fixture.expected_match must be boolean")
    return document


def _event(fields: Mapping[str, Any]) -> SimpleNamespace:
    known = {"module", "message", "severity"}
    severity = SimpleNamespace(name=str(fields.get("severity", "")))
    return SimpleNamespace(
        module=fields.get("module", ""), message=fields.get("message", ""),
        severity=severity, details={k: v for k, v in fields.items() if k not in known},
    )


@dataclass(frozen=True)
class DetectionPackage:
    document: Mapping[str, Any]

    @property
    def package_id(self) -> str:
        return str(self.document["id"])

    def evaluate(self, event: Any) -> bool:
        """Evaluate one event. Invalid event shapes fail closed (no match)."""
        try:
            candidate = _event(event) if isinstance(event, Mapping) else event
            return bool(match({"detection": self.document["logic"]["detection"]}, candidate))
        except Exception:
            return False


def load_package(path: str | Path, *, now: datetime | None = None) -> DetectionPackage:
    """Load, verify, fixture-test, and performance-gate one local JSON package."""
    package_path = Path(path)
    try:
        if package_path.stat().st_size > MAX_PACKAGE_BYTES:
            _fail("package exceeds maximum size")
        raw = package_path.read_bytes()
        document = json.loads(raw.decode("utf-8"))
    except PackageValidationError:
        raise
    except Exception as exc:
        raise PackageValidationError(f"package could not be read: {exc}") from exc
    validated = validate_package(document, now=now)
    package = DetectionPackage(validated)
    started = time.perf_counter()
    for fixture in validated["fixtures"]:
        actual = package.evaluate(fixture["event"])
        if actual is not fixture["expected_match"]:
            _fail(f"fixture failed: {fixture['name']}")
    elapsed_ms = (time.perf_counter() - started) * 1000
    per_event_ms = elapsed_ms / len(validated["fixtures"])
    if per_event_ms > validated["performance"]["max_eval_ms"]:
        _fail(
            f"fixture evaluation exceeded budget: {per_event_ms:.3f}ms/event "
            f"> {validated['performance']['max_eval_ms']}ms/event"
        )
    return package
