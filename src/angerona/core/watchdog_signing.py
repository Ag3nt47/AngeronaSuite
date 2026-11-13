"""Read-only signing review and untrusted update requests for the third watchdog.

Inspection is delegated to an admitted bundled helper. A selected executable is
only an input file; it is never executed. A successful signature check does not
enroll a signer, activate a service or grant response authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import ntpath
from pathlib import Path, PureWindowsPath
import re

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_INSPECTION_FIELDS = frozenset({
    "schema", "signature_valid", "watchdog_sha256", "certificate_sha256",
    "publisher", "not_after", "reason", "activation_eligible",
    "mode_state", "activation_status",
})
_MAX_REQUEST = 16 * 1024


class WatchdogSigningError(ValueError):
    """Signing review is unavailable; no activation is permitted."""


def _text(value: object, limit: int, *, empty: bool = True) -> str:
    if (type(value) is not str or len(value) > limit
            or any(ord(char) < 32 for char in value)
            or (not empty and not value)):
        raise WatchdogSigningError("Signing metadata is malformed or exceeds its bound")
    return value


def _candidate_path(value: object) -> str:
    value = _text(value, 2048, empty=False)
    path = PureWindowsPath(value)
    if (not path.is_absolute() or not re.fullmatch(r"[A-Za-z]:", path.drive)
            or value.startswith(("\\\\", "//"))
            or str(path) != value or ntpath.normpath(value) != value
            or path.name.casefold() != "watchdog3.exe"
            or any(part in {".", ".."} or ":" in part or part.endswith((".", " "))
                   for part in path.parts[1:])):
        raise WatchdogSigningError("Select a local file named watchdog3.exe")
    return value


def _expiry(value: object) -> str:
    value = _text(value, 64, empty=False)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise WatchdogSigningError("Verified certificate expiry is malformed") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise WatchdogSigningError("Certificate expiry must include a timezone")
    return value


@dataclass(frozen=True, slots=True)
class SigningInspection:
    path: str
    signature_valid: bool
    watchdog_sha256: str
    certificate_sha256: str
    publisher: str
    not_after: str
    reason: str


def parse_inspection(path: object, raw: object) -> SigningInspection:
    """Accept only the bounded diagnostic shape, never an activation receipt."""
    selected = _candidate_path(path)
    if (type(raw) is not dict or set(raw) != _INSPECTION_FIELDS
            or type(raw["schema"]) is not int or raw["schema"] != 1
            or type(raw["signature_valid"]) is not bool
            or raw["activation_eligible"] is not False
            or raw["mode_state"] != "diagnostic"
            or raw["activation_status"] != "not-assessed-by-diagnostic"):
        raise WatchdogSigningError("Signing inspector returned an unsupported diagnostic")
    digest = _text(raw["watchdog_sha256"], 64)
    certificate = _text(raw["certificate_sha256"], 64)
    publisher = _text(raw["publisher"], 1024)
    expiry = _text(raw["not_after"], 64)
    reason = _text(raw["reason"], 512)
    if digest and not _SHA256.fullmatch(digest):
        raise WatchdogSigningError("Signing inspector returned an invalid image digest")
    if raw["signature_valid"]:
        if not _SHA256.fullmatch(digest) or not _SHA256.fullmatch(certificate) or not publisher:
            raise WatchdogSigningError("Verified signer identity is incomplete")
        _expiry(expiry)
    elif certificate or publisher or expiry:
        raise WatchdogSigningError("Unverified signer identity cannot be presented as verified")
    return SigningInspection(selected, raw["signature_valid"], digest,
                             certificate, publisher, expiry, reason)


def inspect_candidate(path: object) -> SigningInspection:
    selected = _candidate_path(path)
    # The adapter owns verified bundle admission, the exact child and bounded
    # capture. There is deliberately no fallback to running the selected image.
    from angerona.resilience.native_watchdog import inspect_watchdog_candidate
    return parse_inspection(selected, inspect_watchdog_candidate(selected))


def prepare_signing_update(inspection: SigningInspection) -> dict:
    """Build planning data only; installer must independently reverify final bytes."""
    if type(inspection) is not SigningInspection or inspection.signature_valid is not True:
        raise WatchdogSigningError("A verified signature inspection is required")
    # Revalidate even a directly constructed dataclass before exporting it.
    checked = parse_inspection(inspection.path, {
        "schema": 1, "signature_valid": True,
        "watchdog_sha256": inspection.watchdog_sha256,
        "certificate_sha256": inspection.certificate_sha256,
        "publisher": inspection.publisher, "not_after": inspection.not_after,
        "reason": inspection.reason, "activation_eligible": False,
        "mode_state": "diagnostic", "activation_status": "not-assessed-by-diagnostic",
    })
    return {
        "schema": 1,
        "kind": "angerona.watchdog3.signing-update-request",
        "trusted": False,
        "activation_allowed": False,
        "runtime_compatibility_verified": False,
        "candidate_path": checked.path,
        "activation_record": {
            "schema": 1, "enabled": True,
            "watchdog_sha256": checked.watchdog_sha256,
            "certificate_sha256": checked.certificate_sha256,
            "publisher": checked.publisher,
        },
        "certificate_not_after": checked.not_after,
        "next_step": (
            "A separately governed signed installer must reverify the final image, "
            "signer, protected destination and existing service/configuration authority "
            "before enrolling this record. This request grants no activation authority."
        ),
    }


def export_signing_request(path: Path, request: dict) -> None:
    """Create one user-selected report, never overwrite enrollment or existing data."""
    expected = {
        "schema", "kind", "trusted", "activation_allowed",
        "runtime_compatibility_verified", "candidate_path", "activation_record",
        "certificate_not_after", "next_step",
    }
    if (type(request) is not dict or set(request) != expected
            or type(request.get("schema")) is not int or request["schema"] != 1
            or request.get("kind") != "angerona.watchdog3.signing-update-request"
            or request.get("trusted") is not False
            or request.get("activation_allowed") is not False
            or request.get("runtime_compatibility_verified") is not False):
        raise WatchdogSigningError("Only an untrusted signing review request can be exported")
    record = request["activation_record"]
    if (type(record) is not dict or set(record) != {
            "schema", "enabled", "watchdog_sha256", "certificate_sha256", "publisher"}
            or type(record["schema"]) is not int or record["schema"] != 1
            or record["enabled"] is not True):
        raise WatchdogSigningError("Signing review record is malformed")
    canonical = prepare_signing_update(SigningInspection(
        request["candidate_path"], True, record["watchdog_sha256"],
        record["certificate_sha256"], record["publisher"],
        request["certificate_not_after"], "verified-machine-code-signing-chain"))
    if request != canonical:
        raise WatchdogSigningError("Signing review request changed after preparation")
    payload = (json.dumps(request, sort_keys=True, ensure_ascii=True,
                          separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")
    if len(payload) > _MAX_REQUEST:
        raise WatchdogSigningError("Signing request exceeds its export limit")
    # Export is a normal user report, never the trusted activation.json name.
    destination = Path(path)
    if destination.name.casefold() in {"activation.json", "config.json"}:
        raise WatchdogSigningError("Choose a report filename, not an activation/configuration file")
    with destination.open("xb") as stream:
        stream.write(payload)
        stream.flush()


@dataclass(frozen=True, slots=True)
class SigningIndicator:
    verified: bool
    label: str
    tooltip: str


def signing_indicator(raw: object) -> SigningIndicator:
    """Project copied metadata only; this never queries files, processes or PKI."""
    status = raw if type(raw) is dict else {}
    valid = False
    try:
        digest = _text(status.get("image_sha256", ""), 64)
        checked_digest = _text(status.get("watchdog_sha256", ""), 64)
        certificate = _text(status.get("certificate_sha256", ""), 64)
        publisher = _text(status.get("publisher", ""), 1024)
        expiry = _text(status.get("not_after", ""), 64)
        valid = (status.get("signature_verified") is True
                 and bool(_SHA256.fullmatch(digest))
                 and checked_digest == digest
                 and bool(_SHA256.fullmatch(certificate))
                 and bool(publisher))
        if valid:
            _expiry(expiry)
    except WatchdogSigningError:
        valid = False
    if valid:
        label = "Signature verified"
        signer = publisher
        fingerprint = certificate
        not_after = expiry
    else:
        label = "Unsigned" if status.get("signature_state") == "unsigned" else "Signature unverified"
        signer = fingerprint = not_after = "Unavailable"
    state = status.get("state")
    active = (state in ("active-unsigned", "active-reduced")
              and status.get("heartbeat_verified") is True)
    if active:
        mode = "Active · Reduced protection" if valid else (
            "Active · Unsigned · Reduced protection" if label == "Unsigned"
            else "Active · Signature unverified · Reduced protection")
    elif state == "disabled":
        mode = "Disabled"
    elif state == "stale":
        mode = "Not responding"
    elif state == "stopped":
        mode = "Stopped"
    elif state == "starting":
        mode = "Starting; heartbeat not verified"
    else:
        mode = "Unavailable"
    enrollment = ("Enrolled" if status.get("activation_enrolled") is True
                  else "Not enrolled; signing alone grants no protected operation")
    tooltip = (
        f"Third watchdog: {mode}\n{label}\nSigner: {signer}\n"
        f"Certificate SHA-256: {fingerprint}\nCertificate expiry: {not_after}\n"
        f"Enrollment: {enrollment}\n"
        "Signature and heartbeat are separate. A signed file can be stopped or stale; "
        "an unsigned user-session monitor is easier to stop or tamper with and has no "
        "privileged service, firewall or containment authority.\n"
        "Click to open Watchdog signing settings."
    )
    return SigningIndicator(valid, label, tooltip)
