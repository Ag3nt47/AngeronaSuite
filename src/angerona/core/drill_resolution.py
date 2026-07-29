"""Authenticated action contracts and verified closure for benign drill gaps.

Installing a detector candidate is an *applied action*, not proof that a gap is
closed.  A later drill must produce a fresh, technique-bound Purple Guard
detection before the contract becomes ``VERIFIED_CLOSED``.  The state is
HMAC-authenticated with Angerona's per-install ``bus.key`` and written
atomically; corrupt or forged version-2 state fails closed.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
import time
from pathlib import Path
from types import MappingProxyType
from typing import Iterable, Mapping

from angerona.core import report_attest
from angerona.core.atomic_io import replace_with_retry

_LOCK = threading.RLock()
_CACHE: dict[str, tuple[int, dict, str]] = {}
_DEFAULT_DATA_DIR: Path | None = None
_MITRE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?|RT-[A-Z0-9_.-]+)\b", re.I)

STATE_VERSION = 2
CONTRACT_VERSION = 1
VERIFIER_KIND = "fresh-purple-guard-detector-echo"
ACTION_KIND = "install-detector-candidate-and-clean-inert-markers"
VERIFIED_STATE = "VERIFIED_CLOSED"
APPLIED_STATES = {"APPLIED", "VERIFYING", VERIFIED_STATE, "REOPENED", "EXPIRED"}
_MAX_OCCURRENCES = 32

ResolutionSnapshot = Mapping[str, Mapping[str, object]]


class StateIntegrityError(RuntimeError):
    """Raised when lifecycle state cannot be safely authenticated or updated."""


def _data_dir(data_dir=None) -> Path:
    if data_dir is not None:
        return Path(data_dir)
    global _DEFAULT_DATA_DIR
    with _LOCK:
        if _DEFAULT_DATA_DIR is None:
            try:
                from angerona.core.config import Config

                _DEFAULT_DATA_DIR = Path(Config.load().data_dir)
            except Exception:
                from angerona.core.data_paths import data_dir as canonical_data_dir

                _DEFAULT_DATA_DIR = canonical_data_dir()
        return _DEFAULT_DATA_DIR


def state_path(data_dir=None) -> Path:
    return _data_dir(data_dir) / "shared_logs" / "drill_resolutions.json"


def _empty_state() -> dict:
    return {
        "version": STATE_VERSION,
        "issues": {},
        "contracts": {},
        "legacy_resolutions": {},
        "updated_at": 0.0,
    }


def _clone(value):
    return json.loads(json.dumps(value))


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _attest_receipt(receipt: dict, key: bytes) -> dict:
    body = dict(receipt)
    body["receipt_digest"] = _digest(body)
    signature = report_attest.sign_doc(body, key=key)
    if not signature:
        raise StateIntegrityError("could not authenticate drill action receipt")
    body[report_attest.SIG_FIELD] = signature
    return body


def verify_action_receipt(receipt: Mapping[str, object], data_dir=None) -> bool:
    """Verify a standalone apply/verify/rollback receipt."""
    if not isinstance(receipt, Mapping):
        return False
    key = _state_key(data_dir)
    if key is None:
        return False
    record = dict(receipt)
    expected_digest = str(record.pop("receipt_digest", "") or "")
    record.pop(report_attest.SIG_FIELD, None)
    if not expected_digest or not hmac.compare_digest(
        expected_digest,
        _digest(record),
    ):
        return False
    expected_signature = report_attest.sign_doc(dict(receipt), key=key)
    signature = str(receipt.get(report_attest.SIG_FIELD) or "")
    return bool(
        signature
        and expected_signature
        and hmac.compare_digest(signature, expected_signature)
    )


def _state_key(data_dir=None) -> bytes | None:
    try:
        encoded = (_data_dir(data_dir) / "bus.key").read_text(
            encoding="ascii"
        ).strip()
        key = bytes.fromhex(encoded)
    except Exception:
        return None
    return key if len(key) == 32 else None


def _verify_state(doc: dict, data_dir=None) -> str:
    signature = doc.get(report_attest.SIG_FIELD)
    if not signature:
        return "unsigned"
    key = _state_key(data_dir)
    if not key:
        return "no_key"
    expected = report_attest.sign_doc(doc, key=key)
    return (
        "ok"
        if expected and hmac.compare_digest(str(signature), expected)
        else "bad"
    )


def _load(data_dir=None) -> tuple[dict, str]:
    path = state_path(data_dir)
    key = str(path)
    try:
        stamp = path.stat().st_mtime_ns
    except OSError:
        stamp = -1
    with _LOCK:
        cached = _CACHE.get(key)
        if cached and cached[0] == stamp:
            return _clone(cached[1]), cached[2]

        if stamp == -1:
            data, status = _empty_state(), "missing"
        else:
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(raw, dict):
                    raise ValueError("state root is not an object")
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                data, status = _empty_state(), "corrupt"
            else:
                version = int(raw.get("version", 1) or 1)
                if version < STATE_VERSION:
                    data = _empty_state()
                    legacy = raw.get("resolutions", {})
                    if isinstance(legacy, dict):
                        data["legacy_resolutions"] = legacy
                    data["updated_at"] = float(raw.get("updated_at", 0.0) or 0.0)
                    status = "legacy"
                elif version != STATE_VERSION:
                    data, status = _empty_state(), "unsupported"
                else:
                    status = _verify_state(raw, data_dir)
                    if status == "ok":
                        data = raw
                        data.setdefault("issues", {})
                        data.setdefault("contracts", {})
                        data.setdefault("legacy_resolutions", {})
                    else:
                        data = _empty_state()

        _CACHE[key] = (stamp, _clone(data), status)
        return _clone(data), status


def integrity_status(data_dir=None) -> str:
    """Return ``ok``, ``missing``, ``legacy``, or a fail-closed error state."""
    return _load(data_dir)[1]


def _load_for_write(data_dir=None) -> dict:
    data, status = _load(data_dir)
    if status in {"bad", "corrupt", "unsupported", "no_key", "unsigned"}:
        raise StateIntegrityError(
            f"drill remediation state is not trusted ({status}); refusing to overwrite it"
        )
    if _state_key(data_dir) is None:
        raise StateIntegrityError(
            "the per-install bus.key is unavailable; authenticated drill state "
            "cannot be written"
        )
    return data


def _write(data: dict, data_dir=None) -> None:
    path = state_path(data_dir)
    key = _state_key(data_dir)
    if key is None:
        raise StateIntegrityError("cannot authenticate drill remediation state")
    payload = dict(data)
    payload.pop(report_attest.SIG_FIELD, None)
    payload["version"] = STATE_VERSION
    signature = report_attest.sign_doc(payload, key=key)
    if not signature:
        raise StateIntegrityError("could not sign drill remediation state")
    payload[report_attest.SIG_FIELD] = signature
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        tmp.write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        replace_with_retry(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    with _LOCK:
        _CACHE.pop(str(path), None)


def _mitre(value: object) -> str:
    match = _MITRE_RE.search(str(value or "").strip())
    return match.group(1).upper() if match else ""


def _issue_id(mitre: str) -> str:
    return "DRILL-ISSUE-" + _digest({"mitre": mitre})[:20].upper()


def _contract_id(mitre: str, run_id: str) -> str:
    return "DRILL-ACT-" + _digest(
        {"mitre": mitre, "source_run_id": run_id, "action": ACTION_KIND}
    )[:20].upper()


def _ttl_seconds() -> int:
    try:
        days = int(os.environ.get("ANGERONA_DRILL_VERIFICATION_TTL_DAYS", "30"))
    except (TypeError, ValueError):
        days = 30
    return max(1, min(days, 365)) * 86_400


def _effective_state(contract: Mapping[str, object], now: float | None = None) -> str:
    state = str(contract.get("state") or "OPEN")
    if state != VERIFIED_STATE:
        return state
    try:
        expires_at = float(contract.get("verification_expires_at") or 0.0)
    except (TypeError, ValueError):
        expires_at = 0.0
    if expires_at and expires_at <= float(now or time.time()):
        return "EXPIRED"
    return state


def _immutable_contract_body(contract: Mapping[str, object]) -> dict:
    keys = (
        "contract_version",
        "contract_id",
        "issue_id",
        "mitre",
        "name",
        "source_run_id",
        "action_kind",
        "exact_scope",
        "authorization",
        "preconditions",
        "safety_checks",
        "verifier",
        "rollback",
        "idempotency_key",
    )
    return {key: contract.get(key) for key in keys}


def _new_contract(
    mitre: str,
    name: str,
    run_id: str,
    at: float,
    cleanup_count: int,
    key: bytes,
) -> dict:
    contract_id = _contract_id(mitre, run_id)
    contract = {
        "contract_version": CONTRACT_VERSION,
        "contract_id": contract_id,
        "issue_id": _issue_id(mitre),
        "mitre": mitre,
        "name": str(name or mitre)[:256],
        "source_run_id": str(run_id),
        "action_kind": ACTION_KIND,
        "exact_scope": {
            "technique": mitre,
            "detector": "Purple Remediation Guard",
            "marker_namespace": "_redteam_*",
            "runtime_boundary": "configured Angerona data directory",
        },
        "authorization": {
            "mode": "operator-reviewed",
            "source": "After-Action Report / Apply Fix Candidates",
        },
        "preconditions": [
            "authenticated After-Action Report",
            "missed detection-category finding",
            "registered Purple Guard technique",
        ],
        "safety_checks": [
            "inert drill artifacts only",
            "no executable command or model-authored code",
            "no host persistence or credential access",
        ],
        "verifier": {
            "kind": VERIFIER_KIND,
            "detector": "Purple Remediation Guard",
            "requires_different_run": True,
            "technique_binding": mitre,
        },
        "rollback": {
            "kind": "remove-purple-guard-technique",
            "scope": mitre,
            "preserve_audit_evidence": True,
        },
        "idempotency_key": _digest(
            {"mitre": mitre, "source_run_id": run_id, "action": ACTION_KIND}
        ),
        "created_at": at,
        "state": "APPLIED",
        "applied_at": at,
    }
    contract["contract_digest"] = _digest(_immutable_contract_body(contract))
    receipt = {
        "receipt_id": "DRILL-APPLY-" + _digest(
            {"contract_id": contract_id, "applied_at": at}
        )[:20].upper(),
        "contract_id": contract_id,
        "contract_digest": contract["contract_digest"],
        "outcome": "applied",
        "applied_at": at,
        "result": {
            "detector_candidate_installed": True,
            "technique": mitre,
            "inert_markers_cleaned": max(0, int(cleanup_count)),
        },
    }
    contract["application_receipt"] = _attest_receipt(receipt, key)
    return contract


def _normalise_findings(findings: Iterable[Mapping[str, object]]) -> list[dict]:
    normalised: dict[str, dict] = {}
    for finding in findings:
        mitre = _mitre(finding.get("mitre") or finding.get("technique"))
        if not mitre:
            continue
        normalised[mitre] = {
            "mitre": mitre,
            "name": str(finding.get("name") or finding.get("stage") or mitre),
        }
    return list(normalised.values())


def _record_occurrence(
    issue: dict,
    *,
    run_id: str,
    observed_at: float,
    caught: bool,
    detector: str = "",
) -> bool:
    occurrence_id = _digest(
        {
            "run_id": run_id,
            "mitre": issue["mitre"],
            "caught": bool(caught),
            "detector": detector,
        }
    )
    rows = issue.setdefault("occurrences", [])
    if any(row.get("occurrence_id") == occurrence_id for row in rows):
        return False
    rows.append(
        {
            "occurrence_id": occurrence_id,
            "run_id": run_id,
            "observed_at": observed_at,
            "caught": bool(caught),
            "detector": str(detector or "")[:128],
        }
    )
    issue["occurrences"] = rows[-_MAX_OCCURRENCES:]
    issue["last_observed_run_id"] = run_id
    issue["last_observed_at"] = observed_at
    return True


def record_findings(
    findings: list[dict],
    run_id: str,
    data_dir=None,
    observed_at: float | None = None,
) -> list[dict]:
    """Record unique missed finding classes and reopen stale verified closures."""
    at = float(observed_at or time.time())
    rows = _normalise_findings(findings)
    if not rows:
        return []
    with _LOCK:
        data = _load_for_write(data_dir)
        changed = False
        out = []
        for finding in rows:
            mitre = finding["mitre"]
            issue = data["issues"].setdefault(
                mitre.casefold(),
                {
                    "issue_id": _issue_id(mitre),
                    "mitre": mitre,
                    "name": finding["name"],
                    "status": "OPEN",
                    "occurrences": [],
                },
            )
            issue["name"] = finding["name"]
            changed |= _record_occurrence(
                issue,
                run_id=str(run_id or ""),
                observed_at=at,
                caught=False,
            )
            contract = data["contracts"].get(issue.get("active_contract_id"), {})
            effective = _effective_state(contract, at)
            if effective in {VERIFIED_STATE, "EXPIRED"}:
                contract["state"] = "REOPENED"
                contract["reopened_at"] = at
                contract["reopened_by_run_id"] = str(run_id or "")
                contract["reopen_reason"] = "fresh drill miss after verified closure"
                issue["status"] = "REOPENED"
                changed = True
            elif effective in APPLIED_STATES:
                issue["status"] = effective
            else:
                issue["status"] = "OPEN"
            out.append(_clone(issue))
        if changed:
            data["updated_at"] = at
            _write(data, data_dir)
        return out


def apply_contracts(
    findings: list[dict],
    run_id: str,
    data_dir=None,
    *,
    installed: Iterable[str] | None = None,
    cleanup_count: int = 0,
    applied_at: float | None = None,
) -> list[dict]:
    """Apply registered detector actions and issue authenticated receipts.

    ``installed`` must come from Purple Guard's typed registry. Unsupported
    techniques remain open and receive no applied contract.
    """
    at = float(applied_at or time.time())
    rows = _normalise_findings(findings)
    installed_ids = {
        mitre for value in (installed if installed is not None else ())
        if (mitre := _mitre(value))
    }
    if installed is None:
        installed_ids = {row["mitre"] for row in rows}
    if not rows:
        return []
    with _LOCK:
        data = _load_for_write(data_dir)
        out = []
        changed = False
        for finding in rows:
            mitre = finding["mitre"]
            issue = data["issues"].setdefault(
                mitre.casefold(),
                {
                    "issue_id": _issue_id(mitre),
                    "mitre": mitre,
                    "name": finding["name"],
                    "status": "OPEN",
                    "occurrences": [],
                },
            )
            issue["name"] = finding["name"]
            _record_occurrence(
                issue,
                run_id=str(run_id or ""),
                observed_at=at,
                caught=False,
            )
            if mitre not in installed_ids:
                issue["status"] = "OPEN"
                issue["unsupported_reason"] = "no registered deterministic detector action"
                changed = True
                continue

            contract_id = _contract_id(mitre, str(run_id or ""))
            contract = data["contracts"].get(contract_id)
            if not isinstance(contract, dict):
                contract = _new_contract(
                    mitre,
                    finding["name"],
                    str(run_id or ""),
                    at,
                    cleanup_count,
                    _state_key(data_dir),
                )
                data["contracts"][contract_id] = contract
                changed = True
            issue["active_contract_id"] = contract_id
            issue["status"] = _effective_state(contract, at)
            issue["acknowledged_at"] = at
            issue.pop("unsupported_reason", None)
            out.append(
                {
                    "mitre": mitre,
                    "name": issue["name"],
                    "run_id": str(run_id or ""),
                    "resolved_at": at,
                    "acknowledged_at": at,
                    "resolution": "deterministic detector action applied; rerun verification required",
                    "state": issue["status"],
                    "contract_id": contract_id,
                    "contract_digest": contract["contract_digest"],
                    "application_receipt": _clone(contract["application_receipt"]),
                }
            )
            changed = True
        if changed:
            data["updated_at"] = at
            _write(data, data_dir)
        return out


def resolve(
    findings: list[dict],
    run_id: str = "",
    data_dir=None,
    resolved_at: float | None = None,
) -> list[dict]:
    """Compatibility wrapper: apply registered drill detector contracts."""
    return apply_contracts(
        findings,
        run_id,
        data_dir,
        applied_at=resolved_at,
    )


def verify_detector_evidence(
    mitre: str,
    verification_run_id: str,
    *,
    detector: str,
    event_ts: float,
    event_details: Mapping[str, object],
    data_dir=None,
    verified_at: float | None = None,
    expected_contract_id: str | None = None,
    expected_contract_digest: str | None = None,
) -> dict:
    """Close one action contract only with fresh, exactly-bound detector proof."""
    technique = _mitre(mitre)
    at = float(verified_at or time.time())
    if not technique:
        return {"ok": False, "error": "invalid technique"}
    with _LOCK:
        data = _load_for_write(data_dir)
        issue = data["issues"].get(technique.casefold())
        if not isinstance(issue, dict):
            return {"ok": False, "error": "no open drill issue"}
        contract = data["contracts"].get(issue.get("active_contract_id"))
        if not isinstance(contract, dict):
            return {"ok": False, "error": "no applied action contract"}
        if _digest(_immutable_contract_body(contract)) != contract.get("contract_digest"):
            raise StateIntegrityError("action contract digest does not match its immutable body")
        if (
            expected_contract_id is not None
            and expected_contract_id != contract.get("contract_id")
        ):
            return {"ok": False, "error": "verification contract ID does not match"}
        if (
            expected_contract_digest is not None
            and expected_contract_digest != contract.get("contract_digest")
        ):
            return {"ok": False, "error": "verification contract digest does not match"}
        source_run = str(contract.get("source_run_id") or "")
        verification_run = str(verification_run_id or "")
        if not verification_run or verification_run == source_run:
            return {"ok": False, "error": "verification must come from a different drill run"}
        expected_detector = str(contract.get("verifier", {}).get("detector") or "")
        if detector != expected_detector:
            return {"ok": False, "error": "verification detector is not contract-authorized"}
        evidence_mitre = _mitre(
            event_details.get("mitre") or event_details.get("technique")
        )
        if evidence_mitre != technique:
            return {"ok": False, "error": "verification evidence technique does not match"}
        try:
            observed_ts = float(event_ts)
            applied_at = float(contract.get("applied_at") or 0.0)
        except (TypeError, ValueError):
            return {"ok": False, "error": "verification timestamps are invalid"}
        if observed_ts <= applied_at:
            return {"ok": False, "error": "verification evidence predates the applied action"}

        evidence = {
            "run_id": verification_run,
            "technique": technique,
            "detector": detector,
            "event_ts": observed_ts,
            "contract_id": contract["contract_id"],
            "contract_digest": contract["contract_digest"],
            "event_fingerprint": _digest(
                {
                    "run_id": verification_run,
                    "technique": technique,
                    "detector": detector,
                    "event_ts": observed_ts,
                    "step_id": event_details.get("step_id")
                    or event_details.get("drill_step_id")
                    or "",
                    "artifact": event_details.get("artifact_path")
                    or event_details.get("path")
                    or "",
                    "correlation_token": event_details.get("correlation_token") or "",
                }
            ),
        }
        previous = contract.get("verification_receipt")
        if isinstance(previous, dict) and previous.get("evidence") == evidence:
            return {"ok": True, "idempotent": True, "contract": _clone(contract)}
        if _effective_state(contract, at) not in APPLIED_STATES:
            return {
                "ok": False,
                "error": f"contract state {_effective_state(contract, at)} is not verifiable",
            }
        receipt = {
            "receipt_id": "DRILL-VERIFY-" + _digest(evidence)[:20].upper(),
            "outcome": "verified",
            "verified_at": at,
            "evidence": evidence,
            "application_receipt_digest": contract["application_receipt"][
                "receipt_digest"
            ],
        }
        contract["state"] = VERIFIED_STATE
        contract["verified_at"] = at
        contract["verification_expires_at"] = at + _ttl_seconds()
        key = _state_key(data_dir)
        if key is None:
            raise StateIntegrityError("cannot authenticate verification receipt")
        contract["verification_receipt"] = _attest_receipt(receipt, key)
        issue["status"] = VERIFIED_STATE
        issue["verified_at"] = at
        issue["verified_by_run_id"] = verification_run
        issue["acknowledged_at"] = at
        _record_occurrence(
            issue,
            run_id=verification_run,
            observed_at=observed_ts,
            caught=True,
            detector=detector,
        )
        data["updated_at"] = at
        _write(data, data_dir)
        return {"ok": True, "idempotent": False, "contract": _clone(contract)}


def rollback_contract(
    mitre: str,
    contract_id: str,
    data_dir=None,
    *,
    rolled_back_at: float | None = None,
) -> dict:
    """Remove one exact detector candidate and issue an authenticated rollback."""
    technique = _mitre(mitre)
    at = float(rolled_back_at or time.time())
    if not technique or not contract_id:
        return {"ok": False, "error": "technique and contract ID are required"}
    with _LOCK:
        data = _load_for_write(data_dir)
        issue = data["issues"].get(technique.casefold())
        if not isinstance(issue, dict):
            return {"ok": False, "error": "drill issue does not exist"}
        if issue.get("active_contract_id") != contract_id:
            return {"ok": False, "error": "contract is not active for this issue"}
        contract = data["contracts"].get(contract_id)
        if not isinstance(contract, dict) or contract.get("mitre") != technique:
            return {"ok": False, "error": "contract scope does not match"}
        if _digest(_immutable_contract_body(contract)) != contract.get("contract_digest"):
            raise StateIntegrityError("action contract digest does not match its immutable body")
        if contract.get("state") == "ROLLED_BACK":
            return {"ok": True, "idempotent": True, "contract": _clone(contract)}
        if contract.get("state") not in APPLIED_STATES | {"VERIFYING"}:
            return {
                "ok": False,
                "error": f"contract state {contract.get('state')} cannot be rolled back",
            }

        contract["state"] = "ROLLING_BACK"
        contract["rollback_started_at"] = at
        data["updated_at"] = at
        _write(data, data_dir)
        try:
            from angerona.modules.purple_guard import remove_policies

            result = remove_policies([technique], _data_dir(data_dir))
        except Exception as exc:
            contract["state"] = "ROLLBACK_FAILED"
            contract["rollback_error"] = type(exc).__name__
            data["updated_at"] = time.time()
            _write(data, data_dir)
            return {"ok": False, "error": "detector policy rollback failed"}

        receipt = {
            "receipt_id": "DRILL-ROLLBACK-" + _digest(
                {"contract_id": contract_id, "rolled_back_at": at}
            )[:20].upper(),
            "outcome": "rolled_back",
            "rolled_back_at": at,
            "contract_id": contract_id,
            "contract_digest": contract["contract_digest"],
            "application_receipt_digest": contract["application_receipt"][
                "receipt_digest"
            ],
            "result": {
                "technique": technique,
                "detector_candidate_removed": technique in result["removed"],
                "already_absent": technique in result["not_present"],
            },
        }
        key = _state_key(data_dir)
        if key is None:
            raise StateIntegrityError("cannot authenticate rollback receipt")
        contract["rollback_receipt"] = _attest_receipt(receipt, key)
        contract["state"] = "ROLLED_BACK"
        contract["rolled_back_at"] = at
        issue["status"] = "ROLLED_BACK"
        data["updated_at"] = at
        _write(data, data_dir)
        return {
            "ok": True,
            "idempotent": False,
            "contract": _clone(contract),
        }


def _snapshot(data_dir=None) -> tuple[dict, str]:
    data, status = _load(data_dir)
    if status not in {"ok", "legacy", "missing"}:
        return _empty_state(), status
    now = time.time()
    for issue in data.get("issues", {}).values():
        if not isinstance(issue, dict):
            continue
        contract = data.get("contracts", {}).get(issue.get("active_contract_id"), {})
        if isinstance(contract, dict) and contract:
            issue["status"] = _effective_state(contract, now)
    return data, status


def resolution_snapshot(data_dir=None) -> ResolutionSnapshot:
    """Return an immutable, compatibility-shaped lifecycle view by technique."""
    data, _status = _snapshot(data_dir)
    rows: dict[str, dict] = {}
    for key, issue in data.get("issues", {}).items():
        if not isinstance(issue, dict):
            continue
        contract = data.get("contracts", {}).get(issue.get("active_contract_id"), {})
        rec = dict(issue)
        if isinstance(contract, dict):
            rec.update(
                {
                    "run_id": contract.get("source_run_id", ""),
                    "resolved_at": issue.get("acknowledged_at", 0.0),
                    "contract_id": contract.get("contract_id"),
                    "contract_digest": contract.get("contract_digest"),
                    "state": _effective_state(contract),
                    "applied_at": contract.get("applied_at"),
                    "verified_at": contract.get("verified_at"),
                    "reopened_at": contract.get("reopened_at"),
                    "reopened_by_run_id": contract.get("reopened_by_run_id"),
                    "reopen_reason": contract.get("reopen_reason"),
                    "verification_expires_at": contract.get(
                        "verification_expires_at"
                    ),
                }
            )
        rows[str(key)] = rec
    for key, legacy in data.get("legacy_resolutions", {}).items():
        if isinstance(legacy, dict) and str(key) not in rows:
            rows[str(key)] = {**legacy, "state": "LEGACY_ACKNOWLEDGED"}
    return MappingProxyType(
        {
            str(key): MappingProxyType(_clone(value))
            for key, value in rows.items()
        }
    )


def contract_snapshot(data_dir=None) -> ResolutionSnapshot:
    """Return immutable action contracts, with expiry reflected in state."""
    data, _status = _snapshot(data_dir)
    rows = {}
    for key, value in data.get("contracts", {}).items():
        if not isinstance(value, dict):
            continue
        contract = _clone(value)
        contract["state"] = _effective_state(contract)
        rows[str(key)] = MappingProxyType(contract)
    return MappingProxyType(rows)


def already_resolved(
    mitre: str,
    run_id: str,
    data_dir=None,
    resolutions: ResolutionSnapshot | None = None,
) -> bool:
    rows = resolution_snapshot(data_dir) if resolutions is None else resolutions
    rec = rows.get(str(mitre).casefold(), {})
    return bool(
        run_id
        and rec.get("run_id") == run_id
        and rec.get("state") in APPLIED_STATES | {"LEGACY_ACKNOWLEDGED"}
    )


def event_mitre(event) -> str:
    details = getattr(event, "details", None) or {}
    return _mitre(
        details.get("mitre")
        or details.get("technique")
        or getattr(event, "message", "")
    )


def is_resolved_event(
    event,
    data_dir=None,
    resolutions: ResolutionSnapshot | None = None,
) -> bool:
    """Hide only the acknowledged alert burst; later misses reopen automatically."""
    if getattr(event, "module", "") != "Posture Hardening":
        return False
    if "NEW WEAKNESS (Red Team)" not in str(getattr(event, "message", "") or ""):
        return False
    mitre = event_mitre(event)
    if not mitre:
        return False
    rows = resolution_snapshot(data_dir) if resolutions is None else resolutions
    rec = rows.get(mitre.casefold(), {})
    try:
        acknowledged_at = float(
            rec.get("acknowledged_at") or rec.get("resolved_at") or 0.0
        )
        return float(getattr(event, "ts", 0)) <= acknowledged_at
    except (TypeError, ValueError):
        return False


def reconcile_verdicts(
    verdicts: Iterable[object],
    run_id: str,
    data_dir=None,
) -> dict:
    """Bind a completed run to lifecycle state and return unique-class metrics."""
    grouped: dict[str, list[object]] = {}
    for verdict in verdicts:
        if getattr(verdict, "category", "") != "detection":
            continue
        mitre = _mitre(getattr(verdict, "technique", ""))
        if mitre:
            grouped.setdefault(mitre, []).append(verdict)

    integrity = integrity_status(data_dir)
    if grouped and integrity in {"missing", "legacy", "ok"}:
        misses = []
        for mitre, rows in grouped.items():
            purple = next(
                (
                    row
                    for row in rows
                    if getattr(row, "catch", None) is not None
                    and getattr(row.catch, "module", "")
                    == "Purple Remediation Guard"
                ),
                None,
            )
            if purple is not None:
                try:
                    verify_detector_evidence(
                        mitre,
                        run_id,
                        detector="Purple Remediation Guard",
                        event_ts=float(purple.catch.ts),
                        event_details=purple.catch.details or {},
                        data_dir=data_dir,
                    )
                except StateIntegrityError:
                    pass
            elif not any(getattr(row, "catch", None) is not None for row in rows):
                misses.append(
                    {
                        "mitre": mitre,
                        "name": getattr(rows[0], "stage", mitre),
                    }
                )
        if misses:
            try:
                record_findings(misses, run_id, data_dir)
            except StateIntegrityError:
                pass

    snapshot = resolution_snapshot(data_dir)
    applied = verified = 0
    for mitre, rows in grouped.items():
        record = snapshot.get(mitre.casefold(), {})
        state = str(record.get("state") or "OPEN")
        contract_applied = bool(record.get("applied_at")) and state in APPLIED_STATES
        contract_verified = state == VERIFIED_STATE
        applied += int(contract_applied)
        verified += int(contract_verified)
        for verdict in rows:
            verdict.technique_id = mitre
            verdict.action_state = state
            verdict.contract_id = record.get("contract_id")
            verdict.contract_digest = record.get("contract_digest")
            verdict.action_applied = contract_applied
            verdict.finding_resolved = contract_verified
            verdict.verification_expires_at = record.get(
                "verification_expires_at"
            )
    return {
        "actionable_classes": len(grouped),
        "actions_applied": applied,
        "verified_closures": verified,
        "integrity_status": integrity_status(data_dir),
    }
