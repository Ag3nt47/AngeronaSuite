"""Fail-closed containment proposal builder.

Containment bypasses are important evidence, but neither a model response nor a
repository script is execution authority. Version 12 therefore records a small
typed network-containment proposal for operator review. It never writes an
executable file, edits a mitigation gate, changes firewall policy, or marks a
mitigation verified merely because an inert drill happened to be blocked.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping


_TECHNIQUE = re.compile(r"T\d{4}(?:\.\d{3})?\Z")
_MAX_TIMELINE_BYTES = 64 * 1024


def _proposal_root() -> Path:
    from angerona.core.data_paths import data_dir

    root = data_dir() / "proposals" / "containment"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _bounded_timeline(value: Mapping[str, Any] | None) -> dict[str, Any]:
    source = dict(value or {})
    encoded = json.dumps(
        source,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")
    if len(encoded) > _MAX_TIMELINE_BYTES:
        return {
            "summary": "timeline omitted because it exceeded the review bound",
            "original_sha256": hashlib.sha256(encoded).hexdigest(),
            "original_bytes": len(encoded),
        }
    return json.loads(encoded.decode("utf-8"))


def _atomic_json(path: Path, document: Mapping[str, Any]) -> None:
    payload = json.dumps(
        document, indent=2, sort_keys=True, ensure_ascii=False
    ).encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def tune_containment(
    technique_id: str, timeline: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Stage one deterministic, non-executable containment proposal."""
    technique = str(technique_id or "").strip().upper()
    if _TECHNIQUE.fullmatch(technique) is None:
        return {
            "technique": technique[:64],
            "ok": False,
            "executed": False,
            "error": "invalid ATT&CK technique identity",
        }
    evidence = _bounded_timeline(timeline)
    evidence_digest = hashlib.sha256(
        json.dumps(
            evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()
    proposal_id = (
        f"contain-{technique.casefold().replace('.', '-')}-{evidence_digest[:16]}"
    )
    document: dict[str, Any] = {
        "schema": "angerona.containment-proposal.v12",
        "proposal_id": proposal_id,
        "technique_id": technique,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "review-required",
        "executed": False,
        "verified": False,
        "response_authorized": False,
        "intent": {
            "kind": "network-containment",
            "direction": "outbound",
            "action": "block",
            "remote_scope": "operator-must-select",
            "preserve_loopback": True,
        },
        "required_gates": [
            "typed-target-selection",
            "fresh-host-precondition",
            "rollback-snapshot",
            "exact-operator-approval",
            "postcondition-verification",
            "independent-defensive-retest",
        ],
        "evidence_sha256": evidence_digest,
        "evidence": evidence,
        "limitations": [
            "No firewall rule was created.",
            "No PowerShell or shell text was generated or executed.",
            "A later verified response broker must build a closed-catalog plan.",
        ],
    }
    path = _proposal_root() / f"{proposal_id}.json"
    try:
        _atomic_json(path, document)
    except Exception as exc:
        return {
            "technique": technique,
            "ok": False,
            "executed": False,
            "error": str(exc),
        }
    return {
        "technique": technique,
        "ok": True,
        "proposal": str(path),
        "proposal_id": proposal_id,
        "review_required": True,
        "executed": False,
        "verified": False,
        "reverify": "NOT_RUN",
    }


if __name__ == "__main__":
    import sys

    requested = sys.argv[1] if len(sys.argv) > 1 else "T1055"
    print(json.dumps(tune_containment(requested), indent=2))
