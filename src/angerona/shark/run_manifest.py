"""Versioned safety contracts and evidence manifests for benign drills.

The Shark and Red Team engines intentionally create only inert, reversible test
effects.  This module adds two enterprise controls around those existing steps:

* a fail-closed preflight budget for cycles, jitter, noise and custom text; and
* a deterministic, hash-chained, HMAC-attested ground-truth run manifest.

It does not add techniques or execute any action.  Artifact provenance reads
only bounded files that the drill already recorded, and exports a basename,
size, and SHA-256 digest rather than copying marker content.
"""
from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import math
import os
import re
import unicodedata
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from angerona.core import report_attest


RUN_SCHEMA = "angerona.drill-run"
RUN_SCHEMA_VERSION = 1
SAFETY_CONTRACT_VERSION = 1
EVIDENCE_CHAIN_ALGORITHM = "sha256-chain-v1"
GENESIS_HASH = "0" * 64

ALLOWED_KINDS = frozenset({"shark", "red_team"})
MAX_CYCLES = 4
MAX_JITTER_SECONDS = 60.0
MAX_CUSTOM_NAME_CHARS = 128
MAX_CUSTOM_PAYLOAD_BYTES = 16 * 1024
MAX_STEPS = 80
MAX_ARTIFACT_REFERENCES = 128
MAX_PROCESS_REFERENCES = 128
MAX_EVIDENCE_FILE_BYTES = 16 * 1024 * 1024
MAX_HISTORY_BYTES = 8 * 1024 * 1024

_ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

_SAFETY_PROFILE = {
    "profile": "marker-only-local-v1",
    "allowed_effects": [
        "bounded inert marker writes",
        "read-only local enumeration",
        "short-lived tagged no-op processes",
        "fixed dummy network marker to an approved test destination",
        "bounded benign CPU or temporary-file noise",
        "best-effort cleanup of drill-owned artifacts",
    ],
    "forbidden_effects": [
        "credential or secret access",
        "real persistence",
        "privilege or token manipulation",
        "security-control bypass",
        "destructive overwrite or encryption",
        "real-data collection or exfiltration",
        "unreviewed command or payload execution",
    ],
}


class DrillHistoryIntegrityError(ValueError):
    """Raised when a ground-truth history cannot be trusted for reporting."""


@dataclass(frozen=True)
class PreflightDecision:
    accepted: bool
    kind: str
    cycles: int
    jitter: tuple[float, float]
    noise_chance: float
    target: dict[str, Any]
    custom: dict[str, Any] | None
    request_digest: str
    violations: tuple[str, ...]
    budget: Mapping[str, int | float]

    def as_dict(self) -> dict[str, Any]:
        return {
            "contract_version": SAFETY_CONTRACT_VERSION,
            "accepted": self.accepted,
            "kind": self.kind,
            "cycles": self.cycles,
            "jitter": list(self.jitter),
            "noise_chance": self.noise_chance,
            "target": dict(self.target),
            "custom": dict(self.custom) if self.custom else None,
            "request_digest": self.request_digest,
            "violations": list(self.violations),
            "budget": dict(self.budget),
            "safety_profile": dict(_SAFETY_PROFILE),
        }


@dataclass(frozen=True)
class HistoryVerification:
    valid: bool
    authenticity: str
    reason: str
    steps: int
    final_hash: str
    legacy: bool = False


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _finite_number(value: Any) -> float | None:
    if type(value) not in (int, float):
        return None
    parsed = float(value)
    return parsed if math.isfinite(parsed) else None


def _safe_cycles(value: Any) -> tuple[int, str | None]:
    if isinstance(value, bool):
        return 0, "cycles must be an integer"
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return 0, "cycles must be an integer"
    if parsed < 1 or parsed > MAX_CYCLES:
        return parsed, f"cycles must be between 1 and {MAX_CYCLES}"
    return parsed, None


def preflight_run(
    *,
    kind: str,
    cycles: Any,
    jitter_range: Any,
    noise_chance: Any,
    target_dir: Any = None,
    custom: Any = None,
) -> PreflightDecision:
    """Validate one drill request before any worker or marker is created."""
    normalized_kind = str(kind or "").strip().casefold()
    violations: list[str] = []
    if normalized_kind not in ALLOWED_KINDS:
        violations.append("kind is not a recognized benign drill profile")

    normalized_cycles, cycle_error = _safe_cycles(cycles)
    if cycle_error:
        violations.append(cycle_error)

    lo = hi = 0.0
    if (
        not isinstance(jitter_range, (list, tuple))
        or len(jitter_range) != 2
    ):
        violations.append("jitter_range must contain exactly two numbers")
    else:
        parsed_lo = _finite_number(jitter_range[0])
        parsed_hi = _finite_number(jitter_range[1])
        if parsed_lo is None or parsed_hi is None:
            violations.append("jitter_range values must be finite numbers")
        else:
            lo, hi = parsed_lo, parsed_hi
            if lo < 0 or hi < lo or hi > MAX_JITTER_SECONDS:
                violations.append(
                    f"jitter_range must satisfy 0 <= low <= high <= "
                    f"{MAX_JITTER_SECONDS:g}"
                )

    noise = _finite_number(noise_chance)
    if noise is None or noise < 0.0 or noise > 1.0:
        violations.append("noise_chance must be a finite number from 0 to 1")
        noise = 0.0

    normalized_target: dict[str, Any] = {"scope": "engine-default"}
    if target_dir is not None:
        try:
            raw_target = os.path.expandvars(
                os.path.expanduser(str(target_dir).strip())
            )
            windows_form = raw_target.replace("/", "\\")
            if not raw_target or "\x00" in raw_target:
                raise ValueError("target directory must be a non-empty path")
            if len(raw_target) > 1024:
                raise ValueError("target directory path is too long")
            if windows_form.startswith(
                ("\\\\", "\\\\?\\", "\\\\.\\")
            ):
                raise ValueError("network and device paths are not permitted")
            resolved_target = Path(raw_target).resolve(strict=False)
            if resolved_target == Path(resolved_target.anchor):
                raise ValueError("a filesystem root is not a permitted target")
            canonical_target = os.path.normcase(str(resolved_target))
            normalized_target = {
                "scope": "operator-local-directory",
                "name": resolved_target.name[:260],
                "path_sha256": hashlib.sha256(
                    canonical_target.encode("utf-8")
                ).hexdigest(),
            }
        except (OSError, RuntimeError, UnicodeError, ValueError) as exc:
            violations.append(str(exc) or "target directory is invalid")
            normalized_target = {"scope": "invalid"}

    normalized_custom: dict[str, Any] | None = None
    if custom is not None:
        if not isinstance(custom, Mapping):
            violations.append("custom technique must be a name/payload mapping")
        else:
            name = custom.get("name")
            payload = custom.get("payload")
            if not isinstance(name, str) or not name.strip() or "\x00" in name:
                violations.append("custom technique name must be non-empty text")
                name = ""
            if not isinstance(payload, str) or "\x00" in payload:
                violations.append("custom payload must be inert UTF-8 text")
                payload = ""
            clean_name = unicodedata.normalize("NFC", str(name).strip())
            if any(
                unicodedata.category(character) in {"Cc", "Cf"}
                for character in clean_name
            ):
                violations.append(
                    "custom technique name must not contain control characters"
                )
                clean_name = ""
            payload_text = str(payload)
            try:
                clean_name.encode("utf-8", errors="strict")
            except UnicodeEncodeError:
                violations.append("custom technique name must be valid UTF-8 text")
                clean_name = ""
            if payload_text == "":
                violations.append("custom payload must be non-empty inert text")
            try:
                payload_bytes = payload_text.encode("utf-8", errors="strict")
            except UnicodeEncodeError:
                violations.append("custom payload must be valid UTF-8 text")
                payload_bytes = b""
            if len(clean_name) > MAX_CUSTOM_NAME_CHARS:
                violations.append(
                    f"custom technique name exceeds {MAX_CUSTOM_NAME_CHARS} characters"
                )
            if len(payload_bytes) > MAX_CUSTOM_PAYLOAD_BYTES:
                violations.append(
                    f"custom payload exceeds {MAX_CUSTOM_PAYLOAD_BYTES} UTF-8 bytes"
                )
            normalized_custom = {
                "name": clean_name[:MAX_CUSTOM_NAME_CHARS],
                # Ground truth records a digest and length, never the custom body.
                "payload_bytes": len(payload_bytes),
                "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
            }

    # Worst-case projections include optional custom and noise steps on every
    # cycle. They intentionally overestimate realized work.
    base_steps = 5 if normalized_kind == "shark" else 14
    projected_steps = max(0, normalized_cycles) * (
        base_steps + 1 + (1 if custom is not None else 0)
    )
    projected_artifacts = max(0, normalized_cycles) * (
        (6 if normalized_kind == "shark" else 13)
        + (1 if custom is not None else 0)
    )
    projected_processes = (
        max(0, normalized_cycles) * 16 if normalized_kind == "red_team" else 0
    )
    if projected_steps > MAX_STEPS:
        violations.append(f"projected steps exceed the safety budget of {MAX_STEPS}")
    if projected_artifacts > MAX_ARTIFACT_REFERENCES:
        violations.append(
            "projected artifact references exceed the safety budget of "
            f"{MAX_ARTIFACT_REFERENCES}"
        )
    if projected_processes > MAX_PROCESS_REFERENCES:
        violations.append(
            "projected process references exceed the safety budget of "
            f"{MAX_PROCESS_REFERENCES}"
        )

    request = {
        "contract_version": SAFETY_CONTRACT_VERSION,
        "kind": normalized_kind,
        "cycles": normalized_cycles,
        "jitter": [lo, hi],
        "noise_chance": noise,
        "target": normalized_target,
        "custom": normalized_custom,
        "safety_profile": _SAFETY_PROFILE["profile"],
    }
    return PreflightDecision(
        accepted=not violations,
        kind=normalized_kind,
        cycles=normalized_cycles,
        jitter=(lo, hi),
        noise_chance=float(noise),
        target=normalized_target,
        custom=normalized_custom,
        request_digest=_digest(request),
        violations=tuple(dict.fromkeys(violations)),
        budget={
            "max_cycles": MAX_CYCLES,
            "max_steps": MAX_STEPS,
            "max_artifact_references": MAX_ARTIFACT_REFERENCES,
            "max_process_references": MAX_PROCESS_REFERENCES,
            "max_custom_payload_bytes": MAX_CUSTOM_PAYLOAD_BYTES,
            "projected_steps": projected_steps,
            "projected_artifact_references": projected_artifacts,
            "projected_process_references": projected_processes,
        },
    )


def _step_dict(step: Any) -> dict[str, Any]:
    if dataclasses.is_dataclass(step) and not isinstance(step, type):
        row = dataclasses.asdict(step)
    elif isinstance(step, Mapping):
        row = dict(step)
    else:
        raise TypeError("drill step must be a dataclass or mapping")
    return row


def _artifact_receipt(value: Any) -> dict[str, Any]:
    path = Path(str(value))
    receipt: dict[str, Any] = {
        "name": path.name[:260],
        "status": "missing",
        "size": None,
        "sha256": "",
    }
    try:
        if path.is_symlink():
            receipt["status"] = "symlink-refused"
            return receipt
        if not path.is_file():
            return receipt
        size = path.stat().st_size
        receipt["size"] = int(size)
        if size < 0 or size > MAX_EVIDENCE_FILE_BYTES:
            receipt["status"] = "size-refused"
            return receipt
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(128 * 1024), b""):
                digest.update(chunk)
        receipt["sha256"] = digest.hexdigest()
        receipt["status"] = "hashed"
    except Exception:
        receipt["status"] = "unreadable"
    return receipt


def _attack_ids(step: Mapping[str, Any]) -> list[str]:
    blob = f"{step.get('stage', '')} {step.get('technique', '')}"
    return sorted({match.upper() for match in _ATTACK_ID_RE.findall(blob)})


def _step_hash(
    row: Mapping[str, Any],
    previous_hash: str,
    artifact_receipts: Any = None,
) -> str:
    body = dict(row)
    embedded = body.pop("evidence_receipt", None)
    if artifact_receipts is None and isinstance(embedded, Mapping):
        artifact_receipts = embedded.get("artifact_receipts")
    if not isinstance(artifact_receipts, list):
        artifact_receipts = []
    return _digest({
        "previous_step_hash": previous_hash,
        "step": body,
        "artifact_receipts": artifact_receipts,
    })


def _usage(steps: Iterable[Mapping[str, Any]]) -> dict[str, int | bool]:
    rows = list(steps)
    artifacts = sum(len(row.get("artifact_paths") or []) for row in rows)
    processes = 0
    for row in rows:
        pids = {
            pid for pid in ([row.get("pid")] + list(row.get("pids") or []))
            if isinstance(pid, int) and pid > 0
        }
        processes += len(pids)
    within = (
        len(rows) <= MAX_STEPS
        and artifacts <= MAX_ARTIFACT_REFERENCES
        and processes <= MAX_PROCESS_REFERENCES
    )
    return {
        "steps": len(rows),
        "artifact_references": artifacts,
        "process_references": processes,
        "within_budget": within,
    }


def build_run_history(
    *,
    kind: str,
    run_id: str,
    generated: str,
    steps: Iterable[Any],
    preflight: PreflightDecision | Mapping[str, Any],
    status: str,
) -> dict[str, Any]:
    """Build a versioned history while retaining legacy top-level fields."""
    if isinstance(preflight, PreflightDecision):
        contract = preflight.as_dict()
    elif isinstance(preflight, Mapping):
        contract = dict(preflight)
    else:
        raise TypeError("preflight must be a PreflightDecision or mapping")
    if not contract.get("accepted"):
        raise ValueError("a rejected preflight cannot produce a trusted run history")

    serialized: list[dict[str, Any]] = []
    previous_hash = GENESIS_HASH
    realized_plan: list[dict[str, Any]] = []
    for index, source_step in enumerate(steps):
        row = _step_dict(source_step)
        row["run_id"] = str(run_id)
        step_identity = {
            "run_id": str(run_id),
            "position": index,
            "stage": str(row.get("stage", "")),
            "technique": str(row.get("technique", "")),
        }
        row["step_id"] = f"DSTEP-{_digest(step_identity)[:20].upper()}"
        row["attack_ids"] = _attack_ids(row)
        artifacts = list(row.get("artifact_paths") or [])
        artifact_receipts = [
            _artifact_receipt(value)
            for value in artifacts[:MAX_ARTIFACT_REFERENCES]
        ]
        current_hash = _step_hash(row, previous_hash, artifact_receipts)
        row["evidence_receipt"] = {
            "algorithm": EVIDENCE_CHAIN_ALGORITHM,
            "previous_step_hash": previous_hash,
            "step_hash": current_hash,
            "artifact_receipts": artifact_receipts,
        }
        previous_hash = current_hash
        serialized.append(row)
        realized_plan.append({
            "position": index,
            "stage": str(row.get("stage", "")),
            "technique": str(row.get("technique", "")),
            "attack_ids": list(row["attack_ids"]),
            "ok": bool(row.get("ok", False)),
        })

    usage = _usage(serialized)
    normalized_status = str(status).strip().casefold()
    if normalized_status not in {"completed", "cancelled"}:
        normalized_status = "cancelled"
    payload = {
        "run_schema": RUN_SCHEMA,
        "run_schema_version": RUN_SCHEMA_VERSION,
        "run_id": str(run_id),
        "generated": str(generated),
        "kind": str(kind),
        "status": normalized_status,
        "campaign": {
            "profile_id": (
                "angerona.shark.marker-only"
                if kind == "shark"
                else "angerona.red-team.marker-only"
            ),
            "profile_version": 1,
            "request_digest": str(contract.get("request_digest", "")),
            "realized_plan_sha256": _digest(realized_plan),
            "realized_plan": realized_plan,
        },
        "safety_contract": {
            **contract,
            "actual_usage": usage,
        },
        "steps": serialized,
        "evidence_chain": {
            "algorithm": EVIDENCE_CHAIN_ALGORITHM,
            "genesis_hash": GENESIS_HASH,
            "final_hash": previous_hash,
            "step_count": len(serialized),
        },
    }
    return payload


def attest_run_history(
    history: Mapping[str, Any],
    *,
    key: bytes | None = None,
) -> dict[str, Any]:
    """HMAC-attest a run history with the install key or an explicit test key."""
    body = dict(history)
    body.pop(report_attest.SIG_FIELD, None)
    signature = report_attest.sign_doc(body, key=key)
    if signature:
        body[report_attest.SIG_FIELD] = signature
    return body


def write_run_history(
    path: Path,
    history: Mapping[str, Any],
    *,
    key: bytes | None = None,
) -> bool:
    """Atomically persist an attested run history.

    Returns ``True`` when an HMAC was embedded. Failure to sign is represented
    by ``False`` but the local ground truth is still written for diagnostics;
    strict AAR loading will refuse to trust it.
    """
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    signed = attest_run_history(history, key=key)
    encoded = json.dumps(signed, indent=2, ensure_ascii=False)
    if len(encoded.encode("utf-8")) > MAX_HISTORY_BYTES:
        raise ValueError("run history exceeds the bounded history size")
    temporary = destination.with_name(
        f".{destination.name}.{uuid.uuid4().hex}.tmp"
    )
    try:
        temporary.write_text(encoded, encoding="utf-8")
        os.replace(str(temporary), str(destination))
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except Exception:
            pass
    return report_attest.SIG_FIELD in signed


def _verify_chain(history: Mapping[str, Any]) -> tuple[bool, str, str]:
    steps = history.get("steps")
    if not isinstance(steps, list):
        return False, "steps must be a list", ""
    kind = str(history.get("kind", ""))
    if kind not in ALLOWED_KINDS:
        return False, "drill kind is unsupported", ""
    if not str(history.get("run_id", "")).strip():
        return False, "run id is missing", ""
    if history.get("status") not in {"completed", "cancelled"}:
        return False, "run status is invalid", ""
    if len(steps) > MAX_STEPS:
        return False, "step count exceeds the safety budget", ""
    previous_hash = GENESIS_HASH
    seen_ids: set[str] = set()
    for index, row in enumerate(steps):
        if not isinstance(row, Mapping):
            return False, f"step {index} is not an object", previous_hash
        step_id = str(row.get("step_id", ""))
        if not step_id or step_id in seen_ids:
            return False, f"step {index} has a missing or duplicate id", previous_hash
        seen_ids.add(step_id)
        if str(row.get("run_id", "")) != str(history.get("run_id", "")):
            return False, f"step {index} is bound to a different run", previous_hash
        receipt = row.get("evidence_receipt")
        if not isinstance(receipt, Mapping):
            return False, f"step {index} lacks an evidence receipt", previous_hash
        if receipt.get("algorithm") != EVIDENCE_CHAIN_ALGORITHM:
            return False, f"step {index} uses an unsupported evidence algorithm", previous_hash
        if receipt.get("previous_step_hash") != previous_hash:
            return False, f"step {index} breaks the evidence chain", previous_hash
        expected = _step_hash(row, previous_hash)
        if receipt.get("step_hash") != expected:
            return False, f"step {index} evidence hash does not match", previous_hash
        previous_hash = expected
    chain = history.get("evidence_chain")
    if not isinstance(chain, Mapping):
        return False, "evidence chain summary is missing", previous_hash
    if chain.get("algorithm") != EVIDENCE_CHAIN_ALGORITHM:
        return False, "evidence chain algorithm is unsupported", previous_hash
    if chain.get("genesis_hash") != GENESIS_HASH:
        return False, "evidence chain genesis is invalid", previous_hash
    if chain.get("step_count") != len(steps):
        return False, "evidence chain step count does not match", previous_hash
    if chain.get("final_hash") != previous_hash:
        return False, "evidence chain final hash does not match", previous_hash
    usage = _usage(steps)
    if not usage["within_budget"]:
        return False, "realized run exceeded its safety budget", previous_hash
    recorded_usage = (
        history.get("safety_contract", {}).get("actual_usage")
        if isinstance(history.get("safety_contract"), Mapping)
        else None
    )
    if recorded_usage != usage:
        return False, "recorded safety-budget usage does not match", previous_hash
    safety = history.get("safety_contract")
    if not isinstance(safety, Mapping):
        return False, "safety contract is missing", previous_hash
    if safety.get("kind") != kind:
        return (
            False,
            "safety contract is bound to a different drill kind",
            previous_hash,
        )
    safety_profile = safety.get("safety_profile")
    profile_id = (
        safety_profile.get("profile")
        if isinstance(safety_profile, Mapping)
        else ""
    )
    request = {
        "contract_version": safety.get("contract_version"),
        "kind": safety.get("kind"),
        "cycles": safety.get("cycles"),
        "jitter": safety.get("jitter"),
        "noise_chance": safety.get("noise_chance"),
        "target": safety.get("target"),
        "custom": safety.get("custom"),
        "safety_profile": profile_id,
    }
    if safety.get("request_digest") != _digest(request):
        return False, "safety preflight digest does not match", previous_hash
    campaign = history.get("campaign")
    if not isinstance(campaign, Mapping):
        return False, "campaign manifest is missing", previous_hash
    expected_profile = (
        "angerona.shark.marker-only"
        if kind == "shark"
        else "angerona.red-team.marker-only"
    )
    if campaign.get("profile_id") != expected_profile:
        return False, "campaign profile does not match the drill kind", previous_hash
    realized_plan = [
        {
            "position": index,
            "stage": str(row.get("stage", "")),
            "technique": str(row.get("technique", "")),
            "attack_ids": list(row.get("attack_ids") or []),
            "ok": bool(row.get("ok", False)),
        }
        for index, row in enumerate(steps)
    ]
    if campaign.get("request_digest") != safety.get("request_digest"):
        return False, "campaign is bound to a different preflight", previous_hash
    if campaign.get("realized_plan") != realized_plan:
        return False, "campaign realized plan does not match its steps", previous_hash
    if campaign.get("realized_plan_sha256") != _digest(realized_plan):
        return False, "campaign realized-plan digest does not match", previous_hash
    return True, "evidence chain verified", previous_hash


def verify_run_history(
    history: Mapping[str, Any],
    *,
    require_authenticity: bool = True,
    key: bytes | None = None,
    allow_legacy: bool = False,
) -> HistoryVerification:
    """Verify schema, HMAC, evidence chain, run binding, and safety budgets."""
    if not isinstance(history, Mapping):
        return HistoryVerification(False, "invalid", "history is not an object", 0, "")
    if history.get("run_schema") != RUN_SCHEMA:
        if allow_legacy and isinstance(history.get("steps"), list):
            return HistoryVerification(
                True,
                "legacy-unsigned",
                "legacy history accepted by explicit compatibility policy",
                len(history["steps"]),
                "",
                legacy=True,
            )
        return HistoryVerification(
            False,
            "legacy-unsigned",
            "history lacks the versioned drill-run schema",
            len(history.get("steps", [])) if isinstance(history.get("steps"), list) else 0,
            "",
            legacy=True,
        )
    if history.get("run_schema_version") != RUN_SCHEMA_VERSION:
        return HistoryVerification(
            False,
            "invalid",
            "unsupported drill-run schema version",
            0,
            "",
        )
    safety = history.get("safety_contract")
    if not isinstance(safety, Mapping) or safety.get("accepted") is not True:
        return HistoryVerification(
            False, "invalid", "run lacks an accepted safety preflight", 0, ""
        )

    if key is None:
        authenticity = report_attest.verify(dict(history))
    else:
        provided = str(history.get(report_attest.SIG_FIELD, ""))
        expected = report_attest.sign_doc(dict(history), key=key)
        authenticity = (
            "ok" if provided and expected and hmac.compare_digest(provided, expected)
            else "unsigned" if not provided
            else "bad"
        )
    if authenticity == "bad":
        return HistoryVerification(
            False, authenticity, "history HMAC is invalid", 0, ""
        )
    if require_authenticity and authenticity != "ok":
        return HistoryVerification(
            False,
            authenticity,
            f"history authenticity is {authenticity}",
            0,
            "",
        )

    valid, reason, final_hash = _verify_chain(history)
    steps = len(history.get("steps", []))
    return HistoryVerification(
        valid,
        authenticity,
        reason,
        steps,
        final_hash,
    )


def allow_legacy_history() -> bool:
    """Explicit compatibility escape hatch; secure default is fail closed."""
    return os.environ.get(
        "ANGERONA_ALLOW_UNSIGNED_DRILL_HISTORY", ""
    ).strip().casefold() in {"1", "true", "yes", "on"}


def load_verified_history(
    path: Path,
    *,
    require_authenticity: bool = True,
    allow_legacy: bool | None = None,
) -> dict[str, Any]:
    """Load a bounded history and refuse untrusted ground truth."""
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise DrillHistoryIntegrityError("history must be a regular non-symlink file")
    size = source.stat().st_size
    if size <= 0 or size > MAX_HISTORY_BYTES:
        raise DrillHistoryIntegrityError("history size is outside the accepted bounds")
    try:
        history = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DrillHistoryIntegrityError(
            f"history cannot be parsed ({type(exc).__name__})"
        ) from exc
    verification = verify_run_history(
        history,
        require_authenticity=require_authenticity,
        allow_legacy=(
            allow_legacy_history() if allow_legacy is None else bool(allow_legacy)
        ),
    )
    if not verification.valid:
        raise DrillHistoryIntegrityError(verification.reason)
    return dict(history)
