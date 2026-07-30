"""Typed, approval-gated enterprise response orchestration.

There is intentionally no generic command or shell operation. Every action is
registered in-process with an explicit risk class, argument validator, bounded
expiry, idempotency identity, and rollback description.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Mapping

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{2,127}$")
_OP = re.compile(r"^[a-z][a-z0-9_.-]{2,79}$")
_RISKS = {"low", "medium", "high", "critical"}
_MAX_BYTES = 64 * 1024


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("response data must use finite JSON-safe types") from exc


@dataclass(frozen=True)
class ResponseOperation:
    operation_id: str
    risk: str
    description: str
    rollback: str
    validator: Callable[[Mapping[str, Any]], None] = field(repr=False, compare=False)
    handler: Callable[[Mapping[str, Any]], Mapping[str, Any]] = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.operation_id, str) or not _OP.fullmatch(self.operation_id):
            raise ValueError("invalid operation ID")
        if not isinstance(self.risk, str) or self.risk not in _RISKS:
            raise ValueError("invalid response risk")
        if (
            not isinstance(self.description, str)
            or not isinstance(self.rollback, str)
            or not self.description.strip()
            or not self.rollback.strip()
            or len(self.description) > 2000
            or len(self.rollback) > 2000
            or not callable(self.validator)
            or not callable(self.handler)
        ):
            raise ValueError("description and rollback are required")


@dataclass(frozen=True)
class ResponseProposal:
    proposal_id: str
    operation_id: str
    arguments: Mapping[str, Any]
    target_id: str
    requested_by: str
    created_at: float
    expires_at: float
    dry_run: bool = True

    def __post_init__(self) -> None:
        for value in (self.proposal_id, self.target_id, self.requested_by):
            if not isinstance(value, str) or not _ID.fullmatch(value):
                raise ValueError("invalid response identity")
        if not isinstance(self.operation_id, str) or not _OP.fullmatch(self.operation_id):
            raise ValueError("invalid operation ID")
        if type(self.arguments) is not dict or len(self.arguments) > 64:
            raise ValueError("arguments must be a bounded mapping")
        if (
            type(self.created_at) not in (int, float)
            or type(self.expires_at) not in (int, float)
            or not math.isfinite(float(self.created_at))
            or not math.isfinite(float(self.expires_at))
            or not self.created_at < self.expires_at <= self.created_at + 3600
        ):
            raise ValueError("response expiry must be within one hour")
        if type(self.dry_run) is not bool:
            raise ValueError("dry-run state must be a boolean")
        if len(_canonical(asdict(self))) > _MAX_BYTES:
            raise ValueError("response proposal exceeds byte budget")

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical(asdict(self))).hexdigest()


@dataclass(frozen=True)
class ResponseReceipt:
    proposal_id: str
    proposal_digest: str
    operation_id: str
    target_id: str
    outcome: str
    executed: bool
    approvals: tuple[str, ...]
    result: Mapping[str, Any]
    recorded_at: float
    receipt_hmac: str


class ResponseBroker:
    """In-memory authorization boundary for locally registered handlers."""

    def __init__(self, audit_key: bytes, *, clock=time.time) -> None:
        if not isinstance(audit_key, bytes) or len(audit_key) < 32:
            raise ValueError("audit key must contain at least 32 bytes")
        if not callable(clock):
            raise ValueError("response broker clock must be callable")
        self._key = bytes(audit_key)
        self._clock = clock
        self._operations: dict[str, ResponseOperation] = {}
        self._approvals: dict[str, set[str]] = {}
        self._receipts: dict[str, ResponseReceipt] = {}
        self._lock = threading.RLock()

    def _now(self) -> float:
        stamp = float(self._clock())
        if not math.isfinite(stamp):
            raise ValueError("response broker clock is invalid")
        return stamp

    def register(self, operation: ResponseOperation) -> None:
        if not isinstance(operation, ResponseOperation):
            raise ValueError("operation must use the typed response schema")
        with self._lock:
            if operation.operation_id in self._operations:
                raise ValueError("operation is already registered")
            self._operations[operation.operation_id] = operation

    def registered_operation_ids(self) -> tuple[str, ...]:
        """Return the stable closed operation catalog exposed to session policy."""
        with self._lock:
            return tuple(sorted(self._operations))

    def approve(self, proposal: ResponseProposal, approver_id: str) -> int:
        if not isinstance(proposal, ResponseProposal):
            raise ValueError("proposal must use the typed response schema")
        if not isinstance(approver_id, str) or not _ID.fullmatch(approver_id):
            raise ValueError("invalid approver identity")
        if approver_id == proposal.requested_by:
            raise PermissionError("requester cannot approve their own response")
        if self._now() >= proposal.expires_at:
            raise PermissionError("response proposal expired")
        with self._lock:
            approvals = self._approvals.setdefault(proposal.digest, set())
            approvals.add(approver_id)
            return len(approvals)

    def execute(self, proposal: ResponseProposal) -> ResponseReceipt:
        if not isinstance(proposal, ResponseProposal):
            raise ValueError("proposal must use the typed response schema")
        with self._lock:
            existing = self._receipts.get(proposal.proposal_id)
            if existing is not None:
                if existing.proposal_digest != proposal.digest:
                    raise ValueError("proposal ID conflicts with another request")
                return existing
            operation = self._operations.get(proposal.operation_id)
            if operation is None:
                raise PermissionError("operation is not registered")
            if self._now() >= proposal.expires_at:
                raise PermissionError("response proposal expired")
            operation.validator(dict(proposal.arguments))
            approvals = tuple(sorted(self._approvals.get(proposal.digest, ())))
            required = 2 if operation.risk in {"high", "critical"} else 1
            if not proposal.dry_run and len(approvals) < required:
                raise PermissionError(f"{operation.risk} response requires {required} approval(s)")
            if proposal.dry_run:
                result: Mapping[str, Any] = {
                    "validated": True,
                    "risk": operation.risk,
                    "rollback": operation.rollback,
                }
                outcome, executed = "previewed", False
            else:
                raw = operation.handler(dict(proposal.arguments))
                if not isinstance(raw, Mapping):
                    raise TypeError("response handler must return a mapping")
                result = dict(raw)
                outcome, executed = "completed", True
            if len(_canonical(result)) > _MAX_BYTES:
                raise ValueError("response result exceeds byte budget")
            core = {
                "proposal_id": proposal.proposal_id,
                "proposal_digest": proposal.digest,
                "operation_id": proposal.operation_id,
                "target_id": proposal.target_id,
                "outcome": outcome,
                "executed": executed,
                "approvals": approvals,
                "result": result,
                "recorded_at": self._now(),
            }
            receipt = ResponseReceipt(
                **core,
                receipt_hmac=hmac.new(self._key, _canonical(core), hashlib.sha256).hexdigest(),
            )
            self._receipts[proposal.proposal_id] = receipt
            return receipt

    def verify_receipt(self, receipt: ResponseReceipt) -> bool:
        if not isinstance(receipt, ResponseReceipt):
            return False
        try:
            value = asdict(receipt)
            signature = value.pop("receipt_hmac")
            if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{64}", signature):
                return False
            expected = hmac.new(self._key, _canonical(value), hashlib.sha256).hexdigest()
            return hmac.compare_digest(signature, expected)
        except Exception:
            return False
