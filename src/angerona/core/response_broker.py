"""Typed, approval-gated enterprise response orchestration.

There is intentionally no generic command or shell operation. Every action is
registered in-process with an explicit risk class, argument validator, bounded
expiry, idempotency identity, and rollback description.
"""

from __future__ import annotations

import copy
from contextlib import contextmanager
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Mapping

from angerona.core.approval_identity import (
    ApprovalIdentityVerifier, SignedPrincipalProof, independent_principals,
)

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
    verify_outcome: Callable[[Mapping[str, Any], Mapping[str, Any]], bool] | None = field(
        default=None, repr=False, compare=False)

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
        if self.verify_outcome is not None and not callable(self.verify_outcome):
            raise ValueError("outcome verifier must be callable")


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

    def __init__(self, audit_key: bytes, *, clock=time.time,
                 identity_verifier: ApprovalIdentityVerifier | None = None,
                 state_path: Path | None = None) -> None:
        if not isinstance(audit_key, bytes) or len(audit_key) < 32:
            raise ValueError("audit key must contain at least 32 bytes")
        if not callable(clock):
            raise ValueError("response broker clock must be callable")
        self._key = bytes(audit_key)
        self._clock = clock
        if identity_verifier is not None and not isinstance(identity_verifier, ApprovalIdentityVerifier):
            raise TypeError("Broker identity verifier belongs to trusted backend composition")
        self._identity_verifier = identity_verifier
        self._operations: dict[str, ResponseOperation] = {}
        self._approvals: dict[str, dict[str, SignedPrincipalProof]] = {}
        self._receipts: dict[str, ResponseReceipt] = {}
        self._attempts: dict[str, str] = {}
        self._revoked_proposals: set[str] = set()
        self._revoked_keys: set[str] = set()
        self._revoked_subjects: set[str] = set()
        self._lock = threading.RLock()
        self._closing = threading.Event()
        self._active_operations = 0
        self._state_path = Path(state_path) if state_path is not None else None
        self._lease = None
        self._degraded = ""
        if self._state_path is not None:
            from angerona.core.engine_transport import private_directory
            from angerona.core.file_lease import ExclusiveFileLease
            private_directory(self._state_path.parent)
            self._lease = ExclusiveFileLease(self._state_path.with_suffix(self._state_path.suffix + ".lease"))
            try:
                self._load_state()
            except BaseException:
                self.close()
                raise

    def close(self, timeout=3.0):
        """Latch closed admission; retain custody until admitted work retires.

        False means a native/trusted handler still owns the lease or cleanup
        failed. Its operation finally completes receipt persistence and retries
        cleanup. A reentrant close never releases its own active authority.
        """
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 <= timeout <= 30:
            raise ValueError("Broker close timeout must be finite and at most 30 seconds")
        self._closing.set()
        acquired = self._lock.acquire(timeout=timeout)
        if not acquired:
            return False
        try:
            if self._active_operations:
                return False
            return self._finish_close_locked()
        finally:
            self._lock.release()

    def _finish_close_locked(self):
        if self._lease is not None:
            try:
                self._lease.close()
            except Exception:
                self._degraded = "Broker lease retirement failed; authority remains unavailable"
                return False
            self._lease = None
        if not self._degraded:
            self._degraded = "Broker closed"
        return True

    def _ensure_accepting(self):
        if self._closing.is_set():
            raise PermissionError("Broker is closing or closed; new authority work is unavailable")

    @contextmanager
    def _admitted(self):
        self._ensure_accepting()
        # A queued call must notice close without waiting for a blocked handler.
        while not self._lock.acquire(timeout=0.05):
            self._ensure_accepting()
        try:
            self._ensure_accepting()
            self._active_operations += 1
            try:
                yield
            finally:
                self._active_operations -= 1
                if self._closing.is_set() and not self._active_operations:
                    self._finish_close_locked()
        finally:
            self._lock.release()

    def approval_status(self):
        identity = self._identity_verifier.status() if self._identity_verifier is not None else {
            "state": "unavailable", "reason": "Authenticated operator verifier not provisioned"}
        durable = self._lease is not None and self._lease.held
        closing = self._closing.is_set()
        return dict(state="configured" if identity["state"] == "configured" and durable and not self._degraded and not closing
                    else "unavailable", identity=identity, durable=durable,
                    closing=closing, shutdown_pending=closing and (self._active_operations > 0 or self._lease is not None),
                    reason=self._degraded or ("Broker closing; admitted work retains custody" if closing else
                        "Durable protected backend required" if not durable else identity["reason"]))

    def _state_core(self):
        return dict(approvals={digest: {key: asdict(proof) for key, proof in proofs.items()}
                               for digest, proofs in self._approvals.items()},
                    receipts={key: asdict(receipt) for key, receipt in self._receipts.items()},
                    attempts=self._attempts, revoked_proposals=sorted(self._revoked_proposals),
                    revoked_keys=sorted(self._revoked_keys), revoked_subjects=sorted(self._revoked_subjects))

    def _save_state(self):
        if self._state_path is None:
            return
        if self._lease is None or not self._lease.held:
            raise PermissionError("Durable broker authority is closed")
        from angerona.core.engine_transport import create_private_file, verify_private
        from angerona.core.atomic_io import replace_with_retry
        body = self._state_core()
        encoded = _canonical(dict(schema="angerona.response-broker-state.v1", records=body,
            hmac=hmac.new(self._key, b"response-broker-state\0" + _canonical(body), hashlib.sha256).hexdigest()))
        if len(encoded) > 4 * 1024 * 1024:
            self._degraded = "Broker state byte bound exceeded"
            raise ValueError(self._degraded)
        temporary = self._state_path.with_name("." + self._state_path.name + "." + secrets.token_hex(8))
        try:
            descriptor = create_private_file(temporary)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            if self._state_path.exists():
                verify_private(self._state_path)
            replace_with_retry(temporary, self._state_path)
        except BaseException:
            self._degraded = "Durable approval state write failed; execution unavailable"
            raise
        finally:
            temporary.unlink(missing_ok=True)

    def _load_state(self):
        from angerona.core.engine_transport import create_private_file, verify_private, decode
        marker = self._state_path.with_suffix(self._state_path.suffix + ".enrolled")
        marker_value = hmac.new(self._key, b"response-broker-enrollment-v1", hashlib.sha256).hexdigest().encode()
        if marker.exists():
            verify_private(marker)
            with marker.open("rb") as stream:
                stored_marker = stream.read(65)
            if stored_marker != marker_value or not self._state_path.exists():
                raise ValueError("Durable broker enrollment/state missing or inconsistent")
        else:
            if self._state_path.exists():
                raise ValueError("Broker state enrollment marker missing")
            descriptor = create_private_file(marker)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(marker_value)
                stream.flush()
                os.fsync(stream.fileno())
            self._save_state()
            return
        verify_private(self._state_path)
        with self._state_path.open("rb") as stream:
            raw = stream.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError("Broker state byte bound exceeded")
        value = decode(raw)
        records = value.get("records")
        if value.get("schema") != "angerona.response-broker-state.v1" or not isinstance(records, dict):
            raise ValueError("Broker state schema invalid")
        expected = hmac.new(self._key, b"response-broker-state\0" + _canonical(records), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(value.get("hmac", "")), expected):
            raise ValueError("Broker state authentication failed")
        self._approvals = {digest: {key: SignedPrincipalProof(**proof) for key, proof in proofs.items()}
                           for digest, proofs in records["approvals"].items()}
        for proofs in self._approvals.values():
            if len(proofs) > 128:
                raise ValueError("Broker approval bound exceeded")
            for proof in proofs.values():
                proof.signing_bytes()  # Validate historical schema, not fresh execution authority.
        self._receipts = {key: ResponseReceipt(**{**receipt, "approvals": tuple(receipt["approvals"])})
                          for key, receipt in records["receipts"].items()}
        if any(not self.verify_receipt(receipt) for receipt in self._receipts.values()):
            raise ValueError("Broker receipt authentication failed")
        self._attempts = dict(records["attempts"])
        self._revoked_proposals = set(records["revoked_proposals"])
        self._revoked_keys = set(records["revoked_keys"])
        self._revoked_subjects = set(records["revoked_subjects"])

    def verify_approval(self, proof, purpose_digest, requested_by):
        self._ensure_accepting()
        if self._identity_verifier is None:
            raise PermissionError("Authenticated operator identity unavailable; labels cannot authorize execution")
        principal = self._identity_verifier.verify(proof, purpose_digest, now=self._now())
        requester = self._identity_verifier.resolve_principal(requested_by)
        requester_keys = {record.key_fingerprint for record in self._identity_verifier.credentials.values()
                          if record.principal_id == requester}
        if principal.principal_id == requester or principal.key_fingerprint in requester_keys:
            raise PermissionError("Requester cannot approve their own response")
        if principal.key_fingerprint in self._revoked_keys or principal.principal_id in self._revoked_subjects:
            raise PermissionError("Operator credential or subject revoked")
        return principal

    def verified_approvals(self, proofs, purpose_digest, requested_by):
        verified = []
        for proof in proofs:
            try:
                verified.append(self.verify_approval(proof, purpose_digest, requested_by))
            except PermissionError:
                continue
        return independent_principals(verified)

    def revoke_credential(self, credential_id):
        if self._identity_verifier is None or credential_id not in self._identity_verifier.credentials:
            raise PermissionError("Unknown authenticated credential")
        with self._admitted():
            self._revoked_keys.add(self._identity_verifier.credentials[credential_id].key_fingerprint)
            self._save_state()

    def revoke_proposal(self, proposal_digest):
        if not isinstance(proposal_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", proposal_digest):
            raise ValueError("Invalid proposal digest")
        with self._admitted():
            self._revoked_proposals.add(proposal_digest)
            self._save_state()

    def _now(self) -> float:
        stamp = float(self._clock())
        if not math.isfinite(stamp):
            raise ValueError("response broker clock is invalid")
        return stamp

    def register(self, operation: ResponseOperation) -> None:
        if not isinstance(operation, ResponseOperation):
            raise ValueError("operation must use the typed response schema")
        with self._admitted():
            if operation.operation_id in self._operations:
                raise ValueError("operation is already registered")
            self._operations[operation.operation_id] = operation

    def registered_operation_ids(self) -> tuple[str, ...]:
        """Return the stable closed operation catalog exposed to session policy."""
        with self._lock:
            return tuple(sorted(self._operations))

    def approve(self, proposal: ResponseProposal, approver_id: SignedPrincipalProof) -> int:
        if not isinstance(proposal, ResponseProposal):
            raise ValueError("proposal must use the typed response schema")
        proposal = ResponseProposal(**asdict(proposal))
        self.verify_approval(approver_id, proposal.digest, proposal.requested_by)
        if self._now() >= proposal.expires_at:
            raise PermissionError("response proposal expired")
        with self._admitted():
            if proposal.digest in self._revoked_proposals:
                raise PermissionError("Response proposal revoked")
            if len(self._approvals) >= 1000 and proposal.digest not in self._approvals:
                raise ValueError("Broker proposal bound exceeded")
            approvals = self._approvals.setdefault(proposal.digest, {})
            if len(approvals) >= 128 and approver_id.credential_id not in approvals:
                raise ValueError("Broker approval bound exceeded")
            approvals[approver_id.credential_id] = approver_id
            self._save_state()
            return len(self.verified_approvals(approvals.values(), proposal.digest, proposal.requested_by))

    def execute(self, proposal: ResponseProposal) -> ResponseReceipt:
        if not isinstance(proposal, ResponseProposal):
            raise ValueError("proposal must use the typed response schema")
        # Frozen dataclasses do not freeze a nested arguments dictionary.
        # Hold one detached plan so a caller/validator cannot switch bytes
        # between signature validation and the registered host operation.
        proposal = ResponseProposal(**asdict(proposal))
        with self._admitted():
            existing = self._receipts.get(proposal.proposal_id)
            if existing is not None:
                if existing.proposal_digest != proposal.digest:
                    raise ValueError("proposal ID conflicts with another request")
                if not proposal.dry_run and self.approval_status()["state"] != "configured":
                    raise PermissionError("Durable response receipt unavailable; review backend health")
                return existing
            operation = self._operations.get(proposal.operation_id)
            if operation is None:
                raise PermissionError("operation is not registered")
            admitted_at = self._now()
            if admitted_at >= proposal.expires_at:
                raise PermissionError("response proposal expired")
            operation.validator(copy.deepcopy(proposal.arguments))
            verified = self.verified_approvals(self._approvals.get(proposal.digest, {}).values(),
                                               proposal.digest, proposal.requested_by)
            approvals = tuple(principal.principal_id for principal in verified)
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
                if self.approval_status()["state"] != "configured":
                    raise PermissionError("Durable authenticated approval backend unavailable")
                if proposal.digest in self._revoked_proposals:
                    raise PermissionError("Response proposal revoked")
                if proposal.proposal_id in self._attempts:
                    raise PermissionError("Prior response attempt has no verified terminal receipt; review required")
                if operation.risk in {"high", "critical"} and operation.verify_outcome is None:
                    raise PermissionError("High-impact response requires an independent outcome verifier")
                approved_digest = proposal.digest
                self._attempts[proposal.proposal_id] = approved_digest
                self._save_state()  # Burn before action; restart cannot replay an uncertain operation.
                # Durable/native storage can be slow. All execution authority
                # must still hold AFTER that I/O, directly before dispatch.
                # Rejection keeps the attempt burned; an automatic retry could
                # otherwise duplicate an operation whose outcome is unknown.
                self._ensure_accepting()
                dispatch_at = self._now()
                if dispatch_at < admitted_at:
                    self._degraded = "Broker clock regressed during admission; backend review required"
                    raise PermissionError(self._degraded)
                if not proposal.created_at <= dispatch_at < proposal.expires_at:
                    raise PermissionError("response proposal is not currently valid after durable admission")
                if (proposal.digest != approved_digest
                        or self._attempts.get(proposal.proposal_id) != approved_digest):
                    raise PermissionError("Canonical response identity changed during durable admission")
                if (self.approval_status()["state"] != "configured"
                        or approved_digest in self._revoked_proposals):
                    raise PermissionError("Authenticated backend unavailable after durable admission")
                current = self.verified_approvals(self._approvals.get(approved_digest, {}).values(),
                                                approved_digest, proposal.requested_by)
                final_at = self._now()
                if final_at < dispatch_at:
                    self._degraded = "Broker clock regressed during admission; backend review required"
                    raise PermissionError(self._degraded)
                if (not proposal.created_at <= final_at < proposal.expires_at
                        or len(current) < required or any(principal.expires_at <= final_at for principal in current)):
                    raise PermissionError("Current independent approvals or proposal expired/revoked during durable admission")
                self._ensure_accepting()
                approvals = tuple(principal.principal_id for principal in current)
                raw = operation.handler(copy.deepcopy(proposal.arguments))
                if not isinstance(raw, Mapping):
                    raise TypeError("response handler must return a mapping")
                result = dict(raw)
                verified_outcome = (operation.verify_outcome(copy.deepcopy(proposal.arguments), copy.deepcopy(result)) is True
                                    if operation.verify_outcome is not None else None)
                outcome = ("completed" if verified_outcome is True else
                           "verification-failed" if verified_outcome is False else "completed-unverified")
                executed = True
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
            self._save_state()
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
