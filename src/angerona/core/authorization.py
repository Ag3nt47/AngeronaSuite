"""Local RBAC, service-account, scoped authorization, and audit decisions."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
import time
from collections import OrderedDict
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Mapping, Sequence

MAX_ROLES = 128
MAX_BINDINGS = 5000
MAX_PERMISSIONS = 256
MAX_RECEIPTS = 10_000
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:@/-]{1,160}$")


class PrincipalKind(str, Enum):
    HUMAN = "human"
    SERVICE = "service"


@dataclass(frozen=True)
class Principal:
    principal_id: str
    kind: PrincipalKind
    enabled: bool = True
    expires_at: float = 0

    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.principal_id):
            raise ValueError("invalid principal ID")
        if self.kind is PrincipalKind.SERVICE and self.expires_at <= 0:
            raise ValueError("service accounts require explicit expiry")


@dataclass(frozen=True)
class Role:
    role_id: str
    allow: tuple[str, ...]
    deny: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "allow", tuple(sorted(set(self.allow))))
        object.__setattr__(self, "deny", tuple(sorted(set(self.deny))))
        if not _IDENTIFIER.fullmatch(self.role_id):
            raise ValueError("invalid role ID")
        if len(self.allow) + len(self.deny) > MAX_PERMISSIONS:
            raise ValueError("role permission bound exceeded")
        for permission in (*self.allow, *self.deny):
            _validate_permission(permission)


@dataclass(frozen=True)
class RoleBinding:
    principal_id: str
    role_id: str
    scope: str
    expires_at: float = 0

    def __post_init__(self) -> None:
        if not all(_IDENTIFIER.fullmatch(item) for item in (
            self.principal_id, self.role_id
        )):
            raise ValueError("invalid binding identity or scope")
        _validate_scope(self.scope)


@dataclass(frozen=True)
class AuthorizationRequest:
    request_id: str
    principal_id: str
    permission: str
    scope: str
    resource_id: str = ""

    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.request_id):
            raise ValueError("invalid request ID")
        if not _IDENTIFIER.fullmatch(self.principal_id):
            raise ValueError("invalid principal ID")
        _validate_permission(self.permission)
        _validate_scope(self.scope)
        if self.resource_id and not _IDENTIFIER.fullmatch(self.resource_id):
            raise ValueError("invalid resource ID")


@dataclass(frozen=True)
class AuthorizationDecision:
    request_id: str
    principal_id: str
    permission: str
    scope: str
    resource_id: str
    request_digest: str
    allowed: bool
    reason: str
    matched_roles: tuple[str, ...]
    principal_kind: str
    decided_at: float
    policy_hash: str
    receipt_hmac: str


def _validate_permission(permission: str) -> None:
    parts = permission.split(".")
    if not 2 <= len(parts) <= 5 or any(
        not re.fullmatch(r"[a-z][a-z0-9_-]*|\*", part) for part in parts
    ):
        raise ValueError("invalid permission")
    if "*" in parts[:-1]:
        raise ValueError("wildcard is allowed only as the final segment")


def _matches_permission(rule: str, requested: str) -> bool:
    if rule == requested:
        return True
    return rule.endswith(".*") and requested.startswith(rule[:-1])


def _scope_contains(binding_scope: str, requested_scope: str) -> bool:
    return requested_scope == binding_scope or requested_scope.startswith(
        binding_scope.rstrip("/") + "/"
    )


def _validate_scope(scope: str) -> None:
    if not _IDENTIFIER.fullmatch(scope):
        raise ValueError("invalid authorization scope")
    if scope.startswith("/") or scope.endswith("/") or "//" in scope:
        raise ValueError("authorization scope must be canonical")
    parts = scope.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        raise ValueError("authorization scope must not contain traversal segments")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    ).encode("utf-8")


class AuthorizationPolicy:
    """Immutable-ish local policy evaluator with explicit-deny precedence."""

    def __init__(
        self,
        principals: Sequence[Principal],
        roles: Sequence[Role],
        bindings: Sequence[RoleBinding],
        audit_key: bytes,
    ) -> None:
        if len(audit_key) < 32:
            raise ValueError("audit key must be at least 32 bytes")
        if len(roles) > MAX_ROLES or len(bindings) > MAX_BINDINGS:
            raise ValueError("authorization policy bound exceeded")
        self.principals = {item.principal_id: item for item in principals}
        self.roles = {item.role_id: item for item in roles}
        self.bindings = tuple(bindings)
        self._key = bytes(audit_key)
        self._receipt_lock = threading.RLock()
        self._receipts: OrderedDict[str, tuple[str, AuthorizationDecision]] = OrderedDict()
        if len(self.principals) != len(principals) or len(self.roles) != len(roles):
            raise ValueError("duplicate principal or role")
        for binding in self.bindings:
            if binding.principal_id not in self.principals:
                raise ValueError("binding references unknown principal")
            if binding.role_id not in self.roles:
                raise ValueError("binding references unknown role")
        self.policy_hash = hashlib.sha256(_canonical({
            "principals": [asdict(item) for item in sorted(
                self.principals.values(), key=lambda item: item.principal_id
            )],
            "roles": [asdict(item) for item in sorted(
                self.roles.values(), key=lambda item: item.role_id
            )],
            "bindings": [asdict(item) for item in sorted(
                self.bindings,
                key=lambda item: (item.principal_id, item.role_id, item.scope),
            )],
        })).hexdigest()

    def decide(
        self, request: AuthorizationRequest, *, now: float | None = None
    ) -> AuthorizationDecision:
        request_core = {
            "request_id": request.request_id,
            "principal_id": request.principal_id,
            "permission": request.permission,
            "scope": request.scope,
            "resource_id": request.resource_id,
        }
        request_digest = hashlib.sha256(_canonical(request_core)).hexdigest()
        with self._receipt_lock:
            existing = self._receipts.get(request.request_id)
            if existing:
                if existing[0] != request_digest:
                    raise ValueError("request ID is already bound to another operation")
                self._receipts.move_to_end(request.request_id)
                return existing[1]
        stamp = time.time() if now is None else float(now)
        principal = self.principals.get(request.principal_id)
        allowed = False
        reason = "principal not found"
        roles: list[Role] = []
        if principal is not None:
            if not principal.enabled:
                reason = "principal disabled"
            elif principal.expires_at and principal.expires_at <= stamp:
                reason = "principal expired"
            else:
                role_ids = sorted({
                    binding.role_id for binding in self.bindings
                    if binding.principal_id == principal.principal_id
                    and (not binding.expires_at or binding.expires_at > stamp)
                    and _scope_contains(binding.scope, request.scope)
                })
                roles = [self.roles[role_id] for role_id in role_ids]
                denied = any(
                    _matches_permission(rule, request.permission)
                    for role in roles for rule in role.deny
                )
                permitted = any(
                    _matches_permission(rule, request.permission)
                    for role in roles for rule in role.allow
                )
                if denied:
                    reason = "explicit deny"
                elif permitted:
                    allowed, reason = True, "role permission matched"
                else:
                    reason = "no matching role permission"
        core = {
            **request_core, "request_digest": request_digest, "allowed": allowed,
            "reason": reason, "matched_roles": tuple(role.role_id for role in roles),
            "principal_kind": principal.kind.value if principal else "unknown",
            "decided_at": stamp, "policy_hash": self.policy_hash,
        }
        signature = hmac.new(self._key, _canonical(core), hashlib.sha256).hexdigest()
        decision = AuthorizationDecision(**core, receipt_hmac=signature)
        with self._receipt_lock:
            # Recheck under the lock in case two callers raced on one request ID.
            existing = self._receipts.get(request.request_id)
            if existing:
                if existing[0] != request_digest:
                    raise ValueError("request ID is already bound to another operation")
                return existing[1]
            self._receipts[request.request_id] = (request_digest, decision)
            self._receipts.move_to_end(request.request_id)
            while len(self._receipts) > MAX_RECEIPTS:
                self._receipts.popitem(last=False)
        return decision

    def verify_decision(self, decision: AuthorizationDecision) -> bool:
        core = asdict(decision)
        signature = core.pop("receipt_hmac")
        return (
            decision.policy_hash == self.policy_hash
            and hmac.compare_digest(
                signature,
                hmac.new(self._key, _canonical(core), hashlib.sha256).hexdigest(),
            )
        )
