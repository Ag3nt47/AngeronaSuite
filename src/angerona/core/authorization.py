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


def _scopes_overlap(first: str, second: str) -> bool:
    return _scope_contains(first, second) or _scope_contains(second, first)


def _validate_scope(scope: str) -> None:
    if not _IDENTIFIER.fullmatch(scope):
        raise ValueError("invalid authorization scope")
    if scope.startswith("/") or scope.endswith("/") or "//" in scope:
        raise ValueError("authorization scope must be canonical")
    parts = scope.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        raise ValueError("authorization scope must not contain traversal segments")


STANDARD_ROLES = (
    Role(
        "viewer",
        (
            "alert.read", "case.read", "evidence.read", "inventory.read",
            "module.read", "posture.read",
        ),
    ),
    Role(
        "analyst",
        (
            "alert.acknowledge", "alert.read", "case.comment", "case.create",
            "case.read", "evidence.read", "inventory.read", "posture.read",
        ),
    ),
    Role(
        "hunter",
        (
            "case.comment", "case.create", "case.read", "evidence.read",
            "hunt.cancel", "hunt.create", "hunt.preview", "hunt.read",
            "inventory.read",
        ),
    ),
    Role(
        "responder",
        (
            "alert.read", "case.comment", "case.read", "evidence.read",
            "response.approve", "response.execute", "response.preview",
            "response.propose",
        ),
        ("response.register",),
    ),
    Role(
        "detection-engineer",
        (
            "detection.create", "detection.export", "detection.read",
            "detection.stage", "detection.test", "policy.preview",
        ),
        ("detection.activate", "release.sign"),
    ),
    Role(
        "fleet-operator",
        (
            "collection.preview", "device.quarantine", "device.read",
            "device.revoke", "job.cancel", "job.create", "job.read",
            "policy.read",
        ),
        ("policy.activate", "release.sign"),
    ),
    Role(
        "tenant-administrator",
        (
            "device.read", "identity.bind", "identity.read", "identity.revoke",
            "policy.approve", "policy.preview", "role.bind", "role.read",
            "tenant.read", "tenant.update",
        ),
        ("platform.configure", "release.sign"),
    ),
    Role(
        "platform-administrator",
        (
            "platform.configure", "platform.read", "policy.activate",
            "policy.approve", "policy.preview", "release.read", "release.verify",
            "role.bind", "role.read",
        ),
        ("audit.delete", "evidence.delete", "release.sign"),
    ),
    Role(
        "auditor",
        (
            "audit.export", "audit.read", "case.read", "evidence.read",
            "policy.read", "release.read",
        ),
        (
            "audit.write", "case.write", "evidence.write", "policy.activate",
            "response.execute",
        ),
    ),
)

STANDARD_ROLES_BY_ID = {role.role_id: role for role in STANDARD_ROLES}

# A principal may hold these roles in distinct scopes, but never in overlapping
# scopes. This keeps auditors independent and separates detection authors from
# policy activation authority without relying on a user-interface convention.
DEFAULT_DUTY_CONSTRAINTS = tuple(
    frozenset(("auditor", role_id))
    for role_id in (
        "analyst", "hunter", "responder", "detection-engineer",
        "fleet-operator", "tenant-administrator", "platform-administrator",
    )
) + (
    frozenset(("detection-engineer", "tenant-administrator")),
    frozenset(("detection-engineer", "platform-administrator")),
)


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
        *,
        duty_constraints: Sequence[frozenset[str]] = DEFAULT_DUTY_CONSTRAINTS,
    ) -> None:
        if len(audit_key) < 32:
            raise ValueError("audit key must be at least 32 bytes")
        if len(roles) > MAX_ROLES or len(bindings) > MAX_BINDINGS:
            raise ValueError("authorization policy bound exceeded")
        self.principals = {item.principal_id: item for item in principals}
        self.roles = {item.role_id: item for item in roles}
        self.bindings = tuple(bindings)
        self.duty_constraints = tuple(
            sorted(
                (frozenset(rule) for rule in duty_constraints),
                key=lambda rule: tuple(sorted(rule)),
            )
        )
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
        for rule in self.duty_constraints:
            if len(rule) != 2 or any(
                not _IDENTIFIER.fullmatch(role_id) for role_id in rule
            ):
                raise ValueError("invalid separation-of-duty constraint")
        for index, first in enumerate(self.bindings):
            for second in self.bindings[index + 1:]:
                if first.principal_id != second.principal_id:
                    continue
                pair = frozenset((first.role_id, second.role_id))
                if (
                    pair in self.duty_constraints
                    and _scopes_overlap(first.scope, second.scope)
                ):
                    raise ValueError(
                        "separation-of-duty conflict for overlapping scope"
                    )
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
            "duty_constraints": [
                sorted(rule) for rule in self.duty_constraints
                if rule.issubset(self.roles)
            ],
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
