"""Pure, shadow-only policy evaluation for proposed defensive actions.

This module is deliberately *not* an authorization gate.  It cannot execute,
delay, approve, or refuse an action.  Callers may mirror a proposal here and
record the resulting digest/diagnostic codes for later comparison with the
existing, authoritative control path.

The evaluator has no I/O, network, host-process lookup, or external dependency.
Its ``ALLOW``/``DENY`` result describes only what this experimental policy model
would have decided.  Malformed requests, incomplete authorization context,
stale process identity, protected processes, digest changes, and policy errors
all fail closed *inside the shadow result*.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import PureWindowsPath
from typing import Any


POLICY_VERSION = "angerona-response-safety-shadow/1"
_MAX_DEPTH = 8
_MAX_ITEMS = 512
_MAX_STRING = 4096
_MAX_CANONICAL_BYTES = 65_536
_PROTECTED_PROCESS_NAMES = frozenset({
    "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "svchost.exe", "ntoskrnl.exe", "system", "registry",
})
_SAFE_CODE = re.compile(r"[^a-z0-9_.-]+")


@dataclass(frozen=True)
class ShadowDecision:
    """Non-authoritative result from the experimental policy model."""

    decision: str
    digest: str
    diagnostics: tuple[str, ...]
    policy_version: str = POLICY_VERSION
    shadow_only: bool = True

    @property
    def allowed(self) -> bool:
        """Convenience for analysis; callers must never use this as a gate."""
        return self.decision == "ALLOW"


@dataclass(frozen=True)
class ShadowComparison:
    """Digest-only comparison with an existing control-path disposition."""

    current_decision: str
    shadow_decision: str
    aligned: bool
    digest: str
    diagnostics: tuple[str, ...]
    shadow_only: bool = True


class _InputError(ValueError):
    def __init__(self, code: str, path: str) -> None:
        super().__init__(code)
        self.code = code
        self.path = path


Policy = tuple[str, Callable[[Mapping[str, Any]], str | None]]


def evaluate_shadow(
    principal: Mapping[str, Any],
    action: Mapping[str, Any],
    resource: Mapping[str, Any],
    context: Mapping[str, Any],
    *,
    expected_digest: str | None = None,
    policies: Sequence[Policy] = (),
) -> ShadowDecision:
    """Evaluate a canonical proposal without influencing the real action path.

    Required shapes are intentionally small: principal needs ``kind``/``id``;
    action needs ``name``; resource needs ``kind``/``id``; and context needs
    ``phase``, ``proposed_at``, ``expires_at``, and ``simulation``.  Extra JSON-
    compatible fields are retained in the digest, so argument/context mutation
    changes the identity even when the built-in policies do not inspect it.

    Optional policies are for isolated experiments.  Any exception or malformed
    return is converted to a deterministic shadow denial; it never escapes.
    """
    try:
        request = _canonical_request(principal, action, resource, context)
        encoded = json.dumps(
            request, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        if len(encoded) > _MAX_CANONICAL_BYTES:
            raise _InputError("input.too_large", "request")
        digest = hashlib.sha256(POLICY_VERSION.encode("ascii") + b"\0" + encoded).hexdigest()
    except _InputError as exc:
        marker = f"{POLICY_VERSION}\0{exc.code}\0{exc.path}".encode("utf-8")
        return ShadowDecision(
            "DENY", hashlib.sha256(marker).hexdigest(),
            (_diagnostic(exc.code, exc.path),),
        )
    except Exception:
        marker = f"{POLICY_VERSION}\0input.error".encode("ascii")
        return ShadowDecision(
            "DENY", hashlib.sha256(marker).hexdigest(), ("input.error",),
        )

    try:
        denials = _built_in_denials(request)
    except Exception:
        denials = ["policy.builtin.error"]
    if expected_digest is not None and expected_digest != digest:
        denials.append("binding.digest_mismatch")

    try:
        policy_entries = tuple(policies)
    except Exception:
        policy_entries = ()
        denials.append("policy.extension_set.error")
    for index, entry in enumerate(policy_entries):
        try:
            raw_name, policy = entry
            name = _code_fragment(raw_name)
            if not callable(policy):
                raise TypeError("policy must be callable")
            # Give each experimental policy an isolated copy.  A buggy policy
            # cannot mutate the canonical request or another policy's input.
            result = policy(json.loads(encoded))
            if result is not None:
                if not isinstance(result, str) or not result.strip():
                    raise TypeError("policy result must be a diagnostic code or None")
                denials.append(f"policy.{name}.{_code_fragment(result)}")
        except Exception:
            name = _code_fragment(entry[0]) if (
                isinstance(entry, (list, tuple)) and entry) else f"extension_{index}"
            denials.append(f"policy.{name}.error")

    diagnostics = tuple(sorted(set(denials)))
    if diagnostics:
        return ShadowDecision("DENY", digest, diagnostics)
    return ShadowDecision("ALLOW", digest, ("policy.shadow_allow",))


def compare_current(current_decision: str, shadow: ShadowDecision) -> ShadowComparison:
    """Compare, but never reconcile, a current disposition with the shadow.

    ``STAGE``/``RECOMMEND`` mean the current path did not authorize execution,
    so they align with a shadow denial.  The comparison is data only: no caller
    should branch an action on ``aligned`` or ``shadow_decision``.
    """
    current = str(current_decision).strip().upper()
    expected = {
        "STAGE": "DENY",
        "RECOMMEND": "DENY",
        "DENY": "DENY",
        "REFUSE": "DENY",
        "ALLOW": "ALLOW",
        "EXECUTE": "ALLOW",
        "ACT": "ALLOW",
    }.get(current)
    if expected is None:
        aligned = False
        diagnostics = ("comparison.unknown_current_decision",)
    else:
        aligned = expected == shadow.decision
        diagnostics = ("comparison.aligned" if aligned else "comparison.diverged",)
    return ShadowComparison(
        current or "UNKNOWN", shadow.decision, aligned, shadow.digest, diagnostics,
    )


def _canonical_request(principal: Any, action: Any, resource: Any, context: Any) -> dict:
    request = {
        "principal": _canonicalize(principal, "principal", 0, [0]),
        "action": _canonicalize(action, "action", 0, [0]),
        "resource": _canonicalize(resource, "resource", 0, [0]),
        "context": _canonicalize(context, "context", 0, [0]),
    }
    for section, fields in (
        ("principal", ("kind", "id")),
        ("action", ("name",)),
        ("resource", ("kind", "id")),
        ("context", ("phase", "proposed_at", "expires_at", "simulation")),
    ):
        value = request[section]
        if not isinstance(value, dict):
            raise _InputError("input.mapping_required", section)
        for field in fields:
            if field not in value:
                raise _InputError("input.missing", f"{section}.{field}")

    for section, field in (
        ("principal", "kind"), ("principal", "id"),
        ("action", "name"), ("resource", "kind"), ("resource", "id"),
        ("context", "phase"),
    ):
        value = request[section][field]
        if not isinstance(value, str) or not value.strip():
            raise _InputError("input.nonempty_string_required", f"{section}.{field}")
        value = value.strip()
        if field in ("kind", "name", "phase"):
            value = value.lower()
        request[section][field] = value

    if type(request["context"]["simulation"]) is not bool:
        raise _InputError("input.boolean_required", "context.simulation")
    for field in ("proposed_at", "expires_at"):
        value = request["context"][field]
        if type(value) not in (int, float):
            raise _InputError("input.number_required", f"context.{field}")
    return request


def _canonicalize(value: Any, path: str, depth: int, count: list[int]) -> Any:
    if depth > _MAX_DEPTH:
        raise _InputError("input.too_deep", path)
    count[0] += 1
    if count[0] > _MAX_ITEMS:
        raise _InputError("input.too_many_items", path)
    if value is None or type(value) in (bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise _InputError("input.nonfinite_number", path)
        return 0.0 if value == 0.0 else value
    if type(value) is str:
        if len(value) > _MAX_STRING:
            raise _InputError("input.string_too_long", path)
        return value
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str or not key:
                raise _InputError("input.string_key_required", path)
            if len(key) > 128:
                raise _InputError("input.key_too_long", path)
            out[key] = _canonicalize(item, f"{path}.{key}", depth + 1, count)
        return out
    if type(value) in (list, tuple):
        return [
            _canonicalize(item, f"{path}[{index}]", depth + 1, count)
            for index, item in enumerate(value)
        ]
    raise _InputError("input.unsupported_type", path)


def _built_in_denials(request: Mapping[str, Any]) -> list[str]:
    context = request["context"]
    resource = request["resource"]
    denials: list[str] = []

    proposed_at = float(context["proposed_at"])
    expires_at = float(context["expires_at"])
    if expires_at <= proposed_at:
        denials.append("context.invalid_expiry")

    phase = context["phase"]
    if phase in ("preview", "recommend"):
        denials.append("authorization.pending")
    elif phase == "confirmed":
        if context.get("operator_confirmed") is not True:
            denials.append("authorization.operator_confirmation_missing")
    elif phase == "corroborated":
        evidence_count = context.get("evidence_count")
        if type(evidence_count) is not int or evidence_count < 2:
            denials.append("authorization.corroboration_missing")
    elif phase != "simulation":
        denials.append("context.unknown_phase")

    if phase == "simulation" and context["simulation"] is not True:
        denials.append("context.simulation_flag_missing")
    if context.get("host_mutation") is True and not context["simulation"]:
        if context.get("reversible") is not True and context.get(
                "irreversible_acknowledged") is not True:
            denials.append("safety.rollback_or_ack_missing")

    if resource["kind"] == "process":
        _validate_process_identity(resource, context, denials)
    return denials


def _validate_process_identity(resource: Mapping[str, Any], context: Mapping[str, Any],
                               denials: list[str]) -> None:
    identity = resource.get("identity")
    current = context.get("current_identity")
    required = ("pid", "start_time", "executable")
    if not isinstance(identity, Mapping) or any(field not in identity for field in required):
        denials.append("resource.process_identity_missing")
        return
    if (type(identity["pid"]) is not int or identity["pid"] <= 0 or
            type(identity["start_time"]) not in (int, float) or
            not isinstance(identity["executable"], str) or
            not identity["executable"].strip()):
        denials.append("resource.process_identity_invalid")
        return

    basename = PureWindowsPath(identity["executable"]).name.lower()
    if basename in _PROTECTED_PROCESS_NAMES or context.get("protected_process") is True:
        denials.append("resource.protected_process")

    if not isinstance(current, Mapping) or any(field not in current for field in required):
        denials.append("context.current_process_identity_missing")
        return
    same_pid = current["pid"] == identity["pid"]
    same_start = current["start_time"] == identity["start_time"]
    same_exe = str(current["executable"]).casefold() == identity["executable"].casefold()
    if not (same_pid and same_start and same_exe):
        denials.append("resource.stale_process_identity")


def _diagnostic(code: str, path: str) -> str:
    return f"{_code_fragment(code)}:{_code_fragment(path)}"


def _code_fragment(value: Any) -> str:
    text = _SAFE_CODE.sub("_", str(value).strip().lower()).strip("_")
    return text[:96] or "unnamed"


def self_test() -> tuple[bool, str]:
    """Small dependency-free integrity check for the shadow evaluator."""
    try:
        base = evaluate_shadow(
            {"kind": "assistant", "id": "aria"},
            {"name": "contain", "arguments": {"pid": 7}},
            {"kind": "tool", "id": "contain"},
            {"phase": "simulation", "proposed_at": 1, "expires_at": 2,
             "simulation": True},
        )
        assert base.allowed and len(base.digest) == 64
        staged = evaluate_shadow(
            {"kind": "assistant", "id": "aria"}, {"name": "contain"},
            {"kind": "tool", "id": "contain"},
            {"phase": "preview", "proposed_at": 1, "expires_at": 2,
             "simulation": False},
        )
        assert not staged.allowed and compare_current("STAGE", staged).aligned
        return True, "OK - deterministic shadow evaluation; preview remains non-authoritative."
    except AssertionError as exc:
        return False, f"FAIL - {exc}"
    except Exception as exc:  # pragma: no cover
        return False, f"ERROR - {type(exc).__name__}: {exc}"


if __name__ == "__main__":
    _ok, _detail = self_test()
    print(f"[action_policy] self_test: {'PASS' if _ok else 'FAIL'} - {_detail}")
    raise SystemExit(0 if _ok else 1)
