from __future__ import annotations

from angerona.core.action_policy import compare_current, evaluate_shadow
from angerona.core.assistant import Assistant, ToolKind


def _base_request():
    return (
        {"kind": "assistant", "id": "aria"},
        {"name": "contain", "arguments": {"pid": 4321, "mode": "suspend"}},
        {"kind": "tool", "id": "contain"},
        {"phase": "simulation", "proposed_at": 100.0, "expires_at": 130.0,
         "simulation": True},
    )


def _process_request(executable: str = r"C:\Apps\sample.exe"):
    identity = {"pid": 4321, "start_time": 77.5, "executable": executable}
    return (
        {"kind": "module", "id": "soar"},
        {"name": "suspend", "arguments": {"pid": 4321}},
        {"kind": "process", "id": "pid:4321", "identity": identity},
        {"phase": "corroborated", "proposed_at": 100.0, "expires_at": 130.0,
         "simulation": False, "host_mutation": True, "reversible": True,
         "evidence_count": 2, "current_identity": dict(identity)},
    )


def test_digest_is_stable_across_mapping_order() -> None:
    principal, action, resource, context = _base_request()
    first = evaluate_shadow(principal, action, resource, context)
    second = evaluate_shadow(
        {"id": "aria", "kind": "assistant"},
        {"arguments": {"mode": "suspend", "pid": 4321}, "name": "contain"},
        {"id": "contain", "kind": "tool"},
        {"simulation": True, "expires_at": 130.0, "proposed_at": 100.0,
         "phase": "simulation"},
    )
    assert first.allowed and second.allowed and first.digest == second.digest


def test_argument_mutation_changes_digest_and_fails_binding() -> None:
    principal, action, resource, context = _base_request()
    original = evaluate_shadow(principal, action, resource, context)
    action["arguments"]["mode"] = "terminate"
    changed = evaluate_shadow(
        principal, action, resource, context, expected_digest=original.digest)
    assert not changed.allowed
    assert "binding.digest_mismatch" in changed.diagnostics
    assert changed.digest != original.digest


def test_stale_pid_identity_is_shadow_denied() -> None:
    principal, action, resource, context = _process_request()
    context["current_identity"]["start_time"] = 88.0
    result = evaluate_shadow(principal, action, resource, context)
    assert not result.allowed
    assert "resource.stale_process_identity" in result.diagnostics


def test_missing_context_is_shadow_denied_without_exception() -> None:
    principal, action, resource, _context = _base_request()
    result = evaluate_shadow(principal, action, resource, {})
    assert not result.allowed and len(result.digest) == 64
    assert any(item.startswith("input.missing:") for item in result.diagnostics)


def test_policy_exception_is_shadow_denied_without_escaping() -> None:
    principal, action, resource, context = _base_request()

    def broken_policy(_request):
        raise RuntimeError("must stay inside the shadow")

    result = evaluate_shadow(
        principal, action, resource, context,
        policies=(("broken test policy", broken_policy),),
    )
    assert not result.allowed
    assert "policy.broken_test_policy.error" in result.diagnostics


def test_protected_process_is_shadow_denied() -> None:
    request = _process_request(r"C:\Windows\System32\lsass.exe")
    result = evaluate_shadow(*request)
    assert not result.allowed
    assert "resource.protected_process" in result.diagnostics


def test_aria_preview_audit_is_bounded_shadow_data_and_does_not_execute() -> None:
    calls: list[int] = []
    aria = Assistant(enabled=True, memory_turns=8)
    aria.register("contain", ToolKind.WRITE, lambda pid: calls.append(pid),
                  preview=lambda pid: f"Suspend PID {pid}")
    staged = aria.invoke("contain", 4321)
    assert staged.ok and staged.needs_confirmation and calls == []
    audits = [turn.meta for turn in aria.history(8) if turn.meta.get("shadow_only")]
    assert len(audits) == 1
    audit = audits[0]
    assert audit["current_decision"] == "STAGE"
    assert audit["shadow_decision"] == "DENY"
    assert audit["aligned"] is True and len(audit["digest"]) == 64
    assert "4321" not in repr(audit), "audit metadata must contain no raw arguments"
    assert compare_current("STAGE", evaluate_shadow(
        {"kind": "assistant", "id": "aria"}, {"name": "contain"},
        {"kind": "tool", "id": "contain"},
        {"phase": "preview", "proposed_at": 1, "expires_at": 2,
         "simulation": False},
    )).aligned


if __name__ == "__main__":
    tests = [
        test_digest_is_stable_across_mapping_order,
        test_argument_mutation_changes_digest_and_fails_binding,
        test_stale_pid_identity_is_shadow_denied,
        test_missing_context_is_shadow_denied_without_exception,
        test_policy_exception_is_shadow_denied_without_escaping,
        test_protected_process_is_shadow_denied,
        test_aria_preview_audit_is_bounded_shadow_data_and_does_not_execute,
    ]
    for test in tests:
        test()
        print(f"PASS - {test.__name__}")
