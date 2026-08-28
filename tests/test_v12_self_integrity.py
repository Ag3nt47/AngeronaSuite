from __future__ import annotations

from angerona.modules.self_integrity import _fingerprint


def test_fingerprint_detects_constants_only_code_patch() -> None:
    def decision() -> str:
        return "allow"

    before = _fingerprint(decision)
    constants = tuple("deny" if value == "allow" else value for value in decision.__code__.co_consts)
    decision.__code__ = decision.__code__.replace(co_consts=constants)

    assert decision() == "deny"
    assert _fingerprint(decision) != before


def test_fingerprint_detects_referenced_global_name_patch() -> None:
    namespace = {"allow": lambda: True, "deny": lambda: False}
    exec("def decision():\n    return allow()\n", namespace)
    decision = namespace["decision"]
    before = _fingerprint(decision)
    names = tuple("deny" if value == "allow" else value for value in decision.__code__.co_names)
    decision.__code__ = decision.__code__.replace(co_names=names)

    assert decision() is False
    assert _fingerprint(decision) != before


def test_fingerprint_detects_defaults_and_closure_changes() -> None:
    def with_default(verdict: str = "allow") -> str:
        return verdict

    default_before = _fingerprint(with_default)
    with_default.__defaults__ = ("deny",)
    assert _fingerprint(with_default) != default_before

    def make_decision():
        verdict = "allow"

        def decision() -> str:
            return verdict

        return decision

    closed = make_decision()
    closure_before = _fingerprint(closed)
    replacement = (lambda value: lambda: value)("deny").__closure__[0]
    closed.__closure__[0].cell_contents = replacement.cell_contents
    assert closed() == "deny"
    assert _fingerprint(closed) != closure_before
