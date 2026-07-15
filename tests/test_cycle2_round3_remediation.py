from __future__ import annotations

from unittest.mock import patch
from uuid import UUID

from angerona.core.assistant import Assistant, ToolKind


def test_confirmation_token_collision_never_replaces_a_staged_action() -> None:
    calls: list[tuple[str, str]] = []
    aria = Assistant(enabled=True)
    aria.register(
        "first", ToolKind.WRITE,
        lambda payload: calls.append(("first", payload)),
        preview=lambda payload: f"First {payload}",
    )
    aria.register(
        "second", ToolKind.WRITE,
        lambda payload: calls.append(("second", payload)),
        preview=lambda payload: f"Second {payload}",
    )

    collision = UUID("deadbeef-dead-beef-dead-beefdeadbeef")
    retry = UUID("01234567-89ab-cdef-0123-456789abcdef")
    with patch("angerona.core.assistant.uuid.uuid4",
               side_effect=(collision, collision, retry)):
        first = aria.invoke("first", "reviewed-A")
        second = aria.invoke("second", "different-B")

    assert len(first.confirm_token) == 32 and len(second.confirm_token) == 32
    assert first.confirm_token != second.confirm_token
    assert aria.pending() == [first.confirm_token, second.confirm_token]
    assert aria.confirm(first.confirm_token).ok
    assert calls == [("first", "reviewed-A")]
    assert aria.confirm(second.confirm_token).ok
    assert calls == [("first", "reviewed-A"), ("second", "different-B")]


if __name__ == "__main__":
    test_confirmation_token_collision_never_replaces_a_staged_action()
    print("PASS - confirmation token collision preserves both staged actions")
