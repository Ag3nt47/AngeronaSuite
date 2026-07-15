"""core/aria_dispatch.py — expose the 6-agent improvement loop to ARIA.

Angerona already has the team: the six-agent improvement loop plus the
adversarial/verification subagents (red-team, verifier, threat-research). This
module lets ARIA *dispatch* them by voice or chat — "run the loop", "have
red-team check X", "verify that claim" — while keeping every dispatch behind the
assistant's confirm-then-execute gate. It runs nothing itself: it wraps an
injected ``runner(agent, task) -> str`` (your existing agent invoker) and
registers the dispatch actions as WRITE tools on the assistant.

    HARD SCOPE: orchestration only, and gated. Dispatch is a WRITE action, so
    it previews and waits for confirmation before running. The red-team agent
    surfaces weaknesses only — it never produces offensive tooling (that
    constraint lives in the agent itself; ARIA just calls it).
"""
from __future__ import annotations

from typing import Callable, Optional

try:  # in-package import; falls back to flat layout for the standalone runner
    from angerona.core.assistant import Assistant, ToolKind
except ImportError:  # pragma: no cover
    from assistant import Assistant, ToolKind


# The six-agent improvement loop, in execution order.
LOOP_AGENTS = ("cortex", "copilot", "red-team", "verifier", "threat-research", "scribe")

# agent runner: (agent_name, task) -> result text
Runner = Callable[[str, str], str]


class Dispatch:
    """Wraps the agent runner and drives the loop / single-agent calls."""

    def __init__(self, runner: Runner) -> None:
        self._run = runner

    def agent(self, name: str, task: str) -> str:
        return self._run(name, task)

    def run_loop(self, task: str) -> dict:
        """Run the full six-agent improvement loop over ``task``, in order."""
        results = {a: self._run(a, task) for a in LOOP_AGENTS}
        return {"task": task, "agents": list(results), "results": results}

    # ── Self-test ─────────────────────────────────────────────────────────────
    def self_test(self) -> tuple[bool, str]:
        """Prove the loop and single-agent dispatch are registered as gated WRITE
        tools: nothing runs until confirmed, then the loop runs all six agents in
        order and single-agent calls hit exactly the named agent."""
        try:
            calls: list = []
            disp = Dispatch(lambda a, t: (calls.append((a, t)), f"{a}:ok")[1])
            aria = Assistant(enabled=True)
            register_dispatch_tools(aria, disp)

            # loop is a WRITE tool → staged, not run
            r = aria.invoke("run_loop", task="improve LSASS detection")
            assert r.needs_confirmation and not calls, "loop dispatch must be gated"
            good = aria.confirm(r.confirm_token)
            assert good.ok and len(calls) == len(LOOP_AGENTS), "loop runs all six agents on confirm"
            agents = [a for a, _ in calls]
            assert agents == list(LOOP_AGENTS), "agents run in loop order"
            assert "red-team" in agents and "verifier" in agents, "adversarial + verify present"
            assert all(t == "improve LSASS detection" for _, t in calls), "task threaded to every agent"

            # single-agent dispatch is also gated
            calls.clear()
            r2 = aria.invoke("red_team_check", target="new ETW sensor")
            assert r2.needs_confirmation and not calls, "single-agent dispatch gated"
            aria.confirm(r2.confirm_token)
            assert calls == [("red-team", "new ETW sensor")], "red-team dispatched exactly once on confirm"

            calls.clear()
            aria.confirm(aria.invoke("verify", claim="coverage is 15/18").confirm_token)
            assert calls == [("verifier", "coverage is 15/18")], "verify → verifier agent"

            return True, ("OK — run_loop and single-agent tools register as gated WRITE "
                          "actions; nothing runs pre-confirm; the loop runs all six agents "
                          "(cortex→…→scribe) in order with the task threaded through; "
                          "red_team_check → red-team, verify → verifier, each once on confirm.")
        except AssertionError as exc:
            return False, f"FAIL — {exc}"
        except Exception as exc:  # pragma: no cover
            return False, f"ERROR — {type(exc).__name__}: {exc}"


def register_dispatch_tools(aria: Assistant, dispatch: Dispatch) -> None:
    """Register the dispatch actions as gated WRITE tools on the assistant."""
    aria.register(
        "run_loop", ToolKind.WRITE,
        lambda task="": dispatch.run_loop(task),
        "run the 6-agent improvement loop",
        preview=lambda task="": f"Dispatch the 6-agent loop ({', '.join(LOOP_AGENTS)}) on: {task!r}",
    )
    aria.register(
        "red_team_check", ToolKind.WRITE,
        lambda target="": dispatch.agent("red-team", target),
        "have red-team probe a target for weaknesses (defensive; no offensive output)",
        preview=lambda target="": f"Dispatch red-team to probe: {target!r}",
    )
    aria.register(
        "verify", ToolKind.WRITE,
        lambda claim="": dispatch.agent("verifier", claim),
        "have the verifier audit a claim before it's trusted",
        preview=lambda claim="": f"Dispatch verifier to audit: {claim!r}",
    )
    aria.register(
        "threat_research", ToolKind.WRITE,
        lambda query="": dispatch.agent("threat-research", query),
        "task threat-research with a question",
        preview=lambda query="": f"Dispatch threat-research on: {query!r}",
    )


# ── Singleton factory ──────────────────────────────────────────────────────────
_DISPATCH: Optional[Dispatch] = None


def init_dispatch(runner: Runner) -> Dispatch:
    global _DISPATCH
    _DISPATCH = Dispatch(runner)
    return _DISPATCH


def get_dispatch() -> Optional[Dispatch]:
    return _DISPATCH


if __name__ == "__main__":
    ok, detail = Dispatch(lambda a, t: f"{a}:ok").self_test()
    print(f"[aria_dispatch] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    raise SystemExit(0 if ok else 1)
