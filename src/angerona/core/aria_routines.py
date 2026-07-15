"""core/aria_routines.py — ARIA scheduled routines ("run it before you wake up").

A small registry of recurring routines ARIA can run on a schedule: a nightly
briefing, a weekly red-team drill reminder, a daily ATT&CK-coverage check. Each
routine is a pure function of an injected context dict, so it composes its report
text locally with no side effects — the *scheduling* is delegated to Angerona's
existing scheduler / the Cowork schedule tool via the suggested cron strings.

Local, additive, and side-effect-free by construction: a routine only returns
text. Whether that text is spoken (voice), pushed (channel_push), or shown on the
HUD is the caller's choice, and any *action* a routine recommends still flows
through the assistant's confirm-then-execute gate.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional


# A routine: (name) -> composes a report string from a context dict.
RoutineFn = Callable[[dict], str]


@dataclass
class Routine:
    name: str
    cron: str            # suggested schedule (standard 5-field cron)
    fn: RoutineFn
    description: str = ""


def _get(ctx: dict, key: str, default="n/a"):
    """Read a context value; if it's a callable, call it (lazy providers)."""
    v = ctx.get(key, default)
    try:
        return v() if callable(v) else v
    except Exception as exc:
        return f"<error: {exc}>"


# ── Built-in routines ─────────────────────────────────────────────────────────
def nightly_briefing(ctx: dict) -> str:
    score = _get(ctx, "score")
    delta = _get(ctx, "score_delta", 0)
    arrow = f" ({'+' if isinstance(delta, int) and delta > 0 else ''}{delta})" if delta not in (0, "n/a") else ""
    alerts = _get(ctx, "active_alerts", 0)
    crits = _get(ctx, "criticals_24h", 0)
    coverage = _get(ctx, "coverage")
    return ("🌙 Angerona nightly briefing\n"
            f"• Angerona Score: {score}{arrow}\n"
            f"• Active alerts: {alerts}  (criticals last 24h: {crits})\n"
            f"• ATT&CK coverage: {coverage}\n"
            f"• Posture: {_get(ctx, 'posture', 'nominal')}")


def weekly_redteam_drill(ctx: dict) -> str:
    last = _get(ctx, "last_drill", "never")
    return ("🗡 Weekly red-team drill\n"
            f"• Last drill: {last}\n"
            "• Suggested: run the Shark/RedTeam simulation, then review the AAR.\n"
            "• ARIA can dispatch it — confirm to execute (never auto-runs).")


def daily_coverage_check(ctx: dict) -> str:
    coverage = _get(ctx, "coverage")
    gaps = _get(ctx, "coverage_gaps", [])
    gap_txt = ", ".join(gaps) if isinstance(gaps, (list, tuple)) and gaps else "none flagged"
    return ("🎯 Daily ATT&CK coverage check\n"
            f"• Coverage: {coverage}\n"
            f"• Uncovered techniques: {gap_txt}")


class Routines:
    """Registry + runner for ARIA's scheduled routines."""

    def __init__(self) -> None:
        self._routines: dict[str, Routine] = {}
        # register built-ins with sensible default cadences
        self.register("nightly_briefing", "0 7 * * *", nightly_briefing,
                      "Score, alerts, coverage and posture each morning")
        self.register("weekly_redteam_drill", "0 3 * * 1", weekly_redteam_drill,
                      "Monday red-team drill reminder (dispatch is gated)")
        self.register("daily_coverage_check", "0 8 * * *", daily_coverage_check,
                      "Daily ATT&CK coverage + gaps")

    def register(self, name: str, cron: str, fn: RoutineFn, description: str = "") -> None:
        self._routines[name] = Routine(name, cron, fn, description)

    def list(self) -> list[str]:
        return sorted(self._routines)

    def cron(self, name: str) -> str:
        r = self._routines.get(name)
        return r.cron if r else ""

    def describe(self) -> list[dict]:
        return [{"name": r.name, "cron": r.cron, "description": r.description}
                for r in sorted(self._routines.values(), key=lambda x: x.name)]

    def run(self, name: str, ctx: Optional[dict] = None) -> str:
        r = self._routines.get(name)
        if r is None:
            return f"No such routine: {name!r}. Known: {', '.join(self.list())}."
        try:
            return r.fn(ctx or {})
        except Exception as exc:  # a routine must never crash the scheduler
            return f"Routine {name!r} errored: {exc}"

    # ── Self-test ─────────────────────────────────────────────────────────────
    def self_test(self) -> tuple[bool, str]:
        """Prove built-ins are registered with cron cadences, the briefing
        composes from context (including lazy callable providers), custom
        routines register/run, and an unknown routine fails gracefully."""
        try:
            r = Routines()
            for name in ("nightly_briefing", "weekly_redteam_drill", "daily_coverage_check"):
                assert name in r.list(), f"{name} registered"
                assert r.cron(name).count(" ") == 4, f"{name} has a 5-field cron"

            ctx = {"score": 82, "score_delta": 5, "active_alerts": 2,
                   "criticals_24h": 1, "coverage": "15/18", "posture": "GUARDED"}
            brief = r.run("nightly_briefing", ctx)
            assert "82 (+5)" in brief and "Active alerts: 2" in brief and "15/18" in brief, "briefing composed"

            # lazy provider: score supplied as a callable
            lazy = r.run("nightly_briefing", {"score": lambda: 90, "score_delta": 0})
            assert "Angerona Score: 90" in lazy, "callable provider resolved"

            # coverage gaps formatting
            cov = r.run("daily_coverage_check", {"coverage": "15/18", "coverage_gaps": ["T1218", "T1490"]})
            assert "T1218, T1490" in cov, "gaps listed"

            # custom routine register + run
            r.register("hello", "0 9 * * *", lambda c: f"hi {c.get('name', '')}".strip())
            assert r.run("hello", {"name": "luke"}) == "hi luke", "custom routine runs"
            assert r.cron("hello") == "0 9 * * *", "custom cron stored"

            # unknown routine → graceful
            assert "No such routine" in r.run("does_not_exist"), "unknown routine handled"

            return True, ("OK — 3 built-ins registered with 5-field crons; nightly "
                          "briefing composes score+delta/alerts/coverage; lazy callable "
                          "score resolves to 90; coverage gaps listed; custom routine "
                          "registers/runs; unknown routine fails gracefully.")
        except AssertionError as exc:
            return False, f"FAIL — {exc}"
        except Exception as exc:  # pragma: no cover
            return False, f"ERROR — {type(exc).__name__}: {exc}"


# ── Singleton factory ──────────────────────────────────────────────────────────
_ROUTINES: Optional[Routines] = None


def get_routines() -> Routines:
    global _ROUTINES
    if _ROUTINES is None:
        _ROUTINES = Routines()
    return _ROUTINES


if __name__ == "__main__":
    ok, detail = Routines().self_test()
    print(f"[aria_routines] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    raise SystemExit(0 if ok else 1)
