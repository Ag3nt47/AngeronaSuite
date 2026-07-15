"""core/assistant.py — ARIA's agentic engine (local, gated, defensive-only).

The brain behind the HUD. ARIA keeps a short conversation memory, exposes a
registry of tools, and enforces the project's non-negotiable: **reads run live,
writes are confirm-then-execute**. A read tool (recent alerts, coverage, score,
Cortex status) executes immediately. A write tool (contain, ignore, allow/block,
run a drill, run the improvement loop) returns a *preview* first and only
executes when the operator confirms with the exact token from that preview.

Decoupled by design: tools are plain callables you register, so this file has
no hard dependency on the rest of Angerona and its ``self_test`` runs with mock
providers. Nothing is wired at import; construct an ``Assistant`` and register
tools when you opt in.

    NON-NEGOTIABLES (enforced here):
      • Every write is gated — confirm-then-execute, never auto-run.
      • Defensive-only — the registry ships no offensive tools.
      • Local-first — no network, no model call in this module.
      • Proactive, not autonomous — triggers can *speak*, never *act*.
"""
from __future__ import annotations

import hashlib
import time
import uuid
from collections import deque
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Callable, Optional


class ToolKind(Enum):
    READ = "read"     # observes state; safe to run immediately
    WRITE = "write"   # changes state / takes action; must be confirmed first


@dataclass(frozen=True)
class Tool:
    name: str
    kind: ToolKind
    fn: Callable[..., Any]
    description: str = ""
    # For write tools: a human preview of what *would* happen, given the args.
    preview: Optional[Callable[..., str]] = None
    version: int = 0


@dataclass(frozen=True)
class StagedAction:
    """Immutable snapshot of the exact WRITE action shown to the operator."""
    name: str
    version: int
    kind: ToolKind
    fn: Callable[..., Any]
    args: tuple
    kwargs: tuple
    preview: str
    staged_at: float
    digest: str


@dataclass
class Turn:
    ts: float
    role: str          # "user" | "aria" | "tool" | "system"
    text: str
    meta: dict = field(default_factory=dict)


@dataclass
class Result:
    ok: bool
    text: str
    needs_confirmation: bool = False
    confirm_token: str = ""
    data: Any = None


class Assistant:
    """ARIA's local agentic engine.

    Usage::

        aria = Assistant()
        aria.register("recent_alerts", ToolKind.READ, alerts_provider,
                      "List recent alerts")
        aria.register("contain", ToolKind.WRITE, do_contain,
                      "Isolate a host", preview=lambda pid: f"Isolate PID {pid}")

        r = aria.invoke("contain", pid=1234)     # -> needs_confirmation, token
        aria.confirm(r.confirm_token)            # -> executes
    """

    def __init__(self, *, enabled: bool = False, memory_turns: int = 200) -> None:
        self._enabled = bool(enabled)
        self._tools: dict[str, Tool] = {}
        self._tool_generation = 0
        self._memory: deque[Turn] = deque(maxlen=memory_turns)
        self._pending: dict[str, StagedAction] = {}
        self._triggers: list[tuple[str, Callable[[dict], Optional[str]]]] = []
        self._confirm_ttl = 300.0   # a pending write expires after 5 min

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = bool(value)
        if not self._enabled and hasattr(self, "_pending"):
            self._pending.clear()

    # ── Registration ──────────────────────────────────────────────────────────
    def register(self, name: str, kind: ToolKind, fn: Callable[..., Any],
                 description: str = "", preview: Optional[Callable[..., str]] = None) -> None:
        self._invalidate_pending_for(name)
        self._tool_generation += 1
        self._tools[name] = Tool(name, kind, fn, description, preview,
                                 self._tool_generation)

    def unregister(self, name: str) -> bool:
        self._invalidate_pending_for(name)
        return self._tools.pop(name, None) is not None

    def _invalidate_pending_for(self, name: str) -> None:
        for token, action in list(self._pending.items()):
            if action.name == name:
                self._pending.pop(token, None)

    def register_trigger(self, name: str, predicate: Callable[[dict], Optional[str]]) -> None:
        """A proactive trigger: given a state dict, return a message to surface,
        or None. Triggers may only *speak* — they never invoke write tools."""
        self._triggers.append((name, predicate))

    def tools(self) -> list[str]:
        return sorted(self._tools)

    # ── Memory ────────────────────────────────────────────────────────────────
    def remember(self, role: str, text: str, **meta) -> None:
        self._memory.append(Turn(time.time(), role, text, meta))

    def history(self, n: int = 20) -> list[Turn]:
        return list(self._memory)[-n:]

    # ── Invocation (the gate) ─────────────────────────────────────────────────
    def invoke(self, name: str, *args, **kwargs) -> Result:
        """Run a READ tool immediately; stage a WRITE tool behind confirmation.

        Returns a :class:`Result`. For writes, ``needs_confirmation`` is True and
        ``confirm_token`` must be passed to :meth:`confirm` to actually execute."""
        if not self.enabled:
            return self._say(Result(False, "ARIA is disabled; no tool was invoked."))
        self.remember("user", f"invoke {name}({_fmt_args(args, kwargs)})")
        tool = self._tools.get(name)
        if tool is None:
            return self._say(Result(False, f"No such tool: {name!r}."))

        if tool.kind is ToolKind.READ:
            try:
                data = tool.fn(*args, **kwargs)
                return self._say(Result(True, _summarize(name, data), data=data), role="tool")
            except Exception as exc:
                return self._say(Result(False, f"{name} failed: {exc}"), role="tool")

        # WRITE → stage, do NOT execute yet.
        try:
            frozen_args = tuple(_freeze_value(value) for value in args)
            frozen_kwargs = tuple(sorted(
                ((str(key), _freeze_value(value)) for key, value in kwargs.items()),
                key=lambda item: item[0],
            ))
            call_args = tuple(_thaw_value(value) for value in frozen_args)
            call_kwargs = {key: _thaw_value(value) for key, value in frozen_kwargs}
            preview = (tool.preview(*call_args, **call_kwargs) if tool.preview
                       else f"{name}({_fmt_args(call_args, call_kwargs)})")
        except Exception as exc:
            return self._say(Result(False, f"Could not safely stage {name}: {exc}"))
        token = uuid.uuid4().hex[:8]
        digest = _action_digest(name, tool.version, tool.kind,
                                frozen_args, frozen_kwargs, preview)
        self._pending[token] = StagedAction(
            name=name, version=tool.version, kind=tool.kind, fn=tool.fn,
            args=frozen_args, kwargs=frozen_kwargs, preview=preview,
            staged_at=time.time(), digest=digest,
        )
        msg = (f"⚠ Confirmation required before executing a change.\n"
               f"    Action : {preview}\n"
               f"    Confirm: reply/confirm with token {token}  (expires in {int(self._confirm_ttl)}s)")
        return self._say(Result(True, msg, needs_confirmation=True, confirm_token=token))

    def confirm(self, token: str) -> Result:
        """Execute a previously staged WRITE tool by its confirmation token."""
        if not self.enabled:
            self._pending.clear()
            return self._say(Result(False, "ARIA is disabled; confirmation was refused."))
        staged = self._pending.pop(token, None)
        if staged is None:
            return self._say(Result(False, "Unknown or already-used confirmation token."))
        if time.time() - staged.staged_at > self._confirm_ttl:
            return self._say(Result(False, "Confirmation expired — re-issue the action."))
        tool = self._tools.get(staged.name)
        if tool is None:                       # tool removed between stage & confirm
            return self._say(Result(False, f"Tool {staged.name!r} no longer registered."))
        if (staged.kind is not ToolKind.WRITE or tool.kind is not ToolKind.WRITE or
                tool.version != staged.version or tool.fn is not staged.fn):
            return self._say(Result(False, "The registered action changed; confirmation was revoked."))
        expected = _action_digest(staged.name, staged.version, staged.kind,
                                  staged.args, staged.kwargs, staged.preview)
        if expected != staged.digest:
            return self._say(Result(False, "The staged action failed its integrity check."))
        try:
            args = tuple(_thaw_value(value) for value in staged.args)
            kwargs = {key: _thaw_value(value) for key, value in staged.kwargs}
            data = staged.fn(*args, **kwargs)
            return self._say(Result(True, f"✓ Executed {staged.name}. {_summarize(staged.name, data)}", data=data),
                             role="tool")
        except Exception as exc:
            return self._say(Result(False, f"{staged.name} execution failed: {exc}"), role="tool")

    def cancel(self, token: str) -> bool:
        return self._pending.pop(token, None) is not None

    def pending(self) -> list[str]:
        return list(self._pending)

    # ── Proactivity (speak, never act) ────────────────────────────────────────
    def check_proactive(self, state: dict) -> list[str]:
        """Evaluate triggers against a state snapshot. Returns messages to
        surface on the HUD. Never invokes a tool."""
        if not self.enabled:
            return []
        out: list[str] = []
        for _name, pred in self._triggers:
            try:
                msg = pred(state)
            except Exception:
                msg = None
            if msg:
                out.append(msg)
                self.remember("aria", msg, proactive=True)
        return out

    # ── Internal ──────────────────────────────────────────────────────────────
    def _say(self, result: Result, role: str = "aria") -> Result:
        self.remember(role, result.text)
        return result

    # ── Self-test ─────────────────────────────────────────────────────────────
    def self_test(self) -> tuple[bool, str]:
        """Prove the gate: reads run live; writes stage then execute only on
        confirm; a bad token is refused; memory is retained; proactive triggers
        speak but never act."""
        try:
            calls = {"read": 0, "write": 0}

            def read_alerts():
                calls["read"] += 1
                return [{"sev": "HIGH", "msg": "LSASS access"}]

            def do_contain(pid):
                calls["write"] += 1
                return {"contained": pid}

            a = Assistant(enabled=True)
            a.register("recent_alerts", ToolKind.READ, read_alerts, "recent alerts")
            a.register("contain", ToolKind.WRITE, do_contain, "isolate host",
                       preview=lambda pid: f"Isolate PID {pid} (host-level, reversible)")

            # 1 ── read runs immediately
            r = a.invoke("recent_alerts")
            assert r.ok and calls["read"] == 1 and not r.needs_confirmation, "read runs live"

            # 2 ── write stages, does NOT execute
            w = a.invoke("contain", pid=1234)
            assert w.ok and w.needs_confirmation and w.confirm_token, "write must stage"
            assert calls["write"] == 0, "write must NOT run before confirmation"
            assert "Isolate PID 1234" in w.text, "preview shown"

            # 3 ── wrong token refused, real token executes exactly once
            bad = a.confirm("deadbeef")
            assert not bad.ok and calls["write"] == 0, "bad token refused, still not run"
            good = a.confirm(w.confirm_token)
            assert good.ok and calls["write"] == 1, "confirm executes the write"
            assert a.confirm(w.confirm_token).ok is False, "token is single-use"

            # 4 ── expiry
            e = Assistant(enabled=True)
            e.register("contain", ToolKind.WRITE, do_contain)
            ew = e.invoke("contain", pid=1)
            e._pending[ew.confirm_token] = replace(
                e._pending[ew.confirm_token], staged_at=time.time() - 10_000)
            assert e.confirm(ew.confirm_token).ok is False, "expired confirmation refused"

            # 5 ── memory retained (user + tool + aria turns accumulated)
            assert len(a.history(50)) >= 4, "conversation memory retained"

            # 6 ── proactive speaks but never acts
            a.register_trigger("low_score",
                               lambda s: f"Angerona Score {s['score']} — posture ELEVATED."
                               if s.get("score", 100) < 50 else None)
            spoke = a.check_proactive({"score": 40})
            assert spoke and "40" in spoke[0], "trigger fires under threshold"
            assert a.check_proactive({"score": 95}) == [], "no trigger when healthy"
            assert calls["write"] == 1, "proactive path never invoked a write"

            # 7 ── unknown tool handled
            assert a.invoke("nope").ok is False, "unknown tool refused cleanly"

            # Disabled is a hard gate, including tokens staged before disable.
            disabled_calls = {"read": 0, "write": 0, "proactive": 0}
            d = Assistant(enabled=True)
            d.register("read", ToolKind.READ, lambda: disabled_calls.__setitem__(
                "read", disabled_calls["read"] + 1))
            d.register("write", ToolKind.WRITE, lambda: disabled_calls.__setitem__(
                "write", disabled_calls["write"] + 1))
            d.register_trigger("trigger", lambda _state: disabled_calls.__setitem__(
                "proactive", disabled_calls["proactive"] + 1) or "message")
            staged = d.invoke("write")
            d.enabled = False
            assert not d.invoke("read").ok, "disabled read refused"
            assert not d.invoke("write").ok, "disabled write refused"
            assert not d.confirm(staged.confirm_token).ok, "disabled confirm refused"
            assert d.check_proactive({}) == [], "disabled proactive path silent"
            assert disabled_calls == {"read": 0, "write": 0, "proactive": 0}, \
                "disabled callbacks must never run"
            assert d.pending() == [], "disabling clears pending confirmations"

            return True, ("OK — reads run live; writes stage behind a token and run "
                          "exactly once on confirm; bad/expired/reused tokens refused; "
                          "memory retained; proactive triggers speak (score 40) and stay "
                          "silent when healthy (95) without ever invoking a write.")
        except AssertionError as exc:
            return False, f"FAIL — {exc}"
        except Exception as exc:  # pragma: no cover
            return False, f"ERROR — {type(exc).__name__}: {exc}"


# ── Helpers ────────────────────────────────────────────────────────────────────
def _freeze_value(value: Any) -> tuple:
    """Convert ordinary action arguments into an immutable, replayable form."""
    if value is None:
        return ("none",)
    if type(value) is bool:
        return ("bool", value)
    if type(value) is int:
        return ("int", value)
    if type(value) is float:
        return ("float", value.hex())
    if type(value) is str:
        return ("str", value)
    if type(value) is bytes:
        return ("bytes", value.hex())
    if type(value) is list:
        return ("list", tuple(_freeze_value(item) for item in value))
    if type(value) is tuple:
        return ("tuple", tuple(_freeze_value(item) for item in value))
    if type(value) is dict:
        items = [(_freeze_value(key), _freeze_value(item)) for key, item in value.items()]
        items.sort(key=lambda pair: repr(pair[0]))
        return ("dict", tuple(items))
    if type(value) in (set, frozenset):
        items = sorted((_freeze_value(item) for item in value), key=repr)
        return ("set", tuple(items))
    raise TypeError(f"unsupported confirmation argument type: {type(value).__name__}")


def _thaw_value(value: tuple) -> Any:
    tag = value[0]
    if tag == "none":
        return None
    if tag in ("bool", "int", "str"):
        return value[1]
    if tag == "float":
        return float.fromhex(value[1])
    if tag == "bytes":
        return bytes.fromhex(value[1])
    if tag == "list":
        return [_thaw_value(item) for item in value[1]]
    if tag == "tuple":
        return tuple(_thaw_value(item) for item in value[1])
    if tag == "dict":
        return {_thaw_value(key): _thaw_value(item) for key, item in value[1]}
    if tag == "set":
        return {_thaw_value(item) for item in value[1]}
    raise ValueError("invalid staged argument")


def _action_digest(name: str, version: int, kind: ToolKind, args: tuple,
                   kwargs: tuple, preview: str) -> str:
    payload = repr((name, version, kind.value, args, kwargs, preview)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _fmt_args(args: tuple, kwargs: dict) -> str:
    parts = [repr(a) for a in args] + [f"{k}={v!r}" for k, v in kwargs.items()]
    return ", ".join(parts)


def _summarize(name: str, data: Any) -> str:
    if data is None:
        return f"{name}: done."
    if isinstance(data, (list, tuple)):
        return f"{name}: {len(data)} item(s)."
    if isinstance(data, dict):
        return f"{name}: {', '.join(f'{k}={v}' for k, v in list(data.items())[:4])}"
    return f"{name}: {data}"


# ── Singleton factory ──────────────────────────────────────────────────────────
_ARIA: Optional[Assistant] = None


def init_assistant(*, enabled: bool = False) -> Assistant:
    """Create/replace the shared assistant. Register tools after this. Off by
    default; wired into nothing until you opt in."""
    global _ARIA
    _ARIA = Assistant(enabled=enabled)
    return _ARIA


def get_assistant() -> Assistant:
    global _ARIA
    if _ARIA is None:
        _ARIA = Assistant(enabled=False)
    return _ARIA


if __name__ == "__main__":
    ok, detail = Assistant().self_test()
    print(f"[assistant] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    raise SystemExit(0 if ok else 1)
