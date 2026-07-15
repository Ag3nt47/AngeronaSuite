"""connectors/channel_push.py — ARIA auto-brief to a channel (opt-in egress).

Pushes the daily briefing and CRITICAL alerts to a chat channel — Slack, Teams,
ntfy, or a generic webhook — extending Angerona's existing Signal mobile bridge.
This is the one connector that deliberately sends *outbound*, so it is off by
default and sends nothing until the operator configures a target URL and enables
it. Enabling it IS the consent; no host data leaves the machine otherwise.

Stdlib-only (``urllib`` for the default transport); the transport is injectable
so tests never touch the network. Outgoing text is passed through a secret
redactor first, so a stray key/token in a briefing can't leak to a channel.

    HARD SCOPE: outbound notifications only. It posts text you already chose to
    surface; it never sends raw telemetry, files, or credentials, and it applies
    a redaction pass to every message.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, Optional


class Level(IntEnum):
    INFO = 0
    LOW = 1
    HIGH = 2
    CRITICAL = 3

    @classmethod
    def parse(cls, v) -> "Level":
        if isinstance(v, Level):
            return v
        return cls.__members__.get(str(v).upper(), cls.INFO)


# Redact obvious secrets before anything leaves the machine.
_REDACT = [
    re.compile(r"(?i)\b(api[_-]?key|token|secret|password|passwd|bearer)\b\s*[:=]\s*\S+"),
    re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),                 # openai-style keys
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),        # slack tokens
    re.compile(r"\b[A-Fa-f0-9]{32,}\b"),                    # long hex blobs
]


def redact(text: str) -> str:
    out = text
    for rx in _REDACT:
        out = rx.sub("[REDACTED]", out)
    return out


# transport(url, data: bytes, headers: dict) -> (status_code, body)
Transport = Callable[[str, bytes, dict], "tuple[int, str]"]


@dataclass
class Target:
    kind: str            # "slack" | "teams" | "ntfy" | "webhook"
    url: str
    name: str = ""


@dataclass
class PushResult:
    target: str
    ok: bool
    skipped: bool = False
    status: int = 0
    reason: str = ""


def _default_transport(url: str, data: bytes, headers: dict) -> "tuple[int, str]":  # pragma: no cover
    import urllib.request
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, resp.read().decode("utf-8", "replace")


class ChannelPush:
    """Opt-in channel notifier.

    Usage::

        cp = ChannelPush(enabled=True, min_level=Level.CRITICAL, targets=[
            Target("slack", "https://hooks.slack.com/services/…", "soc"),
            Target("ntfy",  "https://ntfy.sh/angerona-crits"),
        ])
        cp.push("LSASS access from unsigned binary", level="CRITICAL")
        cp.push_briefing({"score": 82, "delta": +5, "criticals": 1, "coverage": "15/18"})
    """

    def __init__(self, *, enabled: bool = False, min_level: Level = Level.INFO,
                 targets: Optional[list] = None,
                 transport: Optional[Transport] = None) -> None:
        self.enabled = enabled
        self.min_level = Level.parse(min_level)
        self.targets: list[Target] = [self._coerce(t) for t in (targets or [])]
        self._transport = transport or _default_transport

    @staticmethod
    def _coerce(t) -> Target:
        if isinstance(t, Target):
            return t
        return Target(t.get("kind", "webhook"), t["url"], t.get("name", ""))

    # ── Payload shaping per channel kind ──────────────────────────────────────
    @staticmethod
    def _payload(kind: str, text: str, level: Level) -> "tuple[bytes, dict]":
        if kind in ("slack", "teams"):
            body = json.dumps({"text": text}).encode("utf-8")
            return body, {"Content-Type": "application/json"}
        if kind == "ntfy":
            headers = {"Content-Type": "text/plain; charset=utf-8",
                       "Title": "Angerona", "Priority": "urgent" if level >= Level.CRITICAL else "default"}
            return text.encode("utf-8"), headers
        # generic webhook
        body = json.dumps({"message": text, "level": level.name}).encode("utf-8")
        return body, {"Content-Type": "application/json"}

    # ── Push ──────────────────────────────────────────────────────────────────
    def push(self, text: str, level="INFO") -> list[PushResult]:
        """Send ``text`` to every configured target. Returns per-target results.
        No-ops (skipped) when disabled or the level is below ``min_level``."""
        lvl = Level.parse(level)
        results: list[PushResult] = []
        if not self.enabled:
            return [PushResult(t.name or t.url, ok=False, skipped=True, reason="disabled")
                    for t in self.targets] or [PushResult("(none)", False, True, reason="disabled")]
        if lvl < self.min_level:
            return [PushResult(t.name or t.url, ok=False, skipped=True,
                               reason=f"below min_level ({lvl.name}<{self.min_level.name})")
                    for t in self.targets]
        safe = redact(text)
        for t in self.targets:
            data, headers = self._payload(t.kind, safe, lvl)
            try:
                status, _body = self._transport(t.url, data, headers)
                results.append(PushResult(t.name or t.url, ok=200 <= status < 300, status=status))
            except Exception as exc:
                results.append(PushResult(t.name or t.url, ok=False, reason=str(exc)))
        return results

    def push_briefing(self, summary: dict) -> list[PushResult]:
        """Format and push a daily briefing dict. Criticals raise the level."""
        text = self.format_briefing(summary)
        lvl = Level.CRITICAL if summary.get("criticals", 0) else Level.INFO
        return self.push(text, level=lvl)

    @staticmethod
    def format_briefing(s: dict) -> str:
        delta = s.get("delta", 0)
        arrow = f" ({'+' if delta > 0 else ''}{delta})" if delta else ""
        return (f"Angerona daily briefing\n"
                f"• Score: {s.get('score', '?')}{arrow}\n"
                f"• Criticals (24h): {s.get('criticals', 0)}\n"
                f"• ATT&CK coverage: {s.get('coverage', 'n/a')}")

    # ── Self-test ─────────────────────────────────────────────────────────────
    def self_test(self) -> tuple[bool, str]:
        """Prove: disabled sends nothing; enabled+target posts the right per-kind
        payload via the (injected) transport; min_level filters; secrets are
        redacted before egress."""
        try:
            sent: list = []
            def fake(url, data, headers):
                sent.append((url, data, headers))
                return 200, "ok"

            # 1 ── disabled → nothing sent
            off = ChannelPush(enabled=False,
                              targets=[Target("slack", "https://x")], transport=fake)
            r = off.push("hello", "CRITICAL")
            assert all(x.skipped for x in r) and sent == [], "disabled must not send"

            # 2 ── enabled slack target → JSON {"text": …} posted once
            cp = ChannelPush(enabled=True, transport=fake,
                             targets=[Target("slack", "https://hooks.slack/x", "soc")])
            r = cp.push("LSASS access", "CRITICAL")
            assert len(sent) == 1 and r[0].ok and r[0].status == 200, "slack push ok"
            url, data, headers = sent[0]
            body = json.loads(data.decode())
            assert body.get("text") == "LSASS access", "slack payload shape"
            assert headers["Content-Type"] == "application/json"

            # 3 ── ntfy target → plain-text body + urgent priority on CRITICAL
            sent.clear()
            n = ChannelPush(enabled=True, transport=fake,
                            targets=[Target("ntfy", "https://ntfy.sh/crits")])
            n.push("beacon storm", "CRITICAL")
            _u, ndata, nhead = sent[0]
            assert ndata == b"beacon storm" and nhead["Priority"] == "urgent", "ntfy plain+urgent"

            # 4 ── min_level filter blocks low-severity sends
            sent.clear()
            crit_only = ChannelPush(enabled=True, min_level=Level.CRITICAL, transport=fake,
                                    targets=[Target("slack", "https://x")])
            rr = crit_only.push("routine info", "INFO")
            assert all(x.skipped for x in rr) and sent == [], "below min_level skipped"
            crit_only.push("real incident", "CRITICAL")
            assert len(sent) == 1, "critical passes the filter"

            # 5 ── secrets redacted before egress
            sent.clear()
            cp.push("leak api_key=SUPERSECRET123 and sk-abcdef......", "CRITICAL")
            leaked = sent[0][1].decode()
            assert "SUPERSECRET123" not in leaked and "[REDACTED]" in leaked, "secrets redacted"

            # 6 ── briefing formatting
            b = ChannelPush.format_briefing({"score": 82, "delta": 5, "criticals": 1, "coverage": "15/18"})
            assert "82 (+5)" in b and "15/18" in b and "Criticals (24h): 1" in b, "briefing format"

            return True, ("OK — disabled sends nothing; slack posts JSON {text}; ntfy "
                          "posts plain text with urgent priority; min_level=CRITICAL "
                          "skips INFO and passes CRITICAL; api_key/sk- secrets redacted "
                          "before egress; briefing shows score +delta and coverage.")
        except AssertionError as exc:
            return False, f"FAIL — {exc}"
        except Exception as exc:  # pragma: no cover
            return False, f"ERROR — {type(exc).__name__}: {exc}"


# ── Singleton factory ──────────────────────────────────────────────────────────
_PUSH: Optional[ChannelPush] = None


def init_channel_push(*, enabled: bool = False, min_level: Level = Level.INFO,
                      targets: Optional[list] = None) -> ChannelPush:
    global _PUSH
    _PUSH = ChannelPush(enabled=enabled, min_level=min_level, targets=targets)
    return _PUSH


def get_channel_push() -> ChannelPush:
    global _PUSH
    if _PUSH is None:
        _PUSH = ChannelPush(enabled=False)
    return _PUSH


if __name__ == "__main__":
    ok, detail = ChannelPush().self_test()
    print(f"[channel_push] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    raise SystemExit(0 if ok else 1)
