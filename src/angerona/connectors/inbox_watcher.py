"""connectors/inbox_watcher.py — background mailbox scanner for ARIA.

Turns the local phishing heuristics in ``inbox_triage`` into a live capability:
a daemon thread that periodically fetches recent mail over read-only IMAP,
scores each message, and emits an alert to the EventBus for anything that isn't
CLEAN (plus lifts vendor CVE advisories into the feed). Opt-in — nothing runs
until a caller constructs a watcher with credentials and calls :meth:`start`.

    HARD SCOPE: read-only. It logs in, SELECTs the folder read-only (never marks
    read / moves / deletes), scores locally, and disconnects. Message bodies are
    scored on-box; nothing is sent anywhere. Credentials come from the caller
    (host/user from settings, password from the .env key ARIA_IMAP_PASS).
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import unicodedata
from collections import OrderedDict
from typing import Callable, Optional

try:  # in-package; falls back to flat layout for the standalone runner
    from angerona.connectors.inbox_triage import InboxTriage, _MAX_MESSAGES
except ImportError:  # pragma: no cover
    from inbox_triage import InboxTriage, _MAX_MESSAGES


# emit(message, severity_name, **details)
Emit = Callable[..., None]
_MAX_SEEN_ALERTS = 2048


def _single_line(value, limit):
    text = str(value or "")[:limit * 4]
    return " ".join("".join(" " if unicodedata.category(char)[0] == "C" else char
                            for char in text).split())[:limit]


class InboxWatcher:
    """Periodic, read-only mailbox phishing scanner.

    Usage::

        w = InboxWatcher(host="imap.gmail.com", user="me@x.com",
                         password=os.environ["ARIA_IMAP_PASS"],
                         interval_s=300, emit=bus_emit)
        w.start()
        ...
        w.stop()

    For tests / a "Test connection" button, pass ``fetch=`` a callable returning
    a list of normalised message dicts (bypassing IMAP entirely)."""

    def __init__(self, *, host: str = "", user: str = "", password: str = "",
                 folder: str = "INBOX", interval_s: float = 300.0, limit: int = 25,
                 emit: Optional[Emit] = None,
                 triage: Optional[InboxTriage] = None,
                 fetch: Optional[Callable[[], list]] = None) -> None:
        self.host = host
        self.user = user
        self._password = password
        self.folder = folder
        self.interval_s = max(30.0, float(interval_s))
        self.limit = int(limit)
        self._emit = emit
        self._triage = triage or InboxTriage()
        self._fetch_fn = fetch
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._scan_lock = threading.Lock()
        # Bounded to this watcher lifetime. It contains delivery identities only,
        # grants no trust, and is retired when the watcher is replaced.
        self._seen: OrderedDict[str, None] = OrderedDict()
        self.last_error: str = ""
        self.last_summary: dict = {}

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    def start(self) -> bool:
        """Begin scanning on a daemon thread. Returns False if already running."""
        if self._thread and self._thread.is_alive():
            return False
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="AriaInboxWatcher", daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        self._stop.set()

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _loop(self) -> None:
        # Scan shortly after start, then every interval; interruptible sleep.
        self._stop.wait(2.0)
        while not self._stop.is_set():
            try:
                self.scan_once()
            except Exception as exc:  # a bad poll must never kill the thread
                self.last_error = str(exc)
            self._stop.wait(self.interval_s)

    # ── One scan ──────────────────────────────────────────────────────────────
    def _fetch(self) -> list:
        if self._fetch_fn is not None:
            return self._fetch_fn()
        if not (self.host and self.user and self._password):
            raise RuntimeError("IMAP host/user/password not configured")
        return self._triage.fetch_recent(self.host, self.user, self._password,
                                          folder=self.folder, limit=self.limit)

    def scan_once(self) -> dict:
        """Score recent mail and deliver each bounded observation once per identity."""
        if not self._scan_lock.acquire(blocking=False):
            raise RuntimeError("An inbox check is already running")
        try:
            messages = self._fetch() or []
            if not isinstance(messages, list) or len(messages) > _MAX_MESSAGES:
                raise ValueError("Inbox response exceeded its message budget")
            scanned = flagged = advisories = incomplete = unverified = emitted = 0
            for m in messages:
                scanned += 1
                try:
                    unverified += int("authentication" in m)
                    if self._triage.is_vendor_advisory(m):
                        advisories += 1
                        emitted += int(self._alert_once(m, "advisory",
                            f"Vendor security advisory: {self._subject(m)}", "LOW"))
                    verdict = self._triage.score_message(m)
                    if verdict.verdict == "INCOMPLETE":
                        incomplete += 1
                        emitted += int(self._alert_once(m, "coverage",
                            f"Inbox content check incomplete: {self._subject(m)}", "LOW",
                            verdict=verdict.verdict, reasons=verdict.reasons))
                    elif verdict.verdict != "CLEAN":
                        flagged += 1
                        emitted += int(self._alert_once(m, "phishing",
                            f"Phishing {verdict.verdict} (score {verdict.score}): {self._subject(m)}",
                            "HIGH", score=verdict.score, verdict=verdict.verdict, reasons=verdict.reasons))
                except Exception as exc:
                    self.last_error = f"scoring failed ({type(exc).__name__})"
            self.last_summary = {"scanned": scanned, "flagged": flagged, "advisories": advisories,
                                 "incomplete": incomplete, "authentication_unverified": unverified,
                                 "emitted": emitted, "ts": time.time()}
            return self.last_summary
        finally:
            self._scan_lock.release()

    def test_connection(self) -> dict:
        """One-shot fetch used by the Settings 'Test' button. Returns
        ``{"ok": bool, "scanned": int, "flagged": int, "error": str}``."""
        try:
            summary = self.scan_once()
            return {"ok": True, **summary, "error": ""}
        except Exception as exc:
            return {"ok": False, "scanned": 0, "flagged": 0, "error": str(exc)}

    # ── Helpers ───────────────────────────────────────────────────────────────
    @staticmethod
    def _subject(m: dict) -> str:
        return _single_line(m.get("subject") or "(no subject)", 120)

    def _alert_identity(self, message, kind):
        native = message.get("message_identity")
        if not isinstance(native, str) or not re.fullmatch(r"[0-9a-f]{64}", native):
            # Injected normalized fetchers retain a deterministic bounded
            # fallback. The live IMAP adapter supplies UID/UIDVALIDITY/raw bytes.
            snapshot = {key: _single_line(message.get(key), 512)
                        for key in ("from", "reply_to", "subject")}
            snapshot["body"] = str(message.get("body") or "")[:64 * 1024]
            snapshot["attachments"] = [_single_line(value, 256)
                                       for value in (message.get("attachments") or [])[:128]]
            snapshot["urls"] = [[_single_line(value, 2048) for value in row[:2]]
                                for row in (message.get("urls") or [])[:128]]
            snapshot["coverage"] = _single_line((message.get("coverage") or {}).get("reason"), 256)
            native = hashlib.sha256(json.dumps(snapshot, sort_keys=True, ensure_ascii=True).encode()).hexdigest()
        scope = [_single_line(self.host, 512).casefold(), _single_line(self.user, 512),
                 _single_line(self.folder, 512), kind, native]
        return hashlib.sha256(json.dumps(scope, ensure_ascii=True).encode()).hexdigest()

    def _alert_once(self, message, kind, text, severity, **details):
        key = self._alert_identity(message, kind)
        if key in self._seen:
            self._seen.move_to_end(key)
            return False
        details.update(kind=kind, sender=_single_line(message.get("from"), 512))
        if "reasons" in details:
            details["reasons"] = [_single_line(value, 240) for value in details["reasons"][:32]]
        if not self._alert(text, severity, **details):
            return False
        self._seen[key] = None
        if len(self._seen) > _MAX_SEEN_ALERTS:
            self._seen.popitem(last=False)
        return True

    def _alert(self, message: str, severity: str, **details) -> bool:
        if self._emit is not None:
            try:
                # Mail content is an observation, regardless of heuristic score.
                # It cannot establish a local active breach or a response token.
                details.update(disposition="observation", observation_only=True,
                               active_attack=False, active_exploitation=False, response_authorized=False)
                return self._emit(_single_line(message, 512),
                                  "LOW" if severity == "LOW" else "HIGH", **details) is not False
            except Exception:
                self.last_error = "Inbox observation publication unavailable"
        return False

    # ── Self-test ─────────────────────────────────────────────────────────────
    def self_test(self) -> tuple[bool, str]:
        """Prove a phish + advisory are flagged and a clean message isn't, with
        alerts emitted at the right severities — no real mailbox required."""
        try:
            phish = {
                "from": "IT <security@paypa1-support.com>", "reply_to": "harvest@evil.ru",
                "subject": "URGENT: verify your password now",
                "body": "confirm your account credentials immediately or it is suspended.",
                "urls": [("http://secure-login.paypa1-support.com/x", "paypal.com")],
                "auth": {"spf": "fail", "dkim": "none", "dmarc": "fail"},
                "attachments": ["invoice.exe"],
            }
            clean = {"from": "dana@ourcompany.com", "reply_to": "dana@ourcompany.com",
                     "subject": "lunch?", "body": "grab lunch at noon?",
                     "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"}}
            advisory = {"from": "psirt@vendor.com",
                        "subject": "Security Advisory CVE-2026-1234 patch available",
                        "body": "A vulnerability was fixed.",
                        "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"}}

            emitted: list = []
            w = InboxWatcher(emit=lambda msg, sev, **d: emitted.append((sev, msg, d)),
                             fetch=lambda: [phish, clean, advisory])
            summary = w.scan_once()
            assert summary["scanned"] == 3, "scanned all three"
            assert summary["flagged"] == 1, "exactly the phish is flagged"
            assert summary["advisories"] == 1, "the CVE advisory is detected"

            sevs = [e[0] for e in emitted]
            assert "HIGH" in sevs and "CRITICAL" not in sevs, "phish remains a HIGH observation"
            assert "LOW" in sevs, "advisory emits LOW"
            crit = next(e for e in emitted if e[0] == "HIGH")
            assert crit[2].get("verdict") == "PHISH_LIKELY" and crit[2].get("reasons"), "rich phishing detail"
            assert crit[2].get("disposition") == "observation" and crit[2].get("active_attack") is False
            assert crit[2].get("response_authorized") is False
            assert w.scan_once()["emitted"] == 0, "repeat poll does not republish the same mail"

            # test_connection surfaces a clean error when nothing is configured
            bad = InboxWatcher().test_connection()
            assert bad["ok"] is False and "not configured" in bad["error"], "unconfigured → clean error"

            return True, ("OK — inert inputs produced 1 HIGH phishing observation and 1 LOW advisory, "
                          "with no active-response authority or repeated-poll delivery; "
                          "low-score input stayed quiet. Real mailbox authenticity is not verified by this fixture.")
        except AssertionError as exc:
            return False, f"FAIL — {exc}"
        except Exception as exc:  # pragma: no cover
            return False, f"ERROR — {type(exc).__name__}: {exc}"


if __name__ == "__main__":
    ok, detail = InboxWatcher().self_test()
    print(f"[inbox_watcher] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    raise SystemExit(0 if ok else 1)
