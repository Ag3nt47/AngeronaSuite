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

import threading
import time
from typing import Callable, Optional

try:  # in-package; falls back to flat layout for the standalone runner
    from angerona.connectors.inbox_triage import InboxTriage
except ImportError:  # pragma: no cover
    from inbox_triage import InboxTriage


# emit(message, severity_name, **details)
Emit = Callable[..., None]


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
        """Fetch + score once. Emits an alert per non-CLEAN message and per CVE
        advisory. Returns a summary dict."""
        messages = self._fetch() or []
        scanned = flagged = advisories = 0
        for m in messages:
            scanned += 1
            try:
                if self._triage.is_vendor_advisory(m):
                    advisories += 1
                    self._alert(f"Vendor security advisory: {self._subject(m)}",
                                "LOW", kind="advisory", sender=m.get("from", ""))
                v = self._triage.score_message(m)
                if v.verdict != "CLEAN":
                    flagged += 1
                    sev = "CRITICAL" if v.verdict == "PHISH_LIKELY" else "HIGH"
                    self._alert(
                        f"Phishing {v.verdict} (score {v.score}): {self._subject(m)}",
                        sev, kind="phishing", score=v.score, verdict=v.verdict,
                        reasons=v.reasons, sender=m.get("from", ""))
            except Exception as exc:
                self.last_error = f"scoring failed: {exc}"
        self.last_summary = {"scanned": scanned, "flagged": flagged,
                             "advisories": advisories, "ts": time.time()}
        return self.last_summary

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
        return str(m.get("subject", "") or "(no subject)")[:120]

    def _alert(self, message: str, severity: str, **details) -> None:
        if self._emit is not None:
            try:
                self._emit(message, severity, **details)
            except Exception:
                pass

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
            assert "CRITICAL" in sevs, "phish emits CRITICAL"
            assert "LOW" in sevs, "advisory emits LOW"
            crit = next(e for e in emitted if e[0] == "CRITICAL")
            assert crit[2].get("verdict") == "PHISH_LIKELY" and crit[2].get("reasons"), "rich phishing detail"

            # test_connection surfaces a clean error when nothing is configured
            bad = InboxWatcher().test_connection()
            assert bad["ok"] is False and "not configured" in bad["error"], "unconfigured → clean error"

            return True, ("OK — scanned 3 messages, flagged 1 phish (CRITICAL, with "
                          "reasons), detected 1 CVE advisory (LOW), left the clean "
                          "message alone; unconfigured test_connection returns a clean error.")
        except AssertionError as exc:
            return False, f"FAIL — {exc}"
        except Exception as exc:  # pragma: no cover
            return False, f"ERROR — {type(exc).__name__}: {exc}"


if __name__ == "__main__":
    ok, detail = InboxWatcher().self_test()
    print(f"[inbox_watcher] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    raise SystemExit(0 if ok else 1)
