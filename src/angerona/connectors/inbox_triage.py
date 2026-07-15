"""connectors/inbox_triage.py — ARIA inbox triage (local phishing heuristics).

Connect a mailbox so ARIA flags likely phishing and lifts vendor advisories into
the threat feed. The scoring is entirely **local and explainable** — a set of
transparent heuristics over a normalised message dict, no model, no network in
the scorer. The IMAP fetch is opt-in and read-only; with no mailbox configured
the module still imports and self-tests on synthetic messages.

    HARD SCOPE: read-only classification. It never replies, deletes, moves, or
    clicks anything. A flagged message becomes an alert on the bus (via the
    caller); any response stays behind the assistant's confirm-then-execute gate.
    Links are reported as text — never fetched here.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# Executable / macro-bearing attachment extensions.
_BAD_EXT = (".exe", ".scr", ".com", ".bat", ".cmd", ".js", ".vbs", ".jar",
            ".ps1", ".lnk", ".iso", ".docm", ".xlsm", ".pptm", ".html", ".htm")
# TLDs over-represented in abuse.
_RISKY_TLD = (".ru", ".tk", ".top", ".zip", ".mov", ".xyz", ".gq", ".cn")
# Credential / urgency lures.
_LURE = ("urgent", "verify", "password", "credential", "confirm", "immediately",
         "suspended", "account", "unusual activity", "reset", "invoice", "gift card",
         "wire transfer", "click here", "login", "expire")

_DOMAIN_RE = re.compile(r"@([A-Za-z0-9.\-]+)")


def _domain(addr: str) -> str:
    m = _DOMAIN_RE.search(addr or "")
    return (m.group(1).lower() if m else "").strip(">").strip()


def _looks_lookalike(dom: str) -> bool:
    """Digit-for-letter or hyphen tricks in a brand-ish domain (paypa1, g00gle)."""
    core = dom.split(".")[0] if dom else ""
    return bool(re.search(r"[a-z][0-9]|[0-9][a-z]", core)) and any(ch.isalpha() for ch in core)


@dataclass
class Verdict:
    score: int              # 0–100, higher = more suspicious
    verdict: str            # "PHISH_LIKELY" | "SUSPICIOUS" | "CLEAN"
    reasons: list = field(default_factory=list)


class InboxTriage:
    """Local phishing triage over normalised message dicts.

    A message dict::

        {
          "from": "IT <security@paypa1-support.com>",
          "reply_to": "harvest@evil.ru",
          "subject": "URGENT: verify your password",
          "body": "confirm your account credentials immediately …",
          "urls": [("http://secure-login.paypa1-support.com", "paypal.com")],  # (href, text)
          "auth": {"spf": "fail", "dkim": "none", "dmarc": "fail"},
          "attachments": ["invoice.exe"],
        }
    """

    PHISH_AT = 60
    SUSPECT_AT = 30

    def score_message(self, msg: dict) -> Verdict:
        """Score one message. Pure, deterministic, explainable."""
        score = 0
        reasons: list[str] = []

        auth = {k: str(v).lower() for k, v in (msg.get("auth") or {}).items()}
        if auth.get("dmarc") in ("fail", "none", "") and "dmarc" in auth:
            score += 25; reasons.append(f"DMARC {auth.get('dmarc')}")
        if auth.get("spf") == "fail":
            score += 15; reasons.append("SPF fail")
        if auth.get("dkim") in ("fail", "none"):
            score += 10; reasons.append(f"DKIM {auth.get('dkim')}")

        from_dom = _domain(msg.get("from", ""))
        reply_dom = _domain(msg.get("reply_to", ""))
        if reply_dom and from_dom and reply_dom != from_dom:
            score += 20; reasons.append(f"Reply-To domain differs ({reply_dom} ≠ {from_dom})")

        if from_dom and (_looks_lookalike(from_dom) or from_dom.endswith(_RISKY_TLD)):
            score += 15; reasons.append(f"Suspicious sender domain ({from_dom})")

        # attachments
        for a in (msg.get("attachments") or []):
            if str(a).lower().endswith(_BAD_EXT):
                score += 25; reasons.append(f"Risky attachment ({a})")
                break

        # lure keywords (subject + body), capped
        text = f"{msg.get('subject', '')} {msg.get('body', '')}".lower()
        hits = sorted({w for w in _LURE if w in text})
        if hits:
            score += min(20, 5 * len(hits)); reasons.append(f"Lure terms: {', '.join(hits[:5])}")

        # link text vs href domain mismatch, or risky link TLD
        for href, shown in (msg.get("urls") or []):
            hd = _domain("@" + re.sub(r"^https?://", "", str(href)).split("/")[0])
            sd = _domain("@" + re.sub(r"^https?://", "", str(shown)).split("/")[0]) if shown else ""
            if sd and hd and sd not in hd and hd not in sd:
                score += 15; reasons.append(f"Link masks {sd} → {hd}")
                break
            if hd.endswith(_RISKY_TLD):
                score += 10; reasons.append(f"Risky link TLD ({hd})")
                break

        score = max(0, min(100, score))
        verdict = ("PHISH_LIKELY" if score >= self.PHISH_AT
                   else "SUSPICIOUS" if score >= self.SUSPECT_AT else "CLEAN")
        return Verdict(score, verdict, reasons)

    def is_vendor_advisory(self, msg: dict) -> bool:
        """Coarse detector for vendor security advisories to lift into the feed."""
        text = f"{msg.get('subject', '')} {msg.get('body', '')}".lower()
        return any(k in text for k in ("security advisory", "cve-", "patch tuesday",
                                       "vulnerability", "security update", "kb50"))

    # ── Opt-in IMAP fetch (read-only) ─────────────────────────────────────────
    def fetch_recent(self, host: str, user: str, password: str, *,
                     folder: str = "INBOX", limit: int = 20) -> list[dict]:  # pragma: no cover
        """Read-only IMAP fetch → normalised dicts. Opt-in; requires imaplib
        (stdlib). Never marks read/deletes. Not exercised by self_test."""
        import email
        import imaplib
        from email.utils import parseaddr

        out: list[dict] = []
        M = imaplib.IMAP4_SSL(host)
        try:
            M.login(user, password)
            M.select(folder, readonly=True)   # readonly — never mutate the mailbox
            _typ, data = M.search(None, "ALL")
            ids = data[0].split()[-limit:]
            for i in reversed(ids):
                _t, raw = M.fetch(i, "(RFC822)")
                m = email.message_from_bytes(raw[0][1])
                body = ""
                if m.is_multipart():
                    for part in m.walk():
                        if part.get_content_type() == "text/plain":
                            body = part.get_payload(decode=True).decode("utf-8", "replace"); break
                else:
                    body = m.get_payload(decode=True).decode("utf-8", "replace")
                out.append({
                    "from": m.get("From", ""),
                    "reply_to": parseaddr(m.get("Reply-To", ""))[1],
                    "subject": m.get("Subject", ""),
                    "body": body,
                    "attachments": [p.get_filename() for p in m.walk() if p.get_filename()],
                    "auth": _parse_auth(m.get("Authentication-Results", "")),
                    "urls": [],
                })
        finally:
            try:
                M.logout()
            except Exception:
                pass
        return out

    # ── Self-test ─────────────────────────────────────────────────────────────
    def self_test(self) -> tuple[bool, str]:
        """Prove a crafted phish scores PHISH_LIKELY with explainable reasons and
        a benign internal message scores CLEAN, plus advisory detection."""
        try:
            t = InboxTriage()

            phish = {
                "from": "IT Support <security@paypa1-support.com>",
                "reply_to": "harvest@evil.ru",
                "subject": "URGENT: verify your password now",
                "body": "Please confirm your account credentials immediately or it will be suspended.",
                "urls": [("http://secure-login.paypa1-support.com/x", "paypal.com")],
                "auth": {"spf": "fail", "dkim": "none", "dmarc": "fail"},
                "attachments": ["invoice.exe"],
            }
            v = t.score_message(phish)
            assert v.verdict == "PHISH_LIKELY", f"expected PHISH_LIKELY, got {v.verdict} ({v.score})"
            assert v.score >= 60 and len(v.reasons) >= 4, "explainable, high score"
            joined = " ".join(v.reasons).lower()
            assert "dmarc" in joined and "attachment" in joined and "reply-to" in joined, "key reasons present"

            clean = {
                "from": "Dana Lee <dana@ourcompany.com>",
                "reply_to": "dana@ourcompany.com",
                "subject": "lunch tomorrow?",
                "body": "want to grab lunch around noon and go over the roadmap?",
                "urls": [],
                "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
                "attachments": [],
            }
            cv = t.score_message(clean)
            assert cv.verdict == "CLEAN" and cv.score < 30, f"benign should be CLEAN ({cv.score})"

            # a middling case: internal-looking but Reply-To mismatch + one lure
            mid = {
                "from": "billing@vendor.com", "reply_to": "billing@vendor-payments.com",
                "subject": "invoice attached", "body": "see attached invoice",
                "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            }
            mv = t.score_message(mid)
            assert mv.verdict in ("SUSPICIOUS", "CLEAN"), "mid case handled without false PHISH"

            # advisory detection
            assert t.is_vendor_advisory({"subject": "Microsoft Security Advisory CVE-2026-1234"}), "advisory"
            assert not t.is_vendor_advisory({"subject": "team offsite photos"}), "non-advisory"

            return True, (f"OK — crafted phish → PHISH_LIKELY (score {v.score}, "
                          f"{len(v.reasons)} reasons: DMARC/attachment/Reply-To…); benign "
                          f"internal mail → CLEAN ({cv.score}); Reply-To-mismatch case stays "
                          f"≤SUSPICIOUS; CVE advisory detected, social mail not.")
        except AssertionError as exc:
            return False, f"FAIL — {exc}"
        except Exception as exc:  # pragma: no cover
            return False, f"ERROR — {type(exc).__name__}: {exc}"


def _parse_auth(header: str) -> dict:  # pragma: no cover - used by IMAP path
    h = (header or "").lower()
    def grab(k):
        m = re.search(k + r"=(\w+)", h)
        return m.group(1) if m else ""
    return {"spf": grab("spf"), "dkim": grab("dkim"), "dmarc": grab("dmarc")}


# ── Singleton factory ──────────────────────────────────────────────────────────
_TRIAGE: Optional[InboxTriage] = None


def get_triage() -> InboxTriage:
    global _TRIAGE
    if _TRIAGE is None:
        _TRIAGE = InboxTriage()
    return _TRIAGE


if __name__ == "__main__":
    ok, detail = InboxTriage().self_test()
    print(f"[inbox_triage] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    raise SystemExit(0 if ok else 1)
