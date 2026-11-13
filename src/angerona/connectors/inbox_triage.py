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

import email
import hashlib
import imaplib
import re
import ssl
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urlsplit


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
_MAX_MESSAGES = 50
_MAX_MESSAGE_BYTES = 256 * 1024
_MAX_HEADER_BYTES = 16 * 1024
_MAX_POLL_BYTES = 4 * 1024 * 1024
_MAX_TEXT_CHARS = 64 * 1024
_MAX_LINKS = 128
_MAX_MIME_PARTS = 128
_MAX_MIME_DEPTH = 16
_IMAP_TIMEOUT_SECONDS = 10.0
_IMAP_DEADLINE_SECONDS = 30.0
_MAX_IMAP_LINE_BYTES = 64 * 1024


class _BoundedIMAP4SSL(imaplib.IMAP4_SSL):
    """Bound protocol input before imaplib allocates server-declared literals."""

    def __init__(self, host, *, deadline):
        self._deadline = deadline
        self._pending = bytearray()
        self._wire_bytes = 0
        super().__init__(host, timeout=_IMAP_TIMEOUT_SECONDS,
                         ssl_context=ssl.create_default_context())

    def _limit_io(self):
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("inbox read deadline expired")
        self.sock.settimeout(min(_IMAP_TIMEOUT_SECONDS, remaining))

    def _chunk(self, size):
        self._limit_io()
        chunk = self.file.read1(size)
        self._wire_bytes += len(chunk)
        if self._wire_bytes > _MAX_POLL_BYTES + 1024 * 1024:
            raise self.abort("inbox protocol byte budget exceeded")
        return chunk

    def read(self, size):
        self._limit_io()
        if type(size) is not int or not 0 <= size <= _MAX_MESSAGE_BYTES + 1:
            raise self.abort("inbox literal byte budget exceeded")
        data = bytes(self._pending[:size])
        del self._pending[:size]
        chunks = [data]
        remaining = size - len(data)
        while remaining:
            chunk = self._chunk(min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def readline(self):
        self._limit_io()
        while True:
            end = self._pending.find(b"\n")
            if end >= 0:
                if end + 1 > _MAX_IMAP_LINE_BYTES:
                    raise self.abort("inbox protocol line budget exceeded")
                line = bytes(self._pending[:end + 1])
                del self._pending[:end + 1]
                return line
            if len(self._pending) > _MAX_IMAP_LINE_BYTES:
                raise self.abort("inbox protocol line budget exceeded")
            chunk = self._chunk(4096)
            if not chunk:
                line = bytes(self._pending)
                self._pending.clear()
                return line
            self._pending.extend(chunk)

    def send(self, data):
        self._limit_io()
        return super().send(data)


def _link_host(value):
    value = str(value or "").strip()
    if not value or len(value) > 2048 or any(char.isspace() for char in value):
        return ""
    try:
        parsed = urlsplit(value if "://" in value else "https://" + value)
        if parsed.scheme.casefold() not in {"http", "https"}:
            return ""
        host = (parsed.hostname or "").rstrip(".").encode("idna").decode("ascii").casefold()
        return host if re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", host) else ""
    except (ValueError, UnicodeError):
        return ""


def _related_hosts(left, right):
    return left == right or left.endswith("." + right) or right.endswith("." + left)


class _MailHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.text = []
        self.limited = False
        self._href = ""
        self._shown = []
        self._shown_chars = 0

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.handle_endtag("a")
            href = next((value for name, value in attrs if name == "href"), "") or ""
            self._href = href[:2048] if len(href) <= 2048 else ""
            if len(href) > 2048:
                self.limited = True

    def handle_endtag(self, tag):
        if tag == "a":
            if self._href and len(self.links) < _MAX_LINKS:
                self.links.append((self._href, "".join(self._shown).strip()))
            elif self._href:
                self.limited = True
            self._href, self._shown, self._shown_chars = "", [], 0

    def handle_data(self, data):
        self.text.append(data)
        if self._href and self._shown_chars < 2048:
            value = data[:2048 - self._shown_chars]
            self._shown.append(value)
            self._shown_chars += len(value)
            if len(value) < len(data):
                self.limited = True
        elif self._href and data:
            self.limited = True


def _incomplete_message(reason):
    return {"from": "", "reply_to": "", "subject": "Inbox check incomplete",
            "body": "", "attachments": [], "auth": {}, "urls": [],
            "coverage": {"complete": False, "reason": reason}}


def _fetch_metadata(rows):
    if type(rows) is not list or len(rows) != 1 or type(rows[0]) is not bytes or len(rows[0]) > _MAX_IMAP_LINE_BYTES:
        raise ValueError("inbox metadata is unavailable")
    return _metadata_values(rows[0])


def _metadata_values(raw):
    uids = re.findall(rb"\bUID (\d+)\b", raw, re.IGNORECASE)
    sizes = re.findall(rb"\bRFC822\.SIZE (\d+)\b", raw, re.IGNORECASE)
    if len(uids) != 1 or len(sizes) != 1 or len(uids[0]) > 10 or len(sizes[0]) > 16:
        raise ValueError("inbox message identity or size is unavailable")
    uid, size = int(uids[0]), int(sizes[0])
    if not 0 < uid <= 2**32 - 1:
        raise ValueError("inbox UID is invalid")
    return uid, size


def _fetch_payload(rows, uid, size, maximum):
    if type(rows) is not list or not 1 <= len(rows) <= 8:
        raise ValueError("inbox body response is unavailable")
    payloads, metadata = [], []
    for row in rows:
        if type(row) is tuple and len(row) == 2 and all(type(value) is bytes for value in row):
            metadata.append(row[0])
            payloads.append(row[1])
        elif type(row) is bytes:
            metadata.append(row)
        else:
            raise ValueError("inbox body response is invalid")
    if (len(payloads) != 1 or len(payloads[0]) > maximum
            or any(len(part) > _MAX_IMAP_LINE_BYTES for part in metadata)
            or _metadata_values(b" ".join(metadata)) != (uid, size)):
        raise ValueError("inbox body identity or size changed")
    return payloads[0]


def _normalize_message(raw, *, size, incomplete=""):
    from email.utils import parseaddr

    if len(raw) > _MAX_MESSAGE_BYTES:
        raise ValueError("inbox parser input exceeded its byte budget")
    message = email.message_from_bytes(raw)
    issues = [incomplete] if incomplete else []
    body, links, attachments = [], [], []
    remaining = _MAX_TEXT_CHARS
    pending = [(message, 0)]
    seen = 0
    while pending:
        part, depth = pending.pop()
        seen += 1
        if seen > _MAX_MIME_PARTS or depth > _MAX_MIME_DEPTH:
            issues.append("MIME structure exceeded the review budget")
            break
        if part.defects:
            issues.append("MIME content was malformed or incomplete")
        filename = part.get_filename()
        if filename:
            attachments.append(str(filename)[:256])
        payload = part.get_payload()
        if type(payload) is list:
            if len(payload) + seen + len(pending) > _MAX_MIME_PARTS:
                issues.append("MIME structure exceeded the review budget")
                break
            pending.extend((child, depth + 1) for child in reversed(payload))
            continue
        if part.get_content_type() not in {"text/plain", "text/html"} or filename:
            continue
        decoded = part.get_payload(decode=True) or b""
        try:
            text = decoded.decode(part.get_content_charset() or "utf-8", "replace")
        except (LookupError, UnicodeError):
            text = decoded.decode("utf-8", "replace")
        if len(text) > remaining:
            issues.append("Message text exceeded the review budget")
        text = text[:remaining]
        remaining -= len(text)
        if part.get_content_type() == "text/html":
            parser = _MailHTML()
            parser.feed(text)
            parser.handle_endtag("a")
            body.append(" ".join(parser.text))
            if parser.limited or len(parser.links) > _MAX_LINKS - len(links):
                issues.append("Message link metadata exceeded the review budget")
            links.extend(parser.links[:_MAX_LINKS - len(links)])
        else:
            body.append(text)
            for match in re.finditer(r"https?://[^\s<>\"']{1,2048}", text, re.IGNORECASE):
                if len(links) >= _MAX_LINKS:
                    issues.append("Message link metadata exceeded the review budget")
                    break
                links.append((match.group(), ""))
    return {"from": str(message.get("From", ""))[:512],
            "reply_to": parseaddr(str(message.get("Reply-To", ""))[:512])[1],
            "subject": str(message.get("Subject", ""))[:512],
            "body": "\n".join(body)[:_MAX_TEXT_CHARS], "attachments": attachments,
            # A message header does not prove which receiving gateway wrote it.
            # Keep reported values as unverified data, outside scoring inputs.
            "auth": {}, "authentication": {"verified": False,
                "reported": _parse_auth(str(message.get("Authentication-Results", ""))[:2048])},
            "urls": links, "coverage": {"complete": not issues,
                "reason": "; ".join(dict.fromkeys(issues)), "message_bytes": size, "read_bytes": len(raw)}}


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
    verdict: str            # "PHISH_LIKELY" | "SUSPICIOUS" | "CLEAN" | "INCOMPLETE"
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
        """Score supplied heuristics. CLEAN does not attest sender authenticity."""
        score = 0
        reasons: list[str] = []

        if "authentication" in msg:
            # Native mailbox records never promote headers into verification.
            # There is no caller-supplied flag that upgrades their provenance.
            auth = {}
            reasons.append("Email authentication is unverified; reported headers did not affect this heuristic score.")
        else:
            # Preserve the existing direct normalized-input heuristic contract.
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
            hd = _link_host(href)
            sd = _link_host(shown) if shown else ""
            if sd and hd and not _related_hosts(sd, hd):
                score += 15; reasons.append(f"Link masks {sd} → {hd}")
                break
            if hd.endswith(_RISKY_TLD):
                score += 10; reasons.append(f"Risky link TLD ({hd})")
                break

        score = max(0, min(100, score))
        verdict = ("PHISH_LIKELY" if score >= self.PHISH_AT
                   else "SUSPICIOUS" if score >= self.SUSPECT_AT else "CLEAN")
        coverage = msg.get("coverage") or {}
        if coverage.get("complete") is False:
            reasons.append("Incomplete inbox check: " + str(coverage.get("reason") or "coverage unavailable")[:200])
            if verdict == "CLEAN":
                verdict = "INCOMPLETE"
        return Verdict(score, verdict, reasons)

    def is_vendor_advisory(self, msg: dict) -> bool:
        """Coarse detector for vendor security advisories to lift into the feed."""
        text = f"{msg.get('subject', '')} {msg.get('body', '')}".lower()
        return any(k in text for k in ("security advisory", "cve-", "patch tuesday",
                                       "vulnerability", "security update", "kb50"))

    # ── Opt-in IMAP fetch (read-only) ─────────────────────────────────────────
    def fetch_recent(self, host: str, user: str, password: str, *,
                     folder: str = "INBOX", limit: int = 20) -> list[dict]:
        """Read-only IMAP fetch → normalised dicts. Opt-in; requires imaplib
        (stdlib). Never marks read/deletes. Not exercised by self_test."""
        if type(limit) is not int or not 1 <= limit <= _MAX_MESSAGES:
            raise ValueError("Choose 1–50 recent inbox messages per check")
        self.last_fetch_coverage = {"complete": False, "messages": 0, "read_bytes": 0}
        out: list[dict] = []
        deadline = time.monotonic() + _IMAP_DEADLINE_SECONDS
        M = _BoundedIMAP4SSL(host, deadline=deadline)
        total = 0
        reading_messages = False
        try:
            M.login(user, password)
            status, data = M.select(folder, readonly=True)
            if (status != "OK" or type(data) is not list or len(data) != 1
                    or type(data[0]) is not bytes or not data[0].isdigit() or len(data[0]) > 10):
                raise ValueError("Inbox message count is unavailable")
            count = int(data[0])
            validity = getattr(M, "untagged_responses", {}).get("UIDVALIDITY", [])
            validity = (validity[0].decode("ascii") if type(validity) is list and len(validity) == 1
                and type(validity[0]) is bytes and validity[0].isdigit() and len(validity[0]) <= 10 else "unavailable")
            reading_messages = True
            for sequence in range(count, max(0, count - limit), -1):
                if time.monotonic() >= deadline or total >= _MAX_POLL_BYTES:
                    out.append(_incomplete_message("Inbox check reached its time or byte budget; remaining messages were not checked"))
                    break
                try:
                    status, metadata = M.fetch(str(sequence), "(UID RFC822.SIZE)")
                    if status != "OK":
                        raise ValueError("inbox metadata fetch failed")
                    uid, size = _fetch_metadata(metadata)
                    oversized = size > min(_MAX_MESSAGE_BYTES, _MAX_POLL_BYTES - total)
                    maximum = min(_MAX_HEADER_BYTES, _MAX_POLL_BYTES - total) if oversized else size
                    section = "HEADER.FIELDS (FROM REPLY-TO SUBJECT AUTHENTICATION-RESULTS)" if oversized else ""
                    query = f"(UID RFC822.SIZE BODY.PEEK[{section}]<0.{maximum + 1}>)"
                    status, payload = M.uid("fetch", str(uid), query)
                    if status != "OK":
                        raise ValueError("inbox body fetch failed")
                    raw = _fetch_payload(payload, uid, size, maximum)
                    if not oversized and len(raw) != size:
                        raise ValueError("inbox body was truncated")
                    total += len(raw)
                    normalized = _normalize_message(raw, size=size,
                        incomplete="Message body exceeded the byte budget; only bounded header metadata was reviewed" if oversized else "")
                    # The watcher adds its mailbox scope. The bounded raw digest
                    # also detects changed content or a reused UID after reset.
                    normalized["message_identity"] = hashlib.sha256(
                        b"angerona-inbox-v1\0" + validity.encode("ascii") + b"\0" + str(uid).encode("ascii")
                        + b"\0" + hashlib.sha256(raw).digest()).hexdigest()
                    out.append(normalized)
                except (ValueError, TypeError, RecursionError):
                    out.append(_incomplete_message("Message metadata or bounded content could not be verified"))
        except (OSError, imaplib.IMAP4.error, ValueError):
            if not reading_messages:
                raise
            out.append(_incomplete_message("Mailbox read failed or exceeded its protocol deadline; coverage is incomplete"))
        finally:
            try:
                M.shutdown()
            except Exception:
                pass
        self.last_fetch_coverage = {"complete": all(row["coverage"]["complete"] for row in out),
                                    "messages": len(out), "read_bytes": total,
                                    "scope": "selected recent mailbox messages", "authentication_verified": False}
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
                          f"{len(v.reasons)} reasons: supplied auth/attachment/Reply-To…); "
                          f"inert low-score input → CLEAN ({cv.score}); Reply-To-mismatch case stays "
                          f"≤SUSPICIOUS. These heuristic fixtures do not verify real mail authenticity.")
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
