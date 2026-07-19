"""Small privacy boundaries shared by optional outbound integrations."""
from __future__ import annotations

import os
import re
import ipaddress
import socket


_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9A-F]{0,4}:){2,8}[0-9A-F]{0,4}(?![\w:])", re.I)
_UNC_PATH = re.compile(r"\\\\[^\\\s]+\\[^\s]+")
_WIN_PATH = re.compile(r"(?i)\b[A-Z]:\\(?:[^\s<>:\"|?*]+\\)*[^\s<>:\"|?*]*")
_TOKEN = re.compile(r"(?i)\b(?:sk|api|token|key)[-_]?[A-Za-z0-9]{16,}\b")
_NAMED_SECRET = re.compile(
    r"(?i)\b(?:password|passwd|pwd|secret|token|api[-_ ]?key|authorization)\b"
    r"\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_URL = re.compile(r"https?://[^\s]+", re.I)
_HOSTNAME = re.compile(r"\b(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"
                       r"[A-Z]{2,63}\b", re.I)


def _clean_url(match: re.Match) -> str:
    return "[URL]"


def _clean_ipv6(match: re.Match) -> str:
    value = match.group(0)
    try:
        if isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address):
            return "[IP]"
    except ValueError:
        pass
    return value


def redact_text(value: object, *, limit: int = 1200) -> str:
    """Remove common host/user identifiers before optional network egress."""
    text = str(value or "")
    for private in (
        os.path.expanduser("~"), os.environ.get("USERNAME", ""),
        os.environ.get("COMPUTERNAME", ""), socket.gethostname(),
    ):
        if private:
            text = re.sub(re.escape(private), "[LOCAL_USER]", text, flags=re.I)
    text = _NAMED_SECRET.sub("[SENSITIVE]=[REDACTED]", text)
    text = _EMAIL.sub("[EMAIL]", text)
    text = _URL.sub(_clean_url, text)
    text = _UNC_PATH.sub("[LOCAL_PATH]", text)
    text = _IPV4.sub("[IP]", text)
    text = _IPV6.sub(_clean_ipv6, text)
    text = _WIN_PATH.sub("[LOCAL_PATH]", text)
    text = _TOKEN.sub("[SECRET]", text)
    text = _HOSTNAME.sub("[HOST]", text)
    return text[:max(0, int(limit))]


def cloud_assistant_prompt(question: object, *, score: object, label: object) -> str:
    """Build the deliberately narrow payload allowed for ARIA cloud fallback."""
    return (
        "You are ARIA, a defensive Windows security assistant. Answer concisely; "
        "do not provide offensive instructions. No raw telemetry or local files are "
        "included.\n\n"
        f"Posture: {redact_text(label, limit=40)} ({redact_text(score, limit=12)}).\n"
        f"Operator question: {redact_text(question)}"
    )
