"""network_protocol_decoder.py — Network Protocol Deep Decoder (Code: NDRD).

Purpose
    Deep-decode DNS traffic and score query-name entropy to surface DGA
    (domain-generation-algorithm) beacons and DNS-tunneling exfiltration — both
    of which produce high-entropy, abnormally-long labels that ordinary
    allow/deny lists miss.

How
    NDRD consumes DNS query strings from the EventBus (emitted by the packet
    sniffer / network monitor) and can also decode raw query names directly. For
    each name it computes Shannon entropy per label, label-length and digit-ratio
    stats, and flags names that exceed the tunneling/DGA thresholds.

Safety
    Read-only analysis of DNS names already observed on-box; no traffic is
    generated, blocked, or sent anywhere.

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import math
import re
import threading
import time
from collections import Counter

from angerona.core.module_base import BaseModule, Severity

# entropy (bits/char) above which a label looks machine-generated
_ENTROPY_HI = 3.6
# a single label longer than this is a classic tunneling indicator
_LABEL_LEN_HI = 30
# DNS query names may arrive embedded in a larger log message
_QNAME_RE = re.compile(r"\b((?:[a-zA-Z0-9_-]{1,63}\.){1,}[a-zA-Z]{2,63})\b")
# common benign suffixes we don't want to score the registrable part of
_KNOWN_TLDS = ("com", "net", "org", "io", "gov", "edu", "co", "uk", "microsoft.com",
               "windows.com", "live.com", "office.com")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class NetworkProtocolDecoderModule(BaseModule):
    CODE = "NDRD"
    NAME = "Network Protocol Deep Decoder"
    name = "Network Protocol Deep Decoder"
    description = ("Decodes DNS query names and scores label entropy to catch DGA "
                   "beacons and DNS-tunneling exfiltration.")
    category = "Network"
    version = "1.0.0"

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._seen = 0
        self._flagged = 0
        self._recent_flags: list[dict] = []

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── analysis ─────────────────────────────────────────────────────────────
    def analyze_qname(self, qname: str) -> dict:
        """Score a single DNS query name. Returns a verdict dict."""
        name = (qname or "").strip().rstrip(".").lower()
        labels = [l for l in name.split(".") if l]
        subject = labels[:-2] if len(labels) > 2 else labels[:1]  # skip registrable domain
        subject_str = "".join(subject) or name
        ent = shannon_entropy(subject_str)
        longest = max((len(l) for l in labels), default=0)
        digits = sum(c.isdigit() for c in subject_str)
        digit_ratio = digits / len(subject_str) if subject_str else 0.0
        reasons = []
        if ent >= _ENTROPY_HI:
            reasons.append(f"entropy {ent:.2f}≥{_ENTROPY_HI}")
        if longest >= _LABEL_LEN_HI:
            reasons.append(f"label len {longest}≥{_LABEL_LEN_HI}")
        if digit_ratio >= 0.5 and len(subject_str) >= 8:
            reasons.append(f"digit-ratio {digit_ratio:.0%}")
        suspicious = bool(reasons)
        return {"qname": name, "entropy": round(ent, 3), "longest_label": longest,
                "digit_ratio": round(digit_ratio, 3), "suspicious": suspicious,
                "reasons": reasons,
                "verdict": "DGA/tunneling-suspect" if suspicious else "benign"}

    def _handle(self, qname: str, src: str = "") -> None:
        v = self.analyze_qname(qname)
        with self.state_lock:
            self._seen += 1
            if v["suspicious"]:
                self._flagged += 1
                self._recent_flags = ([v] + self._recent_flags)[:50]
        if v["suspicious"]:
            self.emit(f"🧬 Suspicious DNS '{v['qname']}' ({', '.join(v['reasons'])}).",
                      Severity.HIGH, **v, source=src)

    def _on_event(self, event) -> None:
        blob = f"{event.message} " + " ".join(str(x) for x in (event.details or {}).values())
        low = blob.lower()
        if "dns" not in low and "query" not in low and "resolve" not in low:
            return
        d = event.details or {}
        qname = d.get("qname") or d.get("query") or d.get("domain") or d.get("host")
        if qname:
            self._handle(str(qname), src=event.module)
            return
        for m in _QNAME_RE.finditer(event.message or ""):
            self._handle(m.group(1), src=event.module)

    def stats(self) -> dict:
        with self.state_lock:
            return {"dns_seen": self._seen, "flagged": self._flagged,
                    "flag_rate_pct": round(self._flagged / self._seen * 100, 1) if self._seen else 0.0}

    # ── lifecycle ────────────────────────────────────────────────────────────
    def run(self) -> None:
        if self._bus is not None:
            try:
                self._bus.subscribe(self._on_event)
            except Exception:
                pass
        self.emit("NDRD online — scoring DNS query-name entropy for DGA/tunneling.",
                  Severity.INFO)
        while not self.stopping:
            st = self.stats()
            self.set_health(100, f"{st['dns_seen']} DNS names, {st['flagged']} flagged")
            self.sleep(10.0)

    def self_test(self) -> tuple[bool, str]:
        """A random high-entropy name must flag; a normal domain must not."""
        dga = self.analyze_qname("kq3v9z7x1p4m8n2b5w0c.example.com")
        good = self.analyze_qname("www.microsoft.com")
        if dga["suspicious"] and not good["suspicious"]:
            return True, f"entropy scoring verified (DGA={dga['entropy']}, ok={good['entropy']})"
        return False, f"entropy logic off (dga={dga}, good={good})"


def register() -> NetworkProtocolDecoderModule:
    return NetworkProtocolDecoderModule()
