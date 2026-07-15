"""Packet sniffer with lightweight deep-packet inspection.

Captures packets in short sessions (via scapy) and flags cleartext TCP payloads
that look like leaked credentials/keys. Ported from Angerona's ``sniffer.py``.

Requires scapy + Npcap. Disabled by default; if scapy/Npcap is missing the
module reports that clearly instead of failing silently.
"""
from __future__ import annotations

import string

from angerona.core.module_base import BaseModule, Severity

# Tokens that, in cleartext on the wire, strongly suggest a credential leak.
LEAK_TOKENS = ("password", "passwd", "api_key", "apikey", "secret", "authorization",
               "token=", "bearer ", "aws_secret", "private_key")
_PRINTABLE = set(string.printable.encode("ascii"))


def _is_text(payload: bytes) -> bool:
    if not payload:
        return False
    hits = sum(1 for b in payload if b in _PRINTABLE)
    return (hits / len(payload)) > 0.85


class PacketSnifferModule(BaseModule):
    name = "Packet Sniffer"
    description = "Inspects network packets for cleartext credentials/secrets on the wire."
    category = "Network"
    enabled_by_default = False  # needs scapy + Npcap

    def run(self) -> None:
        try:
            from scapy.all import IP, TCP, sniff  # noqa: F401
        except Exception:
            self.status = "error"
            self.emit("Packet sniffer disabled: scapy/Npcap not installed. "
                      "Install Npcap + 'pip install scapy' to enable.", Severity.MEDIUM)
            return

        self.emit("Packet sniffer active (DPI for cleartext secrets).", Severity.INFO)

        def on_packet(pkt) -> None:
            try:
                if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
                    return
                raw = bytes(pkt[TCP].payload)
                if not raw or not _is_text(raw):
                    return
                snippet = raw[:250].decode("ascii", errors="ignore").strip()
                if len(snippet) < 10:
                    return
                low = snippet.lower()
                src, dst = pkt[IP].src, pkt[IP].dst
                if any(tok in low for tok in LEAK_TOKENS):
                    self.emit(f"Possible cleartext secret {src}→{dst}: {snippet[:80]!r}",
                              Severity.HIGH, src=src, dst=dst)
            except Exception:
                pass

        # Sniff in bounded sessions so the module can stop responsively.
        while not self.stopping:
            try:
                sniff(prn=on_packet, store=False, timeout=5)
                # ``sniff`` is the bounded work unit; unlike most modules this
                # success path has no BaseModule.sleep() cadence call.
                self.mark_cycle_complete()
            except Exception as exc:
                self.last_error = str(exc)
                self.sleep(5)
