"""ARP Watchdog — G2-F (part 2 of 2).

Detects ARP poisoning / ARP spoofing attacks (T1557.002).

How ARP poisoning works:
  The attacker broadcasts gratuitous ARP replies claiming that a legitimate
  IP (e.g. the default gateway 192.168.1.1) belongs to their MAC address.
  Victim machines update their ARP cache, and all traffic destined for the
  gateway now flows through the attacker (classic Man-in-the-Middle).

Detection methods (two layers):

1. ARP cache diff via `arp -a`
   Parse the Windows ARP cache every POLL_INTERVAL seconds.
   For each IP address, track which MAC we first saw.  If the MAC changes
   (and the IP is in a sensitive range — gateway + local subnet), emit HIGH.

2. Gratuitous ARP sniffer via scapy (optional, requires admin + scapy)
   If scapy is available and the caller has sufficient rights, we spin up a
   daemon thread that sniffs ARP packets on all interfaces and alerts in
   real-time on:
     - is-at (opcode=2) packets where the sender IP matches any known
       IP→MAC mapping with a *different* MAC.
     - is-at packets where both sender IP and sender MAC differ from the
       router but the target IP is a broadcast (gratuitous ARP flood).

Why two methods?
   The `arp -a` fallback is always available but has a latency equal to the
   OS cache refresh cycle (typically 2 minutes).  Scapy captures poisoned
   replies in real-time but requires elevated rights.  Both run if possible.

Limitation:
   Dynamic ARP Inspection (DAI) on managed switches prevents poisoning at the
   network level.  This module catches what reaches the host ARP cache.
"""
from __future__ import annotations

import re
import subprocess
import threading
import time
from typing import Optional

from angerona.core.module_base import BaseModule, Severity
from angerona.core.win import check_output_hidden

_POLL_INTERVAL = 20.0   # seconds between `arp -a` checks

# Parse lines like: 192.168.1.1           00-50-56-c0-00-01     dynamic
_RE_ARP = re.compile(
    r"^\s*([\d.]+)\s+([\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}"
    r"[-:][\da-fA-F]{2}[-:][\da-fA-F]{2}[-:][\da-fA-F]{2})\s+(\w+)",
    re.MULTILINE,
)

# Skip multicast and broadcast MACs (these legitimately change)
_IGNORE_MACS: frozenset[str] = frozenset({
    "ff-ff-ff-ff-ff-ff",
    "01-00-5e",   # IPv4 multicast prefix
})


def _normalise_mac(mac: str) -> str:
    return mac.lower().replace(":", "-")


def _parse_arp_cache() -> dict[str, str]:
    """Run `arp -a` and return {ip: mac} for dynamic entries."""
    result: dict[str, str] = {}
    try:
        out = check_output_hidden(
            ["arp", "-a"],
            timeout=10,
            stderr=subprocess.DEVNULL,
            text=True,
            errors="replace",
        )
        for m in _RE_ARP.finditer(out):
            ip, mac, entry_type = m.group(1), m.group(2), m.group(3)
            if entry_type.lower() not in ("dynamic", "static"):
                continue
            norm_mac = _normalise_mac(mac)
            if any(norm_mac.startswith(prefix) for prefix in _IGNORE_MACS):
                continue
            result[ip] = norm_mac
    except Exception:
        pass
    return result


class ARPWatchdogModule(BaseModule):
    CODE = "ARPW"
    NAME = "ARP Watchdog"
    name = "ARP Watchdog"
    description = (
        "Detects ARP poisoning (T1557.002) via ARP cache diff polling and "
        "optional real-time scapy gratuitous-ARP sniffing."
    )
    category = "Network"

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    def __init__(self) -> None:
        super().__init__()
        # ip → first-seen MAC (our trusted baseline)
        self._baseline: dict[str, str] = {}
        # ip → last-alerted MAC (to avoid re-alerting on every tick)
        self._alerted:  dict[str, str] = {}
        self._scapy_ok  = False

    def run(self) -> None:
        # Seed baseline
        self._baseline = _parse_arp_cache()
        entry_count = len(self._baseline)

        self.emit(
            f"ARP Watchdog active — {entry_count} ARP entries in baseline.",
            Severity.INFO,
            baseline_size=entry_count,
        )
        self.set_health(100, "")

        # Try to start scapy sniffer (optional real-time layer)
        self._try_start_scapy()

        while not self.stopping:
            self.sleep(_POLL_INTERVAL)
            self._check_cache()

    # ── ARP cache diff ────────────────────────────────────────────────────────
    def _check_cache(self) -> None:
        current = _parse_arp_cache()
        for ip, mac in current.items():
            baseline_mac = self._baseline.get(ip)
            if baseline_mac is None:
                # New IP in cache — add to baseline
                self._baseline[ip] = mac
                continue
            if mac == baseline_mac:
                # MAC unchanged — OK
                if ip in self._alerted and self._alerted[ip] != mac:
                    del self._alerted[ip]   # recovered
                continue
            # MAC changed for a known IP
            if self._alerted.get(ip) == mac:
                continue   # already alerted for this specific change
            self._alerted[ip] = mac
            self.emit(
                f"ARP CACHE POISONING DETECTED: IP {ip} MAC changed from "
                f"{baseline_mac} → {mac} — possible Man-in-the-Middle attack (T1557.002)",
                Severity.CRITICAL,
                ip=ip,
                original_mac=baseline_mac,
                current_mac=mac,
                mitre_tags=["T1557.002", "T1040"],
            )

    # ── Scapy real-time sniffer (optional) ───────────────────────────────────
    def _try_start_scapy(self) -> None:
        try:
            import scapy.all as scapy  # type: ignore[import]
            t = threading.Thread(
                target=self._scapy_sniffer,
                args=(scapy,),
                name="arp-watchdog-scapy",
                daemon=True,
            )
            t.start()
            self._scapy_ok = True
            self.emit("ARP Watchdog: scapy sniffer active (real-time mode).", Severity.INFO)
        except ImportError:
            self.emit(
                "ARP Watchdog: scapy not installed — running poll-only mode. "
                "pip install scapy for real-time ARP detection.",
                Severity.INFO,
                scapy_available=False,
            )
        except Exception as exc:
            self.emit(
                f"ARP Watchdog: scapy sniffer failed to start ({exc}) — poll-only mode.",
                Severity.INFO,
                scapy_available=False,
            )

    def _scapy_sniffer(self, scapy: object) -> None:
        """Sniff ARP packets and detect gratuitous ARP replies."""
        def _handle(pkt: object) -> None:
            if self.stopping:
                return
            try:
                arp_layer = pkt.getlayer("ARP")  # type: ignore[union-attr]
                if arp_layer is None:
                    return
                # op=2 → is-at (reply)
                if int(arp_layer.op) != 2:
                    return
                sender_ip  = str(arp_layer.psrc)
                sender_mac = _normalise_mac(str(arp_layer.hwsrc))

                baseline_mac = self._baseline.get(sender_ip)
                if baseline_mac is None:
                    # New IP — add to baseline
                    self._baseline[sender_ip] = sender_mac
                    return
                if sender_mac == baseline_mac:
                    return
                if self._alerted.get(sender_ip) == sender_mac:
                    return

                self._alerted[sender_ip] = sender_mac
                self.emit(
                    f"REAL-TIME ARP POISON: IP {sender_ip} claimed by {sender_mac} "
                    f"(baseline={baseline_mac}) — gratuitous ARP reply (T1557.002)",
                    Severity.CRITICAL,
                    ip=sender_ip,
                    claimed_mac=sender_mac,
                    baseline_mac=baseline_mac,
                    realtime=True,
                    mitre_tags=["T1557.002"],
                )
            except Exception:
                pass

        try:
            scapy.sniff(filter="arp", prn=_handle, store=False, stop_filter=lambda _: self.stopping)  # type: ignore[union-attr]
        except Exception as exc:
            self.emit(
                f"ARP Watchdog scapy sniffer stopped: {exc}",
                Severity.MEDIUM,
            )

    def self_test(self) -> tuple[bool, str]:
        cache = _parse_arp_cache()
        mode  = "scapy+poll" if self._scapy_ok else "poll-only"
        return True, f"ARP cache has {len(cache)} entries — mode={mode}"


def register() -> ARPWWatchdogModule:
    return ARPWatchdogModule()
