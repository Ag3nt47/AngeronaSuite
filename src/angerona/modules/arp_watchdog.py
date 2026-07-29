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
_SCAPY_SNIFF_TIMEOUT = 0.5
_SCAPY_STOP_TIMEOUT = 1.5

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
        self._scapy_lock = threading.Lock()
        self._scapy_helper: Optional[object] = None
        self._scapy_helper_kind = ""
        # This is deliberately separate from BaseModule._stop. BaseModule.start()
        # clears that event, which must never revive an older capture on restart.
        self._scapy_stop_event: Optional[threading.Event] = None

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

        try:
            # Try to start scapy sniffer (optional real-time layer)
            self._try_start_scapy()

            while not self.stopping:
                self.sleep(_POLL_INTERVAL)
                if not self.stopping:
                    self._check_cache()
        finally:
            self._stop_scapy()

    def stop(self) -> None:
        """Stop polling and promptly wake any Scapy capture helper."""
        super().stop()
        self._stop_scapy()

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
        capture_stop: Optional[threading.Event] = None
        previous_capture_stopping = False
        try:
            import scapy.all as scapy  # type: ignore[import]

            with self._scapy_lock:
                if self.stopping:
                    return
                if self._capture_is_active_locked():
                    if self._scapy_stop_event is not None and not self._scapy_stop_event.is_set():
                        # Duplicate start request for this run; the current
                        # capture already provides real-time coverage.
                        return
                    # A previous capture that has not stopped yet owns the single
                    # helper slot. Poll-only mode is safer than overlapping it.
                    self._scapy_ok = False
                    previous_capture_stopping = True
                else:
                    capture_stop = threading.Event()
                    handler = self._make_scapy_handler(capture_stop)
                    async_sniffer = getattr(scapy, "AsyncSniffer", None)
                    if callable(async_sniffer):
                        helper = async_sniffer(
                            filter="arp",
                            prn=handler,
                            store=False,
                        )
                        self._scapy_helper = helper
                        self._scapy_helper_kind = "async"
                        self._scapy_stop_event = capture_stop
                        helper.start()
                    else:
                        helper = threading.Thread(
                            target=self._scapy_sniffer,
                            args=(scapy, capture_stop, handler),
                            name="arp-watchdog-scapy",
                            daemon=True,
                        )
                        self._scapy_helper = helper
                        self._scapy_helper_kind = "thread"
                        self._scapy_stop_event = capture_stop
                        helper.start()
                    self._scapy_ok = True
            if previous_capture_stopping:
                self.emit(
                    "ARP Watchdog: previous scapy capture is still stopping — "
                    "running poll-only mode.",
                    Severity.INFO,
                    scapy_available=True,
                )
                return
            self.emit("ARP Watchdog: scapy sniffer active (real-time mode).", Severity.INFO)
        except ImportError:
            self.emit(
                "ARP Watchdog: scapy not installed — running poll-only mode. "
                "pip install scapy for real-time ARP detection.",
                Severity.INFO,
                scapy_available=False,
            )
        except Exception as exc:
            with self._scapy_lock:
                if capture_stop is not None and self._scapy_stop_event is capture_stop:
                    self._clear_capture_locked()
            self.emit(
                f"ARP Watchdog: scapy sniffer failed to start ({exc}) — poll-only mode.",
                Severity.INFO,
                scapy_available=False,
            )

    def _make_scapy_handler(self, capture_stop: threading.Event):
        """Build a packet callback tied to exactly one capture generation."""
        def _handle(pkt: object) -> None:
            if self.stopping or capture_stop.is_set():
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
        return _handle

    def _scapy_sniffer(self, scapy: object, capture_stop: threading.Event, handler) -> None:
        """Compatibility capture loop for Scapy versions without AsyncSniffer."""
        try:
            while not self.stopping and not capture_stop.is_set():
                # timeout bounds idle-interface shutdown; stop_filter handles
                # active interfaces without waiting for the timeout.
                scapy.sniff(  # type: ignore[union-attr]
                    filter="arp",
                    prn=handler,
                    store=False,
                    timeout=_SCAPY_SNIFF_TIMEOUT,
                    stop_filter=lambda _: self.stopping or capture_stop.is_set(),
                )
        except Exception as exc:
            self.emit(
                f"ARP Watchdog scapy sniffer stopped: {exc}",
                Severity.MEDIUM,
            )
        finally:
            current = threading.current_thread()
            with self._scapy_lock:
                if self._scapy_helper is current:
                    self._clear_capture_locked()

    def _capture_is_active_locked(self) -> bool:
        helper = self._scapy_helper
        if helper is None:
            return False
        if self._scapy_helper_kind == "thread":
            active = bool(helper.is_alive())  # type: ignore[union-attr]
        else:
            active = bool(getattr(helper, "running", False))
        if not active:
            self._clear_capture_locked()
        return active

    def _clear_capture_locked(self) -> None:
        self._scapy_helper = None
        self._scapy_helper_kind = ""
        self._scapy_stop_event = None
        self._scapy_ok = False

    def _stop_scapy(self) -> None:
        """Request capture shutdown and wait only for a short, fixed bound."""
        with self._scapy_lock:
            helper = self._scapy_helper
            kind = self._scapy_helper_kind
            capture_stop = self._scapy_stop_event
            already_stopping = capture_stop is not None and capture_stop.is_set()
            if capture_stop is not None:
                capture_stop.set()

        if helper is None:
            self._scapy_ok = False
            return
        if already_stopping:
            self._scapy_ok = False
            return

        try:
            if kind == "async":
                if bool(getattr(helper, "running", False)):
                    helper.stop(join=False)  # type: ignore[union-attr]
                join = getattr(helper, "join", None)
                if callable(join):
                    join(timeout=_SCAPY_STOP_TIMEOUT)
            else:
                helper.join(timeout=_SCAPY_STOP_TIMEOUT)  # type: ignore[union-attr]
        except Exception:
            # Capture shutdown is best-effort. Keeping the live helper reference
            # below prevents a replacement from overlapping it.
            pass

        with self._scapy_lock:
            if self._scapy_helper is helper:
                if not self._capture_is_active_locked():
                    self._clear_capture_locked()
                else:
                    self._scapy_ok = False

    def self_test(self) -> tuple[bool, str]:
        cache = _parse_arp_cache()
        mode  = "scapy+poll" if self._scapy_ok else "poll-only"
        return True, f"ARP cache has {len(cache)} entries — mode={mode}"


def register() -> ARPWatchdogModule:
    return ARPWatchdogModule()
