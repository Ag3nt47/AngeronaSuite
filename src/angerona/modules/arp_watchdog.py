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

import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

from angerona.core.atomic_io import replace_with_retry
from angerona.core.module_base import BaseModule, Severity
from angerona.core.win import check_output_hidden

_POLL_INTERVAL = 20.0   # seconds between `arp -a` checks
_SCAPY_SNIFF_TIMEOUT = 0.5
_SCAPY_STOP_TIMEOUT = 1.5
_BASELINE_SCHEMA = 1
_BASELINE_HMAC = "hmac_sha256"
_BASELINE_DOMAIN = b"Angerona-ARP-Baseline-v1"
_MAX_BASELINE_BYTES = 256 * 1024

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
    out = check_output_hidden(
        ["arp", "-a"],
        timeout=10,
        stderr=subprocess.DEVNULL,
        text=True,
        errors="replace",
    )
    if not isinstance(out, str) or (not out.strip() and "Interface:" not in out):
        raise RuntimeError("ARP collector returned no parseable output")
    for m in _RE_ARP.finditer(out):
        ip, mac, entry_type = m.group(1), m.group(2), m.group(3)
        if entry_type.lower() not in ("dynamic", "static"):
            continue
        norm_mac = _normalise_mac(mac)
        if any(norm_mac.startswith(prefix) for prefix in _IGNORE_MACS):
            continue
        result[ip] = norm_mac
    return result


class ARPWatchdogModule(BaseModule):
    CODE = "ARPW"
    NAME = "ARP Watchdog"
    name = "ARP Watchdog"
    version = "1.12.1"
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
        self._candidate: dict[str, str] = {}
        self._unknown_alerted: set[tuple[str, str]] = set()
        self._collector_ok = False
        self._baseline_status = "not-loaded"
        self._baseline_path_override: Path | None = None
        self._baseline_key_override: bytes | None = None

    @property
    def _baseline_path(self) -> Path:
        if self._baseline_path_override is not None:
            return self._baseline_path_override
        from angerona.core.data_paths import data_dir

        return data_dir() / "sensor-baselines" / "arp-watchdog.json"

    def _baseline_key(self) -> bytes | None:
        key = self._baseline_key_override
        if key is None:
            try:
                from angerona.core.data_paths import data_dir

                key = bytes.fromhex(
                    (data_dir() / "bus.key").read_text(encoding="ascii").strip()
                )
            except (OSError, ValueError):
                return None
        if len(key) != 32:
            return None
        return hmac.new(key, _BASELINE_DOMAIN, hashlib.sha256).digest()

    @staticmethod
    def _baseline_body(value: dict) -> bytes:
        unsigned = {key: item for key, item in value.items() if key != _BASELINE_HMAC}
        return json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

    def _load_baseline(self) -> bool:
        key = self._baseline_key()
        if key is None:
            self._baseline_status = "key-unavailable"
            return False
        try:
            raw = self._baseline_path.read_bytes()
        except FileNotFoundError:
            self._baseline_status = "approval-required"
            return False
        except OSError:
            self._baseline_status = "unreadable"
            return False
        try:
            if len(raw) > _MAX_BASELINE_BYTES:
                raise ValueError("baseline exceeds byte limit")
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, dict) or set(value) != {
                "schema",
                "approved_at",
                "entries",
                _BASELINE_HMAC,
            }:
                raise ValueError("baseline schema mismatch")
            entries = value["entries"]
            if (
                value["schema"] != _BASELINE_SCHEMA
                or not isinstance(value["approved_at"], (int, float))
                or isinstance(value["approved_at"], bool)
                or not math.isfinite(float(value["approved_at"]))
                or not isinstance(entries, dict)
                or len(entries) > 8192
            ):
                raise ValueError("baseline entries invalid")
            clean: dict[str, str] = {}
            for ip, mac in entries.items():
                if (
                    not isinstance(ip, str)
                    or not isinstance(mac, str)
                    or not re.fullmatch(r"[0-9a-f]{2}(?:-[0-9a-f]{2}){5}", mac)
                ):
                    raise ValueError("baseline entry malformed")
                try:
                    if str(ipaddress.IPv4Address(ip)) != ip:
                        raise ValueError("non-canonical IP address")
                except ipaddress.AddressValueError as exc:
                    raise ValueError("baseline IP address malformed") from exc
                clean[ip] = mac
            supplied = str(value[_BASELINE_HMAC])
            expected = hmac.new(
                key, self._baseline_body(value), hashlib.sha256
            ).hexdigest()
            if len(supplied) != 64 or not hmac.compare_digest(supplied, expected):
                raise ValueError("baseline authentication failed")
        except (TypeError, ValueError, UnicodeError, json.JSONDecodeError):
            self._baseline_status = "invalid"
            return False
        self._baseline = clean
        self._baseline_status = "approved"
        return True

    def approve_current_baseline(self, *, approved: bool = False) -> Path:
        if not approved:
            raise PermissionError("explicit ARP baseline approval is required")
        if not self._collector_ok or not self._candidate:
            raise RuntimeError("a successful non-empty ARP collection is required")
        if self._baseline_status in {"invalid", "unreadable"}:
            raise RuntimeError("refusing to overwrite invalid ARP baseline evidence")
        key = self._baseline_key()
        if key is None:
            raise RuntimeError("ARP baseline key unavailable")
        document = {
            "schema": _BASELINE_SCHEMA,
            "approved_at": time.time(),
            "entries": dict(sorted(self._candidate.items())),
        }
        document[_BASELINE_HMAC] = hmac.new(
            key, self._baseline_body(document), hashlib.sha256
        ).hexdigest()
        payload = json.dumps(
            document, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        if len(payload) > _MAX_BASELINE_BYTES:
            raise RuntimeError("ARP baseline exceeds byte limit")
        path = self._baseline_path
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(
            f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        try:
            with temporary.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            replace_with_retry(temporary, path)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        self._baseline = dict(self._candidate)
        self._baseline_status = "approved"
        return path

    def _collect(self) -> dict[str, str] | None:
        try:
            entries = _parse_arp_cache()
        except Exception as exc:
            self._collector_ok = False
            self.last_error = str(exc)
            return None
        self._collector_ok = True
        self._candidate = dict(entries)
        return entries

    def _set_coverage_health(self) -> None:
        if not self._collector_ok:
            self.set_health(25, "ARP collector unavailable; baseline retained")
        elif self._baseline_status != "approved":
            self.set_health(
                45,
                f"ARP observations untrusted; baseline {self._baseline_status}",
            )
        elif not self._scapy_ok:
            self.set_health(80, "approved ARP baseline; poll-only coverage")
        else:
            self.set_health(100, "approved ARP baseline; poll + realtime coverage")

    def run(self) -> None:
        # Only a separately authenticated, explicitly approved snapshot is a
        # trust baseline. A live observation is always just a candidate.
        self._load_baseline()
        current = self._collect()
        entry_count = len(current or {})
        if current is not None:
            self._evaluate_cache(current)

        self.emit(
            "ARP Watchdog active — live ARP inventory collected.",
            Severity.INFO,
            observed_entries=entry_count,
            approved_baseline_entries=len(self._baseline),
            baseline_status=self._baseline_status,
        )
        self._set_coverage_health()

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
        current = self._collect()
        if current is None:
            self._set_coverage_health()
            return
        self._evaluate_cache(current)
        self._set_coverage_health()

    def _evaluate_cache(self, current: dict[str, str]) -> None:
        """Compare a complete observation without ever auto-enrolling it."""
        for ip, mac in current.items():
            baseline_mac = self._baseline.get(ip)
            if baseline_mac is None:
                key = (ip, mac)
                if key in self._unknown_alerted:
                    continue
                self._unknown_alerted.add(key)
                self.emit(
                    "Unapproved ARP mapping observed; review before baseline approval",
                    Severity.MEDIUM,
                    ip=ip,
                    current_mac=mac,
                    baseline_status=self._baseline_status,
                    local_network_identifiers_omitted=True,
                    mitre_tags=["T1557.002", "T1040"],
                )
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
                "ARP cache mapping changed — possible Man-in-the-Middle attack "
                "(T1557.002)",
                Severity.CRITICAL,
                ip=ip,
                original_mac=baseline_mac,
                current_mac=mac,
                local_network_identifiers_omitted=True,
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
                    self._set_coverage_health()
                    return
                if self._capture_is_active_locked():
                    if (
                        self._scapy_stop_event is not None
                        and not self._scapy_stop_event.is_set()
                    ):
                        # Duplicate start request for this run; the current
                        # capture already provides real-time coverage.
                        self._set_coverage_health()
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
                self._set_coverage_health()
                return
            self.emit("ARP Watchdog: scapy sniffer active (real-time mode).", Severity.INFO)
            self._set_coverage_health()
        except ImportError:
            self.emit(
                "ARP Watchdog: scapy not installed — running poll-only mode. "
                "pip install scapy for real-time ARP detection.",
                Severity.INFO,
                scapy_available=False,
            )
            self._set_coverage_health()
        except Exception as exc:
            with self._scapy_lock:
                if capture_stop is not None and self._scapy_stop_event is capture_stop:
                    self._clear_capture_locked()
            self.emit(
                f"ARP Watchdog: scapy sniffer failed to start ({exc}) — poll-only mode.",
                Severity.INFO,
                scapy_available=False,
            )
            self._set_coverage_health()

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
                    # A packet capture is evidence, never implicit trust. Keep
                    # it as an untrusted candidate until an operator approves a
                    # complete successful cache snapshot.
                    self._candidate[sender_ip] = sender_mac
                    key = (sender_ip, sender_mac)
                    if key in self._unknown_alerted:
                        return
                    self._unknown_alerted.add(key)
                    self.emit(
                        "Unapproved real-time ARP mapping observed; review before "
                        "baseline approval",
                        Severity.MEDIUM,
                        ip=sender_ip,
                        claimed_mac=sender_mac,
                        baseline_status=self._baseline_status,
                        realtime=True,
                        local_network_identifiers_omitted=True,
                        mitre_tags=["T1557.002", "T1040"],
                    )
                    return
                if sender_mac == baseline_mac:
                    return
                if self._alerted.get(sender_ip) == sender_mac:
                    return

                self._alerted[sender_ip] = sender_mac
                self.emit(
                    "Real-time gratuitous ARP mapping change detected (T1557.002)",
                    Severity.CRITICAL,
                    ip=sender_ip,
                    claimed_mac=sender_mac,
                    baseline_mac=baseline_mac,
                    realtime=True,
                    local_network_identifiers_omitted=True,
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
            self._set_coverage_health()

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
            self._set_coverage_health()
            return
        if already_stopping:
            self._scapy_ok = False
            self._set_coverage_health()
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
        self._set_coverage_health()

    def self_test(self) -> tuple[bool, str]:
        # Hermetic: self-tests must not infer coverage from mutable live host
        # state or fail merely because the host has an empty ARP cache.
        sample = "  192.0.2.1  00:11:22:33:44:55  dynamic"
        match = _RE_ARP.search(sample)
        if match is None or _normalise_mac(match.group(2)) != "00-11-22-33-44-55":
            return False, "ARP parser invariant failed"
        mode = "scapy+poll" if self._scapy_ok else "poll-only"
        return True, f"ARP parser ready — mode={mode}; baseline={self._baseline_status}"


def register() -> ARPWatchdogModule:
    return ARPWatchdogModule()
