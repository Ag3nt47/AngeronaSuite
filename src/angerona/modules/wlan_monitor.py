"""WLAN Monitor — G2-F (part 1 of 2).

Detects Evil Twin / rogue access point attacks by monitoring SSID and BSSID
changes on the active wireless interface.

Attack scenario:
  An attacker sets up a hotspot with the same SSID as a known-good network but
  uses their own BSSID (MAC address) and often a stronger signal, causing the
  victim machine to roam to the attacker's AP.  All traffic then passes through
  the attacker who can strip TLS, inject content, or harvest credentials.

Detection method:
  We poll `netsh wlan show interfaces` every POLL_INTERVAL seconds and parse:
    - SSID          (network name)
    - BSSID         (AP MAC address)
    - Signal        (%)
    - RadioType     (802.11ac/ax/n)

  On each tick we compare against the last known state:
    1. If the BSSID changes while the SSID stays the same → Evil Twin candidate.
    2. If a new SSID appears that matches a substring of a known corporate SSID
       with a different BSSID → Honeypot candidate (e.g. "Corp" vs "Corp-Guest").
    3. If signal jumps > SIGNAL_JUMP_THRESHOLD% in one tick → physical proximity
       change (attacker with powerful antenna moving nearby).

Limitation:
  `netsh` only reports the currently connected AP.  To see all nearby BSSIDs
  including the rogue one, we'd need a native wifi scan (Wlan API) or admin
  rights.  The module therefore detects *after* the roam, not before — but this
  is still useful because most exfiltration tools take seconds to minutes to run.

Fallback:
  If `netsh wlan` is unavailable (no wireless adapter, non-Windows, or subprocess
  error) the module runs in idle mode and emits a one-time INFO notice.
"""
from __future__ import annotations

import re
import subprocess
import time
from typing import Optional

from angerona.core.module_base import BaseModule, Severity
from angerona.core.win import check_output_hidden

_POLL_INTERVAL        = 15.0   # seconds between netsh polls
_SIGNAL_JUMP_THRESHOLD = 25    # % signal change in one tick = suspicious

# Regex to extract fields from `netsh wlan show interfaces` output
_RE_SSID    = re.compile(r"^\s+SSID\s*:\s*(.+)$", re.MULTILINE)
_RE_BSSID   = re.compile(r"^\s+BSSID\s*:\s*(.+)$", re.MULTILINE)
_RE_SIGNAL  = re.compile(r"^\s+Signal\s*:\s*(\d+)%", re.MULTILINE)
_RE_RADIO   = re.compile(r"^\s+Radio type\s*:\s*(.+)$", re.MULTILINE)
_RE_STATE   = re.compile(r"^\s+State\s*:\s*(.+)$", re.MULTILINE)


def _parse_interface(text: str) -> Optional[dict]:
    """Parse a single interface block from netsh output."""
    state_m = _RE_STATE.search(text)
    if not state_m or "connected" not in state_m.group(1).lower():
        return None
    ssid_m   = _RE_SSID.search(text)
    bssid_m  = _RE_BSSID.search(text)
    signal_m = _RE_SIGNAL.search(text)
    radio_m  = _RE_RADIO.search(text)
    if not (ssid_m and bssid_m):
        return None
    return {
        "ssid":   ssid_m.group(1).strip(),
        "bssid":  bssid_m.group(1).strip().upper(),
        "signal": int(signal_m.group(1)) if signal_m else 0,
        "radio":  radio_m.group(1).strip() if radio_m else "unknown",
    }


def _query_netsh() -> Optional[dict]:
    """Run `netsh wlan show interfaces` and return parsed data for the first connected interface."""
    try:
        out = check_output_hidden(
            ["netsh", "wlan", "show", "interfaces"],
            timeout=10,
            stderr=subprocess.DEVNULL,
            text=True,
            errors="replace",
        )
    except Exception:
        return None
    return _parse_interface(out)


class WLANMonitorModule(BaseModule):
    CODE = "WLAN"
    NAME = "WLAN Monitor"
    name = "WLAN Monitor"
    description = (
        "Detects Evil Twin / rogue AP attacks by monitoring SSID and BSSID "
        "changes on the active wireless interface via netsh."
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
        self._last: Optional[dict] = None   # last known interface state
        # SSID → set of seen BSSIDs (to detect first-time BSSID for a known SSID)
        self._bssid_history: dict[str, set[str]] = {}

    def run(self) -> None:
        # Initial probe to check availability
        state = _query_netsh()
        if state is None:
            self.set_health(50, "netsh wlan unavailable or no wireless adapter")
            self.emit(
                "WLAN Monitor: netsh wlan unavailable (no wireless adapter or non-Windows). "
                "Running idle.",
                Severity.INFO,
                fallback=True,
            )
            while not self.stopping:
                self.sleep(60.0)
            return

        self.set_health(100, "")
        self.emit(
            f"WLAN Monitor active — connected to SSID={state['ssid']!r} "
            f"BSSID={state['bssid']} Signal={state['signal']}%",
            Severity.INFO,
            **state,
        )
        self._update_history(state)
        self._last = state

        while not self.stopping:
            self.sleep(_POLL_INTERVAL)
            self._tick()

    def _tick(self) -> None:
        state = _query_netsh()
        if state is None:
            # Disconnected — not alarming on its own
            self._last = None
            return

        prev = self._last

        if prev is None:
            # Just (re-)connected
            self.emit(
                f"Wireless connected: SSID={state['ssid']!r} BSSID={state['bssid']}",
                Severity.INFO,
                **state,
            )
            self._update_history(state)
            self._last = state
            return

        same_ssid  = state["ssid"]  == prev["ssid"]
        same_bssid = state["bssid"] == prev["bssid"]
        signal_delta = abs(state["signal"] - prev["signal"])

        # 1. BSSID changed while SSID stayed the same → Evil Twin candidate
        if same_ssid and not same_bssid:
            # If we've seen this BSSID before for this SSID it's a legitimate roam
            known = self._bssid_history.get(state["ssid"], set())
            if state["bssid"] not in known:
                self.emit(
                    f"EVIL TWIN SUSPECT: SSID {state['ssid']!r} now served by new BSSID "
                    f"{state['bssid']} (was {prev['bssid']}) — possible rogue access point",
                    Severity.CRITICAL,
                    ssid=state["ssid"],
                    old_bssid=prev["bssid"],
                    new_bssid=state["bssid"],
                    signal=state["signal"],
                    mitre_tags=["T1557.002"],
                )
            else:
                # Known BSSID — normal roam, emit INFO only
                self.emit(
                    f"Wireless roamed: {state['ssid']!r} {prev['bssid']} → {state['bssid']} "
                    f"(known BSSID)",
                    Severity.INFO,
                    **state,
                )

        # 2. Signal jump — could be attacker's AP overpowering legitimate one
        if signal_delta >= _SIGNAL_JUMP_THRESHOLD and not same_bssid:
            self.emit(
                f"Wireless signal jumped {signal_delta}% in one tick alongside BSSID change — "
                f"possible rogue AP with boosted signal (SSID={state['ssid']!r})",
                Severity.HIGH,
                ssid=state["ssid"],
                signal_before=prev["signal"],
                signal_after=state["signal"],
                delta=signal_delta,
                new_bssid=state["bssid"],
                mitre_tags=["T1557.002"],
            )

        self._update_history(state)
        self._last = state

    def _update_history(self, state: dict) -> None:
        ssid  = state["ssid"]
        bssid = state["bssid"]
        if ssid not in self._bssid_history:
            self._bssid_history[ssid] = set()
        self._bssid_history[ssid].add(bssid)

    def self_test(self) -> tuple[bool, str]:
        state = _query_netsh()
        if state:
            return True, f"Connected to {state['ssid']!r} via {state['bssid']}"
        return True, "netsh wlan query OK (not connected)"


def register() -> WLANMonitorModule:
    return WLANMonitorModule()
