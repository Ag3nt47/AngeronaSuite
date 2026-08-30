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

import hashlib
import hmac
import json
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from angerona.core.atomic_io import replace_with_retry
from angerona.core.data_paths import data_dir
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
_RE_AUTH    = re.compile(r"^\s+Authentication\s*:\s*(.+)$", re.MULTILINE)
_RE_CIPHER  = re.compile(r"^\s+Cipher\s*:\s*(.+)$", re.MULTILINE)
_BSSID = re.compile(r"^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$")
_BASELINE_SCHEMA = "angerona.wlan-approved-baseline.v1"
_BASELINE_SIG = "hmac_sha256"


@dataclass(frozen=True)
class _WLANQuery:
    status: str
    state: Optional[dict]
    reason: str = ""


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
        "authentication": (
            _RE_AUTH.search(text).group(1).strip() if _RE_AUTH.search(text) else "unknown"
        ),
        "cipher": (
            _RE_CIPHER.search(text).group(1).strip() if _RE_CIPHER.search(text) else "unknown"
        ),
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


def _query_wlan() -> _WLANQuery:
    """Distinguish a successful disconnected observation from collector failure."""
    try:
        out = check_output_hidden(
            ["netsh", "wlan", "show", "interfaces"],
            timeout=10,
            stderr=subprocess.DEVNULL,
            text=True,
            errors="replace",
        )
    except Exception as exc:
        return _WLANQuery("error", None, str(exc)[:300])
    parsed = _parse_interface(out)
    if parsed is not None:
        return _WLANQuery("connected", parsed)
    if _RE_STATE.search(out):
        return _WLANQuery("disconnected", None)
    return _WLANQuery("error", None, "netsh returned no parseable interface state")


class WLANMonitorModule(BaseModule):
    CODE = "WLAN"
    NAME = "WLAN Monitor"
    name = "WLAN Monitor"
    version = "1.12.1"
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
        # The last connected observation survives disconnects and collector
        # failures, preventing a reconnect from becoming a fresh trust event.
        self._last: Optional[dict] = None
        self._observed_bssids: dict[str, set[str]] = {}
        self._baseline: dict[str, object] = {
            "schema": _BASELINE_SCHEMA,
            "sequence": 0,
            "networks": {},
        }
        self._baseline_status = "unloaded"
        self._collector_failures = 0
        self._last_query_success_at = 0.0
        self._last_query_alert = ""

    @staticmethod
    def _baseline_path() -> Path:
        return data_dir() / "baselines" / "wlan-approved.json"

    @staticmethod
    def _baseline_key() -> bytes | None:
        try:
            key = bytes.fromhex((data_dir() / "bus.key").read_text(encoding="ascii").strip())
        except Exception:
            return None
        return key if len(key) == 32 else None

    @staticmethod
    def _canonical(value: dict[str, object]) -> bytes:
        body = {key: item for key, item in value.items() if key != _BASELINE_SIG}
        return json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    @staticmethod
    def _clean_security(value: object) -> str:
        return str(value).replace("\x00", "").strip()[:120] or "unknown"

    @classmethod
    def _validate_networks(cls, value: object) -> dict[str, dict[str, object]]:
        if not isinstance(value, dict) or len(value) > 64:
            raise ValueError("WLAN baseline network inventory is invalid")
        clean: dict[str, dict[str, object]] = {}
        for ssid, record in value.items():
            if (
                not isinstance(ssid, str)
                or not 1 <= len(ssid) <= 128
                or "\x00" in ssid
                or not isinstance(record, dict)
                or set(record) != {"bssids", "authentication", "cipher", "approved_at"}
            ):
                raise ValueError("WLAN baseline record is invalid")
            bssids = record["bssids"]
            if not isinstance(bssids, list) or not 1 <= len(bssids) <= 32:
                raise ValueError("WLAN baseline BSSID set is invalid")
            normalized = sorted({str(item).upper() for item in bssids})
            if len(normalized) != len(bssids) or any(not _BSSID.fullmatch(item) for item in normalized):
                raise ValueError("WLAN baseline BSSID is invalid")
            approved_at = float(record["approved_at"])
            if not 0.0 <= approved_at <= time.time() + 300.0:
                raise ValueError("WLAN baseline approval timestamp is invalid")
            clean[ssid] = {
                "bssids": normalized,
                "authentication": cls._clean_security(record["authentication"]),
                "cipher": cls._clean_security(record["cipher"]),
                "approved_at": approved_at,
            }
        return clean

    def _load_baseline(self) -> str:
        key = self._baseline_key()
        if key is None:
            self._baseline_status = "key-unavailable"
            return self._baseline_status
        try:
            raw = self._baseline_path().read_bytes()
        except FileNotFoundError:
            self._baseline_status = "new"
            return self._baseline_status
        except OSError:
            self._baseline_status = "unreadable"
            return self._baseline_status
        try:
            if len(raw) > 64 * 1024:
                raise ValueError("WLAN baseline exceeds 64 KiB")
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, dict) or set(value) != {
                "schema", "sequence", "networks", _BASELINE_SIG,
            }:
                raise ValueError("WLAN baseline schema mismatch")
            if value["schema"] != _BASELINE_SCHEMA or int(value["sequence"]) < 0:
                raise ValueError("WLAN baseline version/sequence invalid")
            expected = hmac.new(key, self._canonical(value), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(str(value[_BASELINE_SIG]), expected):
                raise ValueError("WLAN baseline authentication failed")
            networks = self._validate_networks(value["networks"])
            self._baseline = {
                "schema": _BASELINE_SCHEMA,
                "sequence": int(value["sequence"]),
                "networks": networks,
            }
        except (TypeError, ValueError, UnicodeError, json.JSONDecodeError):
            self._baseline_status = "invalid"
            return self._baseline_status
        self._baseline_status = "ok"
        return self._baseline_status

    def _save_baseline(self) -> bool:
        if self._baseline_status not in {"new", "ok"}:
            return False
        key = self._baseline_key()
        if key is None:
            self._baseline_status = "key-unavailable"
            return False
        payload = dict(self._baseline)
        payload["sequence"] = int(payload.get("sequence", 0)) + 1
        payload[_BASELINE_SIG] = hmac.new(
            key, self._canonical(payload), hashlib.sha256,
        ).hexdigest()
        path = self._baseline_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(
            f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        try:
            with temporary.open("w", encoding="utf-8", newline="\n") as handle:
                json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            replace_with_retry(temporary, path)
        except OSError as exc:
            self.last_error = str(exc)
            self._baseline_status = "write-failed"
            return False
        finally:
            temporary.unlink(missing_ok=True)
        self._baseline = {key: value for key, value in payload.items() if key != _BASELINE_SIG}
        self._baseline_status = "ok"
        return True

    def approve_current_network(self) -> tuple[bool, str]:
        """Persist an explicit approval for the exact live SSID/BSSID/security tuple."""
        state = self._last
        if state is None:
            return False, "no connected WLAN observation is available for approval"
        if self._baseline_status == "unloaded":
            self._load_baseline()
        if self._baseline_status not in {"new", "ok"}:
            return False, f"WLAN baseline is not writable ({self._baseline_status})"
        ssid = str(state.get("ssid", ""))
        bssid = str(state.get("bssid", "")).upper()
        if not ssid or not _BSSID.fullmatch(bssid):
            return False, "live WLAN identity is incomplete"
        networks = self._baseline.setdefault("networks", {})
        if not isinstance(networks, dict):
            return False, "WLAN baseline inventory is invalid"
        existing = networks.get(ssid, {})
        approved = set(existing.get("bssids", [])) if isinstance(existing, dict) else set()
        approved.add(bssid)
        if len(approved) > 32:
            return False, "approved BSSID limit reached for this SSID"
        networks[ssid] = {
            "bssids": sorted(approved),
            "authentication": self._clean_security(state.get("authentication")),
            "cipher": self._clean_security(state.get("cipher")),
            "approved_at": time.time(),
        }
        if not self._save_baseline():
            return False, f"WLAN baseline persistence failed ({self._baseline_status})"
        self.emit(
            "Operator approved the exact current WLAN identity and security tuple.",
            Severity.INFO,
            ssid=ssid,
            bssid=bssid,
            response_authorized=True,
        )
        return True, f"approved {ssid!r} via {bssid}"

    def run(self) -> None:
        baseline_status = self._load_baseline()
        if baseline_status not in {"new", "ok"}:
            self.set_health(35, f"authenticated WLAN baseline unavailable ({baseline_status})")
        self._observe_query(_query_wlan())
        while not self.stopping:
            self.sleep(_POLL_INTERVAL)
            self._tick()

    def _tick(self) -> None:
        self._observe_query(_query_wlan())

    def _observe_query(self, query: _WLANQuery) -> None:
        if query.status == "error":
            self._collector_failures += 1
            reason = query.reason or "collector returned no usable evidence"
            self.last_error = reason
            self.set_health(
                35,
                f"WLAN collector failed ({self._collector_failures} consecutive): {reason}",
            )
            if reason != self._last_query_alert:
                self._last_query_alert = reason
                self.emit(
                    f"WLAN observation failed; last connected identity retained: {reason}",
                    Severity.MEDIUM,
                    finding_code="wlan.collection.failed",
                    response_authorized=False,
                )
            return
        self._collector_failures = 0
        self._last_query_success_at = time.monotonic()
        self._last_query_alert = ""
        if query.status == "disconnected":
            self.set_health(
                70 if self._baseline_status in {"new", "ok"} else 35,
                "WLAN disconnected; last connected identity retained for reconnect validation",
            )
            return
        state = query.state
        if query.status != "connected" or not isinstance(state, dict):
            self.set_health(35, "WLAN query returned an invalid observation state")
            return

        prev = self._last
        ssid = str(state.get("ssid", ""))
        bssid = str(state.get("bssid", "")).upper()
        if not ssid or not _BSSID.fullmatch(bssid):
            self.set_health(35, "WLAN observation omitted a valid SSID/BSSID identity")
            return
        state = dict(state)
        state["bssid"] = bssid

        networks = self._baseline.get("networks", {})
        approved = networks.get(ssid) if isinstance(networks, dict) else None
        approved_bssids = (
            set(approved.get("bssids", [])) if isinstance(approved, dict) else set()
        )
        exact_approved = bssid in approved_bssids
        security_changed = bool(
            isinstance(approved, dict)
            and (
                self._clean_security(state.get("authentication"))
                != self._clean_security(approved.get("authentication"))
                or self._clean_security(state.get("cipher"))
                != self._clean_security(approved.get("cipher"))
            )
        )

        if self._baseline_status not in {"new", "ok"}:
            self.set_health(
                30,
                f"connected WLAN cannot be authenticated against baseline "
                f"({self._baseline_status})",
            )
            self.emit(
                "WLAN connected while its approved baseline is unavailable; trust withheld.",
                Severity.HIGH,
                **state,
                finding_code="wlan.baseline.unavailable",
                response_authorized=False,
            )
        elif isinstance(approved, dict) and not exact_approved:
            self.set_health(25, f"unapproved BSSID {bssid} is serving approved SSID {ssid!r}")
            self.emit(
                f"EVIL TWIN SUSPECT: approved SSID {ssid!r} reconnected through "
                f"unapproved BSSID {bssid}.",
                Severity.CRITICAL,
                ssid=ssid,
                old_bssid=(prev or {}).get("bssid"),
                new_bssid=bssid,
                mitre_tags=["T1557.002"],
                finding_code="wlan.identity.unapproved_bssid",
                response_authorized=False,
            )
        elif security_changed:
            self.set_health(25, f"WLAN security tuple changed for approved SSID {ssid!r}")
            self.emit(
                f"WLAN SECURITY DOWNGRADE SUSPECT: {ssid!r} no longer matches its "
                "operator-approved authentication/cipher tuple.",
                Severity.CRITICAL,
                ssid=ssid,
                bssid=bssid,
                authentication=state.get("authentication"),
                cipher=state.get("cipher"),
                finding_code="wlan.security.changed",
                mitre_tags=["T1557.002"],
                response_authorized=False,
            )
        elif exact_approved:
            self.set_health(100, "connected WLAN matches approved BSSID/security baseline")
        else:
            self.set_health(
                65,
                f"connected WLAN {ssid!r}/{bssid} is observed but not operator-approved",
            )
            self.emit(
                f"Unapproved WLAN observed: SSID={ssid!r} BSSID={bssid}; "
                "use explicit approval before treating it as trusted.",
                Severity.MEDIUM,
                **state,
                finding_code="wlan.identity.pending_approval",
                response_authorized=False,
            )

        if prev is not None:
            same_ssid = ssid == prev.get("ssid")
            same_bssid = bssid == prev.get("bssid")
            signal_delta = abs(int(state.get("signal", 0)) - int(prev.get("signal", 0)))
            if same_ssid and not same_bssid and not exact_approved:
                # This remains an independent live-transition signal even if
                # baseline persistence is unavailable.
                self.emit(
                    f"Wireless identity changed for {ssid!r}: {prev.get('bssid')} → {bssid}.",
                    Severity.CRITICAL,
                    ssid=ssid,
                    old_bssid=prev.get("bssid"),
                    new_bssid=bssid,
                    finding_code="wlan.identity.transition",
                    mitre_tags=["T1557.002"],
                    response_authorized=False,
                )
            if signal_delta >= _SIGNAL_JUMP_THRESHOLD and not same_bssid:
                self.emit(
                    f"Wireless signal jumped {signal_delta}% alongside BSSID change — "
                    f"possible boosted rogue AP (SSID={ssid!r})",
                    Severity.HIGH,
                    ssid=ssid,
                    signal_before=prev.get("signal"),
                    signal_after=state.get("signal"),
                    delta=signal_delta,
                    new_bssid=bssid,
                    mitre_tags=["T1557.002"],
                    response_authorized=False,
                )

        self._update_history(state)
        self._last = state

    def _update_history(self, state: dict) -> None:
        ssid  = state["ssid"]
        bssid = state["bssid"]
        if ssid not in self._observed_bssids:
            self._observed_bssids[ssid] = set()
        self._observed_bssids[ssid].add(bssid)
        if len(self._observed_bssids[ssid]) > 64:
            self._observed_bssids[ssid] = {bssid}
        if len(self._observed_bssids) > 128:
            oldest = next(iter(self._observed_bssids))
            self._observed_bssids.pop(oldest, None)

    def self_test(self) -> tuple[bool, str]:
        query = _query_wlan()
        if query.status == "connected" and query.state:
            return True, f"Connected to {query.state['ssid']!r} via {query.state['bssid']}"
        if query.status == "disconnected":
            return True, "netsh WLAN query succeeded (not connected)"
        return False, f"netsh WLAN query failed: {query.reason}"


def register() -> WLANMonitorModule:
    return WLANMonitorModule()
