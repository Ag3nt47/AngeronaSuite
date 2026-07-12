"""Deterministic Fast-Path Interceptor — G3-D.

Purpose
-------
Complements AI Triage (ai_triage.py) with a deterministic pre-filter that
fires CRITICAL alerts *immediately* for high-confidence, known-bad patterns —
without waiting for Ollama.

Why this matters:
  - Ollama has a 5s timeout (circuit breaker in ai_triage.py).  During Ollama
    downtime, definitively-malicious events still need to be escalated fast.
  - LLMs produce probabilistic output.  For well-known, unambiguous IOC patterns
    (EICAR, Mimikatz strings, known ransomware extensions), deterministic rules
    are faster, cheaper, and more reliable than asking a language model.
  - This module creates a "fast lane" for obvious threats while LLM triage
    handles ambiguous cases in the background.

Design
------
  A compiled list of ``FastPathRule`` objects is checked against every bus event
  that is HIGH or CRITICAL severity from another sensor module.  Each rule
  specifies:
    - ``pattern``   — regex compiled at startup (re.IGNORECASE)
    - ``field``     — which event attribute to test: "message", "image",
                      "command_line", or "path"
    - ``label``     — human-readable threat name
    - ``mitre``     — MITRE ATT&CK technique IDs
    - ``threshold`` — minimum severity to match against (default HIGH)

  When a rule matches, the module emits a CRITICAL event on the bus with
  ``fast_path=True`` in details so SOAR and the GUI know it bypassed AI triage.

  Dedup: the same (rule_label, event_module, pid) triple is only alerted once
  per DEDUP_TTL seconds.

Maintenance
-----------
  Add new rules to the _RULES list below.  Keep rules specific enough to avoid
  false positives — these go straight to CRITICAL without LLM review.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Optional

from angerona.core.module_base import BaseModule, Severity
from angerona.core.net_interfaces import detect_split_tunnel

DEDUP_TTL = 120.0   # seconds between repeat fast-path alerts for same triple


@dataclass(frozen=True)
class FastPathRule:
    pattern:    re.Pattern
    field:      str          # "message", "image", "command_line", "path"
    label:      str
    mitre:      tuple[str, ...]
    threshold:  Severity = Severity.HIGH


def _rule(pattern: str, field: str, label: str, mitre: list[str],
          threshold: Severity = Severity.HIGH) -> FastPathRule:
    return FastPathRule(
        pattern=re.compile(pattern, re.IGNORECASE),
        field=field,
        label=label,
        mitre=tuple(mitre),
        threshold=threshold,
    )


# ── Rule library ──────────────────────────────────────────────────────────────
# KEEP SPECIFIC.  False positives here → CRITICAL alert every time.

_RULES: list[FastPathRule] = [

    # ── Credential access ────────────────────────────────────────────────────
    _rule(
        r"sekurlsa|lsadump|mimikatz|privilege::debug|kerberos::ptt",
        "command_line", "Mimikatz / credential dumping tool", ["T1003", "T1558.003"],
    ),
    _rule(
        r"procdump.*lsass|lsass.*procdump",
        "command_line", "LSASS memory dump via ProcDump", ["T1003.001"],
    ),

    # ── Lateral movement / remote execution ─────────────────────────────────
    _rule(
        r"psexec|paexec|wmiexec|smbexec|atexec",
        "command_line", "Remote execution via PSExec/WMIExec", ["T1021.002", "T1047"],
    ),
    _rule(
        r"invoke-mimikatz|invoke-shellcode|invoke-reflectivepeinjection",
        "command_line", "PowerSploit offensive module", ["T1059.001", "T1055"],
    ),

    # ── Ransomware markers ───────────────────────────────────────────────────
    _rule(
        r"vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete",
        "command_line", "Shadow copy deletion (ransomware pre-encryption)", ["T1490"],
    ),
    _rule(
        r"bcdedit.*recoveryenabled.*no|bcdedit.*bootstatuspolicy.*ignoreallfailures",
        "command_line", "Boot recovery disabled (ransomware)", ["T1490"],
    ),
    _rule(
        r"wbadmin.*delete.*catalog",
        "command_line", "Backup catalog deletion", ["T1490"],
    ),

    # ── Defence evasion ──────────────────────────────────────────────────────
    _rule(
        r"amsiutils|amsi\.dll|amsi.*bypass|patch.*amsi|amsi.*patch",
        "command_line", "AMSI bypass attempt", ["T1562.001"],
    ),
    _rule(
        r"set-mppref.*disablerealtime.*true|add-mppreference.*exclusion",
        "command_line", "Defender real-time protection disabled/excluded", ["T1562.001"],
    ),
    _rule(
        r"netsh.*advfirewall.*allprofiles.*state.*off",
        "command_line", "Windows Firewall disabled", ["T1562.004"],
    ),

    # ── Persistence ──────────────────────────────────────────────────────────
    _rule(
        r"schtasks.*\/create.*\/sc.*(minute|hour|daily|onlogon|onstartup)",
        "command_line", "Scheduled task persistence", ["T1053.005"],
    ),
    _rule(
        r"reg.*add.*\\currentversion\\run",
        "command_line", "Registry Run key persistence", ["T1547.001"],
    ),

    # ── Exfiltration / C2 ────────────────────────────────────────────────────
    _rule(
        r"invoke-webrequest.*-outfile|certutil.*-urlcache.*-split",
        "command_line", "File download via LOLBin", ["T1105"],
    ),
    _rule(
        r"bitsadmin.*\/transfer.*http",
        "command_line", "BITS job download", ["T1197"],
    ),

    # ── Known-bad image paths ────────────────────────────────────────────────
    _rule(
        r"\\temp\\.*\.(exe|dll|ps1|vbs|hta|js)$",
        "image", "Executable from Temp directory", ["T1059", "T1204.002"],
    ),
    _rule(
        r"\\appdata\\.*\\[^\\]+\.(exe|dll)$",
        "image", "Executable from AppData", ["T1059", "T1204.002"],
    ),

    # ── EICAR test string (validates detection pipeline) ────────────────────
    _rule(
        r"EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
        "message", "EICAR AV test string detected by sensor", ["T1204"],
        Severity.MEDIUM,
    ),
]


class FastPathModule(BaseModule):
    CODE = "FPTH"
    NAME = "Deterministic Fast-Path Interceptor"
    name = "Deterministic Fast-Path Interceptor"
    description = (
        "Checks bus events against a deterministic IOC pattern library and emits "
        "CRITICAL alerts immediately — without waiting for Ollama — for high-confidence "
        "known-bad patterns."
    )
    category = "AI"

    _POLL_INTERVAL = 3.0

    def __init__(self) -> None:
        super().__init__()
        self._last_ts = 0.0
        # (rule_label, source_module, pid_str) → last_alert_ts
        self._seen: dict[tuple[str, str, str], float] = {}

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    def run(self) -> None:
        rule_count = len(_RULES)
        self.emit(
            f"Fast-Path Interceptor active — {rule_count} deterministic IOC rules loaded.",
            Severity.INFO,
            rule_count=rule_count,
        )
        self.set_health(100, "")

        while not self.stopping:
            self.sleep(self._POLL_INTERVAL)
            self._scan_bus()
            self._evict_stale_dedup()

    def _scan_bus(self) -> None:
        if self._bus is None:
            return
        for ev in self._bus.recent(50):
            if ev.ts <= self._last_ts:
                continue
            self._last_ts = max(self._last_ts, ev.ts)
            if ev.module == self.name:
                continue   # never process our own output

            self._check_event(ev)

    def _check_event(self, ev) -> None:
        # Rule #18 (behavioural, not regex): split-tunnel abuse. Only run the
        # per-PID connection scan for network-bearing events to stay cheap.
        pid_val = ev.details.get("pid")
        if pid_val is not None and ("raddr" in ev.details or "interface_type" in ev.details):
            self._check_split_tunnel(ev, pid_val)

        # Build a dict of fields we can test
        fields = {
            "message":      ev.message,
            "image":        str(ev.details.get("image", "")),
            "command_line": str(ev.details.get("command_line", "")),
            "path":         str(ev.details.get("path", "")),
        }

        for rule in _RULES:
            if ev.severity < rule.threshold:
                continue
            text = fields.get(rule.field, "")
            if not text:
                continue
            if not rule.pattern.search(text):
                continue

            # Dedup check
            pid_str = str(ev.details.get("pid", ""))
            key     = (rule.label, ev.module, pid_str)
            now     = time.time()
            if now - self._seen.get(key, 0.0) < DEDUP_TTL:
                continue
            self._seen[key] = now

            # Match — emit CRITICAL immediately
            snippet = text[:200]
            self.emit(
                f"[FAST-PATH] {rule.label}: matched in {rule.field!r} from "
                f"{ev.module} — '{snippet}' (bypassed LLM triage)",
                Severity.CRITICAL,
                fast_path=True,
                rule_label=rule.label,
                matched_field=rule.field,
                matched_text=snippet,
                source_module=ev.module,
                mitre_tags=list(rule.mitre),
                pid=ev.details.get("pid"),
            )
            break   # one rule match per event is enough

    def _check_split_tunnel(self, ev, pid) -> None:
        """FPTH rule #18 — split-tunnel abuse: one PID with concurrent connections
        over a Virtual_VPN interface AND a physical interface to an untrusted
        external host. Deterministic, deduped, fail-open."""
        try:
            pid_int = int(pid)
        except (TypeError, ValueError):
            return
        finding = detect_split_tunnel(pid_int)
        if not finding:
            return
        key = ("FPTH-18-SPLIT-TUNNEL", ev.module, str(pid_int))
        now = time.time()
        if now - self._seen.get(key, 0.0) < DEDUP_TTL:
            return
        self._seen[key] = now
        self.emit(
            f"[FAST-PATH] Split-tunnel abuse — pid {pid_int} holds concurrent VPN and "
            f"physical-external connections (bypass / exfil pattern).",
            Severity.CRITICAL,
            fast_path=True,
            rule_label="Split-tunnel abuse (VPN + physical external)",
            matched_field="connections",
            source_module=ev.module,
            mitre_tags=["T1572", "T1090"],
            pid=pid_int,
            vpn_destinations=finding.get("vpn_destinations", []),
            physical_external_destinations=finding.get("physical_external_destinations", []),
        )

    def _evict_stale_dedup(self) -> None:
        cutoff = time.time() - DEDUP_TTL
        stale  = [k for k, ts in self._seen.items() if ts < cutoff]
        for k in stale:
            del self._seen[k]

    def self_test(self) -> tuple[bool, str]:
        # Verify at least one rule matches a known string
        test_text = "sekurlsa::logonpasswords"
        for rule in _RULES:
            if rule.field == "command_line" and rule.pattern.search(test_text):
                return True, f"{len(_RULES)} rules loaded — pattern match verified"
        return False, "Pattern match self-test failed"


def register() -> FastPathModule:
    return FastPathModule()
