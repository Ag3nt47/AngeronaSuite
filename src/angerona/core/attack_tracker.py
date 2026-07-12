"""
core/attack_tracker.py — live MITRE ATT&CK heat tracker.

Every event on the EventBus is inspected for MITRE technique tags; each hit
increments a per-technique counter and refreshes a time-decay heat score.
The result is a point-in-time snapshot consumed by gui/attack_heatmap.py.

Local-first: no network calls, no cloud egress.  Thread-safe: all writes are
inside the subscriber callback (called from the EventBus thread); reads grab a
copy via snapshot() which is called from the GUI thread.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Sequence

# ── 14-tactic order (ATT&CK Enterprise v14) ─────────────────────────────────
TACTIC_ORDER: list[tuple[str, str]] = [
    ("TA0043", "Recon"),
    ("TA0042", "Resource Dev"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Priv Esc"),
    ("TA0005", "Def Evasion"),
    ("TA0006", "Cred Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Move"),
    ("TA0009", "Collection"),
    ("TA0011", "C2"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]

# ── Curated technique catalog: (tid, short_label, tactic_id, full_name) ─────
# ~86 high-signal techniques commonly seen in endpoint telemetry.
# Each technique appears under its PRIMARY tactic only.
TECHNIQUE_CATALOG: list[tuple[str, str, str, str]] = [
    # ── TA0043 Reconnaissance ────────────────────────────────────────────────
    ("T1595",     "Active Scan",     "TA0043", "Active Scanning"),
    ("T1592",     "Host Info",       "TA0043", "Gather Victim Host Information"),
    ("T1589",     "Identity Info",   "TA0043", "Gather Victim Identity Information"),
    ("T1590",     "Network Info",    "TA0043", "Gather Victim Network Information"),
    ("T1591",     "Org Info",        "TA0043", "Gather Victim Org Information"),
    # ── TA0042 Resource Development ─────────────────────────────────────────
    ("T1583",     "Acquire Infra",   "TA0042", "Acquire Infrastructure"),
    ("T1584",     "Comp Infra",      "TA0042", "Compromise Infrastructure"),
    ("T1587",     "Dev Capab",       "TA0042", "Develop Capabilities"),
    ("T1588",     "Obtain Capab",    "TA0042", "Obtain Capabilities"),
    # ── TA0001 Initial Access ────────────────────────────────────────────────
    ("T1190",     "Exploit Pub Svc", "TA0001", "Exploit Public-Facing Application"),
    ("T1566",     "Phishing",        "TA0001", "Phishing"),
    ("T1566.001", "Spearphish Att",  "TA0001", "Spearphishing Attachment"),
    ("T1078",     "Valid Accounts",  "TA0001", "Valid Accounts"),
    ("T1133",     "Ext Remote Svc",  "TA0001", "External Remote Services"),
    ("T1189",     "Drive-by Comp",   "TA0001", "Drive-by Compromise"),
    # ── TA0002 Execution ─────────────────────────────────────────────────────
    ("T1059.001", "PowerShell",      "TA0002", "PowerShell"),
    ("T1059.003", "Windows CMD",     "TA0002", "Windows Command Shell"),
    ("T1059.005", "VBScript",        "TA0002", "Visual Basic"),
    ("T1047",     "WMI",             "TA0002", "Windows Management Instrumentation"),
    ("T1053.005", "Sched Task",      "TA0002", "Scheduled Task/Job: Scheduled Task"),
    ("T1106",     "Native API",      "TA0002", "Native API"),
    ("T1204",     "User Exec",       "TA0002", "User Execution"),
    ("T1569.002", "Svc Exec",        "TA0002", "System Services: Service Execution"),
    ("T1559",     "IPC",             "TA0002", "Inter-Process Communication"),
    # ── TA0003 Persistence ───────────────────────────────────────────────────
    ("T1547.001", "Run Key",         "TA0003", "Registry Run Keys / Startup Folder"),
    ("T1543.003", "Win Service",     "TA0003", "Create/Modify Windows Service"),
    ("T1546.003", "WMI Event Sub",   "TA0003", "WMI Event Subscription"),
    ("T1574.001", "DLL Search",      "TA0003", "DLL Search Order Hijacking"),
    ("T1505.003", "Web Shell",       "TA0003", "Server Software: Web Shell"),
    ("T1136",     "Create Account",  "TA0003", "Create Account"),
    # ── TA0004 Privilege Escalation ──────────────────────────────────────────
    ("T1134",     "Token Manip",     "TA0004", "Access Token Manipulation"),
    ("T1134.001", "Token Impersn",   "TA0004", "Token Impersonation/Theft"),
    ("T1548.002", "UAC Bypass",      "TA0004", "Bypass User Account Control"),
    ("T1055",     "Proc Inject",     "TA0004", "Process Injection"),
    ("T1068",     "Exploit Vuln",    "TA0004", "Exploitation for Privilege Escalation"),
    ("T1078.003", "Local Accounts",  "TA0004", "Valid Accounts: Local Accounts"),
    # ── TA0005 Defense Evasion ───────────────────────────────────────────────
    ("T1036",     "Masquerade",      "TA0005", "Masquerading"),
    ("T1027",     "Obfuscation",     "TA0005", "Obfuscated Files or Information"),
    ("T1070.001", "Clear Logs",      "TA0005", "Clear Windows Event Logs"),
    ("T1070.004", "File Delete",     "TA0005", "File Deletion"),
    ("T1112",     "Mod Registry",    "TA0005", "Modify Registry"),
    ("T1562.001", "Disable Tools",   "TA0005", "Disable or Modify Tools"),
    ("T1218",     "Signed Binary",   "TA0005", "System Binary Proxy Execution"),
    ("T1140",     "Deobfuscate",     "TA0005", "Deobfuscate/Decode Files or Info"),
    ("T1564.001", "Hidden Files",    "TA0005", "Hidden Files and Directories"),
    ("T1553.004", "Install Cert",    "TA0005", "Install Root Certificate"),
    # ── TA0006 Credential Access ─────────────────────────────────────────────
    ("T1003.001", "LSASS Dump",      "TA0006", "LSASS Memory"),
    ("T1003.003", "NTDS.dit",        "TA0006", "NTDS"),
    ("T1110",     "Brute Force",     "TA0006", "Brute Force"),
    ("T1552.001", "Creds Files",     "TA0006", "Credentials In Files"),
    ("T1558.003", "Kerberoast",      "TA0006", "Kerberoasting"),
    ("T1056.001", "Keylogging",      "TA0006", "Keylogging"),
    ("T1187",     "LLMNR Poison",    "TA0006", "Forced Authentication"),
    ("T1649",     "Steal Cert",      "TA0006", "Steal or Forge Authentication Certs"),
    # ── TA0007 Discovery ─────────────────────────────────────────────────────
    ("T1082",     "Sys Info Disc",   "TA0007", "System Information Discovery"),
    ("T1057",     "Process Disc",    "TA0007", "Process Discovery"),
    ("T1049",     "Net Conns Disc",  "TA0007", "System Network Connections Discovery"),
    ("T1083",     "File & Dir Disc", "TA0007", "File and Directory Discovery"),
    ("T1018",     "Remote Sys Disc", "TA0007", "Remote System Discovery"),
    ("T1087",     "Acct Discovery",  "TA0007", "Account Discovery"),
    ("T1016",     "Net Config Disc", "TA0007", "System Network Configuration Discovery"),
    ("T1046",     "Net Svc Disc",    "TA0007", "Network Service Discovery"),
    ("T1069",     "Perm Groups",     "TA0007", "Permission Groups Discovery"),
    ("T1217",     "Browser Info",    "TA0007", "Browser Information Discovery"),
    # ── TA0008 Lateral Movement ──────────────────────────────────────────────
    ("T1021.001", "RDP",             "TA0008", "Remote Desktop Protocol"),
    ("T1021.002", "SMB Admin Shr",   "TA0008", "SMB/Windows Admin Shares"),
    ("T1021.006", "WinRM",           "TA0008", "Windows Remote Management"),
    ("T1550.002", "Pass the Hash",   "TA0008", "Pass the Hash"),
    ("T1550.003", "Pass the Ticket", "TA0008", "Pass the Ticket"),
    ("T1534",     "Internal Spear",  "TA0008", "Internal Spearphishing"),
    ("T1080",     "Taint Shared",    "TA0008", "Taint Shared Content"),
    # ── TA0009 Collection ────────────────────────────────────────────────────
    ("T1560",     "Archive Data",    "TA0009", "Archive Collected Data"),
    ("T1074",     "Data Staged",     "TA0009", "Data Staged"),
    ("T1005",     "Local Data",      "TA0009", "Data from Local System"),
    ("T1113",     "Screenshot",      "TA0009", "Screen Capture"),
    ("T1115",     "Clipboard Data",  "TA0009", "Clipboard Data"),
    ("T1056.002", "GUI Input Cap",   "TA0009", "GUI Input Capture"),
    # ── TA0011 Command and Control ───────────────────────────────────────────
    ("T1071",     "App Layer Proto", "TA0011", "Application Layer Protocol"),
    ("T1071.004", "DNS C2",          "TA0011", "DNS"),
    ("T1095",     "Non-Std Port",    "TA0011", "Non-Standard Port"),
    ("T1105",     "Ingress Tool",    "TA0011", "Ingress Tool Transfer"),
    ("T1568",     "Dyn Resolution",  "TA0011", "Dynamic Resolution"),
    ("T1573",     "Enc Channel",     "TA0011", "Encrypted Channel"),
    ("T1090",     "Proxy",           "TA0011", "Proxy"),
    # ── TA0010 Exfiltration ──────────────────────────────────────────────────
    ("T1041",     "Exfil over C2",   "TA0010", "Exfiltration Over C2 Channel"),
    ("T1048",     "Exfil Alt Proto", "TA0010", "Exfiltration Over Alternative Protocol"),
    ("T1029",     "Sched Transfer",  "TA0010", "Scheduled Transfer"),
    ("T1567",     "Exfil Web Svc",   "TA0010", "Exfiltration Over Web Service"),
    # ── TA0040 Impact ────────────────────────────────────────────────────────
    ("T1485",     "Data Destr",      "TA0040", "Data Destruction"),
    ("T1486",     "Ransomware",      "TA0040", "Data Encrypted for Impact"),
    ("T1489",     "Service Stop",    "TA0040", "Service Stop"),
    ("T1490",     "Inhibit Recov",   "TA0040", "Inhibit System Recovery"),
    ("T1499",     "Endpoint DoS",    "TA0040", "Endpoint Denial of Service"),
    ("T1491",     "Defacement",      "TA0040", "Defacement"),
]

# Build fast lookups ─────────────────────────────────────────────────────────
_TID_TO_META: dict[str, tuple[str, str, str]] = {
    row[0]: (row[1], row[2], row[3]) for row in TECHNIQUE_CATALOG
}  # tid → (short_label, tactic_id, full_name)

_TACTIC_TO_TECHNIQUES: dict[str, list[str]] = {}
for _row in TECHNIQUE_CATALOG:
    _TACTIC_TO_TECHNIQUES.setdefault(_row[2], []).append(_row[0])

# ── ETW event kind → technique IDs ──────────────────────────────────────────
# Keys match the 'kind' field set by Angerona's detection modules.
_ETW_TAG_MAP: dict[str, list[str]] = {
    # Execution
    "powershell_exec":     ["T1059.001"],
    "cmd_exec":            ["T1059.003"],
    "vbs_exec":            ["T1059.005"],
    "wmi_exec":            ["T1047"],
    "scheduled_task":      ["T1053.005"],
    "svc_exec":            ["T1569.002"],
    "user_exec":           ["T1204"],
    # Persistence
    "run_key_write":       ["T1547.001"],
    "service_install":     ["T1543.003"],
    "wmi_event_sub":       ["T1546.003"],
    "dll_search_hijack":   ["T1574.001"],
    "account_created":     ["T1136"],
    # Privilege Escalation
    "token_elevation":     ["T1134", "T1134.001"],
    "uac_bypass":          ["T1548.002"],
    "proc_injection":      ["T1055"],
    # Defense Evasion
    "masquerade":          ["T1036"],
    "log_cleared":         ["T1070.001"],
    "file_deleted":        ["T1070.004"],
    "registry_modified":   ["T1112"],
    "tool_disabled":       ["T1562.001"],
    "signed_binary_proxy": ["T1218"],
    "hidden_file":         ["T1564.001"],
    "yara_hit":            ["T1027"],
    # Credential Access
    "lsass_access":        ["T1003.001"],
    "brute_force":         ["T1110"],
    "kerberoast":          ["T1558.003"],
    "keylog_detected":     ["T1056.001"],
    "llmnr_poison":        ["T1187"],
    # Discovery
    "sys_info_query":      ["T1082"],
    "process_enum":        ["T1057"],
    "net_conn_enum":       ["T1049"],
    "file_enum":           ["T1083"],
    "net_scan":            ["T1046"],
    "acct_enum":           ["T1087"],
    # Lateral Movement
    "smb_lateral":         ["T1021.002"],
    "rdp_connect":         ["T1021.001"],
    "winrm_exec":          ["T1021.006"],
    "pass_hash":           ["T1550.002"],
    "pass_ticket":         ["T1550.003"],
    # C2
    "dns_entropy_high":    ["T1071.004", "T1568"],
    "net_ext_conn":        ["T1071"],
    "non_std_port":        ["T1095"],
    "enc_channel":         ["T1573"],
    "ingress_tool":        ["T1105"],
    # Impact
    "ransomware_sig":      ["T1486"],
    "svc_stop":            ["T1489"],
    "shadow_delete":       ["T1490"],
    # File activity
    "file_written_sys32":  ["T1105", "T1036"],
}

# Process names → technique IDs (matched against event.data.get("process_name"))
_PROC_MAP: dict[str, list[str]] = {
    "powershell":  ["T1059.001"],
    "pwsh":        ["T1059.001"],
    "wscript":     ["T1059.005"],
    "cscript":     ["T1059.005"],
    "wmic":        ["T1047"],
    "schtasks":    ["T1053.005"],
    "mshta":       ["T1218"],
    "regsvr32":    ["T1218"],
    "rundll32":    ["T1218"],
    "msiexec":     ["T1218"],
    "certutil":    ["T1140"],
    "bitsadmin":   ["T1105"],
    "net":         ["T1087", "T1069"],
    "net1":        ["T1087", "T1069"],
    "nltest":      ["T1018"],
    "whoami":      ["T1033"],
    "ipconfig":    ["T1016"],
    "systeminfo":  ["T1082"],
    "tasklist":    ["T1057"],
    "netstat":     ["T1049"],
    "reg":         ["T1112"],
    "sc":          ["T1543.003"],
    "at":          ["T1053.005"],
    "mimikatz":    ["T1003.001", "T1550.002", "T1550.003"],
}

# ── Known threat actor → technique playbooks ─────────────────────────────────
# Used by the heatmap Threat Actor filter to dim non-playbook cells and
# highlight the intersection of actor TTPs with live heat data.
THREAT_ACTOR_PLAYBOOKS: dict[str, list[str]] = {
    "APT29 (Cozy Bear)": [
        # Spearphishing → persistence → living-off-the-land C2
        "T1566", "T1566.001", "T1078", "T1059.001", "T1053.005",
        "T1547.001", "T1027", "T1036", "T1070.001", "T1070.004",
        "T1562.001", "T1003.001", "T1558.003", "T1082", "T1057",
        "T1083", "T1071", "T1071.004", "T1573", "T1568", "T1041",
    ],
    "Wizard Spider (Ryuk)": [
        # BazarLoader → TrickBot → Ryuk ransomware kill chain
        "T1566.001", "T1204", "T1059.001", "T1059.003", "T1047",
        "T1055", "T1548.002", "T1112", "T1562.001", "T1070.001",
        "T1003.001", "T1021.001", "T1021.002", "T1550.002",
        "T1486", "T1490", "T1489",
    ],
    "Lazarus Group": [
        # Supply-chain / watering-hole → credential theft → destructive payload
        "T1190", "T1133", "T1059.001", "T1059.003", "T1547.001",
        "T1543.003", "T1055", "T1027", "T1140", "T1218", "T1553.004",
        "T1003.001", "T1110", "T1082", "T1049", "T1083",
        "T1105", "T1573", "T1071", "T1048", "T1485", "T1486",
    ],
}


# ── Heat cell ────────────────────────────────────────────────────────────────
@dataclass
class TechniqueHeat:
    tid:      str         # "T1059.001"
    label:    str         # "PowerShell"
    tactic:   str         # "TA0002"
    fullname: str         # "PowerShell"
    count:    int   = 0
    last_ts:  float = 0.0
    event_ids: list[str] = field(default_factory=list)

    @property
    def heat(self) -> float:
        """0.0–1.0.  Log-weighted count, 24-hour exponential time decay."""
        if self.count == 0:
            return 0.0
        age_h  = (time.time() - self.last_ts) / 3600
        decay  = max(0.0, 1.0 - age_h / 24)
        weight = min(1.0, math.log1p(self.count) / 5)  # saturates at ~148 hits
        return round(decay * weight, 3)

    def record(self, event_id: str) -> None:
        self.count += 1
        self.last_ts = time.time()
        self.event_ids.append(event_id)
        if len(self.event_ids) > 100:
            self.event_ids = self.event_ids[-100:]


# ── Tracker ──────────────────────────────────────────────────────────────────
class AttackTracker:
    """EventBus subscriber that keeps per-technique hit counts in memory.

    Call on_event() from the bus subscriber thread; call snapshot() from the GUI
    thread.  No locking needed: the EventBus delivers events on a single daemon
    thread, and snapshot() returns a value-copy, not a reference.
    """

    def __init__(self) -> None:
        # Pre-populate cells for the whole catalog so the matrix is always full.
        self._cells: dict[str, TechniqueHeat] = {
            tid: TechniqueHeat(tid=tid, label=lbl, tactic=tac, fullname=full)
            for tid, lbl, tac, full in TECHNIQUE_CATALOG
        }

    # ── bus subscriber ───────────────────────────────────────────────────────
    def on_event(self, event) -> None:
        """Called by EventBus for every published event (bus thread)."""
        tags: list[str] = []

        # 1. Explicit MITRE tags already annotated by detection modules
        for attr in ("mitre_tags", "mitre", "attack_ids", "techniques"):
            val = getattr(event, attr, None)
            if val:
                if isinstance(val, (list, tuple, set)):
                    tags.extend(str(t) for t in val)
                elif isinstance(val, str) and val.startswith("T"):
                    tags.append(val)
                break

        # 2. Map event kind/type to techniques
        kind = str(getattr(event, "kind", "")
                   or getattr(event, "event_type", "")
                   or getattr(event, "type", ""))
        tags.extend(_ETW_TAG_MAP.get(kind, []))

        # 3. Infer from process name in event data dict
        data = getattr(event, "data", None) or {}
        if isinstance(data, dict):
            proc = str(data.get("process_name", "")
                       or data.get("image", "")
                       or data.get("proc", "")).lower()
            # Strip path and extension
            proc = proc.split("\\")[-1].split("/")[-1].replace(".exe", "")
            for key, tids in _PROC_MAP.items():
                if proc == key or proc.startswith(key):
                    tags.extend(tids)
                    break

            # LSASS access detection
            target = str(data.get("target_process", "")
                         or data.get("target", "")).lower()
            if "lsass" in target:
                tags.append("T1003.001")

        if not tags:
            return

        eid = str(getattr(event, "id", "") or getattr(event, "uuid", "") or id(event))
        for tid in set(tags):
            if tid in self._cells:
                self._cells[tid].record(eid)
            # Handle parent technique: "T1059.001" also increments "T1059"
            parent = tid.split(".")[0]
            if parent != tid and parent in self._cells:
                self._cells[parent].record(eid)

    # ── snapshot (GUI thread) ────────────────────────────────────────────────
    def snapshot(self) -> dict:
        """Return a serialisable snapshot for the heatmap widget to render."""
        now_str = time.strftime("%Y-%m-%dT%H:%M:%S")
        matrix: dict[str, dict] = {}
        for tid, cell in self._cells.items():
            matrix[tid] = {
                "label":    cell.label,
                "fullname": cell.fullname,
                "tactic":   cell.tactic,
                "heat":     cell.heat,
                "count":    cell.count,
                "last_seen": (
                    time.strftime("%Y-%m-%dT%H:%M:%S",
                                  time.localtime(cell.last_ts))
                    if cell.last_ts else None
                ),
                "event_ids": cell.event_ids[-10:],  # last 10 only
            }
        active = {tid: v for tid, v in matrix.items() if v["heat"] > 0}
        top = max(active, key=lambda t: active[t]["heat"]) if active else None
        return {
            "generated": now_str,
            "matrix": matrix,
            "summary": {
                "techniques_active": len(active),
                "tactics_active": len({v["tactic"] for v in active.values()}),
                "highest_heat_tid":   top,
                "highest_heat_label": active[top]["label"] if top else None,
            },
        }

    def reset(self) -> None:
        """Clear all counts — callable from the console."""
        for cell in self._cells.values():
            cell.count   = 0
            cell.last_ts = 0.0
            cell.event_ids.clear()


# ── Module-level singleton (mirrors RemediationLog pattern) ─────────────────
_tracker: AttackTracker | None = None


def init_tracker() -> AttackTracker:
    """Create and return the singleton tracker (call once at app startup)."""
    global _tracker
    if _tracker is None:
        _tracker = AttackTracker()
    return _tracker


def get_tracker() -> AttackTracker | None:
    """Return the singleton (None if init_tracker() not yet called)."""
    return _tracker
