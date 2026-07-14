"""core/d3fend_map.py — MITRE D3FEND countermeasure overlay for ATT&CK techniques.

The ATT&CK heatmap shows what an attacker DOES and what Angerona detects. D3FEND
is the defensive counterpart — it names the COUNTERMEASURE technique for an
offensive one. This curated map lets the heatmap show, per technique, the
defensive move that counters it (and whether Angerona already implements it),
turning the matrix into a defensive scorecard.

Curated (not scraped). Local, pure lookup.
"""
from __future__ import annotations

# technique (ATT&CK, base id) -> list of (D3FEND countermeasure, angerona_capability|None)
D3FEND: dict[str, list[tuple[str, str | None]]] = {
    "T1003": [("Credential Hardening / Local Account Monitoring", "LSASS Credential-Access Guard (CREDG)"),
              ("Process Spawn Analysis", "Process Monitor")],
    "T1055": [("Process Segment Execution Prevention", "Memory Injection Scanner (MINJ)"),
              ("Process Self-Modification Detection", None)],
    "T1071": [("Network Traffic Analysis", "C2 Beacon Detector (BEAC)"),
              ("Outbound Traffic Filtering", "SOAR network isolation")],
    "T1486": [("File Access Pattern Analysis", "Ransomware Heuristics (RANS)"),
              ("Decoy File", "Deception / canaries")],
    "T1490": [("Restore Point / Shadow-Copy Monitoring", "Shadow-Copy Guard (VSSG)")],
    "T1547": [("Startup-Item Monitoring", "Persistence Sweep")],
    "T1053": [("Scheduled-Job Analysis", "Persistence Sweep")],
    "T1546": [("Platform Monitoring (WMI subscription)", "Sysmon Listener (SYSL)")],
    "T1562": [("Security-Tool Self-Protection", "AMSI Bridge / posture hardening"),
              ("Configuration-Change Detection", "posture_hardening")],
    "T1021": [("Network Isolation", "SOAR network isolation"),
              ("Remote-Session Analysis", "Network Monitor")],
    "T1566": [("Message / Attachment Analysis", "Initial-Access marker detection")],
    "T1204": [("User-Behavior Analysis", None)],
    "T1091": [("Removable-Media Policy", "USB Monitor (USBW)")],
    "T1027": [("File Content Analysis (entropy/obfuscation)", "YARA Scanner")],
    "T1112": [("Registry-Modification Detection", "Persistence Sweep")],
    "T1074": [("Local Data Staging Detection", "Exfil-staging marker detection")],
    "T1041": [("Egress Filtering / DLP", "Network Monitor")],
    "T1548": [("UAC / Elevation Monitoring", None)],
    "T1571": [("Non-Standard-Port Analysis", "C2 Beacon Detector (BEAC)")],
}


def lookup(tid: str) -> list[dict]:
    """Return the D3FEND countermeasure(s) for a technique id (sub → base fallback)."""
    base = (tid or "").split(".")[0]
    entries = D3FEND.get(tid) or D3FEND.get(base) or []
    return [{"countermeasure": cm, "angerona": cap, "covered": cap is not None}
            for cm, cap in entries]


def summary() -> dict:
    """Coverage of the countered techniques by Angerona capabilities."""
    total = sum(len(v) for v in D3FEND.values())
    covered = sum(1 for v in D3FEND.values() for _cm, cap in v if cap is not None)
    return {"techniques_mapped": len(D3FEND), "countermeasures": total,
            "implemented": covered,
            "implemented_pct": round(100 * covered / total) if total else 0}


def self_test() -> tuple[bool, str]:
    a = lookup("T1003.001")            # sub-technique → base T1003
    b = lookup("T1486")
    s = summary()
    ok = (a and a[0]["covered"] and any("CREDG" in (x["angerona"] or "") for x in a)
          and b and b[0]["countermeasure"]
          and s["techniques_mapped"] >= 15 and 0 <= s["implemented_pct"] <= 100)
    return ok, (f"D3FEND map verified: {s['techniques_mapped']} techniques, "
                f"{s['implemented_pct']}% countermeasures implemented; T1003.001→{a[0]['countermeasure'][:30]}"
                if ok else f"failed: a={a} b={b} s={s}")
