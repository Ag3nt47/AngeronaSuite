"""intel_sync.py — Upstream Threat Intelligence Sync Engine (Code: INTL).

Fetches the canonical CISA Known Exploited Vulnerabilities (KEV) catalog when an
internet connection is available, correlates it against this host's OS build and
running service processes, and writes any applicable matches (with the vendor's
required remediation and a MITRE technique mapping) to
``shared_logs/upstream_threats.json``.

Also provides opt-in Threat-Intel Fusion (Ring 2): when ``ANGERONA_IOC_FEED`` is
configured, it ingests a STIX/TAXII (or simple JSON) indicator feed into an
in-memory IOC cache with O(1) ``is_ip_flagged`` / ``is_hash_flagged`` lookups for
the network and process sensors. Unconfigured, it performs no network I/O.

Local-first / privacy
    The only network I/O is an inbound HTTPS GET of a PUBLIC government feed. No
    host data, process names, or system metadata ever leave the machine — the
    correlation happens locally after the catalog is downloaded.

No auto-remediation
    INTL NEVER applies a host fix. It raises a dashboard alert and stages an
    automation hook that waits for an explicit operator confirmation
    (``confirm(cve_id)``) — wired to the keyboard/console handler in ``agent.py``.

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import json
import os
import platform
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

from angerona.core.module_base import BaseModule, Severity

_KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json")

# Coarse product/vendor -> MITRE technique hints (KEV records don't carry ATT&CK).
_MITRE_HINTS = {
    "windows": "T1210 / T1068 (exploit + privilege escalation)",
    "exchange": "T1190 (exploit public-facing app)",
    "chrome": "T1203 (client execution)",
    "edge": "T1203 (client execution)",
    "office": "T1203 (client execution)",
    "netlogon": "T1210 (remote services exploit)",
    "print spooler": "T1068 (local privilege escalation)",
    "smb": "T1210 (remote services exploit)",
    "rdp": "T1210 (remote services exploit)",
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


# -- Ring 1: Driver-Intel Shield ----------------------------------------------
# Offline, bundled reference set of publicly-documented drivers abused in real
# BYOVD (Bring Your Own Vulnerable Driver) attacks. Public threat-intel data;
# lets FIM/Process Monitor flag a driver drop WITHOUT any network call.
KNOWN_BAD_DRIVERS = {
    "rtcore64.sys":  "MSI Afterburner RTCore64 - arbitrary R/W (CVE-2019-16098)",
    "dbutil_2_3.sys": "Dell DBUtil - arbitrary R/W (CVE-2021-21551)",
    "gdrv.sys":      "Gigabyte GDrv - arbitrary R/W",
    "capcom.sys":    "Capcom - arbitrary kernel exec",
    "procexp152.sys": "spoofed Process Explorer helper - commonly abused",
    "aswarpot.sys":  "Avast anti-rootkit - abused for process termination",
    "mhyprot2.sys":  "Genshin anti-cheat - abused to kill AV/EDR",
    "winring0x64.sys": "WinRing0 - arbitrary MSR/port I/O",
}

BYOVD_DRILL_MARKER = "ANGERONA-BYOVD-DRILL-BENIGN-MARKER"
BYOVD_DRILL_DRIVER = "angerona_byovd_drill.sys"


def is_known_bad_driver(name: str = "", sha256: str = "") -> dict | None:
    """Direct cross-module lookup (used by FIM / Process Monitor - no orchestrator).
    Returns a match dict for a known-vulnerable driver name, or the benign drill
    driver, else None. Name match is case-insensitive on the basename."""
    base = os.path.basename(str(name).replace("\\", "/")).lower().strip()
    if base == BYOVD_DRILL_DRIVER:
        return {"driver": base, "reason": "Angerona BYOVD drill (benign simulation)",
                "drill": True}
    if base in KNOWN_BAD_DRIVERS:
        return {"driver": base, "reason": KNOWN_BAD_DRIVERS[base], "drill": False}
    return None


# -- Ring 2: Threat-Intel Fusion (STIX/TAXII IOC cache) -----------------------
# Opt-in indicator fusion. When ``ANGERONA_IOC_FEED`` is set to a URL returning
# either a STIX 2.x bundle or a simple ``{"ips":[...],"hashes":[...]}`` JSON,
# INTL ingests it on its sync cadence into O(1)-lookup sets that the network and
# process sensors can consult directly. With no feed configured this stays empty
# and performs ZERO network I/O - honouring the same inbound-only model as KEV.
_IOC_LOCK = threading.Lock()
_IOC_IPS: set[str] = set()
_IOC_HASHES: set[str] = set()
_IOC_LAST_UPDATE = 0.0


def is_ip_flagged(ip: str) -> bool:
    """Fast (O(1)) lookup for the network sensor - is this IP a known IOC?"""
    with _IOC_LOCK:
        return str(ip) in _IOC_IPS


def is_hash_flagged(file_hash: str) -> bool:
    """Fast (O(1)) lookup for the process/FIM sensor - is this hash a known IOC?"""
    with _IOC_LOCK:
        return str(file_hash).lower() in _IOC_HASHES


def ioc_stats() -> dict:
    with _IOC_LOCK:
        return {"ips": len(_IOC_IPS), "hashes": len(_IOC_HASHES),
                "last_update": _IOC_LAST_UPDATE}


def _parse_iocs(payload) -> tuple[set[str], set[str]]:
    """Extract IPs + SHA-256 file hashes from a STIX 2.x bundle or a simple
    ``{"ips":[...],"hashes":[...]}`` JSON. Defensive: unknown shapes yield empty
    sets rather than raising."""
    ips: set[str] = set()
    hashes: set[str] = set()
    try:
        if isinstance(payload, dict) and payload.get("type") == "bundle":
            for obj in payload.get("objects", []):
                if not isinstance(obj, dict) or obj.get("type") != "indicator":
                    continue
                patt = str(obj.get("pattern", ""))
                ips.update(re.findall(r"ipv4-addr:value\s*=\s*'([^']+)'", patt))
                ips.update(re.findall(r"ipv6-addr:value\s*=\s*'([^']+)'", patt))
                hashes.update(h.lower() for h in
                              re.findall(r"file:hashes\.'?SHA-?256'?\s*=\s*'([^']+)'", patt))
        elif isinstance(payload, dict):
            ips.update(str(x) for x in payload.get("ips", []) if x)
            hashes.update(str(x).lower() for x in payload.get("hashes", []) if x)
    except Exception:
        pass
    return ips, hashes


class IntelSyncModule(BaseModule):
    CODE = "INTL"
    NAME = "intel_sync"
    name = "Upstream Threat Intel Sync"
    description = ("Correlates the CISA KEV catalog against this host's OS + running "
                   "services; stages review-gated remediation, never auto-applies.")
    category = "Threat Intel"
    version = "1.0.0"

    _INTERVAL = 6 * 3600.0     # re-sync every 6h

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._out = _repo_root() / "shared_logs" / "upstream_threats.json"
        self.alert_pending = False
        self._pending_confirm: dict[str, dict] = {}

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    @staticmethod
    def _online() -> bool:
        try:
            with socket.create_connection(("1.1.1.1", 443), timeout=3):
                return True
        except Exception:
            return False

    def _fetch_kev(self) -> list[dict]:
        """Inbound-only GET of the public KEV catalog (no host data sent)."""
        import urllib.request
        req = urllib.request.Request(_KEV_URL, headers={"User-Agent": "AngeronaSuite/INTL"})
        with urllib.request.urlopen(req, timeout=30) as r:   # nosec - public gov feed
            data = json.loads(r.read().decode("utf-8", "ignore"))
        return data.get("vulnerabilities", []) if isinstance(data, dict) else []

    @staticmethod
    def _host_tokens() -> set[str]:
        tokens = {"windows", platform.system().lower(), platform.release().lower()}
        if psutil is not None:
            for p in psutil.process_iter(["name"]):
                nm = (p.info.get("name") or "").lower().replace(".exe", "")
                if nm:
                    tokens.add(nm)
        return {t for t in tokens if t}

    @classmethod
    def _mitre_for(cls, text: str) -> str:
        low = text.lower()
        for key, tech in _MITRE_HINTS.items():
            if key in low:
                return tech
        return "T1190 / T1203 (review - map to observed vector)"

    @classmethod
    def match_kev(cls, kev: list[dict], tokens: set[str]) -> list[dict]:
        """Isolate KEV records whose vendor/product matches something on this host."""
        matches = []
        for rec in kev:
            hay = f"{rec.get('vendorProject','')} {rec.get('product','')}".lower()
            hit = next((t for t in tokens if len(t) >= 4 and t in hay), None)
            if not hit:
                continue
            matches.append({
                "cve": rec.get("cveID"),
                "vendor": rec.get("vendorProject"),
                "product": rec.get("product"),
                "name": rec.get("vulnerabilityName"),
                "matched_on": hit,
                "date_added": rec.get("dateAdded"),
                "remediation": rec.get("requiredAction"),
                "due_date": rec.get("dueDate"),
                "mitre": cls._mitre_for(hay + " " + (rec.get("vulnerabilityName") or "")),
                "ransomware": rec.get("knownRansomwareCampaignUse"),
            })
        return matches

    def _write(self, matches: list[dict]) -> None:
        payload = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                   "source": "CISA KEV", "match_count": len(matches),
                   "auto_applied": False,
                   "matches": matches}
        try:
            self._out.parent.mkdir(parents=True, exist_ok=True)
            with self.state_lock:
                self._out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
                self._pending_confirm = {m["cve"]: m for m in matches if m.get("cve")}
        except Exception as exc:
            self.last_error = str(exc)

    @staticmethod
    def _technique_from(rec: dict) -> str:
        """Pull the leading MITRE technique id (e.g. T1210) out of the mapping."""
        m = re.search(r"\bT\d{4}(?:\.\d{3})?\b", str(rec.get("mitre", "")))
        return m.group(0) if m else "T1190"

    def _judgment_verify(self, technique_id: str) -> str:
        """Task the Judgment module to run ONE mock footprint test of this
        technique and prove the local EDR/NDR can intercept it before the rule is
        promoted to active. Returns BLOCKED / SUCCESS / ERROR."""
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "angerona.shark.verify", technique_id, "--verify"],
                capture_output=True, text=True, timeout=120)
            buf = (proc.stdout or "") + "\n" + (proc.stderr or "")
        except Exception as exc:
            return f"ERROR ({exc})"
        for line in buf.splitlines():
            if "VERIFICATION_RESULT:" in line:
                return line.split("VERIFICATION_RESULT:", 1)[1].strip().split()[0]
        return "ERROR"

    def _refresh_iocs(self) -> None:
        """Ingest an external STIX/TAXII (or simple JSON) IOC feed into the shared
        in-memory cache. No-op with ZERO network I/O when ANGERONA_IOC_FEED is
        unset. Inbound-only GET; no host data is sent."""
        global _IOC_LAST_UPDATE
        feed = (os.environ.get("ANGERONA_IOC_FEED") or "").strip()
        if not feed:
            return
        try:
            import urllib.request
            req = urllib.request.Request(feed, headers={"User-Agent": "AngeronaSuite/INTL-IOC"})
            with urllib.request.urlopen(req, timeout=20) as r:   # nosec - operator-configured feed
                payload = json.loads(r.read().decode("utf-8", "ignore"))
            ips, hashes = _parse_iocs(payload)
            with _IOC_LOCK:
                _IOC_IPS.update(ips)
                _IOC_HASHES.update(hashes)
                _IOC_LAST_UPDATE = time.time()
            if ips or hashes:
                self.emit(f"IOC fusion: ingested {len(ips)} IP(s) + {len(hashes)} hash(es) "
                          f"from configured feed (total {len(_IOC_IPS)}/{len(_IOC_HASHES)}).",
                          Severity.INFO, ips=len(ips), hashes=len(hashes))
        except Exception as exc:
            self.last_error = f"IOC feed: {exc}"

    def confirm(self, cve_id: str, run_verification: bool = True) -> dict:
        """Called by agent.py's handler AFTER the operator explicitly confirms.
        Stages (does NOT run) the remediation guidance, then - only with explicit
        approval - runs a single Judgment mock-footprint test. Never applies a
        host fix."""
        with self.state_lock:
            rec = self._pending_confirm.get(cve_id)
        if not rec:
            return {"ok": False, "error": f"no pending KEV match for {cve_id}"}
        self.emit(f"Operator confirmed handling of {cve_id} - remediation staged for review.",
                  Severity.INFO, cve=cve_id, mitre=rec.get("mitre"))
        result = {"ok": True, "cve": cve_id, "staged": True,
                  "remediation": rec.get("remediation"), "note": "review-gated; not executed"}
        if run_verification:
            tid = self._technique_from(rec)
            verdict = self._judgment_verify(tid)
            promoted = verdict == "BLOCKED"
            result.update({"technique": tid, "verification": verdict, "promoted": promoted})
            with self.state_lock:
                rec["verified"] = verdict
                rec["active"] = promoted
            if promoted:
                self.emit(f"{cve_id}/{tid} intercept PROVEN (Judgment BLOCKED) - detection "
                          f"rule promoted to active.", Severity.INFO, cve=cve_id, technique=tid)
            else:
                self.emit(f"{cve_id}/{tid} verification returned {verdict} - rule NOT promoted "
                          f"(suite could not prove interception).", Severity.HIGH,
                          cve=cve_id, technique=tid, verified=verdict)
        return result

    def run(self) -> None:
        self.emit("INTL online - will correlate CISA KEV against this host.", Severity.INFO)
        while not self.stopping:
            if not self._online():
                self.set_health(70, "offline - using last cached KEV correlation")
                self.sleep(120)
                continue

            _done = threading.Event()
            _result: dict = {}

            def _fetch_worker() -> None:
                try:
                    kev  = self._fetch_kev()
                    hits = self.match_kev(kev, self._host_tokens())
                    self._write(hits)
                    _result["kev_count"] = len(kev)
                    _result["matches"]   = hits
                except Exception as exc:
                    _result["error"] = str(exc)
                finally:
                    _done.set()

            t = threading.Thread(target=_fetch_worker, daemon=True, name="INTL-fetch")
            t.start()

            timeout = 45.0
            waited  = 0.0
            while not _done.wait(timeout=1.0):
                if self.stopping:
                    break
                waited += 1.0
                if waited >= timeout:
                    self.set_health(75, "KEV fetch timed out")
                    break

            if "error" in _result:
                self.last_error = _result["error"]
                self.set_health(75, "KEV fetch/parse error")
            elif "matches" in _result:
                matches = _result["matches"]
                kev_count = _result.get("kev_count", 0)
                # Analyst-ignored CVEs (no fix / too vague) stay in the feed and the
                # dashboard, but are excluded from the threat level so Angerona doesn't
                # report HIGH/CRITICAL over things the operator can't action.
                try:
                    from angerona.core.cve_ignore import filter_active
                    active = filter_active(matches)
                except Exception:
                    active = matches
                ignored_n = len(matches) - len(active)
                if active:
                    self.alert_pending = True
                    note = f" ({ignored_n} ignored)" if ignored_n else ""
                    self.set_health(60, f"{len(active)} applicable KEV CVE(s){note}")
                    top = ", ".join(m["cve"] for m in active[:5] if m.get("cve"))
                    self.emit(f"{len(active)} host-applicable CISA KEV CVEs (e.g. {top}). "
                              f"Operator confirmation required before any fix.",
                              Severity.HIGH, count=len(active), cves=top, ignored=ignored_n)
                elif matches:
                    # every applicable CVE is analyst-ignored → no threat-level impact
                    self.alert_pending = False
                    self.set_health(100, f"{len(matches)} applicable KEV CVE(s), all ignored")
                else:
                    self.alert_pending = False
                    self.set_health(100, f"{kev_count} KEV records, none applicable")

            # Ring 2: refresh opt-in IOC fusion feed (no-op if unconfigured).
            self._refresh_iocs()

            self.sleep(self._INTERVAL)

    def self_test(self) -> tuple[bool, str]:
        """Offline: verify correlation + MITRE mapping on an embedded sample."""
        sample = [
            {"cveID": "CVE-2021-34527", "vendorProject": "Microsoft",
             "product": "Windows Print Spooler", "vulnerabilityName": "PrintNightmare",
             "requiredAction": "Apply updates", "dateAdded": "2021-11-03"},
            {"cveID": "CVE-2099-0000", "vendorProject": "Acme",
             "product": "NonexistentThing", "vulnerabilityName": "x"},
        ]
        matches = self.match_kev(sample, {"windows", "chrome"})
        ok = len(matches) == 1 and matches[0]["cve"] == "CVE-2021-34527" \
            and "T1" in matches[0]["mitre"]
        drv_ok = (is_known_bad_driver("C:\\Windows\\System32\\drivers\\rtcore64.sys") is not None
                  and is_known_bad_driver(BYOVD_DRILL_DRIVER) is not None
                  and is_known_bad_driver("tcpip.sys") is None)
        ok = ok and drv_ok
        s_ips, s_hashes = _parse_iocs({
            "type": "bundle", "objects": [
                {"type": "indicator", "pattern": "[ipv4-addr:value = '203.0.113.5']"},
                {"type": "indicator", "pattern": "[file:hashes.'SHA-256' = 'AABBCC']"},
            ]})
        j_ips, j_hashes = _parse_iocs({"ips": ["198.51.100.9"], "hashes": ["DDEEFF"]})
        with _IOC_LOCK:
            _IOC_IPS.update(s_ips | j_ips)
            _IOC_HASHES.update(s_hashes | j_hashes)
        ioc_ok = (is_ip_flagged("203.0.113.5") and is_ip_flagged("198.51.100.9")
                  and is_hash_flagged("aabbcc") and is_hash_flagged("DDEEFF")
                  and not is_ip_flagged("8.8.8.8"))
        ok = ok and ioc_ok
        return (ok, "KEV correlation + driver-intel blocklist + IOC fusion verified (offline)"
                if ok else f"correlation failed: kev={matches} drv_ok={drv_ok} ioc_ok={ioc_ok}")


def register() -> IntelSyncModule:
    return IntelSyncModule()
