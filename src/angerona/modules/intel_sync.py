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

import hashlib
import hmac
import ipaddress
import json
import os
import platform
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

from angerona.core.module_base import BaseModule, Severity
from angerona.core.url_policy import (
    PUBLIC_HTTPS_POLICY,
    host_policy,
    read_bounded,
    safe_urlopen,
)

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
    from angerona.core.data_paths import data_dir
    return data_dir()


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
_IOC_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_IOC_MAX_RESPONSE_LINES = 50_000
_IOC_MAX_INDICATORS = 10_000
_IOC_TTL_SECONDS = 12 * 3600.0
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class _IocParseResult:
    ips: frozenset[str]
    hashes: frozenset[str]
    invalid_count: int
    candidate_count: int
    truncated: bool


@dataclass(frozen=True)
class _IocSnapshot:
    ips: frozenset[str] = frozenset()
    hashes: frozenset[str] = frozenset()
    updated_at: float = 0.0
    expires_at: float = 0.0
    source: str = ""
    content_sha256: str = ""
    verification: str = "none"
    verified: bool = False
    invalid_count: int = 0
    candidate_count: int = 0
    truncated: bool = False
    response_bytes: int = 0
    response_lines: int = 0


_IOC_SNAPSHOT = _IocSnapshot()


def _fresh(snapshot: _IocSnapshot, now: float | None = None) -> bool:
    return bool(snapshot.updated_at and (time.time() if now is None else now) < snapshot.expires_at)


def _literal_ip(value: object) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 64 or "%" in value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _lower_sha256(value: object) -> str | None:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        return None
    return value


def is_ip_flagged(ip: str) -> bool:
    """Return response-eligible IOC corroboration.

    Only a fresh snapshot whose exact response bytes matched an operator-pinned
    SHA-256 digest can corroborate response.  Unsigned feed content is visible
    through :func:`is_ip_advisory`, but cannot authorize containment.
    """
    candidate = _literal_ip(ip)
    if candidate is None:
        return False
    with _IOC_LOCK:
        snapshot = _IOC_SNAPSHOT
        return snapshot.verified and _fresh(snapshot) and candidate in snapshot.ips


def is_hash_flagged(file_hash: str) -> bool:
    """Return response-eligible SHA-256 IOC corroboration."""
    candidate = str(file_hash).lower() if isinstance(file_hash, str) else ""
    if _lower_sha256(candidate) is None:
        return False
    with _IOC_LOCK:
        snapshot = _IOC_SNAPSHOT
        return snapshot.verified and _fresh(snapshot) and candidate in snapshot.hashes


def is_ip_advisory(ip: str) -> bool:
    """Return a fresh IOC match regardless of feed verification status."""
    candidate = _literal_ip(ip)
    if candidate is None:
        return False
    with _IOC_LOCK:
        snapshot = _IOC_SNAPSHOT
        return _fresh(snapshot) and candidate in snapshot.ips


def is_hash_advisory(file_hash: str) -> bool:
    """Return a fresh SHA-256 match regardless of feed verification status."""
    candidate = str(file_hash).lower() if isinstance(file_hash, str) else ""
    if _lower_sha256(candidate) is None:
        return False
    with _IOC_LOCK:
        snapshot = _IOC_SNAPSHOT
        return _fresh(snapshot) and candidate in snapshot.hashes


def ioc_stats() -> dict:
    with _IOC_LOCK:
        snapshot = _IOC_SNAPSHOT
        fresh = _fresh(snapshot)
        return {
            "ips": len(snapshot.ips),
            "hashes": len(snapshot.hashes),
            "last_update": snapshot.updated_at,
            "expires_at": snapshot.expires_at,
            "fresh": fresh,
            "source": snapshot.source,
            "content_sha256": snapshot.content_sha256,
            "verification": snapshot.verification,
            "verified": snapshot.verified,
            "response_authorized": snapshot.verified and fresh,
            "candidate_count": snapshot.candidate_count,
            "invalid_count": snapshot.invalid_count,
            "truncated": snapshot.truncated,
            "response_bytes": snapshot.response_bytes,
            "response_lines": snapshot.response_lines,
        }


def _parse_ioc_snapshot(payload: object) -> _IocParseResult:
    """Parse a bounded set of literal IP and lowercase SHA-256 indicators."""
    ips: set[str] = set()
    hashes: set[str] = set()
    invalid = 0
    candidates = 0
    truncated = False

    def add(kind: str, value: object) -> bool:
        nonlocal candidates, invalid, truncated
        if candidates >= _IOC_MAX_INDICATORS:
            truncated = True
            return False
        candidates += 1
        normalized = _literal_ip(value) if kind == "ip" else _lower_sha256(value)
        if normalized is None:
            invalid += 1
        elif kind == "ip":
            ips.add(normalized)
        else:
            hashes.add(normalized)
        return True

    if not isinstance(payload, dict):
        invalid = 1
    elif payload.get("type") == "bundle":
        objects = payload.get("objects", [])
        if not isinstance(objects, list):
            invalid = 1
        else:
            for obj in objects:
                if not isinstance(obj, dict) or obj.get("type") != "indicator":
                    continue
                pattern = obj.get("pattern", "")
                if not isinstance(pattern, str) or len(pattern) > 16_384:
                    invalid += 1
                    continue
                values: list[tuple[str, str]] = []
                values.extend(("ip", match.group(1)) for match in re.finditer(
                    r"ipv4-addr:value\s*=\s*'([^']+)'", pattern))
                values.extend(("ip", match.group(1)) for match in re.finditer(
                    r"ipv6-addr:value\s*=\s*'([^']+)'", pattern))
                values.extend(("hash", match.group(1)) for match in re.finditer(
                    r"file:hashes\.'?SHA-?256'?\s*=\s*'([^']+)'", pattern))
                for kind, value in values:
                    if not add(kind, value):
                        break
                if truncated:
                    break
    else:
        for key, kind in (("ips", "ip"), ("hashes", "hash")):
            values = payload.get(key, [])
            if not isinstance(values, list):
                invalid += 1
                continue
            for value in values:
                if not add(kind, value):
                    break
            if truncated:
                break
    return _IocParseResult(
        frozenset(ips), frozenset(hashes), invalid, candidates, truncated
    )


def _parse_iocs(payload) -> tuple[set[str], set[str]]:
    """Extract IPs + SHA-256 file hashes from a STIX 2.x bundle or a simple
    ``{"ips":[...],"hashes":[...]}`` JSON. Defensive: unknown shapes yield empty
    sets rather than raising."""
    parsed = _parse_ioc_snapshot(payload)
    return set(parsed.ips), set(parsed.hashes)


def _provenance_url(feed: str) -> str:
    """Keep source provenance without persisting URL credentials or query data."""
    parsed = urlsplit(feed)
    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    try:
        port = f":{parsed.port}" if parsed.port is not None else ""
    except ValueError:
        port = ""
    return f"{parsed.scheme.lower()}://{host}{port}{parsed.path}"


class IntelSyncModule(BaseModule):
    CODE = "INTL"
    NAME = "intel_sync"
    name = "Upstream Threat Intel Sync"
    description = ("Correlates the CISA KEV catalog against this host's OS + running "
                   "services; stages review-gated remediation, never auto-applies.")
    category = "Threat Intel"
    version = "1.1.0"

    _INTERVAL = 6 * 3600.0     # re-sync every 6h

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._fetch_lock = threading.RLock()
        self._fetch_thread: threading.Thread | None = None
        self._out = _repo_root() / "shared_logs" / "upstream_threats.json"
        self.alert_pending = False
        self._pending_confirm: dict[str, dict] = {}

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    def _fetch_kev(self) -> list[dict]:
        """Inbound-only GET of the public KEV catalog (no host data sent)."""
        import urllib.request
        req = urllib.request.Request(_KEV_URL, headers={"User-Agent": "AngeronaSuite/INTL"})
        policy = host_policy("CISA KEV catalog", {"www.cisa.gov"})
        with safe_urlopen(req, policy=policy, timeout=30) as r:
            data = json.loads(read_bounded(r, 16 * 1024 * 1024).decode("utf-8", "ignore"))
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

    def _write(
        self,
        matches: list[dict],
        *,
        generation: int | None = None,
        stop_event: threading.Event | None = None,
    ) -> bool:
        payload = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                   "source": "CISA KEV", "match_count": len(matches),
                   "auto_applied": False,
                   "matches": matches}
        candidate = self._out.with_name(
            f".{self._out.name}.{os.getpid()}.{threading.get_ident()}.candidate"
        )
        try:
            self._out.parent.mkdir(parents=True, exist_ok=True)
            with self.state_lock:
                if (
                    generation is not None
                    and (
                        generation != self.lifecycle_generation
                        or (stop_event is not None and stop_event.is_set())
                        or self.status != "running"
                    )
                ):
                    return False
                with candidate.open("x", encoding="utf-8", newline="\n") as handle:
                    json.dump(payload, handle, indent=2, sort_keys=True)
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                # Recheck immediately before commit so a stopped/restarted
                # generation can never overwrite the successor's findings.
                if (
                    generation is not None
                    and (
                        generation != self.lifecycle_generation
                        or (stop_event is not None and stop_event.is_set())
                        or self.status != "running"
                    )
                ):
                    candidate.unlink(missing_ok=True)
                    return False
                os.replace(candidate, self._out)
                self._pending_confirm = {m["cve"]: m for m in matches if m.get("cve")}
                return True
        except Exception as exc:
            self.last_error = str(exc)
            try:
                candidate.unlink(missing_ok=True)
            except OSError:
                pass
            return False

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
        global _IOC_SNAPSHOT
        feed = (os.environ.get("ANGERONA_IOC_FEED") or "").strip()
        if not feed:
            return
        try:
            import urllib.request
            req = urllib.request.Request(feed, headers={"User-Agent": "AngeronaSuite/INTL-IOC"})
            with safe_urlopen(req, policy=PUBLIC_HTTPS_POLICY, timeout=20) as r:
                raw = read_bounded(r, _IOC_MAX_RESPONSE_BYTES)
            line_count = raw.count(b"\n") + 1
            if line_count > _IOC_MAX_RESPONSE_LINES:
                raise ValueError("IOC feed exceeds its line-count bound")
            payload = json.loads(raw.decode("utf-8"))
            parsed = _parse_ioc_snapshot(payload)
            digest = hashlib.sha256(raw).hexdigest()
            expected = (os.environ.get("ANGERONA_IOC_FEED_SHA256") or "").strip()
            if expected and _SHA256.fullmatch(expected) is None:
                raise ValueError("IOC feed SHA-256 pin must be 64 lowercase hex characters")
            if expected and not hmac.compare_digest(digest, expected):
                raise ValueError("IOC feed SHA-256 pin mismatch")
            verified = bool(expected) and not parsed.truncated and not parsed.invalid_count
            verification = (
                "sha256-pinned" if verified else
                "sha256-pinned-invalid-content" if expected else
                "unsigned-advisory"
            )
            now = time.time()
            snapshot = _IocSnapshot(
                ips=parsed.ips,
                hashes=parsed.hashes,
                updated_at=now,
                expires_at=now + _IOC_TTL_SECONDS,
                source=_provenance_url(feed),
                content_sha256=digest,
                verification=verification,
                verified=verified,
                invalid_count=parsed.invalid_count,
                candidate_count=parsed.candidate_count,
                truncated=parsed.truncated,
                response_bytes=len(raw),
                response_lines=line_count,
            )
            with _IOC_LOCK:
                _IOC_SNAPSHOT = snapshot
            if snapshot.ips or snapshot.hashes:
                trust = "verified, response-eligible" if verified else "advisory-only"
                self.emit(
                    f"IOC fusion: replaced snapshot with {len(snapshot.ips)} IP(s) + "
                    f"{len(snapshot.hashes)} hash(es) ({trust}).",
                    Severity.INFO,
                    ips=len(snapshot.ips),
                    hashes=len(snapshot.hashes),
                    intel_verification=verification,
                    intel_expires_at=snapshot.expires_at,
                    intel_invalid_count=snapshot.invalid_count,
                    intel_truncated=snapshot.truncated,
                    response_authorized=False,
                )
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
        generation = self.lifecycle_generation
        while not self.stopping:
            _done = threading.Event()
            _cancelled = threading.Event()
            _result: dict = {}

            def _fetch_worker() -> None:
                try:
                    kev  = self._fetch_kev()
                    hits = self.match_kev(kev, self._host_tokens())
                    committed = self._write(
                        hits, generation=generation, stop_event=_cancelled
                    )
                    if not committed:
                        _result["retired"] = True
                        return
                    _result["kev_count"] = len(kev)
                    _result["matches"]   = hits
                except Exception as exc:
                    _result["error"] = str(exc)
                finally:
                    _done.set()
                    current = threading.current_thread()
                    with self._fetch_lock:
                        if self._fetch_thread is current:
                            self._fetch_thread = None

            t = threading.Thread(target=_fetch_worker, daemon=True, name="INTL-fetch")
            with self._fetch_lock:
                self._fetch_thread = t
            t.start()

            timeout = 45.0
            waited  = 0.0
            while not _done.wait(timeout=1.0):
                if self.stopping:
                    _cancelled.set()
                    break
                waited += 1.0
                if waited >= timeout:
                    _cancelled.set()
                    self.set_health(75, "KEV fetch timed out")
                    break

            if self.stopping:
                t.join(timeout=0.25)
                if not t.is_alive():
                    with self._fetch_lock:
                        if self._fetch_thread is t:
                            self._fetch_thread = None
                return

            if "error" in _result:
                self.last_error = _result["error"]
                self.set_health(75, "KEV fetch/parse error")
            elif "matches" in _result:
                matches = _result["matches"]
                kev_count = _result.get("kev_count", 0)
                # Only current, typed not-applicable exclusions leave threat scoring.
                # No-fix, AI-outage, accepted-risk, and legacy ignore records remain active.
                try:
                    from angerona.core.cve_ignore import filter_active
                    active = filter_active(matches)
                except Exception:
                    active = matches
                ignored_n = len(matches) - len(active)
                if active:
                    self.alert_pending = True
                    note = f" ({ignored_n} verified not applicable)" if ignored_n else ""
                    self.set_health(60, f"{len(active)} applicable KEV CVE(s){note}")
                    top = ", ".join(m["cve"] for m in active[:5] if m.get("cve"))
                    self.emit(f"{len(active)} host-applicable CISA KEV CVEs (e.g. {top}). "
                              f"Operator confirmation required before any fix.",
                              Severity.HIGH, count=len(active), cves=top,
                              not_applicable=ignored_n)
                elif matches:
                    # Every correlation has a current, evidenced not-applicable exclusion.
                    self.alert_pending = False
                    self.set_health(
                        100, f"{len(matches)} KEV correlation(s), all verified not applicable")
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
        sha_a = "a" * 64
        sha_d = "d" * 64
        s_ips, s_hashes = _parse_iocs({
            "type": "bundle", "objects": [
                {"type": "indicator", "pattern": "[ipv4-addr:value = '203.0.113.5']"},
                {"type": "indicator", "pattern": f"[file:hashes.'SHA-256' = '{sha_a}']"},
            ]})
        j_ips, j_hashes = _parse_iocs({
            "ips": ["198.51.100.9"], "hashes": [sha_d]
        })
        global _IOC_SNAPSHOT
        now = time.time()
        with _IOC_LOCK:
            prior_snapshot = _IOC_SNAPSHOT
            _IOC_SNAPSHOT = _IocSnapshot(
                ips=frozenset(s_ips | j_ips), hashes=frozenset(s_hashes | j_hashes),
                updated_at=now, expires_at=now + 60, source="offline-self-test",
                verification="unsigned-advisory", verified=False,
            )
        try:
            ioc_ok = (is_ip_advisory("203.0.113.5")
                      and is_ip_advisory("198.51.100.9")
                      and is_hash_advisory(sha_a) and is_hash_advisory(sha_d.upper())
                      and not is_ip_advisory("8.8.8.8")
                      and not is_ip_flagged("203.0.113.5")
                      and not is_hash_flagged(sha_a))
        finally:
            with _IOC_LOCK:
                _IOC_SNAPSHOT = prior_snapshot
        ok = ok and ioc_ok
        return (ok, "KEV correlation + driver-intel blocklist + IOC fusion verified (offline)"
                if ok else f"correlation failed: kev={matches} drv_ok={drv_ok} ioc_ok={ioc_ok}")


def register() -> IntelSyncModule:
    return IntelSyncModule()
