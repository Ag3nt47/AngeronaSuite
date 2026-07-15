"""connectors/research.py — ARIA research-on-command (indicator → vetted lookups).

Wires Angerona's existing "Research" alert action to on-demand threat lookups:
"look up this hash on VirusTotal / this CVE / this IP." The module is entirely
local for the parts that matter — it classifies an indicator and builds the set
of vetted, read-only lookup URLs — and delegates the actual page fetch to an
injected browser callable (Claude-for-Chrome). With no fetcher wired it just
returns the URLs for the operator to open.

    HARD SCOPE: read-only reconnaissance of indicators the operator chose to
    investigate. Every source is an allow-listed reputation/advisory site;
    nothing is submitted, nothing is uploaded, and no host data is sent. It
    builds lookups and normalises results — it takes no action.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import quote


# Allow-list of source hosts we will ever build a URL for (defensive vetting).
_ALLOWED_HOSTS = {
    "www.virustotal.com", "bazaar.abuse.ch", "urlhaus.abuse.ch",
    "www.abuseipdb.com", "nvd.nist.gov", "www.cisa.gov", "cve.mitre.org",
    "otx.alienvault.com",
}

_RE_MD5 = re.compile(r"^[A-Fa-f0-9]{32}$")
_RE_SHA1 = re.compile(r"^[A-Fa-f0-9]{40}$")
_RE_SHA256 = re.compile(r"^[A-Fa-f0-9]{64}$")
_RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_RE_URL = re.compile(r"^https?://", re.IGNORECASE)
_RE_IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_RE_DOMAIN = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$")


def classify(indicator: str) -> str:
    """Return the indicator kind: sha256/sha1/md5/cve/url/ip/domain/unknown."""
    s = (indicator or "").strip()
    if _RE_CVE.match(s):
        return "cve"
    if _RE_URL.match(s):
        return "url"
    m = _RE_IPV4.match(s)
    if m and all(0 <= int(o) <= 255 for o in m.groups()):
        return "ip"
    if _RE_SHA256.match(s):
        return "sha256"
    if _RE_SHA1.match(s):
        return "sha1"
    if _RE_MD5.match(s):
        return "md5"
    if _RE_DOMAIN.match(s):
        return "domain"
    return "unknown"


@dataclass
class ResearchTask:
    indicator: str
    kind: str
    sources: list = field(default_factory=list)   # list of (name, url)
    results: dict = field(default_factory=dict)    # name -> fetched summary (if any)
    note: str = ""


def _host_of(url: str) -> str:
    return re.sub(r"^https?://", "", url).split("/")[0].lower()


def build_sources(kind: str, indicator: str) -> list:
    """Vetted, read-only lookup URLs for an indicator kind."""
    q = quote(indicator, safe="")
    if kind in ("sha256", "sha1", "md5"):
        src = [("VirusTotal", f"https://www.virustotal.com/gui/file/{q}"),
               ("MalwareBazaar", f"https://bazaar.abuse.ch/browse.php?search={q}")]
    elif kind == "ip":
        src = [("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{q}"),
               ("AbuseIPDB", f"https://www.abuseipdb.com/check/{q}")]
    elif kind == "domain":
        src = [("VirusTotal", f"https://www.virustotal.com/gui/domain/{q}"),
               ("URLhaus", f"https://urlhaus.abuse.ch/browse.php?search={q}")]
    elif kind == "url":
        src = [("VirusTotal", f"https://www.virustotal.com/gui/search/{q}"),
               ("URLhaus", f"https://urlhaus.abuse.ch/browse.php?search={q}")]
    elif kind == "cve":
        cve = indicator.upper()
        src = [("NVD", f"https://nvd.nist.gov/vuln/detail/{cve}"),
               ("CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
               ("MITRE", f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}")]
    else:
        return []
    # defensive: drop anything not on the allow-list
    return [(n, u) for (n, u) in src if _host_of(u) in _ALLOWED_HOSTS]


class Research:
    """Research-on-command.

    Usage::

        r = Research(enabled=True, fetch=chrome_get)   # chrome_get(url)->text
        task = r.run("CVE-2026-1234")                  # fetches + normalises
        # or, with no fetcher, get the URLs to open in Claude-for-Chrome:
        task = Research().run("44d88612fea8a8f36de82e1278abb02f")
    """

    def __init__(self, *, enabled: bool = False,
                 fetch: Optional[Callable[[str], str]] = None) -> None:
        self.enabled = enabled
        self._fetch = fetch

    def run(self, indicator: str) -> ResearchTask:
        kind = classify(indicator)
        sources = build_sources(kind, indicator)
        task = ResearchTask(indicator=indicator.strip(), kind=kind, sources=sources)
        if kind == "unknown" or not sources:
            task.note = "Unrecognised indicator — provide a hash, IP, domain, URL, or CVE."
            return task
        if self.enabled and self._fetch is not None:
            for name, url in sources:
                try:
                    task.results[name] = self._summarise(self._fetch(url))
                except Exception as exc:
                    task.results[name] = f"[fetch error: {exc}]"
            task.note = f"Researched {kind} across {len(task.results)} source(s)."
        else:
            task.note = ("Open these in Claude-for-Chrome to research (no fetcher wired / disabled)."
                         if not self.enabled or self._fetch is None else "")
        return task

    @staticmethod
    def _summarise(text: str, width: int = 280) -> str:
        return " ".join((text or "").split())[:width]

    # ── Self-test ─────────────────────────────────────────────────────────────
    def self_test(self) -> tuple[bool, str]:
        """Prove indicator classification, vetted source building (allow-listed
        hosts only), a no-fetcher run that returns URLs, an injected-fetch run
        that aggregates results, and graceful handling of junk input."""
        try:
            assert classify("44d88612fea8a8f36de82e1278abb02f") == "md5"
            assert classify("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"
            assert classify("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "sha256"
            assert classify("CVE-2026-1234") == "cve"
            assert classify("8.8.8.8") == "ip"
            assert classify("999.1.1.1") == "unknown", "invalid octet rejected"
            assert classify("evil-domain.ru") == "domain"
            assert classify("http://x.com/a?b=1") == "url"
            assert classify("not an indicator !!") == "unknown"

            # sources are built and every host is on the allow-list
            for ind in ("44d88612fea8a8f36de82e1278abb02f", "8.8.8.8", "evil-domain.ru", "CVE-2026-1234"):
                src = build_sources(classify(ind), ind)
                assert src, f"sources for {ind}"
                assert all(_host_of(u) in _ALLOWED_HOSTS for _n, u in src), "allow-listed hosts only"
            cve_src = dict(build_sources("cve", "CVE-2026-1234"))
            assert "nvd.nist.gov" in cve_src["NVD"] and "CVE-2026-1234" in cve_src["NVD"], "CVE→NVD"

            # no fetcher → returns URLs to open, no results
            t = Research().run("CVE-2026-1234")
            assert t.kind == "cve" and t.sources and not t.results and "Claude-for-Chrome" in t.note

            # injected fetch → aggregates a summary per source
            calls: list[str] = []
            def fake(url):
                calls.append(url)
                return "  VirusTotal: 3/70 vendors flagged this indicator.  "
            r = Research(enabled=True, fetch=fake)
            t2 = r.run("8.8.8.8")
            assert len(calls) == len(t2.sources) and t2.results, "fetched each source"
            assert "3/70 vendors" in next(iter(t2.results.values())), "result normalised"

            # junk → graceful
            j = Research().run("???")
            assert j.kind == "unknown" and not j.sources and "Unrecognised" in j.note

            return True, ("OK — md5/sha1/sha256/cve/ip/domain/url classified (bad octet "
                          "rejected); sources built from an 8-host allow-list only; CVE→NVD "
                          "detail URL; no-fetcher run returns URLs; injected fetch aggregates "
                          "per-source summaries; junk indicator handled.")
        except AssertionError as exc:
            return False, f"FAIL — {exc}"
        except Exception as exc:  # pragma: no cover
            return False, f"ERROR — {type(exc).__name__}: {exc}"


# ── Singleton factory ──────────────────────────────────────────────────────────
_RESEARCH: Optional[Research] = None


def init_research(*, enabled: bool = False, fetch: Optional[Callable[[str], str]] = None) -> Research:
    global _RESEARCH
    _RESEARCH = Research(enabled=enabled, fetch=fetch)
    return _RESEARCH


def get_research() -> Research:
    global _RESEARCH
    if _RESEARCH is None:
        _RESEARCH = Research(enabled=False)
    return _RESEARCH


if __name__ == "__main__":
    ok, detail = Research().self_test()
    print(f"[research] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    raise SystemExit(0 if ok else 1)
