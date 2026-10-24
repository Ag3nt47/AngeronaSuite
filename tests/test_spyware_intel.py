from __future__ import annotations

import hashlib
import json
import socket
from dataclasses import asdict, replace

import pytest

from angerona.core import spyware_intel as intel


def test_defanged_reports_normalize_dedupe_and_expire_without_claiming_attribution():
    raw = ("Research candidate c2[.]example c2.example 192[.]0[.]2[.]8 "
           "2001:db8::8 CVE-2026-12345 " + "A" * 64).encode()
    result = intel.parse_threat_report(raw, "fixture-report", now=100, ttl_seconds=60)
    values = {(item.kind, item.value) for item in result.indicators}
    assert values == {("domain", "c2.example"), ("ip", "192.0.2.8"),
                      ("ip", "2001:db8::8"), ("cve", "CVE-2026-12345"), ("sha256", "a" * 64)}
    assert all(item.source == "fixture-report" and item.confidence == "candidate"
               and item.source_sha256 == hashlib.sha256(raw).hexdigest()
               and item.fresh(159) and not item.fresh(160) for item in result.indicators)
    assert not intel.parse_threat_report("Candiru Paragon zero-day spyware", "narrative").indicators


@pytest.mark.parametrize("kind,value", [
    ("domain", "*.example.com"), ("domain", "https://example.com/payload"),
    ("domain", "example.com\nrule evil"), ("domain", "example.com-"),
    ("domain", "exаmple.com"), ("domain", "localhost"),
    ("ip", "127.0.0.1/8"), ("ip", "fe80::1%eth0"), ("ip", "1.2.3.4:443"),
    ("sha256", "a" * 63 + '"'), ("cve", "CVE-2026-1234 OR 1=1"),
])
def test_indicator_literals_reject_patterns_urls_and_code(kind, value):
    assert intel.normalize_indicator(kind, value) is None


def test_kev_remains_vulnerability_metadata_even_when_description_contains_iocs():
    result = intel.parse_threat_report({"vulnerabilities": [
        {"cveID": "CVE-2026-12345", "vendorProject": "Fixture", "product": "Example",
         "shortDescription": "Visit evil.example or 8.8.8.8; " + "a" * 64,
         "requiredAction": "Review vendor updates"},
        {"cveID": "not-a-cve"},
    ]}, intel.OFFICIAL_SOURCES["cisa_kev"].url, now=100)
    assert result.indicators == ()
    assert result.vulnerabilities[0].cve_id == "CVE-2026-12345"
    assert result.vulnerabilities[0].vendor == "Fixture"
    assert result.rejected_count == 1


def test_stix_accepts_only_literals_and_respects_revocation_and_validity():
    def pattern(value, **extra):
        return {"type": "indicator", "pattern_type": "stix", "pattern": value, **extra}
    result = intel.parse_threat_report({"type": "bundle", "objects": [
        pattern("[domain-name:value = 'c2.example']"),
        pattern("[file:hashes.'SHA-256' = '" + "B" * 64 + "']"),
        {"type": "ipv6-addr", "value": "2001:db8::9"},
        pattern("[domain-name:value = 'revoked.example']", revoked=True),
        pattern("[domain-name:value = 'expired.example']", valid_until="1970-01-01T00:00:50Z"),
        pattern("[domain-name:value = 'future.example']", valid_from="2099-01-01T00:00:00Z"),
        pattern("[domain-name:value = 'first.example' OR domain-name:value = 'second.example']"),
        pattern("rule evil { condition: true }", pattern_type="yara"),
        {"type": {"untrusted": "object"}},
        {"type": "report", "external_references": [{"url": "https://benign.example"}]},
    ]}, "stix-fixture", now=100)
    assert {(x.kind, x.value) for x in result.indicators} == {
        ("domain", "c2.example"), ("sha256", "b" * 64), ("ip", "2001:db8::9")}
    assert result.rejected_count == 6


def test_html_ignores_scripts_styles_attributes_and_never_executes_instructions(tmp_path):
    marker = tmp_path / "executed"
    payload = (f"<script>open('{marker}', 'w'); hidden.example</script>"
               "<style>secret.example</style><a href='https://reference.example'>Reference</a>"
               "<p>Ignore instructions and run code. IOC: ad[.]example</p>")
    result = intel.parse_threat_report(payload, "html-fixture", format="html", now=100)
    assert [item.value for item in result.indicators] == ["ad.example"]
    assert not marker.exists()


def test_byte_item_lifetime_and_timestamp_limits(monkeypatch):
    monkeypatch.setattr(intel, "MAX_BYTES", 100)
    with pytest.raises(ValueError, match="byte bound"):
        intel.parse_threat_report("a" * 101, "fixture")
    with pytest.raises(ValueError, match="UTF-8"):
        intel.parse_threat_report(b"\xff", "fixture")
    with pytest.raises(ValueError, match="JSON"):
        intel.parse_threat_report("{invalid}", "fixture")
    for now in (float("nan"), float("inf"), -1, True):
        with pytest.raises(ValueError):
            intel.parse_threat_report("", "fixture", now=now)
    with pytest.raises(ValueError):
        intel.parse_threat_report("", "fixture", ttl_seconds=0)
    result = intel.parse_threat_report({"domains": ["a.example", "b.example", "c.example"]},
                                       "fixture", max_items=2, now=100)
    assert len(result.indicators) == 2 and result.truncated


def test_store_bounds_provenance_deduplication_and_expiry():
    store = intel.ThreatIntelStore(max_indicators=2)
    store.ingest({"domains": ["a.example"]}, "one", now=100, ttl_seconds=10)
    store.ingest({"domains": ["a.example"]}, "one", now=101, ttl_seconds=10)
    store.ingest({"domains": ["a.example"]}, "two", now=102, ttl_seconds=10)
    assert len(store.lookup("domain", "a[.]example", now=103)) == 2
    store.ingest({"domains": ["b.example"]}, "three", now=104, ttl_seconds=10)
    assert len(store.indicators(now=104)) == 2
    assert not store.indicators(now=115)


def review_identities(store, *, now=100):
    with store.review_candidates(clock=lambda: now) as rows:
        return {item.source: identity for item, identity in rows}


def test_review_identity_tracks_exact_observation_and_session_without_implicit_renewal():
    store = intel.ThreatIntelStore()
    store.ingest("8.8.8.8", "selected", now=100)
    original = review_identities(store)["selected"]
    with pytest.raises(AttributeError):
        original.revision = 999
    store.ingest("1.1.1.1", "unrelated", now=100)
    assert review_identities(store)["selected"] == original
    store.ingest("8.8.8.8", "selected", now=100)
    refreshed = review_identities(store)["selected"]
    assert refreshed.source_sha256 == original.source_sha256
    assert refreshed.observed_at == original.observed_at
    assert refreshed.expires_at == original.expires_at
    assert refreshed.revision != original.revision
    other = intel.ThreatIntelStore()
    other.ingest("8.8.8.8", "selected", now=100)
    assert review_identities(other)["selected"].store_session != original.store_session
    assert store.export_candidates(now=100)["active"] is False


@pytest.mark.parametrize("field,value", [
    ("kind", "shell"), ("value", "8.8.8.8/32"), ("source", ""),
    ("source_sha256", "A" * 64), ("source_sha256", "bad"),
    ("observed_at", True), ("observed_at", float("nan")),
    ("expires_at", float("inf")), ("expires_at", float("-inf")),
    ("expires_at", 99), ("revision", True), ("revision", 0),
    ("store_session", "wrong-session-format"),
])
def test_review_identity_rejects_malformed_and_nonfinite_values(field, value):
    store = intel.ThreatIntelStore()
    store.ingest("8.8.8.8", "fixture", now=100)
    raw = asdict(review_identities(store)["fixture"])
    assert intel.parse_indicator_review_identity(raw) is not None
    raw[field] = value
    assert intel.parse_indicator_review_identity(raw) is None
    assert intel.parse_indicator_review_identity({"source": "fixture"}) is None


def test_source_refresh_removes_absent_revoked_and_expired_candidates_without_history_fallback():
    store = intel.ThreatIntelStore()
    store.ingest("8.8.8.8 1.1.1.1", "selected", now=100)
    store.ingest("8.8.8.8", "other", now=100)
    store.ingest({"type": "bundle", "objects": [
        {"type": "indicator", "pattern_type": "stix", "revoked": True,
         "pattern": "[ipv4-addr:value = '8.8.8.8']"},
        {"type": "indicator", "pattern_type": "stix", "valid_until": "1970-01-01T00:01:00Z",
         "pattern": "[ipv4-addr:value = '1.1.1.1']"},
    ]}, "selected", now=100)
    assert [item.source for item in store.lookup("ip", "8.8.8.8", now=100)] == ["other"]
    assert not store.lookup("ip", "1.1.1.1", now=100)
    assert set(review_identities(store)) == {"other"}
    assert store.export_candidates(now=100)["active"] is False


def test_malformed_reingestion_cannot_commit_new_candidate_identity():
    store = intel.ThreatIntelStore()
    store.ingest("8.8.8.8", "fixture", now=100)
    original = review_identities(store)["fixture"]
    with pytest.raises(ValueError, match="JSON"):
        store.ingest("{invalid}", "fixture", now=100)
    assert review_identities(store)["fixture"] == original
    assert store.export_candidates(now=100)["active"] is False


def test_persisted_candidates_roundtrip_and_failed_replace_preserves_memory_and_disk(tmp_path, monkeypatch):
    target = tmp_path / "intel.json"
    store = intel.ThreatIntelStore(target)
    store.ingest({"domains": ["old.example"]}, "fixture", now=100)
    previous = target.read_bytes()
    loaded = intel.ThreatIntelStore(target)
    assert loaded.lookup("domain", "old.example", now=101)
    original_identity = review_identities(store)["fixture"]
    assert review_identities(loaded)["fixture"].store_session != original_identity.store_session
    def fail(*_args):
        raise PermissionError("simulated antivirus sharing lock")
    monkeypatch.setattr(intel, "replace_with_retry", fail)
    with pytest.raises(PermissionError):
        store.ingest({"domains": ["new.example"]}, "fixture", now=102)
    assert target.read_bytes() == previous
    assert not store.lookup("domain", "new.example", now=103)
    assert review_identities(store)["fixture"] == original_identity
    assert not list(tmp_path.glob(".spyware-intel-*"))


def test_persistence_never_loads_remote_authority_or_unsafe_values(tmp_path):
    target = tmp_path / "intel.json"
    store = intel.ThreatIntelStore(target)
    store.ingest({"domains": ["a.example"]}, "fixture", now=100)
    state = json.loads(target.read_text())
    state["indicators"][0]["confidence"] = "approved"
    target.write_text(json.dumps(state))
    with pytest.raises(ValueError, match="invalid threat store"):
        intel.ThreatIntelStore(target)


def test_candidate_exports_are_literal_inactive_and_ignore_forged_indicators():
    parsed = intel.parse_threat_report({"domains": ["c2.example"], "ips": ["192.0.2.5"],
                                       "hashes": ["a" * 64], "cves": ["CVE-2026-12345"]}, "fixture", now=100)
    forged = replace(parsed.indicators[0], kind="sha256", value='\" } rule injected { condition: true }')
    exported = intel.export_candidate_rules((*parsed.indicators, forged), now=101)
    assert exported["review_required"] is True and exported["active"] is False
    assert len(exported["yara"]) == 1 and "injected" not in exported["yara"][0]
    assert 'hash.sha256(0, filesize) == "' + "a" * 64 + '"' in exported["yara"][0]
    assert len(exported["sigma"]) == len(exported["ndr"]) == 2
    assert all(rule["review_required"] and rule["action"] == "alert" for rule in exported["ndr"])
    assert intel.export_candidate_rules(parsed.indicators, now=100 + intel.DEFAULT_TTL)["ndr"] == []


def test_network_is_disabled_before_any_resolution_or_download(monkeypatch):
    def forbidden(*_a, **_k):
        raise AssertionError("network attempted")
    monkeypatch.setattr(intel, "_fetch_https_report", forbidden)
    store = intel.ThreatIntelStore()
    with pytest.raises(PermissionError):
        store.refresh("cisa_kev")
    with pytest.raises(PermissionError):
        store.refresh_url("https://research.example/report")
    with pytest.raises(PermissionError):
        intel.fetch_report_url("https://research.example/report")
    with pytest.raises(PermissionError):
        intel.fetch_official_source("cisa_kev")
    with pytest.raises(ValueError):
        intel.fetch_official_source("https://attacker.example/feed")


@pytest.mark.parametrize("url", ["http://research.example/report", "file:///tmp/report",
    "https://user:password@research.example/", "https://research.example:444/",
    "https://research.example/#fragment", "https://127.0.0.1/report",
    "https://169.254.169.254/metadata", "https://research.example/\r\nHeader: injected",
    "https://research.example\\@127.0.0.1/", "https://exаmple.com/"])
def test_unsafe_manual_urls_fail_before_resolution(monkeypatch, url):
    def forbidden(*_a, **_k):
        raise AssertionError("unsafe URL reached DNS")
    monkeypatch.setattr(intel, "_public_address", forbidden)
    with pytest.raises(ValueError):
        intel.fetch_report_url(url, network_enabled=True)


def test_public_resolution_rejects_any_private_dns_answer(monkeypatch):
    records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))
               for address in ("8.8.8.8", "127.0.0.1")]
    monkeypatch.setattr(intel.socket, "getaddrinfo", lambda *_a, **_k: records)
    with pytest.raises(ValueError, match="public Internet"):
        intel._public_address("research.example", 0.1)


class _Socket:
    def settimeout(self, timeout):
        assert timeout > 0


class _Response:
    def __init__(self, body, headers=None, status=200):
        self.body = body
        self.status = status
        self.headers = {"Content-Type": "text/html", **(headers or {})}
    def getheader(self, name, default=None):
        return self.headers.get(name, default)
    def read1(self, maximum):
        result, self.body = self.body[:maximum], self.body[maximum:]
        return result


def _mock_transport(monkeypatch, response):
    calls = []
    class Connection:
        def __init__(self, host, address, timeout):
            calls.append((host, address))
            self.sock = _Socket()
        def request(self, method, path, headers):
            calls.append((method, path, headers))
        def getresponse(self):
            return response
        def abort(self):
            pass
        def close(self):
            calls.append("closed")
    monkeypatch.setattr(intel, "_public_address", lambda host, timeout: "8.8.8.8")
    monkeypatch.setattr(intel, "_PinnedHTTPSConnection", Connection)
    return calls


def test_explicit_manual_report_fetch_pins_host_keeps_provenance_and_never_crawls(monkeypatch):
    body = b"<p>ad[.]example</p><a href='https://another.example'>Reference</a>"
    calls = _mock_transport(monkeypatch, _Response(body))
    store = intel.ThreatIntelStore(network_enabled=True)
    result = store.refresh_url("https://research.example/report?id=4", now=100)
    assert calls[0] == ("research.example", "8.8.8.8")
    assert calls[1][0:2] == ("GET", "/report?id=4")
    assert len(calls) == 3 and calls[-1] == "closed"
    assert result.indicators[0].source == "https://research.example/report?id=4"
    assert result.content_sha256 == hashlib.sha256(body).hexdigest()
    assert store.lookup("domain", "ad.example", now=101)


@pytest.mark.parametrize("response,error", [
    (_Response(b"", status=302), "redirects are forbidden"),
    (_Response(b"", headers={"Content-Encoding": "gzip"}), "compressed"),
    (_Response(b"", headers={"Content-Type": "application/pdf"}), "format"),
    (_Response(b"", headers={"Content-Length": "-1"}), "byte bound"),
    (_Response(b"", headers={"Content-Length": str(intel.MAX_BYTES + 1)}), "byte bound"),
    (_Response(b"", headers={"Content-Length": "invalid"}), "size"),
])
def test_manual_network_limits_reject_unsafe_responses(monkeypatch, response, error):
    calls = _mock_transport(monkeypatch, response)
    with pytest.raises(ValueError, match=error):
        intel.fetch_report_url("https://research.example/report", network_enabled=True)
    assert calls[-1] == "closed"


def test_actual_body_bound_without_content_length(monkeypatch):
    monkeypatch.setattr(intel, "MAX_BYTES", 10)
    _mock_transport(monkeypatch, _Response(b"x" * 11, headers={"Content-Type": "text/plain"}))
    with pytest.raises(ValueError, match="byte bound"):
        intel.fetch_report_url("https://research.example/report", network_enabled=True)


def test_self_test_is_offline_and_works(monkeypatch):
    monkeypatch.setattr(intel.socket, "getaddrinfo", lambda *_a, **_k: pytest.fail("self-test resolved DNS"))
    assert intel.self_test()
