from __future__ import annotations

import copy
import json
import socket

import pytest

from angerona.modules import intel_sync


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refused(*_args, **_kwargs):
        raise AssertionError("KEV input test attempted real network access")

    monkeypatch.setattr(socket, "socket", refused)
    monkeypatch.setattr(socket, "create_connection", refused)
    monkeypatch.setattr(socket, "getaddrinfo", refused)


def _record(**changes):
    return {"cveID": "CVE-2026-12345", "vendorProject": "Microsoft", "product": "Windows",
            "vulnerabilityName": "Inert vulnerability", "requiredAction": "Apply vendor update.", **changes}


@pytest.mark.parametrize("identifier", [
    "CVE-2026-1234<img src='inert'>", "CVE-2026-1234\n", "../CVE-2026-1234",
    "CVE-2026-" + "1" * 33, "CVE-2026-123", "cve-2026-1234", None, {},
])
def test_kev_ingestion_rejects_malformed_identifier_before_correlation(identifier):
    with pytest.raises(ValueError, match="CVE identifier"):
        intel_sync._parse_kev({"vulnerabilities": [_record(cveID=identifier)]})
    with pytest.raises(ValueError, match="CVE identifier"):
        intel_sync.IntelSyncModule.match_kev([_record(cveID=identifier)], {"windows"})


@pytest.mark.parametrize("field", list(intel_sync._KEV_FIELD_LIMITS))
def test_kev_fields_have_fixed_text_budgets(field):
    record = _record(**{field: "x" * (intel_sync._KEV_FIELD_LIMITS[field] + 1)})
    with pytest.raises(ValueError, match="oversized " + field):
        intel_sync._parse_kev({"vulnerabilities": [record]})
    with pytest.raises(ValueError):
        intel_sync._parse_kev({"vulnerabilities": [_record(**{field: {"unexpected": "object"}})]})


def test_kev_text_remains_literal_data_and_record_inventory_is_bounded(monkeypatch):
    record = _record(vulnerabilityName="Literal <b>feed text</b>", requiredAction="Line one\nLine two")
    original = copy.deepcopy(record)
    matches = intel_sync.IntelSyncModule.match_kev([record], {"windows"})
    assert record == original
    assert matches[0]["name"] == "Literal <b>feed text</b>"
    assert matches[0]["remediation"] == "Line one\nLine two"
    monkeypatch.setattr(intel_sync, "_KEV_MAX_RECORDS", 1)
    with pytest.raises(ValueError, match="inventory"):
        intel_sync._parse_kev({"vulnerabilities": [record, record]})


def test_kev_ingestion_rejects_invisible_controls():
    with pytest.raises(ValueError, match="vulnerabilityName"):
        intel_sync._parse_kev({"vulnerabilities": [_record(vulnerabilityName="spoof\u202e name")]})


def test_real_fetch_normalizes_and_rejects_invalid_feed_through_fake_transport(monkeypatch, tmp_path):
    payload = [{"vulnerabilities": [_record()]}]

    class Response:
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _maximum):
            return json.dumps(payload[0]).encode()

    monkeypatch.setattr(intel_sync, "_repo_root", lambda: tmp_path)
    monkeypatch.setattr(intel_sync, "safe_urlopen", lambda *_args, **_kwargs: Response())
    module = intel_sync.IntelSyncModule()
    assert module._fetch_kev()[0]["cveID"] == "CVE-2026-12345"
    payload[0] = {"vulnerabilities": [_record(cveID="invalid")]}
    with pytest.raises(ValueError, match="CVE identifier"):
        module._fetch_kev()
