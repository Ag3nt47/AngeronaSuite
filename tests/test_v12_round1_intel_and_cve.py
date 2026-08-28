from __future__ import annotations

import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from angerona.core import cve_fix_advisor
from angerona.modules import intel_sync


class _Response:
    def __init__(self, payload: bytes, declared: str | None = None) -> None:
        self.payload = payload
        self.headers = {} if declared is None else {"Content-Length": declared}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _maximum: int) -> bytes:
        return self.payload


@pytest.fixture(autouse=True)
def _clean_ioc_state(monkeypatch):
    monkeypatch.delenv("ANGERONA_IOC_FEED", raising=False)
    monkeypatch.delenv("ANGERONA_IOC_FEED_SHA256", raising=False)
    monkeypatch.setattr(intel_sync, "_IOC_SNAPSHOT", intel_sync._IocSnapshot())


def _feed(monkeypatch, raw: bytes, *, url: str = "https://intel.example/feed.json"):
    monkeypatch.setenv("ANGERONA_IOC_FEED", url)
    monkeypatch.setattr(
        intel_sync,
        "safe_urlopen",
        lambda *_args, **_kwargs: _Response(raw),
    )


def test_ioc_parser_accepts_only_literal_ips_and_lowercase_sha256():
    lower_hash = "a" * 64
    parsed = intel_sync._parse_ioc_snapshot({
        "ips": [
            "192.0.2.7",
            "2001:0db8::7",
            "example.test",
            "192.0.2.0/24",
            "192.0.2.7:443",
            1234,
        ],
        "hashes": [lower_hash, lower_hash.upper(), "abc123"],
    })

    assert parsed.ips == frozenset({"192.0.2.7", "2001:db8::7"})
    assert parsed.hashes == frozenset({lower_hash})
    assert parsed.candidate_count == 9
    assert parsed.invalid_count == 6
    assert parsed.truncated is False


def test_ioc_parser_enforces_indicator_ceiling(monkeypatch):
    monkeypatch.setattr(intel_sync, "_IOC_MAX_INDICATORS", 2)
    parsed = intel_sync._parse_ioc_snapshot({
        "ips": ["192.0.2.1", "192.0.2.2", "192.0.2.3"],
        "hashes": ["b" * 64],
    })

    assert parsed.ips == frozenset({"192.0.2.1", "192.0.2.2"})
    assert parsed.candidate_count == 2
    assert parsed.truncated is True


def test_unsigned_ioc_snapshot_is_fresh_advisory_only(monkeypatch):
    raw = json.dumps({"ips": ["192.0.2.19"], "hashes": ["c" * 64]}).encode()
    _feed(
        monkeypatch,
        raw,
        url="https://token@example.test/feed.json?credential=hidden",
    )
    emitted: list[dict] = []
    module = intel_sync.IntelSyncModule()
    monkeypatch.setattr(module, "emit", lambda *_args, **kwargs: emitted.append(kwargs))

    module._refresh_iocs()

    stats = intel_sync.ioc_stats()
    assert intel_sync.is_ip_advisory("192.0.2.19") is True
    assert intel_sync.is_hash_advisory(("c" * 64).upper()) is True
    assert intel_sync.is_ip_flagged("192.0.2.19") is False
    assert intel_sync.is_hash_flagged("c" * 64) is False
    assert stats["fresh"] is True
    assert stats["verified"] is False
    assert stats["response_authorized"] is False
    assert stats["verification"] == "unsigned-advisory"
    assert stats["source"] == "https://example.test/feed.json"
    assert stats["expires_at"] > stats["last_update"]
    assert stats["response_bytes"] == len(raw)
    assert stats["response_lines"] == 1
    assert emitted and emitted[0]["response_authorized"] is False


def test_exact_pin_enables_fresh_response_lookup_and_atomically_replaces(monkeypatch):
    first = json.dumps({"ips": ["192.0.2.20"], "hashes": []}).encode()
    _feed(monkeypatch, first)
    module = intel_sync.IntelSyncModule()
    monkeypatch.setattr(module, "emit", lambda *_args, **_kwargs: None)
    module._refresh_iocs()
    assert intel_sync.is_ip_advisory("192.0.2.20") is True
    assert intel_sync.is_ip_flagged("192.0.2.20") is False

    second = json.dumps({"ips": ["198.51.100.22"], "hashes": ["d" * 64]}).encode()
    _feed(monkeypatch, second)
    monkeypatch.setenv("ANGERONA_IOC_FEED_SHA256", hashlib.sha256(second).hexdigest())
    module._refresh_iocs()

    assert intel_sync.is_ip_advisory("192.0.2.20") is False
    assert intel_sync.is_ip_flagged("198.51.100.22") is True
    assert intel_sync.is_hash_flagged(("d" * 64).upper()) is True
    assert intel_sync.ioc_stats()["verification"] == "sha256-pinned"
    assert intel_sync.ioc_stats()["response_authorized"] is True


def test_invalid_or_expired_ioc_snapshot_cannot_authorize_response(monkeypatch):
    raw = json.dumps({"ips": ["203.0.113.30"], "hashes": ["E" * 64]}).encode()
    _feed(monkeypatch, raw)
    monkeypatch.setenv("ANGERONA_IOC_FEED_SHA256", hashlib.sha256(raw).hexdigest())
    module = intel_sync.IntelSyncModule()
    monkeypatch.setattr(module, "emit", lambda *_args, **_kwargs: None)
    module._refresh_iocs()

    assert intel_sync.is_ip_advisory("203.0.113.30") is True
    assert intel_sync.is_ip_flagged("203.0.113.30") is False
    assert intel_sync.ioc_stats()["invalid_count"] == 1
    assert intel_sync.ioc_stats()["verification"] == "sha256-pinned-invalid-content"

    monkeypatch.setattr(
        intel_sync,
        "_IOC_SNAPSHOT",
        replace(intel_sync._IOC_SNAPSHOT, expires_at=0.0, verified=True),
    )
    assert intel_sync.is_ip_advisory("203.0.113.30") is False
    assert intel_sync.is_ip_flagged("203.0.113.30") is False
    assert intel_sync.ioc_stats()["response_authorized"] is False


def test_intel_self_test_restores_live_snapshot(monkeypatch):
    original = intel_sync._IocSnapshot(
        ips=frozenset({"192.0.2.88"}), updated_at=1.0, expires_at=2.0,
        source="verified-source", content_sha256="a" * 64,
        verification="sha256-pinned", verified=True,
    )
    monkeypatch.setattr(intel_sync, "_IOC_SNAPSHOT", original)

    ok, _detail = intel_sync.IntelSyncModule().self_test()

    assert ok is True
    assert intel_sync._IOC_SNAPSHOT is original


def test_pin_mismatch_and_transport_bounds_preserve_last_snapshot(monkeypatch):
    raw = json.dumps({"ips": ["203.0.113.31"], "hashes": []}).encode()
    _feed(monkeypatch, raw)
    monkeypatch.setenv("ANGERONA_IOC_FEED_SHA256", hashlib.sha256(raw).hexdigest())
    module = intel_sync.IntelSyncModule()
    monkeypatch.setattr(module, "emit", lambda *_args, **_kwargs: None)
    module._refresh_iocs()
    original = intel_sync._IOC_SNAPSHOT

    changed = json.dumps({"ips": ["203.0.113.32"], "hashes": []}).encode()
    _feed(monkeypatch, changed)
    module._refresh_iocs()
    assert intel_sync._IOC_SNAPSHOT is original
    assert "pin mismatch" in module.last_error

    monkeypatch.delenv("ANGERONA_IOC_FEED_SHA256")
    monkeypatch.setattr(intel_sync, "_IOC_MAX_RESPONSE_BYTES", 8)
    module._refresh_iocs()
    assert intel_sync._IOC_SNAPSHOT is original
    assert "size bound" in module.last_error

    monkeypatch.setattr(intel_sync, "_IOC_MAX_RESPONSE_BYTES", 2 * 1024 * 1024)
    monkeypatch.setattr(intel_sync, "_IOC_MAX_RESPONSE_LINES", 1)
    _feed(monkeypatch, b'{\n"ips": []\n}')
    module._refresh_iocs()
    assert intel_sync._IOC_SNAPSHOT is original
    assert "line-count bound" in module.last_error


def test_retired_intel_generation_cannot_overwrite_newer_results(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(intel_sync, "_repo_root", lambda: tmp_path)
    module = intel_sync.IntelSyncModule()
    module.status = "running"
    current = [{"cve": "CVE-2099-0001"}]
    assert module._write(
        current,
        generation=module.lifecycle_generation,
        stop_event=threading.Event(),
    )
    before = module._out.read_bytes()

    assert not module._write(
        [{"cve": "CVE-2099-9999"}],
        generation=module.lifecycle_generation + 1,
        stop_event=threading.Event(),
    )

    assert module._out.read_bytes() == before
    assert set(module._pending_confirm) == {"CVE-2099-0001"}
    assert not list(module._out.parent.glob("*.candidate"))


def test_intel_atomic_replace_failure_preserves_previous_snapshot(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(intel_sync, "_repo_root", lambda: tmp_path)
    module = intel_sync.IntelSyncModule()
    module.status = "running"
    assert module._write([{"cve": "CVE-2099-0002"}])
    before = module._out.read_bytes()
    monkeypatch.setattr(
        intel_sync.os,
        "replace",
        lambda *_args: (_ for _ in ()).throw(OSError("injected replace failure")),
    )

    assert not module._write([{"cve": "CVE-2099-0003"}])

    assert module._out.read_bytes() == before
    assert not list(module._out.parent.glob("*.candidate"))


def test_cve_staging_rejects_non_cve_input_before_any_write(tmp_path, monkeypatch):
    monkeypatch.setattr(cve_fix_advisor, "_repo_root", lambda: tmp_path)
    monkeypatch.setattr(
        cve_fix_advisor,
        "ollama_available",
        lambda: (_ for _ in ()).throw(AssertionError("invalid CVE reached Ollama")),
    )

    result = cve_fix_advisor.apply_fix("../../outside", {"fix_script": "Set-Service x"})
    analyzed = cve_fix_advisor.analyze({"cve": "CVE-2024-1"})

    assert result["ok"] is False
    assert "Invalid CVE" in result["output"]
    assert "Invalid CVE" in analyzed["reason"]
    assert cve_fix_advisor.applied_state("../../outside") is None
    assert not (tmp_path / "staged_remediation").exists()


def test_cve_proposal_is_exclusive_atomic_contained_and_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(cve_fix_advisor, "_repo_root", lambda: tmp_path)
    analysis = {
        "fix_script": "Set-Service -Name Spooler -StartupType Disabled",
        "revert_script": "Set-Service -Name Spooler -StartupType Automatic",
        "summary": "review proposal",
    }

    first = cve_fix_advisor.apply_fix("cve-2099-0001", analysis)
    second = cve_fix_advisor.apply_fix("CVE-2099-0001", analysis)
    proposal = Path(first["proposal_path"])
    staging = (tmp_path / "staged_remediation").resolve()

    assert first["ok"] and second["ok"]
    assert proposal.resolve().parent == staging
    assert proposal.is_file() and not proposal.is_symlink()
    assert proposal.read_text(encoding="utf-8") == analysis["fix_script"]
    assert not list(staging.glob(".angerona-proposal-*.tmp"))


def test_cve_proposal_never_overwrites_preclaimed_path(tmp_path, monkeypatch):
    monkeypatch.setattr(cve_fix_advisor, "_repo_root", lambda: tmp_path)
    script = "Set-Service -Name Spooler -StartupType Disabled"
    digest = hashlib.sha256(script.encode()).hexdigest()
    staging = tmp_path / "staged_remediation"
    staging.mkdir()
    target = staging / f"CVE-2099-0002-{digest[:12]}.ps1.txt"
    target.write_text("attacker-controlled", encoding="utf-8")

    result = cve_fix_advisor.apply_fix("CVE-2099-0002", {"fix_script": script})

    assert result["ok"] is False
    assert "already exists" in result["output"]
    assert target.read_text(encoding="utf-8") == "attacker-controlled"


def test_cve_staging_rejects_redirected_directory(tmp_path, monkeypatch):
    data_root = tmp_path / "data"
    outside = tmp_path / "outside"
    data_root.mkdir()
    outside.mkdir()
    try:
        (data_root / "staged_remediation").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this host")
    monkeypatch.setattr(cve_fix_advisor, "_repo_root", lambda: data_root)

    result = cve_fix_advisor.apply_fix(
        "CVE-2099-0003", {"fix_script": "Set-Service x"}
    )

    assert result["ok"] is False
    assert "resolves outside" in result["output"]
    assert not list(outside.iterdir())


def test_cve_ledger_updates_are_atomic_across_threads(tmp_path, monkeypatch):
    monkeypatch.setattr(cve_fix_advisor, "_repo_root", lambda: tmp_path)

    def stage(index: int) -> dict:
        return cve_fix_advisor.apply_fix(
            f"CVE-2099-{1000 + index}",
            {
                "fix_script": f"Set-Service -Name Service{index} -StartupType Disabled",
                "revert_script": f"Set-Service -Name Service{index} -StartupType Automatic",
                "summary": "concurrent review proposal",
            },
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(stage, range(24)))

    ledger = cve_fix_advisor._load_applied()
    assert all(result["ok"] for result in results)
    assert len(ledger) == 24
    assert all(record["staged"] and not record["executed"] for record in ledger.values())
    assert not list((tmp_path / "shared_logs").glob(".angerona-cve-ledger-*.tmp"))
