from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from angerona.core import security_interop
from angerona.core.evidence_store import EvidenceStore, HuntQuery
from angerona.core.security_interop import (
    CAPABILITY_PARITY,
    import_json_evidence,
    parity_summary,
    run_osquery_template,
)


def test_parity_registry_is_honest_bounded_and_evidence_backed() -> None:
    report = parity_summary()
    assert report["unqualified_parity_claim"] is False
    assert report["domains"] == len(CAPABILITY_PARITY) >= 10
    assert report["counts"]["external-gate"] >= 1
    assert {row.level for row in CAPABILITY_PARITY} == {
        "operational", "integrated", "preview", "foundation", "external-gate"
    }
    text = json.dumps(report).lower()
    for reference in ("wazuh", "velociraptor", "security onion", "caldera", "thehive"):
        assert reference in text
    assert "everything is supported" not in text


def test_suricata_zeek_and_ocsf_import_into_local_evidence(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "evidence.db")
    try:
        suricata = tmp_path / "eve.json"
        suricata.write_text(json.dumps({
            "timestamp": "2026-08-21T12:00:00Z",
            "event_type": "alert",
            "src_ip": "10.0.0.4",
            "dest_ip": "10.0.0.5",
            "dest_port": 443,
            "alert": {"severity": 1, "signature_id": 42, "signature": "Test detection"},
            "secret_blob": "must-not-cross-normalization",
        }), encoding="utf-8")
        result = import_json_evidence(suricata, "suricata-eve", store)
        assert result.imported == 1
        assert result.skipped == 0

        zeek = tmp_path / "zeek.jsonl"
        zeek.write_text(json.dumps({
            "ts": 1787313600.0, "_path": "conn", "uid": "C123",
            "id.orig_h": "10.0.0.4", "id.resp_h": "10.0.0.5", "id.resp_p": 53,
            "proto": "udp", "not_whitelisted": "must-not-import",
        }) + "\nnot-json\n", encoding="utf-8")
        result = import_json_evidence(zeek, "zeek-json", store)
        assert result.imported == 1
        assert result.skipped == 1

        ocsf = tmp_path / "ocsf.json"
        ocsf.write_text(json.dumps([{
            "time_dt": "2026-08-21T12:01:00Z", "severity_id": 4,
            "class_name": "Detection Finding", "activity_name": "Create",
            "message": r"token=abc123 at C:\Users\Alice\private.txt",
            "unreviewed_payload": "must-not-import",
        }], indent=2), encoding="utf-8")
        result = import_json_evidence(ocsf, "ocsf-json", store)
        assert result.imported == 1

        evidence = store.hunt(HuntQuery(limit=20)).evidence
        encoded = json.dumps([item.to_dict() for item in evidence])
        assert len(evidence) == 3
        assert "must-not-import" not in encoded
        assert "must-not-cross-normalization" not in encoded
        assert "Alice" not in encoded
        assert "abc123" not in encoded
        assert all(item.source == "local" for item in evidence)

        duplicate = import_json_evidence(suricata, "suricata-eve", store)
        assert duplicate.imported == 0
        assert duplicate.duplicates == 1
    finally:
        store.close()


def test_import_rejects_remote_paths_and_unknown_formats(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "evidence.db")
    source = tmp_path / "events.jsonl"
    source.write_text("{}", encoding="utf-8")
    try:
        with pytest.raises(ValueError, match="unsupported"):
            import_json_evidence(source, "arbitrary", store)
        with pytest.raises(ValueError, match="network paths"):
            import_json_evidence(Path(r"\\server\share\events.json"), "generic-json", store)
        link = tmp_path / "events-link.jsonl"
        try:
            link.symlink_to(source)
        except OSError:
            pass
        else:
            with pytest.raises(ValueError, match="links and reparse"):
                import_json_evidence(link, "generic-json", store)
    finally:
        store.close()


def test_osquery_uses_only_fixed_template_and_minimizes_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / ("osqueryi.exe" if security_interop.os.name == "nt" else "osqueryi")
    executable.write_bytes(b"trusted-test-double")
    monkeypatch.setattr(security_interop, "discover_osquery", lambda: executable)
    monkeypatch.setattr(security_interop.platform, "system", lambda: "Windows")
    observed: dict[str, object] = {}

    def fake_run(args, **kwargs):
        observed["args"] = args
        observed["kwargs"] = kwargs
        return subprocess.CompletedProcess(
            args, 0,
            stdout=json.dumps([{
                "pid": "7", "parent": "1", "name": "safe.exe",
                "path": r"C:\Program Files\Safe\safe.exe",
                "environment": "must-not-import",
            }]),
            stderr="",
        )

    monkeypatch.setattr(security_interop.subprocess, "run", fake_run)
    records = run_osquery_template("processes")
    assert len(records) == 1
    assert records[0].attributes == {
        "pid": "7", "parent": "1", "name": "safe.exe",
        "path": r"C:\Program Files\Safe\safe.exe",
    }
    assert "SELECT pid, parent, name, path FROM processes LIMIT 500;" in observed["args"]
    assert observed["kwargs"]["shell"] is False
    assert observed["kwargs"]["timeout"] == 15.0
    assert "--disable_extensions=true" in observed["args"]
    with pytest.raises(ValueError, match="unknown"):
        run_osquery_template("select-anything")
