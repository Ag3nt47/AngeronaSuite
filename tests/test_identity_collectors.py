"""Owned fixtures exercise native continuity and untrusted manifest boundaries."""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import identity_collectors as collectors
from angerona.core.eventbus import EventBus
from angerona.core.identity_collectors import (
    BrowserExtensionCollector, IdentityCollectionError, WindowsSecuritySessionSource,
    WindowsSessionCollector, parse_windows_session_xml,
)
from angerona.core.identity_session import IdentitySessionAnalytics, derive_identity_session_key
from angerona.modules.identity_session_guard import IdentitySessionGuardModule


NOW = 1_800_000_000.0
KEY = derive_identity_session_key(b"i" * 32)
EXTENSION_ID = "a" * 32


def _xml(record=1, event_id=4624, *, timestamp=NOW, sid="S-1-5-21-123-456-789-1001"):
    prefix = "Subject" if event_id == 4672 else "Target"
    stamp = datetime.fromtimestamp(timestamp, timezone.utc).isoformat().replace("+00:00", "Z")
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            '<Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>'
            f'<EventID>{event_id}</EventID><TimeCreated SystemTime="{stamp}"/>'
            f'<EventRecordID>{record}</EventRecordID><Channel>Security</Channel>'
            '<Computer>PRIVATE_DEVICE_NEVER_EXPORTED</Computer></System><EventData>'
            f'<Data Name="{prefix}UserSid">{sid}</Data><Data Name="{prefix}UserName">PRIVATE_USER_NEVER_EXPORTED</Data>'
            f'<Data Name="{prefix}DomainName">PRIVATE_DOMAIN</Data><Data Name="{prefix}LogonId">0x123</Data>'
            '<Data Name="LogonType">10</Data><Data Name="IpAddress">192.0.2.42</Data>'
            '</EventData></Event>')


class _Source:
    def __init__(self, records=None):
        self.records = records if records is not None else {1: _xml()}
        self.closed = False
        self.read_calls = []
        self.override = None

    def oldest_record_id(self):
        return min(self.records, default=0)

    def newest_record_id(self):
        return max(self.records, default=0)

    def record_anchor(self, record_id):
        return hashlib.sha256(self.records[record_id].encode()).hexdigest() if record_id in self.records else ""

    def read_after(self, record_id, limit):
        self.read_calls.append((record_id, limit))
        return self.override if self.override is not None else [self.records[k] for k in sorted(self.records) if k > record_id][:limit]

    def close(self):
        self.closed = True


def _collector(tmp_path, source=None):
    source = source or _Source()
    analytics = IdentitySessionAnalytics(KEY, clock=lambda: NOW)
    collector = WindowsSessionCollector(tmp_path, KEY, analytics.tokenize, source=source, clock=lambda: NOW)
    return collector, source, analytics


@pytest.mark.parametrize("event_id,kind", [(4624, "logon_session"), (4625, "authentication_attempt"),
                                          (4634, "session_end"), (4647, "session_end"), (4672, "privilege_change")])
def test_fixed_native_schemas_and_immediate_privacy_tokenization(event_id, kind):
    record, evidence = parse_windows_session_xml(_xml(event_id=event_id))
    assert record == 1 and evidence.kind == kind
    analytics = IdentitySessionAnalytics(KEY, clock=lambda: NOW)
    token = analytics.tokenize(evidence, evidence_grade="native-os-event-log")
    assert "PRIVATE_" not in repr(token)
    assert "192.0.2.42" not in repr(token)
    assert token.evidence_grade == "native-os-event-log"
    assert evidence.outcome == ("denied" if event_id == 4625 else "success")
    assert bool(evidence.luid) is (event_id != 4625)


@pytest.mark.parametrize("change", ["provider", "guid", "channel", "duplicate", "duplicate-system", "dtd", "oversize", "sid", "session"])
def test_malformed_spoofed_and_ambiguous_xml_is_rejected(change):
    xml = _xml()
    if change == "provider":
        xml = xml.replace("Microsoft-Windows-Security-Auditing", "Caller-Described-Producer")
    elif change == "guid":
        xml = xml.replace("54849625", "00000000")
    elif change == "channel":
        xml = xml.replace("<Channel>Security", "<Channel>System")
    elif change == "duplicate":
        xml = xml.replace("</EventData>", '<Data Name="TargetLogonId">0x999</Data></EventData>')
    elif change == "duplicate-system":
        xml = xml.replace("</System>", "<EventRecordID>2</EventRecordID></System>")
    elif change == "dtd":
        xml = '<!DOCTYPE Event [<!ENTITY xxe SYSTEM "file:///C:/private.txt">]>' + xml
    elif change == "oversize":
        xml += " " * (64 * 1024)
    elif change == "sid":
        xml = xml.replace("S-1-5-21-123-456-789-1001", "-").replace("PRIVATE_USER_NEVER_EXPORTED", "-")
    elif change == "session":
        xml = xml.replace("0x123", "caller session; execute")
    with pytest.raises(IdentityCollectionError):
        parse_windows_session_xml(xml)


def test_enrollment_live_cursor_restart_and_privacy_summaries(tmp_path):
    collector, source, _ = _collector(tmp_path)
    first = collector.poll()
    assert first.state == "baseline" and first.cursor == 1 and not first.records
    source.records[2] = _xml(2)
    live = collector.poll()
    assert live.state == "observing" and live.cursor == 2 and len(live.records) == 1
    assert live.records[0].evidence_grade == "schema-admitted-local"  # injected != native authority
    assert "PRIVATE_" not in repr(live.summary()) + repr(live.records)
    assert all("PRIVATE_" not in p.read_text() for p in tmp_path.rglob("*.json"))
    again, _, _ = _collector(tmp_path, source)
    replay = again.poll()
    assert replay.cursor == 2 and not replay.records
    assert any("whole-profile rollback" in gap for gap in replay.gaps)
    assert replay.summary()["response_authorized"] is False
    collector.close()
    assert not source.closed  # injected source ownership belongs to its caller


@pytest.mark.parametrize("mode", ["clear", "retention", "anchor-reuse"])
def test_channel_loss_and_record_rollback_are_latched_across_restart(tmp_path, mode):
    collector, source, _ = _collector(tmp_path, _Source({20: _xml(20)}))
    assert collector.poll().cursor == 20
    if mode == "clear":
        source.records = {1: _xml(1), 2: _xml(2)}
    elif mode == "retention":
        source.records = {50: _xml(50), 51: _xml(51)}
    else:
        source.records[20] = _xml(20, sid="S-1-5-21-100-200-300-1234")
        source.records[21] = _xml(21)
    lost = collector.poll()
    assert lost.state == "loss"
    assert "PRIVATE_" not in repr(lost.summary())
    restarted, _, _ = _collector(tmp_path, source)
    assert restarted.poll().state == "loss"


@pytest.mark.parametrize("mode", ["replay", "reorder", "forged-last", "future", "stale", "too-many"])
def test_replay_forged_source_anchor_time_bounds_and_native_batch_limit(tmp_path, mode):
    collector, source, _ = _collector(tmp_path)
    collector.poll()
    source.records[2] = _xml(2)
    source.records[3] = _xml(3)
    if mode == "replay":
        source.override = [_xml(1)]
    elif mode == "reorder":
        source.override = [_xml(3), _xml(2)]
    elif mode == "forged-last":
        source.override = [_xml(2), _xml(3, sid="S-1-5-21-999-999-999-1234")]
    elif mode == "future":
        source.records[2] = _xml(2, timestamp=NOW + 10)
        source.records[3] = _xml(3, timestamp=NOW + 10)
    elif mode == "stale":
        source.records[2] = _xml(2, timestamp=NOW - 1000)
        source.records[3] = _xml(3, timestamp=NOW - 1000)
    else:
        source.override = [_xml(i) for i in range(2, 67)]
    result = collector.poll()
    if mode in {"replay", "reorder"}:
        assert result.state == "replay" and not result.records
    elif mode == "forged-last":
        assert result.state == "loss" and not result.records
    elif mode in {"future", "stale"}:
        assert result.rejected_or_stale == 2 and not result.records and result.cursor == 3
    else:
        assert result.state == "unavailable" and not result.records


def test_backlog_is_bounded_and_explicit_not_reported_as_complete(tmp_path):
    collector, source, _ = _collector(tmp_path)
    collector.poll()
    source.records.update({i: _xml(i) for i in range(2, 72)})
    first = collector.poll()
    assert first.state == "replaying" and len(first.records) == 64 and first.cursor == 65
    final = collector.poll()
    assert final.state == "observing" and len(final.records) == 6 and final.cursor == 71
    assert all(limit == 64 for _, limit in source.read_calls)


def test_cursor_tampering_or_deletion_after_enrollment_fails_closed(tmp_path):
    collector, source, _ = _collector(tmp_path)
    collector.poll()
    cursor = tmp_path / "sensor-cursors/identity-sessions-v1.json"
    body = json.loads(cursor.read_text())
    body["channels"]["Security"]["record_id"] = 999
    cursor.write_text(json.dumps(body))
    fresh, _, _ = _collector(tmp_path, source)
    assert fresh.poll().state == "untrusted"
    cursor.unlink()
    fresh, _, _ = _collector(tmp_path, source)
    assert fresh.poll().state == "untrusted"


def test_cursor_hardlink_is_rejected_before_any_unrelated_content_read(tmp_path, monkeypatch):
    from angerona.core import agent_integrity
    cursor = tmp_path / "sensor-cursors/identity-sessions-v1.json"
    cursor.parent.mkdir()
    unrelated = tmp_path / "unrelated-local-file.json"
    unrelated.write_text('{"private":"NOT_CURSOR_CONTENT"}')
    os.link(unrelated, cursor)
    original = agent_integrity._open_sealed
    reads = []
    class ReadGuard:
        def __init__(self, stream):
            self.stream = stream
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            self.stream.close()
        def fileno(self):
            return self.stream.fileno()
        def read(self, *_args):
            reads.append(True)
            raise AssertionError("hardlinked cursor content was read")
    monkeypatch.setattr(agent_integrity, "_open_sealed", lambda path: ReadGuard(original(path)))
    collector, _, _ = _collector(tmp_path)
    assert collector.poll().state in {"unavailable", "denied"}
    assert not reads
    with pytest.raises(IdentityCollectionError):
        WindowsSessionCollector(Path("relative-profile"), KEY, lambda *_args, **_kwargs: None)


def test_access_denied_cancellation_and_query_timeout_do_not_become_clean(tmp_path):
    collector, source, _ = _collector(tmp_path)
    source.oldest_record_id = lambda: (_ for _ in ()).throw(PermissionError("PRIVATE_USER denied"))
    result = collector.poll()
    assert result.state == "denied" and "PRIVATE_USER" not in result.reason
    assert collector.poll(cancelled=lambda: True).state == "cancelled"
    native = WindowsSecuritySessionSource.__new__(WindowsSecuritySessionSource)
    seen = []
    native._api = SimpleNamespace(EvtNext=lambda *args: seen.append(args) or [])
    assert native._next("inert-query", 999) == []
    assert seen == [("inert-query", 64, 500, 0)]


def _manifest(tmp_path, *, browser="Chrome", name="Default", extension=EXTENSION_ID, version="1.2.3_0", body=None):
    root = tmp_path / browser / "User Data"
    path = root / name / "Extensions" / extension / version / "manifest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = body or {"manifest_version": 3, "version": "1.2.3", "permissions": ["storage", "tabs"],
                       "host_permissions": ["https://example.invalid/*"], "optional_permissions": ["history"],
                       "name": "PRIVATE_EXTENSION_NAME", "oauth2": {"client_id": "PRIVATE_IGNORED_VALUE"}}
    path.write_text(json.dumps(payload), encoding="utf-8")
    return root, path


def test_inventory_reads_only_manifest_metadata_never_browser_contents_or_registry(tmp_path, monkeypatch):
    root, manifest = _manifest(tmp_path)
    (root / "Default/Login Data").write_bytes(b"PRIVATE_BROWSER_CREDENTIALS")
    (root / "Default/History").write_bytes(b"PRIVATE_BROWSER_HISTORY")
    def forbidden(*_args, **_kwargs):
        raise AssertionError("inventory attempted process, registry or network access")
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("socket.getaddrinfo", forbidden)
    if os.name == "nt":
        monkeypatch.setattr("winreg.OpenKey", forbidden)
    from angerona.core import agent_integrity
    original = agent_integrity._held_bytes
    observed = []
    @contextlib.contextmanager
    def held(path, maximum):
        observed.append(path)
        with original(path, maximum) as raw:
            yield raw
    monkeypatch.setattr(agent_integrity, "_held_bytes", held)
    result = BrowserExtensionCollector(KEY, roots=[("Chrome", root)]).collect()
    assert result["count"] == 1 and observed == [manifest]
    row = result["rows"][0]
    assert row["extension_id"] == EXTENSION_ID and row["version"] == "1.2.3"
    assert tuple(row["permissions"]) == ("storage", "tabs")
    assert tuple(row["optional_permissions"]) == ("history",)
    assert result["source_trust"] == "unverified-local-manifest"
    assert result["response_authorized"] is False
    assert "PRIVATE_" not in json.dumps(result) and str(root) not in json.dumps(result)
    assert any("Firefox" in gap for gap in result["gaps"])
    assert any("activation" in gap for gap in result["gaps"])


@pytest.mark.parametrize("mode", ["duplicate", "oversize", "permission-count", "permission-secret", "version", "version-mismatch", "recursive"])
def test_manifest_untrusted_schema_and_resource_bounds(tmp_path, mode):
    root, path = _manifest(tmp_path)
    body = json.loads(path.read_text())
    if mode == "duplicate":
        path.write_text('{"version":"1.2.3","version":"1.2.3"}')
    elif mode == "oversize":
        path.write_text(" " * (128 * 1024 + 1))
    elif mode == "permission-count":
        body["permissions"] = ["storage"] * 129
        path.write_text(json.dumps(body))
    elif mode == "permission-secret":
        body["host_permissions"] = ["https://user:PRIVATE_TOKEN@example.invalid/*"]
        path.write_text(json.dumps(body))
    elif mode == "version":
        body["version"] = "999999999.0"
        path.write_text(json.dumps(body))
    elif mode == "version-mismatch":
        body["version"] = "1.2.4"
        path.write_text(json.dumps(body))
    else:
        path.write_text("[" * 1100 + "]" * 1100)
    result = BrowserExtensionCollector(KEY, roots=[("Chrome", root)]).collect()
    assert result["count"] == 0 and result["state"] == "unknown"
    assert any("manifest" in gap for gap in result["gaps"])


def test_hardlink_and_changed_manifest_rejected_before_inventory_admission(tmp_path, monkeypatch):
    root, path = _manifest(tmp_path)
    hardlink = tmp_path / "outside-manifest.json"
    os.link(path, hardlink)
    assert BrowserExtensionCollector(KEY, roots=[("Chrome", root)]).collect()["count"] == 0
    hardlink.unlink()
    from angerona.core import agent_integrity
    @contextlib.contextmanager
    def changed(path, maximum):
        raw = path.read_bytes()
        path.write_bytes(raw + b" ")
        yield raw
    monkeypatch.setattr(agent_integrity, "_held_bytes", changed)
    assert BrowserExtensionCollector(KEY, roots=[("Chrome", root)]).collect()["count"] == 0


def test_reparse_root_alias_relative_root_and_profile_limits_do_not_escape(tmp_path, monkeypatch):
    root, _ = _manifest(tmp_path)
    for unsafe in (Path("relative-root"), Path("//remote/share/User Data"), root / ".." / "User Data"):
        result = BrowserExtensionCollector(KEY, roots=[("Chrome", unsafe)]).collect()
        assert result["count"] == 0
    info = root.stat()
    reparse = SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
    assert not collectors._plain(reparse, directory=True)
    for index in range(17):
        (root / f"Profile {index}").mkdir()
    result = BrowserExtensionCollector(KEY, roots=[("Chrome", root)]).collect()
    assert result["count"] == 0 and any("profile-bound" in gap for gap in result["gaps"])
    with pytest.raises(ValueError):
        BrowserExtensionCollector(KEY, roots=[("Caller Browser", root)])


def test_symlink_root_and_manifest_are_never_followed(tmp_path):
    root, path = _manifest(tmp_path)
    alias = tmp_path / "root-alias"
    try:
        alias.symlink_to(root, target_is_directory=True)
    except OSError:
        pytest.skip("local token cannot create symlinks")
    assert BrowserExtensionCollector(KEY, roots=[("Chrome", alias)]).collect()["count"] == 0
    outside = tmp_path / "outside.json"
    path.replace(outside)
    path.symlink_to(outside)
    assert BrowserExtensionCollector(KEY, roots=[("Chrome", root)]).collect()["count"] == 0


def test_inventory_time_cancel_and_directory_caps_are_visible(tmp_path, monkeypatch):
    root, _ = _manifest(tmp_path)
    ticks = iter((0.0, 4.0))
    result = BrowserExtensionCollector(KEY, roots=[("Chrome", root)], monotonic=lambda: next(ticks, 4.0)).collect()
    assert result["count"] == 0 and any("budget" in gap for gap in result["gaps"])
    assert any("cancelled" in gap for gap in BrowserExtensionCollector(KEY, roots=[("Chrome", root)]).collect(cancelled=lambda: True)["gaps"])
    monkeypatch.setattr(collectors, "_MAX_DIRECTORY_ENTRIES", 1)
    (root / "Profile 1").mkdir()
    assert any("directory-bound" in gap for gap in BrowserExtensionCollector(KEY, roots=[("Chrome", root)]).collect()["gaps"])


def test_guard_default_optouts_no_collector_or_egress_and_cache_snapshots_no_io(tmp_path, monkeypatch):
    module = IdentitySessionGuardModule(data_root=tmp_path, master_key=b"i" * 32)
    def forbidden(*_args, **_kwargs):
        raise AssertionError("opted-out collector accessed host")
    monkeypatch.setattr("angerona.modules.identity_session_guard.WindowsSessionCollector", forbidden)
    monkeypatch.setattr("angerona.modules.identity_session_guard.BrowserExtensionCollector", forbidden)
    module._poll_collectors_once()
    assert module.coverage_snapshot()["sessions"]["state"] == "disabled"
    assert module.browser_inventory_snapshot()["state"] == "disabled"
    monkeypatch.setattr("builtins.open", forbidden)
    snapshot = module.coverage_snapshot()
    snapshot["sessions"]["state"] = "caller-forged"
    assert module.coverage_snapshot()["sessions"]["state"] == "disabled"


def test_stopped_never_started_guard_does_not_read_key_or_begin_new_collectors(tmp_path, monkeypatch):
    module = IdentitySessionGuardModule(data_root=tmp_path, session_collection_enabled=True,
                                        browser_inventory_enabled=True)
    module.stop()
    def forbidden(*_args, **_kwargs):
        raise AssertionError("stopped collector attempted new work")
    monkeypatch.setattr(module, "_ensure_analytics", forbidden)
    module._poll_collectors_once()
    assert module._session_collector is None and module._browser_collector is None


def test_guard_worker_collection_tokenizes_and_keeps_inventory_untrusted_no_response(tmp_path):
    root, _ = _manifest(tmp_path)
    source = _Source()
    bus = EventBus()
    module = IdentitySessionGuardModule(
        data_root=tmp_path, master_key=b"i" * 32, clock=lambda: NOW,
        session_collection_enabled=True, browser_inventory_enabled=True,
        session_source=source, browser_roots=[("Chrome", root)],
    )
    module.bind(bus)
    module._poll_collectors_once()
    source.records[2] = _xml(2)
    module._poll_collectors_once()
    assert len(module._analytics.retained_events) == 1
    assert "PRIVATE_" not in repr(module._analytics.retained_events)
    assert module.coverage_snapshot()["sessions"]["state"] == "observing"
    inventory = module.browser_inventory_snapshot()
    assert inventory["count"] == 1 and inventory["source_trust"] == "unverified-local-manifest"
    assert all(event.details.get("response_authorized") is False for event in bus.recent(100))
    module._browser_inventory_override = False
    assert not module.browser_inventory_snapshot()["rows"]
