from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from angerona.core import community_yara_runtime as yara_runtime
from angerona.core import rule_playbook_library as library
from angerona.core.eventbus import Event, EventBus, Severity
from angerona.modules.soar import SOARModule


class Data:
    def __init__(self, rows):
        self.rows, self.reads, self.fail = rows, 0, False

    def active_data(self, kind):
        self.reads += 1
        if self.fail:
            raise ValueError("revoked source")
        return self.rows


def source(text="rule harmless { condition: true }"):
    return dict(id="a" * 64, repository="local", commit="local draft", path="local/a.yar",
        license="User-authored", active_sha256=hashlib.sha256(text.encode()).hexdigest(), text=text)


class Compiler:
    def __init__(self):
        self.namespaces, self.sources, self.includes = [], [], True

    def enable_includes(self, enabled):
        self.includes = enabled

    def max_warnings(self, count):
        assert count == 32

    def new_namespace(self, name):
        self.namespaces.append(name)

    def add_source(self, text, origin):
        assert not self.includes
        self.sources.append((text, origin))

    def build(self):
        return self


class Scanner:
    def __init__(self, rules):
        self.rules = rules

    def set_timeout(self, value):
        assert value == 2

    def max_matches_per_pattern(self, value):
        assert value == 64

    def fast_scan(self, value):
        assert value is True

    def scan(self, payload):
        return SimpleNamespace(matching_rules=[SimpleNamespace(namespace=self.rules.namespaces[0], identifier="harmless")])


def base_scanner():
    return SimpleNamespace(scan=lambda _: SimpleNamespace(matching_rules=[SimpleNamespace(identifier="Bundled")]))


def test_disabled_rules_do_not_read_storage_or_change_baseline(tmp_path):
    data = Data([source()])
    runtime = yara_runtime.CommunityYaraRuntime(SimpleNamespace(data_dir=tmp_path, community_rules_enabled=False), library=data)
    base = base_scanner()
    assert runtime.compose(base) is base
    assert data.reads == 0
    assert runtime.snapshot()["state"] == "disabled"


def test_reviewed_pack_composes_namespace_and_preserves_base_and_caches(tmp_path):
    data = Data([source()])
    config = SimpleNamespace(data_dir=tmp_path, community_rules_enabled=True)
    clock = [100.0]
    runtime = yara_runtime.CommunityYaraRuntime(config, library=data, compiler=Compiler, scanner=Scanner, clock=lambda: clock[0])
    base = base_scanner()
    combined = runtime.compose(base)
    assert combined is runtime.compose(base)
    assert data.reads == 1
    identifiers = [match.identifier for match in combined.scan(b"inert").matching_rules]
    assert identifiers[0] == "Bundled"
    assert identifiers[1].startswith("Community_community_")
    assert runtime.snapshot()["sources"] == 1
    assert runtime.snapshot()["response_authorized"] is False
    config.community_rules_enabled = False
    assert runtime.compose(base) is base
    assert runtime.snapshot()["sources"] == 0


def test_optional_native_scan_failure_preserves_positive_bundled_result():
    bad = SimpleNamespace(scan=lambda _: (_ for _ in ()).throw(TimeoutError()))
    combined = yara_runtime._CombinedScanner(base_scanner(), bad, {})
    assert [match.identifier for match in combined.scan(b"inert").matching_rules] == ["Bundled"]
    assert "timed out" in combined.community_error


@pytest.mark.parametrize("text", ['include "private.yar"', 'import "pe" rule a { condition: true }'])
def test_unsupported_native_includes_imports_stay_held(tmp_path, text):
    runtime = yara_runtime.CommunityYaraRuntime(SimpleNamespace(data_dir=tmp_path, community_rules_enabled=True),
        library=Data([source(text)]), compiler=Compiler, scanner=Scanner)
    base = base_scanner()
    assert runtime.compose(base) is base
    assert runtime.snapshot()["state"] == "unavailable"


def test_source_revocation_drops_optional_pack_and_keeps_bundled(tmp_path):
    data, clock = Data([source()]), [100.0]
    runtime = yara_runtime.CommunityYaraRuntime(SimpleNamespace(data_dir=tmp_path, community_rules_enabled=True),
        library=data, compiler=Compiler, scanner=Scanner, clock=lambda: clock[0])
    base = base_scanner()
    assert runtime.compose(base) is not base
    data.fail, clock[0] = True, 106.0
    assert runtime.compose(base) is base
    assert runtime.snapshot()["state"] == "unavailable"


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf"), -1, True, "100", 10**1000])
def test_optional_yara_clock_failure_never_aborts_or_retains_optional_scan(tmp_path, bad):
    data, clock = Data([source()]), [100.0]
    runtime = yara_runtime.CommunityYaraRuntime(SimpleNamespace(data_dir=tmp_path, community_rules_enabled=True),
        library=data, compiler=Compiler, scanner=Scanner, clock=lambda: clock[0])
    base = base_scanner()
    combined = runtime.compose(base)
    assert combined is not base
    clock[0] = bad
    assert [rule.identifier for rule in combined.scan(b"after invalid clock").matching_rules] == ["Bundled"]
    assert runtime.snapshot()["state"] == "unavailable"
    assert combined.community_error
    data.fail, clock[0] = True, 101.0
    assert runtime.compose(base) is base
    assert runtime.snapshot()["sources"] == 0


def test_throwing_optional_yara_clock_preserves_baseline(tmp_path):
    def clock():
        raise OSError("inert clock fixture")
    runtime = yara_runtime.CommunityYaraRuntime(SimpleNamespace(data_dir=tmp_path, community_rules_enabled=True),
        library=Data([source()]), compiler=Compiler, scanner=Scanner, clock=clock)
    base = base_scanner()
    assert runtime.compose(base) is base
    assert runtime.snapshot()["state"] == "unavailable"


def test_same_native_rule_name_isolated_by_source_path(tmp_path):
    first, second = source(), source()
    second.update(id="b" * 64, path="local/b.yar")
    runtime = yara_runtime.CommunityYaraRuntime(SimpleNamespace(data_dir=tmp_path, community_rules_enabled=True),
        library=Data([first, second]), compiler=Compiler, scanner=Scanner)
    combined = runtime.compose(base_scanner())
    assert len(set(combined.community.rules.namespaces)) == 2


def test_native_rule_bytes_rechecked_before_compile(tmp_path):
    row = source()
    row["text"] = "changed source"
    runtime = yara_runtime.CommunityYaraRuntime(SimpleNamespace(data_dir=tmp_path, community_rules_enabled=True),
        library=Data([row]), compiler=Compiler, scanner=Scanner)
    base = base_scanner()
    assert runtime.compose(base) is base
    assert "bytes changed" in runtime.snapshot()["reason"]


def test_retained_combined_scanner_rechecks_disable_between_archive_payloads(tmp_path):
    data, clock = Data([source()]), [100.0]
    cfg = SimpleNamespace(data_dir=tmp_path, community_rules_enabled=True)
    runtime = yara_runtime.CommunityYaraRuntime(cfg, library=data, compiler=Compiler, scanner=Scanner, clock=lambda: clock[0])
    combined = runtime.compose(base_scanner())
    assert len(combined.scan(b"outer inert bytes").matching_rules) == 2
    cfg.community_rules_enabled = False
    assert [rule.identifier for rule in combined.scan(b"next inert archive entry").matching_rules] == ["Bundled"]
    assert data.reads == 1


def test_retained_combined_scanner_rechecks_source_revocation_on_cache_deadline(tmp_path):
    data, clock = Data([source()]), [100.0]
    runtime = yara_runtime.CommunityYaraRuntime(SimpleNamespace(data_dir=tmp_path, community_rules_enabled=True),
        library=data, compiler=Compiler, scanner=Scanner, clock=lambda: clock[0])
    combined = runtime.compose(base_scanner())
    data.fail, clock[0] = True, 106.0
    assert [rule.identifier for rule in combined.scan(b"later archive entry").matching_rules] == ["Bundled"]
    assert combined.community_error and runtime.snapshot()["state"] == "unavailable"


def test_bom_decoded_input_compiles_without_losing_raw_source_provenance(tmp_path):
    row = source("rule harmless { condition: true }\r\n")
    row["compile_input_sha256"] = row["active_sha256"]
    row["active_sha256"] = hashlib.sha256(("\ufeff"+row["text"]).encode()).hexdigest()
    runtime = yara_runtime.CommunityYaraRuntime(SimpleNamespace(data_dir=tmp_path, community_rules_enabled=True),
        library=Data([row]), compiler=Compiler, scanner=Scanner)
    combined = runtime.compose(base_scanner())
    assert runtime.snapshot()["state"] == "ready"
    provenance = next(iter(combined.provenance.values()))
    assert provenance["active_sha256"] == row["active_sha256"]
    assert provenance["compile_input_sha256"] == row["compile_input_sha256"]


def test_optional_matches_cannot_grant_response_authority():
    from angerona.modules.yara_scanner import YaraScannerModule
    module = YaraScannerModule()
    event = module._event_for_match("harmless.txt", "Community_example_rule", "", "a" * 64,
        {"device": 1, "inode": 2, "birthtime_ns": 3}, "", "")
    assert event.details["response_authorized"] is False
    assert "corroboration" in event.details["response_withheld_reason"]


def bookrow():
    raw = library._EXAMPLES["examples/request-containment.angerona-playbook.json"]
    return dict(id="a" * 64, text=raw.decode(), active_sha256=hashlib.sha256(raw).hexdigest())


def test_playbook_runtime_gate_cache_and_revocation(tmp_path):
    config = SimpleNamespace(data_dir=tmp_path, community_playbooks_enabled=False)
    data, clock = Data([bookrow()]), [100.0]
    runtime = library.CommunityPlaybookRuntime(config, library=data, clock=lambda: clock[0])
    event = Event("Detector", "original", Severity.CRITICAL, details={"disposition": "active", "response_authorized": True})
    assert runtime.matching(event) == ()
    assert data.reads == 0
    config.community_playbooks_enabled = True
    assert len(runtime.matching(event)) == 1
    assert len(runtime.matching(event)) == 1
    assert data.reads == 1
    data.fail, clock[0] = True, 106.0
    assert runtime.matching(event) == ()
    assert runtime.snapshot()["state"] == "community playbook data unavailable"


def test_new_playbook_needs_original_authenticated_bus_before_selection(tmp_path):
    module = SOARModule()
    module._manager = SimpleNamespace(config=SimpleNamespace(data_dir=tmp_path, community_playbooks_enabled=True))
    calls = []
    module._community_runtime = SimpleNamespace(matching=lambda ev: calls.append(ev) or ())
    event = Event("Detector", "original", Severity.CRITICAL,
        details={"disposition": "active", "response_authorized": True}, hmac_sig="a" * 64)
    assert module._community_playbook_request(event) is False
    assert calls == []
    module._bus = SimpleNamespace(integrity_enabled=True, verify=lambda ev: False)
    assert module._community_playbook_request(event) is False
    assert calls == []
    module._bus = SimpleNamespace(integrity_enabled=True, verify=lambda ev: True)
    assert module._community_playbook_request(event) is False
    assert calls == [event]


def test_custom_notification_is_advisory_and_request_keeps_owner_gate(tmp_path):
    module = SOARModule()
    module._manager = SimpleNamespace(config=SimpleNamespace(data_dir=tmp_path, community_playbooks_enabled=True))
    document = library.validate_playbook(library._EXAMPLES["examples/review-high.angerona-playbook.json"])
    document["actions"].append({"type": "request_containment"})
    row = bookrow()
    module._community_runtime = SimpleNamespace(matching=lambda ev: ((row, document),))
    module._bus = SimpleNamespace(integrity_enabled=True, verify=lambda ev: True)
    notes = []
    module.emit = lambda *args, **kwargs: notes.append((args, kwargs))
    event = Event("Detector", "original", Severity.CRITICAL,
        details={"disposition": "active", "response_authorized": True}, hmac_sig="a" * 64)
    assert module._community_playbook_request(event) is True
    assert notes[0][1]["response_authorized"] is False
    assert notes[0][1]["trigger_hmac"] == event.hmac_sig
    assert module._attempts == 0


def test_real_armed_bus_refuses_mutated_original(tmp_path):
    from angerona.core.eventbus import BusAuthority
    bus = EventBus()
    bus.arm(BusAuthority(b"fixture-only-original-auth-key0000"))
    event = Event("Detector", "original", Severity.CRITICAL,
        details={"disposition": "active", "response_authorized": True})
    bus.publish(event)
    original = bus.recent(1)[0]
    original.details["response_authorized"] = False
    module = SOARModule()
    module._bus = bus
    module._manager = SimpleNamespace(config=SimpleNamespace(data_dir=tmp_path, community_playbooks_enabled=True))
    assert module._community_playbook_request(original) is False
