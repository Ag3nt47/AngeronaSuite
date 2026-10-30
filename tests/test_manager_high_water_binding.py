"""Normal module composition cannot silently lose an injected freshness authority.

The authority is an inert in-memory CAS fixture. Genuine protected local stores
exercise rollback/fork/outage handling; this is not an off-host deployment test.
"""
from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import json
import os
from types import SimpleNamespace

import pytest

from angerona.core import data_paths, module_manager
from angerona.core.engine_transport import create_private_file, private_directory
from angerona.core.event_log_integrity import AuthenticatedEventLogCheckpoint, ChannelCheckpoint
from angerona.core.eventbus import BusAuthority, EventBus
from angerona.core.independent_high_water import (
    AUDIT_DOMAIN, NETWORK_DOMAIN, SCHEMA, ZERO_DIGEST,
    HighWaterHead, HighWaterRejected, HighWaterUnavailable,
)
from angerona.core.module_base import BaseModule
from angerona.core.network_trust import NetworkTrustBaseline, NetworkTrustBaselineStore, load_network_purpose_keys
from angerona.modules import audit_log_guard, network_trust_monitor, smart_deception


class Authority:
    installation_id = "12" * 16

    def __init__(self):
        self.heads = {}
        self.offline = False

    def read_head(self, domain):
        if self.offline:
            raise HighWaterUnavailable("inert outage")
        return self.heads.get(domain)

    def compare_and_advance(self, transition):
        current = self.read_head(transition.domain)
        expected = (current.revision, current.state_digest, current.head) if current else (0, ZERO_DIGEST, ZERO_DIGEST)
        if ((transition.previous_revision, transition.previous_state_digest, transition.previous_head) != expected
                or transition.revision != expected[0] + 1):
            raise HighWaterRejected("inert CAS conflict")
        digest = hashlib.sha256(json.dumps(asdict(transition), sort_keys=True).encode()).hexdigest()
        head = HighWaterHead(SCHEMA, self.installation_id, transition.domain, transition.revision,
                             transition.state_digest, transition.previous_head, digest)
        self.heads[transition.domain] = head
        return head


@pytest.fixture
def profile(tmp_path, monkeypatch):
    root = private_directory(tmp_path / "owned-profile")
    descriptor = create_private_file(root / "bus.key")
    with os.fdopen(descriptor, "wb") as stream:
        stream.write((b"k" * 32).hex().encode("ascii"))
    monkeypatch.setattr(data_paths, "data_dir", lambda: root)
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: root / "bus.key"))
    bus = EventBus()
    bus.arm(BusAuthority.load())
    return SimpleNamespace(root=root, bus=bus)


def manager(profile, authority, *, factory=None):
    return module_manager.ModuleManager(profile.bus, SimpleNamespace(ugcap_enabled=False),
                                        target_platform="windows", high_water_provider=authority,
                                        module_factory=factory)


def discover_only(instance, monkeypatch, *classes):
    monkeypatch.setattr(instance, "_builtin_classes", lambda: list(classes))
    monkeypatch.setattr(instance, "_external_classes", lambda: [])
    instance.discover()
    assert instance.discovery_errors == []
    return tuple(instance.modules[cls.name] for cls in classes)


def network_store(profile, authority):
    _privacy, baseline, enrollment = load_network_purpose_keys(profile.root)
    return NetworkTrustBaselineStore(profile.root / "sensor-baselines/network-trust.json",
        baseline_key=baseline, enrollment_key=enrollment,
        enrollment_path=profile.root / "continuity-epochs/network-trust.json", high_water=authority)


def audit_store(profile, authority):
    return AuthenticatedEventLogCheckpoint(profile.root / "sensor-cursors/audit-log-integrity.json",
                                           high_water=authority)


def seed(store, *, network):
    store.load()
    if network:
        assert store.save(NetworkTrustBaseline(), trusted=False)
    else:
        assert store.save({"Security": ChannelCheckpoint(1, "a" * 64)})
    old = (store.path.read_bytes(), store.enrollment_path.read_bytes())
    if network:
        assert store.save(NetworkTrustBaseline(), trusted=True)
    else:
        assert store.save({"Security": ChannelCheckpoint(2, "b" * 64)})
    return old


def test_normal_discovery_binds_both_real_consumers_before_local_admission(profile, monkeypatch):
    authority = Authority()
    seen = []
    actual_load = NetworkTrustBaselineStore.load

    def record_load(store):
        seen.append(store._high_water)
        return actual_load(store)

    monkeypatch.setattr(NetworkTrustBaselineStore, "load", record_load)
    audit, network = discover_only(manager(profile, authority), monkeypatch,
        audit_log_guard.AuditLogIntegrityGuard, network_trust_monitor.NetworkTrustMonitorModule)
    assert audit.high_water_provider is network.high_water_provider is authority
    assert seen == [authority]  # The constructor, not a late binder, admitted state.
    assert audit._checkpoint._high_water is network._baseline_store._high_water is authority


@pytest.mark.parametrize("network", [False, True])
@pytest.mark.parametrize("failure", ["rollback", "fork", "installation", "offline"])
def test_discovery_preserves_real_store_freshness_failures(profile, monkeypatch, network, failure):
    authority = Authority()
    store = network_store(profile, authority) if network else audit_store(profile, authority)
    old = seed(store, network=network)
    domain = NETWORK_DOMAIN if network else AUDIT_DOMAIN
    if failure == "rollback":
        store.path.write_bytes(old[0])
        store.enrollment_path.write_bytes(old[1])
    elif failure == "fork":
        authority.heads[domain] = replace(authority.heads[domain], state_digest="f" * 64)
    elif failure == "installation":
        authority.installation_id = "34" * 16
    else:
        authority.offline = True
    preserved = (store.path.read_bytes(), store.enrollment_path.read_bytes())
    cls = network_trust_monitor.NetworkTrustMonitorModule if network else audit_log_guard.AuditLogIntegrityGuard
    module, = discover_only(manager(profile, authority), monkeypatch, cls)
    if network:
        observed, state = module._baseline_store, module._baseline_state
    else:
        module._load_checkpoint()
        observed, state = module._checkpoint, module._checkpoint_status
    expected = {"rollback": "local-behind", "fork": "fork-detected",
                "installation": "installation-mismatch", "offline": "provisional-offline"}[failure]
    assert observed.freshness_status == expected
    # Network's stored "trusted" flag means a previously stable local baseline,
    # separate from independent freshness; it remains useful for drift checks.
    expected_state = ("trusted" if network else "provisional") if failure == "offline" else "untrusted"
    assert state == expected_state
    assert observed.independent_freshness_verified is False
    if failure == "offline":
        if network:
            assert observed.save(NetworkTrustBaseline(), trusted=True) is False
        else:
            assert observed.save({"Security": ChannelCheckpoint(3, "c" * 64)}) is False
    assert (store.path.read_bytes(), store.enrollment_path.read_bytes()) == preserved


@pytest.mark.parametrize("cls", [audit_log_guard.AuditLogIntegrityGuard, network_trust_monitor.NetworkTrustMonitorModule])
def test_custom_factory_cannot_silently_omit_constructor_authority(profile, cls):
    authority = Authority()
    with pytest.raises(ValueError, match="constructor-time"):
        manager(profile, authority, factory=lambda candidate: candidate())._construct_module(cls)
    accepted = manager(profile, authority, factory=lambda candidate: candidate(high_water=authority))._construct_module(cls)
    assert accepted.high_water_provider is authority


class Foreign(BaseModule):
    name = "Inert foreign consumer"

    def __init__(self):
        super().__init__()
        self.bound = None

    def bind_high_water(self, authority):
        self.bound = authority

    def _tick(self):
        raise AssertionError("No worker should start during composition")


def test_prefix_and_class_name_spoofs_never_receive_authority(profile):
    authority = Authority()
    for cls in (Foreign, type("OtherBundled", (Foreign,), {"__module__": "angerona.modules.fake"}),
                type("AuditLogIntegrityGuard", (Foreign,), {"__module__": audit_log_guard.__name__})):
        assert manager(profile, authority)._construct_module(cls).bound is None


def test_external_manifest_and_changed_factory_class_do_not_inherit_authority(profile, monkeypatch):
    authority = Authority()
    cls = audit_log_guard.AuditLogIntegrityGuard
    monkeypatch.setattr(cls, "_angerona_manifest", object(), raising=False)
    assert manager(profile, authority)._construct_module(cls).high_water_provider is None
    monkeypatch.setattr(cls, "_angerona_manifest", None)
    with pytest.raises(TypeError, match="changed the bundled class"):
        manager(profile, authority, factory=lambda _candidate: Foreign())._construct_module(cls)


def test_smart_deception_keeps_its_actual_pre_start_binder(profile):
    authority = Authority()
    module = manager(profile, authority)._construct_module(smart_deception.SmartDeception)
    assert module._custody_high_water is authority
    assert module._custody_authority_initialized is False


def test_other_construction_does_not_import_high_water_consumers(profile, monkeypatch):
    import importlib

    monkeypatch.setattr(importlib, "import_module", lambda *_a, **_k: pytest.fail("No eager discovery imports"))
    instance = manager(profile, Authority())._construct_module(Foreign)
    assert instance.bound is None
