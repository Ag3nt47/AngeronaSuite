from __future__ import annotations

import json
from pathlib import Path

from angerona.core.eventbus import EventBus
from angerona.core.module_contract import build_capability_contract
from angerona.core.windows_auth_extensions import (
    AuthExtensionBaselineStore,
    AuthExtensionCollection,
    LocalComponentDetail,
)
from angerona.modules.authentication_extension_guard import (
    AuthenticationExtensionIntegrityGuardModule,
)


class _FakeProvider:
    def __init__(self, collection: AuthExtensionCollection) -> None:
        self.collection = collection

    def collect(self) -> AuthExtensionCollection:
        return self.collection


def _collection() -> AuthExtensionCollection:
    snapshot = AuthenticationExtensionIntegrityGuardModule._selftest_snapshot("a" * 64)
    return AuthExtensionCollection(
        snapshot,
        (
            LocalComponentDetail(
                snapshot.components[0].component_token,
                r"C:\Windows\System32\example.dll",
                "resolved without PATH search or command execution",
            ),
        ),
    )


def _baseline_path(data_root: Path) -> Path:
    return data_root / "baselines" / "windows_auth_extensions.json"


def test_capability_publishes_native_v12_contract_and_fifteen_minute_cadence() -> None:
    module = AuthenticationExtensionIntegrityGuardModule(provider=_FakeProvider(_collection()))
    contract = build_capability_contract(
        module, capability_id="angerona.builtin.authentication_extension_guard"
    )
    assert contract.metadata_level == "native"
    assert contract.metadata_gaps == ()
    assert contract.schema_version == 12
    assert contract.mode == "observe"
    assert contract.response_authority == "none"
    assert contract.egress == "none"
    assert module.INTERVAL_SECONDS == 900


def test_observation_keeps_raw_paths_only_in_local_bounded_details(tmp_path: Path) -> None:
    collection = _collection()
    store = AuthExtensionBaselineStore(
        _baseline_path(tmp_path),
        data_root=tmp_path,
        master_key=b"A" * 32,
        clock=lambda: 1000.0,
        freshness_cap_seconds=900,
    )
    bus = EventBus()
    module = AuthenticationExtensionIntegrityGuardModule(
        provider=_FakeProvider(collection),
        baseline_store=store,
    )
    module.bind(bus)
    result = module.observe_once()

    assert result["baseline_status"] == "provisional"
    assert result["health"] == 65
    assert module.health_note
    assert module.local_component_details()[0]["path"].endswith("example.dll")
    rendered_events = json.dumps(
        [event.details for event in bus.recent()], sort_keys=True, default=str
    )
    rendered_baseline = _baseline_path(tmp_path).read_text(encoding="utf-8")
    assert "example.dll" not in rendered_events
    assert "example.dll" not in rendered_baseline
    assert r"C:\Windows" not in rendered_events
    assert r"C:\Windows" not in rendered_baseline

    for event in bus.recent():
        assert event.details["read_only"] is True
        assert event.details["response_authorized"] is False
        assert event.details["response_authority"] == "observe-only"
        assert event.details["attribution"] == "not-assessed"


def test_drift_event_is_tokenized_and_never_promotes_baseline(tmp_path: Path) -> None:
    first = _collection()
    path = _baseline_path(tmp_path)
    store = AuthExtensionBaselineStore(
        path,
        data_root=tmp_path,
        master_key=b"A" * 32,
        clock=lambda: 1000.0,
        freshness_cap_seconds=900,
    )
    bus = EventBus()
    module = AuthenticationExtensionIntegrityGuardModule(
        provider=_FakeProvider(first), baseline_store=store
    )
    module.bind(bus)
    module.observe_once()
    original = path.read_bytes()

    changed = AuthExtensionCollection(
        AuthenticationExtensionIntegrityGuardModule._selftest_snapshot("b" * 64),
        first.local_details,
    )
    module._provider = _FakeProvider(changed)
    result = module.observe_once()
    assert result["baseline_status"] == "drift"
    assert result["health"] == 40
    assert path.read_bytes() == original
    event = bus.recent()[0]
    assert event.severity.name == "HIGH"
    assert event.details["change_count"] >= 1
    assert "example.dll" not in json.dumps(event.details, default=str)


def test_trusted_enrollment_requires_explicit_reviewed_operator_action(tmp_path: Path) -> None:
    module = AuthenticationExtensionIntegrityGuardModule(
        provider=_FakeProvider(_collection()),
        baseline_store=AuthExtensionBaselineStore(
            _baseline_path(tmp_path),
            data_root=tmp_path,
            master_key=b"A" * 32,
            clock=lambda: 1000.0,
            freshness_cap_seconds=900,
        ),
    )
    module.observe_once()
    result = module.establish_trusted_baseline(
        operator="local-reviewer",
        reason="Reviewed every displayed fixed binding",
        approved=True,
    )
    assert result == {
        "baseline_status": "stable",
        "baseline_trusted": True,
        "baseline_fresh": True,
        "local_only": True,
        "response_authorized": False,
        "response_authority": "observe-only",
    }


def test_collection_failure_is_exactly_degraded_and_observe_only(tmp_path: Path) -> None:
    class _FailingProvider:
        def collect(self) -> AuthExtensionCollection:
            raise RuntimeError(r"private C:\secret\path")

    module = AuthenticationExtensionIntegrityGuardModule(
        provider=_FailingProvider(),
        baseline_store=AuthExtensionBaselineStore(
            _baseline_path(tmp_path),
            data_root=tmp_path,
            master_key=b"A" * 32,
            freshness_cap_seconds=900,
        ),
    )
    bus = EventBus()
    module.bind(bus)
    result = module.observe_once()
    assert result["health"] == 15
    assert module.health_note == (
        "Authentication-extension collection failed closed; no host state was classified as clean."
    )
    event = bus.recent()[0]
    assert "secret" not in json.dumps(event.details)
    assert event.details["response_authorized"] is False


def test_module_self_test_proves_pure_drift_and_event_boundary() -> None:
    passed, detail = AuthenticationExtensionIntegrityGuardModule().self_test()
    assert passed, detail
    assert "observe-only" in detail
