from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
from pathlib import Path

import pytest

from angerona.core.windows_auth_extensions import (
    AUTH_EXTENSION_SCHEMA,
    SURFACE_IDS,
    AuthExtensionBaselineStore,
    AuthExtensionBinding,
    AuthExtensionCollection,
    AuthExtensionSnapshot,
    AuthExtensionSurface,
    BaselineEnrollmentError,
    ComponentEvidence,
    SurfaceCoverage,
    WindowsAuthExtensionEvidenceProvider,
    assess_auth_extension_snapshot,
    compare_auth_extension_snapshots,
    derive_auth_extension_keys,
    resolve_registered_component_path,
    snapshot_from_dict,
    snapshot_to_dict,
)


MASTER_KEY = b"A" * 32


def _component(*, marker: str = "a", token: str = "1") -> ComponentEvidence:
    return ComponentEvidence(
        f"component:v1:{token * 32}",
        f"path:v1:{token * 32}",
        "resolved",
        "",
        marker * 64,
        4096,
        f"file:v1:{token * 32}",
        "verified",
        "not-found",
        marker * 64,
        "1.0.0.0",
        f"owner:v1:{token * 32}",
        f"acl:v1:{token * 32}",
        "complete",
    )


def _snapshot(
    *,
    marker: str = "a",
    host_marker: str = "9",
    coverage_status: str = "complete",
    second_binding: bool = False,
    reverse: bool = False,
) -> AuthExtensionSnapshot:
    first = _component(marker=marker, token="1")
    components = [first]
    bindings = [
        AuthExtensionBinding(
            SURFACE_IDS[0],
            0,
            "binding:v1:" + "2" * 32,
            "lsa",
            "64",
            "REG_MULTI_SZ",
            first.component_token,
            "owner:v1:" + "5" * 32,
            "acl:v1:" + "6" * 32,
            "observed",
        )
    ]
    if second_binding:
        second = _component(marker="b", token="3")
        components.append(second)
        bindings.append(
            AuthExtensionBinding(
                SURFACE_IDS[0],
                1,
                "binding:v1:" + "4" * 32,
                "lsa",
                "64",
                "REG_MULTI_SZ",
                second.component_token,
                "owner:v1:" + "7" * 32,
                "acl:v1:" + "8" * 32,
                "observed",
            )
        )
    if reverse:
        bindings.reverse()
        bindings = [
            AuthExtensionBinding(
                item.surface,
                index,
                item.binding_token,
                item.registry_source,
                item.registry_view,
                item.registry_type,
                item.component_token,
                item.key_owner_token,
                item.key_acl_digest,
                item.key_security_state,
            )
            for index, item in enumerate(bindings)
        ]
    surfaces = []
    for index, surface_id in enumerate(SURFACE_IDS):
        admitted = tuple(bindings) if index == 0 else ()
        reason = "fixed source unavailable" if coverage_status != "complete" else ""
        surfaces.append(
            AuthExtensionSurface(
                SurfaceCoverage(
                    surface_id,
                    coverage_status,
                    reason,
                    len(admitted),
                    len(admitted),
                ),
                admitted,
            )
        )
    return AuthExtensionSnapshot(
        AUTH_EXTENSION_SCHEMA,
        f"host:v1:{host_marker * 32}",
        1000.0,
        tuple(surfaces),
        tuple(components),
        coverage_status,
        "fixed source unavailable" if coverage_status != "complete" else "",
        10,
    )


def test_models_are_immutable_bounded_and_round_trip_without_paths() -> None:
    snapshot = _snapshot()
    with pytest.raises(FrozenInstanceError):
        snapshot.collector_status = "unknown"  # type: ignore[misc]

    document = snapshot_to_dict(snapshot)
    encoded = json.dumps(document, sort_keys=True)
    assert "C:\\" not in encoded
    assert "/Users/" not in encoded
    assert snapshot_from_dict(document) == snapshot

    with pytest.raises(ValueError, match="strict contiguous order"):
        AuthExtensionSurface(
            SurfaceCoverage(SURFACE_IDS[0], "complete", "", 1, 1),
            (
                AuthExtensionBinding(
                    SURFACE_IDS[0],
                    2,
                    "binding:v1:" + "2" * 32,
                    "lsa",
                    "64",
                    "REG_MULTI_SZ",
                    "component:v1:" + "1" * 32,
                ),
            ),
        )


def test_pure_comparison_detects_component_order_coverage_and_host_drift() -> None:
    stable = _snapshot(second_binding=True)
    assert compare_auth_extension_snapshots(stable, stable).status == "stable"

    component_drift = compare_auth_extension_snapshots(stable, _snapshot(marker="c", second_binding=True))
    assert component_drift.status == "drift"
    assert any(change.kind == "modified" for change in component_drift.changes)

    reordered = compare_auth_extension_snapshots(
        stable, _snapshot(second_binding=True, reverse=True)
    )
    assert reordered.status == "drift"
    assert any(change.kind == "reordered" for change in reordered.changes)

    partial = compare_auth_extension_snapshots(stable, _snapshot(coverage_status="partial"))
    assert partial.status == "drift"
    assert any(change.kind == "coverage" for change in partial.changes)

    host = compare_auth_extension_snapshots(stable, _snapshot(host_marker="8", second_binding=True))
    assert host.status == "host-mismatch"
    assert host.changes[0].surface == "host"


def test_assessment_caps_local_only_health_and_incomplete_is_not_enrollable() -> None:
    complete = assess_auth_extension_snapshot(_snapshot())
    assert complete.health == 75
    assert complete.baseline_eligible is True
    assert "independent high-water" in complete.reason

    partial = assess_auth_extension_snapshot(_snapshot(coverage_status="partial"))
    assert partial.health == 50
    assert partial.baseline_eligible is False


def test_baseline_is_exclusive_provisional_and_drift_never_replaces_it(tmp_path: Path) -> None:
    now = [1000.0]
    path = tmp_path / "baselines" / "windows_auth_extensions.json"
    store = AuthExtensionBaselineStore(
        path,
        data_root=tmp_path,
        master_key=MASTER_KEY,
        clock=lambda: now[0],
        freshness_cap_seconds=900,
    )
    baseline = _snapshot()
    first = store.observe(baseline)
    assert first.status == "provisional"
    assert path.is_file()
    original = path.read_bytes()

    drift = store.observe(_snapshot(marker="b"))
    assert drift.status == "drift"
    assert drift.baseline_trusted is False
    assert path.read_bytes() == original

    with pytest.raises(BaselineEnrollmentError, match="approved=True"):
        store.establish_trusted(
            baseline, operator="operator", reason="reviewed fixed surfaces", approved=False
        )
    with pytest.raises(BaselineEnrollmentError, match="differs"):
        store.establish_trusted(
            _snapshot(marker="b"),
            operator="operator",
            reason="reviewed changed surfaces",
            approved=True,
        )

    store.establish_trusted(
        baseline,
        operator="local-maintainer",
        reason="Reviewed every fixed extension binding",
        approved=True,
    )
    stable = store.observe(baseline)
    assert stable.status == "stable"
    assert stable.baseline_trusted is True
    assert stable.local_only is True
    with pytest.raises(BaselineEnrollmentError, match="separate explicit reset"):
        store.establish_trusted(
            baseline,
            operator="local-maintainer",
            reason="Attempted replacement review",
            approved=True,
        )


def test_incomplete_snapshot_is_not_written_and_tamper_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "baselines" / "windows_auth_extensions.json"
    store = AuthExtensionBaselineStore(
        path,
        data_root=tmp_path,
        master_key=MASTER_KEY,
        clock=lambda: 1000.0,
        freshness_cap_seconds=900,
    )
    refused = store.observe(_snapshot(coverage_status="unknown"))
    assert refused.status == "unknown"
    assert not path.exists()

    store.observe(_snapshot())
    wrapper = json.loads(path.read_text(encoding="utf-8"))
    wrapper["body"]["snapshot"]["collector_status"] = "unknown"
    path.write_text(json.dumps(wrapper), encoding="utf-8")
    result = store.observe(_snapshot())
    assert result.status == "tampered"
    assert result.baseline_trusted is False


def test_baseline_has_explicit_local_freshness_cap(tmp_path: Path) -> None:
    now = [1000.0]
    store = AuthExtensionBaselineStore(
        tmp_path / "baselines" / "windows_auth_extensions.json",
        data_root=tmp_path,
        master_key=MASTER_KEY,
        clock=lambda: now[0],
        freshness_cap_seconds=900,
    )
    snapshot = _snapshot()
    store.establish_trusted(
        snapshot,
        operator="reviewer",
        reason="Reviewed complete fixed surfaces",
        approved=True,
    )
    now[0] += 901
    result = store.observe(snapshot)
    assert result.status == "stale"
    assert result.fresh is False
    assert "independent clock" in result.reason


def test_registered_path_resolution_is_fixed_and_never_searches_path() -> None:
    windows = r"C:\Windows"
    system = r"C:\Windows\System32"
    assert resolve_registered_component_path(
        "msv1_0", windows_directory=windows, system_directory=system
    )[0] == r"C:\Windows\System32\msv1_0.dll"
    assert resolve_registered_component_path(
        r"%SystemRoot%\System32\authui.dll",
        windows_directory=windows,
        system_directory=system,
    )[0] == r"C:\Windows\System32\authui.dll"
    for rejected in (
        r"..\payload.dll",
        r"\\server\share\provider.dll",
        r"%TEMP%\provider.dll",
        r"provider.dll -arg",
        r"C:\Windows\a.dll; calc.exe",
    ):
        resolved, reason = resolve_registered_component_path(
            rejected,
            windows_directory=windows,
            system_directory=system,
        )
        assert resolved is None, rejected
        assert reason


def test_non_windows_native_provider_is_fixed_unknown_and_side_effect_free() -> None:
    provider = WindowsAuthExtensionEvidenceProvider(
        derive_auth_extension_keys(MASTER_KEY).privacy_key,
        platform_name="linux",
        wall_clock=lambda: 1000.0,
        monotonic=lambda: 10.0,
    )
    collection = provider.collect()
    assert isinstance(collection, AuthExtensionCollection)
    assert collection.snapshot.collector_status == "unknown"
    assert tuple(item.coverage.surface for item in collection.snapshot.surfaces) == SURFACE_IDS
    assert all(item.coverage.status == "unknown" for item in collection.snapshot.surfaces)
    assert collection.local_details == ()


def test_core_source_has_no_command_or_dynamic_loader_surface() -> None:
    source = Path("src/angerona/core/windows_auth_extensions.py").read_text(encoding="utf-8")
    for forbidden in (
        "import subprocess",
        "subprocess.",
        "os.system(",
        "LoadLibrary",
        "expandvars(",
        "shell=True",
    ):
        assert forbidden not in source
