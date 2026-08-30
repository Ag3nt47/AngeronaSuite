from __future__ import annotations

from dataclasses import replace
import io
import json
import os
from pathlib import Path
import time
import types

import pytest

from angerona.core import module_base
from angerona.core import security_scan_center as scan_module
from angerona.core.module_base import BaseModule
from angerona.core.security_scan_center import SecurityScanCenter
from angerona.core.windows_auth_extensions import (
    AuthExtensionBaselineStore,
    AuthExtensionCollection,
    BaselineEnrollmentError,
    ComponentEvidence,
    assess_auth_extension_snapshot,
)
from angerona.modules.authentication_extension_guard import (
    AuthenticationExtensionIntegrityGuardModule,
)
from angerona.resilience import _selftest_environment as child_boundary


def _complete_collection() -> AuthExtensionCollection:
    return AuthExtensionCollection(
        AuthenticationExtensionIntegrityGuardModule._selftest_snapshot("a" * 64)
    )


def _baseline_path(data_root: Path) -> Path:
    return data_root / "baselines" / "windows_auth_extensions.json"


@pytest.mark.parametrize(
    "changes",
    [
        {"authenticode_state": "invalid"},
        {"authenticode_state": "unknown"},
        {"catalog_state": "error"},
        {"owner_token": ""},
        {"acl_digest": ""},
        {"evidence_status": "partial"},
    ],
)
def test_incomplete_component_assurance_is_partial_and_not_enrollable(
    tmp_path: Path, changes: dict[str, str]
) -> None:
    snapshot = _complete_collection().snapshot
    degraded = replace(
        snapshot,
        components=(replace(snapshot.components[0], **changes),),
    )

    assessment = assess_auth_extension_snapshot(degraded)
    assert assessment.state == "partial"
    assert assessment.health < 75
    assert assessment.baseline_eligible is False
    store = AuthExtensionBaselineStore(
        _baseline_path(tmp_path),
        data_root=tmp_path,
        master_key=b"A" * 32,
        clock=lambda: 1000.0,
        freshness_cap_seconds=900,
    )
    comparison = store.observe(degraded)
    assert comparison.status == "unknown"
    assert not _baseline_path(tmp_path).exists()
    with pytest.raises(BaselineEnrollmentError, match="incomplete evidence"):
        store.establish_trusted(
            degraded,
            operator="reviewer",
            reason="Reviewed incomplete component evidence",
            approved=True,
        )


def test_missing_registry_owner_acl_custody_is_not_complete() -> None:
    snapshot = _complete_collection().snapshot
    first_surface = snapshot.surfaces[0]
    binding = replace(
        first_surface.bindings[0],
        key_owner_token="",
        key_acl_digest="",
        key_security_state="unknown",
    )
    degraded = replace(
        snapshot,
        surfaces=(
            replace(first_surface, bindings=(binding,)),
            *snapshot.surfaces[1:],
        ),
    )

    assessment = assess_auth_extension_snapshot(degraded)
    assert assessment.state == "partial"
    assert assessment.baseline_eligible is False


def _corrupt_baseline(path: Path, variant: str) -> None:
    if variant == "huge-integer":
        wrapper = json.loads(path.read_text(encoding="utf-8"))
        wrapper["body"]["captured_at"] = 10**400
        path.write_text(json.dumps(wrapper), encoding="utf-8")
    elif variant == "huge-float":
        raw = path.read_text(encoding="utf-8")
        path.write_text(raw.replace('"captured_at":1000.0', '"captured_at":1e99999', 1), encoding="utf-8")
    else:
        nested = "[" * 24 + "0" + "]" * 24
        path.write_text(
            '{"body":' + nested + ',"hmac_sha256":"' + "0" * 64 + '"}',
            encoding="utf-8",
        )


@pytest.mark.parametrize("variant", ["huge-integer", "huge-float", "deep"])
def test_malformed_unauthenticated_baseline_never_crashes_observer(
    tmp_path: Path, variant: str
) -> None:
    collection = _complete_collection()
    path = _baseline_path(tmp_path)
    store = AuthExtensionBaselineStore(
        path,
        data_root=tmp_path,
        master_key=b"A" * 32,
        clock=lambda: 1000.0,
        freshness_cap_seconds=900,
    )
    assert store.observe(collection.snapshot).status == "provisional"
    _corrupt_baseline(path, variant)
    module = AuthenticationExtensionIntegrityGuardModule(
        provider=type("Provider", (), {"collect": lambda self: collection})(),
        baseline_store=store,
    )

    result = module.observe_once()

    assert result["baseline_status"] == "tampered"
    assert result["health"] == 15
    assert "baseline failed" in module.health_note.casefold()


class _FakeChild:
    def __init__(self, output: bytes) -> None:
        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO(output)
        self.returncode: int | None = None
        self.pid = 424242
        self.killed = False

    def wait(self, timeout: float | None = None) -> int:
        self.returncode = -9 if self.killed else 0
        return self.returncode

    def poll(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


def test_selftest_child_has_sanitized_isolated_pre_custody_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "C26_INERT_API_KEY",
        "HTTP_PROXY",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "AWS_SECRET_ACCESS_KEY",
    ):
        monkeypatch.setenv(name, "sentinel-not-a-real-secret")
    captured: dict[str, object] = {}
    order: list[str] = []

    def fake_popen(argv, **kwargs):
        order.append("spawn")
        captured.update({"argv": argv, **kwargs})
        return _FakeChild(b'{"detail":"bounded child","ok":true}\n')

    monkeypatch.setattr(child_boundary.subprocess, "Popen", fake_popen)
    if os.name == "nt":
        monkeypatch.setattr(
            child_boundary,
            "_assign_windows_kill_job",
            lambda _process: (order.append("assign") or (object(), lambda _job: None)),
        )
        monkeypatch.setattr(
            child_boundary,
            "_resume_windows_process",
            lambda _process: order.append("resume"),
        )

    ok, detail = child_boundary.run_isolated_selftest(
        "diagnostics",
        "c26_custody_",
        lambda root: {"ANGERONA_DIAG_DIR": str(root)},
        timeout=5.0,
    )

    assert ok, detail
    environment = captured["env"]
    assert isinstance(environment, dict)
    for forbidden in (
        "C26_INERT_API_KEY",
        "HTTP_PROXY",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "AWS_SECRET_ACCESS_KEY",
    ):
        assert forbidden not in environment
    angerona_names = {name for name in environment if name.startswith("ANGERONA_")}
    assert angerona_names == {"ANGERONA_DIAG_DIR", "ANGERONA_SELFTEST_CHILD_TOKEN"}
    argv = captured["argv"]
    assert argv[1:3] == ["-I", "-c"]
    assert Path(str(captured["cwd"])).resolve() == Path(child_boundary.__file__).resolve().parents[2]
    if os.name == "nt":
        assert int(captured["creationflags"]) & 0x00000004
        assert order[:3] == ["spawn", "assign", "resume"]


def test_selftest_output_is_stopped_at_hard_capture_bound() -> None:
    process = _FakeChild(b"x" * (child_boundary._MAX_RESULT_BYTES + 4096))

    state, captured = child_boundary._bounded_process_output(process, "a" * 64, 5.0)

    assert state == "overflow"
    assert len(captured) == child_boundary._MAX_RESULT_BYTES
    assert process.killed is True


def _center(**kwargs) -> SecurityScanCenter:
    return SecurityScanCenter(
        yara_module=object(),
        usb_authorizer=lambda _target: (True, "test-approved"),
        **kwargs,
    )


def test_late_direct_file_read_is_truthfully_timed_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "late.bin"
    target.write_bytes(b"bounded")
    real_read = scan_module.os.read

    def delayed_read(descriptor: int, count: int) -> bytes:
        time.sleep(0.03)
        return real_read(descriptor, count)

    monkeypatch.setattr(scan_module.os, "read", delayed_read)
    result = _center(max_duration_seconds=0.01).scan_path(target)

    assert result.status == "limited"
    assert result.metrics["timed_out"] is True
    assert result.metrics["files_scanned"] == 0


def test_late_yara_result_is_discarded_and_never_reported_completed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "late-yara.bin"
    target.write_bytes(b"bounded")
    center = _center(max_duration_seconds=0.1)

    class SlowScanner:
        def scan(self, _content: bytes):
            time.sleep(0.15)
            return type("Result", (), {"matching_rules": ()})()

    monkeypatch.setattr(center, "_make_yara_scanner", lambda: (SlowScanner(), "active"))
    result = center.scan_path(target)

    assert result.status == "limited"
    assert result.metrics["timed_out"] is True
    assert result.metrics["files_scanned"] == 1
    assert "never reported completed" in result.metrics["deadline_enforcement"]


class _HealthProbe(BaseModule):
    name = "Cycle 26 provenance probe"

    def run(self) -> None:
        return None


def test_mutable_module_registration_cannot_forge_source_provenance() -> None:
    probe = _HealthProbe()
    forged = compile(
        "probe.set_health(41, 'mutable registration probe')",
        str(Path(module_base.__file__).resolve()),
        "exec",
    )
    function = types.FunctionType(forged, module_base.__dict__)
    module_base.__dict__["probe"] = probe
    module_base.__dict__["cycle26_forged_health"] = function
    try:
        function()
    finally:
        module_base.__dict__.pop("cycle26_forged_health", None)
        module_base.__dict__.pop("probe", None)

    evidence = probe.health_evidence
    assert evidence is not None
    assert evidence["source_state"] == "untrusted-external"
    assert evidence["source_provenance"] == "unverified-callsite"
    assert evidence["source_path"] is None
    assert evidence["source_line"] is None
