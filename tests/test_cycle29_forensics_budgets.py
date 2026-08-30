from __future__ import annotations

import json
from types import SimpleNamespace

from angerona.modules import forensics


def test_evidence_root_refuses_byte_and_case_exhaustion(tmp_path, monkeypatch) -> None:
    root = tmp_path / "forensics"
    root.mkdir()
    case = root / "Case_1"
    case.mkdir()
    (case / "evidence.bin").write_bytes(b"x" * 32)
    monkeypatch.setattr(forensics, "_EVIDENCE_ROOT_BUDGET", 16)

    allowed, usage, cases, reason = forensics.ForensicsModule._root_capacity(root)

    assert not allowed
    assert usage >= 32
    assert cases == 1
    assert "budget" in reason


def test_capture_refuses_before_calling_collectors_when_capacity_is_spent(
    tmp_path, monkeypatch
) -> None:
    module = forensics.ForensicsModule()
    monkeypatch.setattr(forensics, "_evidence_root", lambda: tmp_path)
    monkeypatch.setattr(
        module,
        "_root_capacity",
        lambda root: (False, 999, 128, "evidence case budget exhausted"),
    )
    called = []
    monkeypatch.setattr(module, "_dump_memory_strings", lambda *a, **k: called.append(1))

    module._capture(44, expected_create_time=123.0)

    assert called == []
    assert module.health <= 25
    assert list(tmp_path.glob("Case_*")) == []


def test_socket_artifact_has_a_hard_output_budget(tmp_path, monkeypatch) -> None:
    module = forensics.ForensicsModule()
    monkeypatch.setattr(forensics, "_SOCKET_OUTPUT_BUDGET", 64)
    rows = "\n".join(
        f"TCP 127.0.0.1:{index} 1.1.1.1:443 ESTABLISHED 77"
        for index in range(20)
    )
    monkeypatch.setattr(
        forensics,
        "run_hidden",
        lambda *args, **kwargs: SimpleNamespace(stdout=rows),
    )

    receipt = module._audit_sockets(77, tmp_path)

    assert not receipt["complete"]
    assert receipt["written_bytes"] == 64
    assert (tmp_path / "network_sockets.txt").stat().st_size == 64


def test_capture_excludes_unattributable_shell_history(tmp_path, monkeypatch) -> None:
    module = forensics.ForensicsModule()
    monkeypatch.setattr(forensics, "_evidence_root", lambda: tmp_path)
    monkeypatch.setattr(
        module, "_root_capacity", lambda root: (True, 0, 0, "capacity available")
    )
    monkeypatch.setattr(
        module,
        "_dump_memory_strings",
        lambda *args, **kwargs: {"complete": True, "read_bytes": 1},
    )
    monkeypatch.setattr(
        module,
        "_audit_sockets",
        lambda *args, **kwargs: {"complete": True, "written_bytes": 1},
    )

    module._capture(88, expected_create_time=321.0)

    case_dir = next(tmp_path.glob("Case_88_*"))
    receipt = json.loads((case_dir / "capture_receipt.json").read_text("utf-8"))
    assert receipt["shell_history"]["collected"] is False
    assert "not attributable" in receipt["shell_history"]["reason"]
    assert not (case_dir / "shell_history.txt").exists()
    assert module.health == 100
