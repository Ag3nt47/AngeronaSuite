from __future__ import annotations

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
    assert usage >= 0  # Admission reserves one complete bounded encrypted case.
    assert cases == 1
    assert "budget" in reason


def test_capture_refuses_before_calling_collectors_when_capacity_is_spent(
    tmp_path, monkeypatch
) -> None:
    module = forensics.ForensicsModule()
    monkeypatch.setattr(module, "_admit", lambda _event: (44, 123.0, forensics._EPOCH + 1230000000))
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
    assert module.health <= 45
    assert list(tmp_path.glob("Case_*")) == []


def test_socket_artifact_has_a_hard_output_budget(tmp_path, monkeypatch) -> None:
    module = forensics.ForensicsModule()
    monkeypatch.setattr(forensics, "_SOCKET_OUTPUT_BUDGET", 64)
    rows = [{"protocol": "tcp", "remote_ip": "192.0.2.1", "remote_port": index} for index in range(20)]
    monkeypatch.setattr(module, "_admit", lambda _event: (77, 100.0, forensics._EPOCH + 1000000000))
    retained = SimpleNamespace(pid=77, check=lambda: None, check_deadline=lambda: None,
                               native=SimpleNamespace(socket_rows=lambda *_args: rows))
    encrypted_inputs = []
    writer = SimpleNamespace(append=lambda kind, data: encrypted_inputs.append((kind, data)))
    receipt = module._audit_sockets(retained, writer, event=None)

    assert not receipt["complete"]
    assert receipt["written_bytes"] <= 64
    assert encrypted_inputs[0][0] == "sockets"
    assert not list(tmp_path.iterdir())  # Collector never writes plaintext artifacts.


def test_capture_excludes_unattributable_shell_history(tmp_path, monkeypatch) -> None:
    module = forensics.ForensicsModule()
    monkeypatch.setattr(module, "_admit", lambda _event: (88, 321.0, forensics._EPOCH + 3210000000))
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
    class Retained:
        identity = SimpleNamespace(image=r"D:\fixtures\sample.exe")
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            pass
        def check(self):
            pass
    monkeypatch.setattr(forensics, "_CaptureHandle", lambda *_args: Retained())
    from angerona.core.eventbus import EventBus
    module._bus = EventBus()

    module._capture(88, expected_create_time=321.0,
                    event=forensics.Event("Offline test", "inert capture fixture"))

    case_dir = next(tmp_path.glob("Case_88_*"))
    from angerona.core.forensic_vault import read_vault
    receipt = read_vault(case_dir / "evidence.afv")["receipt"]["capture"]
    assert receipt["shell_history"]["collected"] is False
    assert "not attributable" in receipt["shell_history"]["reason"]
    assert not (case_dir / "shell_history.txt").exists()
    assert not (case_dir / "capture_receipt.json").exists()
    assert module.health == 100
