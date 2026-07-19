import hashlib

from angerona.core.release_integrity import verify_blackbox_sidecar


def test_blackbox_sidecar_requires_exact_embedded_digest(tmp_path):
    sidecar = tmp_path / "AngeronaBlackBox.exe"
    sidecar.write_bytes(b"packaged-sidecar")
    expected = hashlib.sha256(sidecar.read_bytes()).hexdigest()

    assert verify_blackbox_sidecar(sidecar, expected)
    assert not verify_blackbox_sidecar(sidecar, "")
    sidecar.write_bytes(b"replaced")
    assert not verify_blackbox_sidecar(sidecar, expected)


def test_generated_yara_rules_write_only_to_runtime_data(tmp_path, monkeypatch):
    from angerona.modules import yara_scanner as module

    resources = tmp_path / "read-only-resources"
    resources.mkdir()
    base = resources / "rules.yar"
    base.write_text("rule Base { condition: false }", encoding="utf-8")
    runtime = tmp_path / "runtime-data"
    scanner = module.YaraScannerModule()
    monkeypatch.setattr(module, "data_dir", lambda: runtime)
    monkeypatch.setattr(scanner, "_find_rules", lambda: str(base))
    monkeypatch.setattr(scanner, "_compile_rules", lambda _path: object())
    monkeypatch.setattr(scanner, "_make_scanner", lambda compiled: compiled)

    assert scanner.reload_rules("rule Generated { condition: false }")
    assert (runtime / "rules" / "auto_generated.yar").is_file()
    assert not (resources / "rules" / "auto_generated.yar").exists()
