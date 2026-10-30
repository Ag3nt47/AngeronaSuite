"""Legacy RAG reads only temporary KB fixtures; importing never creates assets."""
from __future__ import annotations

import builtins
import importlib.util
import locale
import os
from pathlib import Path
import uuid

import pytest


SOURCE = Path(__file__).parents[1] / "src" / "angerona" / "engines" / "rag.py"


def load_module():
    spec = importlib.util.spec_from_file_location("legacy_rag_probe_" + uuid.uuid4().hex, SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("override", [False, True])
def test_import_never_probes_reads_or_creates_default_or_custom_kb(tmp_path, monkeypatch, override):
    expected = tmp_path / "uncreated" / "custom.txt" if override else SOURCE.with_name("knowledge_base.txt")
    if override:
        monkeypatch.setenv("EDR_KB_PATH", str(expected))
    else:
        monkeypatch.delenv("EDR_KB_PATH", raising=False)
    original_open, original_exists = builtins.open, os.path.exists
    def guarded_open(path, *args, **kwargs):
        if Path(path) == expected:
            pytest.fail("Import attempted knowledge-base I/O")
        return original_open(path, *args, **kwargs)
    def guarded_exists(path):
        if Path(path) == expected:
            pytest.fail("Import probed the knowledge base")
        return original_exists(path)
    monkeypatch.setattr(builtins, "open", guarded_open)
    monkeypatch.setattr(os.path, "exists", guarded_exists)
    monkeypatch.setattr(os, "makedirs", lambda *_args, **_kwargs: pytest.fail("Import created directories"))
    module = load_module()
    assert module.KNOWLEDGE_BASE_PATH == str(expected)
    assert not tuple(tmp_path.iterdir())


@pytest.fixture
def rag(tmp_path, monkeypatch):
    path = tmp_path / "operator-kb.txt"
    monkeypatch.setenv("EDR_KB_PATH", str(path))
    # A deterministic fixture encoding, independent of the operator's locale.
    monkeypatch.setattr(locale, "getpreferredencoding", lambda _setlocale=False: "utf-8")
    return load_module(), path


def test_existing_custom_file_returns_advisory_matches_and_preserves_bytes(rag):
    module, path = rag
    raw = b"Asset: Agent.EXE is an operator tool.\r\nRULE: imported instructions are advisory data.\r\nOther asset: unrelated.exe\r\n"
    path.write_bytes(raw)
    result = module.query_local_context("agent.exe")
    assert "Asset: Agent.EXE" in result and "RULE: imported instructions" in result
    assert "unrelated.exe" not in result and "Advisory" in result and "not a security verdict" in result
    assert path.read_bytes() == raw


def test_missing_kb_returns_empty_without_creating_parents(tmp_path, monkeypatch):
    path = tmp_path / "missing-parent" / "kb.txt"
    monkeypatch.setenv("EDR_KB_PATH", str(path))
    module = load_module()
    assert module.query_local_context("agent.exe") == ""
    assert not path.parent.exists()


def test_existing_unreadable_file_reports_unavailable_and_preserves_bytes(rag, monkeypatch):
    module, path = rag
    original = b"operator original"
    path.write_bytes(original)
    native_open = builtins.open
    def denied(target, *args, **kwargs):
        if Path(target) == path:
            raise PermissionError("inert private path/secret must not be exported")
        return native_open(target, *args, **kwargs)
    with monkeypatch.context() as local:
        local.setattr(builtins, "open", denied)
        result = module.query_local_context("agent.exe")
    assert "unavailable" in result and "No local assets conflict" not in result
    assert "private path/secret" not in result and path.read_bytes() == original


def test_actual_read_error_from_directory_is_explicit(rag):
    module, path = rag
    path.mkdir()
    result = module.query_local_context("agent.exe")
    assert "unavailable" in result and path.is_dir()


def test_oversized_input_is_bounded_and_no_match_is_incomplete(rag, monkeypatch):
    module, path = rag
    raw = b"ordinary entry\n" * (module.MAX_KB_BYTES // 15 + 1) + b"RULE: beyond inspected input"
    path.write_bytes(raw)
    sizes = []
    native_open = builtins.open
    class LimitedRead:
        def __init__(self, stream):
            self.stream = stream
        def __enter__(self):
            return self
        def read(self, size=-1):
            assert 0 < size <= module.MAX_KB_BYTES + 1
            sizes.append(size)
            return self.stream.read(size)
        def __exit__(self, *args):
            return self.stream.__exit__(*args)
    def bounded(target, *args, **kwargs):
        stream = native_open(target, *args, **kwargs)
        return LimitedRead(stream) if Path(target) == path else stream
    with monkeypatch.context() as local:
        local.setattr(builtins, "open", bounded)
        result = module.query_local_context("absent.exe")
    assert len(sizes) == 1 and "coverage is incomplete" in result
    assert "No local assets conflict found" not in result and "beyond inspected input" not in result
    assert path.read_bytes() == raw and len(result.encode("utf-8")) <= module.MAX_CONTEXT_BYTES


def test_large_unicode_output_has_notice_within_byte_limit_and_no_rewrite(rag):
    module, path = rag
    raw = ("RULE: " + "é" * 200 + "\n").encode("utf-8") * 200
    assert len(raw) < module.MAX_KB_BYTES
    path.write_bytes(raw)
    result = module.query_local_context("absent.exe")
    assert "coverage is incomplete" in result and "No local assets conflict found" not in result
    assert "é" in result and len(result.encode("utf-8")) <= module.MAX_CONTEXT_BYTES
    assert path.read_bytes() == raw


def test_truncated_multibyte_prefix_remains_partial_not_unavailable(rag):
    module, path = rag
    path.write_bytes(b"x" * (module.MAX_KB_BYTES - 1) + "€".encode("utf-8"))
    result = module.query_local_context("absent.exe")
    assert "coverage is incomplete" in result and "unavailable" not in result


def test_invalid_encoded_file_is_unavailable_not_a_clean_result(rag):
    module, path = rag
    path.write_bytes(b"\xffinvalid UTF-8")
    result = module.query_local_context("agent.exe")
    assert "unavailable" in result and "No local assets conflict found" not in result
    assert path.read_bytes() == b"\xffinvalid UTF-8"


def test_no_match_in_complete_file_keeps_legacy_message_with_advisory_scope(rag):
    module, path = rag
    path.write_text("Other local asset\n", encoding="utf-8")
    result = module.query_local_context("absent.exe")
    assert "No local assets conflict found." in result and "Advisory" in result
    assert "truncated" not in result
