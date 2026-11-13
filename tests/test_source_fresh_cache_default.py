"""Private stale-bytecode regression; no application or external process starts."""
import importlib.machinery
import importlib.util
from importlib import _bootstrap_external
import sys
from types import SimpleNamespace
from angerona import startup


def test_private_fresh_prefix_excludes_valid_timestamp_matching_stale_bytecode(tmp_path, monkeypatch):
    source = tmp_path / "inert_cache_fixture.py"
    source.write_text("VALUE = 'source1'\n", encoding="utf-8")
    # Construct a valid timestamp/size cache with deliberately different inert
    # constant data. No unsafe payload, runtime or collector is imported.
    with monkeypatch.context() as cache_context:
        cache_context.setattr(sys, "pycache_prefix", None)
        cache = __import__("pathlib").Path(importlib.util.cache_from_source(str(source)))
    cache.parent.mkdir()
    info = source.stat()
    poison = _bootstrap_external._code_to_timestamp_pyc(
        compile("VALUE = 'poison1'\n", str(source), "exec"), int(info.st_mtime), info.st_size)
    cache.write_bytes(poison)
    def value():
        code = importlib.machinery.SourceFileLoader("inert_cache_fixture", str(source)).get_code("inert_cache_fixture")
        namespace = {}
        exec(code, namespace)
        return namespace["VALUE"]
    with monkeypatch.context() as cache_context:
        cache_context.setattr(sys, "pycache_prefix", None)
        assert value() == "poison1"  # Demonstrates the stale-cache precondition.
        storage = tmp_path / "data"
        parent = storage / "tmp" / "startup-temp.critical-preflight"
        parent.parent.mkdir(parents=True)
        assert startup.private_directory(parent, create=True)
        prefix = parent / ("source-pycache-" + "a" * 32)
        cache_context.setattr(sys, "pycache_prefix", str(prefix))
        cache_context.setattr(startup, "sys", SimpleNamespace(pycache_prefix=str(prefix),
            _xoptions={"pycache_prefix": str(prefix)}, flags=SimpleNamespace(dont_write_bytecode=1)))
        assert startup._source_fresh_cache_arguments(tmp_path / "source", storage) == (
            "-B", "-X", "pycache_prefix=" + str(prefix))
        assert value() == "source1"
        assert not prefix.exists()
    assert cache.read_bytes() == poison  # No global purge/baseline replacement.
