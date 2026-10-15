"""Benchmark isolated YARA cursor selection and response classification offline.

Uses synthetic data only; starts no sensors, GUI, threads or response actions.
Run with the repository venv Python. --full-inventory additionally measures
actual fair-traversal methods with mocked in-memory DirEntry/scandir objects;
it can take several minutes. No inert paths or files are created.

Wall timings use perf_counter, one warmup and median samples, with neither
cProfile nor tracemalloc active. Allocation tracing runs separately for cursor
selection only. Results are local microbenchmarks, not whole-app idle CPU or
filesystem scan measurements; shared-host wall timings may vary.
"""
from __future__ import annotations

import argparse
import ast
import copy
import statistics
import subprocess
import sys
import time
import tracemalloc
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASELINE = "fea868c768ff01a2ba29130dfac451622c506faa"
SOURCE_PATH = "src/angerona/modules/yara_scanner.py"


def _load_methods(source: str, module) -> dict:
    """Load trusted local scanner methods and isolate their selection blocks."""
    tree = ast.parse(source)
    cls = next(node for node in tree.body
               if isinstance(node, ast.ClassDef) and node.name == "YaraScannerModule")
    namespace = dict(vars(module))
    for name in ("_fair_batch", "_response_classification"):
        method = next(node for node in cls.body
                      if isinstance(node, ast.FunctionDef) and node.name == name)
        # AST source extraction omits decorators, giving a plain callable.
        exec(compile(ast.get_source_segment(source, method), SOURCE_PATH, "exec"), namespace)
        if name != "_fair_batch":
            continue
        names = [
            statement.targets[0].id
            if isinstance(statement, ast.Assign) and isinstance(statement.targets[0], ast.Name)
            else ""
            for statement in method.body
        ]
        start, end = names.index("cursor_key"), names.index("next_cursor")
        selector = copy.deepcopy(method)
        selector.name = "_select"
        selector.decorator_list = []
        selector.args = ast.parse("def _select(candidates, cursor): pass").body[0].args
        selector.returns = None
        selector.body = selector.body[start:end] + ast.parse("return selected").body
        program = ast.fix_missing_locations(ast.Module(body=[selector], type_ignores=[]))
        exec(compile(program, "yara_cursor_selection_fixture.py", "exec"), namespace)
    return namespace


def _timed(function, *, repeat: int = 7) -> float:
    if tracemalloc.is_tracing() or sys.getprofile() is not None or sys.gettrace() is not None:
        raise RuntimeError("Run wall timings without tracing or profiling enabled")
    function()
    samples = []
    for _ in range(repeat):
        start = time.perf_counter()
        function()
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)


def _selection_benchmark(before: dict, after: dict) -> None:
    candidates = [(f"dir/File{number:06d}.bin", number) for number in range(200_000)]
    cursor = "dir/File100000.bin"
    operations = {
        label: lambda namespace=namespace: namespace["_select"](candidates, cursor)
        for label, namespace in (("before", before), ("after", after))
    }
    assert operations["before"]() == operations["after"]()
    for label, operation in operations.items():
        elapsed = _timed(operation, repeat=15)
        # Trace a separate call only after all timed samples have finished.
        tracemalloc.start()
        try:
            operation()
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        print(f"cursor_selection entries=200000 {label}: {elapsed:.6f}s peak={peak} bytes")


def _classification_benchmark(before: dict, after: dict) -> None:
    identity = {"device": 1, "inode": 2, "birthtime_ns": 0}
    for tokens in (b"sekurlsa:: logonpasswords gentilkiwi", b"sekurlsa:: logonpasswords benign"):
        payload = b"MZ\x00PE\x00\x00" + b"\x00" * (16 * 1024 * 1024) + tokens
        arguments = (Path("inert.bin"), payload)
        kwargs = {"observed_content_sha256": "0" * 64, "observed_file_identity": identity}
        previous = lambda: before["_response_classification"](*arguments, **kwargs)
        current = lambda: after["_response_classification"](*arguments, **kwargs)
        expected = previous()
        assert current() == expected
        old_time, new_time = _timed(previous), _timed(current)
        print(f"classification payload=16MiB verdict={expected or 'none'}: "
              f"before={old_time:.6f}s after={new_time:.6f}s "
              f"improvement={(1 - new_time / old_time) * 100:.1f}%")


class _Entry:
    def __init__(self, root: Path, number: int):
        self.name = f"File{number:06d}.bin"
        self.path = str(root / self.name)

    def stat(self, **_): return SimpleNamespace(st_file_attributes=0)
    def is_symlink(self): return False
    def is_dir(self, **_): return False
    def is_file(self, **_): return True


class _Inventory:
    def __init__(self, entries):
        self.entries = entries

    def __enter__(self): return iter(self.entries)
    def __exit__(self, *_): pass


def _inventory_benchmark(before: dict, after: dict, module) -> None:
    root = ROOT / ".tmp" / "inert-yara-inventory"
    for count in (10_000, 100_000):
        entries = [_Entry(root, number) for number in reversed(range(count))]
        cursor = f"File{count // 2:06d}.bin"
        previous = lambda: before["_fair_batch"](module.YaraScannerModule, root, cursor)
        current = lambda: after["_fair_batch"](module.YaraScannerModule, root, cursor)
        with patch.object(module.os, "scandir", lambda _: _Inventory(entries)):
            assert previous() == current()
            old_time, new_time = _timed(previous), _timed(current)
        print(f"full_inventory entries={count}: before={old_time:.6f}s after={new_time:.6f}s "
              f"improvement={(1 - new_time / old_time) * 100:.1f}%")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-ref", default=DEFAULT_BASELINE,
                        help="Reviewed local Git revision containing the comparison scanner")
    parser.add_argument("--full-inventory", action="store_true",
                        help="Also time mocked 10k/100k complete inventories (can be slow)")
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT / "src"))
    from angerona.modules import yara_scanner

    source = subprocess.check_output(
        ["git", "show", f"{args.baseline_ref}:{SOURCE_PATH}"],
        cwd=ROOT, text=True, encoding="utf-8",
    )
    before = _load_methods(source, yara_scanner)
    after = _load_methods((ROOT / SOURCE_PATH).read_text(encoding="utf-8"), yara_scanner)
    print(f"Baseline: {args.baseline_ref}; Python {sys.version.split()[0]}")
    print("Median samples after one warmup: selection=15; classification/inventory=7.")
    print("Wall timing excludes tracing/profiling; separate selection allocation runs use tracemalloc.")
    print("Synthetic local measurements only; no whole-app CPU or filesystem speedup estimate.")
    _selection_benchmark(before, after)
    _classification_benchmark(before, after)
    if args.full_inventory:
        _inventory_benchmark(before, after, yara_scanner)


if __name__ == "__main__":
    main()
