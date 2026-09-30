"""A YARA worker restart must not dispose a thread-bound scanner elsewhere."""
from __future__ import annotations

import threading
import sys
from types import SimpleNamespace

from angerona.modules.yara_scanner import YaraScannerModule


def test_yara_activation_on_next_worker_does_not_drop_previous_thread_scanner(tmp_path) -> None:
    rules = tmp_path / "rules.yar"
    rules.write_text("rule RestartProbe { condition: true }", encoding="utf-8")
    module = YaraScannerModule()
    first_ready = threading.Event()
    release_first = threading.Event()
    failures: list[BaseException] = []

    def activate_first() -> None:
        try:
            module._activate(rules)
            first_ready.set()
            release_first.wait(10)
        except BaseException as exc:
            failures.append(exc)
            first_ready.set()

    def activate_second() -> None:
        if not first_ready.wait(10):
            failures.append(TimeoutError("first YARA worker did not activate"))
            return
        try:
            module._activate(rules)
        except BaseException as exc:
            failures.append(exc)

    first = threading.Thread(target=activate_first, name="YaraWorkerFirst")
    second = threading.Thread(target=activate_second, name="YaraWorkerSecond")
    first.start()
    second.start()
    second.join(15)
    release_first.set()
    first.join(15)
    assert not first.is_alive() and not second.is_alive()
    assert not failures
    assert module._compiled_rules is not None


def test_configuration_traceback_does_not_retain_native_scanner(monkeypatch):
    finalized = []
    retained = []
    owners = []

    class Scanner:
        def __init__(self, _rules):
            owners.append(threading.get_ident())

        def set_timeout(self, _timeout):
            # Native methods do not contribute a Python frame retaining self.
            self = None
            raise RuntimeError("configuration refused")

        def __del__(self):
            finalized.append(threading.get_ident())

    monkeypatch.setitem(sys.modules, "yara_x", SimpleNamespace(Scanner=Scanner))

    def worker():
        try:
            YaraScannerModule._make_scanner(object())
        except RuntimeError as exc:
            retained.append(exc)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(10)
    assert not thread.is_alive()
    assert retained
    assert finalized == owners


def test_scan_failure_traceback_detaches_native_scanner(tmp_path, monkeypatch):
    path = tmp_path / "proof.bin"
    path.write_bytes(b"inert")
    module = YaraScannerModule()
    retained = RuntimeError("classification refused")
    owners = []
    finalized = []
    outcomes = []

    class Scanner:
        def __init__(self):
            owners.append(threading.get_ident())

        def scan(self, _payload):
            return SimpleNamespace(matching_rules=[])

        def __del__(self):
            finalized.append(threading.get_ident())

    def fail_classification(*_args, **_kwargs):
        raise retained

    monkeypatch.setattr(module, "_response_classification", fail_classification)

    def worker():
        scanner = Scanner()
        try:
            outcomes.append(module._scan_file(scanner, path))
        finally:
            scanner = None

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(10)
    assert not thread.is_alive()
    assert outcomes == ["failed"]
    assert retained.__traceback__ is not None
    traceback = retained.__traceback__
    frames = []
    while traceback is not None:
        frames.append((traceback.tb_frame.f_code.co_name, [
            key for key, value in traceback.tb_frame.f_locals.items()
            if isinstance(value, Scanner)
        ]))
        traceback = traceback.tb_next
    assert finalized == owners, frames


def test_run_setup_failure_finalizes_scanner_before_traceback_leaves_worker(tmp_path, monkeypatch):
    rules = tmp_path / "rules.yar"
    rules.write_text("rule inert { condition: false }", encoding="utf-8")
    module = YaraScannerModule()
    retained = []
    owners = []
    finalized = []

    class Scanner:
        def __init__(self):
            owners.append(threading.get_ident())

        def __del__(self):
            finalized.append(threading.get_ident())

    def fail_cursor_load():
        raise RuntimeError("cursor unavailable")

    monkeypatch.setattr(module, "_find_rules", lambda: str(rules))
    monkeypatch.setattr(module, "_activate", lambda _path: object())
    monkeypatch.setattr(module, "_make_scanner", lambda _compiled: Scanner())
    monkeypatch.setattr(module, "_load_cursor_state", fail_cursor_load)

    def worker():
        try:
            module.run()
        except RuntimeError as exc:
            retained.append(exc)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(10)
    assert not thread.is_alive()
    assert retained
    assert finalized == owners
