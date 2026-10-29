"""Running generated data may disappear; stable custody and quotas may not."""
from __future__ import annotations

from contextlib import contextmanager
import errno
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import threading
import time
from types import SimpleNamespace

import pytest

from angerona.core import curated_tools as tools


def job_state(tmp_path):
    job = tmp_path / ("a" * 32)
    state = tools._JobState()
    for name in ("", "scratch", "cache", "profile", "profile/local", "profile/roaming", "profile/config"):
        path = job / name
        path.mkdir(parents=True, exist_ok=True)
        info = path.lstat()
        state.directories[path] = tools._windows_node(path) if os.name == "nt" else (info.st_dev, info.st_ino)
    return job, state


@contextmanager
def delete_after_enumeration(monkeypatch, parent, victims):
    """Real DirEntries, actual concurrent unlink/rmdir, deterministic timing."""
    enumerated, deleted = threading.Event(), threading.Event()
    errors = []
    real = os.scandir

    def remover():
        try:
            assert enumerated.wait(3)
            for victim in victims:
                victim.rmdir() if victim.is_dir() else victim.unlink()
        except BaseException as error:
            errors.append(error)
        finally:
            deleted.set()

    @contextmanager
    def scan(path):
        if Path(path) != parent:
            with real(path) as entries:
                yield entries
            return
        with real(path) as entries:
            retained = list(entries)
        enumerated.set()
        assert deleted.wait(3) and not errors, errors
        yield iter(retained)

    worker = threading.Thread(target=remover)
    worker.start()
    with monkeypatch.context() as patch:
        patch.setattr(tools.os, "scandir", scan)
        try:
            yield
        finally:
            enumerated.set()
            worker.join(3)
            assert not worker.is_alive() and not errors, errors


@pytest.mark.parametrize("base", ["scratch", "cache", "profile"])
@pytest.mark.parametrize("live", [False, True])
def test_real_generated_leaf_disappearance_only_tolerated_by_live_accounting(tmp_path, monkeypatch, base, live):
    job, state = job_state(tmp_path)
    leaf = job / base / "History"
    leaf.write_bytes(b"owned temporary copy")
    with delete_after_enumeration(monkeypatch, leaf.parent, [leaf]):
        if live:
            rows, _used = tools._live_job_inventory(job, state)
            assert leaf not in {path for path, _info in rows}
        else:
            with pytest.raises(FileNotFoundError):
                tools._inventory(job)


@pytest.mark.parametrize("point", ["open", "iterator"])
def test_disappeared_nested_directory_before_scandir_or_iterator_keeps_already_counted_bytes(tmp_path, monkeypatch, point):
    job, state = job_state(tmp_path)
    nested = job / "scratch/bscan_owned"
    nested.mkdir()
    stable = job / "request.json"
    stable.write_bytes(b"stable control")
    real = os.scandir
    entered, deleted = threading.Event(), threading.Event()

    def remove():
        assert entered.wait(3)
        nested.rmdir()
        deleted.set()

    @contextmanager
    def scan(path):
        if Path(path) != nested:
            with real(path) as entries:
                yield entries
            return
        entered.set()
        assert deleted.wait(3)
        if point == "open":
            with real(path) as entries:
                yield entries
        else:
            def iterator():
                raise FileNotFoundError(errno.ENOENT, "owned directory vanished", str(path))
                yield  # pragma: no cover - generator protocol, no fabricated entries
            yield iterator()

    worker = threading.Thread(target=remove)
    worker.start()
    try:
        monkeypatch.setattr(tools.os, "scandir", scan)
        _rows, used = tools._live_job_inventory(job, state)
        assert used >= len(b"stable control")
    finally:
        entered.set()
        worker.join(3)
        assert not worker.is_alive()


@pytest.mark.parametrize("name", ["request.json", "report.json", "report.txt", "summary.json", "stdout.log", "stderr.log",
                                    ".zbt_report_bad.tmp", ".zbt_report_ABCDEFGH.tmp", ".zbt_handoff_abcdefgh.tmp"])
def test_missing_stable_controls_or_unrecognized_root_temporaries_remain_fatal(tmp_path, monkeypatch, name):
    job, state = job_state(tmp_path)
    victim = job / name
    victim.write_bytes(b"stable or unrecognized")
    with delete_after_enumeration(monkeypatch, job, [victim]):
        with pytest.raises(FileNotFoundError):
            tools._live_job_inventory(job, state)


@pytest.mark.parametrize("prefix", ["report", "text"])
@pytest.mark.parametrize("live", [False, True])
def test_only_exact_atomic_report_leaf_names_may_vanish(tmp_path, monkeypatch, prefix, live):
    job, state = job_state(tmp_path)
    victim = job / f".zbt_{prefix}_a1_b2c3d.tmp"
    victim.write_bytes(b"atomic report output")
    with delete_after_enumeration(monkeypatch, job, [victim]):
        if live:
            tools._live_job_inventory(job, state)
        else:
            with pytest.raises(FileNotFoundError):
                tools._inventory(job)


@pytest.mark.parametrize("prefix,destination", [("report", "report.json"), ("text", "report.txt")])
@pytest.mark.parametrize("live", [False, True])
def test_real_atomic_report_rename_preserves_final_control_and_strict_default(tmp_path, monkeypatch, prefix, destination, live):
    job, state = job_state(tmp_path)
    temporary = job / f".zbt_{prefix}_a1_b2c3d.tmp"
    final = job / destination
    payload = b"owned atomic report"
    temporary.write_bytes(payload)
    enumerated, renamed = threading.Event(), threading.Event()
    errors = []
    real = os.scandir

    def replace():
        try:
            assert enumerated.wait(3)
            os.replace(temporary, final)
        except BaseException as error:
            errors.append(error)
        finally:
            renamed.set()

    @contextmanager
    def scan(path):
        with real(path) as entries:
            if Path(path) != job:
                yield entries
                return
            retained = list(entries)
        enumerated.set()
        assert renamed.wait(3) and not errors, errors
        yield iter(retained)

    worker = threading.Thread(target=replace)
    worker.start()
    try:
        with monkeypatch.context() as patch:
            patch.setattr(tools.os, "scandir", scan)
            if live:
                tools._live_job_inventory(job, state)
            else:
                with pytest.raises(FileNotFoundError):
                    tools._inventory(job)
        rows, used = tools._inventory(job)
        assert final in {path for path, _info in rows} and used == len(payload)
        assert final.read_bytes() == payload and not temporary.exists()
    finally:
        enumerated.set()
        worker.join(3)
        assert not worker.is_alive() and not errors, errors


def test_root_directory_named_like_report_temp_does_not_gain_disappearance_permission(tmp_path, monkeypatch):
    job, state = job_state(tmp_path)
    victim = job / ".zbt_report_abcdefgh.tmp"
    victim.mkdir()
    with delete_after_enumeration(monkeypatch, job, [victim]):
        with pytest.raises(FileNotFoundError):
            tools._live_job_inventory(job, state)


@pytest.mark.parametrize("name", ["scratch", "cache", "profile/config"])
def test_created_control_bases_cannot_disappear(tmp_path, name):
    job, state = job_state(tmp_path)
    (job / name).rmdir()
    with pytest.raises((ValueError, FileNotFoundError, tools.ToolError)):
        tools._live_job_inventory(job, state)


def test_changed_control_identity_is_not_adopted(tmp_path):
    job, state = job_state(tmp_path)
    (job / "cache").rename(job / "old-cache")
    (job / "cache").mkdir()
    with pytest.raises(tools.ToolError, match="identity"):
        tools._live_job_inventory(job, state)


def test_pending_generated_directory_replacement_is_detected_without_mtime_false_positive(tmp_path, monkeypatch):
    job, state = job_state(tmp_path)
    scratch = job / "scratch"
    nested = scratch / "bscan_owned"
    nested.mkdir()
    real = os.scandir

    @contextmanager
    def scan(path):
        if Path(path) != scratch:
            with real(path) as entries:
                yield entries
            return
        with real(path) as entries:
            retained = list(entries)
        def iterator():
            for entry in retained:
                yield entry
                if Path(entry.path) == nested:
                    nested.rename(scratch / "old-generation")
                    nested.mkdir()
        yield iterator()

    monkeypatch.setattr(tools.os, "scandir", scan)
    with pytest.raises(tools.ToolError, match="identity"):
        tools._live_job_inventory(job, state)


def test_vanished_names_still_exhaust_entry_limit_and_surviving_bytes_exhaust_byte_limit(tmp_path, monkeypatch):
    job, state = job_state(tmp_path)
    scratch = job / "scratch"
    victims = [scratch / f"vanish-{index}" for index in range(20)]
    for victim in victims:
        victim.write_bytes(b"temporary")
    with delete_after_enumeration(monkeypatch, scratch, victims):
        with pytest.raises(tools.ToolError, match="entry limit"):
            tools._live_job_inventory(job, state, limit=10)
    (scratch / "surviving.bin").write_bytes(b"x" * 32)
    with pytest.raises(tools.ToolError, match="byte budget"):
        tools._live_job_inventory(job, state, byte_limit=31)


@pytest.mark.parametrize("error_type,number", [(PermissionError, errno.EACCES), (NotADirectoryError, errno.ENOTDIR)])
def test_non_disappearance_os_errors_remain_fatal(tmp_path, monkeypatch, error_type, number):
    job, state = job_state(tmp_path)
    nested = job / "scratch/bscan_owned"
    nested.mkdir()
    real = os.scandir

    def scan(path):
        if Path(path) == nested:
            raise error_type(number, "owned refusal", str(path))
        return real(path)

    monkeypatch.setattr(tools.os, "scandir", scan)
    with pytest.raises(error_type):
        tools._live_job_inventory(job, state)


def test_hardlink_and_reparse_metadata_are_still_rejected(tmp_path, monkeypatch):
    job, state = job_state(tmp_path)
    original = tmp_path / "outside-owned-original"
    original.write_bytes(b"preserved")
    linked = job / "scratch/linked"
    os.link(original, linked)
    with pytest.raises(tools.ToolError, match="linked"):
        tools._live_job_inventory(job, state)
    linked.unlink()
    redirected = job / "scratch/redirected"
    redirected.write_bytes(b"inert")
    real = Path.lstat

    def observed(path):
        info = real(path)
        return SimpleNamespace(st_mode=info.st_mode, st_nlink=1, st_file_attributes=0x400) if path == redirected else info

    monkeypatch.setattr(Path, "lstat", observed)
    with pytest.raises(tools.ToolError, match="redirected"):
        tools._live_job_inventory(job, state)
    assert original.read_bytes() == b"preserved"


@pytest.mark.skipif(os.name != "nt", reason="Actual ordinary-user pinned browser worker with native Job custody")
def test_actual_pinned_browser_report_survives_generated_temp_churn(tmp_path, monkeypatch):
    identity = tools._admin_state()
    if identity.get("verified") is not True or identity.get("elevated") is not False:
        pytest.skip("Managed engine requires ordinary-user token; no elevated bypass")
    profile = tmp_path / "owned-browser/Default"
    profile.mkdir(parents=True)
    (profile / "Preferences").write_text("{}", encoding="utf-8")
    history = profile / "History"
    with sqlite3.connect(history) as connection:
        connection.execute("CREATE TABLE urls(url TEXT,title TEXT,last_visit_time INTEGER)")
        connection.execute("CREATE TABLE downloads(current_path TEXT,tab_url TEXT,referrer TEXT)")
        connection.executemany("INSERT INTO urls VALUES(?,?,?)", [
            ("https://owned-inventory.invalid/" if index == 10 else f"https://owned-{index}.invalid/", "Inert test row", 13300000000000000)
            for index in range(100)])
    before = history.read_bytes()
    indicators = tmp_path / "owned-iocs.txt"
    indicators.write_text("owned-inventory.invalid\tsample\tprimary\towned test fixture\n", encoding="utf-8")
    bundle = Path(__file__).resolve().parents[1] / "assets/integrations/zero_breach"
    service = tools.CuratedToolService(tmp_path / "managed-tools", bundle=bundle)
    service.prepare(tools.ToolOperation(timeout=30), allow_download=False)
    environment, command = service._environment, service._command
    fallback = tmp_path / "owned-fallback"
    for part in ("local", "roaming", "config"):
        (fallback / part).mkdir(parents=True, exist_ok=True)

    def isolated(job, **kwargs):
        result = environment(job, **kwargs)
        result.update(HOME=str(fallback), USERPROFILE=str(fallback), APPDATA=str(fallback / "roaming"),
                      LOCALAPPDATA=str(fallback / "local"), ProgramData=str(fallback), XDG_CONFIG_HOME=str(fallback / "config"))
        return result

    def controlled(image, path):
        result = command(image, path)
        index = result.index("-c") + 1
        marker = ";from angerona.core.curated_tool_worker import main;"
        observer = """
import sys,time
def no_external_work(event,args):
    if event.startswith('winreg.') or event in {'socket.connect','socket.getaddrinfo','subprocess.Popen','os.system'}:
        print('OWNED_CHURN_FORBIDDEN:'+event,file=sys.stderr,flush=True)
        raise PermissionError('Controlled browser fixture forbids network/host commands')
sys.addaudithook(no_external_work)
import angerona.core.curated_tool_progress as progress
original=progress._rows_visited
def observed(*args):
    original(*args)
    time.sleep(.05) # Bounded observation window; actual rows are unchanged.
progress._rows_visited=observed
from angerona.core.curated_tool_worker import main
"""
        assert result[index].count(marker) == 1
        result[index] = result[index].replace(marker, "\n" + observer + "\n")
        return result

    monkeypatch.setattr(service, "_environment", isolated)
    monkeypatch.setattr(service, "_command", controlled)
    monkeypatch.setattr(socket, "create_connection", lambda *_a, **_kw: pytest.fail("No fixture network"))
    real_scan = os.scandir
    ready, enumerated, deleted = threading.Event(), threading.Event(), threading.Event()
    churn_errors, races = [], []

    @contextmanager
    def scan(path):
        if Path(path).name != "bscan_live_fixture":
            with real_scan(path) as entries:
                yield entries
            return
        with real_scan(path) as entries:
            retained = list(entries)
        enumerated.set()
        assert deleted.wait(3)
        races.append(True)
        yield iter(retained)

    def churn():
        try:
            deadline = time.monotonic() + 15
            while not service.progress_snapshot().get("job_id"):
                assert time.monotonic() < deadline
                time.sleep(.01)
            job = service._root() / "jobs" / service.progress_snapshot()["job_id"]
            parent = job / "scratch/bscan_live_fixture"
            parent.mkdir()
            (parent / "History").write_bytes(b"owned disposable copy")
            ready.set()
            assert enumerated.wait(15)
            (parent / "History").unlink()
            parent.rmdir()
            deleted.set()
            for index in range(30):
                current = job / "scratch" / f"churn-{index}"
                current.mkdir()
                (current / "copy").write_bytes(b"disposable")
                (current / "copy").unlink()
                current.rmdir()
                time.sleep(.01)
        except BaseException as error:
            churn_errors.append(error)
            deleted.set()

    monkeypatch.setattr(tools.os, "scandir", scan)
    worker = threading.Thread(target=churn)
    worker.start()
    try:
        result = service.scan(tools.ToolScanRequest(mode="targeted", targets=(str(profile),), iocs=(str(indicators),), priority="normal"),
                              tools.ToolOperation(timeout=30))
        worker.join(5)
        assert ready.is_set() and races and not worker.is_alive() and not churn_errors, churn_errors
        assert result["state"] == "findings" and result["findings"], result
        assert result["native_retired"] and all(row["native_retired"] for row in result["native_generations"])
        report = Path(result["report"]).read_bytes()
        assert hashlib.sha256(report).hexdigest() == result["retained_files"]["report.json"]["sha256"]
        assert json.loads(report)["schema_version"] == "1.6"
        assert history.read_bytes() == before and service.wait_for_shutdown(3)
        assert "OWNED_CHURN_FORBIDDEN" not in Path(result["report"]).with_name("stderr.log").read_text(encoding="utf-8")
    finally:
        enumerated.set()
        deleted.set()
        worker.join(5)
        assert not worker.is_alive()
