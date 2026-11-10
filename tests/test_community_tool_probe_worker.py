import base64
import json
from pathlib import Path
import sys

import pytest

from angerona.core.community_tool_adapters import AdapterOperation
from angerona.core import community_tool_probe_worker as worker

RULE = 'rule inert_fixture { strings: $a = "ANGERONA_INERT_PROBE" condition: $a }'


@pytest.mark.parametrize("source", ['include "outside.yar"', 'import "pe"\nrule a { condition: true }', 'x'*65537], ids=["include", "import", "oversize"])
def test_probe_rejects_includes_imports_and_oversize_without_spawn(source, tmp_path, monkeypatch):
    monkeypatch.setattr(worker, "_require_unprivileged", lambda: None)
    with pytest.raises(ValueError, match="64 KiB"):
        worker.run_yara_probe(tmp_path / "probe", [{"path": "fixture.yar", "text": source}], [b"inert"], AdapterOperation())
    assert not (tmp_path / "probe").exists()


def test_closed_probe_request_binds_exact_rule_and_sample_bytes():
    raw = worker._request([{"path": "fixture.yar", "text": RULE}], [b"positive inert"])
    document = json.loads(raw)
    assert document["schema"] == 1 and document["sources"][0]["text"] == RULE
    assert base64.b64decode(document["samples"][0]["base64"]) == b"positive inert"
    with pytest.raises(ValueError):
        worker._request([{"path": "fixture.yar", "text": RULE, "command": "forbidden"}], [b"inert"])


def test_cancelled_probe_does_not_spawn_or_create_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(worker, "_require_unprivileged", lambda: None)
    operation = AdapterOperation()
    operation.cancel()
    with pytest.raises(ValueError, match="cancelled"):
        worker.run_yara_probe(tmp_path / "probe", [{"path": "fixture.yar", "text": RULE}], [b"inert"], operation)
    assert not (tmp_path / "probe").exists()


def test_actual_owned_native_yara_worker_positive_negative_and_retirement(tmp_path, monkeypatch):
    from angerona.core.privilege import is_admin
    if sys.platform == "win32" and is_admin():
        pytest.skip("Production worker deliberately refuses an administrator token")
    pytest.importorskip("yara_x")
    # Staging-only entry seam: production app dispatch is not edited while live.
    # The actual launch, Job limits, real compiler, exit/retirement and cleanup
    # remain the unchanged production runner under test.
    monkeypatch.setattr(worker, "_probe_argv", lambda request, digest: [sys.executable, "-I", "-B", str(Path(worker.__file__)), "--request", str(request), "--sha256", digest])
    result = worker.run_yara_probe(tmp_path / "probe", [{"path": "fixture.yar", "text": RULE}],
                                   [b"ANGERONA_INERT_PROBE", b"ordinary negative"], AdapterOperation(timeout=30))
    assert result["state"] == "completed", result
    assert result["matches"] == [{"sample": 0, "rules": ["inert_fixture"]}, {"sample": 1, "rules": []}]
    assert result["worker_retired"] is True and result["response_authority"] is False
    assert not worker._HELD
    assert [path.name for path in (tmp_path / "probe").iterdir()] == ["probe.lock"]


def test_fixed_source_and_frozen_dispatch_never_accepts_arbitrary_script(monkeypatch, tmp_path):
    request = tmp_path / "request.json"
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    source = worker._probe_argv(request, "a"*64)
    assert source[1:6] == ["-I", "-B", "-m", "angerona", "--community-tool-probe"]
    monkeypatch.setattr(sys, "frozen", True)
    frozen = worker._probe_argv(request, "a"*64)
    assert frozen[1] == "--community-tool-probe" and "-m" not in frozen
    assert worker.worker_main(["--run", "arbitrary.py"]) == 2


def test_actual_owned_compile_failure_then_success_is_retired(tmp_path, monkeypatch):
    from angerona.core.privilege import is_admin
    if sys.platform == "win32" and is_admin():
        pytest.skip("Ordinary-user native probe fixture")
    pytest.importorskip("yara_x")
    monkeypatch.setattr(worker, "_probe_argv", lambda request, digest: [sys.executable, "-I", "-B", str(Path(worker.__file__)), "--request", str(request), "--sha256", digest])
    invalid = worker.run_yara_probe(tmp_path / "probe", [{"path": "bad.yar", "text": "rule broken { condition: ( }"}], [b"inert"], AdapterOperation(timeout=30))
    assert invalid["state"] == "invalid" and invalid["worker_retired"]
    valid = worker.run_yara_probe(tmp_path / "probe", [{"path": "good.yar", "text": RULE}], [b"ordinary negative"], AdapterOperation(timeout=30))
    assert valid["state"] == "completed" and valid["worker_retired"]
    assert not worker._HELD and [path.name for path in (tmp_path / "probe").iterdir()] == ["probe.lock"]


def test_probe_retained_spool_limit_never_deletes_old_diagnostics_or_spawns(tmp_path, monkeypatch):
    monkeypatch.setattr(worker, "_require_unprivileged", lambda: None)
    root = tmp_path / "probe"
    root.mkdir()
    for index in range(worker.MAX_RETAINED_PROBES):
        folder = root / format(index, "032x")
        folder.mkdir()
        (folder / "result.json").write_text("preserved failure diagnostic")
    with pytest.raises(ValueError, match="retained-directory limit"):
        worker.run_yara_probe(root, [{"path": "fixture.yar", "text": RULE}], [b"inert"], AdapterOperation())
    assert all((root / format(index, "032x") / "result.json").read_text() == "preserved failure diagnostic" for index in range(worker.MAX_RETAINED_PROBES))


def test_actual_owned_probe_independent_namespaces_allow_same_rule_names(tmp_path, monkeypatch):
    from angerona.core.privilege import is_admin
    if sys.platform == "win32" and is_admin():
        pytest.skip("Ordinary-user native probe fixture")
    pytest.importorskip("yara_x")
    monkeypatch.setattr(worker, "_probe_argv", lambda request, digest: [sys.executable, "-I", "-B", str(Path(worker.__file__)), "--request", str(request), "--sha256", digest])
    first = 'rule same_name { strings: $a = "FIRST_INERT_MARKER" condition: $a }'
    second = 'rule same_name { strings: $a = "SECOND_INERT_MARKER" condition: $a }'
    result = worker.run_yara_probe(tmp_path / "probe", [{"path": "first.yar", "text": first}, {"path": "second.yar", "text": second}],
                                   [b"FIRST_INERT_MARKER", b"SECOND_INERT_MARKER", b"ordinary inert negative"], AdapterOperation(timeout=30))
    assert result["state"] == "completed", result
    assert result["matches"] == [{"sample": 0, "rules": ["same_name"]}, {"sample": 1, "rules": ["same_name"]}, {"sample": 2, "rules": []}]
    assert result["source_namespaces"] == {worker.source_namespace("first.yar"): "first.yar", worker.source_namespace("second.yar"): "second.yar"}
    assert result["worker_retired"] and worker.probe_custody_released()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job native resource contract")
def test_actual_application_entry_requires_and_verifies_resource_limited_outer_job(tmp_path, monkeypatch):
    from angerona.core.privilege import is_admin
    if is_admin():
        pytest.skip("Ordinary-user native probe fixture")
    pytest.importorskip("yara_x")
    # Exercise the production application dispatch, including venv redirection
    # and the worker's query-only outer Job membership/caps despite the venv's
    # own inner Job. No arbitrary helper argv seam or visible helper window.
    import win32process
    import win32con
    create = win32process.CreateProcess
    observed = []
    def hidden_create(*args):
        observed.append((args[5], args[8].dwFlags, args[8].wShowWindow))
        return create(*args)
    monkeypatch.setattr(win32process, "CreateProcess", hidden_create)
    result = worker.run_yara_probe(tmp_path / "probe", [{"path": "fixture.yar", "text": RULE}],
        [b"ANGERONA_INERT_PROBE", b"negative inert bytes"], AdapterOperation(timeout=30))
    assert result["state"] == "completed" and result["worker_retired"]
    assert result["matches"] == [{"sample": 0, "rules": ["inert_fixture"]}, {"sample": 1, "rules": []}]
    assert worker.probe_custody_released()
    assert [path.name for path in (tmp_path / "probe").iterdir()] == ["probe.lock"]
    assert len(observed) == 1
    flags, startup_flags, show = observed[0]
    assert flags & win32con.CREATE_NO_WINDOW and not flags & win32con.CREATE_NEW_CONSOLE
    assert startup_flags & win32con.STARTF_USESHOWWINDOW and show == 0


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job native resource contract")
def test_ready_marker_without_actual_resource_limits_cannot_start_native_compilation(tmp_path, monkeypatch):
    from angerona.core.privilege import is_admin
    if is_admin():
        pytest.skip("Ordinary-user native probe fixture")
    # The private owned Job and normal ready marker exist, but no memory/CPU
    # admission was set. The child must reject actual OS facts, then retire.
    # Use the same fixed worker seam as the native positive; an unrelated
    # application startup hold must not make this admission test pass.
    monkeypatch.setattr(worker, "_probe_argv", lambda request, digest: [sys.executable, "-I", "-B", str(Path(worker.__file__)), "--request", str(request), "--sha256", digest])
    monkeypatch.setattr(worker, "_windows_limits", lambda _child: None)
    with pytest.raises(ValueError, match="failed or reached a resource limit"):
        worker.run_yara_probe(tmp_path / "probe", [{"path": "fixture.yar", "text": RULE}],
            [b"ANGERONA_INERT_PROBE"], AdapterOperation(timeout=30))
    assert worker.probe_custody_released()
    assert [path.name for path in (tmp_path / "probe").iterdir()] == ["probe.lock"]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job native collision contract")
def test_preexisting_probe_job_is_never_configured_or_used_for_a_child(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import win32job
    import win32process
    from angerona.core.privilege import is_admin
    if is_admin():
        pytest.skip("Ordinary-user native probe fixture")
    fixed = "a" * 32
    root = tmp_path / "probe"
    handle = win32job.CreateJobObject(None, worker._probe_job_name(root / fixed))
    try:
        before = win32job.QueryInformationJobObject(handle, win32job.JobObjectExtendedLimitInformation)
        monkeypatch.setattr(worker.uuid, "uuid4", lambda: SimpleNamespace(hex=fixed))
        monkeypatch.setattr(win32process, "CreateProcess", lambda *_a: pytest.fail("Collision must refuse before launch"))
        with pytest.raises(FileExistsError, match="already in use"):
            worker.run_yara_probe(root, [{"path": "fixture.yar", "text": RULE}], [b"inert"], AdapterOperation())
        after = win32job.QueryInformationJobObject(handle, win32job.JobObjectExtendedLimitInformation)
        assert after == before
        assert worker.probe_custody_released()
        assert [path.name for path in root.iterdir()] == ["probe.lock"]
    finally:
        handle.Close()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job native membership contract")
def test_named_job_query_requires_actual_calling_process_membership(tmp_path):
    import uuid
    import win32job
    root = tmp_path / uuid.uuid4().hex
    handle = win32job.CreateJobObject(None, worker._probe_job_name(root))
    try:
        with pytest.raises(ValueError, match="not a member"):
            worker._verify_windows_worker_limits(root)
        # The worker's query reference was closed; the original owner remains
        # queryable and is never configured or terminated by admission.
        assert win32job.QueryInformationJobObject(handle, win32job.JobObjectExtendedLimitInformation)
    finally:
        handle.Close()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job private naming contract")
@pytest.mark.parametrize("name", ["Global\\Angerona.YaraProbe." + "a" * 32,
    "Local\\OtherProbe." + "a" * 32, "Local\\Angerona.YaraProbe." + "A" * 32, ""])
def test_optional_job_name_cannot_expand_into_an_arbitrary_namespace(name):
    from angerona.core.windows_child_job import WindowsChildJob
    with pytest.raises(ValueError, match="private YARA"):
        WindowsChildJob(job_name=name)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job closed native facts")
@pytest.mark.parametrize("changed", ["missing-memory", "too-much-memory", "too-many-processes", "breakaway", "no-kill-on-close", "no-hard-cpu", "cpu-too-high"])
def test_native_job_admission_rejects_missing_or_weaker_limits(changed):
    import win32job
    flags = win32job.JOB_OBJECT_LIMIT_JOB_MEMORY | win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS | win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    limits = {"BasicLimitInformation": {"LimitFlags": flags, "ActiveProcessLimit": 4}, "JobMemoryLimit": 512 * 1024 * 1024}
    cpu_flags, cpu_rate = 5, 3000
    if changed == "missing-memory":
        limits["BasicLimitInformation"]["LimitFlags"] &= ~win32job.JOB_OBJECT_LIMIT_JOB_MEMORY
    elif changed == "too-much-memory":
        limits["JobMemoryLimit"] += 1
    elif changed == "too-many-processes":
        limits["BasicLimitInformation"]["ActiveProcessLimit"] = 5
    elif changed == "breakaway":
        limits["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK
    elif changed == "no-kill-on-close":
        limits["BasicLimitInformation"]["LimitFlags"] &= ~win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    elif changed == "no-hard-cpu":
        cpu_flags = 1
    elif changed == "cpu-too-high":
        cpu_rate = 3001
    with pytest.raises(ValueError, match="actual Windows Job"):
        worker._validate_windows_admission(limits, cpu_flags, cpu_rate)


@pytest.mark.parametrize("bad", [False, True])
def test_posix_worker_checks_actual_limit_readback_without_touching_host_limits(monkeypatch, bad):
    from types import SimpleNamespace
    set_values = {}
    fake = SimpleNamespace(RLIMIT_AS=1, RLIMIT_CPU=2,
        setrlimit=lambda key, value: set_values.update({key: value}),
        getrlimit=lambda key: (-1, -1) if bad else set_values[key])
    monkeypatch.setitem(sys.modules, "resource", fake)
    if bad:
        with pytest.raises(ValueError, match="actual POSIX"):
            worker._install_posix_worker_limits()
    else:
        worker._install_posix_worker_limits()
        assert set_values == {1: (512 * 1024 * 1024,) * 2, 2: (10, 10)}


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native query-close contract")
def test_worker_never_compiles_after_ambiguous_query_handle_close(tmp_path, monkeypatch):
    import ctypes
    import hashlib
    from types import SimpleNamespace
    import win32job
    closes = []
    class QueryHandle:
        def __int__(self):
            return 123
        def Close(self):
            closes.append("attempted")
            raise OSError("ambiguous native close")
    handle = QueryHandle()
    flags = (win32job.JOB_OBJECT_LIMIT_JOB_MEMORY | win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
    monkeypatch.setattr(win32job, "OpenJobObject", lambda access, inherit, name:
        handle if access == win32job.JOB_OBJECT_QUERY and inherit is False else pytest.fail("Query-only custody required"))
    monkeypatch.setattr(win32job, "IsProcessInJob", lambda _process, query: query is handle)
    monkeypatch.setattr(win32job, "QueryInformationJobObject", lambda *_a:
        {"BasicLimitInformation": {"LimitFlags": flags, "ActiveProcessLimit": 4}, "JobMemoryLimit": 512 * 1024**2})
    def query(_handle, _kind, rate, _size, returned):
        rate._obj.flags, rate._obj.rate, returned._obj.value = 5, 3000, 8
        return 1
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_a, **_k: SimpleNamespace(QueryInformationJobObject=query))
    monkeypatch.setitem(sys.modules, "yara_x", SimpleNamespace(Compiler=lambda:
        pytest.fail("Compilation requires successful native query-reference retirement")))
    monkeypatch.setattr(worker, "_require_unprivileged", lambda: None)
    root = tmp_path / ("b" * 32)
    root.mkdir()
    raw = worker._request([{"path": "fixture.yar", "text": RULE}], [b"inert"])
    (root / "request.json").write_bytes(raw)
    (root / "ready").write_bytes(b"ready")
    with pytest.raises(OSError, match="ambiguous native close"):
        worker._worker(root / "request.json", hashlib.sha256(raw).hexdigest())
    assert closes == ["attempted"] and not (root / "result.json").exists()
