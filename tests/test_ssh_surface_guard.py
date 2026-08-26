from __future__ import annotations

import base64
import json
import os
import stat
import sys
import types
from pathlib import Path

import pytest

import angerona.core.ssh_surface as ssh
import angerona.modules.ssh_surface_guard as ssh_guard_module
from angerona.core.eventbus import Event, EventBus
from angerona.modules.ssh_surface_guard import SSHSurfaceGuardModule


MASTER = bytes(range(32))


def _public_key(algorithm: str = "ssh-ed25519", marker: bytes = b"A") -> str:
    encoded_algorithm = algorithm.encode("ascii")
    blob = len(encoded_algorithm).to_bytes(4, "big") + encoded_algorithm + marker * 32
    return f"{algorithm} {base64.b64encode(blob).decode('ascii')}"


def _candidate(tmp_path: Path, text: str, *, mode: int = 0o600) -> ssh.AuthorizedKeyCandidate:
    home = tmp_path / "home"
    directory = home / ".ssh"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "authorized_keys"
    path.write_text(text, encoding="utf-8")
    try:
        home.chmod(0o700)
        directory.chmod(0o700)
        path.chmod(mode)
    except OSError:
        pass
    return ssh.AuthorizedKeyCandidate("alice", home, path)


def _inventory(candidate: ssh.AuthorizedKeyCandidate, *, platform: str = "linux") -> ssh.AuthorizedKeyInventory:
    return ssh.inventory_authorized_keys(
        (candidate,), privacy_key=ssh.load_ssh_purpose_keys(master_key=MASTER).privacy_key,
        platform=platform,
    )


def _snapshot(
    inventory: ssh.AuthorizedKeyInventory,
    *,
    config_digest: str = "a" * 64,
    runtime: ssh.SSHRuntimeEvidence | None = None,
    host_keys: tuple[dict[str, str], ...] = (),
) -> dict[str, object]:
    return ssh.build_ssh_snapshot(
        config_digest=config_digest,
        config_state="observed",
        inventory=inventory,
        host_keys=host_keys,
        runtime=runtime or ssh.SSHRuntimeEvidence((), ()),
    )


def test_parser_honors_comments_quotes_first_value_and_match_boundary() -> None:
    parsed = ssh.parse_sshd_config(
        """
        # PasswordAuthentication yes
        PasswordAuthentication "no" # ignored comment
        PasswordAuthentication yes
        AllowUsers "ops team" breakglass
        Match User contractor
            PasswordAuthentication yes
            AllowTcpForwarding yes
        """
    )
    assert parsed.option("passwordauthentication").value == "no"
    assert parsed.option("passwordauthentication").line == 3
    assert parsed.option("allowusers").arguments == ("ops team", "breakglass")
    assert parsed.option("allowtcpforwarding").state == "absent"
    assert parsed.match_lines
    assert any(item.code == "ssh.config.match_scope" for item in ssh.evaluate_sshd_posture(parsed))


def test_parser_include_precedence_fails_unknown_but_later_include_does_not_override() -> None:
    before = ssh.parse_sshd_config(
        "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\n"
    )
    after = ssh.parse_sshd_config(
        "PasswordAuthentication no\nInclude /etc/ssh/sshd_config.d/*.conf\n"
    )
    assert before.option("PasswordAuthentication").state == "ambiguous_include"
    assert after.option("PasswordAuthentication").state == "explicit"
    codes = {item.code for item in ssh.evaluate_sshd_posture(before)}
    assert "ssh.config.include_ambiguity.passwordauthentication" in codes
    assert "ssh.auth.password_unknown" in codes


def test_parser_marks_malformed_quotes_and_enforces_hard_bounds() -> None:
    parsed = ssh.parse_sshd_config('PasswordAuthentication "no\n')
    assert parsed.errors == ("line:1:unterminated quote",)
    with pytest.raises(ssh.SSHConfigLimitError):
        ssh.parse_sshd_config("A" * 50, max_bytes=10)
    with pytest.raises(ssh.SSHConfigLimitError):
        ssh.parse_sshd_config("x " + "A" * 50, max_line_chars=10)


def test_posture_covers_auth_forwarding_logging_rate_and_admin_surface() -> None:
    parsed = ssh.parse_sshd_config(
        """
        PasswordAuthentication yes
        KbdInteractiveAuthentication yes
        PermitEmptyPasswords yes
        PermitRootLogin yes
        AllowTcpForwarding yes
        AllowStreamLocalForwarding yes
        PermitTunnel yes
        GatewayPorts clientspecified
        X11Forwarding yes
        PermitUserEnvironment yes
        LogLevel ERROR
        MaxAuthTries 8
        LoginGraceTime 2m
        MaxSessions 20
        MaxStartups 20:30:100
        ClientAliveInterval 0
        Match Group administrators
            AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
        """
    )
    codes = {item.code for item in ssh.evaluate_sshd_posture(parsed, platform="windows")}
    assert {
        "ssh.auth.password_enabled",
        "ssh.auth.keyboard_interactive_enabled",
        "ssh.auth.empty_passwords",
        "ssh.auth.root_access",
        "ssh.auth.allowlist_missing",
        "ssh.auth.administrator_group",
        "ssh.forwarding.tcp_enabled",
        "ssh.forwarding.streamlocal_enabled",
        "ssh.forwarding.tun_enabled",
        "ssh.forwarding.gateway_ports",
        "ssh.forwarding.x11",
        "ssh.auth.user_environment",
        "ssh.logging.weak",
        "ssh.rate.max_auth_tries",
        "ssh.rate.login_grace",
        "ssh.session.max_sessions",
        "ssh.rate.max_startups",
        "ssh.session.idle_timeout",
    } <= codes


def test_canonical_config_candidates_cover_windows_linux_and_macos() -> None:
    windows = ssh.canonical_sshd_config_candidates(
        "windows", environ={"ProgramData": r"D:\ProgramData", "SystemRoot": r"D:\Windows"}
    )
    assert str(windows[0]).casefold().replace("/", "\\").endswith(
        r"programdata\ssh\sshd_config"
    )
    assert Path("/etc/ssh/sshd_config") in ssh.canonical_sshd_config_candidates("linux")
    assert Path("/private/etc/ssh/sshd_config") in ssh.canonical_sshd_config_candidates("macos")


def test_authorized_key_inventory_retains_only_fingerprints_and_ignores_comments(tmp_path: Path) -> None:
    key = _public_key(marker=b"K")
    candidate = _candidate(
        tmp_path,
        f'from="10.0.0.0/8",no-port-forwarding {key} secret comment alice@example\n',
    )
    inventory = _inventory(candidate)
    assert len(inventory.entries) == 1
    entry = inventory.entries[0]
    assert entry.fingerprint.startswith("SHA256:")
    assert "no-port-forwarding" in entry.restrictions
    serialized = json.dumps(entry.as_dict(), sort_keys=True)
    for forbidden in ("secret comment", "alice@example", "10.0.0.0/8", key.split()[1]):
        assert forbidden not in serialized


def test_key_reordering_and_comments_are_stable_but_add_remove_and_options_drift(tmp_path: Path) -> None:
    key_a = _public_key(marker=b"A")
    key_b = _public_key(marker=b"B")
    candidate = _candidate(tmp_path, f"{key_a} first\n{key_b} second\n")
    first = _inventory(candidate)
    candidate.path.write_text(f"{key_b} changed-comment\n{key_a} other-comment\n", encoding="utf-8")
    reordered = _inventory(candidate)
    assert ssh.compare_ssh_snapshots(_snapshot(first), _snapshot(reordered)) == {}

    key_c = _public_key(marker=b"C")
    candidate.path.write_text(f"{key_b}\n{key_a}\n{key_c}\n", encoding="utf-8")
    added = _inventory(candidate)
    added_changes = ssh.compare_ssh_snapshots(_snapshot(first), _snapshot(added))
    assert len(added_changes["keys_added"]) == 1

    candidate.path.write_text(f"no-port-forwarding {key_a}\n", encoding="utf-8")
    changed = _inventory(candidate)
    changes = ssh.compare_ssh_snapshots(_snapshot(first), _snapshot(changed))
    assert len(changes["keys_removed"]) == 1
    assert len(changes["keys_modified"]) == 1


def test_key_inventory_rejects_link_reparse_escape_without_reading(tmp_path: Path, monkeypatch) -> None:
    candidate = _candidate(tmp_path, _public_key() + "\n")
    real = ssh.path_has_link_or_reparse
    monkeypatch.setattr(
        ssh,
        "path_has_link_or_reparse",
        lambda path: Path(path) == candidate.path or real(path),
    )
    result = _inventory(candidate)
    assert result.entries == ()
    assert {item.code for item in result.issues} == {"ssh.keys.link_reparse_rejected"}


def test_windows_acl_is_unknown_until_a_safe_verifier_proves_it(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, _public_key() + "\n")
    privacy = ssh.load_ssh_purpose_keys(master_key=MASTER).privacy_key
    unknown = ssh.inventory_authorized_keys(
        (candidate,), privacy_key=privacy, platform="windows"
    )
    unsafe = ssh.inventory_authorized_keys(
        (candidate,), privacy_key=privacy, platform="windows",
        windows_acl_verifier=lambda _path: False,
    )
    verified = ssh.inventory_authorized_keys(
        (candidate,), privacy_key=privacy, platform="windows",
        windows_acl_verifier=lambda _path: True,
    )
    assert "ssh.keys.windows_acl_unknown" in {item.code for item in unknown.issues}
    assert "ssh.keys.windows_acl_unsafe" in {item.code for item in unsafe.issues}
    assert not {item.code for item in verified.issues} & {
        "ssh.keys.windows_acl_unknown", "ssh.keys.windows_acl_unsafe"
    }


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are unavailable")
def test_unix_group_writable_key_mode_is_flagged(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, _public_key() + "\n", mode=0o620)
    result = _inventory(candidate, platform="linux")
    assert "ssh.keys.file_mode_unsafe" in {item.code for item in result.issues}


def test_baseline_missing_is_unknown_provisional_and_tamper_is_not_relearned(tmp_path: Path) -> None:
    candidate = _candidate(tmp_path, _public_key() + "\n")
    snapshot = _snapshot(_inventory(candidate))
    path = tmp_path / "state" / "ssh.json"
    store = ssh.SSHBaselineStore(path, data_root=tmp_path, master_key=MASTER, clock=lambda: 10.0)
    first = store.observe(snapshot)
    assert first.status == "unknown"
    assert first.baseline_trusted is False
    assert path.exists()
    document = json.loads(path.read_text(encoding="utf-8"))
    document["body"]["snapshot"]["config_digest"] = "b" * 64
    path.write_text(json.dumps(document), encoding="utf-8")
    tampered = store.observe(snapshot)
    assert tampered.status == "tampered"
    assert json.loads(path.read_text(encoding="utf-8"))["body"]["snapshot"]["config_digest"] == "b" * 64


def test_authenticated_schema_one_baseline_is_upgraded_as_coverage_drift_not_tamper(
    tmp_path: Path,
) -> None:
    empty = ssh.AuthorizedKeyInventory((), (), 0, 0, 0, 0)
    current = _snapshot(empty)
    legacy = {
        key: value for key, value in current.items()
        if key in {
            "config_digest", "config_state", "authorized_keys", "host_keys", "services", "listeners"
        }
    }
    path = tmp_path / "ssh.json"
    store = ssh.SSHBaselineStore(path, data_root=tmp_path, master_key=MASTER)
    body = {
        "schema": 1,
        "trusted": True,
        "captured_at": 10.0,
        "snapshot": legacy,
    }
    wrapper = {"body": body, "hmac_sha256": store._signature(body)}
    path.write_text(json.dumps(wrapper, sort_keys=True), encoding="utf-8")
    result = store.observe(current)
    assert result.status == "drift"
    assert result.baseline_trusted is True
    assert "coverage" in result.changes


def test_missing_bus_key_never_writes_or_blesses_baseline(tmp_path: Path) -> None:
    empty = ssh.AuthorizedKeyInventory((), (), 0, 0, 0, 0)
    path = tmp_path / "state.json"
    store = ssh.SSHBaselineStore(path, data_root=tmp_path)
    result = store.observe(_snapshot(empty))
    assert result.status == "unknown"
    assert result.baseline_trusted is False
    assert not path.exists()


def test_bus_key_domains_are_stable_separate_and_malformed_key_fails_closed(tmp_path: Path) -> None:
    key_path = tmp_path / "bus.key"
    key_path.write_text(MASTER.hex(), encoding="ascii")
    loaded = ssh.load_ssh_purpose_keys(tmp_path)
    injected = ssh.load_ssh_purpose_keys(master_key=MASTER)
    assert loaded == injected
    assert loaded.baseline_key != loaded.privacy_key
    key_path.write_text("not-a-key", encoding="ascii")
    assert ssh.load_ssh_purpose_keys(tmp_path) is None


def test_authenticated_baseline_reports_config_host_key_service_and_listener_drift(tmp_path: Path) -> None:
    empty = ssh.AuthorizedKeyInventory((), (), 0, 0, 0, 0)
    privacy = ssh.load_ssh_purpose_keys(master_key=MASTER).privacy_key
    before_runtime = ssh.normalize_runtime_evidence(
        ({"name": "sshd", "executable": r"C:\Windows\System32\OpenSSH\sshd.exe", "state": "running"},),
        ({"address": "127.0.0.1", "port": 22, "service_identity": "sshd"},),
        privacy_key=privacy,
        platform="windows",
    )
    after_runtime = ssh.normalize_runtime_evidence(
        ({"name": "quiet-service", "executable": r"C:\Tools\sshd.exe", "state": "running"},),
        ({"address": "0.0.0.0", "port": 2222, "service_identity": "quiet-service"},),
        privacy_key=privacy,
        platform="windows",
    )
    host_token = "hostkey:v1:" + "1" * 32
    before = _snapshot(
        empty, runtime=before_runtime,
        host_keys=({"path_token": host_token, "digest": "1" * 64},),
    )
    after = _snapshot(
        empty, config_digest="b" * 64, runtime=after_runtime,
        host_keys=({"path_token": host_token, "digest": "2" * 64},),
    )
    store = ssh.SSHBaselineStore(tmp_path / "ssh.json", data_root=tmp_path, master_key=MASTER)
    store.establish_trusted(before)
    result = store.observe(after)
    assert result.status == "drift" and result.baseline_trusted is True
    assert {
        "config", "host_keys_modified", "services_added", "services_removed",
        "listeners_added", "listeners_removed",
    } <= set(result.changes)
    assert after_runtime.services[0].renamed is True
    assert after_runtime.services[0].nonstandard_binary is True


def test_log_analyzer_tokenizes_sources_and_accounts_and_detects_required_signals() -> None:
    lines = (
        "sshd[1]: Failed password for invalid user alice from 203.0.113.7 port 50000 ssh2",
        "sshd[2]: Accepted password for admin from 203.0.113.8 port 50001 ssh2",
        "sshd[3]: Accepted publickey for ops from 2001:db8::5 port 50002 ssh2",
        "sshd[4]: channel 3: open failed: direct-tcpip request from 203.0.113.9 port 1",
    )
    result = ssh.analyze_openssh_logs(lines, privacy_key=MASTER)
    assert {item.kind for item in result.evidence} == {
        "authentication_failure", "successful_password_auth", "successful_key_auth",
        "forwarding_or_tunnel_signal",
    }
    assert all(item.new_source for item in result.evidence)
    serialized = json.dumps([item.as_dict() for item in result.evidence], sort_keys=True)
    for forbidden in ("alice", "admin", "ops", "203.0.113", "2001:db8"):
        assert forbidden not in serialized
    second = ssh.analyze_openssh_logs(
        (lines[2],), privacy_key=MASTER, known_source_tokens=result.observed_source_tokens
    )
    assert second.evidence[0].new_source is False


def test_log_analyzer_stops_at_flood_bounds_and_aggregates() -> None:
    line = "sshd: Failed password for user from 192.0.2.1 port 22"
    consumed = 0
    max_bytes = 10000

    def flood():
        nonlocal consumed
        for _ in range(10000):
            consumed += 1
            yield line

    result = ssh.analyze_openssh_logs(
        flood(), privacy_key=MASTER, max_lines=50, max_bytes=max_bytes
    )
    assert consumed == 51
    assert result.lines_examined == 50
    assert result.dropped_lines == 1
    assert len(result.evidence) == 1
    assert result.evidence[0].count == 50
    assert result.bytes_examined < max_bytes


def test_module_is_observe_only_and_emits_no_raw_runtime_identity(tmp_path: Path) -> None:
    config = tmp_path / "sshd_config"
    config.write_text(
        "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\n"
        "AllowUsers ops\nAllowTcpForwarding no\nAllowStreamLocalForwarding no\n"
        "LogLevel VERBOSE\nMaxAuthTries 2\nLoginGraceTime 20\nMaxSessions 1\n"
        "MaxStartups 5:20:20\nClientAliveInterval 60\n",
        encoding="utf-8",
    )
    key_candidate = _candidate(tmp_path, _public_key() + " private-comment\n")

    def runtime(**kwargs):
        return ssh.normalize_runtime_evidence(
            ({"name": "renamed-secret-service", "executable": r"C:\Tools\sshd.exe", "state": "running"},),
            ({"address": "10.10.10.10", "port": 2222, "service_identity": "renamed-secret-service"},),
            privacy_key=kwargs["privacy_key"], platform="windows",
        )

    module = SSHSurfaceGuardModule(
        data_root=tmp_path / "data",
        master_key=MASTER,
        config_paths=(config,),
        key_candidates=(key_candidate,),
        runtime_collector=runtime,
        platform="windows",
    )
    bus = EventBus()
    module.bind(bus)
    result = module.observe_once()
    assert result["response_authorized"] is False
    events = bus.recent(100)
    assert events
    assert all(event.details.get("response_authorized") is False for event in events)
    serialized = json.dumps(
        [{"message": event.message, "details": event.details} for event in events],
        sort_keys=True,
    )
    for forbidden in ("renamed-secret-service", "10.10.10.10", "private-comment"):
        assert forbidden not in serialized
    assert "state-grade" in serialized
    assert "actor_attribution" in serialized


def test_module_self_test_is_cross_platform_and_negative_contract_is_explicit() -> None:
    module = SSHSurfaceGuardModule(data_root=Path("unused"), master_key=MASTER)
    assert module.self_test()[0] is True
    assert module.CODE == "SSHG"
    assert module.NAME == module.name
    assert isinstance(ssh_guard_module.register(), SSHSurfaceGuardModule)
    assert set(ssh_guard_module.__all__) == {"SSHSurfaceGuardModule", "register"}
    source = Path("src/angerona/modules/ssh_surface_guard.py").read_text(encoding="utf-8")
    assert "response_authorized\": False" in source
    assert "subprocess" not in source
    assert "socket" not in source
    assert "os.remove" not in source
    assert "unlink(" not in source


def test_retained_bus_callback_is_inert_after_module_stop(tmp_path: Path) -> None:
    module = SSHSurfaceGuardModule(data_root=tmp_path, master_key=MASTER)
    module._live_ingest_enabled.set()
    event = Event(
        module="Windows Event Log",
        message="OpenSSH event",
        details={
            "provider": "OpenSSH",
            "event_message": "Accepted password for alice from 198.51.100.2 port 22",
        },
    )
    module._on_bus_event(event)
    assert len(module._queued_log_evidence) == 1
    module.stop()
    module._on_bus_event(event)
    assert len(module._queued_log_evidence) == 1


def test_include_graph_digest_and_configured_sources_are_authenticated_without_paths(
    tmp_path: Path, monkeypatch,
) -> None:
    fragment_dir = tmp_path / "sshd_config.d"
    fragment_dir.mkdir()
    fragment = fragment_dir / "hardening.conf"
    fragment.write_text("PasswordAuthentication no\n", encoding="utf-8")
    authorized = tmp_path / "keys"
    authorized.write_text(_public_key(marker=b"Q") + " private-comment\n", encoding="utf-8")
    principals = tmp_path / "principals"
    principals.write_text("private-principal\n", encoding="utf-8")
    root = tmp_path / "sshd_config"
    root.write_text(
        "\n".join((
            "Include sshd_config.d/*.conf",
            f"AuthorizedKeysFile {authorized.as_posix()}",
            f"AuthorizedPrincipalsFile {principals.as_posix()}",
            "AuthorizedKeysCommand C:/Windows/System32/key-helper.exe --lookup %u",
        )) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(ssh, "verify_windows_ssh_acl", lambda _path: True)
    first = ssh.observe_sshd_config_graph(
        root, privacy_key=MASTER, platform="windows"
    )
    fragment.write_text("PasswordAuthentication yes\n", encoding="utf-8")
    second = ssh.observe_sshd_config_graph(
        root, privacy_key=MASTER, platform="windows"
    )
    assert first.files_observed == 2
    assert first.aggregate_digest != second.aggregate_digest
    assert len(first.authorized_key_candidates) == 1
    assert "ssh.key_command.unsupported" in first.issues
    assert {item.kind for item in first.sources} >= {
        "config", "include", "authorized_keys", "principals", "key_command"
    }
    serialized = json.dumps([item.as_dict() for item in first.sources], sort_keys=True)
    for forbidden in (str(tmp_path), "private-principal", "private-comment", "key-helper"):
        assert forbidden not in serialized
    empty = ssh.AuthorizedKeyInventory((), (), 0, 0, 0, 0)
    before = ssh.build_ssh_snapshot(
        config_digest=first.aggregate_digest,
        config_state="ambiguous",
        inventory=empty,
        host_keys=(),
        runtime=ssh.SSHRuntimeEvidence((), ()),
        configured_sources=first.sources,
        coverage=first.issues,
    )
    after = ssh.build_ssh_snapshot(
        config_digest=second.aggregate_digest,
        config_state="ambiguous",
        inventory=empty,
        host_keys=(),
        runtime=ssh.SSHRuntimeEvidence((), ()),
        configured_sources=second.sources,
        coverage=second.issues,
    )
    changes = ssh.compare_ssh_snapshots(before, after)
    assert changes["config"]["changed"] is True
    assert "configured_sources_modified" in changes


def test_include_graph_rejects_escape_and_reports_incomplete_source(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-sshd.conf"
    outside.write_text("PasswordAuthentication yes\n", encoding="utf-8")
    root = tmp_path / "sshd_config"
    root.write_text(f"Include {outside.as_posix()}\n", encoding="utf-8")
    result = ssh.observe_sshd_config_graph(root, privacy_key=MASTER, platform="linux")
    assert result.files_observed == 1
    assert "ssh.config.include_outside_allowed_root" in result.issues
    assert any(item.kind == "include" and item.state == "unsupported" for item in result.sources)


def test_runtime_process_birth_forwarding_and_connections_are_tokenized() -> None:
    result = ssh.normalize_runtime_evidence(
        (),
        (),
        privacy_key=MASTER,
        platform="windows",
        processes=(
            {
                "name": "sshd.exe",
                "executable": r"C:\Windows\System32\OpenSSH\sshd.exe",
                "identity": "pid:101:birth:123.000000",
            },
            {
                "name": "ssh.exe",
                "executable": r"C:\Tools\ssh.exe",
                "identity": "pid:202:birth:456.000000",
                "cmdline": ("ssh.exe", "-R", "private-port:value", "private-host"),
            },
        ),
        connections=(
            {
                "local": "10.0.0.5:50000",
                "remote": "198.51.100.8:22",
                "state": "ESTABLISHED",
                "process_identity": "pid:202:birth:456.000000",
            },
        ),
    )
    assert {item.role for item in result.processes} == {"server", "client"}
    client = next(item for item in result.processes if item.role == "client")
    assert client.forwarding_flags == ("reverse-forward",)
    assert client.nonstandard_binary is True
    assert len(result.connections) == 1
    assert result.connections[0].direction == "outbound"
    serialized = json.dumps({
        "processes": [item.as_dict() for item in result.processes],
        "connections": [item.as_dict() for item in result.connections],
    }, sort_keys=True)
    for forbidden in (
        "private-port", "private-host", "10.0.0.5", "198.51.100.8",
        "pid:202", r"C:\Tools",
    ):
        assert forbidden not in serialized


def test_windows_runtime_collector_includes_non_service_server_and_client(
    monkeypatch,
) -> None:
    class Process:
        def __init__(self, info: dict[str, object]) -> None:
            self.info = info
            self.cmdline_calls = 0

        def cmdline(self):
            self.cmdline_calls += 1
            return self.info["cmdline"]

    processes = (
        Process({
            "pid": 101,
            "name": "sshd.exe",
            "exe": r"C:\Windows\System32\OpenSSH\sshd.exe",
            "create_time": 1000.0,
            "cmdline": ("sshd.exe", "-D"),
        }),
        Process({
            "pid": 202,
            "name": "ssh.exe",
            "exe": r"C:\Windows\System32\OpenSSH\ssh.exe",
            "create_time": 2000.0,
            "cmdline": ("ssh.exe", "-N", "-L", "private-forward-value", "private-target"),
        }),
    )
    connections = (
        types.SimpleNamespace(
            pid=101, status="LISTEN", laddr=("0.0.0.0", 22), raddr=()
        ),
        types.SimpleNamespace(
            pid=202,
            status="ESTABLISHED",
            laddr=("10.0.0.5", 50000),
            raddr=("203.0.113.10", 22),
        ),
    )
    requested_attributes: list[tuple[str, ...]] = []

    def process_iter(attributes):
        requested_attributes.append(tuple(attributes))
        return processes

    fake_psutil = types.SimpleNamespace(
        CONN_LISTEN="LISTEN",
        win_service_iter=lambda: (),
        process_iter=process_iter,
        net_connections=lambda kind: connections if kind == "tcp" else (),
    )
    monkeypatch.setitem(sys.modules, "psutil", fake_psutil)
    result = ssh.collect_local_ssh_runtime(
        privacy_key=MASTER,
        platform="windows",
        environ={"SystemRoot": r"C:\Windows"},
    )
    assert len(result.services) == 1
    assert {item.role for item in result.processes} == {"server", "client"}
    assert len(result.listeners) == 1
    assert len(result.connections) == 2
    client = next(item for item in result.processes if item.role == "client")
    assert client.forwarding_flags == ("local-forward",)
    assert requested_attributes == [("pid", "name", "exe", "create_time")]
    assert processes[0].cmdline_calls == 0
    assert processes[1].cmdline_calls == 1
    assert "ssh.runtime.signature_verification_unavailable" in result.issues
    serialized = json.dumps({
        "services": [item.as_dict() for item in result.services],
        "processes": [item.as_dict() for item in result.processes],
        "connections": [item.as_dict() for item in result.connections],
    })
    for forbidden in (
        "private-forward-value", "private-target", "10.0.0.5", "203.0.113.10",
        "pid:202", r"C:\Windows",
    ):
        assert forbidden not in serialized


def _windows_openssh_xml(
    *,
    channel: str = "OpenSSH/Operational",
    provider: str = "OpenSSH",
    event_id: int = 4,
    record_id: int = 7,
    payload: str = "Accepted password for private-user from 198.51.100.20 port 22",
) -> str:
    return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
      <System><Provider Name='{provider}'/><EventID>{event_id}</EventID>
      <EventRecordID>{record_id}</EventRecordID><Channel>{channel}</Channel></System>
      <EventData><Data Name='process'>sshd</Data><Data Name='payload'>{payload}</Data></EventData>
    </Event>"""


def test_windows_openssh_event_adapter_is_fixed_provider_bounded_and_private() -> None:
    event = ssh.parse_windows_openssh_event(
        _windows_openssh_xml(), expected_channel="OpenSSH/Operational"
    )
    assert event.record_id == 7 and event.event_id == 4
    analysis = ssh.analyze_openssh_logs((event.message,), privacy_key=MASTER)
    assert analysis.evidence[0].kind == "successful_password_auth"
    assert "private-user" not in json.dumps(analysis.evidence[0].as_dict())
    with pytest.raises(ValueError):
        ssh.parse_windows_openssh_event(
            _windows_openssh_xml(provider="ForeignProvider"),
            expected_channel="OpenSSH/Operational",
        )
    with pytest.raises(ValueError):
        ssh.parse_windows_openssh_event(
            _windows_openssh_xml(channel="Security"),
            expected_channel="OpenSSH/Operational",
        )
    with pytest.raises(ValueError):
        ssh.parse_windows_openssh_event(
            _windows_openssh_xml(event_id=99),
            expected_channel="OpenSSH/Operational",
        )


def test_module_polls_fixed_windows_channels_and_exposes_source_completeness(
    tmp_path: Path,
) -> None:
    config = tmp_path / "sshd_config"
    config.write_text("PasswordAuthentication no\n", encoding="utf-8")

    class Source:
        def __init__(self, channel: str) -> None:
            self.channel = channel

        def newest_record_id(self) -> int:
            return 7 if self.channel.endswith("Operational") else 0

        def oldest_record_id(self) -> int:
            return 7 if self.channel.endswith("Operational") else 0

        def read_after(self, cursor: int, limit: int):
            assert limit == ssh.MAX_WINDOWS_EVENT_ROWS
            if self.channel.endswith("Operational") and cursor < 7:
                return [_windows_openssh_xml()]
            return []

        def close(self) -> None:
            return None

    opened: list[str] = []

    def factory(channel: str):
        opened.append(channel)
        return Source(channel)

    module = SSHSurfaceGuardModule(
        data_root=tmp_path / "data",
        master_key=MASTER,
        config_paths=(config,),
        key_candidates=(),
        runtime_collector=lambda **_kwargs: ssh.SSHRuntimeEvidence((), ()),
        windows_event_source_factory=factory,
        platform="windows",
    )
    bus = EventBus()
    module.bind(bus)
    result = module.observe_once()
    assert opened == [item[0] for item in ssh.WINDOWS_OPENSSH_CHANNELS]
    assert result["source_completeness"] == {
        "admin": "available",
        "operational": "available",
        "runtime-connections": "available",
        "runtime-processes": "available",
        "runtime-services": "available",
        "runtime-signatures": "not-required",
        "text": "not-configured",
    }
    serialized = json.dumps(
        [{"message": event.message, "details": event.details} for event in bus.recent(100)],
        sort_keys=True,
    )
    assert "ssh.logs.successful_password_auth" in serialized
    assert "private-user" not in serialized and "198.51.100.20" not in serialized


def test_native_windows_acl_verifier_rejects_untrusted_writer(monkeypatch) -> None:
    class Dacl:
        def __init__(self, sid: str) -> None:
            self.sid = sid

        def GetAceCount(self) -> int:
            return 1

        def GetAce(self, _index: int):
            return ((0, 0), 0x40000000, self.sid)

    class Security:
        def __init__(self, writer: str) -> None:
            self.writer = writer

        def GetSecurityDescriptorOwner(self):
            return "S-1-5-18"

        def GetSecurityDescriptorDacl(self):
            return Dacl(self.writer)

    state = {"writer": "S-1-5-32-544"}
    fake_win32 = types.SimpleNamespace(
        SE_FILE_OBJECT=1,
        OWNER_SECURITY_INFORMATION=1,
        DACL_SECURITY_INFORMATION=4,
        ACCESS_ALLOWED_ACE_TYPE=0,
        ACCESS_ALLOWED_OBJECT_ACE_TYPE=5,
        GetNamedSecurityInfo=lambda *_args: Security(state["writer"]),
        ConvertSidToStringSid=lambda sid: sid,
    )
    fake_nt = types.SimpleNamespace(
        FILE_GENERIC_WRITE=0x00120116,
        FILE_ALL_ACCESS=0x001F01FF,
        DELETE=0x00010000,
        WRITE_DAC=0x00040000,
        WRITE_OWNER=0x00080000,
    )
    monkeypatch.setitem(sys.modules, "win32security", fake_win32)
    monkeypatch.setitem(sys.modules, "ntsecuritycon", fake_nt)
    assert ssh.verify_windows_ssh_acl(Path("C:/ProgramData/ssh/sshd_config")) is True
    state["writer"] = "S-1-5-32-545"
    assert ssh.verify_windows_ssh_acl(Path("C:/ProgramData/ssh/sshd_config")) is False


def test_per_user_sources_use_home_and_bounded_percent_expansion(
    tmp_path: Path, monkeypatch,
) -> None:
    home = tmp_path / "Users" / "Alice"
    key_dir = home / ".ssh"
    key_dir.mkdir(parents=True)
    plain = key_dir / "custom_keys"
    expanded = key_dir / "keys-Alice-1001-%"
    principals = key_dir / "custom_principals"
    plain.write_text(_public_key(marker=b"P") + " private\n", encoding="utf-8")
    expanded.write_text(_public_key(marker=b"E") + " private\n", encoding="utf-8")
    principals.write_text("private-principal\n", encoding="utf-8")
    config_dir = tmp_path / "ProgramData" / "ssh"
    config_dir.mkdir(parents=True)
    config = config_dir / "sshd_config"
    config.write_text(
        "\n".join((
            "AllowUsers Alice",
            "AuthorizedKeysFile .ssh/custom_keys .ssh/keys-%u-%U-%%",
            "AuthorizedPrincipalsFile .ssh/custom_principals",
        )) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        ssh, "verify_windows_ssh_acl", lambda _path, **_kwargs: True
    )
    result = ssh.observe_sshd_config_graph(
        config,
        privacy_key=MASTER,
        platform="windows",
        local_accounts=(ssh.SSHLocalAccount("Alice", home, 1001),),
    )
    candidate_paths = {item.path for item in result.authorized_key_candidates}
    assert {plain, expanded} <= candidate_paths
    assert config_dir / ".ssh" / "custom_keys" not in candidate_paths
    assert sum(
        item.state == "observed" and item.kind == "authorized_keys"
        for item in result.sources
    ) == 2
    assert any(
        item.state == "observed" and item.kind == "principals"
        for item in result.sources
    )
    serialized = json.dumps([item.as_dict() for item in result.sources], sort_keys=True)
    for forbidden in ("Alice", str(home), "private-principal", "private"):
        assert forbidden not in serialized


def test_per_user_sources_fail_closed_for_unprovable_expansion(tmp_path: Path) -> None:
    home = tmp_path / "Users" / "Alice"
    home.mkdir(parents=True)
    config = tmp_path / "sshd_config"
    config.write_text(
        "\n".join((
            "AuthorizedKeysFile .ssh/keys-%U",
            "AuthorizedPrincipalsFile none",
            "Match User Alice",
            "AuthorizedKeysFile .ssh/conditional",
        )) + "\n",
        encoding="utf-8",
    )
    result = ssh.observe_sshd_config_graph(
        config,
        privacy_key=MASTER,
        platform="windows",
        local_accounts=(ssh.SSHLocalAccount("Alice", home),),
    )
    assert any(
        item.kind == "authorized_keys" and item.state == "unresolved"
        for item in result.sources
    )
    assert any(
        item.kind == "principals" and item.state == "not-applicable"
        and item.custody == "not-applicable"
        for item in result.sources
    )
    assert not any(
        item.kind == "authorized_keys" and item.state == "missing"
        for item in result.sources
    )
    assert "ssh.authorized_keys.dynamic_source_unresolved" in result.issues
    assert "ssh.authorized_keys.conditional_application_unresolved" in result.issues


def test_windows_acl_verifier_checks_parent_delete_child_and_user_policy(
    monkeypatch,
) -> None:
    user_sid = "S-1-5-21-1-2-3-1001"
    state = {"unsafe_parent": True, "user_writer": False}

    class Dacl:
        def __init__(self, aces: list[tuple[tuple[int, int], int, str]]) -> None:
            self.aces = aces

        def GetAceCount(self) -> int:
            return len(self.aces)

        def GetAce(self, index: int):
            return self.aces[index]

    class Security:
        def __init__(self, component: str) -> None:
            self.component = component

        def GetSecurityDescriptorOwner(self):
            return "S-1-5-18"

        def GetSecurityDescriptorDacl(self):
            writer = "S-1-5-32-544"
            mask = 0x40000000
            if state["unsafe_parent"] and self.component.casefold().endswith("\\.ssh"):
                writer, mask = "S-1-5-32-545", 0x00000040
            elif state["user_writer"]:
                writer = user_sid
            return Dacl([((0, 0), mask, writer)])

    fake_win32 = types.SimpleNamespace(
        SE_FILE_OBJECT=1,
        OWNER_SECURITY_INFORMATION=1,
        DACL_SECURITY_INFORMATION=4,
        ACCESS_ALLOWED_ACE_TYPE=0,
        ACCESS_ALLOWED_OBJECT_ACE_TYPE=5,
        GetNamedSecurityInfo=lambda path, *_args: Security(str(path)),
        ConvertSidToStringSid=lambda sid: sid,
        LookupAccountName=lambda _system, _name: (user_sid, "LOCAL", 1),
    )
    fake_nt = types.SimpleNamespace(
        FILE_GENERIC_WRITE=0x00120116,
        FILE_ALL_ACCESS=0x001F01FF,
        DELETE=0x00010000,
        WRITE_DAC=0x00040000,
        WRITE_OWNER=0x00080000,
        FILE_DELETE_CHILD=0x00000040,
    )
    monkeypatch.setitem(sys.modules, "win32security", fake_win32)
    monkeypatch.setitem(sys.modules, "ntsecuritycon", fake_nt)
    path = Path("C:/Users/Alice/.ssh/authorized_keys")
    assert ssh.verify_windows_ssh_acl(path, expected_owner="Alice") is False
    state["unsafe_parent"] = False
    state["user_writer"] = True
    assert ssh.verify_windows_ssh_acl(path, expected_owner="Alice") is True
    assert ssh.verify_windows_ssh_acl(path) is False
    delattr(fake_win32, "LookupAccountName")
    assert ssh.verify_windows_ssh_acl(path, expected_owner="Alice") is None


def test_windows_event_open_retry_backoff_and_bounded_recovery(tmp_path: Path) -> None:
    clock = [100.0]
    calls: dict[str, int] = {}

    class Source:
        def __init__(self, channel: str) -> None:
            self.channel = channel

        def newest_record_id(self) -> int:
            return 7 if self.channel.endswith("Operational") else 0

        def oldest_record_id(self) -> int:
            return 7 if self.channel.endswith("Operational") else 0

        def read_after(self, cursor: int, _limit: int):
            if self.channel.endswith("Operational") and cursor < 7:
                return [_windows_openssh_xml()]
            return []

        def close(self) -> None:
            return None

    def factory(channel: str):
        calls[channel] = calls.get(channel, 0) + 1
        if channel.endswith("Operational") and calls[channel] == 1:
            raise OSError("private source failure")
        return Source(channel)

    module = SSHSurfaceGuardModule(
        data_root=tmp_path,
        master_key=MASTER,
        windows_event_source_factory=factory,
        monotonic_clock=lambda: clock[0],
        platform="windows",
    )
    operational = ssh.WINDOWS_OPENSSH_CHANNELS[0][0]
    _lines, first = module._collect_windows_event_lines()
    assert calls[operational] == 1
    assert "ssh.logs.windows_operational_open_failed" in first
    _lines, second = module._collect_windows_event_lines()
    assert calls[operational] == 1
    assert "ssh.logs.windows_operational_retry_backoff" in second
    clock[0] += 301.0
    lines, recovered = module._collect_windows_event_lines()
    assert calls[operational] == 2 and lines
    assert "ssh.logs.windows_operational_recovered_history_bounded" in recovered
    assert module._log_source_states["operational"] == "recovered-tail"
    assert module._windows_event_last_failure == {}


def test_windows_event_reopens_after_bounded_query_failures(tmp_path: Path) -> None:
    clock = [100.0]
    opened = 0
    closed = 0

    class Source:
        def __init__(self, generation: int) -> None:
            self.generation = generation

        def newest_record_id(self) -> int:
            return 1000 if self.generation > 1 else 7

        def oldest_record_id(self) -> int:
            return 1

        def read_after(self, _cursor: int, _limit: int):
            if self.generation == 1:
                raise OSError("private query failure")
            return [_windows_openssh_xml(record_id=1000)]

        def close(self) -> None:
            nonlocal closed
            closed += 1

    def factory(_channel: str):
        nonlocal opened
        opened += 1
        return Source(opened)

    # Limit this lifecycle probe to one fixed channel.
    module = SSHSurfaceGuardModule(
        data_root=tmp_path,
        master_key=MASTER,
        windows_event_source_factory=factory,
        monotonic_clock=lambda: clock[0],
        platform="windows",
    )
    original_channels = ssh.WINDOWS_OPENSSH_CHANNELS
    try:
        # The module imports this tuple at module load; patch its module global.
        import angerona.modules.ssh_surface_guard as guard

        guard.WINDOWS_OPENSSH_CHANNELS = (original_channels[0],)
        for _ in range(3):
            module._collect_windows_event_lines()
        assert opened == 1 and closed == 1
        _lines, backoff = module._collect_windows_event_lines()
        assert opened == 1
        assert "ssh.logs.windows_operational_retry_backoff" in backoff
        clock[0] += 301.0
        lines, recovered = module._collect_windows_event_lines()
        assert opened == 2 and lines
        assert "ssh.logs.windows_operational_recovered_history_bounded" in recovered
    finally:
        guard.WINDOWS_OPENSSH_CHANNELS = original_channels


def test_strict_ssh_option_parser_consumes_arguments_and_labels_completeness() -> None:
    commands = (
        ("ssh.exe", "-o", "RemoteForward=private", "host"),
        ("ssh.exe", "-oLocalForward=private", "host"),
        ("ssh.exe", "-o", "DynamicForward private", "host"),
        ("ssh.exe", "-o", "Tunnel=no", "host"),
        ("ssh.exe", "-oLogLevel=DEBUG", "host"),
        ("ssh.exe", "-i", "-Lnot-an-option", "host"),
        ("ssh.exe", "-F", "private-config", "host"),
        ("ssh.exe", "-L"),
    )
    rows = tuple({
        "name": "ssh.exe",
        "executable": r"C:\Windows\System32\OpenSSH\ssh.exe",
        "identity": f"process-{index}",
        "cmdline": command,
    } for index, command in enumerate(commands))
    runtime = ssh.normalize_runtime_evidence(
        (), (), privacy_key=MASTER, platform="windows", processes=rows
    )
    by_token = {
        row.process_token: row.forwarding_flags for row in runtime.processes
    }
    expected = {
        ssh._purpose_token(
            MASTER,
            b"ssh-process-birth",
            f"process-{index}\x00{ssh._normalized_executable(rows[index]['executable'])}",
            "process",
        ): labels
        for index, labels in enumerate((
            ("reverse-forward",),
            ("local-forward",),
            ("dynamic-forward",),
            (),
            (),
            (),
            ("client-config-uninspected",),
            ("option-parse-incomplete",),
        ))
    }
    assert by_token == expected
    assert "ssh.runtime.client_config_uninspected" in runtime.issues
    assert "ssh.runtime.client_option_parse_incomplete" in runtime.issues
    serialized = json.dumps(
        [item.as_dict() for item in runtime.processes], sort_keys=True
    )
    for forbidden in ("private", "not-an-option", "LogLevel"):
        assert forbidden not in serialized


def test_uninspected_client_config_is_coverage_not_false_forwarding_high(
    tmp_path: Path,
) -> None:
    config = tmp_path / "sshd_config"
    config.write_text("PasswordAuthentication no\n", encoding="utf-8")

    def runtime(**kwargs):
        return ssh.normalize_runtime_evidence(
            (),
            (),
            privacy_key=kwargs["privacy_key"],
            platform="windows",
            processes=({
                "name": "ssh.exe",
                "executable": r"C:\Windows\System32\OpenSSH\ssh.exe",
                "identity": "private-process-identity",
                "cmdline": ("ssh.exe", "-F", "private-config", "private-host"),
            },),
        )

    module = SSHSurfaceGuardModule(
        data_root=tmp_path / "data",
        master_key=MASTER,
        config_paths=(config,),
        key_candidates=(),
        runtime_collector=runtime,
        windows_event_source_factory=lambda _channel: (_ for _ in ()).throw(OSError()),
        platform="windows",
    )
    bus = EventBus()
    module.bind(bus)
    module.observe_once()
    details = [event.details for event in bus.recent(100)]
    codes = {str(item.get("finding_code")) for item in details}
    assert "ssh.runtime.client_config_uninspected" in codes
    assert "ssh.runtime.client_forwarding_process" not in codes
    serialized = json.dumps(details, sort_keys=True)
    for forbidden in ("private-config", "private-host", "private-process-identity"):
        assert forbidden not in serialized
