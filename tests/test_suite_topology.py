from __future__ import annotations

from types import SimpleNamespace

from angerona.core.eventbus import Event, EventBus, Severity
from angerona.core.suite_topology import SuiteTopologyService, MAX_EDGES, MAX_NODES, MAX_PORTS


def module(name="Fixture module", **values):
    class Fixture:
        description = "Inert module for a read-only topology fixture"
        capability_outputs = ("fixture-observation",)
    result = Fixture()
    result.__dict__.update(_status="running", health=100, health_note="fixture", **values)
    return result


def test_topology_uses_only_cached_module_drive_and_accessory_state():
    usb = module(_known_local_mounts={"C:\\", "D:\\", "F:\\"}, _known={"F:\\"})
    peripheral = module(_scan_observation=(123, "sampled", ("Keyboard + storage",), "unknown"))
    manager = SimpleNamespace(modules={"Fixture module": module(), "Removable-Media / USB Monitor": usb,
        "Peripheral and DMA Posture Guard": peripheral})
    service = SuiteTopologyService(manager, EventBus(), clock=lambda: 10.0)
    snapshot = service._build()
    assert {node.label for node in snapshot.nodes if node.kind == "internal_drive"} == {"Local volume C:\\", "Local volume D:\\"}
    assert [node.label for node in snapshot.nodes if node.kind == "external_drive"] == ["External / removable F:\\"]
    assert any(node.kind == "accessory" and "Keyboard" in node.label for node in snapshot.nodes)
    assert any(node.route == "module" and node.target == "Fixture module" for node in snapshot.nodes)
    assert len(snapshot.nodes) <= MAX_NODES
    assert len(snapshot.edges) <= MAX_EDGES
    assert all(not edge.observed for edge in snapshot.edges)


def test_observed_flow_counts_are_separate_from_architecture_and_drop_is_visible():
    service = SuiteTopologyService(SimpleNamespace(modules={"Fixture module": module()}), EventBus(), clock=lambda: 20.0)
    event = Event("Fixture module", "untrusted text never copied", Severity.HIGH,
        details={"remote_ip": "203.0.113.1", "remote_port": 443, "command_line": "private"})
    for _ in range(520):
        service._observe(event)
    snapshot = service._build()
    assert snapshot.events == 512
    assert snapshot.dropped == 8
    assert any(edge.observed and edge.count == 512 and edge.target == "bus" for edge in snapshot.edges)
    assert any(not edge.observed and edge.target == "recorder" for edge in snapshot.edges)
    rendered = repr(snapshot)
    assert "private" not in rendered
    assert "untrusted text" not in rendered
    assert any(node.kind == "port" and node.label == "203.0.113.1:443" for node in snapshot.nodes)


def test_port_and_module_bounds_never_trigger_native_discovery():
    manager = SimpleNamespace(modules={f"Module {index}": module() for index in range(250)})
    service = SuiteTopologyService(manager, EventBus())
    for index in range(100):
        service._observe(Event("Module 1", "", details={"remote_ip": "203.0.113.1", "remote_port": index + 1}))
    snapshot = service._build()
    assert sum(node.kind == "port" for node in snapshot.nodes) == MAX_PORTS
    assert snapshot.omitted > 0
    assert len(snapshot.nodes) <= MAX_NODES and len(snapshot.edges) <= MAX_EDGES


def test_missing_inventory_does_not_become_no_devices_or_trusted_devices():
    service = SuiteTopologyService(SimpleNamespace(modules={}), EventBus())
    snapshot = service._build()
    assert any("Drive inventory unavailable" in value for value in snapshot.coverage)
    assert any("Accessory inventory unavailable" in value for value in snapshot.coverage)
    assert not any(node.kind in {"internal_drive", "external_drive", "accessory"} for node in snapshot.nodes)


def test_existing_cross_platform_mount_query_supplies_cached_metadata_only(monkeypatch):
    from angerona.modules import usb_monitor as usb
    partitions = [SimpleNamespace(mountpoint="/", opts="rw", device="/dev/sda1", fstype="ext4"),
        SimpleNamespace(mountpoint="/media/example", opts="rw", device="/dev/sdb1", fstype="vfat")]
    monkeypatch.setattr(usb, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(usb, "psutil", SimpleNamespace(disk_partitions=lambda **kwargs: partitions))
    policy_mounts = usb._removable_mounts()
    assert set(policy_mounts) == {"/media/example"}
    assert policy_mounts.all_volumes == (("/", "mounted-volume", "ext4"), ("/media/example", "removable", "vfat"))
    owner = module(_known_local_mounts=set(), _known={"/media/example"}, _cached_volume_inventory=policy_mounts.all_volumes)
    service = SuiteTopologyService(SimpleNamespace(modules={"Removable-Media / USB Monitor": owner}), EventBus())
    snapshot = service._build()
    assert any(node.kind == "volume" and node.label == "Mounted volume /" for node in snapshot.nodes)
    assert any(node.kind == "external_drive" and "/media/example" in node.label for node in snapshot.nodes)


def test_actual_socket_raddr_fields_create_endpoint_nodes_without_resolution():
    service = SuiteTopologyService(SimpleNamespace(modules={"Network Monitor": module()}), EventBus())
    service._observe(Event("Network Monitor", "", details={"raddr": "[2001:db8::1]:443"}))
    snapshot = service._build()
    assert any(node.kind == "port" and node.label == "2001:db8::1:443" for node in snapshot.nodes)


def test_running_soar_thread_does_not_display_as_armed_policy(monkeypatch):
    from angerona.modules.soar_engine import ActiveResponseSOAR
    monkeypatch.delenv("ANGERONA_SOAR_KILL_AND_ROLLBACK", raising=False)
    module = ActiveResponseSOAR()
    module.status = "running"
    module.health = 100
    manager = SimpleNamespace(modules={module.name: module}, platform="windows", _kernel_installed=None,
        config=SimpleNamespace(module_states={}, eco_mode=False))
    snapshot = SuiteTopologyService(manager, EventBus())._build()
    node = next(node for node in snapshot.nodes if node.kind == "module")
    assert node.status == "not_configured"
    assert ("Worker lifecycle", "running") in node.info
    assert any(key == "Policy" and "not armed" in value for key, value in node.info)


def test_live_model_owns_and_retires_its_exact_thread():
    bus = EventBus()
    service = SuiteTopologyService(SimpleNamespace(modules={"Fixture module": module()}), bus)
    assert service.start()
    worker, = service.owned_workers()
    assert worker.is_alive()
    bus.publish(Event("Fixture module", "inert"))
    service.request_shutdown()
    worker.join(timeout=3)
    assert not worker.is_alive()
    assert service.custody_released()
    assert service._subscribed is False
