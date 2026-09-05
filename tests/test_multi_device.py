from blackoutkit.multi_device import (
    MultiDeviceManager,
    register_fleet_device,
    get_fleet_devices,
    get_fleet_aggregate_metrics,
    trigger_device_action,
)

def test_multi_device_registration_and_metrics(tmp_path):
    reg_file = tmp_path / "registry.json"
    mgr = MultiDeviceManager(registry_file=reg_file)

    dev1 = mgr.register_device("dev-001", "HQ Gateway", "10.0.0.1", os_type="linux", tags=["office", "gateway"])
    assert dev1["device_id"] == "dev-001"
    assert dev1["status"] == "online"

    # Update metrics
    mgr.update_device_metrics("dev-001", {"bandwidth_bytes": 1048576, "active_conns": 42})

    devices = mgr.list_devices(filter_tag="office")
    assert len(devices) == 1
    assert devices[0]["metrics"]["bandwidth_bytes"] == 1048576

    metrics = mgr.get_aggregate_metrics()
    assert metrics["total_devices"] == 1
    assert metrics["aggregate_bandwidth_bytes"] == 1048576

def test_remote_quick_action(tmp_path):
    mgr = MultiDeviceManager(registry_file=tmp_path / "r.json")
    mgr.register_device("dev-002", "Server 1", "10.0.0.2")

    res = mgr.execute_remote_action("dev-002", "ROTATE_CONFIG", {"config_id": "ru-fast"})
    assert res["status"] == "success"
    assert res["action"] == "ROTATE_CONFIG"

def test_fleet_helpers():
    dev = register_fleet_device("dev-helper", "Helper Device", "127.0.0.1")
    assert dev["device_id"] == "dev-helper"

    devices = get_fleet_devices()
    assert len(devices) >= 1

    metrics = get_fleet_aggregate_metrics()
    assert isinstance(metrics, dict)

    action = trigger_device_action("dev-helper", "RESTART_DAEMON")
    assert action["status"] == "success"
