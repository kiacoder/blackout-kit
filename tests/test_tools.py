import pytest
from unittest.mock import MagicMock, patch

from blackoutkit import tools
from blackoutkit.tools import ping_stats

def test_ping_stats_empty():
    times = []
    result = ping_stats(times)
    assert result == {
        "avg": None,
        "min": None,
        "max": None,
        "jitter": None,
        "loss_pct": 100.0,
    }

def test_ping_stats_all_none():
    times = [None, None, None]
    result = ping_stats(times)
    assert result == {
        "avg": None,
        "min": None,
        "max": None,
        "jitter": None,
        "loss_pct": 100.0,
    }

def test_ping_stats_single_value():
    times = [10.0]
    result = ping_stats(times)
    assert result == {
        "avg": 10.0,
        "min": 10.0,
        "max": 10.0,
        "jitter": None,
        "loss_pct": 0.0,
    }

def test_ping_stats_mixed():
    times = [10.0, None, 20.0]
    result = ping_stats(times)
    assert result["avg"] == 15.0
    assert result["min"] == 10.0
    assert result["max"] == 20.0
    assert result["jitter"] == 10.0
    assert result["loss_pct"] == pytest.approx(33.333333333333336)

def test_ping_stats_all_valid():
    times = [10.0, 20.0, 30.0]
    result = ping_stats(times)
    assert result == {
        "avg": 20.0,
        "min": 10.0,
        "max": 30.0,
        "jitter": 10.0,
        "loss_pct": 0.0,
    }

def test_ping_stats_jitter_calculation():
    # 10.0 -> 5.0 (diff 5.0) -> 15.0 (diff 10.0) -> sum = 15.0, avg = 7.5
    times = [10.0, 5.0, 15.0]
    result = ping_stats(times)
    assert result["jitter"] == 7.5


def make_adapter(index, name, *, virtual=False, ip_addresses=None, dns_servers=None, status="Up"):
    return {
        "InterfaceIndex": index,
        "Name": name,
        "InterfaceAlias": name,
        "InterfaceDescription": "BlackoutKit TUN" if virtual else "Intel Ethernet",
        "DriverDescription": "BlackoutKit TUN" if virtual else "Intel Ethernet",
        "Status": status,
        "HardwareInterface": not virtual,
        "IpAddresses": ip_addresses or [],
        "DnsServers": dns_servers or [],
    }


def test_tun_config_uses_deterministic_blackout_interface_name():
    from blackoutkit.engines.tun import TUNEngine

    assert TUNEngine()._generate_singbox_config()["inbounds"][0]["interface_name"] == "BlackoutKit-TUN"


def test_loopback_dns_selection_excludes_virtual_and_custom_dns():
    snapshot = {
        "adapters": [
            make_adapter(1, "Ethernet", ip_addresses=["192.168.1.20/24"], dns_servers=["127.0.0.1"]),
            make_adapter(2, "Wi-Fi", ip_addresses=["192.168.1.30/24"], dns_servers=["1.1.1.1"]),
            make_adapter(3, "BlackoutKit-TUN", virtual=True, ip_addresses=["172.19.0.1/30"], dns_servers=["127.0.0.1"]),
        ],
        "routes": [],
    }

    assert tools.find_loopback_dns_adapters(snapshot) == [snapshot["adapters"][0]]


def test_stale_virtual_adapter_requires_missing_address_or_post_crash_managed_route():
    no_address = make_adapter(10, "BlackoutKit-TUN", virtual=True)
    healthy_split_tunnel = make_adapter(11, "wg0", virtual=True, ip_addresses=["10.10.0.2/24"])
    managed_route = make_adapter(12, "BlackoutKit-TUN", virtual=True, ip_addresses=["172.19.0.1/30"])
    snapshot = {
        "adapters": [no_address, healthy_split_tunnel, managed_route],
        "routes": [
            {"InterfaceIndex": 11, "DestinationPrefix": "10.0.0.0/8", "NextHop": "0.0.0.0"},
            {"InterfaceIndex": 12, "DestinationPrefix": "0.0.0.0/0", "NextHop": "172.19.0.2"},
        ],
    }

    assert tools.find_stale_virtual_adapters(snapshot, daemon_running=True) == [no_address]
    assert tools.find_stale_virtual_adapters(snapshot, daemon_running=False) == [no_address, managed_route]


def test_third_party_virtual_adapters_are_not_blackout_owned():
    third_party = make_adapter(9, "Other VPN Wintun", virtual=True)

    assert tools._is_virtual_adapter(third_party) is False


def test_default_wireguard_name_does_not_authorize_adapter_changes():
    unrelated_wireguard = make_adapter(9, "wg0", virtual=True, ip_addresses=["10.10.0.2/24"])

    assert tools._is_virtual_adapter(unrelated_wireguard) is False


def test_stale_route_selection_only_uses_stale_virtual_interfaces():
    stale = make_adapter(10, "BlackoutKit-TUN", virtual=True)
    snapshot = {
        "adapters": [stale],
        "routes": [
            {"InterfaceIndex": 10, "DestinationPrefix": "0.0.0.0/0", "NextHop": "172.19.0.2"},
            {"InterfaceIndex": 5, "DestinationPrefix": "0.0.0.0/0", "NextHop": "192.168.1.1"},
            {"InterfaceIndex": 10, "DestinationPrefix": "127.0.0.0/8", "NextHop": "0.0.0.0"},
        ],
    }

    assert tools.find_stale_virtual_routes(snapshot, [stale]) == [snapshot["routes"][0]]


@patch("blackoutkit.proxy_manager.get_proxy_status", return_value={"enabled": True, "server": "proxy.example:8080"})
@patch("blackoutkit.proxy_manager.clear_system_proxy")
def test_external_system_proxy_is_preserved(mock_clear_proxy, mock_status):
    ok, detail = tools.clear_stale_blackout_proxy()

    assert ok is True
    assert detail == "External proxy preserved: proxy.example:8080"
    mock_clear_proxy.assert_not_called()


@patch("blackoutkit.proxy_manager.get_proxy_status", return_value={"enabled": True, "server": "127.0.0.1:10809"})
@patch("blackoutkit.proxy_manager.clear_system_proxy", return_value=True)
def test_stale_blackout_proxy_is_cleared(mock_clear_proxy, mock_status):
    ok, detail = tools.clear_stale_blackout_proxy()

    assert ok is True
    assert detail == "Removed stale Blackout proxy: 127.0.0.1:10809"
    mock_clear_proxy.assert_called_once()


@patch("blackoutkit.tools._run_recovery_script", return_value=True)
@patch("blackoutkit.tools.clear_stale_blackout_proxy", return_value=(True, "Removed stale Blackout proxy: 127.0.0.1:10809"))
@patch("blackoutkit.daemon.get_state", return_value=None)
@patch("blackoutkit.tools.get_network_recovery_snapshot")
def test_recovery_runs_targeted_repairs_without_full_route_flush(
    mock_snapshot, mock_state, mock_clear_proxy, mock_script
):
    stale_virtual = make_adapter(10, "BlackoutKit-TUN", virtual=True)
    physical_dns = make_adapter(1, "Ethernet", ip_addresses=["192.168.1.20/24"], dns_servers=["127.0.0.1"])
    mock_snapshot.return_value = {
        "adapters": [stale_virtual, physical_dns],
        "routes": [{"InterfaceIndex": 10, "DestinationPrefix": "0.0.0.0/0", "NextHop": "172.19.0.2"}],
    }

    results = tools.run_network_recovery()

    assert all(step["ok"] for step in results)
    assert [step["name"] for step in results] == [
        "Clear system proxy", "Preserve Windows network stack", "Remove stale virtual routes",
        "Restore DHCP DNS", "Restart stale virtual adapters", "Flush DNS cache",
    ]
    script = mock_script.call_args.args[0]
    assert "winsock" not in script
    assert "int' 'ip' 'reset" not in script
    assert "ipconfig.exe '/release'" not in script
    scripts = [call.args[0] for call in mock_script.call_args_list]
    assert any("Remove-NetRoute -InterfaceIndex 10" in script for script in scripts)
    assert any("Set-DnsClientServerAddress -InterfaceIndex 1 -ResetServerAddresses" in script for script in scripts)
    assert any("Disable-NetAdapter -Name 'BlackoutKit-TUN'" in script for script in scripts)
    assert not any("route.exe -f" in script for script in scripts)
    mock_clear_proxy.assert_called_once()
    assert len(mock_script.call_args_list) == 1


@patch("blackoutkit.tools._run_recovery_script")
@patch("blackoutkit.tools.clear_stale_blackout_proxy")
@patch("blackoutkit.daemon.get_state", return_value={"engine": "tun"})
@patch("blackoutkit.tools.get_network_recovery_snapshot")
def test_recovery_preserves_live_daemon_proxy_and_adapter(
    mock_snapshot, mock_state, mock_clear_proxy, mock_script
):
    managed_virtual = make_adapter(10, "BlackoutKit-TUN", virtual=True, ip_addresses=["172.19.0.1/30"])
    mock_snapshot.return_value = {
        "adapters": [managed_virtual],
        "routes": [{"InterfaceIndex": 10, "DestinationPrefix": "0.0.0.0/0", "NextHop": "172.19.0.2"}],
    }

    results = tools.run_network_recovery()

    assert results == [{
        "name": "Targeted network recovery",
        "ok": True,
        "detail": "Skipped while Blackout daemon is active; stop it before repairing the network",
    }]
    mock_clear_proxy.assert_not_called()
    mock_script.assert_not_called()


@patch("blackoutkit.tools._run_recovery_script", return_value=True)
@patch("blackoutkit.tools.clear_stale_blackout_proxy", return_value=(True, "No system proxy configured"))
@patch("blackoutkit.daemon.get_state", return_value=None)
@patch("blackoutkit.tools.get_network_recovery_snapshot", return_value={"adapters": [], "routes": []})
def test_full_route_reset_requires_explicit_opt_in(
    mock_snapshot, mock_state, mock_clear_proxy, mock_script
):
    tools.run_network_recovery(full_route_reset=True)

    assert any("route.exe '-f'" in call.args[0] for call in mock_script.call_args_list)


@patch("blackoutkit.tools._run_recovery_script", return_value=True)
@patch("blackoutkit.tools.clear_stale_blackout_proxy", return_value=(True, "No system proxy configured"))
@patch("blackoutkit.daemon.get_state", return_value=None)
@patch("blackoutkit.tools.get_network_recovery_snapshot", return_value={"adapters": [], "routes": []})
def test_full_stack_reset_requires_explicit_opt_in(
    mock_snapshot, mock_state, mock_clear_proxy, mock_script
):
    tools.run_network_recovery(full_stack_reset=True)

    script = mock_script.call_args.args[0]
    assert "winsock" in script
    assert "int' 'ip' 'reset" in script
    assert "ipconfig.exe '/release'" in script


@patch("blackoutkit.tools._run_recovery_script", return_value=True)
@patch("blackoutkit.tools.clear_stale_blackout_proxy")
@patch("blackoutkit.daemon.get_state", return_value={"engine": "xray", "pid": 4242})
@patch("blackoutkit.tools.get_network_recovery_snapshot", return_value={"adapters": [], "routes": []})
def test_daemon_recovery_preserves_proxy_and_never_resets_full_routes(
    mock_snapshot, mock_state, mock_clear_proxy, mock_script
):
    results = tools.run_network_recovery(full_route_reset=True, from_daemon=True)

    script = mock_script.call_args.args[0]
    assert "route.exe '-f'" not in script
    assert "winsock" not in script
    assert "int' 'ip' 'reset" not in script
    assert "ipconfig.exe '/release'" not in script
    assert mock_clear_proxy.call_count == 0
    assert {step["name"] for step in results} >= {
        "Preserve system proxy",
        "Preserve Windows network stack",
        "Full route-table reset",
    }


@patch("blackoutkit.tools._run_recovery_script", return_value=False)
@patch("blackoutkit.tools.clear_stale_blackout_proxy", return_value=(False, "Could not clear stale Blackout proxy"))
@patch("blackoutkit.daemon.get_state", return_value=None)
@patch("blackoutkit.tools.get_network_recovery_snapshot", return_value={"adapters": [], "routes": []})
def test_recovery_reports_uac_or_command_failure(
    mock_snapshot, mock_state, mock_clear_proxy, mock_script
):
    results = tools.run_network_recovery()

    assert results[0]["ok"] is False
    assert results[-1]["ok"] is False
    assert results[-1]["detail"] == "Command batch failed or UAC denied"
