from types import SimpleNamespace
from unittest.mock import MagicMock

from blackoutkit import linux_network


def test_parse_literal_endpoints_rejects_hosts_and_private_addresses():
    assert linux_network.parse_literal_endpoints([
        "example.com:443",
        "10.0.0.1:443",
        "8.8.8.8:not-a-port",
        "8.8.8.8:443",
        "[2606:4700:4700::1111]:853",
    ]) == [
        ("8.8.8.8", 443),
        ("2606:4700:4700::1111", 853),
    ]


def test_nft_rules_only_reference_owned_table_and_interface():
    rules = linux_network._nft_rules(
        "eth0",
        linux_network._normalize_endpoints([("8.8.8.8", 443)]),
    )

    assert "table inet blackoutkit" in rules
    assert 'oifname "BlackoutKit-TUN" accept' in rules
    assert "flush ruleset" not in rules
    assert "delete table inet" not in rules
    assert "8.8.8.8 tcp dport 443 accept" in rules


def test_remove_owned_firewall_only_uses_blackout_names(monkeypatch):
    commands = []
    monkeypatch.setattr(linux_network, "is_linux", lambda: True)
    monkeypatch.setattr(linux_network, "is_root", lambda: True)
    monkeypatch.setattr(linux_network, "_command_available", lambda _name: True)
    monkeypatch.setattr(linux_network, "_nft_table_exists", lambda: True)
    def record(command, **_kwargs):
        commands.append(command)
        return "-D" not in command

    monkeypatch.setattr(linux_network, "_run_ok", record)

    ok, _ = linux_network.remove_owned_firewall()

    assert ok is True
    assert ["nft", "delete", "table", "inet", "blackoutkit"] in commands
    assert all("flush" not in command for command in commands)
    assert all(
        "BLACKOUTKIT" in " ".join(command) or command[0] == "nft"
        for command in commands
    )


def test_linux_recovery_does_not_flush_neighbor_cache(monkeypatch):
    monkeypatch.setattr(linux_network, "is_linux", lambda: True)
    monkeypatch.setattr(linux_network, "is_root", lambda: True)
    monkeypatch.setattr(linux_network, "remove_owned_firewall", lambda: (True, "removed"))
    monkeypatch.setattr(linux_network, "delete_owned_tunnel", lambda: (True, "removed"))
    monkeypatch.setattr(linux_network, "flush_dns_cache", lambda: (True, "flushed"))
    neighbor_flush = MagicMock()
    monkeypatch.setattr(linux_network, "flush_neighbor_cache", neighbor_flush)

    results = linux_network.run_network_recovery()

    assert all(result["ok"] for result in results)
    neighbor_flush.assert_not_called()


def test_linux_neighbor_flush_requires_root(monkeypatch):
    monkeypatch.setattr(linux_network, "is_linux", lambda: True)
    monkeypatch.setattr(linux_network, "is_root", lambda: False)

    assert linux_network.flush_neighbor_cache() == (False, "Run this command with sudo")


def test_linux_kill_switch_refuses_empty_endpoint_allowlist(monkeypatch):
    monkeypatch.setattr(linux_network, "is_linux", lambda: True)
    monkeypatch.setattr(linux_network, "is_root", lambda: True)
    monkeypatch.setattr(linux_network, "_command_available", lambda _name: True)
    monkeypatch.setattr(linux_network, "default_interface", lambda: "eth0")

    ok, detail = linux_network.enable_kill_switch([])

    assert ok is False
    assert "No validated proxy endpoint" in detail


def test_resolve_proxy_endpoints_filters_non_global_results(monkeypatch):
    monkeypatch.setattr(
        linux_network.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (linux_network.socket.AF_INET, 0, 0, "", ("192.168.1.1", 443)),
            (linux_network.socket.AF_INET, 0, 0, "", ("1.1.1.1", 443)),
        ],
    )

    assert linux_network.resolve_proxy_endpoints([("proxy.example", 443)]) == [("1.1.1.1", 443)]
