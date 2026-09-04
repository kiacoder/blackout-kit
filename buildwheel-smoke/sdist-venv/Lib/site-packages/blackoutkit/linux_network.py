"""Linux TUN, firewall, and recovery helpers owned by Blackout Kit."""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

TUN_INTERFACE = "BlackoutKit-TUN"
NFT_FAMILY = "inet"
NFT_TABLE = "blackoutkit"
IPTABLES_CHAIN = "BLACKOUTKIT_OUTPUT"
_IP6TABLES_CHAIN = "BLACKOUTKIT6_OUTPUT"
ROUTE_TABLE = 20220
ROUTE_RULE_PRIORITY = 32200
_SAFE_INTERFACE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def is_root() -> bool:
    return is_linux() and hasattr(os, "geteuid") and os.geteuid() == 0


def _result(name: str, ok: bool, detail: str) -> dict:
    return {"name": name, "ok": ok, "detail": detail}


def _command_available(name: str) -> bool:
    return shutil.which(name) is not None


def _run(command: list[str], *, timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def _run_ok(command: list[str], *, timeout: int = 15) -> bool:
    try:
        return _run(command, timeout=timeout).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _require_root() -> tuple[bool, str]:
    if not is_linux():
        return False, "Linux-only"
    if not is_root():
        return False, "Run this command with sudo"
    return True, ""


def _interface_name_is_safe(interface: str) -> bool:
    return bool(_SAFE_INTERFACE.fullmatch(interface))


def default_interface() -> str | None:
    if not is_linux() or not _command_available("ip"):
        return None
    try:
        result = _run(["ip", "-j", "route", "show", "default"])
        if result.returncode != 0:
            return None
        routes = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None
    for route in routes:
        interface = route.get("dev")
        if isinstance(interface, str) and _interface_name_is_safe(interface):
            return interface
    return None


def tunnel_exists() -> bool:
    return is_linux() and _run_ok(["ip", "link", "show", "dev", TUN_INTERFACE])


def _remove_owned_routing_rules() -> bool:
    if not _command_available("ip"):
        return False
    _run_ok(["ip", "rule", "del", "priority", str(ROUTE_RULE_PRIORITY)])
    _run_ok(["ip", "route", "flush", "table", str(ROUTE_TABLE)])
    return True


def delete_owned_tunnel() -> tuple[bool, str]:
    allowed, detail = _require_root()
    if not allowed:
        return False, detail
    if not _command_available("ip"):
        return False, "Missing required command: ip"
    routes_ok = _remove_owned_routing_rules()
    if not tunnel_exists():
        return routes_ok, "No stale BlackoutKit-TUN interface found"
    if _run_ok(["ip", "link", "delete", "dev", TUN_INTERFACE]) and routes_ok:
        return True, "Removed stale BlackoutKit-TUN interface"
    return False, "Could not remove BlackoutKit-TUN interface"


def _nft_table_exists() -> bool:
    return _command_available("nft") and _run_ok(["nft", "list", "table", NFT_FAMILY, NFT_TABLE])


def _delete_nft_table() -> bool:
    if not _nft_table_exists():
        return True
    return _run_ok(["nft", "delete", "table", NFT_FAMILY, NFT_TABLE])


def _iptables_available() -> bool:
    return _command_available("iptables") and _command_available("ip6tables")


def _remove_iptables_chain(binary: str, chain: str) -> bool:
    if not _command_available(binary):
        return True
    while _run_ok([binary, "-D", "OUTPUT", "-j", chain]):
        pass
    flush_ok = _run_ok([binary, "-F", chain])
    delete_ok = _run_ok([binary, "-X", chain])
    if not flush_ok and not delete_ok:
        return True
    return delete_ok


def remove_owned_firewall() -> tuple[bool, str]:
    allowed, detail = _require_root()
    if not allowed:
        return False, detail

    nft_ok = _delete_nft_table()
    ipv4_ok = _remove_iptables_chain("iptables", IPTABLES_CHAIN)
    ipv6_ok = _remove_iptables_chain("ip6tables", _IP6TABLES_CHAIN)
    if nft_ok and ipv4_ok and ipv6_ok:
        return True, "Removed Blackout Kit firewall rules"
    return False, "Could not remove all Blackout Kit firewall rules"


def _normalize_endpoints(endpoints: list[tuple[str, int]]) -> list[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]]:
    normalized = []
    for raw_ip, raw_port in endpoints:
        try:
            address = ipaddress.ip_address(raw_ip)
            port = int(raw_port)
        except (ValueError, TypeError):
            continue
        if not address.is_global or not 1 <= port <= 65535:
            continue
        normalized.append((address, port))
    return list(dict.fromkeys(normalized))


def resolve_proxy_endpoints(hosts: list[tuple[str, int]]) -> list[tuple[str, int]]:
    endpoints: list[tuple[str, int]] = []
    for host, raw_port in hosts:
        try:
            port = int(raw_port)
        except (ValueError, TypeError):
            continue
        if not 1 <= port <= 65535:
            continue
        try:
            address = ipaddress.ip_address(host)
            endpoints.append((str(address), port))
            continue
        except ValueError:
            pass
        try:
            records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError:
            continue
        for family, _, _, _, sockaddr in records:
            if family in (socket.AF_INET, socket.AF_INET6):
                endpoints.append((sockaddr[0], port))
    return [(str(address), port) for address, port in _normalize_endpoints(endpoints)]


def parse_literal_endpoints(values: list[str]) -> list[tuple[str, int]]:
    endpoints: list[tuple[str, int]] = []
    for value in values:
        raw = str(value).strip()
        if raw.startswith("["):
            host, separator, port_text = raw[1:].partition("]:")
            if not separator:
                continue
        else:
            host, separator, port_text = raw.rpartition(":")
            if not separator or ":" in host:
                continue
        endpoints.append((host, port_text))
    return [(str(address), port) for address, port in _normalize_endpoints(endpoints)]


def _nft_rules(interface: str, endpoints: list[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]]) -> str:
    endpoint_rules = []
    for address, port in endpoints:
        family = "ip6" if address.version == 6 else "ip"
        endpoint_rules.append(f"{family} daddr {address.compressed} tcp dport {port} accept")
        endpoint_rules.append(f"{family} daddr {address.compressed} udp dport {port} accept")
    return "\n".join([
        f"table {NFT_FAMILY} {NFT_TABLE} {{",
        "  chain output {",
        "    type filter hook output priority filter; policy accept;",
        "    ct state established,related accept",
        '    oifname "lo" accept',
        f'    oifname "{TUN_INTERFACE}" accept',
        "    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } accept",
        "    ip6 daddr { fc00::/7, fe80::/10 } accept",
        "    udp sport 68 udp dport 67 accept",
        "    udp sport 67 udp dport 68 accept",
        *(f"    {rule}" for rule in endpoint_rules),
        "    counter drop",
        "  }",
        "}",
    ])


def _apply_nft_firewall(interface: str, endpoints: list[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]]) -> tuple[bool, str]:
    if not _command_available("nft"):
        return False, "nft is unavailable"
    if not _delete_nft_table():
        return False, "Could not clear the previous Blackout Kit nftables table"

    rules = _nft_rules(interface, endpoints)
    file_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write(rules)
            file_path = Path(handle.name)
        if not _run_ok(["nft", "-c", "-f", str(file_path)]):
            return False, "nftables rejected the generated kill-switch rules"
        if not _run_ok(["nft", "-f", str(file_path)]):
            return False, "Could not apply nftables kill-switch rules"
    finally:
        if file_path is not None:
            file_path.unlink(missing_ok=True)

    if _nft_table_exists():
        return True, "nftables kill switch enabled"
    return False, "nftables table was not created"


def _append_iptables_rules(binary: str, chain: str, interface: str, endpoints: list[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]], version: int) -> bool:
    if not _run_ok([binary, "-N", chain]):
        if not _run_ok([binary, "-F", chain]):
            return False
    if not _run_ok([binary, "-C", "OUTPUT", "-j", chain]):
        if not _run_ok([binary, "-I", "OUTPUT", "1", "-j", chain]):
            return False

    rules = [
        ["-A", chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ["-A", chain, "-o", "lo", "-j", "ACCEPT"],
        ["-A", chain, "-o", TUN_INTERFACE, "-j", "ACCEPT"],
    ]
    if version == 4:
        for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"):
            rules.append(["-A", chain, "-d", network, "-j", "ACCEPT"])
        rules.extend([
            ["-A", chain, "-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT"],
            ["-A", chain, "-p", "udp", "--sport", "67", "--dport", "68", "-j", "ACCEPT"],
        ])
    else:
        for network in ("fc00::/7", "fe80::/10"):
            rules.append(["-A", chain, "-d", network, "-j", "ACCEPT"])

    for address, port in endpoints:
        if address.version != version:
            continue
        for protocol in ("tcp", "udp"):
            rules.append(["-A", chain, "-d", address.compressed, "-p", protocol, "--dport", str(port), "-j", "ACCEPT"])
    rules.append(["-A", chain, "-j", "DROP"])

    return all(_run_ok([binary, *rule]) for rule in rules)


def _apply_iptables_firewall(interface: str, endpoints: list[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]]) -> tuple[bool, str]:
    if not _iptables_available():
        return False, "Neither nft nor both iptables and ip6tables are available"
    ipv4_ok = _append_iptables_rules("iptables", IPTABLES_CHAIN, interface, endpoints, 4)
    ipv6_ok = _append_iptables_rules("ip6tables", _IP6TABLES_CHAIN, interface, endpoints, 6)
    if ipv4_ok and ipv6_ok:
        return True, "iptables/ip6tables kill switch enabled"
    remove_owned_firewall()
    return False, "Could not apply the complete iptables/ip6tables kill switch"


def enable_kill_switch(endpoints: list[tuple[str, int]]) -> tuple[bool, str]:
    allowed, detail = _require_root()
    if not allowed:
        return False, detail
    if not _command_available("ip"):
        return False, "Missing required command: ip"
    interface = default_interface()
    if not interface:
        return False, "Could not determine the active network interface"
    normalized = _normalize_endpoints(endpoints)
    if not normalized:
        return False, "No validated proxy endpoint IP and port are available"
    if _command_available("nft"):
        return _apply_nft_firewall(interface, normalized)
    return _apply_iptables_firewall(interface, normalized)


def kill_switch_is_active() -> bool:
    if not is_linux() or not is_root():
        return False
    if _nft_table_exists():
        return True
    return (
        _run_ok(["iptables", "-C", "OUTPUT", "-j", IPTABLES_CHAIN])
        and _run_ok(["ip6tables", "-C", "OUTPUT", "-j", _IP6TABLES_CHAIN])
    )


def flush_neighbor_cache() -> tuple[bool, str]:
    allowed, detail = _require_root()
    if not allowed:
        return False, detail
    if not _command_available("ip"):
        return False, "Missing required command: ip"
    if _run_ok(["ip", "-4", "neigh", "flush", "all"]):
        return True, "Flushed IPv4 ARP/neighbor cache"
    return False, "Could not flush the IPv4 ARP/neighbor cache"


def flush_dns_cache() -> tuple[bool, str]:
    if not is_linux():
        return False, "Linux-only"
    for command in (
        ["resolvectl", "flush-caches"],
        ["systemd-resolve", "--flush-caches"],
        ["nscd", "-i", "hosts"],
    ):
        if _command_available(command[0]) and _run_ok(command):
            return True, "Flushed local DNS cache"
    return True, "No supported local DNS cache service was active"


def plan_network_recovery(*, flush_arp: bool = False, from_daemon: bool = False) -> list[dict]:
    """Describe recovery of Blackout-owned Linux state without mutating it."""
    if not is_linux():
        return [_result("Linux recovery", False, "Linux-only")]
    prefix = "Daemon targeted recovery" if from_daemon else "Targeted Linux recovery"
    if not is_root():
        return [_result(prefix, False, "Run with sudo to repair Blackout-owned network state")]
    firewall_detail = "Would remove inet blackoutkit and BLACKOUTKIT_* firewall objects" if (_nft_table_exists() or _command_available("iptables")) else "No Blackout-owned firewall objects detected"
    tunnel_detail = "Would remove BlackoutKit-TUN and route table 20220/rule 32200" if tunnel_exists() else "No stale BlackoutKit-TUN interface found"
    plan = [
        _result(f"{prefix}: remove firewall", True, firewall_detail),
        _result(f"{prefix}: remove TUN", True, tunnel_detail),
        _result("Flush DNS cache", True, "Would flush a supported local DNS cache"),
    ]
    if flush_arp:
        plan.append(_result("Flush ARP cache", True, "Would explicitly flush the IPv4 ARP/neighbor cache"))
    return plan


def run_network_recovery(*, from_daemon: bool = False) -> list[dict]:
    if not is_linux():
        return [_result("Linux recovery", False, "Linux-only")]
    if not is_root():
        return [_result("Linux recovery", False, "Run `sudo blackout fix` to repair Blackout-owned network state")]

    firewall_ok, firewall_detail = remove_owned_firewall()
    tunnel_ok, tunnel_detail = delete_owned_tunnel()
    dns_ok, dns_detail = flush_dns_cache()
    prefix = "Daemon targeted recovery" if from_daemon else "Targeted Linux recovery"
    return [
        _result(f"{prefix}: remove firewall", firewall_ok, firewall_detail),
        _result(f"{prefix}: remove TUN", tunnel_ok, tunnel_detail),
        _result("Flush DNS cache", dns_ok, dns_detail),
    ]
