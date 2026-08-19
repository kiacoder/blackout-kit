"""
Blackout Kit - Network toolkit & diagnostics.
DNS flush, speed test, MTU optimizer, adapter info, ping, traceroute, and auto-fix.
"""
import base64
import concurrent.futures
import ctypes
import ipaddress
import json
import logging
import os
import socket
import subprocess
import sys
import time
import urllib.request

_log = logging.getLogger(__name__)

from rich.table import Table
from rich import box

from .theme import console, make_table
from .proxy_manager import is_admin as _is_admin
from . import elevate
from . import APP_DATA_DIR

SPEEDTEST_HISTORY_FILE = APP_DATA_DIR / "speedtest_history.json"
_SPEEDTEST_HISTORY_MAX = 200


def _run_elevated(cmd: list[str], timeout_ms: int = 30000) -> bool:
    """
    Run a single command with admin rights via a UAC prompt.
    Launches powershell.exe elevated, which runs the command with -Wait.
    """
    ps_script = (
        f"$p = Start-Process -FilePath '{cmd[0]}' "
        f"-ArgumentList '{subprocess.list2cmdline(cmd[1:])}' "
        f"-NoNewWindow -Wait -PassThru; exit $p.ExitCode"
    )
    handle, pid = elevate.launch_elevated(
        "powershell.exe",
        ["-NoProfile", "-Command", ps_script],
    )
    if handle is None:
        return False
    ctypes.windll.kernel32.WaitForSingleObject(handle, timeout_ms)
    exit_code = ctypes.c_ulong()
    if ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
        ctypes.windll.kernel32.CloseHandle(handle)
        return exit_code.value == 0
    ctypes.windll.kernel32.CloseHandle(handle)
    return True


def _run_elevated_multi(commands: list[list[str]], timeout_ms: int = 60000) -> bool:
    """Run multiple admin commands in one elevated PowerShell session."""
    blocks = []
    for cmd in commands:
        blocks.append(
            f"$p = Start-Process -FilePath '{cmd[0]}' "
            f"-ArgumentList '{subprocess.list2cmdline(cmd[1:])}' "
            f"-NoNewWindow -Wait -PassThru; if ($p.ExitCode -ne 0) {{ exit $p.ExitCode }}"
        )
    ps_script = "& { " + "; ".join(blocks) + " }"
    handle, _ = elevate.launch_elevated(
        "powershell.exe",
        ["-NoProfile", "-Command", ps_script],
    )
    if handle is None:
        return False
    try:
        wait_result = ctypes.windll.kernel32.WaitForSingleObject(handle, timeout_ms)
        if wait_result == 0x00000102:
            return False
        exit_code = ctypes.c_ulong()
        return bool(
            ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
            and exit_code.value == 0
        )
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def _run_powershell_json(script: str) -> list[dict]:
    """Run a read-only PowerShell query and normalize its JSON array output."""
    if sys.platform != "win32":
        return []
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=15,
            encoding="utf-8",
            errors="ignore",
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []
        data = json.loads(result.stdout)
        if isinstance(data, dict):
            return [data]
        return [item for item in data if isinstance(item, dict)]
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return []


def _powershell_encoded(script: str) -> list[str]:
    """Wrap a script in an encoded PowerShell command to keep adapter names opaque."""
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return ["powershell.exe", "-NoProfile", "-EncodedCommand", encoded]


_PHYSICAL_ADAPTER_MARKERS = ("ethernet", "wi-fi", "wifi", "wlan")
_LOOPBACK_DNS_ADDRESSES = {"127.0.0.1", "::1"}


def _is_loopback_dns_server(server: str) -> bool:
    try:
        return ipaddress.ip_address(server).is_loopback
    except ValueError:
        return server in _LOOPBACK_DNS_ADDRESSES


def _is_virtual_adapter(adapter: dict) -> bool:
    """Return whether an adapter has a deterministic Blackout Kit identity."""
    name = str(adapter.get("Name", "")).lower()
    alias = str(adapter.get("InterfaceAlias", "")).lower()
    return name == "blackoutkit-tun" or alias == "blackoutkit-tun"


def _is_connected_physical_adapter(adapter: dict) -> bool:
    if _is_virtual_adapter(adapter):
        return False
    status = str(adapter.get("Status", "")).lower()
    if status != "up":
        return False
    identity = " ".join(
        str(adapter.get(field, ""))
        for field in ("Name", "InterfaceDescription", "DriverDescription", "InterfaceAlias")
    ).lower()
    return "loopback" not in identity and (
        any(marker in identity for marker in _PHYSICAL_ADAPTER_MARKERS)
        or bool(adapter.get("HardwareInterface"))
    )


def get_network_recovery_snapshot() -> dict:
    """Return normalized adapter, DNS, and route state for safe recovery decisions."""
    adapter_script = r"""
Get-NetAdapter -IncludeHidden | ForEach-Object {
    [PSCustomObject]@{
        Name=$_.Name; InterfaceAlias=$_.InterfaceAlias; InterfaceIndex=$_.ifIndex;
        Status=$_.Status.ToString(); HardwareInterface=$_.HardwareInterface;
        InterfaceDescription=$_.InterfaceDescription; DriverDescription=$_.DriverDescription
    }
} | ConvertTo-Json -Compress
"""
    address_script = r"""
Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{ InterfaceIndex=$_.InterfaceIndex; Address=$_.IPAddress; PrefixLength=$_.PrefixLength }
} | ConvertTo-Json -Compress
"""
    dns_script = r"""
Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object {
    [PSCustomObject]@{ InterfaceIndex=$_.InterfaceIndex; ServerAddresses=@($_.ServerAddresses) }
} | ConvertTo-Json -Compress
"""
    route_script = r"""
Get-NetRoute -AddressFamily IPv4 | ForEach-Object {
    [PSCustomObject]@{
        InterfaceIndex=$_.InterfaceIndex; DestinationPrefix=$_.DestinationPrefix;
        NextHop=$_.NextHop; RouteMetric=$_.RouteMetric; State=$_.State.ToString()
    }
} | ConvertTo-Json -Compress
"""
    adapters = _run_powershell_json(adapter_script)
    addresses_by_index: dict[object, list[str]] = {}
    for item in _run_powershell_json(address_script):
        address = item.get("Address")
        prefix = item.get("PrefixLength")
        if address is not None and prefix is not None:
            addresses_by_index.setdefault(item.get("InterfaceIndex"), []).append(f"{address}/{prefix}")
    dns_by_index = {
        item.get("InterfaceIndex"): [str(value) for value in item.get("ServerAddresses") or []]
        for item in _run_powershell_json(dns_script)
    }
    routes = _run_powershell_json(route_script)
    for adapter in adapters:
        index = adapter.get("InterfaceIndex")
        adapter["IpAddresses"] = addresses_by_index.get(index, [])
        adapter["DnsServers"] = dns_by_index.get(index, [])
    return {"adapters": adapters, "routes": routes}


def _has_usable_address(adapter: dict) -> bool:
    for address in adapter.get("IpAddresses", []):
        try:
            ip = ipaddress.ip_interface(address).ip
            if not ip.is_loopback and not ip.is_unspecified and not ip.is_link_local:
                return True
        except ValueError:
            continue
    return False


def find_stale_virtual_adapters(snapshot: dict, daemon_running: bool = False) -> list[dict]:
    """Return virtual adapters that remain unhealthy after the daemon has stopped."""
    routes_by_index: dict[object, list[dict]] = {}
    for route in snapshot.get("routes", []):
        routes_by_index.setdefault(route.get("InterfaceIndex"), []).append(route)

    stale = []
    for adapter in snapshot.get("adapters", []):
        if not _is_virtual_adapter(adapter) or str(adapter.get("Status", "")).lower() != "up":
            continue
        routes = routes_by_index.get(adapter.get("InterfaceIndex"), [])
        has_managed_route = any(
            route.get("DestinationPrefix") in ("0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1")
            for route in routes
        )
        if not _has_usable_address(adapter) or (not daemon_running and has_managed_route):
            stale.append(adapter)
    return stale


def find_loopback_dns_adapters(snapshot: dict) -> list[dict]:
    """Return connected physical adapters that are still configured with loopback DNS."""
    return [
        adapter
        for adapter in snapshot.get("adapters", [])
        if _is_connected_physical_adapter(adapter)
        and any(_is_loopback_dns_server(server) for server in adapter.get("DnsServers", []))
    ]


def find_stale_virtual_routes(snapshot: dict, stale_adapters: list[dict]) -> list[dict]:
    """Return routes owned by stale virtual adapters; never select physical routes."""
    stale_indexes = {adapter.get("InterfaceIndex") for adapter in stale_adapters}
    return [
        route for route in snapshot.get("routes", [])
        if route.get("InterfaceIndex") in stale_indexes
        and route.get("DestinationPrefix") not in ("127.0.0.0/8", "224.0.0.0/4")
    ]


def _is_blackout_proxy_server(server: str) -> bool:
    """Return whether a system proxy address belongs to a Blackout local listener."""
    normalized = server.strip().lower()
    if normalized.startswith("socks="):
        normalized = normalized.split("=", 1)[1]
    try:
        host, port_text = normalized.rsplit(":", 1)
        port = int(port_text)
    except ValueError:
        return False
    host = host.strip("[]")
    if host not in {"127.0.0.1", "localhost", "::1"}:
        return False

    from . import settings as cfg

    settings = cfg.load()
    blackout_ports = {
        settings.get("xray_socks_port", 10808),
        settings.get("xray_http_port", 10809),
        settings.get("psiphon_socks_port", 1081),
        settings.get("gas_proxy_port", 8087),
        8085,
        9050,
        1080,
    }
    return port in blackout_ports


def clear_stale_blackout_proxy() -> tuple[bool, str]:
    """Clear only an offline system proxy targeting a Blackout local port."""
    from .proxy_manager import clear_system_proxy, get_proxy_status

    status = get_proxy_status()
    if not status.get("enabled"):
        return True, "No system proxy configured"
    server = str(status.get("server", ""))
    if not _is_blackout_proxy_server(server):
        return True, "External proxy preserved"
    return clear_system_proxy(), "Removed stale Blackout proxy"


def _script_result(name: str, ok: bool, detail: str) -> dict:
    return {"name": name, "ok": ok, "detail": detail}


def plan_network_recovery(
    full_route_reset: bool = False,
    full_stack_reset: bool = False,
    flush_arp: bool = False,
    *,
    from_daemon: bool = False,
) -> list[dict]:
    """Describe owned recovery actions without changing system state."""
    if sys.platform.startswith("linux"):
        from . import daemon, linux_network

        if daemon.get_state() is not None and not from_daemon:
            return [_script_result("Targeted Linux recovery", True, "Would skip while Blackout daemon is active")]
        return linux_network.plan_network_recovery(flush_arp=flush_arp and not from_daemon, from_daemon=from_daemon)
    if sys.platform != "win32":
        return [_script_result("Network recovery", False, "Unsupported platform")]

    from . import daemon

    if daemon.get_state() is not None and not from_daemon:
        return [_script_result("Targeted network recovery", True, "Would skip while Blackout daemon is active")]
    snapshot = get_network_recovery_snapshot()
    stale_adapters = find_stale_virtual_adapters(snapshot, daemon_running=not from_daemon)
    loopback_dns_adapters = find_loopback_dns_adapters(snapshot)
    stale_routes = find_stale_virtual_routes(snapshot, stale_adapters)
    plan = []
    if from_daemon:
        plan.append(_script_result("Preserve system proxy", True, "Daemon recovery keeps the current proxy setting"))
    else:
        from .proxy_manager import get_proxy_status

        proxy = get_proxy_status()
        if proxy.get("enabled") and _is_blackout_proxy_server(str(proxy.get("server", ""))):
            plan.append(_script_result("Clear system proxy", True, "Would remove stale Blackout local proxy"))
        elif proxy.get("enabled"):
            plan.append(_script_result("Preserve external proxy", True, "External proxy is not Blackout-managed"))
        else:
            plan.append(_script_result("Clear system proxy", True, "No system proxy configured"))
    plan.append(_script_result("Remove stale virtual routes", True, f"Would remove {len(stale_routes)} Blackout-owned route(s)" if stale_routes else "No stale Blackout routes found"))
    plan.append(_script_result("Restore DHCP DNS", True, f"Would restore DHCP DNS on {len(loopback_dns_adapters)} physical adapter(s)" if loopback_dns_adapters else "No loopback DNS on physical adapters"))
    plan.append(_script_result("Restart stale virtual adapters", True, f"Would restart {len(stale_adapters)} BlackoutKit-TUN adapter(s)" if stale_adapters else "No unhealthy BlackoutKit-TUN adapter found"))
    plan.append(_script_result("Flush DNS cache", True, "Would clear the local resolver cache"))
    if full_route_reset and not from_daemon:
        plan.append(_script_result("Full route-table reset", True, "Would run explicit emergency route reset"))
    elif from_daemon:
        plan.append(_script_result("Full route-table reset", True, "Daemon recovery never flushes all routes"))
    if full_stack_reset and not from_daemon:
        plan.append(_script_result("Full Windows network-stack reset", True, "Would run explicit Winsock, TCP/IP, autotuning, and DHCP resets"))
    else:
        plan.append(_script_result("Preserve Windows network stack", True, "Targeted recovery skips Winsock, TCP/IP, and DHCP resets"))
    if flush_arp and not from_daemon:
        plan.append(_script_result("Flush ARP cache", True, "Would explicitly flush the local ARP cache"))
    return plan


def _run_recovery_script(script: str, timeout_ms: int = 60000) -> bool:
    command = _powershell_encoded(script)
    if _is_admin():
        try:
            return subprocess.run(command, capture_output=True, timeout=timeout_ms // 1000, check=False).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False
    return _run_elevated_multi([command], timeout_ms)


def _checked_process_command(executable: str, *arguments: str) -> str:
    arguments_text = " ".join("'" + argument.replace("'", "''") + "'" for argument in arguments)
    return (
        f"& {executable} {arguments_text}; "
        "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"
    )


def run_network_recovery(
    full_route_reset: bool = False,
    full_stack_reset: bool = False,
    flush_arp: bool = False,
    *,
    from_daemon: bool = False,
    audit_source: str = "cli",
) -> list[dict]:
    """Safely repair Blackout-owned network state after a crash or failed reconnect."""
    if sys.platform.startswith("linux"):
        from . import daemon, linux_network

        if daemon.get_state() is not None and not from_daemon:
            return [_script_result(
                "Targeted Linux recovery",
                True,
                "Skipped while Blackout daemon is active; stop it before repairing the network",
            )]
        results = linux_network.run_network_recovery(from_daemon=from_daemon)
        if flush_arp and not from_daemon:
            ok, detail = flush_arp_cache()
            results.append(_script_result("Flush ARP cache", ok, detail))
        from . import recovery_audit
        recovery_audit.record(
            source="daemon" if from_daemon else audit_source,
            flags={"full_route_reset": False, "full_stack_reset": False, "flush_arp": flush_arp},
            results=results,
        )
        return results

    if sys.platform != "win32":
        return [_script_result("Network recovery", False, "Unsupported platform")]

    if from_daemon:
        flush_arp = False

    from . import daemon

    if daemon.get_state() is not None and not from_daemon:
        return [_script_result(
            "Targeted network recovery",
            True,
            "Skipped while Blackout daemon is active; stop it before repairing the network",
        )]

    if from_daemon:
        full_route_reset = False
        full_stack_reset = False

    snapshot = get_network_recovery_snapshot()
    stale_adapters = find_stale_virtual_adapters(snapshot, daemon_running=not from_daemon)
    loopback_dns_adapters = find_loopback_dns_adapters(snapshot)
    stale_routes = find_stale_virtual_routes(snapshot, stale_adapters)
    if from_daemon:
        results = [_script_result("Preserve system proxy", True, "Daemon reconnect keeps the current proxy setting")]
    else:
        proxy_ok, proxy_detail = clear_stale_blackout_proxy()
        results = [_script_result("Clear system proxy", proxy_ok, proxy_detail)]
    script_lines = ["$ErrorActionPreference='Stop'"]
    batch_steps: list[tuple[str, str]] = []

    if stale_routes:
        for route in stale_routes:
            script_lines.append(
                "Remove-NetRoute -InterfaceIndex {index} -DestinationPrefix '{prefix}' "
                "-NextHop '{next_hop}' -Confirm:$false -ErrorAction Stop".format(
                    index=int(route["InterfaceIndex"]),
                    prefix=str(route["DestinationPrefix"]).replace("'", "''"),
                    next_hop=str(route.get("NextHop", "0.0.0.0")).replace("'", "''"),
                )
            )
        batch_steps.append(("Remove stale virtual routes", f"{len(stale_routes)} route(s)"))
    else:
        results.append(_script_result("Remove stale virtual routes", True, "No stale Blackout routes found"))

    if loopback_dns_adapters:
        for adapter in loopback_dns_adapters:
            script_lines.append(
                "Set-DnsClientServerAddress -InterfaceIndex {index} -ResetServerAddresses -ErrorAction Stop".format(
                    index=int(adapter["InterfaceIndex"])
                )
            )
        names = ", ".join(str(adapter.get("Name", adapter["InterfaceIndex"])) for adapter in loopback_dns_adapters)
        batch_steps.append(("Restore DHCP DNS", names))
    else:
        results.append(_script_result("Restore DHCP DNS", True, "No loopback DNS on physical adapters"))

    if stale_adapters:
        for adapter in stale_adapters:
            name = str(adapter.get("Name", "")).replace("'", "''")
            script_lines.extend([
                f"Disable-NetAdapter -Name '{name}' -Confirm:$false -ErrorAction Stop",
                f"Enable-NetAdapter -Name '{name}' -Confirm:$false -ErrorAction Stop",
            ])
        names = ", ".join(str(adapter.get("Name", adapter["InterfaceIndex"])) for adapter in stale_adapters)
        batch_steps.append(("Restart stale virtual adapters", names))
    else:
        results.append(_script_result("Restart stale virtual adapters", True, "No unhealthy virtual adapters found"))

    script_lines.append(_checked_process_command("ipconfig.exe", "/flushdns"))
    batch_steps.append(("Flush DNS cache", "Cleared resolver cache"))

    if full_route_reset:
        script_lines.extend([
            _checked_process_command("route.exe", "-f"),
            _checked_process_command("ipconfig.exe", "/renew"),
        ])
        batch_steps.append(("Full route-table reset", "Explicit emergency reset"))

    if full_stack_reset:
        for command, label in (
            (("netsh.exe", "winsock", "reset"), "Reset Winsock"),
            (("netsh.exe", "int", "ip", "reset"), "Reset TCP/IP stack"),
            (("netsh.exe", "int", "tcp", "set", "global", "autotuninglevel=normal"), "Reset TCP autotuning"),
            (("ipconfig.exe", "/release"), "Release IP address"),
            (("ipconfig.exe", "/renew"), "Renew IP address"),
        ):
            script_lines.append(_checked_process_command(*command))
            batch_steps.append((label, "Applied"))
    else:
        results.append(_script_result("Preserve Windows network stack", True, "Targeted recovery skips Winsock, TCP/IP, and DHCP resets"))
    if from_daemon:
        results.append(_script_result("Full route-table reset", True, "Daemon recovery never flushes all routes"))

    if batch_steps:
        batch_ok = _run_recovery_script("; ".join(script_lines), timeout_ms=90000)
        results.extend(
            _script_result(
                name,
                batch_ok,
                detail if batch_ok else "Command batch failed or UAC denied",
            )
            for name, detail in batch_steps
        )

    if flush_arp:
        arp_ok, arp_detail = flush_arp_cache()
        results.append(_script_result("Flush ARP cache", arp_ok, arp_detail))
    from . import recovery_audit
    recovery_audit.record(
        source="daemon" if from_daemon else audit_source,
        flags={
            "full_route_reset": full_route_reset,
            "full_stack_reset": full_stack_reset,
            "flush_arp": flush_arp,
        },
        results=results,
    )
    return results


def flush_arp_cache() -> tuple[bool, str]:
    """Explicitly flush the local IPv4 ARP/neighbor cache."""
    if sys.platform.startswith("linux"):
        from . import linux_network

        return linux_network.flush_neighbor_cache()
    if sys.platform != "win32":
        return False, "Unsupported platform"
    if not _is_admin():
        return False, "Run this command as Administrator"
    try:
        result = subprocess.run(
            ["arp.exe", "-d", "*"],
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False, "Could not run arp.exe"
    if result.returncode == 0:
        return True, "Flushed IPv4 ARP cache"
    return False, "Could not flush the IPv4 ARP cache"


# ─────────────────────────── DNS tools ───────────────────────────

POPULAR_DNS = {
    "Cloudflare (1.1.1.1)":   "1.1.1.1",
    "Cloudflare (1.0.0.1)":   "1.0.0.1",
    "Google (8.8.8.8)":       "8.8.8.8",
    "Google (8.8.4.4)":       "8.8.4.4",
    "Quad9 (9.9.9.9)":        "9.9.9.9",
    "AdGuard (94.140.14.14)": "94.140.14.14",
    "OpenDNS (208.67.222.222)": "208.67.222.222",
    "Shecan (shecan.ir)":     "185.51.200.2",     # Iranian filtered-but-fast DNS
    "Electro (Electrotm)":    "78.157.42.100",    # Iranian bypass DNS
    "403 online":             "10.202.10.202",    # Iranian ISP DNS
}


def flush_dns() -> bool:
    """Flush the operating system DNS cache."""
    try:
        if sys.platform == "win32":
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True, check=True, timeout=10)
        else:
            # Try common Linux DNS cache flush methods
            for cmd in [
                ["systemctl", "restart", "systemd-resolved"],
                ["service", "dnsmasq", "restart"],
                ["nscd", "-i", "hosts"],
            ]:
                try:
                    subprocess.run(cmd, capture_output=True, check=True, timeout=10)
                    break
                except Exception:
                    continue
        return True
    except Exception:
        return False


def benchmark_dns(domain: str = "www.google.com", repeat: int = 3) -> list[tuple[str, str, float]]:
    """
    Benchmark all popular DNS servers concurrently using a thread pool.
    Returns sorted list of (name, ip, avg_latency_ms).
    Much faster than sequential — all servers tested in parallel.
    """
    def _measure(name: str, ip: str) -> tuple[str, str, float] | None:
        times = []
        for _ in range(repeat):
            try:
                start = time.monotonic()
                if _dns_query(ip, domain) is not None:
                    times.append((time.monotonic() - start) * 1000)
            except Exception:
                pass
        if times:
            return (name, ip, round(sum(times) / len(times), 1))
        return None

    _log.debug("Benchmarking %d DNS servers concurrently (domain=%s, repeat=%d)",
               len(POPULAR_DNS), domain, repeat)

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(POPULAR_DNS)) as pool:
        futures = {pool.submit(_measure, name, ip): name for name, ip in POPULAR_DNS.items()}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    results.sort(key=lambda x: x[2])
    _log.debug("DNS benchmark complete — fastest: %s (%s ms)", results[0][0], results[0][2] if results else "N/A")
    return results


def resolve_doh(domain: str, timeout: float = 5.0) -> str | None:
    """Resolve a domain to an IP using Cloudflare DoH (DNS over HTTPS)."""
    import urllib.request
    import json
    import ipaddress
    try:
        ipaddress.ip_address(domain)
        return domain
    except ValueError:
        pass

    try:
        req = urllib.request.Request(
            f"https://1.1.1.1/dns-query?name={domain}&type=A",
            headers={"accept": "application/dns-json"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("Status") == 0 and data.get("Answer"):
                for answer in data["Answer"]:
                    if answer.get("type") == 1:  # A record
                        return answer["data"]
    except Exception as e:
        _log.warning("DoH bootstrap failed for %s: %s", domain, e)
    return None


def _dns_query(dns_ip: str, hostname: str, timeout: float = 3.0) -> str | None:
    """Simple DNS A-record query using raw UDP to a specific server."""
    import struct, random
    query_id = random.randint(0, 65535)
    # Build a minimal DNS query packet
    header  = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    qname   = b"".join(len(part).to_bytes(1, "big") + part.encode()
                        for part in hostname.split(".")) + b"\x00"
    question = qname + struct.pack(">HH", 1, 1)  # Type A, Class IN
    packet  = header + question
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (dns_ip, 53))
        data, _ = sock.recvfrom(512)
        return data  # We just care if we get a response
    except Exception:
        return None
    finally:
        sock.close()


# ─────────────────────────── Speed test ──────────────────────────

SPEED_TEST_FILES = [
    # (url, size_bytes, label)
    ("http://speed.cloudflare.com/__down?bytes=1000000",  1_000_000,  "1 MB  (Cloudflare)"),
    ("http://speed.cloudflare.com/__down?bytes=10000000", 10_000_000, "10 MB (Cloudflare)"),
]
UPLOAD_TEST_URL  = "https://speed.cloudflare.com/__up"
UPLOAD_SIZE      = 1_000_000   # 1 MB of random data for upload test


def simple_speed_test() -> dict:
    """
    Run a download + upload speed test via Cloudflare.
    Returns: {latency_ms, download_mbps, upload_mbps, test_size, server}
    """
    # Latency
    latency = None
    for _ in range(3):
        try:
            start = time.monotonic()
            urllib.request.urlopen("http://speed.cloudflare.com/__ping", timeout=5)
            latency = (time.monotonic() - start) * 1000
            break
        except Exception:
            pass

    # Download speed
    mbps  = None
    label = None
    for url, _size, lbl in SPEED_TEST_FILES:
        try:
            start = time.monotonic()
            with urllib.request.urlopen(url, timeout=30) as resp:
                data = resp.read()
            elapsed = time.monotonic() - start
            if elapsed > 0:
                mbps  = (len(data) * 8) / elapsed / 1_000_000
                label = lbl
            break
        except Exception:
            continue

    # Upload speed
    upload_mbps = None
    try:
        upload_data = os.urandom(UPLOAD_SIZE)
        req = urllib.request.Request(
            UPLOAD_TEST_URL,
            data=upload_data,
            method="POST",
            headers={"Content-Type": "application/octet-stream"},
        )
        start = time.monotonic()
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp.read()
        elapsed = time.monotonic() - start
        if elapsed > 0:
            upload_mbps = (len(upload_data) * 8) / elapsed / 1_000_000
    except Exception:
        pass

    return {
        "latency_ms":    latency,
        "download_mbps": mbps,
        "upload_mbps":   upload_mbps,
        "test_size":     label,
        "server":        "Cloudflare",
    }


def record_speedtest_result(result: dict) -> None:
    """Append a speedtest result to the persisted history, capped at the last N entries."""
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        history = json.loads(SPEEDTEST_HISTORY_FILE.read_text()) if SPEEDTEST_HISTORY_FILE.exists() else []
    except Exception:
        history = []

    history.append({
        "ts": time.time(),
        "latency_ms": result.get("latency_ms"),
        "download_mbps": result.get("download_mbps"),
        "upload_mbps": result.get("upload_mbps"),
    })
    history = history[-_SPEEDTEST_HISTORY_MAX:]

    try:
        SPEEDTEST_HISTORY_FILE.write_text(json.dumps(history, indent=2))
    except Exception:
        pass


def get_speedtest_history(limit: int = 30) -> list[dict]:
    """Return the most recent N recorded speedtest results, oldest first."""
    try:
        history = json.loads(SPEEDTEST_HISTORY_FILE.read_text()) if SPEEDTEST_HISTORY_FILE.exists() else []
    except Exception:
        history = []
    return history[-limit:]


# ─────────────────────────── Public IP ──────────────────────────

_PUBLIC_IP_ENDPOINTS = [
    "https://api.ipify.org",
    "https://checkip.amazonaws.com",
    "https://ifconfig.me/ip",
]


def get_public_ip(timeout: float = 5.0) -> str | None:
    """
    Return the machine's current public IPv4 address.
    Tries multiple endpoints in order — first success wins.
    If a VPN is active, this returns the VPN's exit IP (useful for leak check).
    Returns None if all endpoints are unreachable.
    """
    for url in _PUBLIC_IP_ENDPOINTS:
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "blackout-kit/1.0"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                ip = resp.read().decode().strip()
                if ip and "." in ip:
                    _log.debug("Public IP via %s: %s", url, ip)
                    return ip
        except Exception:
            continue
    _log.debug("Could not determine public IP — all endpoints unreachable.")
    return None


# ─────────────────────────── MTU detection ───────────────────────

def detect_mtu(host: str = "8.8.8.8") -> int | None:
    """
    Detect the path MTU to a host using binary search with ICMP ping.
    Only works on Windows (uses ping's -f and -l flags).
    Returns discovered MTU or None.
    """
    if sys.platform != "win32":
        return None
    low, high = 576, 1500
    result = None
    while low <= high:
        mid = (low + high) // 2
        try:
            # -l specifies the data payload size. 
            # Actual packet size = payload + 28 bytes (20 byte IP header + 8 byte ICMP header).
            # We want to find the largest packet size that passes.
            r = subprocess.run(
                ["ping", "-n", "1", "-f", "-l", str(mid), host],
                capture_output=True, timeout=5,
            )
            if r.returncode == 0 and b"100%" not in r.stdout:
                result = mid + 28  # Store the actual MTU
                low = mid + 1
            else:
                high = mid - 1
        except Exception:
            high = mid - 1   # Treat subprocess failure as "packet too large"
    return result


def _get_adapter_by_mtu(mtu: int) -> str | None:
    """Find a connected adapter that has a non-standard MTU."""
    try:
        result = subprocess.run(
            ["netsh", "interface", "ipv4", "show", "subinterfaces"],
            capture_output=True, text=True, encoding="utf-8", errors="ignore"
        )
        # Output format:   MTU  MediaSenseState   Bytes In  Bytes Out  Interface
        #                ------  ---------------  ---------  ---------  -------------
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                try:
                    if int(parts[0]) == mtu:
                        # Return the interface name (can contain spaces)
                        return " ".join(parts[4:])
                except ValueError:
                    continue
    except Exception:
        pass
    return None


def set_mtu(mtu: int, adapter: str | None = None) -> bool:
    """
    Set MTU for a Windows network adapter.
    If adapter is None, tries to find the current active adapter.
    Auto-elevates via UAC if not running as admin.
    """
    if sys.platform != "win32":
        return False
    if not _is_admin():
        _log.info("MTU set requires admin — requesting elevation via UAC…")
        if not _run_elevated(["cmd.exe", "/c", "echo Auto-elevate placeholder"]):
            return False
        # Re-query adapter after elevation may not work — use direct approach
    try:
        if not adapter:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", "(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -notlike '*Loopback*' }).Name"],
                capture_output=True, text=True, errors="ignore", timeout=10
            )
            out = result.stdout.strip()
            if out:
                adapter = out.splitlines()[0].strip()

        if not adapter:
            return False

        if not _is_admin():
            return _run_elevated(["netsh", "interface", "ipv4", "set", "subinterface",
                                  adapter, f"mtu={mtu}", "store=persistent"])

        subprocess.run(
            ["netsh", "interface", "ipv4", "set", "subinterface",
             adapter, f"mtu={mtu}", "store=persistent"],
            capture_output=True, check=True, timeout=10,
        )
        return True
    except Exception:
        return False


# ─────────────────────────── Network adapters ────────────────────

def list_adapters() -> list[dict]:
    """List all network adapters with their IPs and connection status."""
    adapters: list[dict] = []
    if sys.platform != "win32":
        return adapters
    try:
        import psutil
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        
        for name, stat in stats.items():
            current = {
                "name": name,
                "ipv4": "",
                "ipv6": "",
                "status": "Connected" if stat.isup else "Disconnected"
            }
            if name in addrs:
                for addr in addrs[name]:
                    if addr.family == socket.AF_INET:
                        current["ipv4"] = addr.address
                    elif addr.family == socket.AF_INET6:
                        current["ipv6"] = addr.address
            adapters.append(current)
    except Exception:
        pass
    return adapters


# ─────────────────────────── Ping / traceroute ───────────────────

def ping(host: str, count: int = 4) -> list[float | None]:
    """Ping a host n times via TCP :80. Returns list of RTT in ms (None = timeout)."""
    times: list[float | None] = []
    for _ in range(count):
        try:
            start = time.monotonic()
            sock  = socket.create_connection((host, 80), timeout=3.0)
            times.append((time.monotonic() - start) * 1000)
            sock.close()
        except Exception:
            times.append(None)
        time.sleep(0.2)
    return times


def ping_stats(times: list[float | None]) -> dict:
    """
    Compute statistics from a ping times list.
    Returns: {avg, min, max, jitter, loss_pct}
    Jitter = mean of absolute differences between consecutive successful RTTs.
    """
    valid    = [t for t in times if t is not None]
    total    = len(times) if times else 1
    loss_pct = 100.0 * (total - len(valid)) / total

    if not valid:
        return {"avg": None, "min": None, "max": None, "jitter": None, "loss_pct": loss_pct}

    avg    = sum(valid) / len(valid)
    jitter = None
    if len(valid) >= 2:
        diffs  = [abs(valid[i] - valid[i - 1]) for i in range(1, len(valid))]
        jitter = sum(diffs) / len(diffs)

    return {
        "avg":      avg,
        "min":      min(valid),
        "max":      max(valid),
        "jitter":   jitter,
        "loss_pct": loss_pct,
    }


def traceroute(host: str, max_hops: int = 20) -> list[tuple[int, str]]:
    """
    Run a traceroute to host.
    Returns list of (hop_number, result_line) tuples.
    """
    cmd = (["tracert", "-h", str(max_hops), host] if sys.platform == "win32"
           else ["traceroute", "-m", str(max_hops), host])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                                encoding="utf-8", errors="ignore")
        lines = result.stdout.splitlines()
        return [(i + 1, l) for i, l in enumerate(lines[3:]) if l.strip()]
    except Exception:
        return []


# ─────────────────────────── Network Analysis ────────────────────

def get_active_connections(established_only: bool = False) -> list[dict]:
    """
    Return a list of active network connections with process attribution.
    Each entry: {pid, process, local_addr, local_port, remote_addr, remote_port, status, protocol}
    Requires psutil. Skips connections whose owning process cannot be read (permission denied).
    """
    import psutil

    results: list[dict] = []
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        return results

    proc_name_cache: dict[int, str] = {}

    for conn in connections:
        if established_only and conn.status != psutil.CONN_ESTABLISHED:
            continue
        if not conn.laddr:
            continue

        pid = conn.pid
        proc_name = "-"
        if pid:
            if pid in proc_name_cache:
                proc_name = proc_name_cache[pid]
            else:
                try:
                    proc_name = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = "(privileged)"
                proc_name_cache[pid] = proc_name

        protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        results.append({
            "pid": pid or 0,
            "process": proc_name,
            "local_addr": conn.laddr.ip,
            "local_port": conn.laddr.port,
            "remote_addr": conn.raddr.ip if conn.raddr else "",
            "remote_port": conn.raddr.port if conn.raddr else 0,
            "status": conn.status,
            "protocol": protocol,
        })

    results.sort(key=lambda item: (item["process"].lower(), item["local_port"]))
    return results


# ─────────────────────────── DNS inspector ────────────────────────

DNS_POISON_CHECK_DOMAINS = [
    "www.google.com",
    "www.youtube.com",
    "www.wikipedia.org",
    "www.cloudflare.com",
]


def get_system_dns_servers() -> list[str]:
    """Return the DNS server IPs currently configured on active adapters."""
    servers: set[str] = set()
    if sys.platform == "win32":
        snapshot = get_network_recovery_snapshot()
        for adapter in snapshot.get("adapters", []):
            if str(adapter.get("Status", "")).lower() != "up":
                continue
            for server in adapter.get("DnsServers", []):
                servers.add(str(server))
    else:
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            servers.add(parts[1])
        except OSError:
            pass
    return sorted(servers)


def _system_resolve(domain: str, timeout: float = 3.0) -> str | None:
    """Resolve a domain using the OS resolver (whatever DNS server is configured)."""
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            return socket.gethostbyname(domain)
        finally:
            socket.setdefaulttimeout(old_timeout)
    except Exception:
        return None


def inspect_dns() -> dict:
    """
    Compare system DNS resolution against a trusted DoH resolver (Cloudflare)
    for a set of well-known domains, to surface possible DNS interference or
    poisoning. This is a heuristic signal, not proof of tampering — CDNs
    legitimately return different IPs to different resolvers.

    A domain is only flagged "suspect" when the trusted resolver succeeded but
    the system resolver failed — that is the strongest local signal of
    blocking/poisoning. If the trusted resolver itself is unreachable (e.g.
    outbound HTTPS to 1.1.1.1 is blocked), no domain is flagged, since we have
    no independent baseline to compare against.

    Returns {servers, trusted_resolver_reachable, checks: [{domain, system_ip, trusted_ip, suspect}]}
    """
    servers = get_system_dns_servers()
    checks = []
    trusted_reachable = False
    for domain in DNS_POISON_CHECK_DOMAINS:
        system_ip = _system_resolve(domain)
        trusted_ip = resolve_doh(domain)
        if trusted_ip:
            trusted_reachable = True
        suspect = bool(trusted_ip) and not system_ip
        checks.append({
            "domain": domain,
            "system_ip": system_ip or "no response",
            "trusted_ip": trusted_ip or "no response",
            "suspect": suspect,
        })
    return {"servers": servers, "trusted_resolver_reachable": trusted_reachable, "checks": checks}


# ─────────────────────────── Network discovery ───────────────────

def _local_ip_and_prefix() -> tuple[str, str] | None:
    """Return (local_ip, /24 network prefix like '192.168.1') via a UDP socket trick."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
        prefix = ".".join(local_ip.split(".")[:3])
        return local_ip, prefix
    except Exception:
        return None


def _arp_table() -> dict[str, str]:
    """Return {ip: mac} from the OS ARP/neighbor table."""
    table: dict[str, str] = {}
    try:
        if sys.platform == "win32":
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10, errors="ignore")
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0].count(".") == 3:
                    ip, mac = parts[0], parts[1]
                    if "-" in mac or ":" in mac:
                        table[ip] = mac.replace("-", ":").lower()
        else:
            result = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=10, errors="ignore")
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0].count(".") == 3:
                    table[parts[0]] = parts[4].lower()
    except Exception:
        pass
    return table


def discover_lan_hosts(timeout: float = 0.3, max_workers: int = 100, progress_callback=None) -> list[dict]:
    """
    Sweep the local /24 subnet to discover live hosts.

    Pings every address (TCP connect attempts on common ports populate the OS
    ARP cache), then reads the ARP table for IP → MAC mappings and attempts a
    reverse-DNS lookup for a friendly hostname.

    Returns a list of {ip, mac, hostname, is_self}.
    """
    local = _local_ip_and_prefix()
    if not local:
        return []
    local_ip, prefix = local

    def _probe(ip: str) -> None:
        for port in (80, 443, 445, 22, 139):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect_ex((ip, port))
                sock.close()
                break
            except Exception:
                continue
        if progress_callback:
            progress_callback()

    targets = [f"{prefix}.{i}" for i in range(1, 255) if f"{prefix}.{i}" != local_ip]
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        list(pool.map(_probe, targets))

    arp = _arp_table()
    hosts: list[dict] = [{"ip": local_ip, "mac": arp.get(local_ip, "-"), "hostname": "(this device)", "is_self": True}]

    for ip, mac in arp.items():
        if not ip.startswith(prefix + ".") or ip == local_ip:
            continue
        hostname = "-"
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass
        hosts.append({"ip": ip, "mac": mac, "hostname": hostname, "is_self": False})

    hosts.sort(key=lambda h: tuple(int(part) for part in h["ip"].split(".")))
    return hosts


COMMON_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-Sub",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
    2049: "NFS", 27017: "MongoDB", 3000: "Dev-HTTP", 3306: "MySQL",
    3389: "RDP", 5000: "Dev-HTTP", 5432: "PostgreSQL", 5900: "VNC",
    5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 6379: "Redis", 8000: "HTTP-Alt",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9000: "Dev-HTTP", 9200: "Elasticsearch",
    27015: "Steam", 25565: "Minecraft",
}


def scan_ports(
    host: str,
    ports: list[int] | None = None,
    timeout: float = 0.5,
    max_workers: int = 100,
    progress_callback=None,
) -> list[dict]:
    """
    Scan a host for open TCP ports using a thread pool of raw connect() attempts.

    ports: explicit list, or None to scan the built-in COMMON_PORTS list.
    Returns a list of {port, service, open} for every port that responded open.
    """
    target_ports = ports if ports is not None else list(COMMON_PORTS.keys())

    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror:
        return []

    def _check(port: int) -> dict | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((resolved_ip, port))
            if result == 0:
                return {"port": port, "service": COMMON_PORTS.get(port, "unknown"), "open": True}
            return None
        except Exception:
            return None
        finally:
            sock.close()
            if progress_callback:
                progress_callback()

    open_ports: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_check, port) for port in target_ports]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda item: item["port"])
    return open_ports


def calculate_subnet(ip_cidr: str) -> dict | None:
    """
    Calculate subnet details (Network, Broadcast, Mask, Usable range) from a CIDR string.
    Returns a dict with the parsed details or None if invalid.
    """
    try:
        network = ipaddress.IPv4Network(ip_cidr, strict=False)
        return {
            "network": str(network.network_address),
            "broadcast": str(network.broadcast_address),
            "netmask": str(network.netmask),
            "cidr": network.prefixlen,
            "total_hosts": network.num_addresses,
            "usable_hosts": network.num_addresses - 2 if network.num_addresses > 2 else 0,
            "first_ip": str(network[1]) if network.num_addresses > 2 else "N/A",
            "last_ip": str(network[-2]) if network.num_addresses > 2 else "N/A",
        }
    except ValueError:
        return None


def set_dns(dns_ip: str, adapter: str | None = None) -> bool:
    """
    Set the DNS server for all active adapters (or a specific one).
    Auto-elevates via UAC if not running as admin.
    """
    if sys.platform != "win32":
        return False
    try:
        if adapter:
            adapters_to_set = [adapter]
        else:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", "(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -notlike '*Loopback*' }).Name"],
                capture_output=True, text=True, errors="ignore", timeout=10
            )
            adapters_to_set = [line.strip() for line in result.stdout.strip().splitlines() if line.strip()]

        if not adapters_to_set:
            return False

        if not _is_admin():
            cmds = [["netsh", "interface", "ip", "set", "dns", adp, "static", dns_ip]
                    for adp in adapters_to_set]
            return _run_elevated_multi(cmds)

        for adp in adapters_to_set:
            subprocess.run(
                ["netsh", "interface", "ip", "set", "dns", adp, "static", dns_ip],
                capture_output=True, check=False, timeout=10
            )
        return True
    except Exception:
        return False


def toggle_hotspot() -> str:
    """
    Toggle Windows Mobile Hotspot using PowerShell.
    Returns a status message string.
    """
    if sys.platform != "win32":
        return "[error]Hotspot control only works on Windows.[/error]"
    ps_script = r"""
Add-Type -AssemblyName System.Runtime.WindowsRuntime
[void][Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking,ContentType=WindowsRuntime]
$connections = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]
$profile = $connections::GetInternetConnectionProfile()
if ($profile -eq $null) { Write-Output "NO_INTERNET"; exit }
$manager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($profile)
if ($manager.TetheringOperationalState -eq 1) {
    $manager.StopTetheringAsync() | Out-Null; Write-Output "STOPPED"
} else {
    $manager.StartTetheringAsync() | Out-Null; Write-Output "STARTED"
}
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True, text=True, timeout=20,
            encoding="utf-8", errors="ignore",
        )
        out = result.stdout.strip()
        if "STARTED" in out:
            return "[success]✓ Hotspot started. Other devices can now connect.[/success]"
        if "STOPPED" in out:
            return "[warning]Hotspot stopped.[/warning]"
        return f"[warning]Hotspot toggle returned: {out or result.stderr[:80]}[/warning]"
    except Exception as e:
        return f"[error]Hotspot error: {e}[/error]"


def enable_ics() -> str:
    """
    Enable Internet Connection Sharing on the VPN / proxy adapter
    via Windows registry. Requires admin + reboot to fully apply.
    """
    if sys.platform != "win32":
        return "[error]ICS only works on Windows.[/error]"
    ps_script = r"""
# Share the first active non-loopback adapter's internet to the hotspot
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -notlike '*Loopback*' }
foreach ($a in $adapters) {
    $config = $a | Get-NetAdapterBinding -ComponentID ms_server
    if ($config) { Write-Output $a.Name; break }
}
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True, text=True, timeout=15,
            encoding="utf-8", errors="ignore",
        )
        adp = result.stdout.strip()
        if adp:
            return (
                f"[success]Found adapter: {adp}[/success]\n"
                "[muted]To enable ICS: open Network Connections → right-click your VPN adapter\n"
                "→ Properties → Sharing → 'Allow other network users to connect'[/muted]\n"
                "[dim](Full programmatic ICS requires Windows SDK bindings)[/dim]"
            )
        return "[warning]No suitable adapter found. Enable ICS manually via Network Connections.[/warning]"
    except Exception as e:
        return f"[error]{e}[/error]"


def autofix_windows() -> list[str]:
    """Run the shared, targeted Windows recovery sequence."""
    return [
        (f"[success]✓[/success] {step['name']}" if step["ok"]
         else f"[warning]⚠[/warning] {step['name']} — {step['detail']}")
        for step in run_network_recovery()
    ]
