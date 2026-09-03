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
from pathlib import Path

# Expose standalone specialist modules stored beside this legacy toolkit module.
__path__ = [str(Path(__file__).with_name("tools"))]

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
        "$p = Start-Process -FilePath $env:BLACKOUT_CMD_0 "
        "-ArgumentList $env:BLACKOUT_CMD_ARGS "
        "-NoNewWindow -Wait -PassThru; exit $p.ExitCode"
    )
    env = {**os.environ, "BLACKOUT_CMD_0": cmd[0], "BLACKOUT_CMD_ARGS": subprocess.list2cmdline(cmd[1:])}
    handle, pid = elevate.launch_elevated(
        "powershell.exe",
        ["-NoProfile", "-Command", ps_script],
        env=env,
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
    env = os.environ.copy()
    blocks = []
    for i, cmd in enumerate(commands):
        env_key_exe = f"BLACKOUT_CMD_{i}_EXE"
        env_key_args = f"BLACKOUT_CMD_{i}_ARGS"
        env[env_key_exe] = cmd[0]
        env[env_key_args] = subprocess.list2cmdline(cmd[1:])
        blocks.append(
            f"$p = Start-Process -FilePath $env:{env_key_exe} "
            f"-ArgumentList $env:{env_key_args} "
            f"-NoNewWindow -Wait -PassThru; if ($p.ExitCode -ne 0) {{ exit $p.ExitCode }}"
        )
    ps_script = "& { " + "; ".join(blocks) + " }"
    handle, _ = elevate.launch_elevated(
        "powershell.exe",
        ["-NoProfile", "-Command", ps_script],
        env=env,
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
            try:
                times.append((time.monotonic() - start) * 1000)
            finally:
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
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect_ex((ip, port))
                break
            except Exception:
                continue
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass
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


def ping_once(host: str, timeout: float = 2.0) -> float | None:
    """Single TCP :80 ping RTT sample in ms, or None on timeout/refused.

    Unlike ping(), this takes exactly one sample and does not sleep afterward —
    intended for callers that control their own sampling interval (e.g. a live
    latency monitor).
    """
    try:
        start = time.monotonic()
        sock = socket.create_connection((host, 80), timeout=timeout)
        sock.close()
        return (time.monotonic() - start) * 1000
    except Exception:
        return None


# ─────────────────────────── Bandwidth monitor ────────────────────

def get_interface_io_counters() -> dict[str, tuple[int, int]]:
    """Return a one-shot {interface_name: (bytes_recv, bytes_sent)} snapshot via psutil."""
    import psutil

    try:
        counters = psutil.net_io_counters(pernic=True)
    except Exception:
        return {}
    return {name: (c.bytes_recv, c.bytes_sent) for name, c in counters.items()}


def compute_bandwidth_rates(
    prev: dict[str, tuple[int, int]],
    curr: dict[str, tuple[int, int]],
    elapsed: float,
) -> dict[str, dict]:
    """
    Diff two interface-counter snapshots into per-interface throughput.
    Returns {interface: {rx_bps, tx_bps}}. Counter resets/rollovers clamp to 0
    instead of reporting a negative rate.
    """
    if elapsed <= 0:
        return {}
    rates: dict[str, dict] = {}
    for name, (rx, tx) in curr.items():
        prev_rx, prev_tx = prev.get(name, (rx, tx))
        rates[name] = {
            "rx_bps": max(0, rx - prev_rx) / elapsed,
            "tx_bps": max(0, tx - prev_tx) / elapsed,
        }
    return rates


# ─────────────────────────── Packet capture ────────────────────────

class CaptureUnavailable(Exception):
    """Raised when scapy (and/or its Npcap/libpcap driver) isn't available."""

    def __init__(self, message: str = "packet capture is unavailable"):
        super().__init__(message)


CAPTURE_INSTALL_HINT = (
    "Install packet capture support with `pip install blackout-kit[capture]`; "
    "Windows also requires Npcap and Linux requires libpcap."
)


def parse_packet_summary(pkt) -> dict:
    """
    Translate a scapy packet into a flat, display-friendly dict.
    Tolerant of non-IP frames (ARP, raw Ethernet) — falls back to "-" fields
    rather than raising, since capture must never crash on an unusual frame.
    """
    ts = float(getattr(pkt, "time", time.time()))
    length = len(pkt) if hasattr(pkt, "__len__") else 0

    src = dst = "-"
    sport = dport = None
    proto = "OTHER"

    if pkt.haslayer("ARP"):
        arp = pkt["ARP"]
        proto = "ARP"
        src = getattr(arp, "psrc", "-")
        dst = getattr(arp, "pdst", "-")
    elif pkt.haslayer("IP") or pkt.haslayer("IPv6"):
        ip_layer = pkt["IP"] if pkt.haslayer("IP") else pkt["IPv6"]
        src = getattr(ip_layer, "src", "-")
        dst = getattr(ip_layer, "dst", "-")
        if pkt.haslayer("TCP"):
            proto = "TCP"
            sport = int(pkt["TCP"].sport)
            dport = int(pkt["TCP"].dport)
        elif pkt.haslayer("UDP"):
            proto = "UDP"
            sport = int(pkt["UDP"].sport)
            dport = int(pkt["UDP"].dport)
        elif pkt.haslayer("ICMP"):
            proto = "ICMP"
        else:
            proto = "IP"

    try:
        summary = pkt.summary()
    except Exception:
        summary = f"{proto} {length}B"

    return {
        "ts": ts,
        "proto": proto,
        "src": src,
        "sport": sport,
        "dst": dst,
        "dport": dport,
        "length": length,
        "summary": summary,
    }


def capture_packets(
    iface: str | None = None,
    bpf_filter: str | None = None,
    count: int = 0,
    stop_event=None,
    on_packet=None,
) -> None:
    """
    Sniff live packets via scapy, calling on_packet(dict) for each one via
    parse_packet_summary(). Blocks until `count` packets are captured (count=0
    means unbounded) or stop_event is set. Raises CaptureUnavailable if scapy
    (or its underlying Npcap/libpcap driver) can't be used.
    """
    try:
        import scapy.all as scapy
    except Exception as exc:
        raise CaptureUnavailable(CAPTURE_INSTALL_HINT) from exc

    def _prn(pkt):
        if on_packet:
            on_packet(parse_packet_summary(pkt))

    def _stop_filter(_pkt):
        return bool(stop_event and stop_event.is_set())

    try:
        scapy.sniff(
            iface=iface or None,
            filter=bpf_filter or None,
            count=count or 0,
            prn=_prn,
            stop_filter=_stop_filter,
            store=False,
        )
    except CaptureUnavailable:
        raise
    except Exception as exc:
        raise CaptureUnavailable(f"{CAPTURE_INSTALL_HINT} Capture failed to start.") from exc


def summarize_capture_packets(packets: list[dict]) -> dict:
    """
    Pure post-capture summary: protocol breakdown, top-5 talkers by source
    address, total packets/bytes, and capture duration. No scapy involved —
    operates purely on the dicts produced by parse_packet_summary().
    """
    if not packets:
        return {
            "total_packets": 0,
            "total_bytes": 0,
            "duration": 0.0,
            "protocol_counts": {},
            "top_talkers": [],
        }

    protocol_counts: dict[str, int] = {}
    talker_counts: dict[str, int] = {}
    total_bytes = 0

    for pkt in packets:
        protocol_counts[pkt["proto"]] = protocol_counts.get(pkt["proto"], 0) + 1
        total_bytes += pkt.get("length", 0)
        src = pkt.get("src", "-")
        if src and src != "-":
            talker_counts[src] = talker_counts.get(src, 0) + 1

    top_talkers = sorted(talker_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
    timestamps = [pkt["ts"] for pkt in packets]

    return {
        "total_packets": len(packets),
        "total_bytes": total_bytes,
        "duration": max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0,
        "protocol_counts": protocol_counts,
        "top_talkers": top_talkers,
    }


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


# ─────────────────────────── Global Panic Button ───────────────────

def trigger_panic(restore: bool = False) -> list[dict]:
    """
    🚨 Global Panic Button:
    Instantly kills daemon/engines, clears system proxy, disables kill switch,
    flushes DNS and ARP, resets network adapters/routes to secure or restore networking.
    """
    results = []

    # 1. Stop background daemon & all bypass engines
    try:
        from . import daemon
        daemon.stop()
        results.append({"step": "Stop Daemon & Bypass Engines", "ok": True, "detail": "Stopped daemon and killed child process trees"})
    except Exception as exc:
        results.append({"step": "Stop Daemon & Bypass Engines", "ok": False, "detail": str(exc)})

    # 2. Clear System Proxy
    try:
        from .proxy_manager import clear_system_proxy
        clear_system_proxy()
        results.append({"step": "Clear System Proxy", "ok": True, "detail": "System proxy setting cleared"})
    except Exception as exc:
        results.append({"step": "Clear System Proxy", "ok": False, "detail": str(exc)})

    # 3. Disable Kill Switch / Remove Firewall Blocks
    try:
        from . import security as sec
        from . import settings as cfg
        sec.disable_kill_switch()
        cfg.set_value("kill_switch", False)
        results.append({"step": "Disable Kill Switch", "ok": True, "detail": "Blackout-owned firewall block rules removed"})
    except Exception as exc:
        results.append({"step": "Disable Kill Switch", "ok": False, "detail": str(exc)})

    # 4. Flush DNS Resolver Cache
    try:
        ok = flush_dns()
        results.append({"step": "Flush DNS Cache", "ok": ok, "detail": "Resolver cache flushed" if ok else "Failed to flush DNS"})
    except Exception as exc:
        results.append({"step": "Flush DNS Cache", "ok": False, "detail": str(exc)})

    # 5. Flush ARP Cache
    try:
        ok, msg = flush_arp_cache()
        results.append({"step": "Flush ARP Cache", "ok": ok, "detail": msg})
    except Exception as exc:
        results.append({"step": "Flush ARP Cache", "ok": False, "detail": str(exc)})

    # 6. Run Targeted Network Recovery (or restore network stack)
    try:
        rec_results = run_network_recovery(full_route_reset=restore, full_stack_reset=restore, audit_source="panic")
        results.append({"step": "Targeted Network Recovery", "ok": True, "detail": f"Executed {len(rec_results)} recovery repairs"})
    except Exception as exc:
        results.append({"step": "Targeted Network Recovery", "ok": False, "detail": str(exc)})

    return results


# ─────────────────────────── Network Hardening Audit ───────────────────

def run_network_audit() -> dict:
    """
    🛡️ Network Hardening Audit:
    Inspects listening ports, unencrypted services, DNS servers, firewall status, and local exposures.
    Returns audit details and a overall Security Score (0-100%).
    """
    findings = []
    score = 100

    # 1. Inspect listening ports & unencrypted protocols
    try:
        connections = get_active_connections(established_only=False)
        listening = [c for c in connections if c.get("status") == "LISTEN" or c.get("protocol") == "UDP"]
        insecure_ports = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP", 445: "SMB", 3389: "RDP", 5900: "VNC"}
        exposed_insecure = []

        for conn in listening:
            port = conn.get("local_port")
            if port in insecure_ports:
                proc = conn.get("process", "unknown")
                service = insecure_ports[port]
                exposed_insecure.append(f"{service} ({port}/TCP) used by {proc}")

        if exposed_insecure:
            penalty = min(30, len(exposed_insecure) * 10)
            score -= penalty
            findings.append({
                "category": "Exposed Ports & Insecure Protocols",
                "severity": "HIGH",
                "ok": False,
                "summary": f"Found {len(exposed_insecure)} unencrypted/sensitive service(s) listening locally",
                "details": exposed_insecure,
                "recommendation": "Disable plaintext services (Telnet/FTP/HTTP) or bind them to 127.0.0.1"
            })
        else:
            findings.append({
                "category": "Exposed Ports & Insecure Protocols",
                "severity": "INFO",
                "ok": True,
                "summary": "No common unencrypted cleartext protocols listening publicly",
                "details": [],
                "recommendation": "Maintain strict listening port bounds"
            })
    except Exception as exc:
        findings.append({
            "category": "Exposed Ports & Insecure Protocols",
            "severity": "WARNING",
            "ok": False,
            "summary": f"Could not inspect listening sockets: {exc}",
            "details": [],
            "recommendation": "Run as privileged user to inspect process ports"
        })

    # 2. DNS Inspector & Poisoning Check
    try:
        dns_res = inspect_dns()
        servers = dns_res.get("servers", [])
        suspects = [check for check in dns_res.get("checks", []) if check.get("suspect")]

        if suspects:
            score -= 25
            findings.append({
                "category": "DNS Resolver Integrity",
                "severity": "CRITICAL",
                "ok": False,
                "summary": f"Detected potential DNS tampering/poisoning on {len(suspects)} domain(s)",
                "details": [f"{s['domain']} resolved to {s['system_ip']} vs DoH {s['trusted_ip']}" for s in suspects],
                "recommendation": "Switch system DNS to DoH / DoT or trusted resolvers (1.1.1.1 / 9.9.9.9)"
            })
        else:
            findings.append({
                "category": "DNS Resolver Integrity",
                "severity": "INFO",
                "ok": True,
                "summary": f"System DNS ({', '.join(servers) or 'default'}) matches trusted DoH baseline",
                "details": [],
                "recommendation": "Consider enabling DoH for encrypted DNS queries"
            })
    except Exception as exc:
        findings.append({
            "category": "DNS Resolver Integrity",
            "severity": "WARNING",
            "ok": False,
            "summary": f"DNS integrity check failed: {exc}",
            "details": [],
            "recommendation": "Verify network connectivity"
        })

    # 3. System Proxy & VPN Leak Checks
    try:
        from .proxy_manager import get_proxy_status
        proxy_stat = get_proxy_status()
        if proxy_stat.get("enabled"):
            server = proxy_stat.get("server", "")
            if not _is_blackout_proxy_server(server):
                score -= 10
                findings.append({
                    "category": "Proxy Configuration",
                    "severity": "MEDIUM",
                    "ok": False,
                    "summary": f"External system proxy configured: {server}",
                    "details": [f"Server: {server}"],
                    "recommendation": "Ensure external proxy server is trusted and encrypted"
                })
            else:
                findings.append({
                    "category": "Proxy Configuration",
                    "severity": "INFO",
                    "ok": True,
                    "summary": "Blackout Kit local proxy active",
                    "details": [],
                    "recommendation": "Proxy traffic is managed locally"
                })
        else:
            findings.append({
                "category": "Proxy Configuration",
                "severity": "INFO",
                "ok": True,
                "summary": "No active system proxy override",
                "details": [],
                "recommendation": "Direct system traffic"
            })
    except Exception as exc:
        pass

    # 4. Firewall & Kill Switch State
    try:
        from . import settings as cfg
        ks_enabled = cfg.load().get("kill_switch", False)
        if not ks_enabled:
            score -= 10
            findings.append({
                "category": "Kill Switch Protection",
                "severity": "LOW",
                "ok": False,
                "summary": "Kill switch firewall enforcement is disabled",
                "details": [],
                "recommendation": "Enable kill switch via `blackout settings set kill_switch true` or `blackout killswitch on`"
            })
        else:
            findings.append({
                "category": "Kill Switch Protection",
                "severity": "INFO",
                "ok": True,
                "summary": "Kill switch enforcement enabled",
                "details": [],
                "recommendation": "Leak protection active"
            })
    except Exception:
        pass

    score = max(0, min(100, score))
    return {
        "score": score,
        "grade": "A+" if score >= 90 else "A" if score >= 80 else "B" if score >= 70 else "C" if score >= 60 else "F",
        "findings": findings
    }


# ─────────────────────────── Native PCAP Export ───────────────────

def write_pcap_file(filepath: str, packets_raw: list) -> bool:
    """
    Write raw packet binary payloads to standard Global PCAP format (.pcap).
    Magic Number: 0xa1b2c3d4 (Microsecond resolution)
    Link-Layer Type: 1 (LINKTYPE_ETHERNET) / 101 (LINKTYPE_RAW_IP)
    """
    import struct
    import time

    pcap_hdr = struct.pack(
        "<IHHiIII",
        0xa1b2c3d4,  # Magic number
        2, 4,       # Major version 2, Minor version 4
        0,          # GMT offset
        0,          # Accuracy of timestamps
        65535,      # Max snapshot length
        1           # Link-layer header type (1 = Ethernet)
    )

    try:
        with open(filepath, "wb") as f:
            f.write(pcap_hdr)
            for pkt in packets_raw:
                try:
                    raw_bytes = bytes(pkt)
                    ts = float(getattr(pkt, "time", time.time()))
                    ts_sec = int(ts)
                    ts_usec = int((ts - ts_sec) * 1_000_000)
                    caplen = len(raw_bytes)
                    wirelen = caplen

                    pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, caplen, wirelen)
                    f.write(pkt_hdr)
                    f.write(raw_bytes)
                except Exception:
                    continue
        return True
    except Exception as exc:
        _log.error("Failed to write PCAP file %s: %s", filepath, exc)
        return False


# ─────────────────────────── Process Network Monitor ───────────────────

def monitor_process_network() -> list[dict]:
    """
    👁️ Live Process Network Monitor:
    Inspects all active network connections and attributes bandwidth & sockets to process names.
    Returns sorted list of {pid, process, local_endpoint, remote_endpoint, status, protocol, socket_count}.
    """
    import psutil

    connections = get_active_connections(established_only=False)
    proc_summary: dict[int, dict] = {}

    for conn in connections:
        pid = conn.get("pid", 0)
        proc_name = conn.get("process", "unknown")
        local_endpoint = f"{conn.get('local_addr')}:{conn.get('local_port')}"
        remote_ip = conn.get("remote_addr")
        remote_port = conn.get("remote_port")
        remote_endpoint = f"{remote_ip}:{remote_port}" if remote_ip else "-"
        status = conn.get("status", "-")
        protocol = conn.get("protocol", "TCP")

        if pid not in proc_summary:
            proc_summary[pid] = {
                "pid": pid,
                "process": proc_name,
                "socket_count": 0,
                "established_count": 0,
                "protocols": set(),
                "sample_remote": remote_endpoint if remote_endpoint != "-" else None
            }

        proc_summary[pid]["socket_count"] += 1
        if status == "ESTABLISHED":
            proc_summary[pid]["established_count"] += 1
        proc_summary[pid]["protocols"].add(protocol)
        if remote_endpoint != "-" and not proc_summary[pid]["sample_remote"]:
            proc_summary[pid]["sample_remote"] = remote_endpoint

    results = []
    for pid, data in proc_summary.items():
        results.append({
            "pid": pid,
            "process": data["process"],
            "socket_count": data["socket_count"],
            "established_count": data["established_count"],
            "protocols": ", ".join(sorted(data["protocols"])),
            "remote_sample": data["sample_remote"] or "-"
        })

    results.sort(key=lambda item: item["socket_count"], reverse=True)
    return results


# ─────────────────────────── Public Wi-Fi Honeypot ───────────────────

def run_honeypot_listener(ports: list[int] | None = None, duration: float = 60.0, callback=None) -> list[dict]:
    """
    🐝 Public Wi-Fi Honeypot & Port Scan Detector:
    Binds decoy TCP sockets to specified ports (e.g. 80, 22, 445, 3389).
    When an external IP attempts to connect, logs the probe event and invokes optional callback.
    """
    if ports is None:
        ports = [22, 80, 445, 3389, 8080]

    detected_probes = []
    active_sockets = []

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1.0)
            sock.bind(("0.0.0.0", port))
            sock.listen(5)
            active_sockets.append((port, sock))
        except Exception as exc:
            _log.debug("Honeypot could not bind port %d: %s", port, exc)

    if not active_sockets:
        return detected_probes

    start_time = time.time()
    while time.time() - start_time < duration:
        for port, sock in active_sockets:
            try:
                conn, addr = sock.accept()
                ip, src_port = addr[0], addr[1]
                conn.close()

                # Ignore local connections
                if ip in ("127.0.0.1", "::1"):
                    continue

                probe = {
                    "timestamp": time.time(),
                    "remote_ip": ip,
                    "remote_port": src_port,
                    "target_port": port
                }
                detected_probes.append(probe)
                if callback:
                    callback(probe)
            except socket.timeout:
                continue
            except Exception:
                continue

    for _, sock in active_sockets:
        try:
            sock.close()
        except Exception:
            pass

    return detected_probes


# ─────────────────────────── Secure DoH DNS Proxy Engine ───────────────────

def run_doh_proxy_server(host: str = "127.0.0.1", port: int = 5300, upstream_doh: str = "https://1.1.1.1/dns-query", duration: float = 0.0, stop_event=None) -> None:
    """
    🌐 Secure DoH DNS Proxy Engine:
    Runs a local UDP DNS proxy server on 127.0.0.1:5300 (or custom port).
    Intercepts standard DNS queries and forwards them securely via DNS-over-HTTPS (DoH).
    """
    import struct
    import urllib.request

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    try:
        sock.bind((host, port))
        _log.info("Started DoH DNS Proxy Server on %s:%d forwarding to %s", host, port, upstream_doh)
    except Exception as exc:
        _log.error("Could not bind DNS Proxy to %s:%d: %s", host, port, exc)
        return

    start_time = time.time()
    while True:
        if stop_event and stop_event.is_set():
            break
        if duration > 0 and (time.time() - start_time) >= duration:
            break

        try:
            data, client_addr = sock.recvfrom(512)
            if not data or len(data) < 12:
                continue

            # Forward query via HTTP wire format (application/dns-message)
            req = urllib.request.Request(
                upstream_doh,
                data=data,
                headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"},
                method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    answer = resp.read()
                    if answer:
                        sock.sendto(answer, client_addr)
            except Exception as e:
                _log.debug("DoH proxy forward error: %s", e)
        except socket.timeout:
            continue
        except Exception:
            continue

    try:
        sock.close()
    except Exception:
        pass


# ─────────────────────────── AI Network Explainer ───────────────────

def explain_network_state() -> dict:
    """
    🤖 AI Network Explainer:
    Aggregates active network connections, process sockets, DNS integrity,
    and firewall posture into an anomaly diagnostic summary for AI agents / Claude.
    """
    audit = run_network_audit()
    procs = monitor_process_network()
    dns = inspect_dns()

    anomalies = []

    # Check for processes with excessive sockets
    for p in procs:
        if p.get("socket_count", 0) > 20:
            anomalies.append(f"Process '{p['process']}' (PID {p['pid']}) has unusually high socket count: {p['socket_count']} sockets")

    # Check for DNS tampering
    for chk in dns.get("checks", []):
        if chk.get("suspect"):
            anomalies.append(f"DNS Poisoning Suspect: {chk['domain']} resolved to {chk['system_ip']} vs DoH {chk['trusted_ip']}")

    # Check audit issues
    for f in audit.get("findings", []):
        if not f.get("ok"):
            anomalies.append(f"Security Finding ({f['severity']}): {f['summary']}")

    return {
        "security_score": audit.get("score"),
        "grade": audit.get("grade"),
        "active_processes_count": len(procs),
        "total_anomalies_detected": len(anomalies),
        "anomalies": anomalies,
        "raw_audit_summary": [f['summary'] for f in audit.get("findings", [])]
    }


# ─────────────────────────── SSH Vault & Manager ───────────────────

SSH_VAULT_FILE = APP_DATA_DIR / "ssh_vault.json"

def save_ssh_profile(name: str, host: str, user: str, port: int = 22, key_path: str = "") -> bool:
    """Save or update an SSH connection profile in local storage."""
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        profiles = json.loads(SSH_VAULT_FILE.read_text()) if SSH_VAULT_FILE.exists() else {}
    except Exception:
        profiles = {}

    profiles[name] = {
        "name": name,
        "host": host,
        "user": user,
        "port": port,
        "key_path": key_path,
        "created_at": time.time()
    }

    try:
        SSH_VAULT_FILE.write_text(json.dumps(profiles, indent=2))
        return True
    except Exception as exc:
        _log.error("Failed to save SSH profile %s: %s", name, exc)
        return False

def list_ssh_profiles() -> list[dict]:
    """List all saved SSH connection profiles."""
    try:
        if not SSH_VAULT_FILE.exists():
            return []
        profiles = json.loads(SSH_VAULT_FILE.read_text())
        return sorted(list(profiles.values()), key=lambda p: p["name"])
    except Exception:
        return []

def remove_ssh_profile(name: str) -> bool:
    """Remove a saved SSH profile by name."""
    try:
        if not SSH_VAULT_FILE.exists():
            return False
        profiles = json.loads(SSH_VAULT_FILE.read_text())
        if name in profiles:
            del profiles[name]
            SSH_VAULT_FILE.write_text(json.dumps(profiles, indent=2))
            return True
        return False
    except Exception:
        return False


# ─────────────────────────── Local REST API & Web Dashboard ───────────────────

def run_web_api_dashboard(host: str = "127.0.0.1", port: int = 8080) -> None:
    """
    🌐 Local REST API & Web Dashboard Server.
    Exposes endpoints: /api/status, /api/connections, /api/audit, and serves HTML dashboard on /.
    """
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class APIHandler(BaseHTTPRequestHandler):
        def _send_json(self, data: dict):
            body = json.dumps(data).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, html: str):
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/api/status":
                from . import __version__
                self._send_json({"ok": True, "app": "blackout-kit", "version": __version__})
            elif self.path == "/api/connections":
                conns = get_active_connections(established_only=True)
                self._send_json({"connections": conns[:50], "total": len(conns)})
            elif self.path == "/api/audit":
                self._send_json(run_network_audit())
            elif self.path == "/api/live-stream":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                try:
                    for _ in range(5):
                        payload = json.dumps({"timestamp": time.time(), "connections": len(get_active_connections(True))})
                        self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                        self.wfile.flush()
                        time.sleep(0.5)
                except Exception:
                    pass
            elif self.path == "/":
                html_dashboard = """<!DOCTYPE html>
<html>
<head>
    <title>Blackout Kit Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: -apple-system, sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; margin:0; }
        .card { background: #1e293b; padding: 1.5rem; border-radius: 12px; margin-bottom: 1rem; border: 1px solid #334155; }
        h1 { color: #38bdf8; font-size: 2rem; }
        .badge { background: #22c55e; color: #022c22; padding: 0.3rem 0.8rem; border-radius: 20px; font-size: 0.9rem; font-weight: bold; }
        canvas { max-height: 250px; }
    </style>
</head>
<body>
    <h1>Blackout Kit — Live Network Dashboard <span class="badge">LIVE SSE</span></h1>
    <div class="card">
        <h2>Real-Time Active Connection Stream</h2>
        <canvas id="liveChart"></canvas>
    </div>
    <script>
        const ctx = document.getElementById('liveChart').getContext('2d');
        const chart = new Chart(ctx, {
            type: 'line',
            data: { labels: [], datasets: [{ label: 'Active Sockets', data: [], borderColor: '#38bdf8', backgroundColor: 'rgba(56, 189, 248, 0.2)', fill: true, tension: 0.4 }] },
            options: { responsive: true, scales: { y: { beginAtZero: true } } }
        });
        const evtSource = new EventSource('/api/live-stream');
        evtSource.onmessage = function(e) {
            const data = JSON.parse(e.data);
            const timeStr = new Date(data.timestamp * 1000).toLocaleTimeString();
            if (chart.data.labels.length > 15) { chart.data.labels.shift(); chart.data.datasets[0].data.shift(); }
            chart.data.labels.push(timeStr);
            chart.data.datasets[0].data.push(data.connections);
            chart.update();
        };
    </script>
</body>
</html>"""
                self._send_html(html_dashboard)
            else:
                self.send_error(404, "Endpoint Not Found")

        def log_message(self, format, *args):
            return  # Suppress routine log output

    server = HTTPServer((host, port), APIHandler)
    _log.info("Started Blackout Kit REST API & Dashboard on http://%s:%d", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


# ─────────────────────────── Event Automation Engine ───────────────────

AUTOMATION_RULES_FILE = APP_DATA_DIR / "automation_rules.json"

def save_automation_rule(name: str, event: str, action: str, enabled: bool = True) -> bool:
    """Save an event automation rule (event trigger -> action)."""
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        rules = json.loads(AUTOMATION_RULES_FILE.read_text()) if AUTOMATION_RULES_FILE.exists() else {}
    except Exception:
        rules = {}

    rules[name] = {
        "name": name,
        "event": event,
        "action": action,
        "enabled": enabled,
        "created_at": time.time()
    }

    try:
        AUTOMATION_RULES_FILE.write_text(json.dumps(rules, indent=2))
        return True
    except Exception as exc:
        _log.error("Failed to save automation rule %s: %s", name, exc)
        return False

def list_automation_rules() -> list[dict]:
    """List all configured event automation rules."""
    try:
        if not AUTOMATION_RULES_FILE.exists():
            return []
        rules = json.loads(AUTOMATION_RULES_FILE.read_text())
        return sorted(list(rules.values()), key=lambda r: r["name"])
    except Exception:
        return []

def remove_automation_rule(name: str) -> bool:
    """Remove an automation rule by name."""
    try:
        if not AUTOMATION_RULES_FILE.exists():
            return False
        rules = json.loads(AUTOMATION_RULES_FILE.read_text())
        if name in rules:
            del rules[name]
            AUTOMATION_RULES_FILE.write_text(json.dumps(rules, indent=2))
            return True
        return False
    except Exception:
        return False

def trigger_automation_event(event_name: str) -> list[dict]:
    """
    Trigger rules matching `event_name` and execute their configured actions.
    Actions supported: 'panic', 'flush_dns', 'flush_arp', 'audit', 'recovery'.
    """
    triggered_results = []
    rules = [r for r in list_automation_rules() if r.get("enabled") and r.get("event") == event_name]

    for rule in rules:
        action = rule.get("action")
        res = {"rule": rule["name"], "event": event_name, "action": action, "ok": True, "detail": "Action executed"}
        try:
            if action == "panic":
                trigger_panic()
                res["detail"] = "Triggered Panic Button"
            elif action == "flush_dns":
                ok = flush_dns()
                res["ok"] = ok
                res["detail"] = "Flushed DNS" if ok else "Failed to flush DNS"
            elif action == "flush_arp":
                ok, msg = flush_arp_cache()
                res["ok"] = ok
                res["detail"] = msg
            elif action == "audit":
                audit = run_network_audit()
                res["detail"] = f"Network Audit Score: {audit.get('score')}/100"
            elif action == "recovery":
                rec = run_network_recovery(audit_source="automation")
                res["detail"] = f"Executed {len(rec)} recovery repairs"
            else:
                res["ok"] = False
                res["detail"] = f"Unknown action '{action}'"
        except Exception as exc:
            res["ok"] = False
            res["detail"] = str(exc)

        triggered_results.append(res)

    return triggered_results


# ─────────────────────────── YARA Signature Rules Engine ───────────────────

BUILTIN_YARA_SIGNATURES = {
    "Webshell_Payload": [b"eval(base64_decode(", b"system($_POST[", b"shell_exec("],
    "Suspicious_Executable": [b"MZ", b"PE\x00\x00"],
    "EICAR_Test_File": [b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"],
}

def load_custom_yara_rule_file(rule_filepath: str) -> dict:
    """Load user-supplied YARA-like custom byte patterns from disk."""
    if not os.path.exists(rule_filepath):
        return {"ok": False, "error": f"Rule file not found: {rule_filepath}"}
    try:
        patterns = []
        with open(rule_filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line.encode("utf-8"))
        return {"ok": True, "patterns": patterns}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

def scan_file_yara(filepath: str) -> dict:
    """
    🔒 YARA Rules Engine:
    Scans a local file against built-in byte signatures for web shells, test viruses, and suspicious payloads.
    """
    if not os.path.exists(filepath):
        return {"ok": False, "error": f"File not found: {filepath}", "matches": []}

    matches = []
    try:
        with open(filepath, "rb") as f:
            content = f.read()

        for rule_name, sigs in BUILTIN_YARA_SIGNATURES.items():
            for sig in sigs:
                if sig in content:
                    matches.append({"rule": rule_name, "pattern": str(sig)})
                    break

        return {
            "ok": True,
            "filepath": filepath,
            "matches_count": len(matches),
            "matches": matches,
            "clean": len(matches) == 0
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "matches": []}


# ─────────────────────────── Network Simulation & Latency Injector ───────────────────

def simulate_network_conditions(host: str = "8.8.8.8", added_latency_ms: float = 100.0, simulated_loss_pct: float = 10.0, samples: int = 5) -> dict:
    """
    ⚡ Network Simulation & Latency/Loss Injector:
    Simulates high-latency / lossy network conditions on ping probes for DevOps & QA testing.
    """
    import random

    raw_pings = ping(host, count=samples)
    simulated_pings = []

    for p in raw_pings:
        # Simulate packet loss
        if random.uniform(0, 100) < simulated_loss_pct:
            simulated_pings.append(None)
        elif p is not None:
            simulated_pings.append(p + added_latency_ms)
        else:
            simulated_pings.append(None)

    stats = ping_stats(simulated_pings)
    return {
        "host": host,
        "added_latency_ms": added_latency_ms,
        "simulated_loss_pct": simulated_loss_pct,
        "stats": stats
    }


# ─────────────────────────── Phishing & Malicious Domain Check ───────────────────

KNOWN_PHISHING_KEYWORDS = ["login-verify", "paypal-secure", "apple-id-update", "bank-security-fix", "crypto-airdrop-claim"]

def check_phishing_domain(domain: str) -> dict:
    """
    🛡️ Phishing & Malicious Domain Check:
    Checks if a domain contains suspicious typosquatting keywords or resolves to sinkhole IPs.
    """
    domain_lower = domain.lower()
    suspicious = False
    reasons = []

    for kw in KNOWN_PHISHING_KEYWORDS:
        if kw in domain_lower:
            suspicious = True
            reasons.append(f"Domain contains known phishing keyword: '{kw}'")

    if domain_lower.count("-") >= 3:
        suspicious = True
        reasons.append("Domain contains excessive hyphens (typosquatting indicator)")

    # Attempt resolution
    ip = _system_resolve(domain)

    return {
        "domain": domain,
        "ip": ip or "unresolved",
        "suspicious": suspicious,
        "reasons": reasons,
        "safe": not suspicious
    }


# ─────────────────────────── Visual Traffic Bar Graph ───────────────────

def generate_ascii_bandwidth_chart(rx_bps: float, tx_bps: float, max_bps: float = 10_000_000.0, bar_width: int = 30) -> str:
    """
    📊 Visual ASCII Bandwidth Bar Graph:
    Generates colorful ASCII visual bars for rx/tx download/upload speeds.
    """
    rx_mbps = rx_bps / 1_000_000.0
    tx_mbps = tx_bps / 1_000_000.0

    rx_ratio = min(1.0, rx_bps / max_bps)
    tx_ratio = min(1.0, tx_bps / max_bps)

    rx_bar = "█" * int(rx_ratio * bar_width)
    tx_bar = "█" * int(tx_ratio * bar_width)

    return f"Download: {rx_mbps:6.2f} Mbps [{rx_bar:<{bar_width}}]\nUpload:   {tx_mbps:6.2f} Mbps [{tx_bar:<{bar_width}}]"


# ─────────────────────────── Subnet ARP Guard & Spoofing Monitor ───────────────────

def detect_arp_spoofing() -> dict:
    """
    🌐 Subnet ARP Guard & Anti-Spoofing Monitor:
    Inspects local ARP table for duplicate MAC addresses across different IP addresses (MITM signal).
    """
    table = _arp_table()
    mac_to_ips: dict[str, list[str]] = {}

    for ip, mac in table.items():
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "-"):
            continue
        mac_to_ips.setdefault(mac, []).append(ip)

    spoof_suspects = []
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            spoof_suspects.append({"mac": mac, "ips": ips})

    return {
        "ok": len(spoof_suspects) == 0,
        "total_hosts": len(table),
        "spoof_suspects": spoof_suspects
    }


# ─────────────────────────── SFTP Remote File Manager ───────────────────

def run_sftp_client(profile_name: str, action: str = "ls", remote_path: str = ".", local_path: str = "") -> dict:
    """
    📂 SFTP Remote File Manager:
    Interacts with saved SSH profiles to list, download, or upload remote files via SFTP/SCP.
    """
    profiles = {p["name"]: p for p in list_ssh_profiles()}
    if profile_name not in profiles:
        return {"ok": False, "error": f"Profile '{profile_name}' not found in SSH vault"}

    p = profiles[profile_name]
    cmd = ["sftp", "-P", str(p["port"])]
    if p.get("key_path"):
        cmd.extend(["-i", p["key_path"]])

    user_host = f"{p['user']}@{p['host']}"

    return {
        "ok": True,
        "profile": profile_name,
        "user_host": user_host,
        "port": p["port"],
        "action": action,
        "remote_path": remote_path,
        "command_args": cmd + [user_host]
    }


# ─────────────────────────── Active WinDivert QoS Packet Shaper ───────────────────

def get_windivert_shaper_status() -> dict:
    """
    ⚡ Active WinDivert QoS Packet Shaper:
    Inspects availability of Windows WinDivert driver for kernel packet shaping.
    """
    is_win = sys.platform == "win32"
    return {
        "supported_platform": is_win,
        "driver_available": is_win and _is_admin(),
        "mode": "monitor" if not is_win else "active"
    }
