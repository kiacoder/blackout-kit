"""
Blackout Kit - Network toolkit & diagnostics.
DNS flush, speed test, MTU optimizer, adapter info, ping, traceroute, and auto-fix.
"""
import concurrent.futures
import ctypes
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
    """
    Run multiple admin commands in ONE elevated PowerShell session (ONE UAC prompt).
    """
    blocks = []
    for cmd in commands:
        blocks.append(
            f"$p = Start-Process -FilePath '{cmd[0]}' "
            f"-ArgumentList '{subprocess.list2cmdline(cmd[1:])}' "
            f"-NoNewWindow -Wait -PassThru"
        )
    ps_script = "& { " + "; ".join(blocks) + " }"
    handle, pid = elevate.launch_elevated(
        "powershell.exe",
        ["-NoProfile", "-Command", ps_script],
    )
    if handle is None:
        return False
    ctypes.windll.kernel32.WaitForSingleObject(handle, timeout_ms)
    ctypes.windll.kernel32.CloseHandle(handle)
    return True

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
        if not _run_elevated(["cmd.exe", "/c", f"echo Auto-elevate placeholder"]):
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


# ─────────────────────────── Auto-fix ────────────────────────────

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
    """
    Run common Windows network repair commands.
    Returns list of completed steps.
    Auto-elevates via a single UAC prompt if not admin.
    """
    steps = []
    commands = [
        (["ipconfig", "/flushdns"],                              "Flush DNS cache"),
        (["netsh", "winsock", "reset"],                          "Reset Winsock"),
        (["netsh", "int", "ip", "reset"],                        "Reset TCP/IP stack"),
        (["netsh", "int", "tcp", "set", "global", "autotuninglevel=normal"], "Reset TCP autotuning"),
        (["ipconfig", "/release"],                               "Release IP address"),
        (["ipconfig", "/renew"],                                 "Renew IP address"),
    ]

    if not _is_admin():
        _log.info("Network fix requires admin — requesting elevation via UAC…")
        if _run_elevated_multi([c for c, _ in commands]):
            for _, label in commands:
                steps.append(f"[success]✓[/success] {label}")
        else:
            steps.append("[warning]⚠ UAC denied — cannot apply fixes.[/warning]")
        return steps

    for cmd, label in commands:
        try:
            subprocess.run(cmd, capture_output=True, timeout=15, check=False)
            steps.append(f"[success]✓[/success] {label}")
        except Exception as e:
            steps.append(f"[warning]⚠[/warning] {label} — {e}")
    return steps
