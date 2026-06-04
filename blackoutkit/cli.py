"""
Blackout Kit - Main CLI.
All user-facing commands live here.
"""
import argparse
import asyncio
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    Progress, SpinnerColumn, BarColumn,
    TextColumn, TimeElapsedColumn, TaskProgressColumn,
)
from rich.table import Table
from rich.live import Live
from rich.columns import Columns
from rich import box

from . import __version__
from .theme import console, print_banner, make_table, latency_color, engine_badge, BLACKOUT_THEME
from . import settings as cfg
from . import daemon
from .engines.sni     import SNIEngine
from .engines.xray    import XRayEngine
from .engines.gdpi    import GoodbyeDPIEngine
from .engines.psiphon import PsiphonEngine
from .proxy_manager   import set_system_proxy, clear_system_proxy, get_proxy_status
from .scanner.ip_scanner  import generate_cloudflare_ips, scan_ips, check_ip, CLOUDFLARE_RANGES
from .scanner.proxy_tester import test_direct, test_http_proxy, test_tcp_port, full_connectivity_report
from .config.manager  import (
    load_configs, save_configs, add_config, remove_config,
    parse_v2ray_uri, import_and_merge,
)
from . import tools as net_tools
from . import doctor as doc
from . import updater
from .help_text import get_help
from .engines.warp      import WARPEngine
from .engines.tun       import TUNEngine
from .engines.tor       import TorEngine
from .engines.mhrv      import MhrvEngine
from .engines.ikev2     import IKEv2Engine
from .engines.wireguard import WireGuardEngine
from .engines.openvpn   import OpenVPNEngine
from .engines.softether  import SoftEtherEngine
from .engines.neighbor   import NeighborShareEngine, NeighborConnectEngine
from .engines.appsscript import AppsScriptEngine
from . import security as sec
from . import country_profiles as cp

# ──────────────────────────── Engine map ─────────────────────────

ENGINES = {
    # Core bypass engines
    "sni":          (SNIEngine, XRayEngine),
    "gdpi":         (GoodbyeDPIEngine,),
    "psiphon":      (PsiphonEngine,),
    "warp":         (WARPEngine,),
    "tun":          (TUNEngine,),
    "tor":          (TorEngine,),
    "mhrv":         (MhrvEngine,),
    # VPN protocol engines (require config in settings)
    "ikev2":        (IKEv2Engine,),
    "wireguard":    (WireGuardEngine,),
    "openvpn":      (OpenVPNEngine,),
    "softether":    (SoftEtherEngine,),
    # Domain fronting — no binary needed, pure Python
    "appsscript":   (AppsScriptEngine,),
}

ALL_ENGINE_CHOICES = list(ENGINES.keys()) + ["auto"]


def _start_engine_stack(name: str) -> list:
    """Instantiate and start all engines in a stack. Returns running list."""
    classes = ENGINES.get(name, ())
    running = []
    for cls in classes:
        eng = cls()
        if eng.start():
            running.append(eng)
        else:
            console.print(f"  [warning]⚠ {eng.name} binary not found in bins/[/warning]")
    return running


# ──────────────────────────── Country profile helper ─────────────

def _get_active_profile():
    """Return CountryProfile from settings pin or auto-detect from ISP (4s timeout)."""
    from .network_switcher import get_isp_info
    code = cfg.load().get("country", "")
    if code:
        return cp.get_profile(code)
    return cp.detect_country(get_isp_info(timeout=4.0))


# ──────────────────────────── Commands ───────────────────────────

def cmd_country(args):
    """Show, set, or reset the active country profile."""
    subcmd = getattr(args, "country_command", None)

    if subcmd == "set":
        code = args.code.upper()
        profile = cp.get_profile(code)
        if not profile:
            console.print(
                f"[error]Unknown country code: {code}[/error]  "
                "Valid codes: IR, US, GB, CN, IQ"
            )
            return
        cfg.set_value("country", code)
        console.print(f"[success]✓ Country pinned to:[/success] [bold]{profile.name}[/bold] ({code})")
        console.print(f"  [muted]Run [bold]blackout country[/bold] to see the full profile.[/muted]")
        return

    if subcmd == "reset":
        cfg.set_value("country", "")
        console.print("[success]✓ Country pin cleared.[/success]  Back to auto-detect from ISP.")
        return

    # ── No subcommand: detect + show panel ──
    pinned = cfg.load().get("country", "")
    with console.status("[bold]Detecting country...[/bold]", spinner="dots"):
        profile = _get_active_profile()

    if not profile:
        console.print(Panel(
            "  [warning]Could not detect country.[/warning]\n\n"
            "  [dim]Set manually: [bold]blackout country set IR[/bold][/dim]\n"
            "  [dim]Valid codes:  IR  US  GB  CN  IQ[/dim]",
            title="[bold]Country Profile[/bold]",
            border_style="yellow",
            width=56,
        ))
        return

    detect_label  = "pinned" if pinned else "auto-detected"
    level_upper   = profile.censorship_level.upper()
    engine_str    = " → ".join(profile.engine_order)
    dns_str       = " / ".join(label for label, _ in profile.bypass_dns)
    test_str      = "  ".join(profile.test_urls) if profile.test_urls else "(none)"

    console.print(Panel(
        f"  [muted]Country:[/muted]    [bold]{profile.name}[/bold]  ({detect_label})\n"
        f"  [muted]Code:[/muted]       {profile.code}\n"
        f"  [muted]Level:[/muted]      [bold]{level_upper}[/bold] censorship\n\n"
        f"  [muted]Engine order:[/muted]  {engine_str}\n"
        f"  [muted]Bypass DNS:[/muted]    {dns_str}\n"
        f"  [muted]Test URLs:[/muted]     {test_str}\n\n"
        f"  [dim]\"{profile.notes}\"[/dim]",
        title="[bold]Country Profile[/bold]",
        border_style="cyan",
        width=60,
    ))


def cmd_scan(args):
    s = cfg.load()
    do_ips = args.ips or not args.sni
    do_sni = args.sni or not args.ips

    console.print()

    if do_sni:
        _scan_fake_snis()

    if do_ips:
        count = getattr(args, "count", s["scan_ip_count"])
        _scan_cloudflare_ips(count, s["scan_concurrency"], s["scan_timeout"])


def _scan_fake_snis():
    sni_file = Path(__file__).parent.parent / "data" / "fake_snis.txt"
    if not sni_file.exists():
        console.print("[warning]data/fake_snis.txt not found[/warning]")
        return

    domains = [
        d.strip() for d in sni_file.read_text().splitlines()
        if d.strip() and not d.startswith("#")
    ]

    table = make_table(
        "Fake SNI Domains",
        [("Domain", "cyan"), ("Resolves?", ""), ("Notes", "dim")],
        [],
    )

    import socket as _sock
    for domain in domains:
        try:
            _sock.setdefaulttimeout(3)
            _sock.getaddrinfo(domain, 443)
            table.add_row(domain, "[success]✓ Yes[/success]", "Safe to use")
        except Exception:
            table.add_row(domain, "[error]✗ No[/error]", "DNS blocked")

    console.print(table)
    console.print()


def _scan_cloudflare_ips(count: int, concurrency: int, timeout: float):
    console.print(f"[info]Generating {count} Cloudflare IPs to scan...[/info]")
    ips = generate_cloudflare_ips(count)

    scanned = {"done": 0}

    with Progress(
        SpinnerColumn(style="bold red"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40, style="red", complete_style="green"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(f"Scanning {len(ips)} IPs on :443 ...", total=len(ips))

        def on_done():
            scanned["done"] += 1
            progress.advance(task)

        results = asyncio.run(
            scan_ips(ips, concurrency=concurrency, timeout=timeout, progress_callback=on_done)
        )

    if not results:
        console.print("[error]No reachable Cloudflare IPs found. Your internet may be fully blocked.[/error]")
        return

    table = make_table(
        f"Reachable Cloudflare IPs  ({len(results)} / {len(ips)} responded)",
        [("IP Address", "cyan"), ("Latency", ""), ("Quality", "")],
        [],
    )
    for ip, ms in results[:20]:
        quality = "⚡ Excellent" if ms < 50 else ("✓ Good" if ms < 150 else "~ Slow")
        table.add_row(ip, latency_color(ms), quality)

    console.print(table)

    best_ip = results[0][0]
    console.print(
        f"\n[success]Best IP:[/success] [bold]{best_ip}[/bold]  "
        f"({results[0][1]:.0f}ms)\n"
        f"Apply it: [bold]blackout settings set sni_connect_ip {best_ip}[/bold]"
    )


def cmd_test(args):
    configs = load_configs()
    if not configs:
        console.print("[warning]No configs in data/configs.txt[/warning]")
        console.print("Add one: [bold]blackout config add <uri>[/bold]")
        console.print("Or import: [bold]blackout config import <url>[/bold]")
        return

    sni_ok  = sum(1 for c in configs if c.is_sni_compatible())
    direct  = len(configs) - sni_ok

    console.print(
        f"\n[info]Loaded {len(configs)} configs[/info]  "
        f"([success]{sni_ok} SNI-compatible[/success]  "
        f"[muted]{direct} direct[/muted])\n"
    )

    table = make_table(
        "Config List",
        [("#", "dim"), ("Proto", "cyan"), ("SNI Domain", "yellow"),
         ("Type", ""), ("Name", "white")],
        [],
    )
    for i, c in enumerate(configs, 1):
        ctype = "[success]SNI spoofer[/success]" if c.is_sni_compatible() else "[muted]direct[/muted]"
        table.add_row(str(i), c.protocol, c.sni or "-", ctype, c.name or "-")

    console.print(table)


def cmd_start(args):
    engine_name = args.engine if args.engine != "auto" else "sni"
    background  = getattr(args, "background", False)

    if background:
        try:
            pid = daemon.start(engine_name)
            console.print(Panel(
                f"[success]Engine:[/success]  [bold]{engine_name}[/bold]\n"
                f"[success]PID:[/success]     [bold]{pid}[/bold]\n"
                f"[success]Log:[/success]     [dim]{daemon.LOG_FILE}[/dim]\n\n"
                f"[muted]Run [bold]blackout status[/bold] to monitor.[/muted]\n"
                f"[muted]Run [bold]blackout stop[/bold] to stop.[/muted]",
                title="[bold green]✓ Blackout Kit — Background[/bold green]",
                border_style="green",
            ))
        except RuntimeError as e:
            console.print(f"[error]{e}[/error]")
        return

    # ── Foreground mode ──
    s = cfg.load()
    console.print(f"\n[info]Starting engine stack: [bold]{engine_name}[/bold][/info]")
    engines = _start_engine_stack(engine_name)

    if not engines:
        console.print("[error]No engines could start. Make sure binaries are in bins/.[/error]")
        return

    for eng in engines:
        console.print(f"  [success]✓ {eng.name}[/success] running (PID {eng.pid})")

    if s.get("auto_set_proxy"):
        if set_system_proxy(s["proxy_host"], s["proxy_port"]):
            console.print(f"  [success]✓ System proxy set[/success] → {s['proxy_host']}:{s['proxy_port']}")

    console.print("\n[muted]Press Ctrl+C to stop.[/muted]\n")

    try:
        while all(e.is_running() for e in engines):
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        console.print("\n[warning]Stopping...[/warning]")
        for eng in engines:
            eng.stop()
        if s.get("auto_set_proxy"):
            clear_system_proxy()
        console.print("[success]Stopped. System proxy cleared.[/success]")


def cmd_stop(args):
    if daemon.stop():
        s = cfg.load()
        if s.get("auto_set_proxy"):
            clear_system_proxy()
        console.print("[success]✓ Daemon stopped. System proxy cleared.[/success]")
    else:
        console.print("[warning]No daemon is running.[/warning]")


def cmd_emergency(args):
    background = getattr(args, "background", False)

    if background:
        try:
            pid = daemon.start("emergency")
            console.print(Panel(
                "[bold red]🚨 EMERGENCY MODE — Background[/bold red]\n\n"
                f"[muted]Trying engines in order: {' → '.join(cfg.get('engine_order'))}[/muted]\n\n"
                f"[success]PID:[/success] [bold]{pid}[/bold]\n"
                f"[success]Log:[/success] [dim]{daemon.LOG_FILE}[/dim]",
                border_style="red",
            ))
        except RuntimeError as e:
            console.print(f"[error]{e}[/error]")
        return

    # ── Foreground emergency ──
    console.print(Panel(
        "[bold red]🚨 EMERGENCY MODE[/bold red]\n"
        "Trying all engines until one works.",
        border_style="red",
    ))

    s             = cfg.load()
    em_profile    = _get_active_profile()
    default_order = em_profile.engine_order if em_profile else ["sni", "gdpi", "psiphon"]
    order         = s.get("engine_order") or default_order
    active        = []

    for ename in order:
        console.print(f"\n[info]Trying [bold]{ename}[/bold]...[/info]")
        engines = _start_engine_stack(ename)
        if not engines:
            console.print(f"  [error]✗ {ename} — no binaries found[/error]")
            continue

        time.sleep(3)

        ok = all(e.is_running() for e in engines)
        if ok:
            console.print(f"  [success]✓ {ename} is running![/success]")
            active = engines
            break
        else:
            for eng in engines:
                eng.stop()
            console.print(f"  [error]✗ {ename} crashed[/error]")

    if not active:
        console.print("\n[error]All engines failed. Check bins/ folder.[/error]")
        return

    if s.get("auto_set_proxy"):
        if set_system_proxy(s["proxy_host"], s["proxy_port"]):
            console.print(f"[success]✓ System proxy set[/success] → {s['proxy_host']}:{s['proxy_port']}")

    console.print("\n[muted]Press Ctrl+C to stop.[/muted]")
    try:
        while all(e.is_running() for e in active):
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for eng in active:
            eng.stop()
        if s.get("auto_set_proxy"):
            clear_system_proxy()
        console.print("[success]Stopped.[/success]")


def cmd_status(args):
    s      = cfg.load()
    pid    = daemon.get_pid()
    state  = daemon.get_state()
    proxy  = get_proxy_status()

    console.print()

    # Daemon panel
    if pid:
        engine_name = state.get("engine", "unknown") if state else "unknown"
        started     = state.get("started", "-") if state else "-"
        daemon_info = (
            f"[success]● Running[/success]  (PID {pid})\n"
            f"  Engine:  [bold]{engine_name}[/bold]\n"
            f"  Started: {started}\n"
            f"  Log:     [dim]{daemon.LOG_FILE}[/dim]"
        )
    else:
        daemon_info = "[muted]○ Not running[/muted]"

    console.print(Panel(daemon_info, title="[bold]Daemon[/bold]", border_style="cyan", width=60))

    # System proxy panel
    if proxy["enabled"]:
        proxy_info = f"[success]● Active[/success]  →  {proxy['server']}"
    else:
        proxy_info = "[muted]○ Off[/muted]"
    console.print(Panel(proxy_info, title="[bold]System Proxy[/bold]", border_style="cyan", width=60))

    # Connectivity
    console.print("\n[muted]Running connectivity checks...[/muted]")
    report = full_connectivity_report(s["xray_http_port"], s["xray_socks_port"])

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column(style="dim", width=22)
    table.add_column()

    def ck(ok):
        return "[success]✓ Yes[/success]" if ok else "[error]✗ No[/error]"

    def lat(ms):
        return latency_color(ms) if ms else "[error]✗ unreachable[/error]"

    table.add_row("Direct internet",       ck(report["direct"]))
    table.add_row("HTTP proxy port",        ck(report["http_proxy_port_open"]))
    table.add_row("SOCKS proxy port",       ck(report["socks_proxy_port_open"]))
    table.add_row("HTTP proxy latency",     lat(report["http_proxy_latency"]))
    table.add_row("SOCKS5 proxy latency",   lat(report["socks_proxy_latency"]))

    console.print(Panel(table, title="[bold]Connectivity[/bold]", border_style="cyan"))

    # Security mode + stability panel
    mode    = sec.get_current_mode()
    ks_on   = s.get("kill_switch", False)
    ks_disp = "[red]● ON[/red]" if ks_on else "[muted]○ off[/muted]"

    # Stability stats for the active engine (if known)
    stability_text = ""
    if state:
        eng_name = state.get("engine", "")
        score    = sec.get_stability_score(eng_name)
        if score["avg_ms"] is not None:
            stability_text = (
                f"\n  [muted]Stability:[/muted]  "
                f"avg {score['avg_ms']:.0f}ms  "
                f"loss {score['loss_pct']:.0f}%  "
                f"trend [{score['trend']}]"
            )

    console.print(Panel(
        f"  [muted]Security mode:[/muted]  [bold]{mode.upper()}[/bold]\n"
        f"  [muted]Kill switch:[/muted]    {ks_disp}"
        f"{stability_text}\n\n"
        f"  [dim]Change mode: [bold]blackout mode speed|private|legend[/bold][/dim]",
        title="[bold]Security[/bold]", border_style="cyan",
    ))
    console.print()


def cmd_logs(args):
    lines = getattr(args, "lines", 50)
    content = daemon.read_logs(lines)
    console.print(Panel(
        f"[dim]{content}[/dim]",
        title=f"[bold]Daemon Logs[/bold]  [dim]{daemon.LOG_FILE}[/dim]",
        border_style="dim",
    ))


def cmd_config(args):
    if not hasattr(args, "config_command") or not args.config_command:
        console.print("[warning]Usage: blackout config [list | add <uri> | import <url> | remove <n>][/warning]")
        return

    if args.config_command == "list":
        configs = load_configs()
        if not configs:
            console.print("[warning]No configs saved. Use 'blackout config add' or 'blackout config import'.[/warning]")
            return
        table = make_table(
            f"Saved Configs  ({len(configs)})",
            [("#", "dim"), ("Protocol", "cyan"), ("SNI Domain", "yellow"),
             ("Compatible", ""), ("Name", "white")],
            [],
        )
        for i, c in enumerate(configs, 1):
            compat = "[success]✓ SNI[/success]" if c.is_sni_compatible() else "[dim]direct[/dim]"
            table.add_row(str(i), c.protocol, c.sni or "-", compat, c.name or "-")
        console.print(table)

    elif args.config_command == "add":
        try:
            c = add_config(args.uri)
            console.print(f"[success]✓ Added:[/success] {c.protocol}://{c.address}:{c.port}  [{c.name}]")
        except ValueError as e:
            console.print(f"[error]{e}[/error]")

    elif args.config_command == "remove":
        try:
            remove_config(args.index - 1)
            console.print(f"[success]✓ Removed config #{args.index}[/success]")
        except IndexError as e:
            console.print(f"[error]{e}[/error]")

    elif args.config_command == "import":
        console.print(f"[info]Importing from subscription URL...[/info]")
        try:
            added, total = import_and_merge(args.url)
            console.print(f"[success]✓ Imported {added} new configs. Total: {total}[/success]")
        except Exception as e:
            console.print(f"[error]Import failed: {e}[/error]")

    elif args.config_command == "encrypt":
        if sec.configs_are_obfuscated():
            console.print("[warning]Configs are already encrypted (configs.enc exists).[/warning]")
            return
        sec.obfuscate_configs()
        console.print("[success]✓ Configs encrypted → configs.enc[/success]")
        console.print("[muted]Original configs.txt has been securely wiped.[/muted]")
        console.print("[muted]To restore: [bold]blackout config decrypt[/bold][/muted]")

    elif args.config_command == "decrypt":
        if not sec.configs_are_obfuscated():
            console.print("[warning]No encrypted configs found (configs.enc missing).[/warning]")
            return
        if sec.deobfuscate_configs():
            console.print("[success]✓ Configs decrypted → configs.txt[/success]")
        else:
            console.print("[error]Decryption failed. File may be corrupted or from a different machine.[/error]")


def cmd_settings(args):
    s = cfg.load()

    if not hasattr(args, "settings_command") or not args.settings_command:
        _settings_list(s)
        return

    if args.settings_command == "list":
        _settings_list(s)

    elif args.settings_command == "get":
        if args.key not in cfg.DEFAULTS:
            console.print(f"[error]Unknown key: {args.key}[/error]")
            return
        console.print(f"  [bold]{args.key}[/bold] = [cyan]{s[args.key]}[/cyan]")
        console.print(f"  [muted]{cfg.describe(args.key)}[/muted]")

    elif args.settings_command == "set":
        try:
            # Try to cast to the same type as the default
            default_val = cfg.DEFAULTS[args.key]
            if isinstance(default_val, bool):
                value = args.value.lower() in ("1", "true", "yes", "on")
            elif isinstance(default_val, int):
                value = int(args.value)
            elif isinstance(default_val, float):
                value = float(args.value)
            elif isinstance(default_val, list):
                value = [v.strip() for v in args.value.split(",")]
            else:
                value = args.value
            cfg.set_value(args.key, value)
            console.print(f"[success]✓ {args.key} = {value}[/success]")
        except (KeyError, ValueError) as e:
            console.print(f"[error]{e}[/error]")

    elif args.settings_command == "reset":
        cfg.reset()
        console.print("[success]✓ All settings reset to defaults.[/success]")


def _settings_list(s: dict):
    table = make_table(
        "Settings",
        [("Key", "cyan"), ("Value", "bold white"), ("Description", "dim")],
        [],
    )
    for key, default in cfg.DEFAULTS.items():
        val = str(s.get(key, default))
        table.add_row(key, val, cfg.describe(key))
    console.print(table)


def cmd_tools(args):
    s = cfg.load()

    if not hasattr(args, "tools_command") or not args.tools_command:
        console.print(Panel(
            "[bold]Available tools:[/bold]\n\n"
            "  [cyan]ping <host>[/cyan]              — TCP ping test\n"
            "  [cyan]dns-bench[/cyan]                — Benchmark DNS servers\n"
            "  [cyan]dns-flush[/cyan]                — Flush DNS cache\n"
            "  [cyan]speedtest[/cyan]                — Download speed test\n"
            "  [cyan]mtu [host][/cyan]               — Detect path MTU\n"
            "  [cyan]adapters[/cyan]                 — List network adapters\n"
            "  [cyan]traceroute <host>[/cyan]        — Traceroute\n"
            "  [cyan]cert-check <host[:port]>[/cyan] — TLS certificate check\n"
            "  [cyan]netfix[/cyan]                   — Auto-fix common network problems\n",
            title="[bold]Network Toolkit[/bold]", border_style="cyan",
        ))
        return

    if args.tools_command == "ping":
        host = getattr(args, "host", "8.8.8.8")
        console.print(f"\n[info]Pinging {host} (4 times via TCP :80)...[/info]\n")
        times = net_tools.ping(host, 4)
        stats = net_tools.ping_stats(times)
        table = make_table(
            f"Ping — {host}",
            [("Packet", "dim"), ("Result", "")],
            [],
        )
        for i, t in enumerate(times, 1):
            table.add_row(f"#{i}", latency_color(t) if t else "[error]timeout[/error]")
        console.print(table)
        if stats["avg"] is not None:
            jitter_str = (f"  jitter=[bold]{stats['jitter']:.1f}ms[/bold]"
                          if stats["jitter"] is not None else "")
            console.print(
                f"\n  avg=[bold]{stats['avg']:.1f}ms[/bold]  "
                f"min={stats['min']:.1f}ms  max={stats['max']:.1f}ms"
                f"{jitter_str}  loss=[bold]{stats['loss_pct']:.0f}%[/bold]"
            )

    elif args.tools_command == "dns-bench":
        console.print("\n[info]Benchmarking DNS servers (3 queries each)...[/info]\n")
        with console.status("[bold]Testing...[/bold]", spinner="dots"):
            results = net_tools.benchmark_dns()
        table = make_table(
            "DNS Benchmark",
            [("Server", "cyan"), ("IP", "dim"), ("Avg Latency", "")],
            [],
        )
        for name, ip, ms in results:
            table.add_row(name, ip, latency_color(ms))
        console.print(table)
        if results:
            best = results[0]
            console.print(f"\n[success]Best DNS:[/success] {best[0]} — {best[1]}  ({best[2]:.0f}ms)")
            console.print(f"Set it: [bold]blackout settings set sni_fake_sni {best[1]}[/bold]")

    elif args.tools_command == "dns-flush":
        console.print("[info]Flushing DNS cache...[/info]")
        if net_tools.flush_dns():
            console.print("[success]✓ DNS cache flushed.[/success]")
        else:
            console.print("[error]Failed — try running as administrator.[/error]")

    elif args.tools_command == "speedtest":
        console.print("\n[info]Running speed test via Cloudflare (download + upload)...[/info]\n")
        with console.status("[bold]Testing...[/bold]", spinner="dots"):
            result = net_tools.simple_speed_test()
        lat         = result["latency_ms"]
        mbps        = result["download_mbps"]
        upload_mbps = result.get("upload_mbps")
        up_str = f"[bold]{'%.2f' % upload_mbps} Mbps[/bold]" if upload_mbps else "[dim]—[/dim]"
        console.print(Panel(
            f"  [muted]Latency:[/muted]   {latency_color(lat) if lat else '[error]timeout[/error]'}\n"
            f"  [muted]Download:[/muted]  [bold]{'%.2f' % mbps if mbps else '?'} Mbps[/bold]\n"
            f"  [muted]Upload:[/muted]    {up_str}\n"
            f"  [muted]Test:[/muted]      {result.get('test_size', '-')}",
            title="[bold]Speed Test — Cloudflare[/bold]",
            border_style="cyan",
        ))

    elif args.tools_command == "mtu":
        host = getattr(args, "host", "8.8.8.8")
        console.print(f"[info]Detecting MTU to {host}...[/info]")
        with console.status("[bold]Probing...[/bold]"):
            mtu = net_tools.detect_mtu(host)
        if mtu:
            console.print(f"[success]Detected MTU: {mtu}[/success]")
            console.print(f"Optimal is usually 1500. If lower, try: [bold]blackout tools netfix[/bold]")
        else:
            console.print("[warning]MTU detection requires Windows and admin privileges.[/warning]")

    elif args.tools_command == "adapters":
        adapters = net_tools.list_adapters()
        table = make_table(
            "Network Adapters",
            [("Adapter", "cyan"), ("Status", ""), ("IPv4", "white"), ("IPv6", "dim")],
            [],
        )
        for a in adapters:
            if a.get("ipv4") or a.get("ipv6"):
                raw_status = a.get("status", "Unknown")
                if raw_status == "Connected":
                    status_markup = "[green]● Connected[/green]"
                elif raw_status == "Disconnected":
                    status_markup = "[dim]○ Disconnected[/dim]"
                else:
                    status_markup = f"[dim]{raw_status}[/dim]"
                table.add_row(a["name"], status_markup, a.get("ipv4", "-"), a.get("ipv6", "-"))
        console.print(table)

    elif args.tools_command == "traceroute":
        host = getattr(args, "host", "8.8.8.8")
        console.print(f"\n[info]Traceroute to {host}...[/info]\n")
        with console.status("[bold]Tracing...[/bold]"):
            hops = net_tools.traceroute(host)
        for hop, line in hops:
            console.print(f"  [dim]{hop:>2}[/dim]  {line}")
        console.print()

    elif args.tools_command == "dns-set":
        presets = {
            # Global public DNS
            "cloudflare":  "1.1.1.1",
            "cloudflare2": "1.0.0.1",
            "google":      "8.8.8.8",
            "google2":     "8.8.4.4",
            "quad9":       "9.9.9.9",
            "opendns":     "208.67.222.222",
            "adguard":     "94.140.14.14",
            # Iranian bypass/filtered DNS
            "shecan":      "185.51.200.2",
            "shecan2":     "178.22.122.100",
            "electro":     "78.157.42.100",
            "electro2":    "78.157.42.101",
            "403":         "10.202.10.202",
            "begzar":      "185.55.226.26",
            # Chinese domestic DNS (trusted inside GFW)
            "alibaba":     "223.5.5.5",
            "tencent":     "119.29.29.29",
            "114dns":      "114.114.114.114",
        }
        dns_ip = presets.get(args.server.lower(), args.server)
        console.print(f"[info]Setting DNS to {dns_ip}...[/info]")
        ok = net_tools.set_dns(dns_ip)
        if ok:
            console.print(f"[success]✓ DNS set to {dns_ip}[/success]")
            console.print("[muted]Run 'blackout tools dns-flush' to apply immediately.[/muted]")
            # Country-aware tip
            dns_profile = _get_active_profile()
            if dns_profile:
                rec_dns = dns_profile.bypass_dns[0][1] if dns_profile.bypass_dns else None
                if rec_dns and dns_ip != rec_dns:
                    console.print(
                        f"  [dim]Tip for {dns_profile.name}: "
                        f"recommended DNS is {dns_profile.bypass_dns[0][0]} "
                        f"({rec_dns})[/dim]"
                    )
        else:
            console.print("[error]Failed — run as administrator.[/error]")

    elif args.tools_command == "cert-check":
        from . import cert_bypass as cb
        from . import security as sec

        raw = args.host
        if ":" in raw:
            parts = raw.rsplit(":", 1)
            try:
                host, port = parts[0], int(parts[1])
            except ValueError:
                console.print("[error]Invalid format — use: cert-check host[:port][/error]")
                return
        else:
            host, port = raw, 443

        # Handle --allow flag (mark as manually allowed for LEGEND mode)
        if getattr(args, "allow", False):
            cb.allow_host(host, port)
            console.print(
                f"[success]✓ {host}:{port} marked as manually allowed.[/success]  "
                "LEGEND mode will now permit this connection."
            )

        with console.status(f"[bold]Probing {host}:{port}...[/bold]", spinner="dots"):
            record = cb.check_host_cert(host, port, timeout=8.0)

        # ── Status line ───────────────────────────────────────────
        if record.cert_ok:
            status_line = "[success]✓ VALID[/success]"
        elif record.error and "Connection" in record.error:
            status_line = f"[warning]⚠ UNREACHABLE[/warning]  ({record.error})"
        else:
            status_line = f"[error]✗ INVALID[/error]  ({record.error})"

        # ── Expiry display ────────────────────────────────────────
        if record.expires:
            if record.days_left < 0:
                expiry_str = f"{record.expires}  [error](EXPIRED {abs(record.days_left)} days ago)[/error]"
            elif record.days_left < 14:
                expiry_str = f"{record.expires}  [warning]({record.days_left} days left — expiring soon!)[/warning]"
            else:
                expiry_str = f"{record.expires}  [dim]({record.days_left} days left)[/dim]"
        else:
            expiry_str = "[dim]Unknown[/dim]"

        self_signed_str = "[error]YES[/error]" if record.self_signed else "[success]No[/success]"

        # ── Mode policy table ────────────────────────────────────
        current_mode = sec.get_current_mode()
        policy_lines = []
        for m in ("speed", "private", "legend"):
            allow, warn = cb.should_allow_insecure(host, port, m)
            icon   = "✓" if allow else "✗"
            colour = "success" if allow else "error"
            marker = "  ◄ active" if m == current_mode else ""
            policy_lines.append(
                f"  [{colour}]{icon}[/{colour}]  {m.upper():<8}  allowInsecure = {'True' if allow else 'False'}{marker}"
            )

        console.print(Panel(
            f"  [muted]Host:[/muted]        [bold]{host}:{port}[/bold]\n"
            f"  [muted]Status:[/muted]      {status_line}\n"
            f"  [muted]Subject:[/muted]     [dim]{record.subject or 'N/A'}[/dim]\n"
            f"  [muted]Issuer:[/muted]      [dim]{record.issuer or 'N/A'}[/dim]\n"
            f"  [muted]Expires:[/muted]     {expiry_str}\n"
            f"  [muted]Self-signed:[/muted] {self_signed_str}\n\n"
            "[bold]Mode Policy (allowInsecure):[/bold]\n" +
            "\n".join(policy_lines) +
            (f"\n\n[dim]To allow in LEGEND mode: [bold]blackout tools cert-check {host} --allow[/bold][/dim]"
             if not record.cert_ok and not record.manually_allowed else ""),
            title="[bold]TLS Certificate[/bold]",
            border_style="cyan" if record.cert_ok else "yellow",
            width=64,
        ))

    elif args.tools_command == "hotspot":
        console.print("[info]Toggling Windows Mobile Hotspot...[/info]")
        result = net_tools.toggle_hotspot()
        console.print(result)

    elif args.tools_command == "share-vpn":
        console.print(Panel(
            "[bold]VPN Connection Sharing[/bold]\n\n"
            "This enables Windows Internet Connection Sharing (ICS)\n"
            "so other devices on your hotspot get the VPN too.\n\n"
            "[dim]Requires: admin rights + hotspot active[/dim]",
            border_style="yellow",
        ))
        result = net_tools.enable_ics()
        console.print(result)

    elif args.tools_command == "netfix":
        console.print(Panel(
            "[bold yellow]Running auto-fix. Admin rights recommended.[/bold yellow]\n"
            "[dim]This will reset Winsock, TCP/IP stack, and DNS cache.[/dim]",
            border_style="yellow",
        ))
        steps = net_tools.autofix_windows()
        for step in steps:
            console.print(f"  {step}")
        console.print("\n[success]Done. Restart may be needed for full effect.[/success]")


def cmd_mode(args):
    """Set or display the security mode (speed / private / legend)."""
    mode_name = getattr(args, "mode_name", None)

    if not mode_name:
        # Just display current mode and all options
        current = sec.get_current_mode()
        table = make_table(
            "Security Modes",
            [("Mode", "cyan"), ("Active", ""), ("Description", "dim")],
            [],
        )
        for name, info in sec.MODES.items():
            active = "[success]● YES[/success]" if name == current else "[muted]  —[/muted]"
            table.add_row(name.upper(), active, info["description"])
        console.print()
        console.print(table)
        console.print(
            f"\n[muted]Current mode: [bold]{current.upper()}[/bold]  "
            f"Change: [bold]blackout mode speed|private|legend[/bold][/muted]\n"
        )
        return

    try:
        sec.apply_mode(mode_name)
        console.print(f"\n[success]✓ Security mode set to:[/success] [bold]{mode_name.upper()}[/bold]")
        console.print(f"  [muted]{sec.mode_description(mode_name)}[/muted]")

        # Auto-enable kill switch in LEGEND mode
        if mode_name == "legend":
            s = cfg.load()
            if not s.get("kill_switch", False):
                console.print(
                    "\n[yellow]Tip:[/yellow] LEGEND mode works best with the kill switch enabled.\n"
                    "Run: [bold]blackout killswitch on[/bold]"
                )
    except ValueError as e:
        console.print(f"[error]{e}[/error]")
    console.print()


def cmd_killswitch(args):
    """Enable or disable the Windows Firewall kill switch."""
    action = getattr(args, "action", None)

    if not action:
        s = cfg.load()
        enabled = s.get("kill_switch", False)
        status = "[success]● ENABLED[/success]" if enabled else "[muted]○ Disabled[/muted]"
        console.print(Panel(
            f"Kill Switch: {status}\n\n"
            "[dim]When ON: if the proxy drops, ALL internet is blocked (no leaks).[/dim]\n"
            "[dim]When OFF: if the proxy drops, traffic falls back to direct (may be censored).[/dim]\n\n"
            "[muted]Commands: [bold]blackout killswitch on[/bold]  /  [bold]blackout killswitch off[/bold][/muted]",
            title="[bold]Kill Switch[/bold]", border_style="red",
        ))
        return

    if action == "on":
        console.print("[info]Enabling kill switch (Windows Firewall)...[/info]")
        ok = sec.enable_kill_switch()
        if ok:
            cfg.set_value("kill_switch", True)
            console.print("[success]✓ Kill switch ENABLED.[/success]  All traffic blocked unless proxy is up.")
        else:
            console.print("[error]Failed — run as administrator.[/error]")

    elif action == "off":
        console.print("[info]Disabling kill switch...[/info]")
        ok = sec.disable_kill_switch()
        if ok:
            cfg.set_value("kill_switch", False)
            console.print("[success]✓ Kill switch DISABLED.[/success]  Normal routing restored.")
        else:
            console.print("[error]Failed — try running as administrator.[/error]")


def cmd_neighbor(args):
    """Neighbor internet — share or connect via a nearby Blackout Kit device."""
    subcmd = getattr(args, "neighbor_command", None)

    if not subcmd or subcmd == "help":
        console.print(Panel(
            "[bold]Neighbor Internet[/bold] — connect via a nearby device that has internet.\n\n"
            "  [cyan]discover[/cyan]           — Scan LAN for nearby sharers (8s timeout)\n"
            "  [cyan]connect[/cyan]            — Auto-discover + route through a neighbor\n"
            "  [cyan]connect --host IP[/cyan]  — Connect to a specific neighbor by IP\n"
            "  [cyan]share[/cyan]              — Broadcast your proxy so others can find you\n\n"
            "[dim]HOW IT WORKS:\n"
            "  Sharer: Has internet + runs Blackout Kit → enables 'share' mode\n"
            "          Creates a hotspot → guests connect to it\n"
            "  Guest:  Joins sharer's hotspot → runs 'neighbor connect'\n"
            "          Traffic routes: Guest → [LAN] → Sharer → [SNI/VPN] → Internet[/dim]",
            title="[bold]Neighbor Internet[/bold]", border_style="cyan",
        ))
        return

    if subcmd == "discover":
        console.print("[info]Scanning LAN for nearby Blackout Kit devices (8 seconds)...[/info]")
        result = NeighborConnectEngine.discover(timeout=8.0)
        if result:
            host, port = result
            console.print(Panel(
                f"[success]✓ Found a sharer![/success]\n\n"
                f"  IP:    [bold]{host}[/bold]\n"
                f"  Port:  [bold]{port}[/bold]  (HTTP proxy)\n\n"
                f"Connect: [bold]blackout neighbor connect --host {host}[/bold]",
                title="[bold green]Neighbor Found[/bold green]", border_style="green",
            ))
        else:
            console.print("[warning]No sharers found on LAN. Ask your neighbor to run:[/warning]")
            console.print("  [bold]blackout neighbor share[/bold]")

    elif subcmd == "connect":
        host = getattr(args, "host", None)
        port = getattr(args, "port", 0)

        if not host:
            console.print("[info]Discovering nearby sharer (8s)...[/info]")
            result = NeighborConnectEngine.discover(timeout=8.0)
            if not result:
                console.print("[error]No sharer found. Try: blackout neighbor discover[/error]")
                return
            host, port = result
            console.print(f"[success]✓ Found sharer at {host}:{port}[/success]")

        port = port or 10809
        console.print(f"[info]Connecting to neighbor proxy at {host}:{port}...[/info]")

        engine = NeighborConnectEngine(peer_host=host, peer_port=port)
        if not engine.start():
            console.print(f"[error]Cannot reach {host}:{port} — is the neighbor's proxy running?[/error]")
            return

        # Set system proxy to point at the neighbor
        s = cfg.load()
        if s.get("auto_set_proxy"):
            set_system_proxy(host, port)
            console.print(f"[success]✓ System proxy → {host}:{port}[/success]")

        console.print(Panel(
            f"[success]Connected via neighbor[/success]\n\n"
            f"  Routing through: [bold]{host}:{port}[/bold]\n\n"
            "[dim]Your traffic: You → [LAN] → Neighbor → Internet[/dim]\n\n"
            "[muted]Press Ctrl+C to disconnect.[/muted]",
            title="[bold green]Neighbor Connected[/bold green]", border_style="green",
        ))

        try:
            while engine.is_running():
                time.sleep(2)
            console.print("[warning]⚠ Neighbor proxy went offline![/warning]")
        except KeyboardInterrupt:
            pass
        finally:
            engine.stop()
            if s.get("auto_set_proxy"):
                clear_system_proxy()
            console.print("[success]Disconnected.[/success]")

    elif subcmd == "share":
        s = cfg.load()
        port = s.get("neighbor_proxy_port", s.get("xray_http_port", 10809))

        # Get local LAN IP
        local_ip = _get_local_ip()

        console.print(Panel(
            f"[bold]Sharing proxy on LAN[/bold]\n\n"
            f"  Announcing port [bold]{port}[/bold] via UDP multicast\n"
            f"  Your LAN IP: [bold]{local_ip}[/bold]\n\n"
            "[yellow]IMPORTANT:[/yellow] You must have a bypass engine running first!\n"
            "[dim]Run:[/dim] [bold]blackout start -d[/bold] [dim](in another terminal)[/dim]\n\n"
            "[yellow]Also:[/yellow] Create a hotspot so neighbors can connect to your WiFi.\n"
            "[dim]Run:[/dim] [bold]blackout tools hotspot[/bold]\n\n"
            "[muted]Press Ctrl+C to stop sharing.[/muted]",
            title="[bold yellow]Neighbor Share Mode[/bold yellow]", border_style="yellow",
        ))

        engine = NeighborShareEngine(proxy_port=port)
        engine.start()

        try:
            while engine.is_running():
                time.sleep(2)
        except KeyboardInterrupt:
            pass
        finally:
            engine.stop()
            console.print("[success]Stopped sharing.[/success]")


def _get_local_ip() -> str:
    """Get the LAN IP of this machine."""
    try:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "unknown"


def cmd_help(args):
    topic = getattr(args, "topic", None)
    content = get_help(topic)
    console.print(Panel(content, title="[bold]Blackout Kit — Help[/bold]", border_style="cyan"))


def cmd_doctor(args):
    auto_fix = getattr(args, "fix", False)
    fix_av   = getattr(args, "fix_av", False)

    if fix_av:
        console.print("[info]Adding bins/ folder to Windows Defender exclusions...[/info]")
        ok = sec.add_defender_exclusion()
        if ok:
            console.print("[success]✓ Exclusion added! Defender will no longer flag binaries in bins/.[/success]")
        else:
            console.print("[error]Failed — run as administrator and try again.[/error]")
        return

    if auto_fix:
        console.print("[yellow]Running checks and auto-fixing where possible...[/yellow]")
    else:
        console.print("[info]Running diagnostic checks...[/info]")
    results = doc.run_all_checks(auto_fix=auto_fix)
    doc.print_report(results, auto_fixed=auto_fix)


def cmd_update(args):
    """Check for updates and optionally apply them."""
    force = getattr(args, "force", False)

    console.print(f"\n[info]Current version: {__version__}[/info]")
    console.print("[muted]Checking GitHub for updates...[/muted]")

    with console.status("[bold]Checking...[/bold]", spinner="dots"):
        release = updater.check_for_update()

    if not release:
        console.print(f"\n[success]✓ You are up to date! ({__version__})[/success]\n")
        return

    console.print(Panel(
        f"[bold yellow]New version available![/bold yellow]\n\n"
        f"  Current:  [muted]{__version__}[/muted]\n"
        f"  Latest:   [bold green]{release['version']}[/bold green]\n\n"
        f"[dim]{(release.get('body') or '')[:300]}{'...' if len(release.get('body') or '') > 300 else ''}[/dim]",
        title="[bold]Update Available[/bold]", border_style="yellow",
    ))

    if not force:
        console.print("\nRun [bold]blackout update --apply[/bold] to install the update.")
        return

    console.print("\n[info]Downloading and applying update...[/info]")
    with console.status("[bold]Updating...[/bold]", spinner="dots"):
        ok = updater.download_and_apply(release)

    if ok:
        console.print(f"[success]✓ Updated to {release['version']}! Restart blackout to use it.[/success]\n")
    else:
        console.print("[error]Update failed. Check your internet connection and try again.[/error]\n")


def cmd_preflight(args):
    """Run offline-first readiness check — are you ready for a blackout?"""
    console.print()
    console.print(Panel(
        "[bold]Pre-Blackout Readiness Check[/bold]\n"
        "[dim]Verifying that Blackout Kit can work with zero internet access.[/dim]",
        border_style="yellow",
    ))
    console.print()

    with console.status("[bold]Checking...[/bold]", spinner="dots"):
        results = updater.run_preflight()

    ready, crit_fails, total_fails = updater.preflight_summary(results)

    table = make_table(
        "Preflight Report",
        [("Check", "white"), ("Status", ""), ("Details", "dim")],
        [],
    )
    for r in results:
        if r.ok:
            status = "[success]✓ READY[/success]"
        elif r.critical:
            status = "[error]✗ CRITICAL[/error]"
        else:
            status = "[yellow]⚠ WARN[/yellow]"
        table.add_row(r.name, status, r.message)

    console.print(table)

    if ready:
        console.print(Panel(
            "[bold green]✓ READY FOR BLACKOUT![/bold green]\n\n"
            "All critical checks passed. When the blackout hits:\n"
            "  → [bold]blackout start -d[/bold]   (or 'blackout emergency -d' if SNI fails)\n\n"
            "[dim]Tip: Run 'blackout scan' periodically to keep the IP cache fresh.[/dim]",
            border_style="green",
        ))
    else:
        console.print(Panel(
            f"[bold red]✗ NOT READY  ({crit_fails} critical issue(s))[/bold red]\n\n"
            "Fix the CRITICAL items above before the blackout hits!\n\n"
            "Quick checklist:\n"
            "  1. Download binaries → [bold]blackout doctor[/bold] shows where\n"
            "  2. Add configs   → [bold]blackout config import <subscription-url>[/bold]\n"
            "  3. Scan IPs      → [bold]blackout scan[/bold]\n"
            "  4. Test it now   → [bold]blackout start[/bold]",
            border_style="red",
        ))
    console.print()


def cmd_network(args):
    """WiFi network switcher and ISP detection."""
    from . import network_switcher as ns

    subcmd = getattr(args, "network_command", None)

    if not subcmd:
        # ── Status panel ──
        with console.status("[bold]Detecting network info...[/bold]", spinner="dots"):
            ssid     = ns.get_current_ssid()
            signal   = ns.get_wifi_signal()
            isp_info = ns.get_isp_info()
            switchable = ns.get_switchable_networks()

        ssid_disp   = f"[bold]{ssid}[/bold]" if ssid else "[dim]Not connected[/dim]"
        isp_disp    = isp_info.isp_short if isp_info else "[dim]Unknown[/dim]"
        sw_count    = len(switchable)

        if signal is not None:
            bar = ns._signal_bar(signal)
            signal_disp = f"{bar}  {signal}%"
        else:
            signal_disp = "[dim]N/A (ethernet or no WiFi)[/dim]"

        sw_disp = (
            f"[success]{sw_count} available[/success]"
            if sw_count > 0
            else "[muted]None[/muted]"
        )

        # Country line
        net_profile = cp.detect_country(isp_info)
        if net_profile:
            country_disp = (
                f"[bold]{net_profile.name}[/bold]  "
                f"[dim][{net_profile.censorship_level.upper()} censorship][/dim]"
            )
        else:
            country_disp = "[dim]Unknown[/dim]"

        console.print(Panel(
            f"  [muted]SSID:[/muted]     {ssid_disp}\n"
            f"  [muted]ISP:[/muted]      [bold]{isp_disp}[/bold]\n"
            f"  [muted]Country:[/muted]  {country_disp}\n"
            f"  [muted]Signal:[/muted]   {signal_disp}\n"
            f"  [muted]Switchable networks:[/muted] {sw_disp}\n\n"
            f"  [dim]Run: [bold]blackout network scan[/bold][/dim]",
            title="[bold]Network Status[/bold]",
            border_style="cyan",
            width=60,
        ))
        return

    if subcmd == "scan":
        with console.status("[bold]Scanning WiFi networks...[/bold]", spinner="dots"):
            available = ns.list_available_networks()
            saved_set = set(ns.list_saved_profiles())

        for net in available:
            net.saved = net.ssid in saved_set

        available.sort(key=lambda n: n.signal, reverse=True)

        if not available:
            console.print("[warning]No WiFi networks found. Make sure you're on WiFi.[/warning]")
            return

        table = make_table(
            "Available WiFi Networks",
            [("SSID", "cyan"), ("Signal", ""), ("Auth", "dim"), ("Switchable", "")],
            [],
        )
        for net in available:
            bar = ns._signal_bar(net.signal, width=4)
            signal_str = f"{bar} {net.signal}%"
            sw_str = "[success]✓ YES[/success]" if net.saved else "[dim](no pass)[/dim]"
            table.add_row(net.ssid, signal_str, net.auth, sw_str)

        console.print(table)

    elif subcmd == "isp":
        with console.status("[bold]Looking up ISP...[/bold]", spinner="dots"):
            isp_info = ns.get_isp_info()

        if not isp_info:
            console.print("[error]Could not reach ISP lookup API. Check your internet connection.[/error]")
            return

        console.print(Panel(
            f"  [muted]ISP:[/muted]         [bold]{isp_info.isp}[/bold]\n"
            f"  [muted]Short name:[/muted]  [bold cyan]{isp_info.isp_short}[/bold cyan]\n"
            f"  [muted]ASN:[/muted]         [dim]{isp_info.asn or 'N/A'}[/dim]\n"
            f"  [muted]City:[/muted]        {isp_info.city or 'N/A'}\n"
            f"  [muted]Country:[/muted]     {isp_info.country or 'N/A'}",
            title="[bold]ISP Information[/bold]",
            border_style="cyan",
        ))

        # Country context panel
        isp_profile = cp.detect_country(isp_info)
        if isp_profile:
            best_engine = isp_profile.engine_order[0] if isp_profile.engine_order else "sni"
            console.print(Panel(
                f"  [dim]\"{isp_profile.notes}\"[/dim]\n"
                f"  [muted]Best engine:[/muted] [bold]{best_engine}[/bold]",
                title="[bold]Country Context[/bold]",
                border_style="dim",
                width=50,
            ))

    elif subcmd == "switch":
        ssid = args.ssid
        saved = ns.list_saved_profiles()

        if ssid not in saved:
            console.print(f"[error]No saved profile for '{ssid}'.[/error]")
            console.print("[muted]You can only switch to networks you've connected to before.[/muted]")
            if saved:
                console.print(f"[muted]Saved profiles: {', '.join(saved)}[/muted]")
            else:
                console.print("[muted]No saved profiles found.[/muted]")
            return

        console.print(f"\n[info]Switching to [bold]{ssid}[/bold]...[/info]")
        with console.status(f"[bold]Connecting to {ssid}...[/bold]", spinner="dots"):
            ok = ns.switch_to_network(ssid)

        if ok:
            console.print(Panel(
                f"[success]✓ Connected to [bold]{ssid}[/bold]![/success]\n\n"
                "[dim]ISP may have changed. Check it: [bold]blackout network isp[/bold][/dim]",
                border_style="green",
            ))
        else:
            console.print(
                f"[error]Failed to connect to '{ssid}'.[/error]\n"
                "[muted]Make sure the network is in range and your saved password is correct.[/muted]"
            )

    elif subcmd == "auto":
        current = ns.get_current_ssid()
        switchable = ns.get_switchable_networks()

        if not switchable:
            console.print(Panel(
                "[warning]No switchable networks found.[/warning]\n\n"
                "  Possible reasons:\n"
                "  [dim]• You're on ethernet (no WiFi in use)[/dim]\n"
                "  [dim]• No other saved networks are in range[/dim]\n"
                "  [dim]• All nearby networks require a new password[/dim]\n\n"
                "[dim]Run [bold]blackout network scan[/bold] to see all nearby networks.[/dim]",
                title="[bold]Auto-Switch[/bold]",
                border_style="yellow",
            ))
            return

        console.print(
            f"\n[info]Found [bold]{len(switchable)}[/bold] candidate network(s). "
            "Trying best signal first...[/info]\n"
        )
        for net in switchable:
            bar = ns._signal_bar(net.signal, width=4)
            console.print(f"  [dim]→[/dim] [bold]{net.ssid}[/bold]  {bar} {net.signal}%")
        console.print()

        with console.status("[bold]Auto-switching...[/bold]", spinner="dots"):
            new_ssid = ns.auto_switch(exclude_ssid=current)

        if new_ssid:
            console.print(Panel(
                f"[success]✓ Auto-switched to [bold]{new_ssid}[/bold]![/success]\n\n"
                "[dim]ISP may have changed. Check it: [bold]blackout network isp[/bold][/dim]",
                title="[bold green]Connected[/bold green]",
                border_style="green",
            ))
        else:
            console.print(
                "[error]Auto-switch failed — could not connect to any available network.[/error]\n"
                "[muted]Try manually: [bold]blackout network switch <ssid>[/bold][/muted]"
            )


def cmd_bins(args):
    """Manage engine binaries — show status, download missing, update all."""
    from . import downloader as dl
    from rich.panel import Panel as _Panel

    subcmd = getattr(args, "bins_command", None)

    # ── No subcommand: status table ───────────────────────────────
    if not subcmd:
        installed   = dl.check_installed()
        all_bins    = dl.list_available()
        auto_count  = sum(1 for b in all_bins if b.github_repo)
        inst_count  = sum(1 for k, v in installed.items() if v)

        table = make_table(
            f"Engine Binaries  ({inst_count}/{len(all_bins)} installed)",
            [("Binary", "cyan"), ("Status", ""), ("Auto?", "dim"), ("Description", "dim")],
            [],
        )
        for b in all_bins:
            is_inst = installed.get(b.key, False)
            status  = "[success]✓ Installed[/success]" if is_inst else (
                "[error]✗ Missing[/error]" if b.required else "[yellow]○ Optional[/yellow]"
            )
            auto    = "[green]✓ auto[/green]" if b.github_repo else "[dim]manual[/dim]"
            table.add_row(b.display_name, status, auto, b.description)

        console.print()
        console.print(table)

        missing_required = [b for b in all_bins if b.required and not installed.get(b.key)]
        missing_auto     = [b for b in all_bins if b.github_repo and not installed.get(b.key)]
        missing_manual   = [b for b in all_bins if not b.github_repo and not installed.get(b.key)]

        if missing_required:
            names = ", ".join(b.display_name for b in missing_required)
            console.print(f"\n[error]Required binaries missing: {names}[/error]")

        if missing_auto:
            console.print(
                f"\n[dim]{len(missing_auto)} binary/ies can be auto-downloaded:[/dim]  "
                "[bold]blackout bins download[/bold]"
            )
        if missing_manual:
            console.print(f"[dim]{len(missing_manual)} require manual download — run [bold]blackout bins download[/bold] for links.[/dim]")
        console.print()
        return

    # ── download ──────────────────────────────────────────────────
    if subcmd == "download":
        target_key = getattr(args, "binary", None)

        if target_key:
            # Download one specific binary
            info = dl.BIN_REGISTRY.get(target_key)
            if not info:
                valid = ", ".join(dl.BIN_REGISTRY.keys())
                console.print(f"[error]Unknown binary: '{target_key}'[/error]  Valid: {valid}")
                return

            if not info.github_repo:
                console.print(_Panel(
                    f"[yellow]{info.display_name}[/yellow] requires manual download.\n\n"
                    f"  [dim]{info.manual_note}[/dim]\n\n"
                    f"  Download from: [bold]{info.manual_url}[/bold]\n"
                    f"  Then place the .exe in: [bold]{dl.BINS_DIR}[/bold]",
                    title="[bold]Manual Download Required[/bold]",
                    border_style="yellow",
                ))
                return

            _download_single(dl, target_key, info)

        else:
            # Download ALL missing auto-downloadable binaries
            all_bins  = dl.list_available()
            installed = dl.check_installed()
            to_dl     = [b for b in all_bins if b.github_repo and not installed.get(b.key)]
            manual    = [b for b in all_bins if not b.github_repo and not installed.get(b.key)]

            if not to_dl and not manual:
                console.print("[success]✓ All binaries are already installed![/success]")
                return

            if to_dl:
                console.print(f"\n[info]Downloading {len(to_dl)} binary/ies...[/info]\n")
                for b in to_dl:
                    _download_single(dl, b.key, b)

            if manual:
                console.print()
                console.print(_Panel(
                    "[bold]The following require manual download:[/bold]\n\n" +
                    "\n".join(
                        f"  [yellow]{b.display_name}[/yellow]\n"
                        f"    {b.manual_note}\n"
                        f"    Download: [dim]{b.manual_url}[/dim]\n"
                        f"    Place in: [dim]{dl.BINS_DIR}[/dim]"
                        for b in manual
                    ),
                    title="[bold]Manual Downloads[/bold]",
                    border_style="yellow",
                ))

    # ── update ────────────────────────────────────────────────────
    elif subcmd == "update":
        installed = dl.check_installed()
        to_update = [
            b for b in dl.list_available()
            if b.github_repo and installed.get(b.key)
        ]

        if not to_update:
            console.print("[warning]No auto-downloadable binaries are currently installed.[/warning]")
            return

        console.print(f"\n[info]Re-downloading {len(to_update)} installed binary/ies to get latest versions...[/info]\n")
        for b in to_update:
            _download_single(dl, b.key, b, force=True)


def _download_single(dl, key: str, info, force: bool = False):
    """Download one binary with a Rich progress bar. Used by cmd_bins."""
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn,
        TextColumn, DownloadColumn, TransferSpeedColumn, TimeRemainingColumn,
    )

    label = f"Downloading [bold]{info.display_name}[/bold]..."
    console.print(f"  [dim]→[/dim] {info.display_name}  [dim]{info.github_repo}[/dim]")

    task_ref: dict = {"id": None, "progress": None}

    def _cb(done: int, total: int) -> None:
        p = task_ref["progress"]
        t = task_ref["id"]
        if p is None or t is None:
            return
        if total and p.tasks[t].total is None:
            p.update(t, total=total)
        p.update(t, completed=done)

    with Progress(
        SpinnerColumn(style="bold red"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=34, style="red", complete_style="green"),
        DownloadColumn(),
        TransferSpeedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=True,
    ) as progress:
        task_ref["progress"] = progress
        task_ref["id"] = progress.add_task(label, total=None)

        ok, msg = dl.download_binary(key, progress_callback=_cb)

    if ok:
        console.print(f"  [success]✓ {msg}[/success]")
    else:
        console.print(f"  [error]✗ {msg}[/error]")


def cmd_easteregg(args):
    console.print(Panel(
        "[bold yellow]🥚 OH WOW! YOU FOUND THE EASTER EGG! 🥚[/bold yellow]\n\n"
        "Congrats — you're officially the kind of person who reads docs\n"
        "or tries random commands for fun. Respect. 🫡\n\n"
        "[bold red]🖕[/bold red] to every firewall that ever got in your way.\n\n"
        "[dim]Now go tell everyone. Or don't. Your choice.[/dim]",
        title="[bold]SECRET COMMAND[/bold]",
        border_style="yellow",
    ))


def cmd_connect(args):
    """Smart connect — auto-preps and starts the best available engine."""
    engine_name = getattr(args, "engine", None) or "sni"
    background  = getattr(args, "background", False)
    iran_mode   = getattr(args, "iran", False)

    s = cfg.load()

    # Apply Iran bypass profile if requested
    if iran_mode:
        console.print("[info]Applying Iran bypass profile: Firefox fingerprint + private mode...[/info]")
        try:
            sec.apply_mode("private")
            cfg.set_value("xray_fingerprint", "firefox")
            s = cfg.load()
        except Exception:
            pass

    # Print country-aware hint
    connect_profile = _get_active_profile()
    if connect_profile:
        rec = connect_profile.engine_order[0] if connect_profile.engine_order else engine_name
        console.print(
            f"  [dim]Detected: {connect_profile.name} "
            f"({connect_profile.censorship_level}) — {rec} recommended[/dim]"
        )
        if connect_profile.code == "CN" and engine_name in ("sni",):
            console.print(
                "[yellow]Note:[/yellow] SNI spoofing is largely ineffective against "
                "China's Great Firewall (GFW blocks IPs + SNI).\n"
                "  Suggested engine: [bold]blackout connect --engine xray[/bold]"
            )

    # If SNI engine and no saved Cloudflare IP, do a quick 10-IP scan first
    if engine_name in ("sni", "auto") and not s.get("sni_connect_ip"):
        console.print("[yellow]No saved Cloudflare IP — running quick scan (10 IPs)...[/yellow]")
        ips = generate_cloudflare_ips(10)
        with Progress(
            SpinnerColumn(style="bold red"),
            TextColumn("[progress.description]{task.description}"),
            console=console, transient=True,
        ) as p:
            p.add_task("Scanning Cloudflare IPs...")
            results = asyncio.run(scan_ips(ips, concurrency=10, timeout=3.0))

        if results:
            best_ip = results[0][0]
            cfg.set_value("sni_connect_ip", best_ip)
            console.print(f"[success]✓ Best IP found: {best_ip} ({results[0][1]:.0f}ms)[/success]")
        else:
            console.print("[warning]No reachable Cloudflare IPs. Proceeding anyway...[/warning]")

    # Delegate to cmd_start with resolved engine
    class _FakeArgs:
        pass
    fake         = _FakeArgs()
    fake.engine  = engine_name if engine_name != "auto" else "sni"
    fake.background = background
    cmd_start(fake)


def cmd_fix(args):
    """Auto-fix common network issues — live Rich checklist with real-time results."""
    import subprocess as _sp

    def _run(cmd: list[str]) -> bool:
        try:
            _sp.run(cmd, capture_output=True, timeout=15, check=False)
            return True
        except Exception:
            return False

    fix_steps = [
        ("Flush DNS cache",     lambda: net_tools.flush_dns()),
        ("Reset Winsock",       lambda: _run(["netsh", "winsock", "reset"])),
        ("Reset TCP/IP stack",  lambda: _run(["netsh", "int", "ip", "reset"])),
        ("Reset TCP autotuning",lambda: _run(["netsh", "int", "tcp", "set", "global",
                                              "autotuninglevel=normal"])),
        ("Release IP address",  lambda: _run(["ipconfig", "/release"])),
        ("Renew IP address",    lambda: _run(["ipconfig", "/renew"])),
        ("Clear system proxy",  lambda: (clear_system_proxy(), True)[1]),
    ]

    results: list[tuple[str, str]] = []   # (step_name, status_markup)

    def _make_table():
        t = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan", padding=(0, 2))
        t.add_column("Step", style="white", width=28)
        t.add_column("Status", width=18)
        for name, status in results:
            t.add_row(name, status)
        for name, _ in fix_steps[len(results):]:
            t.add_row(f"[dim]{name}[/dim]", "[dim]—[/dim]")
        return t

    console.print()
    console.print(Panel(
        "[bold yellow]Auto-Fix Network Issues[/bold yellow]\n"
        "[dim]Resets DNS, Winsock, TCP/IP stack, and clears system proxy.[/dim]\n"
        "[dim]Run as Administrator for full effect.[/dim]",
        border_style="yellow",
    ))
    console.print()

    with Live(_make_table(), console=console, refresh_per_second=10) as live:
        for name, fn in fix_steps:
            results.append((name, "[yellow]Running...[/yellow]"))
            live.update(_make_table())
            try:
                ok = fn()
                results[-1] = (name, "[green]✓ Done[/green]" if ok else "[red]✗ Failed[/red]")
            except Exception:
                results[-1] = (name, "[red]✗ Error[/red]")
            live.update(_make_table())
            time.sleep(0.15)

    done = sum(1 for _, s in results if "✓" in s)
    console.print()
    console.print(f"[success]✓ {done}/{len(fix_steps)} steps completed.[/success]")
    console.print("[muted]A system restart may be needed for some changes to fully take effect.[/muted]")
    console.print()


# ──────────────────── Interactive Zero-Flag menu ─────────────────

def _make_fake_args(**kwargs):
    """Build a fake argparse Namespace for calling cmd_ functions from the menu."""
    class _Fake:
        pass
    obj = _Fake()
    for k, v in kwargs.items():
        setattr(obj, k, v)
    return obj


def _interactive_menu():
    """Display an interactive numbered menu when blackout is run with no arguments."""
    menu_items = [
        ("1", "🚀 Connect",   "Start bypass — smart auto-select"),
        ("2", "⚡ Emergency",  "Try all engines until one works"),
        ("3", "📊 Status",    "Check daemon + connection health"),
        ("4", "🔍 Scan",      "Scan Cloudflare IPs + SNI domains"),
        ("5", "🏥 Doctor",    "Self-diagnose and auto-repair"),
        ("6", "🔧 Fix",       "Auto-fix DNS / Winsock / TCP/IP"),
        ("7", "🌐 Tools",     "Network toolkit (ping, speedtest…)"),
        ("8", "⚙  Settings",  "View and change settings"),
        ("0", "❌ Exit",      ""),
    ]

    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    t.add_column("Num", style="bold cyan", width=4)
    t.add_column("Action", style="bold white", width=16)
    t.add_column("Description", style="dim")
    for num, action, desc in menu_items:
        t.add_row(f"[{num}]", action, desc)

    console.print(Panel(t, title="[bold]What do you want to do?[/bold]", border_style="cyan"))

    _EXIT = object()  # sentinel for "0" so we can distinguish exit from unknown input
    _dispatch = {
        "1": lambda: cmd_connect(_make_fake_args(engine=None, background=False, iran=False)),
        "2": lambda: cmd_emergency(_make_fake_args(background=False)),
        "3": lambda: cmd_status(_make_fake_args()),
        "4": lambda: cmd_scan(_make_fake_args(ips=False, sni=False, count=None)),
        "5": lambda: cmd_doctor(_make_fake_args(fix=False, fix_av=False)),
        "6": lambda: cmd_fix(_make_fake_args()),
        "7": lambda: cmd_tools(_make_fake_args(tools_command=None)),
        "8": lambda: cmd_settings(_make_fake_args(settings_command=None)),
        "0": _EXIT,
    }

    try:
        choice = console.input("\n[bold cyan]Enter choice [0-8]:[/bold cyan] ").strip()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[muted]Bye![/muted]")
        return

    handler = _dispatch.get(choice)
    if handler is _EXIT:
        console.print("[muted]Bye![/muted]")
    elif handler is None:
        console.print("[warning]Invalid choice.[/warning]")
    else:
        console.print()
        handler()


def cmd_daemon_run(args):
    """Hidden command — runs inside the background daemon process."""
    daemon.run_daemon_loop(args.engine)


# ──────────────────────────── Entry point ────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="blackout",
        description="Blackout Kit — DPI Bypass & Censorship Circumvention Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="version", version=f"blackout-kit {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # ── connect ──
    conn_p = sub.add_parser("connect", help="Smart connect — auto-preps and starts the best engine")
    conn_p.add_argument(
        "--engine",
        choices=ALL_ENGINE_CHOICES,
        default=None,
        metavar="ENGINE",
        help="sni | gdpi | psiphon | warp | tun | … (default: auto)",
    )
    conn_p.add_argument("-d", "--background", action="store_true",
                        help="Run as background daemon")
    conn_p.add_argument("--iran", action="store_true",
                        help="Apply Iran bypass profile (Firefox fingerprint + private mode)")

    # ── fix ──
    sub.add_parser("fix", help="Auto-fix DNS / Winsock / TCP/IP and clear system proxy")

    # ── scan ──
    scan_p = sub.add_parser("scan", help="Scan Cloudflare IPs and fake SNI domains")
    scan_p.add_argument("--ips",   action="store_true", help="Scan Cloudflare IPs only")
    scan_p.add_argument("--sni",   action="store_true", help="Test fake SNI domains only")
    scan_p.add_argument("--count", type=int, default=None, help="Number of IPs to scan")

    # ── test ──
    sub.add_parser("test", help="Analyze saved V2Ray configs")

    # ── start ──
    start_p = sub.add_parser("start", help="Start bypass engine")
    start_p.add_argument("--engine",
                         choices=ALL_ENGINE_CHOICES,
                         default="auto",
                         metavar="ENGINE",
                         help=(
                             "sni | gdpi | psiphon | warp | tun | tor | mhrv | "
                             "ikev2 | wireguard | openvpn | softether | appsscript | auto"
                         ))
    start_p.add_argument("-d", "--background", action="store_true",
                         help="Run as background daemon (survives terminal close)")

    # ── stop ──
    sub.add_parser("stop", help="Stop background daemon")

    # ── emergency ──
    em_p = sub.add_parser("emergency", help="Try all engines until one works")
    em_p.add_argument("-d", "--background", action="store_true", help="Run in background")

    # ── status ──
    sub.add_parser("status", help="Show daemon status and connection health")

    # ── logs ──
    logs_p = sub.add_parser("logs", help="View daemon log output")
    logs_p.add_argument("-n", "--lines", type=int, default=50, help="Lines to show (default: 50)")

    # ── mode ──
    mode_p = sub.add_parser("mode", help="View or set security mode (speed/private/legend)")
    mode_p.add_argument("mode_name", nargs="?",
                        choices=["speed", "private", "legend"],
                        metavar="MODE",
                        help="speed | private | legend  (omit to show current)")

    # ── killswitch ──
    ks_p = sub.add_parser("killswitch", help="Enable/disable kill switch (blocks net if proxy drops)")
    ks_p.add_argument("action", nargs="?", choices=["on", "off"],
                      metavar="on|off", help="Enable or disable (omit to check status)")

    # ── neighbor ──
    nb_p   = sub.add_parser("neighbor", help="Connect via a nearby Blackout Kit device")
    nb_sub = nb_p.add_subparsers(dest="neighbor_command")
    nb_sub.add_parser("discover", help="Scan LAN for nearby sharers")
    nb_conn = nb_sub.add_parser("connect", help="Use a neighbor's proxy")
    nb_conn.add_argument("--host", default=None, help="Neighbor IP (auto-discover if omitted)")
    nb_conn.add_argument("--port", type=int, default=0, help="Neighbor proxy port")
    nb_sub.add_parser("share", help="Broadcast your proxy so neighbors can connect")

    # ── config ──
    cfg_p    = sub.add_parser("config", help="Manage V2Ray proxy configs")
    cfg_sub  = cfg_p.add_subparsers(dest="config_command")
    cfg_sub.add_parser("list", help="List all saved configs")
    add_p = cfg_sub.add_parser("add", help="Add a V2Ray URI")
    add_p.add_argument("uri", help="vless:// or trojan:// URI")
    imp_p = cfg_sub.add_parser("import", help="Import from subscription URL")
    imp_p.add_argument("url", help="Subscription URL")
    rm_p = cfg_sub.add_parser("remove", help="Remove a config by number")
    rm_p.add_argument("index", type=int, help="Config number from 'config list'")
    cfg_sub.add_parser("encrypt", help="Obfuscate configs.txt → configs.enc (protects at rest)")
    cfg_sub.add_parser("decrypt", help="Restore configs.enc → configs.txt")

    # ── settings ──
    set_p    = sub.add_parser("settings", help="View and change all settings")
    set_sub  = set_p.add_subparsers(dest="settings_command")
    set_sub.add_parser("list", help="List all settings")
    get_p = set_sub.add_parser("get", help="Get a setting value")
    get_p.add_argument("key")
    sv_p = set_sub.add_parser("set", help="Change a setting")
    sv_p.add_argument("key")
    sv_p.add_argument("value")
    set_sub.add_parser("reset", help="Reset all settings to defaults")

    # ── tools ──
    tools_p   = sub.add_parser("tools", help="Network diagnostics, DNS, hotspot, and more")
    tools_sub = tools_p.add_subparsers(dest="tools_command")
    tools_sub.add_parser("dns-bench",  help="Benchmark DNS servers")
    tools_sub.add_parser("dns-flush",  help="Flush DNS cache")
    dns_set = tools_sub.add_parser("dns-set", help="Set system DNS server")
    dns_set.add_argument("server", help="DNS IP or preset name (cloudflare/google/shecan/electro)")
    tools_sub.add_parser("speedtest",  help="Run download speed test")
    tools_sub.add_parser("adapters",   help="List network adapters and IPs")
    tools_sub.add_parser("netfix",     help="Auto-fix common network problems (admin)")
    tools_sub.add_parser("hotspot",    help="Start/stop Windows Mobile Hotspot")
    tools_sub.add_parser("share-vpn",  help="Share VPN connection via hotspot (ICS)")
    ping_p = tools_sub.add_parser("ping",  help="TCP ping test")
    ping_p.add_argument("host", nargs="?", default="8.8.8.8")
    mtu_p  = tools_sub.add_parser("mtu",   help="Detect and optionally set MTU")
    mtu_p.add_argument("host", nargs="?", default="8.8.8.8")
    tr_p   = tools_sub.add_parser("traceroute", help="Traceroute to a host")
    tr_p.add_argument("host", nargs="?", default="8.8.8.8")
    cert_p = tools_sub.add_parser("cert-check", help="Check TLS certificate for a host[:port]")
    cert_p.add_argument("host", help="Hostname or host:port (default port 443)")
    cert_p.add_argument("--allow", action="store_true",
                        help="Mark host as manually allowed (enables LEGEND mode bypass)")

    # ── network ──
    net_p   = sub.add_parser("network", help="WiFi network switcher + ISP detection")
    net_sub = net_p.add_subparsers(dest="network_command")
    net_sub.add_parser("scan",  help="Show all available WiFi networks")
    net_sub.add_parser("isp",   help="Show current ISP provider info")
    net_sub.add_parser("auto",  help="Auto-switch to best available saved network")
    sw_p    = net_sub.add_parser("switch", help="Switch to a specific WiFi network")
    sw_p.add_argument("ssid", help="Network name (SSID) to connect to")

    # ── bins ──
    bins_p   = sub.add_parser("bins", help="Download and manage engine binaries")
    bins_sub = bins_p.add_subparsers(dest="bins_command")
    bins_dl  = bins_sub.add_parser("download", help="Download missing binaries (or a specific one)")
    bins_dl.add_argument("binary", nargs="?", default=None,
                         help="Binary key to download (xray/goodbyedpi/sing-box/warp-plus). "
                              "Omit to download all missing.")
    bins_sub.add_parser("update", help="Re-download all installed binaries to get latest versions")

    # ── country ──
    ctr_p   = sub.add_parser("country", help="Show or set active country profile")
    ctr_sub = ctr_p.add_subparsers(dest="country_command")
    ctr_set = ctr_sub.add_parser("set",   help="Pin country code (IR/US/GB/CN/IQ)")
    ctr_set.add_argument("code", help="ISO code: IR, US, GB, CN, IQ")
    ctr_sub.add_parser("reset", help="Remove pin — return to auto-detect")

    # ── help ──
    help_p = sub.add_parser("help", help="Detailed help for any command")
    help_p.add_argument("topic", nargs="?", default=None,
                        help="Command name (scan / start / settings / tools / ...)")

    # ── update ──
    upd_p = sub.add_parser("update", help="Check for and apply updates from GitHub")
    upd_p.add_argument("--apply", action="store_true", dest="force",
                       help="Download and install the update")

    # ── preflight ──
    sub.add_parser("preflight", help="Check readiness for an internet blackout")

    # ── doctor ──
    doc_p = sub.add_parser("doctor", help="Self-diagnose and auto-repair the app")
    doc_p.add_argument("--fix",    action="store_true", help="Auto-fix detected problems")
    doc_p.add_argument("--fix-av", action="store_true",
                       help="Add bins/ to Windows Defender exclusions (admin required)",
                       dest="fix_av")

    # ── secret easter egg ──
    sub.add_parser("0xDEADBEEF", help=argparse.SUPPRESS)

    # ── hidden: daemon runner ──
    dr_p = sub.add_parser("_daemon_run", help=argparse.SUPPRESS)
    dr_p.add_argument("--engine", required=True)

    # ── Parse & dispatch ──
    args = parser.parse_args()

    if not args.command:
        s = cfg.load()
        if s.get("show_banner", True):
            print_banner()
        _interactive_menu()
        return

    dispatch = {
        "connect":     cmd_connect,
        "fix":         cmd_fix,
        "scan":        cmd_scan,
        "test":        cmd_test,
        "start":       cmd_start,
        "stop":        cmd_stop,
        "emergency":   cmd_emergency,
        "status":      cmd_status,
        "logs":        cmd_logs,
        "config":      cmd_config,
        "settings":    cmd_settings,
        "tools":       cmd_tools,
        "mode":        cmd_mode,
        "killswitch":  cmd_killswitch,
        "neighbor":    cmd_neighbor,
        "network":     cmd_network,
        "bins":        cmd_bins,
        "country":     cmd_country,
        "update":      cmd_update,
        "preflight":   cmd_preflight,
        "help":        cmd_help,
        "doctor":      cmd_doctor,
        "0xDEADBEEF":  cmd_easteregg,
        "_daemon_run": cmd_daemon_run,
    }

    handler = dispatch.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()
