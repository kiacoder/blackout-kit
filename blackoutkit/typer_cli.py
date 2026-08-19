"""
Blackout Kit - Modern Typer CLI (Migration in Progress).
This will eventually replace cli.py.
"""
import sys
import typer
from rich.console import Console

from . import __version__
from .theme import ask_choice, ask_int, ask_text, console, is_interactive, print_friendly_error

app = typer.Typer(
    name="blackout",
    help="Blackout Kit — DPI Bypass & Censorship Circumvention Toolkit",
    add_completion=False,
    no_args_is_help=False,
    rich_markup_mode="rich"
)

# We will gradually port commands from cli.py into here.

@app.command()
def version():
    """Show the Blackout Kit version."""
    console.print(f"blackout-kit [bold green]{__version__}[/bold green]")

@app.command()
def fix(
    full_route_reset: bool = typer.Option(
        False,
        "--full-route-reset",
        help="Emergency only: flush every IPv4 route before renewing DHCP",
    ),
    full_stack_reset: bool = typer.Option(
        False,
        "--full-stack-reset",
        help="Emergency only: reset Winsock, TCP/IP, autotuning, and DHCP",
    ),
    flush_arp: bool = typer.Option(
        False,
        "--flush-arp",
        help="Explicitly flush the local ARP/neighbor cache",
    ),
    preview: bool = typer.Option(False, "--preview", help="Show Blackout-owned recovery actions without changing anything"),
    history: bool = typer.Option(False, "--history", help="Show redacted local recovery audit history"),
    history_lines: int = typer.Option(20, "--history-lines", min=1, max=100, help="Audit records to show with --history"),
):
    """Repair targeted post-crash Blackout network state."""
    from .cli import cmd_fix

    class DummyArgs:
        pass

    args = DummyArgs()
    args.full_route_reset = full_route_reset
    args.full_stack_reset = full_stack_reset
    args.flush_arp = flush_arp
    args.preview = preview
    args.history = history
    args.history_lines = history_lines
    cmd_fix(args)

@app.command()
def scan(
    ips: bool = typer.Option(False, "--ips", help="Scan Cloudflare IPs"),
    sni: bool = typer.Option(False, "--sni", help="Scan fake SNI domains"),
    count: int = typer.Option(None, "--count", "-c", help="Number of IPs to generate")
):
    """Scan Cloudflare IPs and fake SNI domains"""
    from .cli import cmd_scan
    class DummyArgs:
        pass
    
    args = DummyArgs()
    args.ips = ips
    args.sni = sni
    args.count = count
    
    cmd_scan(args)

def _ask_engine(prompt_text: str = "Choose an engine") -> str | None:
    from rich.columns import Columns
    from rich.panel import Panel
    from rich.align import Align
    from .cli import ALL_ENGINE_CHOICES

    if not is_interactive():
        return None
    engine_panels = [Panel(f"[engine]{engine}[/engine]", border_style="panel.border", expand=True) for engine in ALL_ENGINE_CHOICES]
    console.print(Panel(
        Align.center(Columns(engine_panels, align="center", expand=True, equal=True)),
        title="[heading]Available engines[/heading]",
        border_style="panel.border",
        padding=(1, 2),
    ))
    return ask_choice(prompt_text, ALL_ENGINE_CHOICES, default="auto")


def _forward_status(watch: bool, interval: float) -> None:
    from .cli import cmd_status

    class DummyArgs:
        pass

    args = DummyArgs()
    args.watch = watch
    args.interval = interval
    cmd_status(args)


@app.command()
def route():
    """Show local, read-only engine recommendations."""
    from .cli import cmd_route

    class DummyArgs:
        pass

    cmd_route(DummyArgs())


@app.command()
def theme(
    palette: str = typer.Argument(None, help="dark | light (omit to show/select)"),
):
    """Show or set Blackout Kit's terminal-only palette."""
    from .cli import cmd_theme

    if palette is None and is_interactive():
        from . import settings as cfg
        palette = ask_choice(
            "Choose terminal palette",
            ["dark", "light"],
            default=cfg.load().get("terminal_theme", "dark"),
        )
    if palette is not None and palette not in ("dark", "light"):
        raise typer.BadParameter("must be dark or light")

    class DummyArgs:
        pass

    args = DummyArgs()
    args.palette = palette
    cmd_theme(args)


@app.command()
def status(
    watch: bool = typer.Option(False, "--watch", "-w", help="Refresh local status until Ctrl+C"),
    interval: float = typer.Option(2.0, "--interval", min=0.5, max=60.0, help="Refresh interval in seconds"),
):
    """Show daemon status and local connection health."""
    _forward_status(watch, interval)


@app.command()
def ready(
    engine: str = typer.Argument("auto", help="Engine to validate locally (or auto)"),
):
    """Check local engine readiness without changing anything."""
    from .cli import cmd_ready

    class DummyArgs:
        pass

    args = DummyArgs()
    args.engine = engine
    if not cmd_ready(args):
        raise typer.Exit(code=1)


@app.command()
def connect(
    pos_engine: str = typer.Argument(None, help="Engine to use (e.g. sni, psiphon, auto)"),
    engine: str = typer.Option(None, "--engine", help="Engine to use"),
    background: bool = typer.Option(False, "--background", "-d", help="Run as background daemon"),
    iran: bool = typer.Option(False, "--iran", help="TIC 2026 evasion profile"),
    russia: bool = typer.Option(False, "--russia", help="Russia transport preset"),
):
    """Smart connect — uses a recommendation when no engine is specified."""
    from .cli import cmd_connect

    class DummyArgs:
        pass

    args = DummyArgs()
    args.pos_engine = pos_engine
    args.engine = engine
    args.background = background
    args.iran = iran
    args.russia = russia
    cmd_connect(args)


@app.command()
def mode(
    mode_name: str = typer.Argument(None, help="speed | private | legend (omit to interactively select)"),
):
    """View or set security mode."""
    from .cli import cmd_mode

    if not mode_name:
        mode_name = ask_choice("Select a security mode", ["speed", "private", "legend"])
        if mode_name is None:
            return

    class DummyArgs:
        pass

    args = DummyArgs()
    args.mode_name = mode_name
    cmd_mode(args)


@app.command()
def killswitch(
    action: str = typer.Argument(None, help="on | off | test (omit to interactively select)"),
):
    """Manage the Linux-only endpoint-scoped kill switch."""
    from .cli import cmd_killswitch

    if not action:
        action = ask_choice("Select kill-switch action", ["on", "off", "test"])
        if action is None:
            return

    class DummyArgs:
        pass

    args = DummyArgs()
    args.action = action
    cmd_killswitch(args)


# Existing command implementations continue below.
def _add_to_user_path(directory: str) -> bool:
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
            try:
                current_path, _ = winreg.QueryValueEx(key, "PATH")
            except OSError:
                current_path = ""
            
            if directory.lower() not in current_path.lower():
                new_path = current_path
                if new_path and not new_path.endswith(";"):
                    new_path += ";"
                new_path += directory
                winreg.SetValueEx(key, "PATH", 0, winreg.REG_EXPAND_SZ, new_path)
                return True
            return False
    except Exception as e:
        console.print(f"[error]Failed to update PATH: {e}[/error]")
        return False

@app.command("add-to-path")
def add_to_path():
    """Add Blackout Kit to the system PATH so you can run it anywhere."""
    import sys
    from pathlib import Path
    
    if getattr(sys, 'frozen', False):
        target_dir = str(Path(sys.executable).parent.resolve())
    else:
        target_dir = str(Path(__file__).parent.parent.resolve())
        
    if _add_to_user_path(target_dir):
        console.print(f"[success]✓ Added {target_dir} to your system PATH![/success]")
        console.print("[info]You will need to restart your terminal for this to take effect.[/info]")
    else:
        console.print(f"[info]Blackout Kit ({target_dir}) is already in your PATH.[/info]")

@app.command(hidden=True)
def gui():
    """Start the native desktop app"""
    from .gui_app import run_gui
    run_gui()

@app.command()
def mcp():
    """Start the AI Agent MCP (Model Context Protocol) stdio server."""
    from .mcp_server import run_mcp_server
    run_mcp_server()

# ── SPLIT TUNNEL GROUP ──
split_app = typer.Typer(help="Split Tunneling & Direct Proxy Bypass", no_args_is_help=True)
app.add_typer(split_app, name="split-tunnel")

@split_app.command("list")
def split_list():
    """List all direct proxy bypass rules"""
    from .split_tunnel import load_split_rules
    rules = load_split_rules()
    console.print("\n[bold cyan]Direct Bypass Rules (Split Tunnel):[/bold cyan]")
    for r in rules:
        console.print(f"  • {r}")
    console.print()

@split_app.command("add")
def split_add(target: str = typer.Argument(..., help="Domain, IP, or CIDR to bypass proxy")):
    """Add a domain or IP to bypass system proxy directly"""
    from .split_tunnel import add_direct_route
    if add_direct_route(target):
        console.print(f"[success]✓ Added '{target}' to split-tunnel direct bypass list![/success]")

@split_app.command("remove")
def split_remove(target: str = typer.Argument(..., help="Domain, IP, or CIDR to remove")):
    """Remove a domain or IP from direct proxy bypass list"""
    from .split_tunnel import remove_direct_route
    if remove_direct_route(target):
        console.print(f"[success]✓ Removed '{target}' from split-tunnel direct bypass list![/success]")

# ── NETWORK GROUP ──
network_app = typer.Typer(help="WiFi network switcher + ISP detection", no_args_is_help=True)
app.add_typer(network_app, name="network")

@network_app.command("scan")
def net_scan():
    """Show all available WiFi networks"""
    from .cli import cmd_network
    class DummyArgs: pass
    args = DummyArgs()
    args.network_command = "scan"
    cmd_network(args)

@network_app.command("isp")
def net_isp():
    """Show current ISP provider info"""
    from .cli import cmd_network
    class DummyArgs: pass
    args = DummyArgs()
    args.network_command = "isp"
    cmd_network(args)

@network_app.command("auto")
def net_auto():
    """Auto-switch to best available saved network"""
    from .cli import cmd_network
    class DummyArgs: pass
    args = DummyArgs()
    args.network_command = "auto"
    cmd_network(args)

@network_app.command("switch")
def net_switch(
    ssid: str = typer.Argument(None, help="SSID of the network to switch to")
):
    """Switch to a specific WiFi network."""
    from .cli import cmd_network

    ssid = ssid or ask_text("Enter the SSID of the network to switch to")
    if not ssid:
        return
    class DummyArgs: pass
    args = DummyArgs()
    args.network_command = "switch"
    args.ssid = ssid
    cmd_network(args)

# ── CONFIG GROUP ──
config_app = typer.Typer(help="Manage V2Ray proxy configs", no_args_is_help=True)
app.add_typer(config_app, name="config")

@config_app.command("list")
def cfg_list():
    """List all saved configs"""
    from .cli import cmd_config
    class DummyArgs: pass
    args = DummyArgs()
    args.config_command = "list"
    cmd_config(args)

@config_app.command("add")
def cfg_add(uri: str = typer.Argument(None, help="V2Ray URI to add (vmess://, vless://, etc)")):
    """Add a V2Ray URI."""
    from .cli import cmd_config

    uri = uri or ask_text("Enter the V2Ray URI")
    if not uri:
        return
    class DummyArgs: pass
    args = DummyArgs()
    args.config_command = "add"
    args.uri = uri
    cmd_config(args)

@config_app.command("import")
def cfg_import(url: str = typer.Argument(None, help="Subscription URL to import")):
    """Import from subscription URL."""
    from .cli import cmd_config

    url = url or ask_text("Enter the subscription URL")
    if not url:
        return
    class DummyArgs: pass
    args = DummyArgs()
    args.config_command = "import"
    args.url = url
    cmd_config(args)

@config_app.command("remove")
def cfg_remove(num: int = typer.Argument(None, help="Config number to remove")):
    """Remove a config by number."""
    from .cli import cmd_config

    num = num if num is not None else ask_int("Enter the config number to remove")
    if num is None:
        return
    class DummyArgs: pass
    args = DummyArgs()
    args.config_command = "remove"
    args.index = num
    cmd_config(args)

@config_app.command("encrypt")
def cfg_encrypt():
    """Obfuscate configs.txt → configs.enc (protects at rest)"""
    from .cli import cmd_config
    class DummyArgs: pass
    args = DummyArgs()
    args.config_command = "encrypt"
    cmd_config(args)

@config_app.command("decrypt")
def cfg_decrypt():
    """Restore configs.enc → configs.txt"""
    from .cli import cmd_config
    class DummyArgs: pass
    args = DummyArgs()
    args.config_command = "decrypt"
    cmd_config(args)

# ── TOOLS GROUP ──
tools_app = typer.Typer(help="Network diagnostics, DNS, hotspot, and more", no_args_is_help=True)
app.add_typer(tools_app, name="tools")

@tools_app.command("dns-bench")
def tools_dns_bench():
    """Benchmark DNS servers"""
    from .cli import cmd_tools
    class DummyArgs: pass
    args = DummyArgs()
    args.tools_command = "dns-bench"
    cmd_tools(args)

@tools_app.command("dns-flush")
def tools_dns_flush():
    """Flush DNS cache"""
    from .cli import cmd_tools
    class DummyArgs: pass
    args = DummyArgs()
    args.tools_command = "dns_flush".replace("_", "-")
    cmd_tools(args)

@tools_app.command("dns-set")
def tools_dns_set(
    ip: str = typer.Argument(None, help="DNS IP (e.g. 1.1.1.1)"),
    adapter: str = typer.Option(None, "--adapter", "-a", help="Specific adapter name")
):
    """Set system DNS server."""
    from .cli import cmd_tools

    ip = ip or ask_text("Enter the DNS IP to set")
    if not ip:
        return
    class DummyArgs: pass
    args = DummyArgs()
    args.tools_command = "dns-set"
    args.server = ip
    args.adapter = adapter
    cmd_tools(args)

@tools_app.command("speedtest")
def tools_speedtest():
    """Run download speed test"""
    from .cli import cmd_tools
    class DummyArgs: pass
    args = DummyArgs()
    args.tools_command = "speedtest".replace("_", "-")
    cmd_tools(args)

@tools_app.command("adapters")
def tools_adapters():
    """List network adapters and IPs"""
    from .cli import cmd_tools
    class DummyArgs: pass
    args = DummyArgs()
    args.tools_command = "adapters".replace("_", "-")
    cmd_tools(args)

@tools_app.command("netfix")
def tools_netfix(
    preview: bool = typer.Option(False, "--preview", help="Show Blackout-owned recovery actions without changing anything"),
):
    """Safely repair post-crash network state (admin may be requested)"""
    from .cli import cmd_tools
    class DummyArgs: pass
    args = DummyArgs()
    args.tools_command = "netfix"
    args.preview = preview
    cmd_tools(args)


@tools_app.command("arp-flush")
def tools_arp_flush():
    """Explicitly flush the local ARP/neighbor cache"""
    from .cli import cmd_tools
    class DummyArgs: pass
    args = DummyArgs()
    args.tools_command = "arp-flush"
    cmd_tools(args)

@tools_app.command("hotspot")
def tools_hotspot(
    action: str = typer.Argument(None, help="on | off")
):
    """Start or stop Windows Mobile Hotspot."""
    from .cli import cmd_tools

    action = action or ask_choice("Select hotspot action", ["on", "off"])
    if not action:
        return
    class DummyArgs: pass
    args = DummyArgs()
    args.tools_command = "hotspot"
    args.action = action
    cmd_tools(args)

@tools_app.command("share-vpn")
def tools_share_vpn(
    action: str = typer.Argument(None, help="on | off")
):
    """Share VPN connection via hotspot (ICS)."""
    from .cli import cmd_tools

    action = action or ask_choice("Select ICS VPN sharing action", ["on", "off"])
    if not action:
        return
    class DummyArgs: pass
    args = DummyArgs()
    args.tools_command = "share-vpn"
    args.action = action
    cmd_tools(args)

@tools_app.command("ping")
def tools_ping(host: str = typer.Argument(None, help="Host to ping")):
    """TCP ping test."""
    from .cli import cmd_tools

    host = host or ask_text("Enter host or IP to ping")
    if not host:
        return
    class DummyArgs: pass
    args = DummyArgs()
    args.tools_command = "ping"
    args.host = host
    cmd_tools(args)
    
@tools_app.command("mtu")
def tools_mtu(
    host: str = typer.Argument("8.8.8.8", help="Host to ping"),
    set_mtu: bool = typer.Option(False, "--set", help="Auto-set the best MTU")
):
    """Detect and optionally set MTU"""
    from .cli import cmd_tools
    class DummyArgs: pass
    args = DummyArgs()
    args.tools_command = "mtu"
    args.host = host
    args.set = set_mtu
    cmd_tools(args)

@tools_app.command("traceroute")
def tools_traceroute(host: str = typer.Argument(None, help="Host to trace")):
    """Traceroute to a host."""
    from .cli import cmd_tools

    host = host or ask_text("Enter host or IP to trace")
    if not host:
        return
    class DummyArgs: pass
    args = DummyArgs()
    args.tools_command = "traceroute"
    args.host = host
    cmd_tools(args)

@tools_app.command("cert-check")
def tools_cert_check(
    host: str = typer.Argument(None, help="Host to check"),
    allow: bool = typer.Option(False, "--allow", help="Trust this host in LEGEND mode"),
):
    """Check TLS certificate for a host[:port]."""
    from .cli import cmd_tools

    host = host or ask_text("Enter host or IP to check TLS certificate")
    if not host:
        return
    class DummyArgs:
        pass
    args = DummyArgs()
    args.tools_command = "cert-check"
    args.host = host
    args.allow = allow
    cmd_tools(args)

@app.command()
def test():
    """Analyze saved V2Ray configs"""
    from .cli import cmd_test
    class DummyArgs: pass
    cmd_test(DummyArgs())

@app.command()
def start(
    pos_engine: str = typer.Argument(None, help="Engine to use"),
    engine: str = typer.Option(None, "--engine", help="Engine to use"),
    background: bool = typer.Option(False, "--background", "-d", help="Run as daemon"),
    iran: bool = typer.Option(False, "--iran", help="TIC 2026 profile"),
    russia: bool = typer.Option(False, "--russia", help="Russia transport preset"),
):
    """Start a selected bypass engine."""
    from .cli import cmd_start

    final_engine = pos_engine or engine or _ask_engine("Choose an engine to start")
    if not final_engine:
        return
    class DummyArgs: pass
    args = DummyArgs()
    args.pos_engine = final_engine
    args.engine = None
    args.background = background
    args.iran = iran
    args.russia = russia
    cmd_start(args)

@app.command()
def stop():
    """Stop background daemon"""
    from .cli import cmd_stop
    class DummyArgs: pass
    cmd_stop(DummyArgs())

@app.command()
def disconnect():
    """Stop background daemon (alias for stop)"""
    from .cli import cmd_stop
    class DummyArgs: pass
    cmd_stop(DummyArgs())

@app.command()
def emergency(
    background: bool = typer.Option(False, "--background", "-d", help="Run as background daemon"),
):
    """Try locally supported engine candidates in sequence."""
    from .cli import cmd_emergency
    class DummyArgs:
        pass
    args = DummyArgs()
    args.background = background
    cmd_emergency(args)


@app.command()
def logs(
    lines: int = typer.Option(50, "--lines", "-n", min=1, help="Number of log lines to show"),
):
    """View daemon log output"""
    from .cli import cmd_logs
    class DummyArgs:
        pass
    args = DummyArgs()
    args.lines = lines
    cmd_logs(args)

@app.command()
def panic():
    """🚨 Instantly kill all connections, flush DNS, clear proxies, and restore normal state"""
    from .cli import cmd_panic
    class DummyArgs: pass
    cmd_panic(DummyArgs())

@app.command()
def shield():
    """Apply DNS blocking and request Linux-only firewall protection"""
    from .cli import cmd_shield
    class DummyArgs: pass
    cmd_shield(DummyArgs())

@app.command()
def update(
    apply: bool = typer.Option(False, "--apply", help="Download and apply the available update"),
):
    """Update Blackout Kit to latest version"""
    from .cli import cmd_update
    class DummyArgs:
        pass
    args = DummyArgs()
    args.force = apply
    cmd_update(args)

def _show_help(topic):
    from .cli import cmd_help

    class DummyArgs:
        pass

    args = DummyArgs()
    args.topic = topic
    cmd_help(args)


@app.command(name="manual")
def manual_help(topic: str = typer.Argument(None, help="Help topic (e.g., 'iran', 'engines', 'configs')")):
    """Show detailed manual/help for a specific topic"""
    _show_help(topic)


@app.command(name="help")
def help_command(topic: str = typer.Argument(None, help="Help topic (e.g., 'iran', 'engines', 'configs')")):
    """Show detailed manual/help for a specific topic"""
    _show_help(topic)

@app.command()
def doctor(
    fix: bool = typer.Option(False, "--fix", help="Auto-fix every repairable issue"),
    fix_av: bool = typer.Option(False, "--fix-av", help="Add Windows Defender exclusions"),
):
    """Diagnose and fix environment issues"""
    from .cli import cmd_doctor
    class DummyArgs:
        pass
    args = DummyArgs()
    args.fix = fix
    args.fix_av = fix_av
    cmd_doctor(args)

country_app = typer.Typer(help="View or pin the active censorship country profile", no_args_is_help=False)
app.add_typer(country_app, name="country")

@country_app.callback(invoke_without_command=True)
def country_status(ctx: typer.Context):
    """Show the active country profile."""
    if ctx.invoked_subcommand is None:
        from .cli import cmd_country
        class DummyArgs:
            pass
        args = DummyArgs()
        args.country_command = None
        cmd_country(args)

@country_app.command("set")
def country_set(code: str = typer.Argument(..., help="Country code: IR, RU, CN, IQ, GB, US, or EU")):
    """Pin the active country profile."""
    from .cli import cmd_country
    class DummyArgs:
        pass
    args = DummyArgs()
    args.country_command = "set"
    args.code = code
    cmd_country(args)

@country_app.command("reset")
def country_reset():
    """Return to ISP-based country auto-detection."""
    from .cli import cmd_country
    class DummyArgs:
        pass
    args = DummyArgs()
    args.country_command = "reset"
    cmd_country(args)

@country_app.command("show", hidden=True)
def country_show():
    """Show the active country profile."""
    from .cli import cmd_country
    class DummyArgs:
        pass
    args = DummyArgs()
    args.country_command = None
    cmd_country(args)

# ── NEIGHBOR GROUP ──
neighbor_app = typer.Typer(help="Connect via a nearby Blackout Kit device", no_args_is_help=True)
app.add_typer(neighbor_app, name="neighbor")

@neighbor_app.command("discover")
def neighbor_discover():
    """Scan LAN for nearby sharers"""
    from .cli import cmd_neighbor
    class DummyArgs: pass
    args = DummyArgs()
    args.neighbor_command = "discover"
    cmd_neighbor(args)

@neighbor_app.command("connect")
def neighbor_connect(
    ip: str = typer.Argument(None, help="Neighbor IP address (e.g. 192.168.1.5)")
):
    """Use a neighbor's proxy."""
    from .cli import cmd_neighbor

    ip = ip or ask_text("Enter neighbor IP to connect to")
    if not ip:
        return
    class DummyArgs: pass
    args = DummyArgs()
    args.neighbor_command = "connect"
    args.host = ip
    cmd_neighbor(args)

@neighbor_app.command("share")
def neighbor_share():
    """Broadcast your proxy so neighbors can connect"""
    from .cli import cmd_neighbor
    class DummyArgs: pass
    args = DummyArgs()
    args.neighbor_command = "share"
    cmd_neighbor(args)

# ── SETTINGS GROUP ──
settings_app = typer.Typer(help="View and change all settings", no_args_is_help=True)
app.add_typer(settings_app, name="settings")

@settings_app.command("list")
def settings_list():
    """List all settings"""
    from .cli import cmd_settings
    class DummyArgs: pass
    args = DummyArgs()
    args.settings_command = "list"
    cmd_settings(args)

@settings_app.command("get")
def settings_get(key: str = typer.Argument(..., help="Setting key")):
    """Get a setting value"""
    from .cli import cmd_settings
    class DummyArgs: pass
    args = DummyArgs()
    args.settings_command = "get"
    args.key = key
    cmd_settings(args)

@settings_app.command("set")
def settings_set(
    key: str = typer.Argument(..., help="Setting key"),
    value: str = typer.Argument(..., help="New value")
):
    """Change a setting"""
    from .cli import cmd_settings
    class DummyArgs: pass
    args = DummyArgs()
    args.settings_command = "set"
    args.key = key
    args.value = value
    cmd_settings(args)

@settings_app.command("reset")
def settings_reset():
    """Reset all settings to defaults"""
    from .cli import cmd_settings
    class DummyArgs: pass
    args = DummyArgs()
    args.settings_command = "reset"
    cmd_settings(args)

# ── BINS GROUP ──
bins_app = typer.Typer(help="Download and manage engine binaries", no_args_is_help=False)
app.add_typer(bins_app, name="bins")

@bins_app.callback(invoke_without_command=True)
def bins_status(ctx: typer.Context):
    """Show installed and missing engine binaries."""
    if ctx.invoked_subcommand is None:
        from .cli import cmd_bins
        class DummyArgs:
            pass
        args = DummyArgs()
        args.bins_command = None
        cmd_bins(args)

@bins_app.command("download")
def bins_download(
    engine: str = typer.Argument(None, help="Specific engine (or omit for all missing)")
):
    """Download missing binaries"""
    from .cli import cmd_bins
    class DummyArgs: pass
    args = DummyArgs()
    args.bins_command = "download"
    args.binary = engine
    cmd_bins(args)

@bins_app.command("update")
def bins_update():
    """Re-download installed binaries to update them."""
    from .cli import cmd_bins
    class DummyArgs:
        pass
    args = DummyArgs()
    args.bins_command = "update"
    cmd_bins(args)

@app.command(name="_daemon_run", hidden=True)
def daemon_run(
    engine: str = typer.Option(..., "--engine"),
    env_overrides_json: str = typer.Option(None, "--env-overrides-json", hidden=True),
):
    from .cli import cmd_daemon_run
    class DummyArgs: pass
    args = DummyArgs()
    args.engine = engine
    args.env_overrides_json = env_overrides_json
    cmd_daemon_run(args)

@app.command()
def preflight():
    """Check readiness for an internet blackout"""
    from .cli import cmd_preflight
    class DummyArgs: pass
    cmd_preflight(DummyArgs())

@app.command(name="0xDEADBEEF", hidden=True)
def deadbeef():
    from .cli import cmd_easteregg
    class DummyArgs: pass
    cmd_easteregg(DummyArgs())

@app.callback(invoke_without_command=True)
def app_callback(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        # Try to start the modern GUI Launcher first
        from .launcher import start_launcher
        launched = start_launcher()
        
        # Fallback to the terminal interactive menu if GUI is missing dependencies
        if not launched:
            from . import settings as cfg
            from .cli import print_banner, _interactive_menu
            s = cfg.load()
            if s.get("show_banner", True):
                print_banner()
            _interactive_menu()


def main():
    """Global entry point for the new Typer CLI."""
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[muted]Operation cancelled by user.[/muted]")
        sys.exit(130)
    except Exception as exc:
        print_friendly_error(exc)
        sys.exit(1)

if __name__ == "__main__":
    main()
