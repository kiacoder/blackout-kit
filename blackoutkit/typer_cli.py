"""
Blackout Kit - Modern Typer CLI (Migration in Progress).
This will eventually replace cli.py.
"""
import sys
import typer
from rich.console import Console

from . import __version__
from .theme import console, error_panel

app = typer.Typer(
    name="blackout",
    help="Blackout Kit — DPI Bypass & Censorship Circumvention Toolkit",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich"
)

# We will gradually port commands from cli.py into here.

@app.command()
def version():
    """Show the Blackout Kit version."""
    console.print(f"blackout-kit [bold green]{__version__}[/bold green]")

@app.command()
def fix():
    """Auto-fix DNS / Winsock / TCP/IP and clear system proxy"""
    from .cli import cmd_fix
    class DummyArgs: pass
    cmd_fix(DummyArgs())

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

@app.command()
def connect(
    pos_engine: str = typer.Argument(None, help="Engine to use (e.g. sni, gdpi, psiphon, auto)"),
    engine: str = typer.Option(None, "--engine", help="Engine to use"),
    background: bool = typer.Option(False, "--background", "-d", help="Run as background daemon"),
    iran: bool = typer.Option(False, "--iran", help="🔥 TIC 2026 evasion profile")
):
    """Smart connect — auto-preps and starts the best engine"""
    from rich.prompt import Prompt
    from .cli import ALL_ENGINE_CHOICES
    
    # Interactive mode if engine is missing
    final_engine = pos_engine or engine
    if not final_engine:
        console.print()
        final_engine = Prompt.ask(
            "⚡ Select an engine to connect with",
            choices=ALL_ENGINE_CHOICES,
            default="auto"
        )
        console.print()
        
    from .cli import cmd_connect
    class DummyArgs: pass
    args = DummyArgs()
    args.pos_engine = final_engine
    args.engine = None
    args.background = background
    args.iran = iran
    
    cmd_connect(args)

@app.command()
def mode(
    mode_name: str = typer.Argument(None, help="speed | private | legend (omit to interactively select)")
):
    """View or set security mode"""
    from rich.prompt import Prompt
    from .cli import cmd_mode
    
    if not mode_name:
        console.print()
        mode_name = Prompt.ask(
            "🛡️ Select a security mode",
            choices=["speed", "private", "legend"]
        )
        console.print()
        
    class DummyArgs: pass
    args = DummyArgs()
    args.mode_name = mode_name
    cmd_mode(args)

@app.command()
def killswitch(
    action: str = typer.Argument(None, help="on | off | test (omit to interactively select)")
):
    """Enable/disable kill switch (blocks net if proxy drops)"""
    from rich.prompt import Prompt
    from .cli import cmd_killswitch
    
    if not action:
        console.print()
        action = Prompt.ask(
            "☠️ Select killswitch action",
            choices=["on", "off", "test"]
        )
        console.print()
        
    class DummyArgs: pass
    args = DummyArgs()
    args.action = action
    cmd_killswitch(args)

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
    """Switch to a specific WiFi network"""
    from rich.prompt import Prompt
    from .cli import cmd_network
    
    if not ssid:
        console.print()
        ssid = Prompt.ask("📶 Enter the SSID of the network to switch to")
        console.print()
        
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
    """Add a V2Ray URI"""
    from rich.prompt import Prompt
    from .cli import cmd_config
    
    if not uri:
        console.print()
        uri = Prompt.ask("🔗 Enter the V2Ray URI (vless://... or trojan://...)")
        console.print()
        
    class DummyArgs: pass
    args = DummyArgs()
    args.config_command = "add"
    args.uri = uri
    cmd_config(args)

@config_app.command("import")
def cfg_import(url: str = typer.Argument(None, help="Subscription URL to import")):
    """Import from subscription URL"""
    from rich.prompt import Prompt
    from .cli import cmd_config
    
    if not url:
        console.print()
        url = Prompt.ask("🌐 Enter the subscription URL to import from")
        console.print()
        
    class DummyArgs: pass
    args = DummyArgs()
    args.config_command = "import"
    args.url = url
    cmd_config(args)

@config_app.command("remove")
def cfg_remove(num: int = typer.Argument(None, help="Config number to remove")):
    """Remove a config by number"""
    from rich.prompt import IntPrompt
    from .cli import cmd_config
    
    if num is None:
        console.print()
        num = IntPrompt.ask("🗑️  Enter the config number to remove (see \'config list\')")
        console.print()
        
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
    """Set system DNS server"""
    from rich.prompt import Prompt
    from .cli import cmd_tools
    if not ip:
        console.print()
        ip = Prompt.ask("🖥️  Enter the DNS IP to set (e.g. 1.1.1.1)")
        console.print()
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
def tools_netfix():
    """Auto-fix common network problems (admin)"""
    from .cli import cmd_tools
    class DummyArgs: pass
    args = DummyArgs()
    args.tools_command = "netfix"
    cmd_tools(args)

@tools_app.command("hotspot")
def tools_hotspot(
    action: str = typer.Argument(None, help="on | off")
):
    """Start/stop Windows Mobile Hotspot"""
    from rich.prompt import Prompt
    from .cli import cmd_tools
    if not action:
        console.print()
        action = Prompt.ask("📡 Select hotspot action", choices=["on", "off"])
        console.print()
    class DummyArgs: pass
    args = DummyArgs()
    args.tools_command = "hotspot"
    args.action = action
    cmd_tools(args)

@tools_app.command("share-vpn")
def tools_share_vpn(
    action: str = typer.Argument(None, help="on | off")
):
    """Share VPN connection via hotspot (ICS)"""
    from rich.prompt import Prompt
    from .cli import cmd_tools
    if not action:
        console.print()
        action = Prompt.ask("🌐 Select ICS VPN sharing action", choices=["on", "off"])
        console.print()
    class DummyArgs: pass
    args = DummyArgs()
    args.tools_command = "share-vpn"
    args.action = action
    cmd_tools(args)

@tools_app.command("ping")
def tools_ping(host: str = typer.Argument(None, help="Host to ping")):
    """TCP ping test"""
    from rich.prompt import Prompt
    from .cli import cmd_tools
    if not host:
        console.print()
        host = Prompt.ask("🏓 Enter host or IP to ping")
        console.print()
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
    """Traceroute to a host"""
    from rich.prompt import Prompt
    from .cli import cmd_tools
    if not host:
        console.print()
        host = Prompt.ask("🗺️  Enter host or IP to trace")
        console.print()
    class DummyArgs: pass
    args = DummyArgs()
    args.tools_command = "traceroute"
    args.host = host
    cmd_tools(args)

@tools_app.command("cert-check")
def tools_cert_check(host: str = typer.Argument(None, help="Host to check")):
    """Check TLS certificate for a host[:port]"""
    from rich.prompt import Prompt
    from .cli import cmd_tools
    if not host:
        console.print()
        host = Prompt.ask("🔐 Enter host or IP to check TLS certificate")
        console.print()
    class DummyArgs: pass
    args = DummyArgs()
    args.tools_command = "cert-check"
    args.host = host
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
    iran: bool = typer.Option(False, "--iran", help="TIC 2026 profile")
):
    """Start bypass engine"""
    from rich.prompt import Prompt
    from .cli import ALL_ENGINE_CHOICES, cmd_start
    final_engine = pos_engine or engine
    if not final_engine:
        console.print()
        final_engine = Prompt.ask("⚡ Select engine to start", choices=ALL_ENGINE_CHOICES, default="auto")
        console.print()
    class DummyArgs: pass
    args = DummyArgs()
    args.pos_engine = final_engine
    args.engine = None
    args.background = background
    args.iran = iran
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
def emergency():
    """Try all engines until one works"""
    from .cli import cmd_emergency
    class DummyArgs: pass
    cmd_emergency(DummyArgs())

@app.command()
def status():
    """Show daemon status and connection health"""
    from .cli import cmd_status
    class DummyArgs: pass
    cmd_status(DummyArgs())

@app.command()
def logs():
    """View daemon log output"""
    from .cli import cmd_logs
    class DummyArgs: pass
    cmd_logs(DummyArgs())

@app.command()
def panic():
    """🚨 Instantly kill all connections, flush DNS, clear proxies, and restore normal state"""
    from .cli import cmd_panic
    class DummyArgs: pass
    cmd_panic(DummyArgs())

@app.command()
def shield():
    """🛡️ Activate Mullvad-style strict kill switch and Ad/Tracker blocker"""
    from .cli import cmd_shield
    class DummyArgs: pass
    cmd_shield(DummyArgs())

@app.command()
def update():
    """Update Blackout Kit to latest version"""
    from .cli import cmd_update
    class DummyArgs: pass
    cmd_update(DummyArgs())

@app.command()

@app.command(name="manual")
def manual_help(topic: str = typer.Argument(None, help="Help topic (e.g., 'iran', 'engines', 'configs')")):
    """Show detailed manual/help for a specific topic"""
    from .cli import cmd_help
    class DummyArgs: pass
    args = DummyArgs()
    args.topic = topic
    cmd_help(args)

@app.command()
def doctor(
    fix_av: bool = typer.Option(False, "--fix-av", help="Add Windows Defender exclusions")
):
    """Diagnose and fix environment issues"""
    from .cli import cmd_doctor
    class DummyArgs: pass
    args = DummyArgs()
    args.fix_av = fix_av
    cmd_doctor(args)

@app.command()
def country(
    iso_code: str = typer.Argument(None, help="2-letter ISO code (IR, CN, RU) or 'auto'")
):
    """Set censorship country profile"""
    from rich.prompt import Prompt
    from .cli import cmd_country
    if not iso_code:
        console.print()
        iso_code = Prompt.ask("🌍 Enter country code (IR, CN, RU, auto)")
        console.print()
    class DummyArgs: pass
    args = DummyArgs()
    args.iso_code = iso_code
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
    ip: str = typer.Argument(None, help="Neighbor IP address (e.g., 192.168.1.5)")
):
    """Use a neighbor's proxy"""
    from rich.prompt import Prompt
    from .cli import cmd_neighbor
    if not ip:
        console.print()
        ip = Prompt.ask("🤝 Enter neighbor IP to connect to")
        console.print()
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
bins_app = typer.Typer(help="Download and manage engine binaries", no_args_is_help=True)
app.add_typer(bins_app, name="bins")

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

@bins_app.command("clean")
def bins_clean():
    """Delete all cached binaries to force a fresh download"""
    from .cli import cmd_bins
    class DummyArgs: pass
    args = DummyArgs()
    args.bins_command = "clean"
    cmd_bins(args)

@app.command(name="_daemon_run", hidden=True)
def daemon_run(
    engine: str = typer.Option(..., "--engine")
):
    from .cli import cmd_daemon_run
    class DummyArgs: pass
    args = DummyArgs()
    args.engine = engine
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
    except Exception as e:
        console.print(error_panel(
            f"An unexpected fatal error occurred:\n{str(e)}\n\n[dim]Please run 'blackout doctor' to auto-fix common issues.[/dim]",
            title="Fatal Error"
        ))
        sys.exit(1)

if __name__ == "__main__":
    main()
