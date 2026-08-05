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
    from .cli import cmd_net_scan
    class DummyArgs: pass
    cmd_net_scan(DummyArgs())

@network_app.command("isp")
def net_isp():
    """Show current ISP provider info"""
    from .cli import cmd_net_isp
    class DummyArgs: pass
    cmd_net_isp(DummyArgs())

@network_app.command("auto")
def net_auto():
    """Auto-switch to best available saved network"""
    from .cli import cmd_net_auto
    class DummyArgs: pass
    cmd_net_auto(DummyArgs())

@network_app.command("switch")
def net_switch(
    ssid: str = typer.Argument(None, help="SSID of the network to switch to")
):
    """Switch to a specific WiFi network"""
    from rich.prompt import Prompt
    from .cli import cmd_net_switch
    
    if not ssid:
        console.print()
        ssid = Prompt.ask("📶 Enter the SSID of the network to switch to")
        console.print()
        
    class DummyArgs: pass
    args = DummyArgs()
    args.ssid = ssid
    cmd_net_switch(args)

# ── CONFIG GROUP ──
config_app = typer.Typer(help="Manage V2Ray proxy configs", no_args_is_help=True)
app.add_typer(config_app, name="config")

@config_app.command("list")
def cfg_list():
    """List all saved configs"""
    from .cli import cmd_cfg_list
    class DummyArgs: pass
    cmd_cfg_list(DummyArgs())

@config_app.command("add")
def cfg_add(uri: str = typer.Argument(None, help="V2Ray URI to add (vmess://, vless://, etc)")):
    """Add a V2Ray URI"""
    from rich.prompt import Prompt
    from .cli import cmd_cfg_add
    
    if not uri:
        console.print()
        uri = Prompt.ask("🔗 Enter the V2Ray URI (vless://... or trojan://...)")
        console.print()
        
    class DummyArgs: pass
    args = DummyArgs()
    args.uri = uri
    cmd_cfg_add(args)

@config_app.command("import")
def cfg_import(url: str = typer.Argument(None, help="Subscription URL to import")):
    """Import from subscription URL"""
    from rich.prompt import Prompt
    from .cli import cmd_cfg_import
    
    if not url:
        console.print()
        url = Prompt.ask("🌐 Enter the subscription URL to import from")
        console.print()
        
    class DummyArgs: pass
    args = DummyArgs()
    args.url = url
    cmd_cfg_import(args)

@config_app.command("remove")
def cfg_remove(num: int = typer.Argument(None, help="Config number to remove")):
    """Remove a config by number"""
    from rich.prompt import IntPrompt
    from .cli import cmd_cfg_remove
    
    if num is None:
        console.print()
        num = IntPrompt.ask("🗑️  Enter the config number to remove (see 'config list')")
        console.print()
        
    class DummyArgs: pass
    args = DummyArgs()
    args.num = num
    cmd_cfg_remove(args)

@config_app.command("encrypt")
def cfg_encrypt():
    """Obfuscate configs.txt → configs.enc (protects at rest)"""
    from .cli import cmd_cfg_encrypt
    class DummyArgs: pass
    cmd_cfg_encrypt(DummyArgs())

@config_app.command("decrypt")
def cfg_decrypt():
    """Restore configs.enc → configs.txt"""
    from .cli import cmd_cfg_decrypt
    class DummyArgs: pass
    cmd_cfg_decrypt(DummyArgs())

# ── TOOLS GROUP ──
tools_app = typer.Typer(help="Network diagnostics, DNS, hotspot, and more", no_args_is_help=True)
app.add_typer(tools_app, name="tools")

@tools_app.command("dns-bench")
def tools_dns_bench():
    """Benchmark DNS servers"""
    from .cli import cmd_tools_dns_bench
    class DummyArgs: pass
    cmd_tools_dns_bench(DummyArgs())

@tools_app.command("dns-flush")
def tools_dns_flush():
    """Flush DNS cache"""
    from .cli import cmd_tools_dns_flush
    class DummyArgs: pass
    cmd_tools_dns_flush(DummyArgs())

@tools_app.command("dns-set")
def tools_dns_set(
    ip: str = typer.Argument(None, help="DNS IP (e.g. 1.1.1.1)"),
    adapter: str = typer.Option(None, "--adapter", "-a", help="Specific adapter name")
):
    """Set system DNS server"""
    from rich.prompt import Prompt
    from .cli import cmd_tools_dns_set
    if not ip:
        console.print()
        ip = Prompt.ask("🖥️  Enter the DNS IP to set (e.g. 1.1.1.1)")
        console.print()
    class DummyArgs: pass
    args = DummyArgs()
    args.ip = ip
    args.adapter = adapter
    cmd_tools_dns_set(args)

@tools_app.command("speedtest")
def tools_speedtest():
    """Run download speed test"""
    from .cli import cmd_tools_speedtest
    class DummyArgs: pass
    cmd_tools_speedtest(DummyArgs())

@tools_app.command("adapters")
def tools_adapters():
    """List network adapters and IPs"""
    from .cli import cmd_tools_adapters
    class DummyArgs: pass
    cmd_tools_adapters(DummyArgs())

@tools_app.command("netfix")
def tools_netfix():
    """Auto-fix common network problems (admin)"""
    from .cli import cmd_tools_netfix
    class DummyArgs: pass
    cmd_tools_netfix(DummyArgs())

@tools_app.command("hotspot")
def tools_hotspot(
    action: str = typer.Argument(None, help="on | off")
):
    """Start/stop Windows Mobile Hotspot"""
    from rich.prompt import Prompt
    from .cli import cmd_tools_hotspot
    if not action:
        console.print()
        action = Prompt.ask("📡 Select hotspot action", choices=["on", "off"])
        console.print()
    class DummyArgs: pass
    args = DummyArgs()
    args.action = action
    cmd_tools_hotspot(args)

@tools_app.command("share-vpn")
def tools_share_vpn(
    action: str = typer.Argument(None, help="on | off")
):
    """Share VPN connection via hotspot (ICS)"""
    from rich.prompt import Prompt
    from .cli import cmd_tools_share_vpn
    if not action:
        console.print()
        action = Prompt.ask("🌐 Select ICS VPN sharing action", choices=["on", "off"])
        console.print()
    class DummyArgs: pass
    args = DummyArgs()
    args.action = action
    cmd_tools_share_vpn(args)

@tools_app.command("ping")
def tools_ping(host: str = typer.Argument(None, help="Host to ping")):
    """TCP ping test"""
    from rich.prompt import Prompt
    from .cli import cmd_tools_ping
    if not host:
        console.print()
        host = Prompt.ask("🏓 Enter host or IP to ping")
        console.print()
    class DummyArgs: pass
    args = DummyArgs()
    args.host = host
    cmd_tools_ping(args)
    
@tools_app.command("mtu")
def tools_mtu(
    host: str = typer.Argument("8.8.8.8", help="Host to ping"),
    set_mtu: bool = typer.Option(False, "--set", help="Auto-set the best MTU")
):
    """Detect and optionally set MTU"""
    from .cli import cmd_tools_mtu
    class DummyArgs: pass
    args = DummyArgs()
    args.host = host
    args.set = set_mtu
    cmd_tools_mtu(args)

@tools_app.command("traceroute")
def tools_traceroute(host: str = typer.Argument(None, help="Host to trace")):
    """Traceroute to a host"""
    from rich.prompt import Prompt
    from .cli import cmd_tools_traceroute
    if not host:
        console.print()
        host = Prompt.ask("🗺️  Enter host or IP to trace")
        console.print()
    class DummyArgs: pass
    args = DummyArgs()
    args.host = host
    cmd_tools_traceroute(args)

@tools_app.command("cert-check")
def tools_cert_check(host: str = typer.Argument(None, help="Host to check")):
    """Check TLS certificate for a host[:port]"""
    from rich.prompt import Prompt
    from .cli import cmd_tools_cert_check
    if not host:
        console.print()
        host = Prompt.ask("🔐 Enter host or IP to check TLS certificate")
        console.print()
    class DummyArgs: pass
    args = DummyArgs()
    args.host = host
    cmd_tools_cert_check(args)


def main():
    """Global entry point for the new Typer CLI."""
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[muted]Operation cancelled by user.[/muted]")
        sys.exit(130)
    except Exception as e:
        import traceback
        console.print(error_panel(
            f"An unexpected fatal error occurred:\n{str(e)}\n\n[dim]Please run 'blackout doctor' to auto-fix common issues.[/dim]",
            title="Fatal Error"
        ))
        sys.exit(1)

if __name__ == "__main__":
    main()
