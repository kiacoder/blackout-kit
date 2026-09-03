with open("blackoutkit/typer_cli.py", "r") as f:
    code = f.read()

old_capture_cmd = '''@tools_app.command("capture")
def tools_capture(
    iface: str = typer.Argument(None, help="Interface name to capture on (see `tools adapters`); omit for auto"),
    count: int = typer.Option(0, "--count", "-c", help="Stop after N packets (0 = unbounded, Ctrl+C to stop)"),
    filter: str = typer.Option(None, "--filter", "-f", help="Raw BPF filter expression (e.g. 'tcp port 443')"),
    host: str = typer.Option(None, "--host", help="Shorthand filter for traffic to/from this host"),
    ctx: typer.Context = None,
):
    """Capture packets locally; install `blackout-kit[capture]` and Npcap/libpcap first."""
    options = _output_options(ctx)
    try:
        require_import("capture", "scapy.all", "scapy", "Windows also requires Npcap; Linux requires libpcap")
    except OptionalDependencyError as exc:
        _optional_dependency_error(exc, options=options)
    from .cli import cmd_tools
    cmd_tools(_args(
        tools_command="capture",
        iface=_option_value(iface),
        count=int(_option_value(count, 0)),
        filter=_option_value(filter),
        host=_option_value(host),
    ))'''

new_capture_cmd = '''@tools_app.command("capture")
def tools_capture(
    iface: str = typer.Argument(None, help="Interface name to capture on (see `tools adapters`); omit for auto"),
    count: int = typer.Option(0, "--count", "-c", help="Stop after N packets (0 = unbounded, Ctrl+C to stop)"),
    filter: str = typer.Option(None, "--filter", "-f", help="Raw BPF filter expression (e.g. 'tcp port 443')"),
    host: str = typer.Option(None, "--host", help="Shorthand filter for traffic to/from this host"),
    pcap: str = typer.Option(None, "--pcap", "-p", help="Export packet trace to standard .pcap binary file for Wireshark"),
    ctx: typer.Context = None,
):
    """Capture packets locally; install `blackout-kit[capture]` and Npcap/libpcap first."""
    options = _output_options(ctx)
    try:
        require_import("capture", "scapy.all", "scapy", "Windows also requires Npcap; Linux requires libpcap")
    except OptionalDependencyError as exc:
        _optional_dependency_error(exc, options=options)
    from .cli import cmd_tools
    cmd_tools(_args(
        tools_command="capture",
        iface=_option_value(iface),
        count=int(_option_value(count, 0)),
        filter=_option_value(filter),
        host=_option_value(host),
        pcap=_option_value(pcap),
    ))'''

if old_capture_cmd in code:
    code = code.replace(old_capture_cmd, new_capture_cmd)
    with open("blackoutkit/typer_cli.py", "w") as f:
        f.write(code)
    print("Updated tools_capture in blackoutkit/typer_cli.py with --pcap option")
else:
    print("Could not match exact old_capture_cmd in blackoutkit/typer_cli.py")
