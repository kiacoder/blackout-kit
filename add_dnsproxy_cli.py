with open("blackoutkit/typer_cli.py", "r") as f:
    code = f.read()

dnsproxy_cmd = '''
@tools_app.command("dns-proxy")
def tools_dns_proxy(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Local IP to bind DNS proxy listener"),
    port: int = typer.Option(5300, "--port", "-p", help="Local UDP port to bind DNS proxy listener"),
    upstream: str = typer.Option("https://1.1.1.1/dns-query", "--upstream", "-u", help="Upstream DoH endpoint URL"),
):
    """🌐 Secure DoH DNS Proxy Engine (local UDP listener that forwards queries over encrypted DNS-over-HTTPS)."""
    from .tools import run_doh_proxy_server

    console.print(f"[bold cyan]🌐 Secure DoH DNS Proxy Engine Active[/bold cyan]")
    console.print(f"[muted]Listening on UDP {host}:{port} -> Forwarding over encrypted DoH to {upstream}[/muted]")
    console.print("[dim]Press Ctrl+C to stop local DNS proxy...[/dim]\\n")

    try:
        run_doh_proxy_server(host=host, port=port, upstream_doh=upstream)
    except KeyboardInterrupt:
        console.print("\\n[muted]DoH DNS Proxy server stopped.[/muted]")
'''

if 'def tools_dns_proxy(' not in code:
    code += "\n" + dnsproxy_cmd
    with open("blackoutkit/typer_cli.py", "w") as f:
        f.write(code)
    print("Added tools_dns_proxy to blackoutkit/typer_cli.py")
